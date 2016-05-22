/*
 *  This file is part of rmlint.
 *
 *  rmlint is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  rmlint is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with rmlint.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *
 *  - Christopher <sahib> Pahl 2010-2015 (https://github.com/sahib)
 *  - Daniel <SeeSpotRun> T.   2014-2015 (https://github.com/SeeSpotRun)
 *
 * Hosted on http://github.com/sahib/rmlint
 *
 */

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/uio.h>

#include "checksum.h"
#include "hasher.h"

#include "formats.h"
#include "preprocess.h"
#include "utilities.h"

#include "md-scheduler.h"
#include "shredder.h"
#include "xattr.h"

/* Needed for RmTreeMerger */
#include "treemerge.h"

/* Enable extra debug messages? */
#define _RM_SHRED_DEBUG 0

/* This is the engine of rmlint for file duplicate matching.
 *
 * Files are compared in progressive "generations" to identify matching
 * clusters termed "ShredGroup"s:
 * Generation 0: Same size files
 * Generation 1: Same size and same hash of first  ~16kB
 * Generation 2: Same size and same hash of first  ~50MB
 * Generation 3: Same size and same hash of first ~100MB
 * Generation 3: Same size and same hash of first ~150MB
 * ... and so on until the end of the file is reached.
 *
 * The default step size can be configured below.
 *
 *
 * The clusters and generations look something like this:
 *
 *+-------------------------------------------------------------------------+
 *|     Initial list after filtering and preprocessing                      |
 *+-------------------------------------------------------------------------+
 *          | same size                   | same size           | same size
 *   +------------------+           +------------------+    +----------------+
 *   |   ShredGroup 1   |           |   ShredGroup 2   |    |   ShredGroup 3 |
 *   |F1,F2,F3,F4,F5,F6 |           |F7,F8,F9,F10,F11  |    |   F12,F13      |
 *   +------------------+           +------------------+    +----------------+
 *       |            |                 |            |
 *  +------------+ +----------+     +------------+  +---------+  +----+ +----+
 *  | Child 1.1  | |Child 1.2 |     | Child 2.1  |  |Child 2.2|  |3.1 | |3.2 |
 *  | F1,F3,F6   | |F2,F4,F5  |     |F7,F8,F9,F10|  |  F11    |  |F12 | |F13 |
 *  |(hash=hash1 | |(hash=h2) |     |(hash=h3)   |  |(hash=h4)|  |(h5)| |(h6)|
 *  +------------+ +----------+     +------------+  +---------+  +----+ +----+
 *       |            |                |        |              \       \
 *   +----------+ +-----------+  +-----------+ +-----------+    free!   free!
 *   |Child1.1.1| |Child 1.2.1|  |Child 2.2.1| |Child 2.2.2|
 *   |F1,F3,F6  | |F2,F4,F5   |  |F7,F9,F10  | |   F8      |
 *   +----------+ +-----------+  +-----------+ +-----------+
 *               \             \              \             \
 *                rm!           rm!            rm!           free!
 *
 *
 * The basic workflow is:
 * 1. One worker thread is established for each physical device
 * 2. The device thread picks a file from its queue, reads the next increment of that
 *    file, and sends it to a hashing thread.
 * 3. Depending on some logic ("shredder_waiting"), the device thread may wait for the
 *    file increment to finish hashing, or may move straight on to the next file in
 *    the queue.  The "shredder_waiting" logic aims to reduce disk seeks on rotational
 *    devices.
 * 4. The hashed fragment result is "sifted" into a child RmShredGroup of its parent
 *    group, and unlinked it from its parent.
 * 5. (a) If the child RmShredGroup needs hashing (ie >= 2 files and not completely hashed
 *    yet) then the file is pushed back to the device queue for further hashing;
 *    (b) If the file is not completely hashed but is the only file in the group (or
 *    otherwise fails criteria such as --must-match-tagged) then it is retained by the
 *    child RmShredGroup until a suitable sibling arrives, whereupon it is released to
 *    the device queue.
 *    (c) If the file has finished hashing, it is retained by the child RmShredGroup
 *    until its parent and all ancestors have finished processing, whereupon the file
 *    is sent to the "result factory" (if >= 2 files in the group) or discarded.
 *
 * In the above example, the hashing order will depend on the "shredder_waiting" logic.
 *    On a rotational device the hashing order should end up being something like:
 *         F1.1 F2.1 (F3.1,F3.2), (F4.1,F4.2), (F5.1,F5.2,F5.3)...
 *                        ^            ^            ^    ^
 *        (^ indicates where hashing could continue on to a second increment (avoiding a
 *           disk seek) because there was already a matching file after the first
 *           increment)
 *
 *    On a non-rotational device where there is no seek penalty, the hashing order is:
 *         F1.1 F2.1 F3.1 F4.1 F5.1...
 *
 *
 * The threading looks somewhat like this for two devices:
 *
 *                          +----------+
 *                          |  Result  |
 *                          |  Factory |
 *                          |  Pipe    |
 *                          +----------+
 *                                ^
 *                                |
 *                        +--------------+
 *                        | Matched      |
 *                        | fully-hashed |
 *                        | dupe groups  |
 *    Device #1           +--------------+      Device #2
 *                                ^
 * +-------------------+          |          +-------------------+
 * | RmShredDevice     |          |          | RmShredDevice     |
 * | Worker            |          |          | Worker            |
 * | +-------------+   |          |          | +-------------+   |
 * | | File Queue  |<--+----+     |     +----+>| File Queue  |   |
 * | +-------------+   |    |     |     |    | +-------------+   |
 * | pop from          |    |     |     |    |        pop from   |
 * |  queue            |    |     |     |    |         queue     |
 * |     |             |    |     |     |    |            |      |
 * |     |<--Continue  |    |     |     |    | Continue-->|      |
 * |     |     ^       |    |     |     |    |      ^     |      |
 * |     v     |       |    |     |     |    |      |     v      |
 * |   Read    |       |    |     |     |    |      |    Read    |
 * |     |     |       |    |     |     |    |      |     |      |
 * |     |     |       |    |     |     |    |      |     |      |
 * |     |     |       |  Device  |  Device  |      |     |      |
 * |    [1]    |       |   Not    |    Not   |      |    [1]     |
 * +-----|-----+-------+ Waiting  |  Waiting +------|-----|------+
 *       |     |            |     |     |           |     |
 *       |     |            |     |     |           |     |
 *       |  Device  +-------+-----+-----+------+  Device  |
 *       | Waiting  |         Sifting          | Waiting  |
 *       |     |    |  (Identifies which       |    |     |
 *       |     -----+  partially-hashed files  +----+     |
 *       |          |  qualify for further     |          |
 *       |     +--->|  hashing)                |<--+      |
 *       |     |    |                          |   |      |
 *       |     |    +--------------------------+   |      |
 *       |     |         ^            |            |      |
 *       |     |         |            v            |      |
 *       |     |  +----------+   +----------+      |      |
 *       |     |  |Initial   |   | Rejects  |      |      |
 *       |     |  |File List |   |          |      |      |
 *       |     |  +----------+   +----------+      |      |
 *       |     |                                   |      |
 *  +----+-----+-----------------------------------+------+----+
 *  |    v     |        Hashing Pool               |      v    |
 *  |  +----------+                              +----------+  |
 *  |  |Hash Pipe |                              |Hash Pipe |  |
 *  |  +----------+                              +----------+  |
 *  +----------------------------------------------------------+
 *
 *  Note [1] - at this point the read results are sent to the hashpipe
 *             and the Device must decide if it is worth waiting for
 *             the hashing/sifting result; if not then the device thread
 *             will immediately pop the next file from its queue.
 *
 *
 *
 * Every subbox left and right are the task that are performed.
 *
 * The Device Workers, Hash Pipes and Finisher Pipe run as separate threads
 * managed by GThreadPool.  Note that while they are implemented as
 * GThreadPools, the hashers and finisher are limited to 1 thread eash
 * hence the term "pipe" is more appropriate than "pool".  This is
 * particularly important for hashing because hash functions are generally
 * order-dependent, ie hash(ab) != hash(ba); the only way to ensure hashing
 * tasks are complete in correct sequence is to use a single pipe.
 *
 * The Device Workers work sequentially through the queue of hashing
 * jobs; if the device is rotational then the files are sorted in order of
 * disk offset in order to reduce seek times.
 *
 * The Devlist Manager calls the hasher library (see hasher.c) to read one
 * file at a time.  The hasher library takes care of read buffers, hash
 * pipe allocation, etc.  Once the hasher is done, the result is sent back
 * via callback to rm_shred_hash_callback.
 *
 * If "shredder_waiting" has been flagged then the callback sends the file
 * back to the Device Worker thread via a GAsyncQueue, whereupon the Device
 * Manager does a quick check to see if it can continue with the same file;
 * if not then a new file is taken from the device queue.
 *
 * The RmShredGroups don't have a thread managing them, instead the individual
 * Device Workers and/or hash pipe callbacks write to the RmShredGroups
 * under mutex protection.
 *
 *
 * The main ("foreground") thread waits for the Devlist Managers to
 * finish their sequential walk through the files.  If there are still
 * files to process on the device, the initial thread sends them back to
 * the GThreadPool for another pass through the files.
 *
 *
 *
 * Additional notes regarding "paranoid" hashing:
 *
 * The default file matching method uses the SHA1 cryptographic hash; there are
 * several other hash functions available as well.  The data hashing is somewhat
 * cpu-intensive but this is handled by separate threads (the hash pipes) so
 * generally doesn't bottleneck rmlint (as long as CPU exceeds disk reading
 * speed).  The subsequent hash matching is very fast because we only
 * need to compare 20 bytes (in the case of SHA1) to find matching files.
 *
 * The "paranoid" method uses byte-by-byte comparison.  In the implementation,
 * this is masqueraded as a hash function, but there is no hashing involved.
 * Instead, the whole data increment is kept in memory.  This introduces 2 new
 * challenges:
 *
 * (1) Memory management.  In order to avoid overflowing mem availability, we
 * limit the number of concurrent active RmShredGroups and also limit the size
 * of each file increment.
 *
 * (2) Matching time.  Unlike the conventional hashing strategy (CPU-intensive
 * hashing followed by simple matching), the paranoid method requires
 * almost no CPU during reading/hashing, but requires a large memcmp() at the
 * end to find matching files/groups.
 *
 * That would not be a bottleneck as long as the reader thread still has other
 * files that it can go and read while the hasher/sorter does the memcmp in
 * parallel... but unfortunately the memory management issue means that's not
 * always an option and so reading gets delayed while waiting for the memcmp()
 * to catch up.  Two strategies are used to speed this up:
 *
 * (a) Pre-matching of candidate digests.  During reading/hashing, as each
 * buffer (4096 bytes) is read in, it can be checked against a "twin candidate".
 * We can send twin candidates to the hash pipe at any time via
 * rm_digest_send_match_candidate().  If the correct twin candidate has been
 * sent, then when the increment is finished the matching has already been done,
 * and rm_digest_equal() is almost instantaneous.
 *
 * (b) Shadow hash.  A lightweight hash (Murmor) is calculated and used for
 * hashtable lookup to quickly identify potential matches.  This saves time in
 * the case of RmShredGroups with large number of child groups and where the
 * pre-matching strategy failed.
 * */

/*
* Below some performance controls are listed that may impact performance.
* Controls are sorted by subjectve importanceness.
*/

////////////////////////////////////////////
// OPTIMISATION PARAMETERS FOR DECIDING   //
// HOW MANY BYTES TO READ BEFORE STOPPING //
// TO COMPARE PROGRESSIVE HASHES          //
////////////////////////////////////////////

/* how many bytes to use for initial read (will be rounded up to a whole page) */
#define SHRED_FIRST_INCREMENT (16 * 1024)

/* Maximum increment size for digests; increments bigger than this would
 * give negligible seek savings and risk hashing past the point where two
 * files diverge
 */
#define SHRED_MAX_INCREMENT (256 * 1024 * 1024)

/* Maximum increment size for paranoid digests.  This is smaller than for other
 * digest types due to memory management issues.
 * 16MB read at typical 100 MB/s read rate = 160ms read vs typical seek time 10ms
 * so the speed penalty is around 6% */
#define SHRED_MAX_PARANOID (16 * 1024 * 1024)

/* How quickly to (geometrically) increase increment size */
#define SHRED_ACCELERATION (8)

/* empirical estimate of mem usage per file (excluding read buffers and
 * paranoid digests) */
#define SHRED_AVERAGE_MEM_PER_FILE (100)

///////////////////////////////////////////////////////////////////////
//    INTERNAL STRUCTURES, WITH THEIR INITIALISERS AND DESTROYERS    //
///////////////////////////////////////////////////////////////////////

/////////* The main extra data for the duplicate finder *///////////

typedef struct RmShredTag {
    RmCfg *cfg;
    GMutex hash_mem_mtx;
    GCond hash_mem_cond;
    gint64 paranoid_mem_alloc; /* how much memory available for paranoid checks */

    RmHasher *hasher;
    RmMDS *mds;
    /* threadpool for sending files and progress updates to session.c */
    GThreadPool *shredder_pipe;
    RmOff buffer_size;
    RmOff first_increment;
    RmOff max_increment;

    GMutex lock;

    gint32 remaining_files;
    gint64 remaining_bytes;

    bool after_preprocess : 1;
    bool mds_paused : 1;

} RmShredTag;

#define HAS_CACHE(shredder) (shredder->cfg->read_cksum_from_xattr)

#define NEEDS_SHADOW_HASH(cfg) (cfg->merge_directories || cfg->read_cksum_from_xattr)

/** RmShredNode is a node of an RmShredGroup which represents a cluster of files
 * with identical [partial] hashes
 **/
typedef struct RmShredNode {
    /* the tree to which we belong */
    struct RmShredTree *tree;

    /* parent node or NULL for first level of tree */
    struct RmShredNode *parent;

    /* files which don't need hashing (yet) - either have finished hashing
     * or don't yet have enough candidate files */
    GSList *held_files;

    /* once the node's files qualify for hashing, they are queued to MDS and
     * will return again via rm_shred_sift;
     * num_pending tracks how many hashing jobs are still pending */
    guint32 num_pending;

    /* once files return from hashing, they are grouped into child nodes;
     * note: a hashtable might be faster in corner cases but a GSList uses
     * less memory */
    GSList *children;

    /** counters and flags for deciding whether node's files need further hashing
     * note: nodes with more than ~4 billion files (G_MAXUINT32) are not supported
     * but we would probably run out of RAM well before that anyway
     **/

    /* number of files (including bundled hardlinked files) in self + children */
    guint32 num_files;

    /* number of files (excluding bundled hardlinked files) in self + children */
    guint32 num_inodes;

    /* set if group has 1 or more files from "preferred" paths */
    bool has_pref : 1;

    /* set if group has 1 or more files from "non-preferred" paths */
    bool has_npref : 1;

    /* set if group has 1 or more files newer than cfg->min_mtime */
    bool has_new : 1;

    /* true if all files in the group have an external checksum */
    bool has_only_ext_cksums : 1;

    /* if whole group has same basename, pointer to first file, else null */
    RmFile *unique_basename;

    /* whether the node has sufficient files to qualify as a dupe group */
    gboolean qualifies : 1;

    /* whether this is the final increment for member files (ie EOF) */
    gboolean final : 1;

    /* checksum of first file to enter the group */
    RmDigestSum *sum;

} RmShredNode;

/** initialises an RmShredNode based on file;
 * note: assumes node is already memset to all zeros
 **/
static void rm_shred_node_init(RmShredNode *node, RmFile *file, RmDigestSum *sum) {
    if(file->shred_node) {
        /* should be true unless this is first node of tree */
        node->parent = file->shred_node;
        node->tree = node->parent->tree;
    }
    node->final = (file->hash_offset == file->file_size);
    node->sum = sum;
}

/** allocate and initialise a new RmShredNode based on file;
 * takes ownership of file's digest.
 **/
static RmShredNode *rm_shred_node_new(RmFile *file, RmDigestSum *sum) {
    RmShredNode *self = g_slice_new0(RmShredNode);
    rm_shred_node_init(self, file, sum);

    return self;
}

/** Free an RmShredNode
 **/
static void rm_shred_node_free(RmShredNode *node) {
    rm_assert_gentle(!node->held_files);
    rm_assert_gentle(!node->children);
    /* don't free top-level node; it is embedded in RmShredTree */
    rm_assert_gentle((gpointer)node != (gpointer)node->tree);

    if(node->sum) {
        rm_digest_sum_free(node->sum);
    }
    g_slice_free(RmShredNode, node);
}

/** RmShredTree is a group of same-sized files; as the files are incrementally
 * hashed and compared, the tree may branch out into multiple nodes
 **/
typedef struct RmShredTree {
    /* tree of [partially] matched nodes
     * note: must be first so that tree can be cast as a node
     */
    RmShredNode head;

    /* reference count to decide when to free tree */
    gint32 remaining_files;

    /* lock for access to the tree and its nodes */
    GMutex lock;

    /* memory allocation for paranoid hashing */
    gint64 paranoid_mem_alloc;

    /* Reference to main */
    RmShredTag *shredder;
} RmShredTree;

/* allocate and initialise new RmShredTree using file as a template*/
static RmShredTree *rm_shred_tree_new(RmShredTag *shredder, RmFile *file) {
    RmShredTree *tree = g_new0(RmShredTree, 1);

    tree->shredder = shredder;
    rm_shred_node_init(&tree->head, file, NULL);
    tree->head.tree = tree;

    g_mutex_init(&tree->lock);

    return tree;
}

static void rm_shred_tree_free(RmShredTree *tree) {
    rm_assert_gentle(!tree->head.held_files);
    rm_assert_gentle(!tree->head.children);
    if(tree->paranoid_mem_alloc != 0) {
        RmShredTag *shredder = tree->shredder;
        g_mutex_lock(&shredder->hash_mem_mtx);
        {
            shredder->paranoid_mem_alloc += tree->paranoid_mem_alloc;
            g_cond_signal(&shredder->hash_mem_cond);
        }
        g_mutex_unlock(&shredder->hash_mem_mtx);
    }
    g_mutex_clear(&tree->lock);
    g_free(tree);
}

//////////////////////////////////
// OPTIMISATION AND MEMORY      //
// MANAGEMENT ALGORITHMS        //
//////////////////////////////////

/* Compute optimal size for next hash increment */
static gint32 rm_shred_get_read_size(RmFile *file, RmShredTag *shredder) {
    rm_assert_gentle(file->hash_offset < file->file_size);

    RmOff target = file->hash_offset * SHRED_ACCELERATION + shredder->first_increment;
    /* eg for first_increment == 10 and SHRED_ACCELERATION == 4
     *   -> 10,  50,  210,  850...
     *    (+10)(+40)(+160)(+640)...
     */

    /* don't over-shoot file */
    target = MIN(target, file->file_size);

    RmOff result = target - file->hash_offset;

    /* don't exceed max increment */
    result = MIN(result, shredder->max_increment);

    rm_assert_gentle(result > 0);
    return result;
}

///////////////////////////////////
//       Progress Reporting      //
///////////////////////////////////

RmShredBuffer *rm_shred_buffer_new(GSList *files, gint delta_files, gint64 delta_bytes) {
    RmShredBuffer *buffer = g_slice_new(RmShredBuffer);
    buffer->delta_files = delta_files;
    buffer->delta_bytes = delta_bytes;
    buffer->finished_files = files;
    return buffer;
}

void rm_shred_buffer_free(RmShredBuffer *buffer) {
    /* do not free buffer->finished_files; caller keeps ownership of that */
    g_slice_free(RmShredBuffer, buffer);
}

/* send updates and/or results to session.c */
static void rm_shred_send(RmShredTag *shredder, GSList *files, gint delta_files,
                          gint64 delta_bytes) {
    if(files) {
        RmFile *head = files->data;
        rm_assert_gentle(head);
#if _RM_SHRED_DEBUG
        RM_DEFINE_PATH(head);
        rm_log_debug_line("Forwarding %s's group", head_path);
#endif

        /* unref files from MDS */
        /* TODO: maybe do this in rm_shred_group_find_original */
        /* check we don't double-count: */
        rm_assert_gentle(delta_bytes == 0);
        rm_assert_gentle(delta_files == 0);

        for(GSList *iter = files; iter; iter = iter->next) {
            RmFile *file = iter->data;
            if(!RM_IS_BUNDLED_HARDLINK(file)) {
                rm_assert_gentle(file->disk);
                rm_mds_device_ref(file->disk, -1, FALSE);
                file->disk = NULL;
                delta_files--;
                delta_bytes -= file->file_size - file->hash_offset;
            }
        }
    }

    /* send to session.c */
    g_thread_pool_push(shredder->shredder_pipe,
                       rm_shred_buffer_new(files, delta_files, delta_bytes), NULL);
}

/** Send dead RmFile to session.c
 **/
static void rm_shred_discard_file(RmFile *file) {
    rm_assert_gentle(file);
    rm_assert_gentle(file->shred_node);
    RmShredTag *shredder = file->shred_node->tree->shredder;

    /* session.c expects files in a GSList; can't send file directly*/
    GSList *coffin = g_slist_append(NULL, file);
    rm_shred_send(shredder, coffin, 0, 0);
}

/** Push file to scheduler queue.
 **/
static void rm_shred_push_queue(RmFile *file) {
    if(file->hash_offset == 0) {
        /* first-timer; lookup disk offset */
        if(file->cfg->build_fiemap && rm_mds_device_is_rotational(file->disk)) {
            RM_DEFINE_PATH(file);
            file->disk_offset = rm_offset_get_from_path(file_path, 0, NULL);
        } else {
            /* use inode number instead of disk offset */
            file->disk_offset = file->inode;
        }
    }
    rm_mds_push_task(file->disk, file->dev, file->disk_offset, NULL, file);
}

//////////////////////////////////
//    RMSHREDGROUP UTILITIES    //
//    AND SIFTING ALGORITHM     //
//////////////////////////////////

/* some macros to improve readability of rm_shred_node_qualifies */
#define NEEDS_PREF(cfg) (cfg->must_match_tagged)
#define NEEDS_NPREF(cfg) (cfg->keep_all_tagged)
#define NEEDS_NEW(cfg) (cfg->min_mtime)
#define NEEDS_BASENAMES(cfg) (cfg->unmatched_basenames)

/** Checks whether node qualifies as duplicate candidate (ie more than
 * two members and meets has_pref and other cfg criteria).
 * Assume already protected by node->tree->lock.
 * If true then sets node->qualifies true to avoid needing to re-check.
 * Call with tree node->tree locked
 **/
static gboolean rm_shred_node_qualifies(RmShredNode *node) {
    if(node->qualifies) {
        return TRUE;
    }
    RmCfg *cfg = node->tree->shredder->cfg;
    node->qualifies =
        (1 && (node->num_files >= 2) /* it takes 2 to tango */
         &&
         (node->has_pref || !NEEDS_PREF(cfg))
         /* we have at least one file from preferred path, or we don't care */
         &&
         (node->has_npref || !NEEDS_NPREF(cfg))
         /* we have at least one file from non-pref path, or we don't care */
         &&
         (node->has_new || !NEEDS_NEW(cfg))
         /* we have at least one file newer than cfg->min_mtime, or we don't care */
         &&
         (!node->unique_basename || !NEEDS_BASENAMES(cfg))
         /* we have more than one unique basename, or we don't care */
         );
    return node->qualifies;
}

/** prepare and output a finished RmShredNode
 **/
static void rm_shred_node_output(RmShredNode *node) {
    rm_assert_gentle(node->held_files);

    RmLintType lint_type = RM_LINT_TYPE_UNKNOWN;

    if(rm_shred_node_qualifies(node)) {
        rm_assert_gentle(node->final);
        lint_type = RM_LINT_TYPE_DUPE_CANDIDATE;
    } else {
        lint_type = RM_LINT_TYPE_UNIQUE_FILE;
    }

    if(node->sum) {
        rm_digest_sum_free(node->sum);
        node->sum = NULL;
    }

    /* find the original(s) (note this also unbundles hardlinks and sorts
     * the group from highest ranked to lowest ranked, and points the files
     * to their (shared) digest
     */
    RmShredTag *shredder = node->tree->shredder;
    node->held_files =
        rm_shred_group_find_original(shredder->cfg, node->held_files, lint_type);

    /* send files to session for output and file freeing */
    rm_shred_send(shredder, node->held_files, 0, 0);
}

/* returns the number of actual files (including bundled
 * hardlinks) associated with an RmFile */
static gint rm_shred_num_files(RmFile *file) {
    if(file->hardlinks.is_head) {
        rm_assert_gentle(file->hardlinks.files);
        return 1 + file->hardlinks.files->length;
    } else {
        return 1;
    }
}

/** rm_shred_node_add_file adds a file to the node unless it needs further
 * hashing, in which case it is added the the hashing queue instead.
 * call with tree node->tree locked
 **/
static void rm_shred_node_add_file(RmShredNode *node, RmFile *file) {
    file->shred_node = node;

    /* logic for cfg->unmatched_basenames option */
    RmCfg *cfg = node->tree->shredder->cfg;
    if(cfg->unmatched_basenames && node->num_files == 0) {
        /* first file into group sets the basename */
        node->unique_basename = file;
        rm_log_debug_line("Unique basename: %s", file->folder->basename)
    }
    if(node->unique_basename) {
        rm_log_debug_line("Unique basename checking...")
            /* check if we still have only 1 unique basename... */
            if(rm_file_basenames_cmp(file, node->unique_basename) != 0) {
            node->unique_basename = NULL;
            rm_log_debug_line("Unique basename failed")
        }
        else if(file->hardlinks.is_head) {
            /* also check hardlink names */
            for(GList *iter = file->hardlinks.files->head; iter; iter = iter->next) {
                if(rm_file_basenames_cmp(iter->data, node->unique_basename) != 0) {
                    node->unique_basename = NULL;
                    rm_log_debug_line("Unique basename failed on hardlink") break;
                }
            }
        }
        if(node->unique_basename) {
            rm_log_debug_line("still unique");
        }
    }

    /* update node totals */
    node->num_inodes++;
    node->num_files += rm_shred_num_files(file); /* includes hardlinks */
    node->has_pref |= file->is_prefd || file->hardlinks.has_prefd;
    node->has_npref |= (!file->is_prefd) || file->hardlinks.has_non_prefd;
    node->has_new |= file->is_new_or_has_new;
    node->has_only_ext_cksums &= file->has_ext_cksum;

    /* check whether to send for further hashing, or store in the node */
    if(rm_shred_node_qualifies(node) && !node->final) {
        /* push any held files to the md-scheduler for hashing */
        while(node->held_files) {
            node->num_pending++;
            RmFile *held = node->held_files->data;
            rm_shred_push_queue(held);
            node->held_files = g_slist_delete_link(node->held_files, node->held_files);
        }
        /* push the new arrival too */
        node->num_pending++;
        rm_shred_push_queue(file);
    } else {
        /* hold onto the file */
        node->held_files = g_slist_prepend(node->held_files, file);
    }
}

/** check whether a node may still expect incoming files;
 * call with tree node->tree locked
 **/
static gboolean rm_shred_node_has_pending(RmShredNode *node) {
    if(!node) {
        return FALSE;
    }
    return (node->num_pending > 0 || rm_shred_node_has_pending(node->parent));
}

/** RmSListRFunc to recursively check if node and its children have finished; if yes then
 * outputs node's result (if applicable) and, if delete==true, deletes the node from the
 * tree and frees it
 * note: if children have finished then they are always deleted and freed.
 **/
static gboolean rm_shred_node_finished(RmShredNode *node, _UNUSED RmShredNode *prev,
                                       gboolean delete) {
    if(rm_shred_node_has_pending(node)) {
        /* still waiting for incoming hashes */
        return FALSE;
    }

    if(node->held_files) {
        rm_assert_gentle(!node->children);
        /* send files to session.c */
        rm_shred_node_output(node);
        node->held_files = NULL;
    }

    if(node->children) {
        /* remove children recursively if they are finished */
        rm_util_slist_foreach_remove(
            &node->children, (RmSListRFunc)rm_shred_node_finished, GINT_TO_POINTER(TRUE));
    }
    /* anything left? */
    if(node->children == NULL) {
        if(delete) {
            rm_shred_node_free(node);
        }
        return TRUE;
    }
    return FALSE;
}

/** detach a node from tree; recursively move upwards, detaching parent nodes
 * if they too are finished.  If this results in a completely denuded tree then
 * return true.
 **/
static gboolean rm_shred_node_prune(RmShredNode *node) {
    rm_assert_gentle(!node->children);
    rm_assert_gentle(!node->held_files);
    RmShredNode *parent = node->parent;
    if(!parent) {
        /* top of tree reached */
        rm_assert_gentle(node->tree == (RmShredTree *)node);
        rm_assert_gentle(!node->held_files);
        rm_assert_gentle(!node->children);
        return TRUE;
    }

    /* remove self from parent and free self */
    parent->children = g_slist_remove(parent->children, node);
    rm_shred_node_free(node);

    /* recurse upwards? */
    if(rm_shred_node_finished(parent, NULL, FALSE)) {
        return rm_shred_node_prune(parent);
    } else {
        /* parent still busy */
        return FALSE;
    }
}

/** After partial hashing of RmFile, maybe add it back into the file tree;
 * or if further hashing is required then put into hashing queue instead.
 * Note rm_shred_reschedule also does any pruning of branches that die as
 * a result.  If the last branch is removed then the tree will be freed.
 **/
static void rm_shred_reschedule(RmFile *file) {
    rm_assert_gentle(file);
    RmShredNode *current = file->shred_node;
    rm_assert_gentle(current);
    RmShredTree *tree = current->tree;
    rm_assert_gentle(tree);

    gboolean free_tree = FALSE;

    g_mutex_lock(&tree->lock);
    {
        current->num_pending--;

        if(file->lint_type != RM_LINT_TYPE_DUPE_CANDIDATE) {
            /* reading/hashing failed somewhere; don't reinsert into tree */
            rm_shred_discard_file(file);

        } else {
            /* find right node to reinsert into tree */
            rm_assert_gentle(file->digest);
            RmShredNode *child = NULL;
            RmDigestSum *sum = rm_digest_sum(file->digest);
            for(GSList *iter = current->children; iter; iter = iter->next) {
                RmShredNode *candidate = iter->data;
                if(rm_digest_sum_equal(candidate->sum, sum)) {
                    child = candidate;
                    rm_digest_sum_free(sum);
                    break;
                }
            }
            if(!child) {
                child = rm_shred_node_new(file, sum);
                current->children = g_slist_prepend(current->children, child);
            }
            /* add file to child node, or maybe send it to hashing queue */
            rm_shred_node_add_file(child, file);
        }

        /* check if current group (and its children) have finished; if yes
         * then do some pruning of the tree */
        if(rm_shred_node_finished(current, NULL, FALSE)) {
            /* all children have been removed and current node will
             * never receive more files;
             * remove current node from tree, rucursing up the tree to
             * remove dead parents */
            free_tree = rm_shred_node_prune(current);
        }
    }
    g_mutex_unlock(&tree->lock);

    if(free_tree) {
        rm_shred_tree_free(tree);
    }
}

/* Hasher callback when file increment hashing is completed.
 * */
static void rm_shred_hash_callback(_UNUSED RmHasher *hasher, RmDigest *digest,
                                   _UNUSED RmShredTag *shredder, RmFile *file) {
    if(!file->digest) {
        file->digest = digest;
    }
    rm_assert_gentle(file->digest == digest);

    if(file->lint_type != RM_LINT_TYPE_READ_ERROR &&
       shredder->cfg->write_cksum_to_xattr && file->has_ext_cksum == false) {
        /* remember that checksum */
        rm_xattr_write_hash(shredder->cfg, file);
    }

    rm_shred_reschedule(file);
}

////////////////////////////////////
//  SHRED-SPECIFIC PREPROCESSING  //
////////////////////////////////////

/* Basically this unloads files from the initial list build (which has
 * hardlinks already grouped).
 * Outline:
 * 1. Use g_hash_table_foreach_remove to send RmFiles from node_table
 *    to size_groups via rm_shred_file_preprocess.
 * 2. Use g_hash_table_foreach_remove to delete all singleton and other
 *    non-qualifying groups from size_groups via rm_shred_group_preprocess.
 * 3. Use g_hash_table_foreach to do the FIEMAP lookup for all remaining
 *    files via rm_shred_device_preprocess.
 * */

/* Called for each file; find appropriate RmShredGroup (ie files with same size) and
 * push the file to it.
 * */
static void rm_shred_file_preprocess(RmFile *file, RmShredTree *tree) {
    /* initial population of RmShredTree's and linking to RmMDS devices */
    RmShredTag *shredder = tree->shredder;
    RmCfg *cfg = shredder->cfg;

    rm_assert_gentle(file);
    rm_assert_gentle(file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE);
    rm_assert_gentle(file->file_size > 0);

    file->is_new_or_has_new = (file->mtime >= cfg->min_mtime);

    /* if file has hardlinks then set file->hardlinks.has_[non_]prefd*/
    if(file->hardlinks.is_head) {
        for(GList *iter = file->hardlinks.files->head; iter; iter = iter->next) {
            RmFile *link = iter->data;
            file->hardlinks.has_non_prefd |= !(link->is_prefd);
            file->hardlinks.has_prefd |= link->is_prefd;
            file->is_new_or_has_new |= (link->mtime >= cfg->min_mtime);
        }
    }

    RM_DEFINE_PATH(file);

    /* add reference for this file to the MDS scheduler, and get pointer to its device */
    file->disk = rm_mds_device_get(shredder->mds, file_path, (cfg->fake_pathindex_as_disk)
                                                                 ? file->path_index + 1
                                                                 : file->dev);
    rm_mds_device_ref(file->disk, 1, FALSE);

    if(cfg->read_cksum_from_xattr) {
        char *ext_cksum = rm_xattr_read_hash(shredder->cfg, file);
        if(ext_cksum != NULL) {
            file->folder->data = ext_cksum;
            file->has_ext_cksum = TRUE;
        }
    }

    rm_shred_node_add_file(&tree->head, file);
    if(cfg->checksum_type == RM_DIGEST_PARANOID) {
        tree->paranoid_mem_alloc += MIN(file->file_size, shredder->max_increment);
    }
}

static void rm_shred_preprocess_group(GSList *files, RmShredTag *shredder) {
    /* push files to shred group */
    rm_assert_gentle(files);
    rm_assert_gentle(files->data);

    RmFile *first = files->data;
    RmShredTree *tree = rm_shred_tree_new(shredder, first);
    gboolean launch_failure = FALSE;

    g_mutex_lock(&tree->lock);
    {
        g_slist_foreach(files, (GFunc)rm_shred_file_preprocess, tree);
        g_slist_free(files);
        launch_failure = rm_shred_node_finished(&tree->head, NULL, FALSE);
    }
    g_mutex_unlock(&tree->lock);
    if(launch_failure) {
        tree->paranoid_mem_alloc = 0;
    }

    if(tree->paranoid_mem_alloc > 0) {
        g_mutex_lock(&shredder->hash_mem_mtx);
        {
            rm_log_debug_line("shredder: mem %li to %li", shredder->paranoid_mem_alloc,
                              shredder->paranoid_mem_alloc - tree->paranoid_mem_alloc);
            shredder->paranoid_mem_alloc -= tree->paranoid_mem_alloc;
            /* check paranoid mem avail before proceeding to next group */
            while(shredder->paranoid_mem_alloc <= 0) {
                rm_log_debug_line("shredder: waiting for mem");
                if(shredder->mds_paused) {
                    rm_mds_resume(shredder->mds);
                    shredder->mds_paused = FALSE;
                }
                g_cond_wait(&shredder->hash_mem_cond, &shredder->hash_mem_mtx);
            }
            rm_log_debug_line("shred mem ok");
        }
        g_mutex_unlock(&shredder->hash_mem_mtx);
    }
}

static void rm_shred_preprocess_input(RmShredTag *shredder, RmFileTables *tables) {
    /* move files from node tables into initial RmShredGroups */
    rm_log_debug_line("preparing size groups for shredding (dupe finding)...");
    /* small files first... */
    tables->size_groups = g_slist_reverse(tables->size_groups);
    g_slist_foreach(tables->size_groups, (GFunc)rm_shred_preprocess_group, shredder);
    g_slist_free(tables->size_groups);
    tables->size_groups = NULL;

    /* special signal for end of preprocessing */
    rm_shred_send(shredder, NULL, 0, 0);
}

/////////////////////////////////
//       POST PROCESSING       //
/////////////////////////////////

/* Discard files with same basename as headfile.
 * (RmRFunc for rm_util_queue_foreach_remove).
 */
static gint rm_shred_remove_basename_matches(RmFile *file, _UNUSED RmFile *prev,
                                             RmFile *headfile) {
    if(file == headfile) {
        return 0;
    }
    if(rm_file_basenames_cmp(file, headfile) != 0) {
        return 0;
    }
    /* TODO: how should formats report this? */
    RM_DEFINE_PATH(file);
    rm_log_debug_line("removing basename twin %s", file_path);
    file->lint_type = RM_LINT_TYPE_BASENAME_TWIN;
    rm_shred_discard_file(file);
    return 1;
}

/* iterate over group to find highest ranked; return it and tag it as original    */
/* also in special cases (eg keep_all_tagged) there may be more than one original,
 * in which case tag them as well
 */
GSList *rm_shred_group_find_original(RmCfg *cfg, GSList *files, RmLintType lint_type) {
    /* iterate over group, unbundling hardlinks and identifying "tagged" originals */
    for(GSList *iter = files; iter; iter = iter->next) {
        RmFile *file = iter->data;
        file->lint_type = lint_type;
        file->is_original = FALSE;

        if(file->hardlinks.is_head && file->hardlinks.files) {
            /* if group member has a hardlink cluster attached to it then
             * unbundle the cluster and append it to the queue
             */
            GQueue *hardlinks = file->hardlinks.files;
            for(GList *link = hardlinks->head; link; link = link->next) {
                RmFile *link_file = link->data;
                link_file->lint_type = lint_type;
                link_file->digest = file->digest;
                files = g_slist_prepend(files, link_file);
            }
            g_queue_free(hardlinks);
            file->hardlinks.files = NULL;
        }

        if(lint_type == RM_LINT_TYPE_DUPE_CANDIDATE && file->is_prefd &&
           cfg->keep_all_tagged) {
            /* may have multiple 'tagged' originals... */
            file->is_original = true;
#if _RM_SHRED_DEBUG
            RM_DEFINE_PATH(file);
            rm_log_debug_line("tagging %s as original because tagged", file_path);
#endif
        }
    }

    /* sort the unbundled group */
    files =
        g_slist_sort_with_data(files, (GCompareDataFunc)rm_file_cmp_orig_criteria, cfg);

    RmFile *headfile = files->data;
    if(lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        headfile->is_original = true;
#if _RM_SHRED_DEBUG
        RM_DEFINE_PATH(headfile);
        rm_log_debug_line("tagging %s as original because it is highest ranked",
                          headfile_path);
#endif
    }

    if(cfg->unmatched_basenames && lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        /* remove files which match headfile's basename */
        rm_log_debug_line("removing basename matches");
        rm_util_slist_foreach_remove(
            &files, (RmSListRFunc)rm_shred_remove_basename_matches, files->data);
    }
    return files;
}

/////////////////////////////////
//    ACTUAL IMPLEMENTATION    //
/////////////////////////////////

/** Callback for RmMDS
 **/
static void rm_shred_process_file(RmFile *file, RmShredTag *shredder) {
    if(rm_session_was_aborted()) {
        file->lint_type = RM_LINT_TYPE_INTERRUPTED;
        rm_shred_reschedule(file);
        return;
    }

    if(!file->digest) {
        RmCfg *cfg = shredder->cfg;
        file->digest = rm_digest_new(cfg->checksum_type,
                                     cfg->hash_seed1,
                                     cfg->hash_seed2,
                                     0,
                                     NEEDS_SHADOW_HASH(cfg));
    }

    /* hash the next increment of the file */
    RmOff bytes_to_read = rm_shred_get_read_size(file, shredder);

    RmHasherTask *task = rm_hasher_task_new(shredder->hasher, file->digest, file);
    RM_DEFINE_PATH(file);
    if(!rm_hasher_task_hash(task, file_path, file->hash_offset, bytes_to_read,
                            file->is_symlink)) {
        /* rm_hasher_start_increment failed somewhere */
        file->lint_type = RM_LINT_TYPE_READ_ERROR;
    }
    file->hash_offset += bytes_to_read;

    /* Update totals for file, device and session*/
    if(file->is_symlink) {
        rm_shred_send(shredder, NULL, 0, -(gint64)file->file_size);
    } else {
        rm_shred_send(shredder, NULL, 0, -(gint64)bytes_to_read);
    }

    /* tell the hasher we have finished */
    rm_hasher_task_finish(task);
}

void rm_shred_run(RmCfg *cfg, RmFileTables *tables, RmMDS *mds,
                  GThreadPool *shredder_pipe, guint total_files) {
    RmShredTag shredder;
    shredder.shredder_pipe = shredder_pipe;
    shredder.cfg = cfg;
    shredder.mds = mds;
    shredder.paranoid_mem_alloc = G_MAXINT64;

    shredder.buffer_size = sysconf(_SC_PAGESIZE);
    shredder.first_increment =
        MAX(1, SHRED_FIRST_INCREMENT / shredder.buffer_size) * shredder.buffer_size;
    if(cfg->checksum_type == RM_DIGEST_PARANOID) {
        shredder.max_increment =
            MAX(1, SHRED_MAX_PARANOID / shredder.buffer_size) * shredder.buffer_size;
    } else {
        shredder.max_increment =
            MAX(1, SHRED_MAX_INCREMENT / shredder.buffer_size) * shredder.buffer_size;
    }

    shredder.after_preprocess = FALSE;  // TODO: eliminate

    /* would use g_atomic, but helgrind does not like that */
    g_mutex_init(&shredder.hash_mem_mtx);
    g_cond_init(&shredder.hash_mem_cond);

    g_mutex_init(&shredder.lock);

    /* estimate mem used for RmFiles and allocate any leftovers to read buffer and/or
     * paranoid mem */
    RmOff mem_used = SHRED_AVERAGE_MEM_PER_FILE * total_files;
    RmOff read_buffer_mem = MAX(1024 * 1024, (gint64)cfg->total_mem - (gint64)mem_used);

    if(cfg->checksum_type == RM_DIGEST_PARANOID) {
        /* allocate any spare mem for paranoid hashing */
        shredder.paranoid_mem_alloc = (gint64)cfg->total_mem - (gint64)mem_used;
        shredder.paranoid_mem_alloc = MAX(0, shredder.paranoid_mem_alloc) * 2;
        /* note the times 2 is empirical; actual memory used is alway less than
         * half the theoretical */
        rm_log_debug_line("Paranoid Mem: %" LLU, shredder.paranoid_mem_alloc);
        /* paranoid memory manager takes care of memory load; */
        read_buffer_mem = 0;
    }
    rm_log_debug_line("Read buffer Mem: %" LLU, read_buffer_mem);

    /* Initialise hasher */
    /* Optimum buffer size based on /usr without dropping caches:
     * SHRED_PAGE_SIZE * 1 => 5.29 seconds
     * SHRED_PAGE_SIZE * 2 => 5.11 seconds
     * SHRED_PAGE_SIZE * 4 => 5.04 seconds
     * SHRED_PAGE_SIZE * 8 => 5.08 seconds
     * With dropped caches:
     * SHRED_PAGE_SIZE * 1 => 45.2 seconds
     * SHRED_PAGE_SIZE * 4 => 45.0 seconds
     * Optimum buffer size using a rotational disk and paranoid hash:
     * SHRED_PAGE_SIZE * 1 => 16.5 seconds
     * SHRED_PAGE_SIZE * 2 => 16.5 seconds
     * SHRED_PAGE_SIZE * 4 => 15.9 seconds
     * SHRED_PAGE_SIZE * 8 => 15.8 seconds */

    shredder.hasher = rm_hasher_new(cfg->checksum_type,
                                    cfg->threads,
                                    cfg->use_buffered_read,
                                    shredder.buffer_size,
                                    read_buffer_mem,
                                    (RmHasherCallback)rm_shred_hash_callback,
                                    &shredder);

    rm_mds_configure(shredder.mds,
                     (RmMDSFunc)rm_shred_process_file,
                     &shredder,
                     cfg->sweep_count,
                     cfg->threads_per_hdd,
                     cfg->threads_per_ssd,
                     (RmMDSSortFunc)rm_mds_elevator_cmp,
                     NULL);
    rm_mds_start(shredder.mds);
    shredder.mds_paused = TRUE;

    /* optional (reduces speed but makes counting nicer): */
    rm_mds_pause(shredder.mds);

    rm_shred_preprocess_input(&shredder, tables);
    shredder.after_preprocess = TRUE;  // TODO: eliminate

    /* optional (see above): */
    rm_mds_resume(shredder.mds);

    /* should complete shred session and then free: */
    rm_mds_free(shredder.mds, FALSE);
    rm_hasher_free(shredder.hasher, TRUE);

    g_mutex_clear(&shredder.hash_mem_mtx);
}
