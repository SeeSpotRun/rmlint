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

/* how many pages can we read in (seek_time)/(CHEAP)? (use for initial read) */
#define SHRED_BALANCED_PAGES (4)

/* How large a single page is (typically 4096 bytes but not always)*/
#define SHRED_PAGE_SIZE (sysconf(_SC_PAGESIZE))

#define SHRED_MAX_READ_FACTOR \
    ((256 * 1024 * 1024) / SHRED_BALANCED_PAGES / SHRED_PAGE_SIZE)

/* Maximum increment size for paranoid digests.  This is smaller than for other
 * digest types due to memory management issues.
 * 16MB should be big enough buffer size to make seek time fairly insignificant
 * relative to sequential read time, eg 16MB read at typical 100 MB/s read
 * rate = 160ms read vs typical seek time 10ms*/
#define SHRED_PARANOID_BYTES (16 * 1024 * 1024)

/* When paranoid hashing, if a file increments is larger
 * than SHRED_PREMATCH_THRESHOLD, we take a guess at the likely
 * matching file and do a progressive memcmp() on each buffer
 * rather than waiting until the whole increment has been read
 * */
#define SHRED_PREMATCH_THRESHOLD (0)

/* empirical estimate of mem usage per file (excluding read buffers and
 * paranoid digests) */
#define SHRED_AVERAGE_MEM_PER_FILE (100)

/* Maximum number of bytes before worth_waiting becomes false */
#define SHRED_TOO_MANY_BYTES_TO_WAIT (64 * 1024 * 1024)

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
    gint32 page_size;
    bool mem_refusing;

    GMutex lock;

    gint32 remaining_files;
    gint64 remaining_bytes;

    bool after_preprocess : 1;
    bool mds_paused : 1;

} RmShredTag;

#define NEEDS_PREF(group) (group->shredder->cfg->must_match_tagged)
#define NEEDS_NPREF(group) (group->shredder->cfg->keep_all_tagged)
#define NEEDS_NEW(group) (group->shredder->cfg->min_mtime)

#define HAS_CACHE(shredder) (shredder->cfg->read_cksum_from_xattr)

#define NEEDS_SHADOW_HASH(cfg) (cfg->merge_directories || cfg->read_cksum_from_xattr)
/* Performance is faster with shadow hash, probably due to hash collisions in
 * large RmShredGroups */

typedef struct RmShredGroup {
    /* holding queue for files; they are held here until the group first meets
     * criteria for further hashing (normally just 2 or more files, but sometimes
     * related to preferred path counts)
     * */
    GQueue *held_files;

    /* link(s) to next generation of RmShredGroups(s) which have this RmShredGroup as
     * parent*/
    GHashTable *children;

    /* RmShredGroup of the same size files but with lower RmFile->hash_offset;
     * getsset to null when parent dies
     * */
    struct RmShredGroup *parent;

    /* total number of files that have passed through this group (including
     * bundled hardlinked files) */
    gulong num_files;

    /* number of pending digests (ignores bundled hardlink files)*/
    gulong num_pending;

    /* set if group has 1 or more files from "preferred" paths */
    bool has_pref : 1;

    /* set if group has 1 or more files from "non-preferred" paths */
    bool has_npref : 1;

    /* set if group has 1 or more files newer than cfg->min_mtime */
    bool has_new : 1;

    /* true if all files in the group have an external checksum */
    bool has_only_ext_cksums : 1;

    /* incremented for each file in the group that obtained its checksum from ext.
     * If all files came from there we do not even need to hash the group.
     */
    gulong num_ext_cksums;

    /* if whole group has same basename, pointer to first file, else null */
    RmFile *unique_basename;

    /* initially RM_SHRED_GROUP_DORMANT; triggered as soon as we have >= 2 files
     * and meet preferred path and will go to either RM_SHRED_GROUP_HASHING or
     * RM_SHRED_GROUP_FINISHING.  When switching from dormant to hashing, all
     * held_files are released and future arrivals go straight to hashing
     * */
    RmShredGroupStatus status;

    /* file size of files in this group */
    RmOff file_size;

    /* file hash_offset when files arrived in this group */
    RmOff hash_offset;

    /* file hash_offset for next increment */
    RmOff next_offset;

    /* Factor of SHRED_BALANCED_PAGES to read next time */
    gint64 offset_factor;

    /* checksum structure taken from first file to enter the group.  This allows
     * digests to be released from RmFiles and memory freed up until they
     * are required again for further hashing.*/
    RmDigestType digest_type;
    RmDigest *digest;

    /* lock for access to this RmShredGroup */
    GMutex lock;

    /* Reference to main */
    RmShredTag *shredder;
} RmShredGroup;

/////////// RmShredGroup ////////////////

/* allocate and initialise new RmShredGroup; uses file's digest type if available */
static RmShredGroup *rm_shred_group_new(RmFile *file, RmShredTag *shredder) {
    RmShredGroup *self = g_slice_new0(RmShredGroup);

    rm_assert_gentle(shredder);
    if(file->digest) {
        self->digest_type = file->digest->type;
        self->digest = file->digest;
        file->digest = NULL;
    }

    self->parent = file->shred_group;
    self->shredder = shredder;

    if(self->parent) {
        self->offset_factor = MIN(self->parent->offset_factor * 8, SHRED_MAX_READ_FACTOR);
    } else {
        self->offset_factor = 1;
    }

    self->held_files = g_queue_new();
    self->file_size = file->file_size;
    self->hash_offset = file->hash_offset;

    g_mutex_init(&self->lock);

    return self;
}

//////////////////////////////////
// OPTIMISATION AND MEMORY      //
// MANAGEMENT ALGORITHMS        //
//////////////////////////////////

/* Compute optimal size for next hash increment call this with group locked */
static gint32 rm_shred_get_read_size(RmFile *file, RmShredTag *shredder) {
    RmShredGroup *group = file->shred_group;
    rm_assert_gentle(group);

    gint32 result = 0;

    /* calculate next_offset property of the RmShredGroup */
    RmOff balanced_bytes = shredder->page_size * SHRED_BALANCED_PAGES;
    RmOff target_bytes = balanced_bytes * group->offset_factor;
    if(group->next_offset == 2) {
        file->fadvise_requested = 1;
    }

    /* round to even number of pages, round up to MIN_READ_PAGES */
    RmOff target_pages = MAX(target_bytes / shredder->page_size, 1);
    target_bytes = target_pages * shredder->page_size;

    /* test if cost-effective to read the whole file */
    if(group->hash_offset + target_bytes + (balanced_bytes) >= group->file_size) {
        group->next_offset = group->file_size;
        file->fadvise_requested = 1;
    } else {
        group->next_offset = group->hash_offset + target_bytes;
    }

    /* for paranoid digests, make sure next read is not > max size of paranoid buffer */
    if(group->digest_type == RM_DIGEST_PARANOID) {
        group->next_offset =
            MIN(group->next_offset, group->hash_offset + SHRED_PARANOID_BYTES);
    }

    file->status = RM_FILE_STATE_NORMAL;
    result = (group->next_offset - file->hash_offset);

    return result;
}

/* Memory manager (only used for RM_DIGEST_PARANOID at the moment
 * but could also be adapted for other digests if very large
 * filesystems are contemplated)
 */
static gint64 rm_shred_mem_adjust(RmShredTag *shredder, gint files, gint64 size) {
    if(shredder->after_preprocess || shredder->cfg->checksum_type != RM_DIGEST_PARANOID) {
        return 1;
    }
    gint64 result;
    g_mutex_lock(&shredder->hash_mem_mtx);
    {
        shredder->paranoid_mem_alloc += (gint64)files * MIN(size, SHRED_PARANOID_BYTES);
        result = shredder->paranoid_mem_alloc;
        g_cond_signal(&shredder->hash_mem_cond);
    }
    g_mutex_unlock(&shredder->hash_mem_mtx);
    return result;
}

///////////////////////////////////
//       Progress Reporting      //
///////////////////////////////////

void rm_shred_buffer_free(RmShredBuffer *buffer) {
    /* do not free group; caller owns that */
    g_slice_free(RmShredBuffer, buffer);
}

RmShredBuffer *rm_shred_buffer_new(GQueue *files, gint delta_files, gint64 delta_bytes) {
    RmShredBuffer *buffer = g_slice_new(RmShredBuffer);
    buffer->delta_files = delta_files;
    buffer->delta_bytes = delta_bytes;
    buffer->finished_files = files;
    return buffer;
}

/* send updates and/or results to session.c */
static void rm_shred_send(RmShredTag *shredder, GQueue *files, gint delta_files,
                          gint64 delta_bytes) {
    gint64 file_size = 0;
    if(files) {
        RmFile *head = files->head->data;
        rm_assert_gentle(head);
        file_size = head->file_size;
#if _RM_SHRED_DEBUG
        RM_DEFINE_PATH(head);
        rm_log_debug_line("Forwarding %s's group", head_path);
#endif

        /* unref files from MDS */
        /* TODO: maybe do this in rm_shred_group_find_original */
        rm_assert_gentle(delta_bytes == 0);
        rm_assert_gentle(delta_files == 0);
        for(GList *iter = files->head; iter; iter = iter->next) {
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

    /* adjust hash mem allowance */
    if(delta_files != 0) {
        if(file_size == 0) {
            file_size = delta_bytes / delta_files;
        }
        rm_shred_mem_adjust(shredder, -delta_files, file_size);
    }
    /* send to session.c */
    g_thread_pool_push(shredder->shredder_pipe,
                       rm_shred_buffer_new(files, delta_files, delta_bytes), NULL);
}

/* Unlink dead RmFile from Shredder
 */
static void rm_shred_discard_file(RmFile *file, RmLintType lint_type) {
    rm_assert_gentle(file);
    file->lint_type = lint_type;
    rm_assert_gentle(file->shred_group->shredder);
    RmShredTag *shredder = file->shred_group->shredder;

    /* session.c expects files in a GQueue; can't send file directly*/
    GQueue *coffin = g_queue_new();
    g_queue_push_head(coffin, file);

    rm_shred_send(shredder, coffin, 0, 0);
}

/* Push file to scheduler queue.
 * */
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

/* Free RmShredGroup and any dormant files still in its queue
 */
static void rm_shred_group_free(RmShredGroup *self, bool free_digest) {
    rm_assert_gentle(self->parent == NULL); /* children should outlive their parents! */
    rm_assert_gentle(self->num_pending == 0);

    if(self->held_files) {
        rm_assert_gentle(self->held_files->length == 0);
    }

    if(self->digest && free_digest) {
        rm_digest_free(self->digest);
        self->digest = NULL;
    }

    if(self->children) {
        /* note: calls GDestroyNotify function rm_shred_group_make_orphan()
         * for each RmShredGroup member of self->children: */
        g_hash_table_unref(self->children);
    }

    g_mutex_clear(&self->lock);

    g_slice_free(RmShredGroup, self);
}

/* prepare a finished shred_group for output */
static void rm_shred_group_output(RmShredGroup *group) {
    if(g_queue_get_length(group->held_files) > 0) {
        /* find the original(s) (note this also unbundles hardlinks and sorts
         * the group from highest ranked to lowest ranked
         */
        rm_shred_group_find_original(group->shredder->cfg, group->held_files,
                                     group->status);

        /* Point the files to their (shared) digest */
        for(GList *iter = group->held_files->head; iter; iter = iter->next) {
            RmFile *file = iter->data;
            file->digest = group->digest;
        }

        /* send files to session for output and file freeing */
        rm_shred_send(group->shredder, group->held_files, 0, 0);
        group->held_files = NULL;
    }

    if(group->status == RM_SHRED_GROUP_FINISHING) {
        group->status = RM_SHRED_GROUP_FINISHED;
    }
    /* Do not free digest, output module will do that. */
    rm_shred_group_free(group, false);
}

/* call unlocked; should be no contention issues since group is finished */
static void rm_shred_group_finalise(RmShredGroup *self) {
    /* return any paranoid mem allocation */
    switch(self->status) {
    case RM_SHRED_GROUP_DORMANT:
        /* Dead-ended files; may still be wanted by some output formatters */
        rm_shred_group_output(self);
        break;
    case RM_SHRED_GROUP_START_HASHING:
    case RM_SHRED_GROUP_HASHING:
        /* intermediate increment group no longer required; free group and digest */
        rm_assert_gentle(!self->held_files);
        rm_shred_group_free(self, TRUE);
        break;
    case RM_SHRED_GROUP_FINISHING:
        /* free any paranoid buffers held in group->digest (should not be needed for
         * results processing */
        if(self->digest_type == RM_DIGEST_PARANOID) {
            rm_digest_release_buffers(self->digest);
        }
        /* send it to finisher (which takes responsibility for calling
         * rm_shred_group_free())*/
        /* TODO: direct call */
        rm_shred_group_output(self);
        break;
    case RM_SHRED_GROUP_FINISHED:
    default:
        rm_assert_gentle_not_reached();
    }
}

/* Checks whether group qualifies as duplicate candidate (ie more than
 * two members and meets has_pref and NEEDS_PREF criteria).
 * Assume group already protected by group_lock.
 * */
static void rm_shred_group_update_status(RmShredGroup *group) {
    if(group->status == RM_SHRED_GROUP_DORMANT) {
        if(1 && group->num_files >= 2 /* it takes 2 to tango */
           &&
           (group->has_pref || !NEEDS_PREF(group))
           /* we have at least one file from preferred path, or we don't care */
           &&
           (group->has_npref || !NEEDS_NPREF(group))
           /* we have at least one file from non-pref path, or we don't care */
           &&
           (group->has_new || !NEEDS_NEW(group))
           /* we have at least one file newer than cfg->min_mtime, or we don't care */
           &&
           (!group->unique_basename || !group->shredder->cfg->unmatched_basenames)
           /* we have more than one unique basename, or we don't care */
           ) {
            if(group->hash_offset < group->file_size &&
               group->has_only_ext_cksums == false) {
                /* group can go active */
                group->status = RM_SHRED_GROUP_START_HASHING;
            } else {
                group->status = RM_SHRED_GROUP_FINISHING;
            }
        }
    }
}

/* Only called by rm_shred_group_free (via GDestroyNotify of group->children).
 * Call with group->lock unlocked.
 */
static void rm_shred_group_make_orphan(RmShredGroup *self) {
    gboolean group_finished = FALSE;
    g_mutex_lock(&self->lock);
    {
        self->parent = NULL;
        group_finished = (self->num_pending == 0);
    }
    g_mutex_unlock(&self->lock);

    if(group_finished) {
        rm_shred_group_finalise(self);
    }
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

/* Call with shred_group->lock unlocked. */
static RmFile *rm_shred_group_push_file(RmShredGroup *shred_group, RmFile *file) {
    RmFile *result = NULL;
    rm_assert_gentle(shred_group);
    file->shred_group = shred_group;

    if(file->digest) {
        rm_digest_free(file->digest);
        file->digest = NULL;
    }

    g_mutex_lock(&shred_group->lock);
    {
        shred_group->has_pref |= file->is_prefd || file->hardlinks.has_prefd;
        shred_group->has_npref |= (!file->is_prefd) || file->hardlinks.has_non_prefd;
        shred_group->has_new |= file->is_new_or_has_new;

        if(shred_group->num_files == 0 &&
           shred_group->shredder->cfg->unmatched_basenames) {
            shred_group->unique_basename = file;
        } else if(shred_group->unique_basename &&
                  rm_file_basenames_cmp(file, shred_group->unique_basename) != 0) {
            shred_group->unique_basename = NULL;
        }
        shred_group->num_files += rm_shred_num_files(file);
        if(file->hardlinks.is_head && shred_group->unique_basename &&
           shred_group->shredder->cfg->unmatched_basenames) {
            for(GList *iter = file->hardlinks.files->head; iter; iter = iter->next) {
                if(rm_file_basenames_cmp(iter->data, shred_group->unique_basename) != 0) {
                    shred_group->unique_basename = NULL;
                    break;
                }
            }
        }

        rm_assert_gentle(file->hash_offset == shred_group->hash_offset);

        rm_shred_group_update_status(shred_group);
        switch(shred_group->status) {
        case RM_SHRED_GROUP_START_HASHING:
            /* clear the queue and push all its rmfiles to the md-scheduler */
            if(shred_group->held_files) {
                shred_group->num_pending += g_queue_get_length(shred_group->held_files);
                g_queue_free_full(shred_group->held_files,
                                  (GDestroyNotify)rm_shred_push_queue);
                shred_group->held_files = NULL; /* won't need shred_group queue any more,
                                                   since new arrivals will bypass */
            }
        /* FALLTHROUGH */
        case RM_SHRED_GROUP_HASHING:
            shred_group->num_pending++;
            if(!file->shredder_waiting) {
                /* add file to device queue */
                rm_shred_push_queue(file);
            } else {
                /* calling routine will handle the file */
                result = file;
            }
            break;
        case RM_SHRED_GROUP_DORMANT:
        case RM_SHRED_GROUP_FINISHING:
            /* add file to held_files */
            g_queue_push_head(shred_group->held_files, file);
            break;
        case RM_SHRED_GROUP_FINISHED:
        default:
            rm_assert_gentle_not_reached();
        }
    }
    g_mutex_unlock(&shred_group->lock);

    return result;
}

/* After partial hashing of RmFile, add it back into the sieve for further
 * hashing if required.  If waiting option is set, then try to return the
 * RmFile to the calling routine so it can continue with the next hashing
 * increment (this bypasses the normal device queue and so avoids an unnecessary
 * file seek operation ) returns true if the file can be immediately be hashed
 * some more.
 * */
static RmFile *rm_shred_sift(RmFile *file) {
    RmFile *result = NULL;
    gboolean current_group_finished = FALSE;

    rm_assert_gentle(file);
    RmShredGroup *current_group = file->shred_group;
    rm_assert_gentle(current_group);

    g_mutex_lock(&current_group->lock);
    {
        current_group->num_pending--;

        if(file->status == RM_FILE_STATE_IGNORE) {
            /* reading/hashing failed somewhere */
            rm_shred_discard_file(file, RM_LINT_TYPE_READ_ERROR);

        } else {
            rm_assert_gentle(file->digest);

            /* check is child group hashtable has been created yet */
            if(current_group->children == NULL) {
                current_group->children =
                    g_hash_table_new_full((GHashFunc)rm_digest_hash,
                                          (GEqualFunc)rm_digest_equal,
                                          NULL,
                                          (GDestroyNotify)rm_shred_group_make_orphan);
            }

            /* check if there is already a descendent of current_group which
             * matches snap... if yes then move this file into it; if not then
             * create a new group ... */
            RmShredGroup *child_group =
                g_hash_table_lookup(current_group->children, file->digest);
            if(!child_group) {
                child_group = rm_shred_group_new(file, current_group->shredder);
                g_hash_table_insert(current_group->children, child_group->digest,
                                    child_group);
                child_group->has_only_ext_cksums = current_group->has_only_ext_cksums;
            }
            rm_assert_gentle(child_group);
            result = rm_shred_group_push_file(child_group, file);
        }

        /* is current shred group needed any longer? */
        current_group_finished =
            !current_group->parent && current_group->num_pending == 0;
    }
    g_mutex_unlock(&current_group->lock);

    if(current_group_finished) {
        rm_shred_group_finalise(current_group);
    }

    return result;
}

/* Hasher callback when file increment hashing is completed.
 * */
static void rm_shred_hash_callback(_UNUSED RmHasher *hasher, RmDigest *digest,
                                   _UNUSED RmShredTag *shredder, RmFile *file) {
    if(!file->digest) {
        file->digest = digest;
    }
    rm_assert_gentle(file->digest == digest);
    rm_assert_gentle(file->hash_offset == file->shred_group->next_offset);

    if(file->status != RM_FILE_STATE_IGNORE && shredder->cfg->write_cksum_to_xattr &&
       file->has_ext_cksum == false) {
        /* remember that checksum */
        rm_xattr_write_hash(shredder->cfg, file);
    }

    rm_shred_sift(file);
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
static void rm_shred_file_preprocess(RmFile *file, RmShredGroup *group) {
    /* initial population of RmShredDevice's and first level RmShredGroup's */
    RmShredTag *shredder = group->shredder;
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

    rm_assert_gentle(group);
    rm_shred_group_push_file(group, file);

    if(cfg->read_cksum_from_xattr) {
        char *ext_cksum = rm_xattr_read_hash(shredder->cfg, file);
        if(ext_cksum != NULL) {
            file->folder->data = ext_cksum;
        }
    }

    if(HAS_CACHE(shredder)) {
        if(rm_trie_search(&cfg->file_trie, file_path)) {
            group->num_ext_cksums += 1;
            file->has_ext_cksum = 1;
        }
    }
}

static void rm_shred_preprocess_group(GSList *files, RmShredTag *shredder) {
    /* push files to shred group */
    rm_assert_gentle(files);
    rm_assert_gentle(files->data);

    RmFile *first = files->data;
    RmShredGroup *group = rm_shred_group_new(first, shredder);
    group->parent = GINT_TO_POINTER(1); /* dummy parent to prevent premature free */
    group->digest_type = shredder->cfg->checksum_type;
    group->shredder = shredder;

    g_slist_foreach(files, (GFunc)rm_shred_file_preprocess, group);
    g_slist_free(files);

    /* check if group has external checksums for all files */
    if(HAS_CACHE(shredder) && group->num_files == group->num_ext_cksums) {
        group->has_only_ext_cksums = true;
    }

    rm_assert_gentle(group);
    /* give the group its independence */
    rm_shred_group_make_orphan(group);

    /* check paranoid mem avail - hold back groups if out of mem */
    g_mutex_lock(&shredder->hash_mem_mtx);
    {
        while(shredder->paranoid_mem_alloc <= 0) {
            rm_log_debug_line("shredder: waiting for mem");
            if(shredder->mds_paused) {
                rm_mds_resume(shredder->mds);
                shredder->mds_paused = FALSE;
            }
            g_cond_wait(&shredder->hash_mem_cond, &shredder->hash_mem_mtx);
        }
    }
    g_mutex_unlock(&shredder->hash_mem_mtx);
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
static gint rm_shred_remove_basename_matches(RmFile *file, RmFile *headfile) {
    if(file == headfile) {
        return 0;
    }
    if(rm_file_basenames_cmp(file, headfile) != 0) {
        return 0;
    }
    /* TODO: report as ?unique? file */
    rm_shred_discard_file(file, RM_LINT_TYPE_BASENAME_TWIN);
    return 1;
}

/* iterate over group to find highest ranked; return it and tag it as original    */
/* also in special cases (eg keep_all_tagged) there may be more than one original,
 * in which case tag them as well
 */
void rm_shred_group_find_original(RmCfg *cfg, GQueue *files, RmShredGroupStatus status) {
    /* iterate over group, unbundling hardlinks and identifying "tagged" originals */
    for(GList *iter = files->head; iter; iter = iter->next) {
        RmFile *file = iter->data;
        file->is_original = false;

        if(file->hardlinks.is_head && file->hardlinks.files) {
            /* if group member has a hardlink cluster attached to it then
             * unbundle the cluster and append it to the queue
             */
            GQueue *hardlinks = file->hardlinks.files;
            for(GList *link = hardlinks->head; link; link = link->next) {
                RmFile *link_file = link->data;
                // hacky workaround after deleting file->session from RmFile struct:
                link_file->shred_group =
                    file->shred_group;  // TODO: make this unnecessary
                g_queue_push_tail(files, link->data);
            }
            g_queue_free(hardlinks);
            file->hardlinks.files = NULL;
        }
        if(status == RM_SHRED_GROUP_FINISHING) {
            /* identify "tagged" originals: */
            if((file->is_prefd) && (cfg->keep_all_tagged)) {
                file->is_original = true;

#if _RM_SHRED_DEBUG
                RM_DEFINE_PATH(file);
                rm_log_debug_line("tagging %s as original because tagged", file_path);
#endif
            }
        } else {
            file->lint_type = RM_LINT_TYPE_UNIQUE_FILE;
        }
    }

    /* sort the unbundled group */
    g_queue_sort(files, (GCompareDataFunc)rm_file_cmp_orig_criteria, cfg);

    RmFile *headfile = files->head->data;
    if(!headfile->is_original && status == RM_SHRED_GROUP_FINISHING) {
        headfile->is_original = true;

#if _RM_SHRED_DEBUG
        RM_DEFINE_PATH(headfile);
        rm_log_debug_line("tagging %s as original because it is highest ranked",
                          headfile_path);
#endif
    }
    if(cfg->unmatched_basenames && status == RM_SHRED_GROUP_FINISHING) {
        /* remove files which match headfile's basename */
        rm_util_queue_foreach_remove(files, (RmRFunc)rm_shred_remove_basename_matches,
                                     files->head->data);
    }
}

/////////////////////////////////
//    ACTUAL IMPLEMENTATION    //
/////////////////////////////////

static void rm_shred_reassign_checksum(RmShredTag *shredder, RmFile *file) {
    RmCfg *cfg = shredder->cfg;
    RmShredGroup *group = file->shred_group;

    if(group->has_only_ext_cksums) {
        /* Cool, we were able to read the checksum from disk */
        file->digest = rm_digest_new(RM_DIGEST_EXT, 0, 0, 0, NEEDS_SHADOW_HASH(cfg));

        RM_DEFINE_PATH(file);

        char *hexstring = file->folder->data;

        if(hexstring != NULL) {
            rm_digest_update(file->digest, (unsigned char *)hexstring, strlen(hexstring));
            rm_log_debug_line("%s=%s was read from cache.", hexstring, file_path);
        } else {
            rm_log_warning_line(
                "Unable to read external checksum from interal cache for %s", file_path);
            file->has_ext_cksum = 0;
            group->has_only_ext_cksums = 0;
        }
    } else if(group->digest_type == RM_DIGEST_PARANOID) {
        file->digest = rm_digest_new(RM_DIGEST_PARANOID, 0, 0, 0, NEEDS_SHADOW_HASH(cfg));
    } else if(group->digest) {
        /* pick up the digest-so-far from the RmShredGroup */
        file->digest = rm_digest_copy(group->digest);
    } else {
        /* this is first generation of RMGroups, so there is no progressive hash yet */
        file->digest = rm_digest_new(cfg->checksum_type,
                                     cfg->hash_seed1,
                                     cfg->hash_seed2,
                                     0,
                                     NEEDS_SHADOW_HASH(cfg));
    }
}

/* Callback for RmMDS
 * Return value of 1 tells md-scheduler that we have processed the file and either
 * disposed of it or pushed it back to the scheduler queue.
 * Return value of 0 tells md-scheduler we can't process the file right now, and
 * have pushed it back to the queue.
 * */
static gint rm_shred_process_file(RmFile *file, RmShredTag *shredder) {
    if(rm_session_was_aborted() || file->shred_group->has_only_ext_cksums) {
        if(rm_session_was_aborted()) {
            file->status = RM_FILE_STATE_IGNORE;
        } else if(file->shred_group->has_only_ext_cksums) {
            rm_shred_reassign_checksum(shredder, file);
        }
        file->shredder_waiting = FALSE;
        rm_shred_sift(file);
        return 1;
    }

    RM_DEFINE_PATH(file);

    if(!file->digest) {
        rm_shred_reassign_checksum(shredder, file);
    }
    /* hash the next increment of the file */
    RmOff bytes_to_read = rm_shred_get_read_size(file, shredder);

    RmHasherTask *task = rm_hasher_task_new(shredder->hasher, file->digest, file);
    if(!rm_hasher_task_hash(task, file_path, file->hash_offset, bytes_to_read,
                            file->is_symlink)) {
        /* rm_hasher_start_increment failed somewhere */
        file->status = RM_FILE_STATE_IGNORE;
    }

    /* Update totals for file, device and session*/
    file->hash_offset += bytes_to_read;
    if(file->is_symlink) {
        rm_shred_send(shredder, NULL, 0, -(gint64)file->file_size);
    } else {
        rm_shred_send(shredder, NULL, 0, -(gint64)bytes_to_read);
    }

    /* tell the hasher we have finished */
    rm_hasher_task_finish(task);

    /* rm_shred_hash_callback will take care of the file */
    file = NULL;

    return 1;
}

void rm_shred_run(RmCfg *cfg, RmFileTables *tables, RmMDS *mds,
                  GThreadPool *shredder_pipe, guint total_files) {
    RmShredTag shredder;
    shredder.mem_refusing = false;
    shredder.shredder_pipe = shredder_pipe;
    shredder.cfg = cfg;
    shredder.mds = mds;
    shredder.paranoid_mem_alloc = G_MAXINT64;

    shredder.page_size = SHRED_PAGE_SIZE;

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
                                    SHRED_PAGE_SIZE * 4,
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
