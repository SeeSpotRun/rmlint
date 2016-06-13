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
 * During preprocessing, files were already grouped into candidate
 * sets (basically files of the same size, although additional criteria
 * may apply depending on settings).
 *
 * Shredder creates an "RmShredTree" for each group and then progressively
 * reads data from tree files, comparing the files after a predefined
 * sequence of increments (based on defined constants SHRED_FIRST_INCREMENT
 * and SHRED_ACCELERATION values of 4kb and 8 respectively, the increment
 * series is 4kb, 4kb, 32kb, 256kb, 2MB, 16MB...)
 *
 * Each RmShredTree builds a node tree of partial matches.  The tree forks
 * each time a file increment differs from its siblings.
 *
 * File increment comparison is either with one of the checksum types defined
 * in checksum.[ch]; the checksum used depends on the rmlint command-line
 * options (the default is SHA1).
 *
 * File reading is scheduled via md-scheduler.[ch] ('MDS'), which optimises
 * read order on hdd's in order to minimise seek time.  MDS creates a
 * threadpool so multiple disks are read in parallel.
 *
 * The file data read in is sent to a second set of threadpools managed
 * by hasher.[ch] which does the checksum hashing and RmShredTree node
 * comparisons.  Note that the hasher "threadpool" is actually a
 * collection of single-threaded threadpools which ensure that file
 * increments are hashed on a FIFO basis.
 *
 * By decoupling reading and hashing, the reader threads
 * run continuously, with no delay for hash calculation time.
 *
 * Shredder's algorithm decides how many increments of each file to
 * read before moving on to the next file:
 *   On ssd's, only one increment is read at a time
 *   On hdd's, increments are read until the file has moved 2 increments
 * past its last partially-matched twin.
 *
 *
 * There is an option for a special case called "paranoid" checksum; in
 * this case the file data is compared byte-by-byte (no hash used).  This
 * is very memory-hungry, so a special memory manager is applied which
 * limits the number of trees being concurrently processed.
 *
 *
 * As trees and nodes reach their endpoints (either end of file, or
 * dead-end due to lack of partially-matched siblings), the node's files
 * are sent to session.c for outputting (via a single-threaded threadpool).
 *
 */

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
#define SHRED_FIRST_INCREMENT (4 * 1024)

/* Maximum increment size for digests; increments bigger than this would
 * give negligible seek savings and risk hashing past the point where two
 * files diverge
 */
#define SHRED_MAX_INCREMENT (256 * 1024 * 1024)

/* Maximum increment size for paranoid digests.  This is smaller than for other
 * digest types due to memory management issues.
 * Note that on hdd's, the shredder algorithm normally reads two increments
 * at a time.  For SHRED_MAX_PARANOID == 32MB, that gives 64MB read between
 * seeks.  At a "typical" 4TB NAS drive sequential read rate of 150 MB/s and seek
 * time of ~15 ms, that means each 64MB read takes 15ms to access the start and
 * then ~430 ms to read the data, so the seek speed penalty is around 3.5% */
#define SHRED_MAX_PARANOID (32 * 1024 * 1024)

/* How quickly to (geometrically) increase increment size */
#define SHRED_ACCELERATION (8)

/* empirical estimate of mem overhead per file (excluding memory for
 * reading, hashing and paranoid comparisons) */
#define SHRED_AVERAGE_MEM_PER_FILE (100)

///////////////////////////////
//    INTERNAL STRUCTURES    //
///////////////////////////////

/**
 * RmShredSession contains common data accessible to shredder's procedures
 */
typedef struct RmShredSession {
    /* rmlint settings */
    RmCfg *cfg;

    /* memory budgeting for paranoid digests (and associated mutex & cond) */
    gint64 paranoid_mem_alloc; /* how much memory available for paranoid checks */
    GMutex hash_mem_lock;
    GCond hash_mem_cond;

    /* RmHasher object for reading/hashing file data (refer hasher.[ch]) */
    RmHasher *hasher;

    /* buffer size used for hasher */
    RmOff buffer_size;

    /* RmMDS object for optimally scheduling read jobs on multiple
     * hdd's & ssd's */
    RmMDS *mds;

    /* single-threaded threadpool for sending files and progress updates
     * to session.c */
    GThreadPool *shredder_pipe;

    /* Un-launched RmShredTrees held back pending paranoid mem availability */
    GSList *trees;

    /* number of bytes to read/hash on first file increment */
    RmOff first_increment;

    /* largest single file increment size (bytes) */
    RmOff max_increment;

    /* flag indicating file preprocessing finished */
    bool after_preprocess : 1;

    /* flag indicating mds started */
    bool mds_started : 1;

} RmShredSession;

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

    /* set if group has 1 or more files from "preferred" (tagged) paths */
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

    /* if the tree hdd files, the lowest disk offset of those files */
    RmOff min_offset;

    /* Reference to main */
    RmShredSession *shredder;
} RmShredTree;

//////////////////////////////////////////////
//  Post-processing and Progress Reporting  //
//////////////////////////////////////////////

/**
 *  rm_shred_buffer_new creates a new buffer for communicating back to session.c
 */
static RmShredBuffer *rm_shred_buffer_new(GSList *files, gint64 delta_bytes) {
    RmShredBuffer *buffer = g_slice_new(RmShredBuffer);
    buffer->delta_bytes = delta_bytes;
    buffer->finished_files = files;
    return buffer;
}

/**
 * rm_shred_send sends updates and/or results to session.c */
static void rm_shred_send(RmShredSession *shredder, GSList *files, gint64 delta_bytes) {
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

        for(GSList *iter = files; iter; iter = iter->next) {
            RmFile *file = iter->data;
            if(!RM_IS_BUNDLED_HARDLINK(file)) {
                rm_assert_gentle(file->disk);
                rm_mds_device_ref(file->disk, -1);
                file->disk = NULL;
            }
        }
    }

    /* send to session.c */
    g_thread_pool_push(shredder->shredder_pipe, rm_shred_buffer_new(files, delta_bytes),
                       NULL);
}

/**
 * rm_shred_file_discard sends a dead RmFile to session.c
 */
static void rm_shred_file_discard(RmFile *file) {
    rm_assert_gentle(file);
    rm_assert_gentle(file->shred_node);
    RmShredSession *shredder = file->shred_node->tree->shredder;

    /* session.c expects files in a GSList; can't send file directly*/
    GSList *coffin = g_slist_append(NULL, file);
    rm_shred_send(shredder, coffin, 0);
}

/////////////////////////////////
//       POST PROCESSING       //
/////////////////////////////////

/**
 * rm_shred_remove_basename_matches extracts files with same basename as
 * headfile and sends them to session.c as RM_LINT_TYPE_BASENAME_TWIN.
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
    rm_shred_file_discard(file);
    return 1;
}

/**
 * rm_shred_group_find_original iterates over a list of duplicates to find highest
 * ranked which is tagged as original;
 * in special cases (eg keep_all_tagged) there may be more than one original,
 * in which case tag them as well.
 * Any bundled hardlinks are unbundled.
 * If cfg->unmatched_basenames then any files which match headfile's basename.
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

//////////////////////////////////////////////
//        Interface with md-scheduler       //
//////////////////////////////////////////////

/**
 * rm_shred_get_read_size computes size for next hash increment
 */
static gint32 rm_shred_get_read_size(RmFile *file, RmOff read_offset,
                                     RmShredSession *shredder) {
    rm_assert_gentle(read_offset < file->file_size);

    RmOff target = read_offset * SHRED_ACCELERATION + shredder->first_increment;
    /* eg for first_increment == 10 and SHRED_ACCELERATION == 4
     *   -> 10,  50,  210,  850...
     *    (+10)(+40)(+160)(+640)...
     */

    /* don't over-shoot file */
    target = MIN(target, file->file_size);

    RmOff result = target - read_offset;

    /* don't exceed max increment */
    result = MIN(result, shredder->max_increment);

    rm_assert_gentle(result > 0);
    return result;
}

/**
 * rm_shred_file_set_offset reads (if applicable) the disk offset of file
 * into file->disk_offset
 */
static void rm_shred_file_set_offset(RmFile *file) {
    if(file->disk_offset != (RmOff)-1) {
        /* already set */
        return;
    }
    if(file->cfg->build_fiemap && rm_mds_device_is_rotational(file->disk)) {
        RM_DEFINE_PATH(file);
        file->disk_offset = rm_offset_get_from_path(file_path, 0, NULL);
    } else {
        /* use inode number instead of disk offset */
        file->disk_offset = file->inode;
    }
}

/**
 * rm_shred_file_schedule sends a file to md-scheduler.c for scheduling.
 */
static void rm_shred_file_schedule(RmFile *file) {
    rm_shred_file_set_offset(file);
    rm_mds_push_task(file->disk, file->dev, file->disk_offset, NULL, file);
}

//////////////////////////////////////////////
// RmShredNode & RmShredTree Implementation //
//////////////////////////////////////////////

/** rm_shred_node_init initialises an RmShredNode using file and sum as a template;
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

/** rm_shred_node_new allocates a new RmShredNode and initialises it
 * based on file and sum.
 * Takes ownership of sum.
 **/
static RmShredNode *rm_shred_node_new(RmFile *file, RmDigestSum *sum) {
    RmShredNode *self = g_slice_new0(RmShredNode);
    rm_shred_node_init(self, file, sum);

    return self;
}

static void rm_shred_node_launch_held(RmShredNode *node) {
    /* push any held files to the md-scheduler for hashing */
    while(node->held_files) {
        node->num_pending++;
        RmFile *held = node->held_files->data;
        rm_shred_file_schedule(held);
        node->held_files = g_slist_delete_link(node->held_files, node->held_files);
    }
}

/**
 * rm_shred_node_free_sum frees node's checksum (if any)
 */
static inline void rm_shred_node_free_sum(RmShredNode *node) {
    if(node->sum) {
        rm_digest_sum_free(node->sum);
        node->sum = NULL;
    }
}

/**
 * rm_shred_node_free frees an RmShredNode and associated structs
 */
static void rm_shred_node_free(RmShredNode *node) {
    rm_assert_gentle(!node->held_files);
    rm_assert_gentle(!node->children);
    /* don't free top-level node; it is embedded in RmShredTree */
    rm_assert_gentle((gpointer)node != (gpointer)node->tree);
    rm_shred_node_free_sum(node);

    g_slice_free(RmShredNode, node);
}

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

/** prepare a finished RmShredNode for output and send files
 * to rm_shred_send()
 **/
static void rm_shred_node_output(RmShredNode *node) {
    rm_assert_gentle(node->held_files);

    RmLintType lint_type = RM_LINT_TYPE_UNKNOWN;

    if(rm_shred_node_qualifies(node)) {
        lint_type = RM_LINT_TYPE_DUPE_CANDIDATE;
    } else {
        lint_type = RM_LINT_TYPE_UNIQUE_FILE;
    }

    rm_shred_node_free_sum(node);

    /* find the original(s) (note this also unbundles hardlinks and sorts
     * the group from highest ranked to lowest ranked, and points the files
     * to their (shared) digest
     */
    RmShredSession *shredder = node->tree->shredder;
    node->held_files =
        rm_shred_group_find_original(shredder->cfg, node->held_files, lint_type);

    /* send files to session for output and file freeing */
    rm_shred_send(shredder, node->held_files, 0);
}

/**
 * defines modes for rm_shred_node_add_file()
 */
typedef enum RmShredAddMode {
    RM_SHRED_HOLD = 0,
    RM_SHRED_SIFT,
    RM_SHRED_CONTINUING
} RmShredAddMode;

#define RM_SHRED_NEEDS_HASHING(node, cfg) \
    (rm_shred_node_qualifies(node) &&     \
     (node->num_inodes > 1 || cfg->merge_directories) && !node->final)

/** rm_shred_node_add_file adds a file to the node.
 * If mode==RM_SHRED_HOLD then the file is stored in the node
 * If mode==RM_SHRED_SIFT then the node is tested via rm_shred_node_qualifies()
 * and if the result is negative then the file is stored in the node; if
 * the result is positive then the file, plus any held files, are scheduled for
 * further reading / hashing.
 * If mode==RM_SHRED_CONTINUING then the file was predestined for further hashing
 * and it is not stored in the node.
 *
 * Call with tree node->tree locked.
 **/
static void rm_shred_node_add_file(RmShredNode *node, RmFile *file, RmShredAddMode mode) {
    file->shred_node = node;

    /* logic for cfg->unmatched_basenames option */
    RmCfg *cfg = node->tree->shredder->cfg;
    if(cfg->unmatched_basenames && node->num_files == 0) {
        /* first file into group sets the basename */
        node->unique_basename = file;
    }
    if(node->unique_basename) {
        /* check if we still have only 1 unique basename... */
        if(rm_file_basenames_cmp(file, node->unique_basename) != 0) {
            node->unique_basename = NULL;
        } else if(file->hardlinks.is_head) {
            /* also check hardlink names */
            for(GList *iter = file->hardlinks.files->head; iter; iter = iter->next) {
                if(rm_file_basenames_cmp(iter->data, node->unique_basename) != 0) {
                    node->unique_basename = NULL;
                }
            }
        }
    }

    /* update node totals */
    node->num_inodes++;
    node->num_files += rm_file_filecount(file); /* includes hardlinks */
    node->has_pref |= file->is_prefd || file->hardlinks.has_prefd;
    node->has_npref |= (!file->is_prefd) || file->hardlinks.has_non_prefd;
    node->has_new |= file->is_new_or_has_new;
    node->has_only_ext_cksums &= !!file->ext_cksum;

    /* check whether to send for further hashing, or store in the node */
    if(mode != RM_SHRED_HOLD && RM_SHRED_NEEDS_HASHING(node, cfg)) {
        file->shred_overshot = FALSE;
        rm_shred_node_launch_held(node);

        /* push the new arrival too */
        node->num_pending++;
        if(mode == RM_SHRED_SIFT) {
            rm_shred_file_schedule(file);
        }
    } else if(mode == RM_SHRED_CONTINUING) {
        /* file is still hashing */
        rm_assert_gentle(!node->final);
        node->num_pending++;
        /* indicate back to rm_shred_process_file() to stop reading: */
        file->shred_overshot = TRUE;
    } else {
        /* hold onto the file */
        node->held_files = g_slist_prepend(node->held_files, file);
    }
}

/**
 * rm_shred_node_has_pending checks whether a node may still expect incoming
 * files from any of its ancestor nodes.
 * Call with tree node->tree locked
 **/
static gboolean rm_shred_node_has_pending(RmShredNode *node) {
    if(!node) {
        return FALSE;
    }
    return (node->num_pending > 0 || rm_shred_node_has_pending(node->parent));
}

/**
 * rm_shred_node_finished recursively checks if node and its children have finished;
 * if yes then outputs node's result (if applicable) and, if delete==true, deletes
 * the node from the tree and frees it.
 * note: if children have finished then they are always deleted and freed.
 * note: prototyped as RmSListRFunc
 **/
static gboolean rm_shred_node_finished(RmShredNode *node, _UNUSED RmShredNode *prev,
                                       gboolean delete) {
    if(rm_shred_node_has_pending(node)) {
        /* still waiting for incoming hashes */
        return FALSE;
    }

    /* no pending files so checksum not needed */
    rm_shred_node_free_sum(node);

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

/** rm_shred_node_prune detaches a node from tree;
 * If recursively moves upwards, detaching parent nodes if they too are finished.
 * If this results in a completely denuded tree then return true.
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

/**
 * allocate and initialise new RmShredTree using file as a template
 */
static RmShredTree *rm_shred_tree_new(RmShredSession *shredder, RmFile *file) {
    RmShredTree *tree = g_new0(RmShredTree, 1);

    tree->shredder = shredder;

    rm_shred_node_init(&tree->head, file, NULL);
    tree->head.tree = tree;

    g_mutex_init(&tree->lock);

    tree->min_offset = (RmOff)-1; /* lowest hdd offset in tree */

    return tree;
}

/**
 * free and RmShredTree and associated structs
 */
static void rm_shred_tree_free(RmShredTree *tree) {
    rm_assert_gentle(!tree->head.held_files);
    rm_assert_gentle(!tree->head.children);
    RmShredSession *shredder = tree->shredder;
    if(tree->paranoid_mem_alloc != 0 && !shredder->after_preprocess) {
        /* return paranoid mem allocation */
        g_mutex_lock(&shredder->hash_mem_lock);
        {
            shredder->paranoid_mem_alloc += tree->paranoid_mem_alloc;
            g_cond_signal(&shredder->hash_mem_cond);
        }
        g_mutex_unlock(&shredder->hash_mem_lock);
    }
    g_mutex_clear(&tree->lock);
    g_free(tree);
}

/**
 * rm_shred_tree_launch checks if tree qualifies for hashing;
 * if yes then sends files to hashing scheduler;
 * if not then reports files as unique and frees the tree.
 */
static void rm_shred_tree_launch(RmShredTree *tree) {
    gboolean finished = TRUE;
    RmShredNode *node = &tree->head;
    g_mutex_lock(&tree->lock);
    {
        if(RM_SHRED_NEEDS_HASHING(node, tree->shredder->cfg)) {
            rm_shred_node_launch_held(node);
        }
        finished = rm_shred_node_finished(node, NULL, FALSE);
    }
    g_mutex_unlock(&tree->lock);
    if(finished) {
        rm_shred_tree_free(tree);
    }
}

/** sort function to sort trees into ascending order based on lowest hdd
 * offset of member files; trees with only ssd files go last.
 */
static gint rm_shred_tree_cmp(RmShredTree *a, RmShredTree *b) {
    /* sort in  */
    if(a->min_offset < b->min_offset) {
        return -1;
    }
    return (a->min_offset >= b->min_offset);
}

/**
 * rm_shred_reschedule receives partially hashed files and sorts/matches them
 * into RmShredNodes.
 * If appropriate the file will be scheduled for further hashing.
 *
 * Any nodes impacted by file's return are 'shaken' to remove dead
 * leaves via rm_shred_node_finished() and then any dead branches are pruned.
 * If the last branch is removed then the tree will be freed.
 **/
static void rm_shred_reschedule(RmFile *file, RmShredAddMode mode) {
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
            rm_shred_file_discard(file);

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
            rm_shred_node_add_file(child, file, mode);
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

/**
 * hasher.c callback; called when a file increment has finished hashing.
 * Updates file->hash_offset and processes file via rm_shred_reschedule().
 * note: is_last==FALSE implies that reading is ongoing.
 * */
static void rm_shred_hash_callback(_UNUSED RmHasher *hasher, RmDigest *digest,
                                   _UNUSED RmShredSession *shredder, RmFile *file,
                                   guint bytes_read, gboolean is_last) {
    rm_assert_gentle(file->digest == digest);
    file->hash_offset += bytes_read;
    rm_assert_gentle(file->hash_offset <= file->file_size);

    if(file->lint_type != RM_LINT_TYPE_READ_ERROR &&
       shredder->cfg->write_cksum_to_xattr && file->ext_cksum == NULL) {
        /* remember that checksum */
        rm_xattr_write_hash(shredder->cfg, file);
    }

    rm_shred_reschedule(file, is_last ? RM_SHRED_SIFT : RM_SHRED_CONTINUING);
}

/**
 * rm_shred_process_file is a callback for RmMDS which incrementally reads
 * and hashes file (via hasher.c) until it is "time to stop".
 * Further processing of the file is generally managed by the hasher callback
 * (with the exception of rm_session_was_aborted()).
 **/
static void rm_shred_process_file(RmFile *file, RmShredSession *shredder) {
    if(rm_session_was_aborted()) {
        file->lint_type = RM_LINT_TYPE_INTERRUPTED;
        rm_shred_reschedule(file, RM_SHRED_SIFT);
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

    RmHasherTask *task = rm_hasher_task_new(shredder->hasher, file->digest, file);

    RmOff read_offset = file->hash_offset;
    file->shred_overshot = FALSE;
    gboolean stop = FALSE;
    RM_DEFINE_PATH(file);

    while(!stop) {
        /* hash the next increment of the file */
        guint bytes_to_read = rm_shred_get_read_size(file, read_offset, shredder);
        if(!rm_hasher_task_hash(task, file_path, read_offset, bytes_to_read,
                                file->is_symlink)) {
            /* rm_hasher_start_increment failed somewhere */
            file->lint_type = RM_LINT_TYPE_READ_ERROR;
            stop = TRUE;
        }
        read_offset += bytes_to_read;

        /* Update totals for file, device and session*/
        if(file->is_symlink) {
            rm_shred_send(shredder, NULL, -(gint64)file->file_size);
        } else {
            rm_shred_send(shredder, NULL, -(gint64)bytes_to_read);
        }

        /* can't continue to next increment if at end of file */
        stop = stop || (read_offset == file->file_size);
        /* don't force to next increment if on SSD since they have no seek penalty */
        stop = stop || !rm_mds_device_is_rotational(file->disk);
        /* if file is already 2 increments ahead of its siblings then stop
         * (not strictly threadsafe but false positives are harmless): */
        stop = stop || file->shred_overshot;
        /* if reading is 2 increments ahead of hashing then stop
         * (not strictly threadsafe but false positives are harmless): */
        stop = stop || file->hash_offset + bytes_to_read < read_offset;
        /* trigger hasher callback */
        rm_hasher_task_queue_callback(task, GUINT_TO_POINTER(bytes_to_read), FALSE, stop);
    }
}

////////////////////////////////////
//  SHRED-SPECIFIC PREPROCESSING  //
////////////////////////////////////

/**
 * rm_shred_file_preprocess is called for each file:
 * Update file counters based on any bundled hardlinks;
 * Associate file with appropriate md-scheduler disk;
 * Read any xattr checksums;
 * Add file to tree;
 * Maybe do some paranoid mem accounting;
 * Maybe lookup disk offset to help optimise paranoid order.
 * */
static void rm_shred_file_preprocess(RmFile *file, RmShredTree *tree) {
    /* initial population of RmShredTree's and linking to RmMDS devices */
    RmShredSession *shredder = tree->shredder;
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
    rm_mds_device_ref(file->disk, 1);

    if(cfg->read_cksum_from_xattr) {
        file->ext_cksum = rm_xattr_read_hash(shredder->cfg, file);
    }

    rm_shred_node_add_file(&tree->head, file, RM_SHRED_HOLD);

    if(cfg->checksum_type == RM_DIGEST_PARANOID) {
        if(rm_mds_device_is_rotational(file->disk)) {
            rm_shred_file_set_offset(file);
            tree->min_offset = MIN(tree->min_offset, file->disk_offset);
        }
        guint64 paranoid_mem_alloc = shredder->max_increment;
        if(!rm_mds_device_is_rotational(file->disk)) {
            paranoid_mem_alloc = paranoid_mem_alloc / 2;
        }
        tree->paranoid_mem_alloc += MIN(file->file_size, paranoid_mem_alloc);
    }
}

/**
 * rm_shred_preprocess_group takes a GSList of files (prepared by preprocess.c),
 * adds the files into an RmShredTree, and launches the tree.
 * In the case of paranoid hashing, the launch is deferred and the tree added
 * to a list.
 */
static void rm_shred_preprocess_group(GSList *files, RmShredSession *shredder) {
    rm_assert_gentle(files);
    rm_assert_gentle(files->data);
    RmFile *first = files->data;

    RmShredTree *tree = rm_shred_tree_new(shredder, first);

    g_slist_foreach(files, (GFunc)rm_shred_file_preprocess, tree);
    g_slist_free(files);

    if(shredder->cfg->checksum_type == RM_DIGEST_PARANOID) {
        /* delayed launch */
        shredder->trees = g_slist_prepend(shredder->trees, tree);
    } else {
        rm_shred_tree_launch(tree);
    }
}

/**
 * rm_shred_preprocess_input processes the jagged list of size_groups prepared
 * by preprocess.c.
 * In the case of paranoid hashing, launching of the resultant RmShredTrees
 * is memory-managed.
 */
static void rm_shred_preprocess_input(RmShredSession *shredder, RmFileTables *tables) {
    /* move files from node tables into initial RmShredGroups */
    rm_log_debug_line("preparing size groups for shredding (dupe finding)...");
    /* small files first... */
    tables->size_groups = g_slist_reverse(tables->size_groups);
    g_slist_foreach(tables->size_groups, (GFunc)rm_shred_preprocess_group, shredder);
    g_slist_free(tables->size_groups);
    tables->size_groups = NULL;

    if(shredder->trees) {
        rm_assert_gentle(shredder->cfg->checksum_type == RM_DIGEST_PARANOID);
        /* launch held trees in optimised order */
        rm_log_debug_line("Sorting shred trees into optimal order...");
        shredder->trees = g_slist_sort(shredder->trees, (GCompareFunc)rm_shred_tree_cmp);
        for(GSList *iter = shredder->trees; iter; iter = iter->next) {
            RmShredTree *tree = iter->data;
            g_mutex_lock(&shredder->hash_mem_lock);
            { shredder->paranoid_mem_alloc -= tree->paranoid_mem_alloc; }
            g_mutex_unlock(&shredder->hash_mem_lock);
            rm_shred_tree_launch(tree);
            /* check paranoid mem avail before proceeding to next group */
            g_mutex_lock(&shredder->hash_mem_lock);
            {
                while(shredder->paranoid_mem_alloc <= 0) {
                    if(!shredder->mds_started) {
                        rm_mds_start(shredder->mds);
                        shredder->mds_started = TRUE;
                    }
                    rm_log_debug_line("Waiting for paranoid mem...");
                    g_cond_wait(&shredder->hash_mem_cond, &shredder->hash_mem_lock);
                }
            }
            g_mutex_unlock(&shredder->hash_mem_lock);
        }
        g_slist_free(shredder->trees);
        shredder->trees = NULL;
        rm_log_debug_line("All trees launched");
    }

    /* special signal for end of preprocessing */
    rm_shred_send(shredder, NULL, 0);
}

////////////////////////////////////////////
//           Shredder Session             //
////////////////////////////////////////////

void rm_shred_run(RmCfg *cfg, RmFileTables *tables, RmMDS *mds,
                  GThreadPool *shredder_pipe, guint total_files) {
    RmShredSession shredder;
    shredder.shredder_pipe = shredder_pipe;
    shredder.cfg = cfg;
    shredder.mds = mds;
    shredder.paranoid_mem_alloc = G_MAXINT64;
    shredder.mds_started = FALSE;
    shredder.trees = NULL;

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

    shredder.after_preprocess = FALSE;

    /* would use g_atomic, but helgrind does not like that */
    g_mutex_init(&shredder.hash_mem_lock);
    g_cond_init(&shredder.hash_mem_cond);

    /* estimate mem used for RmFiles and allocate any leftovers to read buffer and/or
     * paranoid mem */
    RmOff mem_used = SHRED_AVERAGE_MEM_PER_FILE * total_files;
    RmOff read_buffer_mem = MAX(1024 * 1024, (gint64)cfg->total_mem - (gint64)mem_used);

    if(cfg->checksum_type == RM_DIGEST_PARANOID) {
        /* allocate any spare mem for paranoid hashing */
        shredder.paranoid_mem_alloc = (gint64)cfg->total_mem - (gint64)mem_used;
        shredder.paranoid_mem_alloc = MAX(1, shredder.paranoid_mem_alloc);
        rm_log_debug_line("Paranoid Mem Avail: %" LLU, shredder.paranoid_mem_alloc);
        /* paranoid memory manager takes care of memory load; */
        read_buffer_mem = 0;
    }
    rm_log_debug_line("Read buffer Mem: %" LLU, read_buffer_mem);

    /* Initialise hasher */
    shredder.hasher = rm_hasher_new(cfg->checksum_type,
                                    cfg->hash_threads,
                                    cfg->use_buffered_read,
                                    shredder.buffer_size,
                                    read_buffer_mem,
                                    (RmHasherCallback)rm_shred_hash_callback,
                                    &shredder);

    /* configure mds */
    rm_mds_configure(shredder.mds,
                     (RmMDSFunc)rm_shred_process_file,
                     &shredder,
                     cfg->sweep_count,
                     cfg->threads_per_hdd,
                     cfg->threads_per_ssd,
                     (RmMDSSortFunc)rm_mds_elevator_cmp,
                     NULL);

    /* preprocess file groups */
    rm_shred_preprocess_input(&shredder, tables);

    shredder.after_preprocess = TRUE;
    if(!shredder.mds_started) {
        rm_mds_start(shredder.mds);
    }

    /* complete shred session: */
    rm_mds_finish(shredder.mds);

    /* free any session structs */
    rm_hasher_free(shredder.hasher, TRUE);
    g_mutex_clear(&shredder.hash_mem_lock);
    g_cond_clear(&shredder.hash_mem_cond);
}
