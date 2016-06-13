/**
* This file is part of rmlint.
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
**/

#ifndef RM_FILE_H
#define RM_FILE_H

#include <glib.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "cfg.h"
#include "pathtricia.h"
#include "utilities.h"

/* types of lint */
typedef enum RmLintType {
    /* ---- guard against uninitialised values: */
    RM_LINT_TYPE_UNKNOWN = 0,

    /* ---- reportable 'other lint';
     * freed by formats.c */
    RM_LINT_TYPE_BADLINK,
    RM_LINT_TYPE_EMPTY_DIR,
    RM_LINT_TYPE_EMPTY_FILE,
    RM_LINT_TYPE_NONSTRIPPED,
    RM_LINT_TYPE_BADUID,
    RM_LINT_TYPE_BADGID,
    RM_LINT_TYPE_BADUGID,
    /* sentinel for 'other' lint: */
    RM_LINT_TYPE_LAST_OTHER = RM_LINT_TYPE_BADUGID,

    /* types used by shredder for dupe match reporting;
     * may be modified by treemerge;
     * freed by formats.c */
    RM_LINT_GROUP_DUPE_FILES = 0x10,
    RM_LINT_TYPE_DUPE_CANDIDATE, /* candidate for duplicate search */
    RM_LINT_TYPE_DUPE_FILE,      /* confirmed duplicate */
    RM_LINT_TYPE_DUPE_DIR_FILE,  /* file within a duplicate dir; must
                                    come after RM_LINT_TYPE_DUPE_FILE */
    RM_LINT_TYPE_UNIQUE_FILE,    /* candidate which didn't match*/

    /* types used by session.c for emptydir detection
     * and by treemerge for dupe dir detection;
     * empty dirs freed by formats.c;
     * the rest freed by treemerge.c */
    RM_LINT_GROUP_DUPE_DIRS = 0x20,
    RM_LINT_TYPE_DIR,         /* dir encountered during traverse */
    RM_LINT_TYPE_DUPE_DIR_CANDIDATE,    /* duplicate dir */
    RM_LINT_TYPE_UNIQUE_DIR,  /* unmatched dir */
    RM_LINT_TYPE_DUPE_SUBDIR, /* subdir of dupe dir */

    /* Files skipped during traversal; these count +1 towards
     * parent dir file count (for emptydir and dupe dir detection).
     * not sent to output; freed by session.c during traversal */
    RM_LINT_GROUP_SINGLE_SKIP = 0x40,
    RM_LINT_TYPE_WRONG_SIZE,   // file ignored due to size limits
    RM_LINT_TYPE_BADPERM,      // no, it's not a 1980's reference!
                               // file ignored due to permission limits.
                               // (TODO: do we also need BADPERM_DIR ?)
    RM_LINT_TYPE_OVERCLAMPED,  // file smaller than clamp range
    RM_LINT_TYPE_WRONG_TIME,   // file ignored due to mtime limits
    RM_LINT_TYPE_HIDDEN_FILE,  // hidden file ignored due to settings
    RM_LINT_TYPE_SYMLINK,      // symlink not 'seen' due to settings
    RM_LINT_TYPE_EVIL_FILE,    // file on evil fs
    RM_LINT_TYPE_NO_STAT,      // file ignored because unable to stat
    RM_LINT_TYPE_OUTPUT,       // a file which is an output of rmlint
    RM_LINT_TYPE_UNHANDLED,    // a file whose stat.st_mode not handled by walk.c

    /* dirs skipped during traversal; these contribute unknown count
     * to parent dir file */
    RM_LINT_GROUP_MULTI_SKIP = 0x80,
    RM_LINT_TYPE_HIDDEN_DIR,      // hidden file ignored due to settings
    RM_LINT_TYPE_MAX_DEPTH,       // recursing into folder would exceed max depth
    RM_LINT_TYPE_XDEV,            // recursing into folder would cross mountpoint
    RM_LINT_TYPE_EVIL_DIR,        // dir on evil fs
    RM_LINT_TYPE_GOODLINK,        // symlink that we didn't follow
    RM_LINT_TYPE_TRAVERSE_ERROR,  // other traversal error

    /* objects skipped during traversal that don't impact emptydir status */
    RM_LINT_GROUP_ZERO_SKIP = 0x100,
    RM_LINT_TYPE_CYCLIC,
    RM_LINT_TYPE_WHITEOUT,  // file ignored due to whiteout

    /* files rejected during preprocessing, dupe matching or postprocessing;
     * non-reporting;
     * freed by session.c */
    RM_LINT_GROUP_REJECTS = 0x200,
    RM_LINT_TYPE_PATHDOUBLE,     // path double detected during preprocessing
    RM_LINT_TYPE_HARDLINK,       // hardlink rejected during preprocessing
    RM_LINT_TYPE_READ_ERROR,     // read error during duplicate search
    RM_LINT_TYPE_BASENAME_TWIN,  // rejected post-dupe-search due to --unmatched-basename
    RM_LINT_TYPE_INTERRUPTED,    // dupe search interrupted eg by ctrl-c
} RmLintType;

#define RM_IS_OTHER_LINT_TYPE(type) (type <= RM_LINT_TYPE_LAST_OTHER)

#define RM_IS_DUPE_FILE_SEARCH_TYPE(type) ((type & RM_LINT_GROUP_DUPE_FILES) != 0)

#define RM_IS_DUPE_DIR_SEARCH_TYPE(type) ((type & RM_LINT_GROUP_DUPE_DIRS) != 0)

#define RM_IS_DIR_TYPE(type) \
    (RM_IS_DUPE_DIR_SEARCH_TYPE(type) || type == RM_LINT_TYPE_EMPTY_DIR)

/* single files for purpose of counting number of files in dir */
#define RM_IS_COUNTED_FILE_TYPE(type)                                   \
    ((RM_IS_OTHER_LINT_TYPE(type) && type != RM_LINT_TYPE_EMPTY_DIR) || \
     RM_IS_DUPE_FILE_SEARCH_TYPE(type) || ((type & RM_LINT_GROUP_SINGLE_SKIP) != 0))

#define RM_IS_UNTRAVERSED_TYPE(type) ((type & RM_LINT_GROUP_MULTI_SKIP) != 0)

#define RM_IS_REPORTING_TYPE(type)                                       \
    (RM_IS_OTHER_LINT_TYPE(type) || RM_IS_DUPE_FILE_SEARCH_TYPE(type) || \
     RM_IS_DUPE_DIR_SEARCH_TYPE(type))

struct RmSession;

typedef guint16 RmPatternBitmask;

/* Get the number of usable fields in a RmPatternBitmask */
#define RM_PATTERN_N_MAX (sizeof(RmPatternBitmask) * 8 / 2)

/* Check if a field has been set already in the RmPatternBitmask */
#define RM_PATTERN_IS_CACHED(mask, idx) (!!((*mask) & (1 << (idx + RM_PATTERN_N_MAX))))

/* If the field was set, this will retrieve the previous result */
#define RM_PATTERN_GET_CACHED(mask, idx) (!!((*mask) & (1 << idx)))

/* Set a field and remember that it was set. */
#define RM_PATTERN_SET_CACHED(mask, idx, match) \
    ((*mask) |= ((!!match << idx) | (1 << (idx + RM_PATTERN_N_MAX))))

/**
 * RmFile structure; used by pretty much all rmlint modules.
 */

typedef struct RmFile {
    char *bname;

    /* parent dir path 'zipped' as a node of folder n-ary tree
     * (memory efficient but slower) */
    RmNode *folder;

    /* File modification date/time
     * */
    time_t mtime;

    /* Depth of the file, relative to the path it was found in.
     */
    short depth;

    /* Depth of the path of this file.
     */
    guint8 path_depth;

    /* The inode and device of this file.
     * Used to filter double paths and hardlinks.
     */
    ino_t inode;
    dev_t dev;
    struct _RmMDSDevice *disk;

    /* True if the file is a symlink
     * shredder needs to know this, since the metadata might be about the
     * symlink file itself, while open() returns the pointed file.
     * Chaos would break out in this case.
     */
    bool is_symlink : 1;

    /* True if traversal followed a symlink on the way to finding file;
     * this may mean the file is a symlink target, or in a dir that
     * was a symlink target, etc */
    bool via_symlink : 1;

    /* True if this file is in one of the preferred paths,
     * i.e. paths prefixed with // on the commandline.
     * In the case of hardlink clusters, the head of the cluster
     * contains information about the preferred path status of the other
     * files in the cluster
     */
    bool is_prefd : 1;

    /* In the late processing, one file of a group may be set as original file.
     * With this flag we indicate this.
     */
    bool is_original : 1;

    /* True if this file, or at least one of its embedded hardlinks, are newer
     * than cfg->min_mtime
     */
    bool is_new_or_has_new : 1;

    /* True if this file, or at least one its path's componennts, is a hidden
     * file. This excludes files above the directory rmlint was started on.
     * This is relevant to --partial-hidden.
     */
    bool is_hidden : 1;

    /* If true, the file will be request to be pre-cached on the next read */
    bool fadvise_requested : 1;

    /* If this file is the head of a hardlink cluster, the following structure
     * contains the other hardlinked RmFile's.  This is used to avoid
     * hashing every file within a hardlink set */
    struct {
        bool has_prefd : 1;
        bool has_non_prefd : 1;
        bool is_head : 1;
        union {
            GQueue *files;
            struct RmFile *hardlink_head;
        };
    } hardlinks;

    /* The index of the path this file belongs to. */
    RmOff path_index;

    /* Filesize in bytes
     */
    RmOff file_size;

    /* How many bytes were already read.
    * (lower or equal file_size)
    */
    RmOff hash_offset;

    /* digest of this file updated on every hash iteration.  Use a pointer so we can share
     * with RmShredGroup
     */
    RmDigest *digest;

    /* The checksum of this file read from the xattrs of the file, if available.
     * It was stored there previously by rmlint.
     */
    char *ext_cksum;

    /* Those are never used at the same time.
     * disk_offset is used during computation,
     * twin_count during output.
     */
    union {
        /* Count of twins of this file.
         * (i.e. length of group of this file); used during output
         */
        gint64 twin_count;

        /* Disk fiemap / physical offset at start of file (tests mapping subsequent
         * file fragements did not deliver any significant additionl benefit) */
        RmOff disk_offset;
    };

    /* What kind of lint this file is.
     */
    RmLintType lint_type;

    /* Link to the RmShredNode that the file currently belongs to
     * (for duplicate file candidates only) */
    struct RmShredNode *shred_node;

    /* Required for rm_file_equal and for RM_DEFINE_PATH */
    const struct RmCfg *cfg;

    /* whether file has hashed more than one increment past its siblings */
    bool shred_overshot : 1;

    /* Caching bitmasks to ensure each file is only matched once
     * for every GRegex combination.
     * See also preprocess.c for more explanation.
     * */
    RmPatternBitmask pattern_bitmask_path;
    RmPatternBitmask pattern_bitmask_basename;
} RmFile;

typedef enum RmTraversalType {
    RM_TRAVERSAL_NONE = 0,
    RM_TRAVERSAL_PART,
    RM_TRAVERSAL_FULL
} RmTraversalType;

/* struct for all dirs traversed */
typedef struct RmDirInfo {
    /* initially true; set false if we traversed to this dir without
     * passing through any hidden folders
     * note: hidden dirs passed explicitly to command line do not count
     * as hidden)
     */
    bool hidden;

    /* initially true; set false if we traversed to this dir without
     * following any symlinks;
     */
    bool via_symlink;

    /* note: during traversal, the following counters and flags
     * exclude subdirs.  At the end of traversal they are integrated
     * up to give cumulative values for the dir + subdirs
     */

    /* file count (including traversal errors and ignored files) */
    gint file_count;

    /* duplicate count */
    gint dupe_count;

    /* whether we found another RmDirInfo with same count */
    gboolean has_count_match;

    /* duplicate UID's and count */
    GHashTable *dupe_IDs;
    gint dupe_ID_count;

    /* set true if we didn't traverse all subdirs
     */
    RmTraversalType traversal;

    /* during traversal, create and RmFile for the dir as possible emptydir */
    RmFile *dir_as_file;

} RmDirInfo;

RmDirInfo *rm_dir_info_new(RmTraversalType traversal);

void rm_dir_info_free(RmDirInfo *info);

/* Defines a path variable containing the file's path */
#define RM_DEFINE_PATH_IF_NEEDED(file, needed)           \
    char file##_path[PATH_MAX];                          \
    if(needed) {                                         \
        rm_file_build_path((RmFile *)file, file##_path); \
    }

/* Fill path always */
#define RM_DEFINE_PATH(file) RM_DEFINE_PATH_IF_NEEDED(file, true)

#define RM_IS_BUNDLED_HARDLINK(file) \
    (file->hardlinks.hardlink_head && !file->hardlinks.is_head)

/**
 * @brief Create a new RmFile handle.
 */
RmFile *rm_file_new(const RmCfg *cfg, const char *path, size_t size, dev_t dev,
                    ino_t inode, time_t mtime, RmLintType type, bool is_ppath,
                    unsigned path_index, short depth);

/**
 * @brief Deallocate the memory allocated by rm_file_new.
 * @note does not deallocate file->digest since this is handled by shredder.c
 */
void rm_file_destroy(RmFile *file);

/**
 * @brief Set a path to the file. Normally, you should never do this since the
 * path is immutable.
 */
void rm_file_set_path(RmFile *file, char *path);

/**
 * @brief Convert RmLintType to a human readable short string.
 */
const char *rm_file_lint_type_to_string(RmLintType type);

/**
 * @brief Convert a string to a RmLintType
 *
 * @param type a string description.
 *
 * @return a valid lint type or RM_LINT_TYPE_UNKNOWN
 */
RmLintType rm_file_string_to_lint_type(const char *type);

/**
 * @brief Convert file from conventional file->path char* to more
 * memory-efficient pathtricia.
 */
void rm_file_zip_path(RmFile *file, const char *path);

/**
 * @brief Internal helper function for RM_DEFINE_PATH using folder tree and basename.
 */
void rm_file_build_path(const RmFile *file, char *buf);

/** returns the number of actual files (including bundled hardlinks) associated
 * with an RmFile */
gint rm_file_filecount(RmFile *file);

/**
 * @brief Compare basenames of two files
 * @retval true if basenames match.
 */
gint rm_file_basenames_cmp(const RmFile *file_a, const RmFile *file_b);

/**
 * @brief Compare two files in order to find out which file is the
 * higher ranked (ie original).
 *
 * Returns: -1 if a outranks b, 0 if a == b and +1 else.
 */
int rm_file_cmp_orig_criteria(const RmFile *a, const RmFile *b, const RmCfg *cfg);

/**
 * @brief Rank two files in terms of size; if equal then rank in terms of
 * cfg->match_... options.  A return of 0 implies file_a and file_b are
 * duplicate candidates */
gint rm_file_cmp_dupe_group(const RmFile *file_a, const RmFile *file_b, const RmCfg *cfg);

/**
 * @brief Rank two files in terms of dev then inode
 * @note used to help find inode matches
 */
gint rm_file_node_cmp(const RmFile *file_a, const RmFile *file_b);

/**
 * @brief Rank two files in reverse alphabetical order
 * @note used to help find inode matches
 */
gint rm_file_cmp_reverse_alphabetical(const RmFile *a, const RmFile *b);

/**
 * @brief Rank two files with identical inode in an order which
 * places path doubles adjacent to each other
 */
gint rm_file_cmp_pathdouble(const RmFile *a, const RmFile *b);

#endif /* end of include guard */
