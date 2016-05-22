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
    RM_LINT_TYPE_UNKNOWN = 0,
    RM_LINT_TYPE_BADLINK,
    RM_LINT_TYPE_EMPTY_DIR,
    RM_LINT_TYPE_EMPTY_FILE,
    RM_LINT_TYPE_NONSTRIPPED,
    RM_LINT_TYPE_BADUID,
    RM_LINT_TYPE_BADGID,
    RM_LINT_TYPE_BADUGID,
    /* dummy types ignored by traverser (used for counting) */
    RM_LINT_TYPE_OTHER,  // must be first, used as marker
    RM_LINT_TYPE_BADPERM,
    RM_LINT_TYPE_WRONG_SIZE,
    RM_LINT_TYPE_HIDDEN_DIR,
    RM_LINT_TYPE_HIDDEN_FILE,
    RM_LINT_TYPE_WRONG_TIME,
    RM_LINT_TYPE_KEEP_TAGGED,
    RM_LINT_TYPE_PATHDOUBLE,
    RM_LINT_TYPE_HARDLINK,
    RM_LINT_TYPE_READ_ERROR,
    RM_LINT_TYPE_BASENAME_TWIN,

    /* note: this needs to be after all non-duplicate lint type item in list */
    RM_LINT_TYPE_DUPE_CANDIDATE,

    /* Directories are no "normal" RmFiles, they are actual
     * different structs that hide themselves as RmFile to
     * be compatible with the output system.
     *
     * Also they only appear at the very end of processing temporarily.
     * So it does not matter if this type is behind RM_LINT_TYPE_DUPE_CANDIDATE.
     */
    RM_LINT_TYPE_DUPE_DIR_CANDIDATE,

    /* Special type for files that got sieved out during shreddering.
     * if cfg->write_unfinished is true, those may be included in the
     * json/xattr/csv output.
     *
     * This is mainly useful for caching.
     */
    RM_LINT_TYPE_UNIQUE_FILE,
    /* Files that were buffered when shredder was interrupted */
    RM_LINT_TYPE_INTERRUPTED,
} RmLintType;

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
    /* path 'zipped' as a node of folder n-ary tree (memory efficient
     * but slower) */
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

    /* If false rm_file_destroy will not destroy the digest. This is useful
     * for sharing the digest of duplicates in a group.
     */
    bool free_digest : 1;

    /* If true, the checksum of this file was read from the xattrs of the file.
     * It was cached previously by rmlint on the disk.
     */
    bool has_ext_cksum : 1;

    /* If true, the file will be request to be pre-cached on the next read */
    bool fadvise_requested : 1;

    /* Set to true if rm_shred_process_file() for hash increment */
    bool shredder_waiting : 1;

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

    /* Those are never used at the same time.
     * disk_offset is used during computation,
     * twin_count during output.
     */
    union {
        /* Count of twins of this file.
         * (i.e. length of group of this file)
         */
        gint64 twin_count;

        /* Disk fiemap / physical offset at start of file (tests mapping subsequent
         * file fragements did not deliver any significant additionl benefit) */
        RmOff disk_offset;
    };

    /* What kind of lint this file is.
     */
    RmLintType lint_type;

    /* Link to the RmShredNode that the file currently belongs to */
    struct RmShredNode *shred_node;

    /* Required for rm_file_equal and for RM_DEFINE_PATH */
    const struct RmCfg *cfg;

    struct RmSignal *signal;

    /* Caching bitmasks to ensure each file is only matched once
     * for every GRegex combination.
     * See also preprocess.c for more explanation.
     * */
    RmPatternBitmask pattern_bitmask_path;
    RmPatternBitmask pattern_bitmask_basename;
} RmFile;

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
                    unsigned pnum, short depth);

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
