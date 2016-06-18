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

#ifndef RM_WALK_H
#define RM_WALK_H

#include <glib.h>
#include "md-scheduler.h"

/**
 * @file walk.h
 * @brief multi-threaded walk of passed path(s) using md-scheduler
 * to improve speed.
 * TODO:
 * [ ] testing
 * [ ] maybe make RmWalkSession more opaque
 * [ ] option to run without pathtricia trie
 * [ ] option to run without MDS
 * [ ] ignore_root_links option
 **/

/**
 * RmWalkSession hosts fields required by walk procedures
 * TODO: maybe should be more opaque?
 */
typedef struct RmWalkSession {
    /* walk options (set directly after creating session */
    /* default for all bool's is FALSE;
     * note: the sense of these options have been chosen so that default==0
     * gives a reasonably vanilla-flavoured file walk */
    // bool ignore_root_links;  // TODO: if true, root paths that are symlinks will be
    // ignored
    bool do_links;   // if true, link and/or link target will be sent for each non-root
                     // symlink
                     // note: root symlinks will be processed regardless
    bool see_links;  // if true, walk returns symlinks as symlinks (else as their targets)
    bool see_dot;    // if true, returns "." and ".." entries // TODO:
    bool
        send_hidden;  // if true, will send files starting with '.', else may send warning
    bool walk_hidden;    // if true, will traverse dirs starting with '.', else may send
                         // warning
                         // (note: hidden root paths are always processed)
    bool send_dirs;      // if true, sends dir paths
    bool ignore_files;   // if true, doesn't return files
    bool one_device;     // if true, walk won't cross filesystem boundaries
    bool send_errors;    // if true, sends a dummy file for error RmWalkType's
    bool send_warnings;  // if true, sends a dummy file for warning RmWalkType's
    bool send_badlinks;  // if true, sends a symlink for each bad symlink

    guint16 max_depth;  // if recursing dirs, limit depth:
                        //  0 = passed paths only
                        //  1 = files in root dirs
                        //  default = (guint16)-1

    /* semi-private fields; don't access directly: */
    GHashTable *roots;
    GAsyncQueue *crumbs;
    RmMDS *mds;
    RmTrie *trie;
    GThreadPool *result_pipe;
    RmMountTable *mounts;
} RmWalkSession;

typedef enum RmWalkType {
    RM_WALK_REG,      // regular file
    RM_WALK_DIR,      // dir
    RM_WALK_SL,       // symbolic link
    RM_WALK_BADLINK,  // link with unreachable target
    RM_WALK_DOT,      // . or ..
    RM_WALK_OTHER,    // unhandled st_mode
    /* warning types */
    RM_WALK_HIDDEN_FILE,   // hidden file ignored due to settings
    RM_WALK_HIDDEN_DIR,    // hidden dir ignored due to settings
    RM_WALK_WHITEOUT,      // erased file on tape drive?
    RM_WALK_SKIPPED_ROOT,  // didn't descend into dir that was a root path
    RM_WALK_MAX_DEPTH,     // max depth reached
    RM_WALK_XDEV,          // didn't cross fs boundary
    RM_WALK_EVILFS,        // scary looking subdir
    RM_WALK_DC,            // a directory which causes cycles
    /* error types */
    RM_WALK_PATHMAX,  // path too long
    RM_WALK_DNR,      // couldn't open dir
    RM_WALK_NS,       // couldn't stat file
} RmWalkType;

typedef struct RmWalkFile {
    RmWalkType type;
    char *path;
    RmNode *dir_node;
    char *bname;
    RmStat *statp;
    guint index;
    gint16 depth;
    int err;
    gboolean is_hidden : 1;
    gboolean is_symlink : 1;
    gboolean via_symlink : 1;
} RmWalkFile;

/**
 * @brief allocate a new walk session
 * @param mds an existing multi-disk scheduler
 * @param result_pipe for sending results
 * @param trie pathtricia tree; a node is inserted for each dir
 * @param mounts mount table
 */
RmWalkSession *rm_walk_session_new(RmMDS *mds, GThreadPool *result_pipe, RmTrie *trie,
                                   RmMountTable *mounts);

/**
 * @brief run and free the RmWalkSession
 * @param paths string vector of absolute paths
 * @param session the RmWalkSession
 * @param threads_per_hdd number of threads per rotational disk
 * @param threads_per_ssd number of threads per non-rotational disk
 * @param sort_interval re-sort the mds job queues after this many dirs
 */
void rm_walk_paths(char **paths, RmWalkSession *walker, gint threads_per_hdd,
                   gint threads_per_ssd, gint sort_interval);

/**
 * @brief free an RmWalkFile
 */
void rm_walk_file_free(RmWalkFile *file);

#endif /* end of include guard */
