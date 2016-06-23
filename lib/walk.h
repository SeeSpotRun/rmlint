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
#include "session.h"

/**
 * @file walk.h
 * @brief multi-threaded walk of an array of path(s);
 * optionally uses md-scheduler.c for optimised multi-threading.
 *
 * Algorithm outline:
 * 1. remove duplicate root paths from array.
 * 2. process each path:
 *      do some filtering & classifying depending on config and file type;
 *      if the path meets criteria, send it to caller via caller's threadpool/pipe.
 * 3. if the path is a dir, maybe schedule it for traversal via md-scheduler:
 *      check first against config (eg max depth);
 *      check also for cyclic dirs.
 *
 * TODO:
 * [ ] testing
 * [ ] maybe make RmWalkSession more opaque
 * [ ] option to run without MDS
 * [ ] ignore_root_links option
 * [ ] cross-platform compatibility:
 *     Aim: provide similar compatibility to BSD's fts.[ch] implementation
 *     (refer
 *https://github.com/sahib/rmlint/blob/53bf236aa16f4e4eccdad5f41e8cbf718654d65e/lib/fts/fts.[ch])
 *      [x] O_CLOEXEC:
 *          fts:  required flag for open() calls if using chdir instead of building full
 *paths;
 *          walk: doesn't use chdir so not applicable.
 *      [x] __FTS_COMPAT_TAILINGSLASH:
 *          fts:  has two slightly different ways of deciding where to insert '/' between
 *path elements
 *          walk: checks for trailing slash and inserts only if necessary
 *      [x] __FTS_COMPAT_LENGTH:
 *          fts:  if defined then limits path length to USHRT_MAX.
 *          walk: path length is configurable by caller;
 *                if defined(__FTS_COMPAT_LENGTH) then caps this at USHRT_MAX.
 *      [x] __FTS_COMPAT_LEVEL:
 *          fts:  if this flag is defined then limits path depth to SHRT_MAX (32767)
 *          walk: path depth limit is user configurable;
 *                if this flag is defined then caps to SHRT_MAX (32767)
 *      [~]DT_DIR :
 *          fts:  if FTS_NOSTAT is set then skips stat(2) calls where possible
 *          walk: saves a stat() call in one trivial case;
 *                revisit if we decide to add a WALK_NOSTAT() option.
 *      [ ] Whiteout:
 *          fts:  behaviour depends on defines for DTF_HIDEW and DT_WHT
 *          walk: TODO; have only partially 'translated' the fts logic
 *
 **/

/**
 * RmWalkSession hosts fields required by walk procedures
 * TODO: maybe should be more opaque?
 */
typedef struct RmWalkSession {
    /* walk options (set directly after creating session)
     * default for all bool's is FALSE;
     * note: the sense of these options have been chosen so that defaults
     * give a reasonably vanilla-flavoured file walk */
    gboolean do_links;       // if true, link and/or link target will be sent for
                             // each non-root symlink;
                             // note: root symlinks will be processed regardless
    gboolean see_links;      // if true, walk returns symlinks as symlink files
    gboolean send_hidden;    // if true, will send hidden files, else may send warning
    gboolean walk_hidden;    // if true, will traverse hidden dirs, else may send warning
                             // (note: hidden root paths are always processed)
    gboolean send_dirs;      // if true, sends dir paths
    gboolean ignore_files;   // if true, doesn't return files
    gboolean one_device;     // if true, walk won't cross filesystem boundaries
    gboolean send_errors;    // if true, sends a dummy file for error RmWalkType's
    gboolean send_warnings;  // if true, sends a dummy file for warning RmWalkType's
    gboolean send_badlinks;  // if true, sends a symlink for each bad symlink
    gboolean see_dot;        // if true, returns "." and ".." entries
    gboolean basename_only;  // if true, doesn't send full path for files with a
                             // linked parent.
    // TODO: gboolean ignore_root_links; // if true, root path symlinks will be ignored

    guint path_max;  // maximum absolute path length in chars (including final null)
                     // default = PATH_MAX

    guint16 max_depth;  // if recursing dirs, limit depth:
                        //  0 = passed paths only
                        //  1 = files in root dirs
                        //  default = (guint16)-1

    /* semi-private fields; don't access directly: */
    GHashTable *roots;
    GThreadPool *result_pipe;
    RmMountTable *mounts;
    RmMDS *mds;  // disk sceduler
} RmWalkSession;

typedef enum RmWalkType {
    RM_WALK_REG,      // regular file
    RM_WALK_DIR,      // dir (pre processing of dir's files)
    RM_WALK_SL,       // symbolic link
    RM_WALK_BADLINK,  // link with unreachable target
    RM_WALK_DOT,      // . or ..
    RM_WALK_OTHER,    // unhandled st_mode
    /* warning types */
    RM_WALK_HIDDEN_FILE,   // hidden file ignored due to settings
    RM_WALK_HIDDEN_DIR,    // hidden dir ignored due to settings
    RM_WALK_WHITEOUT,      // erased file on tape drive?
    RM_WALK_SKIPPED_ROOT,  // didn't descend into dir that was a root path
    RM_WALK_XDEV,          // didn't cross fs boundary
    RM_WALK_EVILFS,        // scary looking subdir
    RM_WALK_DC,            // a directory which causes cycles
    /* error types: may not have valid stat() data: */
    RM_WALK_PATHMAX,  // path too long
    RM_WALK_DNR,      // couldn't open dir
    RM_WALK_NS,       // couldn't stat file
} RmWalkType;

/**
 * TODO: document me
 */
typedef struct RmWalkFile {
    RmWalkType type;
    char *path;
    char *bname;
    RmStat *statp;
    guint index;
    int err;
    gint16 depth;
    gboolean is_hidden : 1;
    gboolean is_symlink : 1;
    gboolean via_symlink : 1;
    gboolean is_ref_counted : 1;
    gboolean is_dir : 1;
    gboolean is_traversed : 1;
    struct RmWalkFile *parent;
    gpointer user_data;
} RmWalkFile;

/**
 * @brief allocate a new walk session
 * @param mds an existing multi-disk scheduler
 * @param result_pipe for sending results
 * @param mounts mount table
 */
RmWalkSession *rm_walk_session_new(RmMDS *mds, GThreadPool *result_pipe,
                                   RmMountTable *mounts, guint path_max);

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
