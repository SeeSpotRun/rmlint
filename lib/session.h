/**
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
** Authors:
 *
 *  - Christopher <sahib> Pahl 2010-2015 (https://github.com/sahib)
 *  - Daniel <SeeSpotRun> T.   2014-2015 (https://github.com/SeeSpotRun)
 *
** Hosted on http://github.com/sahib/rmlint
*
**/

#ifndef RM_SESSION_H
#define RM_SESSION_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <glib.h>

#include "cfg.h"
#include "file.h"

typedef struct RmFileTables {
    /* List of all files found during traversal */
    GQueue *all_files;

    /* GSList of GList's, one for each file size */
    GSList *size_groups;

    /* Used for finding inode matches */
    GHashTable *node_table;

    /* Used for finding path doubles */
    GHashTable *unique_paths_table;

    /*array of lists, one for each "other lint" type */
    GSList *other_lint[RM_LINT_TYPE_OTHER];

    /* lock for access to *list during traversal */
    GMutex lock;
} RmFileTables;

typedef struct RmCounters {
    /* Counters for printing useful statistics */
    gint total_files;
    gint ignored_files;
    gint ignored_folders;

    RmOff total_filtered_files;
    RmOff total_lint_size;
    RmOff shred_bytes_remaining;
    RmOff shred_bytes_total;
    RmOff shred_files_remaining;
    RmOff shred_bytes_after_preprocess;
    RmOff dup_counter;
    RmOff dup_group_counter;
    RmOff other_lint_cnt;
    /* Debugging counters */
    RmOff offset_fragments;
    RmOff offsets_read;
    RmOff offset_fails;

} RmCounters;

typedef struct RmSession {
    /* stores output formatter config based on command line input */
    struct RmFmtTable *formats;

    /* stores all other configuration data based on command line input */
    RmCfg *cfg;

    /* Stores for RmFile during traversal, preproces and shredder */
    struct RmFileTables *tables;

    /* Table of mountpoints used in the system */
    struct RmMountTable *mounts;

    /* Treemerging for -D */
    struct RmTreeMerger *dir_merger;

    /* Shredder session */
    struct RmShredTag *shredder;

    /* Disk Scheduler */
    struct _RmMDS *mds;

    RmCounters *counters;

    /* flag indicating if rmlint was aborted early */
    volatile gint aborted;

    /* timer used for debugging and profiling messages */
    GTimer *timer;

    /* true once shredder finished running */
    bool shredder_finished;

    /* true once traverse finished running */
    bool traverse_finished;

    /* temporary? */
    GThreadPool *preprocess_file_pipe;
} RmSession;

/**
 * @brief Initialize session.
 */
void rm_session_init(RmSession *session);

/**
 * @brief Run the rmlint session.
 *
 * @return exit_status for exit()
 */
int rm_session_run(RmSession *session);

/**
 * @brief Clear all memory allocated by rm_session_init.
 */
void rm_session_clear(RmSession *session);

/**
 * @brief Set the global abort flag.
 *
 * This flag is checked periodically on strategic points,
 * leading to an early but planned exit.
 *
 * Threadsafe.
 */
void rm_session_abort(void);

/**
 * @brief Check if rmlint was aborted early.
 *
 * Threadsafe.
 */
bool rm_session_was_aborted(void);

/* Maybe colors, for use outside of the rm_log macros,
 * in order to work with the --with-no-color option
 *
 * MAYBE_COLOR checks the file we output too.
 * If it is stderr or stdout it consults the respective setting automatically.
 * */
#define MAYBE_COLOR(o, s, col)                           \
    (!s->cfg->with_color                                 \
         ? ""                                            \
         : (fileno(o) == 1                               \
                ? (s->cfg->with_stdout_color ? col : "") \
                : (fileno(o) == 2 ? (s->cfg->with_stderr_color ? col : "") : "")))

#define MAYBE_RED(o, s) MAYBE_COLOR(o, s, RED)
#define MAYBE_YELLOW(o, s) MAYBE_COLOR(o, s, YELLOW)
#define MAYBE_RESET(o, s) MAYBE_COLOR(o, s, RESET)
#define MAYBE_GREEN(o, s) MAYBE_COLOR(o, s, GREEN)
#define MAYBE_BLUE(o, s) MAYBE_COLOR(o, s, BLUE)

#endif /* end of include guard */
