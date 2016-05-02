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

#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "config.h"
#include "session.h"
#include "formats.h"
#include "traverse.h"
#include "preprocess.h"
#include "replay.h"
#include "md-scheduler.h"
#include "treemerge.h"
#include "traverse.h"
#include "preprocess.h"
#include "shredder.h"
#include "utilities.h"
#include "xattr.h"

void rm_session_init(RmSession *session) {
    memset(session, 0, sizeof(RmSession));
    session->timer = g_timer_new();
    session->counters = g_slice_new0(RmCounters);
    session->formats = rm_fmt_open(session);
    session->tables = rm_file_tables_new(session);
}

void rm_session_clear(RmSession *session) {
    RmCfg *cfg = session->cfg;

    /* Free mem */
    if(cfg->paths) {
        g_strfreev(cfg->paths);
    }

    g_free(cfg->sort_criteria);
    g_ptr_array_free(cfg->pattern_cache, TRUE);
    rm_fmt_close(session->formats);

    g_timer_destroy(session->timer);
    rm_file_tables_destroy(session->tables);
    if(session->mounts) {
        rm_mounts_table_destroy(session->mounts);
    }

    if(session->dir_merger) {
        rm_tm_destroy(session->dir_merger);
    }

    g_free(cfg->joined_argv);
    g_free(cfg->iwd);

    for(GList *iter = session->cfg->replay_files.head; iter; iter = iter->next) {
        g_free(iter->data);
    }

    g_queue_clear(&session->cfg->replay_files);
    rm_trie_destroy(&cfg->file_trie);

    g_slice_free(RmCounters, session->counters);
}

volatile int SESSION_ABORTED;

void rm_session_abort(void) {
    g_atomic_int_add(&SESSION_ABORTED, 1);
}

static gpointer rm_session_print_first_abort_warn(_UNUSED gpointer data) {
    rm_log_warning("\r");
    rm_log_warning_line(_("Received Interrupt, stopping..."));
    return NULL;
}

bool rm_session_was_aborted() {
    gint rc = g_atomic_int_get(&SESSION_ABORTED);

    static GOnce print_once = G_ONCE_INIT;

    switch(rc) {
    case 1:
        g_once(&print_once, rm_session_print_first_abort_warn, NULL);
        break;
    case 2:
        rm_log_warning_line(_("Received second Interrupt, stopping hard."));
        exit(EXIT_FAILURE);
        break;
    }

    return rc;
}

static int rm_session_replay(RmSession *session) {
    /* User chose to replay some json files. */
    RmParrotCage cage;
    rm_parrot_cage_open(&cage, session);

    for(GList *iter = session->cfg->replay_files.head; iter; iter = iter->next) {
        rm_parrot_cage_load(&cage, iter->data);
    }

    rm_parrot_cage_close(&cage);
    rm_fmt_flush(session->formats);
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_PRE_SHUTDOWN);
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_SUMMARY);

    return EXIT_SUCCESS;
}

/* threadpool to receive files from traverser.
 * single threaded; assumes safe access to tables->all_files
 * and session->counters.
 */
static void rm_session_file_pool(RmFile *file, RmSession *session) {
    RM_DEFINE_PATH(file);

    if(rm_mounts_is_evil(session->mounts, file->dev)
       /* A file in an evil fs. Ignore. */
       ||
       rm_fmt_is_a_output(session->formats, file_path)
       /* ignore files which are rmlint outputs */
       ||
       (file->lint_type == RM_LINT_TYPE_EMPTY_FILE && !session->cfg->find_emptyfiles)
       /* ignoring empty files */
       ||
       file->lint_type == RM_LINT_TYPE_BADPERM ||
       file->lint_type == RM_LINT_TYPE_WRONG_SIZE ||
       file->lint_type == RM_LINT_TYPE_HIDDEN_FILE) {
        session->counters->ignored_files++;
        rm_file_destroy(file);
        return;
    }

    if(file->lint_type == RM_LINT_TYPE_HIDDEN_DIR) {
        session->counters->ignored_folders++;
        rm_file_destroy(file);
        return;
    }

    if(session->cfg->clear_xattr_fields &&
       file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        rm_xattr_clear_hash(session->cfg, file);
    }
    g_queue_push_tail(session->tables->all_files, file);

    if(++session->counters->total_files % 100 == 0) {
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_TRAVERSE);
    }
}

int rm_session_run(RmSession *session) {
    /* --- Setup --- */
    int exit_state = EXIT_SUCCESS;
    RmCfg *cfg = session->cfg;

    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_INIT);

    if(session->cfg->replay_files.length) {
        return rm_session_replay(session);
    }

    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_TRAVERSE);

    if(cfg->list_mounts) {
        session->mounts = rm_mounts_table_new(cfg->fake_fiemap);
    }

    if(session->mounts == NULL) {
        rm_log_debug_line("No mount table created.");
    }

    session->mds = rm_mds_new(cfg->threads, session->mounts, cfg->fake_pathindex_as_disk);

    if(cfg->merge_directories) {
        rm_assert_gentle(cfg->cache_file_structs);
        session->dir_merger = rm_tm_new(session);
    }

    /* --- Traversal --- */

    /* Create a single-threaded pool to receive files from traverse */
    GThreadPool *file_pool =
        rm_util_thread_pool_new((GFunc)rm_session_file_pool, session, 1);

    rm_traverse_tree(session->cfg, file_pool, session->mds);
    rm_log_debug_line("Traversal finished at %.3f",
                      g_timer_elapsed(session->timer, NULL));

    g_thread_pool_free(file_pool, FALSE, TRUE);
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_TRAVERSE);

    rm_log_debug_line(
        "List build finished at %.3f with %d files; ignored %d hidden files and %d "
        "hidden folders",
        g_timer_elapsed(session->timer, NULL), session->counters->total_files,
        session->counters->ignored_files, session->counters->ignored_folders);

    /* --- Preprocessing --- */

    if(session->counters->total_files >= 1) {
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_PREPROCESS);
        rm_preprocess(session);

        if(cfg->find_duplicates || cfg->merge_directories) {
            rm_shred_run(session);

            rm_log_debug_line("Dupe search finished at time %.3f",
                              g_timer_elapsed(session->timer, NULL));
        } else {
            /* Clear leftovers */
            rm_file_tables_clear(session);
        }
    }

    if(cfg->merge_directories) {
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_MERGE);
        rm_tm_finish(session->dir_merger);
    }

    rm_fmt_flush(session->formats);
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_PRE_SHUTDOWN);
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_SUMMARY);

    if(session->counters->shred_bytes_remaining != 0) {
        rm_log_error_line(
            "BUG: Number of remaining bytes is %lu"
            " (not 0). Please report this.",
            session->counters->shred_bytes_remaining);
        exit_state = EXIT_FAILURE;
    }

    if(session->counters->shred_files_remaining != 0) {
        rm_log_error_line(
            "BUG: Number of remaining files is %lu"
            " (not 0). Please report this.",
            session->counters->shred_files_remaining);
        exit_state = EXIT_FAILURE;
    }

    return exit_state;
}
