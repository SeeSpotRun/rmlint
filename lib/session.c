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
    session->tables = rm_file_tables_new();
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
    rm_file_tables_destroy(session->tables); /* TODO: maybe earlier? */
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

/* threadpipe to receive files from traverser.
 * single threaded; assumes safe access to tables->all_files
 * and session->counters.
 */
static void rm_session_traverse_pipe(RmFile *file, RmSession *session) {
    if(rm_mounts_is_evil(session->mounts, file->dev)
       /* A file in an evil fs. Ignore. */
       ||
       rm_fmt_is_a_output(session->formats, file->path)
       /* ignore files which are rmlint outputs */
       ||
       (file->lint_type == RM_LINT_TYPE_EMPTY_FILE && !session->cfg->find_emptyfiles)
       /* ignoring empty files */
       ||
       file->lint_type == RM_LINT_TYPE_BADPERM ||
       file->lint_type == RM_LINT_TYPE_WRONG_SIZE ||
       file->lint_type == RM_LINT_TYPE_HIDDEN_FILE) {
        session->counters->ignored_files++;
        g_free(file->path);
        rm_file_destroy(file);
        return;
    }

    if(file->lint_type == RM_LINT_TYPE_HIDDEN_DIR) {
        session->counters->ignored_folders++;
        g_free(file->path);
        rm_file_destroy(file);
        return;
    }

    /* convert from regular path to pathtricia */
    rm_file_zip_path(file, file->path);
    g_free(file->path);

    if(session->cfg->clear_xattr_fields &&
       file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        rm_xattr_clear_hash(session->cfg, file);
    }
    session->tables->all_files = g_slist_prepend(session->tables->all_files, file);

    session->counters->total_files++;
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_TRAVERSE);
}

/* threadpipe to receive "other" lint and rejected files from preprocess.
 * single threaded; runs concurrently with rm_session_pp_files_pipe.
 * Assumes safe access to session->tables->other_lint and session->counters.
 */
static void rm_session_pp_files_pipe(RmFile *file, RmSession *session) {
    if(file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        /* bundled hardlink is counted as filtered file */
        rm_assert_gentle(file->hardlinks.hardlink_head);
        session->counters->total_filtered_files--;
    } else if(file->lint_type == RM_LINT_TYPE_UNIQUE_FILE) {
        session->counters->total_filtered_files--;
        rm_fmt_write(file, session->formats, 1);
    } else if(file->lint_type >= RM_LINT_TYPE_OTHER) {
        rm_assert_gentle(file->lint_type <= RM_LINT_TYPE_DUPE_CANDIDATE);
        /* filtered reject based on mtime, --keep, etc */
        session->counters->total_filtered_files--;
        rm_file_destroy(file);
    } else {
        /* collect "other lint" for later processing */
        session->tables->other_lint[file->lint_type] =
            g_slist_prepend(session->tables->other_lint[file->lint_type], file);
        session->counters->total_filtered_files--;
        session->counters->other_lint_cnt++;
    }
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_PREPROCESS);
}

static void rm_session_output_other_lint(const RmSession *session) {
    RmFileTables *tables = session->tables;

    for(RmOff type = 0; type < RM_LINT_TYPE_OTHER; ++type) {
        if(type == RM_LINT_TYPE_EMPTY_DIR) {
            /* sort empty dirs in reverse so that they can be deleted sequentially */
            tables->other_lint[type] =
                g_slist_sort(tables->other_lint[type],
                             (GCompareFunc)rm_session_cmp_reverse_alphabetical);
        }

        GSList *list = tables->other_lint[type];
        for(GSList *iter = list; iter; iter = iter->next) {
            RmFile *file = iter->data;

            rm_assert_gentle(file);
            rm_assert_gentle(type == file->lint_type);

            rm_fmt_write(file, session->formats, -1);
        }

        if(!session->cfg->cache_file_structs) {
            g_slist_free_full(list, (GDestroyNotify)rm_file_destroy);
        } else {
            g_slist_free(list);
        }
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
    GThreadPool *traverse_file_pool =
        rm_util_thread_pool_new((GFunc)rm_session_traverse_pipe, session, 1);

    rm_traverse_tree(session->cfg, traverse_file_pool, session->mds);
    rm_log_debug_line("Traversal finished at %.3f",
                      g_timer_elapsed(session->timer, NULL));

    g_thread_pool_free(traverse_file_pool, FALSE, TRUE);
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_TRAVERSE_DONE);

    rm_log_debug_line(
        "List build finished at %.3f with %d files; ignored %d hidden files and %d "
        "hidden folders",
        g_timer_elapsed(session->timer, NULL), session->counters->total_files,
        session->counters->ignored_files, session->counters->ignored_folders);

    /* --- Preprocessing --- */

    if(session->counters->total_files >= 1) {
        session->counters->total_filtered_files = session->counters->total_files;
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_PREPROCESS);

        /* Create a single-threaded pools to receive files and groups from traverse */
        GThreadPool *preprocess_file_pipe =
            rm_util_thread_pool_new((GFunc)rm_session_pp_files_pipe, session, 1);

        rm_preprocess(session->cfg, session->tables, preprocess_file_pipe);
        rm_log_debug_line(
            "path doubles removal/hardlink bundling/other lint stripping finished at "
            "%.3f",
            g_timer_elapsed(session->timer, NULL));

        g_thread_pool_free(preprocess_file_pipe, FALSE, TRUE);
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_PREPROCESS_DONE);
        rm_log_debug_line(
            "Preprocessing finished at %.3f with %d files; ignored %d hidden files and "
            "%d "
            "hidden folders",
            g_timer_elapsed(session->timer, NULL), session->counters->total_files,
            session->counters->ignored_files, session->counters->ignored_folders);

        rm_session_output_other_lint(session);

        rm_log_debug_line("Preprocessing output finished at %.3f (%lu other lint)",
                          g_timer_elapsed(session->timer, NULL),
                          session->counters->other_lint_cnt);

        if(cfg->find_duplicates || cfg->merge_directories) {
            rm_shred_run(session);

            rm_log_debug_line("Dupe search finished at time %.3f",
                              g_timer_elapsed(session->timer, NULL));
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
