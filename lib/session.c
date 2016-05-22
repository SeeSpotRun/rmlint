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

#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "formats.h"
#include "md-scheduler.h"
#include "preprocess.h"
#include "preprocess.h"
#include "replay.h"
#include "session.h"
#include "shredder.h"
#include "traverse.h"
#include "traverse.h"
#include "treemerge.h"
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
static void rm_session_traverse_pipe(RmTraverseFile *file, RmSession *session) {
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
    } else if(file->lint_type == RM_LINT_TYPE_HIDDEN_DIR) {
        session->counters->ignored_folders++;
    } else {
        RmFile *real = rm_file_new(session->cfg, file->path, file->size, file->dev,
                                   file->inode, file->mtime, file->lint_type,
                                   file->is_prefd, file->path_index, file->depth);

        if(!real) {
            session->counters->ignored_files++;
        } else {
            real->is_symlink = file->is_symlink;
            real->is_hidden = file->is_hidden;
            if(session->cfg->clear_xattr_fields &&
               real->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
                rm_xattr_clear_hash(session->cfg, real);
            }
            session->tables->all_files =
                g_slist_prepend(session->tables->all_files, real);

            session->counters->total_files++;
            session->counters->shred_bytes_remaining +=
                real->file_size - real->hash_offset;
            rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_TRAVERSE);
        }
    }
    rm_traverse_file_destroy(file);
}

/* threadpipe to receive "other" lint and rejected files from preprocess.
 * single threaded; runs concurrently with rm_session_pp_files_pipe.
 * Assumes safe access to session->tables->other_lint and session->counters.
 */
static void rm_session_pp_files_pipe(RmFile *file, RmSession *session) {
    session->counters->total_filtered_files--;
    session->counters->shred_bytes_remaining -= file->file_size;

    if(file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        /* bundled hardlink is counted as filtered file */
        rm_assert_gentle(file->hardlinks.hardlink_head);
    } else if(file->lint_type == RM_LINT_TYPE_UNIQUE_FILE) {
        rm_fmt_write(file, session->formats, 1);
        if(!session->cfg->cache_file_structs) {
            rm_file_destroy(file);
        }
    } else if(file->lint_type >= RM_LINT_TYPE_OTHER) {
        rm_assert_gentle(file->lint_type <= RM_LINT_TYPE_DUPE_CANDIDATE);
        /* filtered reject based on mtime, --keep, etc */
        rm_file_destroy(file);
    } else {
        /* collect "other lint" for later processing */
        session->tables->other_lint[file->lint_type] =
            g_slist_prepend(session->tables->other_lint[file->lint_type], file);
        session->counters->other_lint_cnt++;
    }
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_PREPROCESS);
}

/* after preprocessing, rm_session_output_other_lint sends the accumulated
 * "other" lint files to the output formatters
 * TODO: maybe move this to formats.c?
 */
static void rm_session_output_other_lint(const RmSession *session) {
    RmFileTables *tables = session->tables;

    for(RmOff type = 0; type < RM_LINT_TYPE_OTHER; ++type) {
        if(type == RM_LINT_TYPE_EMPTY_DIR) {
            /* sort empty dirs in reverse so that they can be deleted sequentially */
            tables->other_lint[type] = g_slist_sort(
                tables->other_lint[type], (GCompareFunc)rm_file_cmp_reverse_alphabetical);
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

static void rm_session_output_group(GSList *files, RmSession *session, bool merge,
                                    bool count) {
    RmFile *file = files->data;
    if(count && file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        session->counters->dup_group_counter++;
    }
    for(GSList *iter = files; iter; iter = iter->next) {
        file = iter->data;

        if(count && file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
            if(!file->is_original) {
                session->counters->dup_counter++;
                if(!RM_IS_BUNDLED_HARDLINK(file)) {
                    /* Only check file size if it's not a hardlink.  Since
                     * deleting hardlinks does not free any space they should
                     * not be counted unless all of them would be removed.
                     */
                    session->counters->total_lint_size += file->file_size;
                }
            }
        }

        if(merge) {
            rm_tm_feed(session->dir_merger, file);
        } else {
            /* Hand it over to the printing module */
            if(file->lint_type != RM_LINT_TYPE_READ_ERROR &&
               file->lint_type != RM_LINT_TYPE_BASENAME_TWIN) {
                /* TODO: revisit desired output for RM_LINT_TYPE_READ_ERROR and
                 * RM_LINT_TYPE_BASENAME_TWIN */
                rm_fmt_write(file, session->formats, g_slist_length(files));
            }
        }
    }
    if(!session->cfg->cache_file_structs) {
        g_slist_free_full(files, (GDestroyNotify)rm_file_destroy);
    } else {
        g_slist_free(files);
    }
}

/* threadpipe to receive duplicate files from treemerge
 */
static void rm_session_merge_pipe(GSList *files, RmSession *session) {
    rm_session_output_group(files, session, FALSE, FALSE);
    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_MERGE);
}

/* threadpipe to receive duplicate files and progress updates from shredder
 */
static void rm_session_shredder_pipe(RmShredBuffer *buffer, RmSession *session) {
    if(buffer->delta_bytes == 0 && buffer->delta_files == 0 && !buffer->finished_files) {
        /* special signal for end of shred preprocessing */
        session->state = RM_PROGRESS_STATE_SHREDDER;
    }

    session->counters->shred_files_remaining += buffer->delta_files;
    if(buffer->delta_files < 0) {
        session->counters->total_filtered_files += buffer->delta_files;
    }

    if(buffer->delta_bytes != 0) {
        session->counters->shred_bytes_remaining += buffer->delta_bytes;

        /* fake interrupt option for debugging/testing: */
        if(session->state == RM_PROGRESS_STATE_SHREDDER && session->cfg->fake_abort &&
           session->counters->shred_bytes_remaining * 10 <
               session->counters->shred_bytes_total * 9) {
            rm_session_abort();
            /* prevent multiple aborts */
            session->counters->shred_bytes_total = 0;
        }
    }

    GSList *files = buffer->finished_files;
    if(files) {
        rm_assert_gentle(files);
        RmFile *head = files->data;
        ;
        rm_assert_gentle(head);
        bool merge = (session->cfg->merge_directories &&
                      head->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE);
        rm_session_output_group(files, session, merge, TRUE);
    }

    rm_shred_buffer_free(buffer);
    rm_fmt_set_state(session->formats, session->state);
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
        rm_util_thread_pool_new((GFunc)rm_session_traverse_pipe, session, 1, TRUE);

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

        /* Create a single-threaded pools to receive files from preprocess */
        GThreadPool *preprocess_file_pipe =
            rm_util_thread_pool_new((GFunc)rm_session_pp_files_pipe, session, 1, TRUE);

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
    }

    if(session->tables->size_groups && (cfg->find_duplicates || cfg->merge_directories)) {
        /* run dupe finder */
        session->counters->shred_bytes_after_preprocess =
            session->counters->shred_bytes_remaining;
        session->counters->shred_bytes_total = session->counters->shred_bytes_remaining;
        session->counters->shred_files_remaining =
            session->counters->total_filtered_files;

        session->state = RM_PROGRESS_STATE_SHREDDER;
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_SHREDDER);

        GThreadPool *shredder_pipe =
            rm_util_thread_pool_new((GFunc)rm_session_shredder_pipe, session, 1, FALSE);

        rm_shred_run(cfg, session->tables, session->mds, shredder_pipe,
                     session->counters->total_filtered_files);
        g_thread_pool_free(shredder_pipe, FALSE, TRUE);
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_SHREDDER_DONE);

        rm_log_debug_line("Dupe search finished at time %.3f",
                          g_timer_elapsed(session->timer, NULL));
    }

    if(cfg->merge_directories) {
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_MERGE);
        GThreadPool *merge_pipe =
            rm_util_thread_pool_new((GFunc)rm_session_merge_pipe, session, 1, TRUE);

        rm_tm_finish(session->dir_merger, merge_pipe);
        g_thread_pool_free(merge_pipe, FALSE, TRUE);
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
