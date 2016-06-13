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
static void rm_session_traverse_pipe(RmFile *file, RmSession *session) {
    if(!file) {
        session->counters->ignored_files++;
        return;
    }

    if(file->lint_type == RM_LINT_TYPE_OTHER ||
       (file->lint_type == RM_LINT_TYPE_EMPTY_FILE && !session->cfg->find_emptyfiles) ||
       file->lint_type == RM_LINT_TYPE_BADPERM ||
       file->lint_type == RM_LINT_TYPE_WRONG_SIZE ||
       file->lint_type == RM_LINT_TYPE_HIDDEN_FILE) {
        session->counters->ignored_files++;
    } else if(file->lint_type == RM_LINT_TYPE_HIDDEN_DIR) {
        session->counters->ignored_folders++;
    } else {
        if(session->cfg->clear_xattr_fields &&
           file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
            rm_xattr_clear_hash(session->cfg, file);
        }
        session->tables->all_files = g_slist_prepend(session->tables->all_files, file);

        session->counters->total_files++;
        session->counters->shred_bytes_remaining += file->file_size - file->hash_offset;
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_TRAVERSE);
        return;
    }
    rm_file_destroy(file);
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
        session->counters->unique_bytes += file->file_size;
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

typedef enum RmSessionFileSource {
    RM_FILE_SOURCE_SHREDDER,
    RM_FILE_SOURCE_TREEMERGE
} RmSessionFileSource;

/**
 * rm_session_output_group outputs a group of files via formats.[ch]
 * The files may have been received from either rm_session_merge_pipe()
 * or rm_session_shredder_pipe().
 * The workflow is:
 * Non-duplicate files from rm_session_shredder_pipe() are sent directly
 * to formats.
 * If the treemerge option is *not* selected, then duplicate files from
 * rm_session_shredder_pipe() are also sent straight to formats.
 * If the treemerge option *is* selected, then duplicate files from
 * rm_session_shredder_pipe() are fed to treemerge, which later returns
 * the same files as either RM_LINT_TYPE_DUPE_CANDIDATE or
 * as RM_LINT_TYPE_DUPE_DIR_FILE.  In addition, treemerge sends duplicate
 * dirs as dummy files of type RM_LINT_TYPE_DUPE_DIR_CANDIDATE.
 */

/* threadpipe to receive duplicate files and folders from treemerge;
 */
static void rm_session_merge_pipe(GSList *files, RmSession *session) {
    for(GSList *iter = files; iter; iter = iter->next) {
        /* Hand file over to the printing module */
        rm_fmt_write((RmFile *)iter->data, session->formats, g_slist_length(files));
    }

    /* free files: */
    if(!session->cfg->cache_file_structs) {
        for(GSList *iter = files; iter; iter = iter->next) {
            RmFile *file = iter->data;
            /* treemerge frees its own RM_LINT_TYPE_DUPE_DIR_CANDIDATE 'files' */
            if(file->lint_type != RM_LINT_TYPE_DUPE_DIR_CANDIDATE) {
                rm_file_destroy(file);
            }
        }
    }
    g_slist_free(files);

    rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_MERGE);
}

/* threadpipe to receive duplicate files and progress updates from shredder
 */
static void rm_session_shredder_pipe(RmShredBuffer *buffer, RmSession *session) {
    RmCounters *counters = session->counters;
    if(buffer->delta_bytes == 0 && !buffer->finished_files) {
        /* special signal for end of shred preprocessing */
        /* TODO: not sure if we need this any more */
        session->state = RM_PROGRESS_STATE_SHREDDER;

    } else if(buffer->delta_bytes != 0) {
        /* update of bytes (partially) hashed (no finished files) */
        rm_assert_gentle(!buffer->finished_files);
        counters->shred_bytes_remaining += buffer->delta_bytes;
        counters->shred_bytes_read -= buffer->delta_bytes;

        /* maybe do fake interrupt (option for debugging/testing): */
        if(session->state == RM_PROGRESS_STATE_SHREDDER && session->cfg->fake_abort &&
           counters->shred_bytes_remaining * 10 < counters->shred_bytes_total * 9) {
            rm_session_abort();
            /* prevent multiple aborts */
            counters->shred_bytes_total = 0;
        }

    } else {
        /* buffer contains finished files...

         * get first file and compute some convenience flags*/
        RmFile *file = buffer->finished_files->data;
        gboolean is_dupe_group = file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE;
        gboolean merge = is_dupe_group && session->cfg->merge_directories;
        gint files = g_slist_length(buffer->finished_files);

        if(is_dupe_group) {
            /* increment duplicate file group counter */
            counters->dup_group_counter++;
        }

        /* iterate over group, updating counters and forwarding files
         * to either formats or treemerge */
        for(GSList *iter = buffer->finished_files; iter; iter = iter->next) {
            file = iter->data;

            RM_DEFINE_PATH(file);
            /* update progress counters which exclude hardlink files */
            if(!RM_IS_BUNDLED_HARDLINK(file)) {
                counters->shred_files_remaining--;
                counters->shred_bytes_remaining -= file->file_size - file->hash_offset;
                if(is_dupe_group && !file->is_original) {
                    counters->total_lint_size += file->file_size;
                }
            }

            /* update progress counters which apply to dupes (including
             * hardlinks) */
            if(is_dupe_group) {
                if(file->is_original) {
                    counters->original_bytes += file->file_size;
                } else {
                    counters->dup_counter++;
                    counters->duplicate_bytes += file->file_size;
                }
            } else {
                counters->unique_bytes += file->file_size;
            }

            if(merge) {
                /* feed file to treemerge */
                rm_tm_feed(session->dir_merger, file);
            } else {
                /* Hand file over to the printing module */
                /* TODO: check this handles RM_LINT_TYPE_READ_ERROR and
                 * RM_LINT_TYPE_BASENAME_TWIN correctly */
                rm_fmt_write(file, session->formats, files);
            }
        }
        if(!merge && !session->cfg->cache_file_structs) {
            g_slist_free_full(buffer->finished_files, (GDestroyNotify)rm_file_destroy);
        } else {
            g_slist_free(buffer->finished_files);
        }
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

    session->mds =
        rm_mds_new(cfg->read_threads, session->mounts, cfg->fake_pathindex_as_disk);

    if(cfg->merge_directories) {
        session->dir_merger = rm_tm_new(cfg);
    }

    /* --- Traversal --- */

    /* Create a single-threaded pool to receive files from traverse */
    GThreadPool *traverse_file_pool =
        rm_util_thread_pool_new((GFunc)rm_session_traverse_pipe, session, 1, TRUE);

    rm_traverse_tree(session->cfg, traverse_file_pool, session->mds, session->formats,
                     session->mounts);
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
            "%d hidden folders",
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
        session->counters->shred_bytes_read = 0;

        session->state = RM_PROGRESS_STATE_SHREDDER;
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_SHREDDER);

        GThreadPool *shredder_pipe =
            rm_util_thread_pool_new((GFunc)rm_session_shredder_pipe, session, 1, FALSE);

        rm_shred_run(cfg, session->tables, session->mds, shredder_pipe,
                     session->counters->total_filtered_files);
        g_thread_pool_free(shredder_pipe, FALSE, TRUE);
        rm_fmt_set_state(session->formats, RM_PROGRESS_STATE_SHREDDER_DONE);

        rm_log_debug_line("Dupe search finished at time %.3f, total bytes read %lu",
                          g_timer_elapsed(session->timer, NULL),
                          session->counters->shred_bytes_read);
    }

    rm_mds_free(session->mds, FALSE);

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

    if(session->counters->shred_bytes_remaining != 0 &&
       (cfg->find_duplicates || cfg->merge_directories)) {
        rm_log_error_line(
            "BUG: Number of remaining bytes is %lu"
            " (not 0). Please report this.",
            session->counters->shred_bytes_remaining);
        exit_state = EXIT_FAILURE;
    }

    if(session->counters->shred_files_remaining != 0 &&
       (cfg->find_duplicates || cfg->merge_directories)) {
        rm_log_error_line(
            "BUG: Number of remaining files is %lu"
            " (not 0). Please report this.",
            session->counters->shred_files_remaining);
        exit_state = EXIT_FAILURE;
    }

    return exit_state;
}
