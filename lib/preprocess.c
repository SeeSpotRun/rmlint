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
 * Authors:
 *
 *  - Christopher <sahib> Pahl 2010-2015 (https://github.com/sahib)
 *  - Daniel <SeeSpotRun> T.   2014-2015 (https://github.com/SeeSpotRun)
 *
 * Hosted on http://github.com/sahib/rmlint
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "preprocess.h"
#include "utilities.h"
#include "formats.h"
#include "cmdline.h"
#include "shredder.h"

typedef struct RmPPSession {
    const RmCfg *cfg;
    RmFileTables *tables;
    GThreadPool *preprocess_file_pipe;
} RmPPSession;

RmFileTables *rm_file_tables_new(void) {
    RmFileTables *tables = g_slice_new0(RmFileTables);
    g_mutex_init(&tables->lock);
    return tables;
}

void rm_file_tables_destroy(RmFileTables *tables) {
    g_slist_free(tables->all_files);

    if(tables->size_groups) {
        g_slist_free(tables->size_groups);
        tables->size_groups = NULL;
    }

    g_mutex_clear(&tables->lock);
    g_slice_free(RmFileTables, tables);
}

static int rm_preprocess_hardlinks(RmFile *file, RmFile *prev,
                                   RmPPSession *preprocessor) {
    if(!prev) {
        return FALSE;
    }
    if(rm_file_node_cmp(file, prev) != 0) {
        /* not a hardlink */
        return FALSE;
    }

    /* file is a hardlink of prev; remove from list, possibly bundling first depending on
     * cfg */
    if(!preprocessor->cfg->find_hardlinked_dupes) {
        /* we're not looking for hardlinked dupes */
        file->lint_type = RM_LINT_TYPE_HARDLINK;
    } else {
        /* bundle hardlink */
        if(!prev->hardlinks.files) {
            /* first hardlink, set up queue */
            prev->hardlinks.files = g_queue_new();
            prev->hardlinks.is_head = TRUE;
        }
        g_queue_push_tail(prev->hardlinks.files, file);
        file->hardlinks.hardlink_head = prev;
    }

    /* send file to session for counting purposes (whether bundled or not) */
    rm_util_thread_pool_push(preprocessor->preprocess_file_pipe, file);
    return TRUE;
}

/* Preprocess duplicate candidate groups to bundle embedded hardlinks.
 * Return TRUE if the resultant group has only 1 member */
static int rm_preprocess_size_group(GSList *group, _UNUSED GSList *prev,
                                    RmPPSession *preprocessor) {
    rm_assert_gentle(group);
    rm_assert_gentle(preprocessor);
    rm_util_slist_foreach_remove(&group, (RmSListRFunc)rm_preprocess_hardlinks,
                                 preprocessor);
    rm_assert_gentle(group);
    if(!group->next) {
        RmFile *solo = group->data;
        if(!solo->hardlinks.is_head) {
            solo->lint_type = RM_LINT_TYPE_UNIQUE_FILE;
            rm_util_thread_pool_push(preprocessor->preprocess_file_pipe, solo);
            g_slist_free(group);
            return TRUE;
        }
    }
    return FALSE;
}

/* sort function to sort files into size groups; also groups hardlinks within
 * each size group.  Guaranteed to place path doubles adjacent to each other
 * in decreasing order of "originality" criteria.
 * Used for first pass of preprocessing */
gint rm_pp_cmp_phase1(const RmFile *file_a, const RmFile *file_b, const RmCfg *cfg) {
    /* sort by size then (depending on cfg) maybe by basename extension and/or prefix;
     * note this will never separate path doubles but may separate hardlinks */
    gint result = rm_file_cmp_dupe_group(file_a, file_b, cfg);
    if(result != 0) {
        return result;
    }
    /* next sort by dev/inode so that hardlinks path doubles get grouped together */
    if((result = rm_file_node_cmp(file_a, file_b)) != 0) {
        return result;
    }

    if((result = rm_file_cmp_pathdouble(file_a, file_b)) != 0) {
        return result;
    }

    /* must be path doubles; rank most "original" first */

    return rm_file_cmp_orig_criteria_pre(file_a, file_b, cfg);
}

/* sort function to sort size groups by inode then by originality; this facilitates
 * hardlink bundling */
gint rm_pp_cmp_phase2(const RmFile *file_a, const RmFile *file_b, const RmCfg *cfg) {
    gint result = rm_file_node_cmp(file_a, file_b);
    if(result != 0) {
        return result;
    }
    return rm_file_cmp_orig_criteria_pre(file_a, file_b, cfg);
}

/* RMRFunc to strip out "other lint" and path doubles */
static int rm_pp_strip_lint(RmFile *file, RmFile *prev, RmPPSession *preprocessor) {
    rm_assert_gentle(file);

    if(prev && rm_file_node_cmp(file, prev) == 0 &&
       rm_file_cmp_pathdouble(file, prev) == 0) {
        /* path double; kick out */
        rm_log_debug_line("Kicking path double");
        file->lint_type = RM_LINT_TYPE_PATHDOUBLE;
        /* will send to threadpool before return */
    } else if(file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        return FALSE;
    } else {
        /* handle "other" lint... */
        /* First check some filter criteria (TODO: move to traversal?) */
        const RmCfg *cfg = preprocessor->cfg;
        if(cfg->filter_mtime && file->mtime < cfg->min_mtime) {
            file->lint_type = RM_LINT_TYPE_WRONG_TIME;
        } else if((cfg->keep_all_tagged && file->is_prefd) ||
                  (cfg->keep_all_untagged && !file->is_prefd)) {
            /* "Other" lint protected by --keep-all-{un,}tagged */
            file->lint_type = RM_LINT_TYPE_KEEP_TAGGED;
        }
    }

    g_thread_pool_push(preprocessor->preprocess_file_pipe, file, NULL);
    return TRUE;
}

/* This does preprocessing including handling of "other lint" (non-dupes)
 * After rm_preprocess(), all remaining duplicate candidates are in
 * a jagged GSList of GSLists as follows:
 * session->tables->size_groups->group1->file1a
 *                                     ->file1b
 *                                     ->file1c
 *                             ->group2->file2a
 *                                     ->file2b
 *                                       etc
 */
void rm_preprocess(const RmCfg *cfg, RmFileTables *tables,
                   GThreadPool *preprocess_file_pipe) {
    RmPPSession preprocessor;
    preprocessor.cfg = cfg;
    preprocessor.tables = tables;
    preprocessor.preprocess_file_pipe = preprocess_file_pipe;

    rm_assert_gentle(tables->all_files);

    /* initial sort by size */
    tables->all_files = g_slist_sort_with_data(
        tables->all_files, (GCompareDataFunc)rm_pp_cmp_phase1, (gpointer)cfg);

    /* remove path doubles and other lint */
    rm_util_slist_foreach_remove(&tables->all_files, (RmSListRFunc)rm_pp_strip_lint,
                                 &preprocessor);

    /* chunk into size groups */
    for(GSList *iter = tables->all_files, *next = NULL; iter; iter = next) {
        next = iter->next;
        if(!next || rm_file_cmp_dupe_group(iter->data, next->data, cfg) != 0) {
            iter->next = NULL;
            GSList *size_group = g_slist_sort_with_data(
                tables->all_files, (GCompareDataFunc)rm_pp_cmp_phase2, (gpointer)cfg);
            tables->size_groups = g_slist_prepend(tables->size_groups, size_group);
            tables->all_files = next;
        }
    }

    /* for each size group, bundle hardlinks.  Delete any singleton groups */
    rm_util_slist_foreach_remove(&tables->size_groups,
                                 (RmSListRFunc)rm_preprocess_size_group, &preprocessor);
}
