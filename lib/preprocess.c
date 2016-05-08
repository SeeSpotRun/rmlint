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

    g_hash_table_unref(tables->unique_paths_table);

    g_mutex_clear(&tables->lock);
    g_slice_free(RmFileTables, tables);
}

/* if file is not DUPE_CANDIDATE then send it to session->tables->other_lint and
 * return 1; else return 0 */
static bool rm_pp_handle_other_lint(RmFile *file, const RmPPSession *preprocessor) {
    if(file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        return FALSE;
    }
    /* TODO: move to traversal? */
    if(preprocessor->cfg->filter_mtime && file->mtime < preprocessor->cfg->min_mtime) {
        file->lint_type = RM_LINT_TYPE_WRONG_TIME;
    } else if((preprocessor->cfg->keep_all_tagged && file->is_prefd) ||
              (preprocessor->cfg->keep_all_untagged && !file->is_prefd)) {
        /* "Other" lint protected by --keep-all-{un,}tagged */
        file->lint_type = RM_LINT_TYPE_KEEP_TAGGED;
    }
    g_thread_pool_push(preprocessor->preprocess_file_pipe, file, NULL);
    return TRUE;
}

/* this is slightly annoying but enables use of rm_util_slist_foreach_remove */
typedef struct {
    RmFile *prev_file;
    GThreadPool *preprocess_file_pipe;
} RmPPPathDoubleBuffer;

static bool rm_pp_check_path_double(RmFile *file, RmPPPathDoubleBuffer *buf) {
    if(buf->prev_file && rm_file_cmp_pathdouble(file, buf->prev_file) == 0) {
        file->lint_type = RM_LINT_TYPE_PATHDOUBLE;
        g_thread_pool_push(buf->preprocess_file_pipe, file, NULL);
        return TRUE;
    }
    buf->prev_file = file;
    return FALSE;
}

#define RM_SLIST_LEN_GT_1(list) (list) && (list)->next

/* Preprocess files, including embedded hardlinks.  Any embedded hardlinks
 * that are "other lint" types are sent to rm_pp_handle_other_lint.  If the
 * file itself is "other lint" types it is likewise sent to rm_pp_handle_other_lint.
 * If there are no files left after this then return TRUE so that the
 * cluster can be deleted from the node_table hash table.
 * NOTE: we rely on rm_file_list_insert to select an RM_LINT_TYPE_DUPE_CANDIDATE as head
 * file (unless ALL the files are "other lint"). */
static RmFile *rm_preprocess_cluster(GSList *cluster, RmPPSession *preprocessor) {
    const RmCfg *cfg = preprocessor->cfg;

    if(RM_SLIST_LEN_GT_1(cluster)) {
        /* there is a cluster of inode matches */

        /* remove path doubles by sorting and then finding identical neighbours */
        /* TODO: this seems to slow down rmlint somewhat; revisit */
        cluster = g_slist_sort(cluster, (GCompareFunc)rm_file_cmp_pathdouble_full);

        RmPPPathDoubleBuffer buf;
        buf.prev_file = NULL;
        buf.preprocess_file_pipe = preprocessor->preprocess_file_pipe;

        rm_util_slist_foreach_remove(&cluster, (RmRFunc)rm_pp_check_path_double, &buf);
    }

    /* process and remove other lint */
    rm_util_slist_foreach_remove(&cluster, (RmRFunc)rm_pp_handle_other_lint,
                                 (RmPPSession *)preprocessor);

    if(RM_SLIST_LEN_GT_1(cluster)) {
        /* bundle or free the non-head files */
        /* TODO: defer this until shredder */
        RmFile *headfile = cluster->data;
        if(cfg->find_hardlinked_dupes) {
            /* prepare to bundle files under the hardlink head */
            headfile->hardlinks.files = g_queue_new();
            headfile->hardlinks.is_head = TRUE;
        }
        GSList *hardlinks = cluster->next;
        cluster->next = NULL;

        for(GSList *iter = hardlinks; iter; iter = iter->next) {
            RmFile *file = iter->data;
            if(cfg->find_hardlinked_dupes) {
                /* bundle hardlink */
                g_queue_push_tail(headfile->hardlinks.files, file);
                file->hardlinks.hardlink_head = headfile;
            } else {
                file->lint_type = RM_LINT_TYPE_HARDLINK;
            }
            /* send to file pipe for counting (hardlink cluster are counted as
             * filtered files since they are either ignored or treated as automatic
             * duplicates depending on settings, and occupy no space anyway).
             */
            g_thread_pool_push(preprocessor->preprocess_file_pipe, file, NULL);
        }
        g_slist_free(hardlinks);
    }

    if(cluster) {
        /* should only be max 1 file left in list */
        rm_assert_gentle(!cluster->next);
        RmFile *result = cluster->data;
        g_slist_free(cluster);
        return result;
    }
    return NULL;
}

static GSList *rm_preprocess_size_group(GSList *head, RmPPSession *preprocessor) {
    /* sort by inode so we can identify inode clusters; this is faster
     * and lighter than hashtable approach */
    GSList *result = NULL;
    head = g_slist_sort(head, (GCompareFunc)rm_file_node_cmp);
    GSList *next = NULL;
    for(GSList *iter = head; iter; iter = next) {
        next = iter->next;
        if(!next || rm_file_node_cmp(iter->data, next->data) != 0) {
            /* next inode found; split the list */
            iter->next = NULL;
            /* process head...iter to remove lint and bundle hardlinks */
            RmFile *cluster_file = rm_preprocess_cluster(head, preprocessor);
            if(cluster_file) {
                result = g_slist_prepend(result, cluster_file);
            }
            /* point to start of next cluster */
            head = next;
        }
    }
    if(result && !result->next && !((RmFile *)result->data)->hardlinks.is_head) {
        /* singleton group; discard */
        RmFile *file = result->data;
        file->lint_type = RM_LINT_TYPE_UNIQUE_FILE;
        g_thread_pool_push(preprocessor->preprocess_file_pipe, file, NULL);
        g_slist_free(result);
        result = NULL;
    }

    return result;
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
    RmPPSession *preprocessor = g_slice_new(RmPPSession);
    preprocessor->cfg = cfg;
    preprocessor->tables = tables;
    preprocessor->preprocess_file_pipe = preprocess_file_pipe;

    rm_assert_gentle(tables->all_files);

    /* initial sort by size */
    tables->all_files = g_slist_sort_with_data(
        tables->all_files, (GCompareDataFunc)rm_file_cmp_full, (gpointer)cfg);

    /* split into file size groups and process each group to remove path doubles etc */
    GSList *next = NULL;
    for(GSList *iter = tables->all_files; iter; iter = next) {
        next = iter->next;
        if(!next || rm_file_cmp_size_etc(iter->data, next->data, (gpointer)cfg) != 0) {
            /* split list and process size group*/
            if(rm_session_was_aborted()) {
                break;
            }
            iter->next = NULL;
            GSList *size_group =
                rm_preprocess_size_group(tables->all_files, preprocessor);
            if(size_group) {
                tables->size_groups = g_slist_prepend(tables->size_groups, size_group);
            }
            tables->all_files = next;
        }
    }
    g_slice_free(RmPPSession, preprocessor);
}
