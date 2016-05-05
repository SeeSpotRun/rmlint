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

/* GHashTable key tuned to recognize duplicate paths.
 * i.e. RmFiles that are not only hardlinks but
 * also point to the real path
 */
typedef struct RmPathDoubleKey {
    /* stat(dirname(file->path)).st_ino */
    ino_t parent_inode;

    /* File the key points to */
    RmFile *file;

} RmPathDoubleKey;

static gpointer rm_path_double_hash(const RmPathDoubleKey *key) {
    /* depend only on the always set components, never change the hash duringthe run */
    return (gpointer)key->file->folder->parent;
}

static bool rm_path_have_same_parent(RmPathDoubleKey *key_a, RmPathDoubleKey *key_b) {
    RmFile *file_a = key_a->file, *file_b = key_b->file;
    return file_a->folder->parent == file_b->folder->parent;
}

static gboolean rm_path_double_equal(RmPathDoubleKey *key_a, RmPathDoubleKey *key_b) {
    if(key_a->file->inode != key_b->file->inode) {
        return FALSE;
    }

    if(key_a->file->dev != key_b->file->dev) {
        return FALSE;
    }

    RmFile *file_a = key_a->file;
    RmFile *file_b = key_b->file;

    if(!rm_path_have_same_parent(key_a, key_b)) {
        return FALSE;
    }

    return g_strcmp0(file_a->folder->basename, file_b->folder->basename) == 0;
}

static RmPathDoubleKey *rm_path_double_new(RmFile *file) {
    RmPathDoubleKey *key = g_malloc0(sizeof(RmPathDoubleKey));
    key->file = file;
    return key;
}

static void rm_path_double_free(RmPathDoubleKey *key) {
    g_free(key);
}

RmFileTables *rm_file_tables_new(void) {
    RmFileTables *tables = g_slice_new0(RmFileTables);

    tables->unique_paths_table =
        g_hash_table_new_full((GHashFunc)rm_path_double_hash,
                              (GEqualFunc)rm_path_double_equal,
                              (GDestroyNotify)rm_path_double_free,
                              NULL);

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

static bool rm_pp_check_path_double(RmFile *file, RmPPSession *preprocessor) {
    RmPathDoubleKey *key = rm_path_double_new(file);

    /* Lookup if there is a file with the same path */
    RmPathDoubleKey *match_double_key =
        g_hash_table_lookup(preprocessor->tables->unique_paths_table, key);

    if(match_double_key == NULL) {
        g_hash_table_add(preprocessor->tables->unique_paths_table, key);
        return FALSE;
    }
    RmFile *match_double = match_double_key->file;
    rm_assert_gentle(match_double != file);

    rm_path_double_free(key);
    file->lint_type = RM_LINT_TYPE_PATHDOUBLE;
    g_thread_pool_push(preprocessor->preprocess_file_pipe, file, NULL);
    return TRUE;
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

        /* remove path doubles */
        rm_util_slist_foreach_remove(&cluster, (RmRFunc)rm_pp_check_path_double,
                                     preprocessor);
        /* clear the hashtable ready for the next cluster */
        g_hash_table_remove_all(preprocessor->tables->unique_paths_table);
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
