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

static gint rm_file_cmp_with_extension(const RmFile *file_a, const RmFile *file_b) {
    char *ext_a = rm_util_path_extension(file_a->folder->basename);
    char *ext_b = rm_util_path_extension(file_b->folder->basename);

    if(ext_a && ext_b) {
        return g_ascii_strcasecmp(ext_a, ext_b);
    } else {
        return (!!ext_a - !!ext_b);
    }
}

static gint rm_file_cmp_without_extension(const RmFile *file_a, const RmFile *file_b) {
    const char *basename_a = file_a->folder->basename;
    const char *basename_b = file_b->folder->basename;

    char *ext_a = rm_util_path_extension(basename_a);
    char *ext_b = rm_util_path_extension(basename_b);

    /* Check length till extension, or full length if none present */
    size_t a_len = (ext_a) ? (ext_a - basename_a) : (int)strlen(basename_a);
    size_t b_len = (ext_b) ? (ext_b - basename_b) : (int)strlen(basename_a);

    if(a_len != b_len) {
        return a_len - b_len;
    }

    return g_ascii_strncasecmp(basename_a, basename_b, a_len);
}

/* test if two files qualify for the same "group"; if not then rank them by
 * size and then other factors depending on settings */
gint rm_file_cmp(const RmFile *file_a, const RmFile *file_b) {
    gint result = SIGN_DIFF(file_a->file_size, file_b->file_size);

    const RmCfg *const cfg = file_a->cfg;

    if(result == 0) {
        result = (cfg->match_basename) ? rm_file_basenames_cmp(file_a, file_b) : 0;
    }

    if(result == 0) {
        result =
            (cfg->match_with_extension) ? rm_file_cmp_with_extension(file_a, file_b) : 0;
    }

    if(result == 0) {
        result = (cfg->match_without_extension)
                     ? rm_file_cmp_without_extension(file_a, file_b)
                     : 0;
    }

    return result;
}

gint rm_file_cmp_full(const RmFile *file_a, const RmFile *file_b,
                      const RmSession *session) {
    gint result = rm_file_cmp(file_a, file_b);
    if(result != 0) {
        return result;
    }
    return rm_pp_cmp_orig_criteria(file_a, file_b, session);
}

static int rm_node_cmp(const RmFile *file_a, const RmFile *file_b) {
    gint result = SIGN_DIFF(file_a->dev, file_b->dev);
    if(result == 0) {
        return SIGN_DIFF(file_a->inode, file_b->inode);
    }
    return result;
}

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

RmFileTables *rm_file_tables_new(_UNUSED const RmSession *session) {
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

static int rm_pp_cmp_by_regex(GRegex *regex, int idx, RmPatternBitmask *mask_a,
                              const char *path_a, RmPatternBitmask *mask_b,
                              const char *path_b) {
    int result = 0;

    if(RM_PATTERN_IS_CACHED(mask_a, idx)) {
        /* Get the previous match result */
        result = RM_PATTERN_GET_CACHED(mask_a, idx);
    } else {
        /* Match for the first time */
        result = g_regex_match(regex, path_a, 0, NULL);
        RM_PATTERN_SET_CACHED(mask_a, idx, result);
    }

    if(result) {
        return -1;
    }

    if(RM_PATTERN_IS_CACHED(mask_b, idx)) {
        /* Get the previous match result */
        result = RM_PATTERN_GET_CACHED(mask_b, idx);
    } else {
        /* Match for the first time */
        result = g_regex_match(regex, path_b, 0, NULL);
        RM_PATTERN_SET_CACHED(mask_b, idx, result);
    }

    if(result) {
        return +1;
    }

    /* Both match or none of the both match */
    return 0;
}

/* Sort criteria for sorting by preferred path (first) then user-input criteria */
/* Return:
 *      a negative integer file 'a' outranks 'b',
 *      0 if they are equal,
 *      a positive integer if file 'b' outranks 'a'
 */
int rm_pp_cmp_orig_criteria(const RmFile *a, const RmFile *b, const RmSession *session) {
    if(a->lint_type != b->lint_type) {
        /* "other" lint outranks duplicates and has lower ENUM */
        return a->lint_type - b->lint_type;
    } else if(a->is_symlink != b->is_symlink) {
        return a->is_symlink - b->is_symlink;
    } else if(a->is_prefd != b->is_prefd) {
        return (b->is_prefd - a->is_prefd);
    } else {
        /* Only fill in path if we have a pattern in sort_criteria */
        bool path_needed = (session->cfg->pattern_cache->len > 0);
        RM_DEFINE_PATH_IF_NEEDED(a, path_needed);
        RM_DEFINE_PATH_IF_NEEDED(b, path_needed);

        RmCfg *sets = session->cfg;

        for(int i = 0, regex_cursor = 0; sets->sort_criteria[i]; i++) {
            long cmp = 0;
            switch(tolower((unsigned char)sets->sort_criteria[i])) {
            case 'm':
                cmp = (long)(a->mtime) - (long)(b->mtime);
                break;
            case 'a':
                cmp = g_ascii_strcasecmp(a->folder->basename, b->folder->basename);
                break;
            case 'l':
                cmp = strlen(a->folder->basename) - strlen(b->folder->basename);
                break;
            case 'd':
                cmp = (short)a->depth - (short)b->depth;
                break;
            case 'p':
                cmp = (long)a->path_index - (long)b->path_index;
                break;
            case 'x': {
                cmp = rm_pp_cmp_by_regex(
                    g_ptr_array_index(session->cfg->pattern_cache, regex_cursor),
                    regex_cursor, (RmPatternBitmask *)&a->pattern_bitmask_basename,
                    a->folder->basename, (RmPatternBitmask *)&b->pattern_bitmask_basename,
                    b->folder->basename);
                regex_cursor++;
                break;
            }
            case 'r':
                cmp = rm_pp_cmp_by_regex(
                    g_ptr_array_index(session->cfg->pattern_cache, regex_cursor),
                    regex_cursor, (RmPatternBitmask *)&a->pattern_bitmask_path, a_path,
                    (RmPatternBitmask *)&b->pattern_bitmask_path, b_path);
                regex_cursor++;
                break;
            }
            if(cmp) {
                /* reverse order if uppercase option */
                cmp = cmp * (isupper((unsigned char)sets->sort_criteria[i]) ? -1 : +1);
                return cmp;
            }
        }
        return 0;
    }
}

/* if file is not DUPE_CANDIDATE then send it to session->tables->other_lint and
 * return 1; else return 0 */
static bool rm_pp_handle_other_lint(RmFile *file, const RmSession *session) {
    if(file->lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        return FALSE;
    }
    /* TODO: move to traversal? */
    if(session->cfg->filter_mtime && file->mtime < session->cfg->min_mtime) {
        file->lint_type = RM_LINT_TYPE_WRONG_TIME;
    } else if((session->cfg->keep_all_tagged && file->is_prefd) ||
              (session->cfg->keep_all_untagged && !file->is_prefd)) {
        /* "Other" lint protected by --keep-all-{un,}tagged */
        file->lint_type = RM_LINT_TYPE_KEEP_TAGGED;
    }
    session->tables->other_lint[file->lint_type] =
        g_slist_prepend(session->tables->other_lint[file->lint_type], file);
    return TRUE;
}

static bool rm_pp_check_path_double(RmFile *file, RmSession *session) {
    RmPathDoubleKey *key = rm_path_double_new(file);

    /* Lookup if there is a file with the same path */
    RmPathDoubleKey *match_double_key =
        g_hash_table_lookup(session->tables->unique_paths_table, key);

    if(match_double_key == NULL) {
        g_hash_table_add(session->tables->unique_paths_table, key);
        return FALSE;
    }
    RmFile *match_double = match_double_key->file;
    rm_assert_gentle(match_double != file);

    rm_path_double_free(key);
    file->lint_type = RM_LINT_TYPE_PATHDOUBLE;
    g_thread_pool_push(session->preprocess_file_pipe, file, NULL);
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
static RmFile *rm_preprocess_cluster(GSList *cluster, RmSession *session) {
    RmCfg *cfg = session->cfg;

    if(RM_SLIST_LEN_GT_1(cluster)) {
        /* there is a cluster of inode matches */

        /* remove path doubles */
        rm_util_slist_foreach_remove(&cluster, (RmRFunc)rm_pp_check_path_double, session);
        /* clear the hashtable ready for the next cluster */
        g_hash_table_remove_all(session->tables->unique_paths_table);
    }

    /* process and remove other lint */
    rm_util_slist_foreach_remove(&cluster, (RmRFunc)rm_pp_handle_other_lint,
                                 (RmSession *)session);

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
            g_thread_pool_push(session->preprocess_file_pipe, file, NULL);
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

static GSList *rm_preprocess_size_group(GSList *head, RmSession *session) {
    /* sort by inode so we can identify inode clusters; this is faster
     * and lighter than hashtable approach */
    GSList *result = NULL;
    head = g_slist_sort(head, (GCompareFunc)rm_node_cmp);
    GSList *next = NULL;
    for(GSList *iter = head; iter; iter = next) {
        next = iter->next;
        if(!next || rm_node_cmp(iter->data, next->data) != 0) {
            /* next inode found; split the list */
            iter->next = NULL;
            /* process head...iter to remove lint and bundle hardlinks */
            RmFile *cluster_file = rm_preprocess_cluster(head, session);
            if(cluster_file) {
                result = g_slist_prepend(result, cluster_file);
            }
            /* point to start of next cluster */
            head = next;
        }
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
void rm_preprocess(RmSession *session) {
    RmFileTables *tables = session->tables;
    GSList *head = tables->all_files;
    tables->all_files = NULL;
    rm_assert_gentle(head);

    /* initial sort by size */
    head = g_slist_sort_with_data(head, (GCompareDataFunc)rm_file_cmp_full, session);
    rm_log_debug_line("initial size sort finished at time %.3f",
                      g_timer_elapsed(session->timer, NULL));

    /* split into file size groups and process each group to remove path doubles etc */
    GSList *next = NULL;
    for(GSList *iter = head; iter; iter = next) {
        next = iter->next;
        if(!next || rm_file_cmp(iter->data, next->data) != 0) {
            /* split list and process size group*/
            if(rm_session_was_aborted()) {
                break;
            }
            iter->next = NULL;
            GSList *size_group = rm_preprocess_size_group(head, session);
            if(size_group) {
                tables->size_groups = g_slist_prepend(tables->size_groups, size_group);
            }
            head = next;
        }
    }
}
