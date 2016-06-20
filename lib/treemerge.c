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

/* This is the treemerge algorithm.
 *
 * It tries to solve the following problem and sometimes even succeeds:
 * Take a list of duplicates (as RmFiles) and figure out which directories
 * consist fully out of duplicates and can be thus removed.
 *
 * The basic algorithm is split in four phases:
 *
 * - Counting:  Walk through all directories given on the commandline and
 *              traverse them. Count all files during traverse and safe it in
 *              an radix-tree (libart is used here). The key is the path, the
 *              value the count of files in it. Invalid directories and
 *              directories above the given are set to -1.
 * - Feeding:   Collect all duplicates and store them in RmDirectory structures.
 *              If a directory appears to consist of dupes only (num_dupes == num_files)
 *              then it is remembered as valid directory.
 * - Upcluster: Take all valid directories and cluster them up, so subdirs get
 *              merged into the parent directory. Continue as long the parent
 *              directory is full too. Remember full directories in a hashtable
 *              with the hash of the directory (which is a hash of the file's
 *              hashes) as key and a list of matching directories as value.
 * - Extract:   Extract the result information out of the hashtable top-down.
 *              If a directory is reported, mark all subdirs of it as finished
 *              so they do not get reported twice. Files that could not be
 *              grouped in directories are found and reported as usually.
 */

/*
 * Comment this out to see helpful extra debugging:
 */
// #define _RM_TREEMERGE_DEBUG

#include <glib.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "formats.h"
#include "pathtricia.h"
#include "preprocess.h"
#include "shredder.h"
#include "treemerge.h"

typedef struct RmDirectory {
    char *dirname;       /* Path to this directory without trailing slash              */
    GQueue known_files;  /* RmFiles in this directory                                  */
    GQueue children;     /* Children for directories with subdirectories               */
    gint64 prefd_files;  /* Files in this directory that are tagged as original        */
    gint64 dupe_count;   /* Count of RmFiles actually in this directory                */
    gint64 file_count;   /* Count of files actually in this directory (or -1 on error) */
    gint64 mergeups;     /* number of times this directory was merged up               */
    bool finished : 1;   /* Was this dir or one of his parents already printed?        */
    bool was_merged : 1; /* true if this directory was merged up already (only once)   */
    bool was_inserted : 1; /* true if this directory was added to results (only once) */
    unsigned short depth; /* path depth (i.e. count of / in path, no trailing /)        */
    GHashTable *hash_set; /* Set of hashes, used for equality check (to be sure)        */
    RmDigest *digest;     /* Common digest of all RmFiles in this directory             */
    RmNode *node;         /* corresponding node in the 'main' trie                      */

    struct {
        time_t dir_mtime; /* Directory Metadata: Modification Time */
        ino_t dir_inode;  /* Directory Metadata: Inode             */
        dev_t dir_dev;    /* Directory Metadata: Device ID         */
    } metadata;
} RmDirectory;

struct RmTreeMerger {
    RmCfg *cfg;               /* rmlint configuration settings                       */
    RmFmtTable *formats;      /* output module                                       */
    RmCounters *counters;     /* session statistics                                  */
    RmTrie dir_tree;          /* Path-Trie with all RmFiles as value                 */
    GHashTable *result_table; /* {hash => [RmDirectory]} mapping                     */
    GHashTable *file_groups;  /* Group files by hash                                 */
    GHashTable *file_checks;  /* Set of files that were handled already.             */
    GHashTable *known_hashs;  /* Set of known hashes, only used for cleanup.         */
    GQueue *free_list;        /* List of directory-as-RmFiles to free at end.        */
    GQueue valid_dirs;        /* Directories consisting of RmFiles only              */
};

///////////////////////////////
// DIRECTORY STRUCT HANDLING //
///////////////////////////////

static RmDirectory *rm_directory_new(char *dirname) {
    RmDirectory *self = g_new0(RmDirectory, 1);

    self->file_count = 0;
    self->dupe_count = 0;
    self->prefd_files = 0;
    self->was_merged = false;
    self->was_inserted = false;
    self->mergeups = 0;

    self->dirname = dirname;
    self->finished = false;

    self->depth = 0;
    for(char *s = dirname; *s; s++) {
        self->depth += (*s == G_DIR_SEPARATOR);
    }

    RmStat dir_stat;
    if(rm_sys_stat(self->dirname, &dir_stat) == -1) {
        rm_log_perror("stat(2) failed during sort");
    } else {
        self->metadata.dir_mtime = dir_stat.st_mtime;
        self->metadata.dir_inode = dir_stat.st_ino;
        self->metadata.dir_dev = dir_stat.st_dev;
    }

    /* Special cumulative hashsum, that is not dependent on the
     * order in which the file hashes were added.
     * It is not used as full hash, but as sorting speedup.
     */
    self->digest = rm_digest_new(RM_DIGEST_CUMULATIVE, 0, 0, 0, false);

    g_queue_init(&self->known_files);
    g_queue_init(&self->children);

    self->hash_set =
        g_hash_table_new((GHashFunc)rm_digest_hash, (GEqualFunc)rm_digest_equal);

    return self;
}

static void rm_directory_free(RmDirectory *self) {
    // TODO: rm_digest_free(self->digest);
    g_hash_table_unref(self->hash_set);
    g_queue_clear(&self->known_files);
    g_queue_clear(&self->children);
    g_free(self->dirname);
    g_free(self);
}

static RmOff rm_tm_calc_file_size(const RmDirectory *directory) {
    RmOff acc = 0;

    for(GList *iter = directory->known_files.head; iter; iter = iter->next) {
        RmFile *file = iter->data;
        acc += file->file_size;
    }

    /* Recursively propagate to children */
    for(GList *iter = directory->children.head; iter; iter = iter->next) {
        acc += rm_tm_calc_file_size((RmDirectory *)iter->data);
    }

    return acc;
}

static void rm_directory_to_file(RmTreeMerger *merger, const RmDirectory *self,
                                 RmFile *file) {
    memset(file, 0, sizeof(RmFile));

    /* Need to set cfg first, since set_path expects that */
    file->cfg = merger->cfg;
    file->folder = rm_trie_insert(&merger->cfg->file_trie, self->dirname);

    file->lint_type = RM_LINT_TYPE_DUPE_DIR_CANDIDATE;
    file->digest = self->digest;

    /* Set these to invalid for now */
    file->mtime = self->metadata.dir_mtime;
    file->inode = self->metadata.dir_inode;
    file->dev = self->metadata.dir_dev;
    file->depth = rm_util_path_depth(self->dirname);

    /* Recursively calculate the file size */
    file->file_size = rm_tm_calc_file_size(self);
    file->is_prefd = (self->prefd_files >= self->dupe_count);
}

static RmFile *rm_directory_as_new_file(RmTreeMerger *merger, const RmDirectory *self) {
    /* Masquerades an RmDirectory as RmFile for purpose of output */
    RmFile *file = g_malloc0(sizeof(RmFile));
    rm_directory_to_file(merger, self, file);
    return file;
}

static bool rm_directory_equal(RmDirectory *d1, RmDirectory *d2) {
    if(d1->mergeups != d2->mergeups) {
        return false;
    }

    if(rm_digest_equal(d1->digest, d2->digest) == false) {
        return false;
    }

    if(g_hash_table_size(d1->hash_set) != g_hash_table_size(d2->hash_set)) {
        return false;
    }

    gpointer digest_key;
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, d1->hash_set);
    while(g_hash_table_iter_next(&iter, &digest_key, NULL)) {
        if(g_hash_table_contains(d2->hash_set, digest_key) == false) {
            return false;
        }
    }

    return true;
}

static guint rm_directory_hash(const RmDirectory *d) {
    /* This hash is used to quickly compare directories with each other.
     * Different directories might yield the same hash of course.
     * To prevent this case, rm_directory_equal really compares
     * all the file's hashes with each other.
     */
    return rm_digest_hash(d->digest) ^ d->mergeups;
}

static int rm_directory_add(RmDirectory *directory, RmFile *file) {
    /* Update the directorie's hash with the file's hash
       Since we cannot be sure in which order the files come in
       we have to add the hash cummulatively.
     */
    rm_assert_gentle(file);
    rm_assert_gentle(file->digest);
    rm_assert_gentle(directory);
    rm_assert_gentle(rm_file_filecount(file) == 1);

    RmDigestSum *sum = NULL;

    if(file->digest->type == RM_DIGEST_PARANOID) {
        rm_assert_gentle(file->digest->paranoid->shadow_hash);
        sum = rm_digest_sum(file->digest->paranoid->shadow_hash);
    } else {
        sum = rm_digest_sum(file->digest);
    }

    /* + and not XOR, since ^ would yield 0 for same hashes always. No matter
     * which hashes. Also this would be confusing. For me and for debuggers.
     */
    rm_digest_update(directory->digest, sum->sum, sum->bytes);

    /* The file value is not really used, but we need some non-null value */
    g_hash_table_add(directory->hash_set, file->digest);

    rm_digest_sum_free(sum);
    directory->dupe_count++;
    directory->prefd_files += file->is_prefd;

    return 1;
}

static void rm_directory_add_subdir(RmDirectory *parent, RmDirectory *subdir) {
    if(subdir->was_merged) {
        return;
    }

    parent->mergeups = subdir->mergeups + parent->mergeups + 1;
    parent->dupe_count += subdir->dupe_count;
    g_queue_push_head(&parent->children, subdir);
    parent->prefd_files += subdir->prefd_files;

#ifdef _RM_TREEMERGE_DEBUG
    g_printerr("%55s (%3ld/%3ld) <- %s (%3ld/%3ld)\n", parent->dirname,
               parent->dupe_count, parent->file_count, subdir->dirname,
               subdir->dupe_count, subdir->file_count);
#endif

    /**
     * Here's something weird:
     * - a counter is used and substraced at once from parent->dupe_count.
     * - it would ofc. be nicer to substract it step by step.
     * - but for some weird reasons this only works on clang, not gcc.
     * - yes, what. But I tested this, I promise!
     */
    for(GList *iter = subdir->known_files.head; iter; iter = iter->next) {
        int c = rm_directory_add(parent, (RmFile *)iter->data);
        parent->dupe_count -= c;
    }

    /* Inherit the child's checksum */
    RmDigestSum *sum = rm_digest_sum(subdir->digest);
    rm_digest_update(parent->digest, sum->sum, sum->bytes);
    rm_digest_sum_free(sum);

    subdir->was_merged = true;
}

///////////////////////////
// TREE MERGER ALGORITHM //
///////////////////////////

RmTreeMerger *rm_tm_new(RmCfg *cfg, RmFmtTable *formats, RmCounters *counters) {
    RmTreeMerger *self = g_slice_new(RmTreeMerger);
    self->cfg = cfg;
    self->formats = formats;
    self->counters = counters;

    g_queue_init(&self->valid_dirs);
    self->free_list = g_queue_new();

    self->result_table = g_hash_table_new_full((GHashFunc)rm_directory_hash,
                                               (GEqualFunc)rm_directory_equal, NULL,
                                               (GDestroyNotify)g_queue_free);

    self->file_groups =
        g_hash_table_new_full((GHashFunc)rm_digest_hash, (GEqualFunc)rm_digest_equal,
                              NULL, (GDestroyNotify)g_queue_free);

    self->known_hashs = g_hash_table_new_full(NULL, NULL, NULL, NULL);

    rm_trie_init(&self->dir_tree);

    return self;
}

int rm_tm_destroy_iter(_UNUSED RmTrie *self, RmNode *node, _UNUSED int level,
                       _UNUSED RmTreeMerger *tm) {
    RmDirectory *directory = node->data;
    rm_directory_free(directory);
    return 0;
}

void rm_tm_destroy(RmTreeMerger *self) {
    g_hash_table_unref(self->result_table);
    g_hash_table_unref(self->file_groups);

    /* TODO: sort out digest freeing
     * GList *digest_keys = g_hash_table_get_keys(self->known_hashs);
     * g_list_free_full(digest_keys, (GDestroyNotify)rm_digest_free); */
    g_hash_table_unref(self->known_hashs);

    g_queue_clear(&self->valid_dirs);

    /* Kill all RmDirectories stored in the tree */
    rm_trie_iter(&self->dir_tree, NULL, true, false,
                 (RmTrieIterCallback)rm_tm_destroy_iter, self);

    rm_trie_destroy(&self->dir_tree);
    g_queue_free(self->free_list);

    g_slice_free(RmTreeMerger, self);
}

static void rm_tm_insert_dir(RmTreeMerger *self, RmDirectory *directory) {
    if(directory->was_inserted) {
        return;
    }

    GQueue *dir_queue =
        rm_hash_table_setdefault(self->result_table, directory, (RmNewFunc)g_queue_new);
    g_queue_push_head(dir_queue, directory);
    directory->was_inserted = true;
}

static void rm_directory_get_filecount(RmDirectory *directory) {
    RmDirInfo *info = directory->node ? directory->node->data : NULL;
    if(!info || info->traversal != RM_TRAVERSAL_FULL) {
        directory->file_count = -1;
    } else {
        directory->file_count = info->file_count;
    }
}

void rm_tm_feed(RmTreeMerger *self, RmFile *file) {
    RM_DEFINE_PATH(file);
    char *dirname = g_path_get_dirname(file_path);

    /* See if we know that directory already */
    RmDirectory *directory = rm_trie_search(&self->dir_tree, dirname);

    if(directory == NULL) {
        directory = rm_directory_new(dirname);
        directory->node = file->folder->parent;
        /* Get the actual file count */
        rm_directory_get_filecount(directory);

        /* Make the new directory known */
        rm_trie_insert(&self->dir_tree, dirname)->data = directory;

        g_queue_push_head(&self->valid_dirs, directory);

    } else {
        g_free(dirname);
    }

    g_queue_push_tail(self->free_list, file);
    rm_directory_add(directory, file);

    /* Add the file to this directory */
    g_queue_push_head(&directory->known_files, file);

    /* Remember the digest (if only to free it later...) */
    g_hash_table_replace(self->known_hashs, file->digest, NULL);

    /* Check if the directory reached the number of actual files in it */
    if(directory->dupe_count == directory->file_count && directory->file_count > 0) {
        rm_tm_insert_dir(self, directory);
    }
}

static void rm_tm_mark_finished(RmTreeMerger *self, RmDirectory *directory) {
    if(directory->finished) {
        return;
    }

    directory->finished = true;

    /* Recursively propagate to children */
    for(GList *iter = directory->children.head; iter; iter = iter->next) {
        rm_tm_mark_finished(self, (RmDirectory *)iter->data);
    }
}

static void rm_tm_mark_original_files(RmTreeMerger *self, RmDirectory *directory) {
    directory->finished = false;

    /* Recursively propagate to children */
    for(GList *iter = directory->children.head; iter; iter = iter->next) {
        RmDirectory *child = iter->data;
        rm_tm_mark_original_files(self, child);
    }
}

static gint64 rm_tm_mark_duplicate_files(RmTreeMerger *self, RmDirectory *directory) {
    gint64 acc = 0;

    for(GList *iter = directory->known_files.head; iter; iter = iter->next) {
        RmFile *file = iter->data;
        acc += file->is_prefd;
    }

    /* Recursively propagate to children */
    for(GList *iter = directory->children.head; iter; iter = iter->next) {
        RmDirectory *child = iter->data;
        acc += rm_tm_mark_duplicate_files(self, child);
    }

    return acc;
}

static void rm_tm_write_unfinished_cksums(RmTreeMerger *self, RmDirectory *directory) {
    for(GList *iter = directory->known_files.head; iter; iter = iter->next) {
        RmFile *file = iter->data;
        file->lint_type = RM_LINT_TYPE_UNIQUE_FILE;
        rm_fmt_write(file, self->formats, -1);
    }

    /* Recursively propagate to children */
    for(GList *iter = directory->children.head; iter; iter = iter->next) {
        RmDirectory *child = iter->data;
        rm_tm_write_unfinished_cksums(self, child);
    }
}

static int rm_tm_sort_paths(const RmDirectory *da, const RmDirectory *db,
                            _UNUSED RmTreeMerger *self) {
    return da->depth - db->depth;
}

static int rm_tm_sort_paths_reverse(const RmDirectory *da, const RmDirectory *db,
                                    _UNUSED RmTreeMerger *self) {
    return -rm_tm_sort_paths(da, db, self);
}

static int rm_tm_sort_orig_criteria(const RmDirectory *da, const RmDirectory *db,
                                    RmTreeMerger *self) {
    RmCfg *cfg = self->cfg;

    if(da->prefd_files - db->prefd_files) {
        if(cfg->keep_all_tagged) {
            return db->prefd_files - da->prefd_files;
        } else {
            return da->prefd_files - db->prefd_files;
        }
    }

    RmFile file_a, file_b;
    rm_directory_to_file(self, da, &file_a);
    rm_directory_to_file(self, db, &file_b);

    return rm_file_cmp_orig_criteria(&file_a, &file_b, cfg);
}

static void rm_tm_forward_unresolved(RmTreeMerger *self, RmDirectory *directory) {
    if(directory->finished == true) {
        return;
    } else {
        directory->finished = true;
    }

    for(GList *iter = directory->known_files.head; iter; iter = iter->next) {
        RmFile *file = iter->data;

        GQueue *file_list = rm_hash_table_setdefault(self->file_groups, file->digest,
                                                     (RmNewFunc)g_queue_new);
        g_queue_push_head(file_list, file);
    }

    /* Recursively propagate to children */
    for(GList *iter = directory->children.head; iter; iter = iter->next) {
        rm_tm_forward_unresolved(self, (RmDirectory *)iter->data);
    }
}

static int rm_tm_iter_unfinished_files(_UNUSED RmTrie *trie, RmNode *node,
                                       _UNUSED int level, _UNUSED void *user_data) {
    RmTreeMerger *self = user_data;
    rm_tm_forward_unresolved(self, node->data);
    return 0;
}

static int rm_tm_cmp_directory_groups(GQueue *a, GQueue *b) {
    if(a->length == 0 || b->length == 0) {
        return b->length - a->length;
    }

    RmDirectory *first_a = a->head->data;
    RmDirectory *first_b = b->head->data;
    return first_b->mergeups - first_a->mergeups;
}

static int rm_tm_hidden_file(RmFile *file, _UNUSED gpointer user_data) {
    return file->is_hidden;
}

/* needed because someone rewrote shredder to use GSList instead of GQueue*/
static void rm_tm_send(GQueue *group, RmTreeMerger *self, gboolean find_original) {
    /* convert GQueue to GSList for passing to rm_shred_group_find_original() */
    GSList *list = NULL;
    for(GList *iter = group->tail; iter; iter = iter->prev) {
        list = g_slist_prepend(list, iter->data);
    }

    if(find_original) {
        list = rm_shred_group_find_original(self->cfg, list, RM_LINT_TYPE_DUPE_CANDIDATE);
    }

    /* Hand it over to the printing module */
    for(GSList *iter = list; iter; iter = iter->next) {
        RmFile *file = iter->data;
        rm_fmt_write(file, self->formats, group->length);
    }

    g_slist_free(list);
}

static void rm_tm_extract(RmTreeMerger *self) {
    /* Iterate over all directories per hash (which are same therefore) */
    RmCfg *cfg = self->cfg;
    GList *result_table_values = g_hash_table_get_values(self->result_table);
    result_table_values =
        g_list_sort(result_table_values, (GCompareFunc)rm_tm_cmp_directory_groups);

    for(GList *iter = result_table_values; iter; iter = iter->next) {
        /* Needs at least two directories to be duplicate... */
        GQueue *dir_list = iter->data;

#ifdef _RM_TREEMERGE_DEBUG
        for(GList *i = dir_list->head; i; i = i->next) {
            RmDirectory *d = i->data;
            char buf[512];
            memset(buf, 0, sizeof(buf));
            rm_digest_hexstring(d->digest, buf);
            g_printerr("    mergeups=%" LLU ": %s - %s\n", d->mergeups, d->dirname, buf);
        }
        g_printerr("---\n");
#endif
        if(dir_list->length < 2) {
            continue;
        }

        if(rm_session_was_aborted()) {
            break;
        }

        /* List of result directories */
        GQueue result_dirs = G_QUEUE_INIT;

        /* Sort the RmDirectory list by their path depth, lowest depth first */
        g_queue_sort(dir_list, (GCompareDataFunc)rm_tm_sort_paths, self);

        /* Output the directories and mark their children to prevent
         * duplicate directory reports in lower levels.
         */
        for(GList *iter = dir_list->head; iter; iter = iter->next) {
            RmDirectory *directory = iter->data;
            if(directory->finished == false) {
                rm_tm_mark_finished(self, directory);
                g_queue_push_head(&result_dirs, directory);
            }
        }

        /* Make sure the original directory lands as first
         * in the result_dirs queue.
         */
        g_queue_sort(&result_dirs, (GCompareDataFunc)rm_tm_sort_orig_criteria, self);

        GQueue file_adaptor_group = G_QUEUE_INIT;

        for(GList *iter = result_dirs.head; iter; iter = iter->next) {
            RmDirectory *directory = iter->data;
            RmFile *mask = rm_directory_as_new_file(self, directory);
            g_queue_push_tail(self->free_list, mask);
            g_queue_push_tail(&file_adaptor_group, mask);

            if(iter == result_dirs.head) {
                /* First one in the group -> It's the original */
                mask->is_original = true;
                rm_tm_mark_original_files(self, directory);
            } else {
                gint64 prefd = rm_tm_mark_duplicate_files(self, directory);
                if(prefd == directory->dupe_count && cfg->keep_all_tagged) {
                    /* Mark the file as original when all files in it are preferred. */
                    mask->is_original = true;
                }
            }

            if(self->cfg->write_unfinished) {
                rm_tm_write_unfinished_cksums(self, directory);
            }
        }

        if(result_dirs.length >= 2) {
            rm_tm_send(&file_adaptor_group, self, FALSE);
        }

        g_queue_clear(&file_adaptor_group);
        g_queue_clear(&result_dirs);
    }

    g_list_free(result_table_values);

    /* Iterate over all non-finished dirs in the tree,
     * and grab unfinished files that must be dupes elsewhise.
     */
    rm_trie_iter(&self->dir_tree, NULL, true, false, rm_tm_iter_unfinished_files, self);

    /* Now here's a problem. Consider an input like this:
     *  /root
     *  ├── a
     *  ├── sub1
     *  │   ├── a
     *  │   └── b
     *  └── sub2
     *      ├── a
     *      └── b
     *
     *  This yields two duplicate dirs (sub1, sub2)
     *  and one duplicate, unmatched file (a).
     *
     *  For outputting files we need groups, which consist of at least 2 files.
     *  So how to group that, so we don't end up deleting a file many times?
     *  We always choose which directories are originals first, so we flag all
     *  files in it as originals.
     */
    GHashTableIter iter;
    g_hash_table_iter_init(&iter, self->file_groups);

    GQueue *file_list = NULL;
    while(g_hash_table_iter_next(&iter, NULL, (void **)&file_list)) {
        if(self->cfg->partial_hidden) {
            /* with --partial-hidden we do not want to output */
            rm_util_queue_foreach_remove(file_list, (RmRFunc)rm_tm_hidden_file, NULL);
        }

        if(file_list->length >= 2) {
            /* If no separate duplicate files are requested, we can stop here */
            if(self->cfg->find_duplicates == false) {
                self->counters->dup_group_counter -= 1;
                self->counters->dup_counter -= file_list->length - 1;
            } else {
                rm_tm_send(file_list, self, TRUE);
            }
        }
    }
}

static void rm_tm_cluster_up(RmTreeMerger *self, RmDirectory *directory) {
    char *parent_dir = g_path_get_dirname(directory->dirname);
    bool is_root = strcmp(parent_dir, "/") == 0;

    /* Lookup if we already found this parent before (if yes, merge with it) */
    RmDirectory *parent = rm_trie_search(&self->dir_tree, parent_dir);

    if(parent == NULL) {
        /* none yet, basically copy child */
        parent = rm_directory_new(parent_dir);
        parent->node = directory->node ? directory->node->parent : NULL;
        /* Get the actual file count */
        rm_directory_get_filecount(parent);
        rm_trie_insert(&self->dir_tree, parent_dir)->data = parent;

    } else {
        g_free(parent_dir);
    }

    rm_directory_add_subdir(parent, directory);

    if(parent->dupe_count == parent->file_count && parent->file_count > 0) {
        rm_tm_insert_dir(self, parent);
        if(!is_root) {
            rm_tm_cluster_up(self, parent);
        }
    }
}

void rm_tm_finish(RmTreeMerger *self) {
    /* Iterate over all valid directories and try to level them all layers up.
     */
    g_queue_sort(&self->valid_dirs, (GCompareDataFunc)rm_tm_sort_paths_reverse, self);
    for(GList *iter = self->valid_dirs.head; iter; iter = iter->next) {
        RmDirectory *directory = iter->data;
        rm_tm_cluster_up(self, directory);
#ifdef _RM_TREEMERGE_DEBUG
        g_printerr("###\n");
#endif
    }

    if(!rm_session_was_aborted()) {
        /* Recursively call self to march on */
        rm_tm_extract(self);
    }
}
