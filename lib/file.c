/**
* This file is part of rmlint.
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

#include "file.h"
#include "session.h"
#include "utilities.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

RmFile *rm_file_new(const RmCfg *cfg, RmNode *node, size_t size, dev_t dev, ino_t inode,
                    time_t mtime, RmLintType type, bool is_ppath, unsigned path_index,
                    short depth) {
    RmFile *self = g_slice_new0(RmFile);
    self->cfg = cfg;

    self->folder = node;
    self->depth = depth;
    while(node && (node = node->parent)) {
        self->path_depth++;
    }

    self->inode = inode;
    self->dev = dev;
    self->mtime = mtime;

    self->disk_offset = (RmOff)-1;

    self->lint_type = type;
    self->is_prefd = is_ppath;
    self->is_original = false;
    self->is_symlink = false;
    self->path_index = path_index;
    self->file_size = size;
    if(type == RM_LINT_TYPE_DUPE_CANDIDATE) {
        if(cfg->use_absolute_end_offset) {
            self->file_size = CLAMP(size, 1, cfg->skip_end_offset);
        } else {
            self->file_size = size * cfg->skip_end_factor;
        }
        if(cfg->use_absolute_start_offset) {
            self->hash_offset = cfg->skip_start_offset;
        } else {
            self->hash_offset = cfg->skip_start_factor * size;
        }
        if(self->hash_offset >= self->file_size) {
            /* oops tightened the clamp too much! */
            self->lint_type = RM_LINT_TYPE_OVERCLAMPED;
            self->hash_offset = self->file_size;
        }
    }
    return self;
}

void rm_file_build_path(const RmFile *file, char *buf) {
    rm_assert_gentle(file);

    rm_trie_build_path((RmTrie *)&file->cfg->file_trie, file->folder, buf, PATH_MAX);
}

void rm_file_destroy(RmFile *file) {
    if(file->hardlinks) {
        g_queue_remove(&file->hardlinks->files, file);
        file->hardlinks->num_prefd -= file->is_prefd;
        if(file->hardlinks->files.length == 0) {
            g_slice_free(RmFileCluster, file->hardlinks);
        }
    }

    if(file->digest && !file->hardlinks) {
        rm_digest_free(file->digest);
    }

    if(file->ext_cksum) {
        g_free(file->ext_cksum);
    }

    g_slice_free(RmFile, file);
}

static const char *LINT_TYPES[] = {[RM_LINT_TYPE_UNKNOWN] = "",
                                   [RM_LINT_TYPE_EMPTY_DIR] = "emptydir",
                                   [RM_LINT_TYPE_NONSTRIPPED] = "nonstripped",
                                   [RM_LINT_TYPE_BADLINK] = "badlink",
                                   [RM_LINT_TYPE_BADUID] = "baduid",
                                   [RM_LINT_TYPE_BADGID] = "badgid",
                                   [RM_LINT_TYPE_BADUGID] = "badugid",
                                   [RM_LINT_TYPE_EMPTY_FILE] = "emptyfile",
                                   [RM_LINT_TYPE_READ_ERROR] = "read_error",
                                   [RM_LINT_TYPE_DUPE_CANDIDATE] = "duplicate_file",
                                   [RM_LINT_TYPE_DUPE_DIR_CANDIDATE] = "duplicate_dir",
                                   [RM_LINT_TYPE_DUPE_DIR_FILE] = "duplicate_dir_file",
                                   [RM_LINT_TYPE_UNIQUE_FILE] = "unfinished_cksum"};
/* TODO: rename 'unfinished_cksum; to 'unique_file' and update nosetests accordingly */

const char *rm_file_lint_type_to_string(RmLintType type) {
    return LINT_TYPES[MIN(type, sizeof(LINT_TYPES) / sizeof(const char *))];
}

RmLintType rm_file_string_to_lint_type(const char *type) {
    const int N = sizeof(LINT_TYPES) / sizeof(const char *);
    for(int i = 0; i < N; ++i) {
        if(g_strcmp0(type, LINT_TYPES[i]) == 0) {
            return (RmLintType)i;
        }
    }

    return RM_LINT_TYPE_UNKNOWN;
}

gint rm_file_filecount(RmFile *file) {
    if(file->is_cluster) {
        rm_assert_gentle(file->hardlinks);
        return file->hardlinks->files.length;
    } else {
        return 1;
    }
}

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

gint rm_file_basenames_cmp(const RmFile *file_a, const RmFile *file_b) {
    return g_ascii_strcasecmp(file_a->folder->basename, file_b->folder->basename);
}

/* Sort criteria for sorting during preprocessing;
 * Return:
 *      a negative integer file 'a' outranks 'b',
 *      0 if they are equal,
 *      a positive integer if file 'b' outranks 'a'
 */
int rm_file_cmp_orig_criteria(const RmFile *a, const RmFile *b, const RmCfg *cfg) {
    if(a->lint_type != b->lint_type) {
        /* "other" lint outranks duplicates and has lower ENUM */
        return a->lint_type - b->lint_type;
    } else if(a->is_symlink != b->is_symlink) {
        /* Make sure to *never* make a symlink to be the original */
        return a->is_symlink - b->is_symlink;
    } else if(a->is_prefd != b->is_prefd) {
        return (b->is_prefd - a->is_prefd);
    } else {
        for(int i = 0, regex_cursor = 0; cfg->sort_criteria[i]; i++) {
            long cmp = 0;
            switch(tolower((unsigned char)cfg->sort_criteria[i])) {
            case 'm':
                cmp = (long)(a->mtime) - (long)(b->mtime);
                break;
            case 'f': {
                RM_DEFINE_PATH(a);
                RM_DEFINE_PATH(b);
                cmp = g_ascii_strcasecmp(a_path, b_path);
            } break;
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
                    g_ptr_array_index(cfg->pattern_cache, regex_cursor), regex_cursor,
                    (RmPatternBitmask *)&a->pattern_bitmask_basename, a->folder->basename,
                    (RmPatternBitmask *)&b->pattern_bitmask_basename,
                    b->folder->basename);
                regex_cursor++;
                break;
            }
            case 'r': {
                RM_DEFINE_PATH(a);
                RM_DEFINE_PATH(b);
                cmp = rm_pp_cmp_by_regex(
                    g_ptr_array_index(cfg->pattern_cache, regex_cursor), regex_cursor,
                    (RmPatternBitmask *)&a->pattern_bitmask_path, a_path,
                    (RmPatternBitmask *)&b->pattern_bitmask_path, b_path);
                regex_cursor++;
            } break;
            }
            if(cmp) {
                if(isupper((unsigned char)cfg->sort_criteria[i])) {
                    /* reverse order if uppercase option */
                    cmp = -cmp;
                }
                return cmp;
            }
        }
        return 0;
    }
}

gint rm_file_cmp_dupe_group(const RmFile *file_a, const RmFile *file_b,
                            const RmCfg *cfg) {
    gint result = SIGN_DIFF(file_a->file_size, file_b->file_size);

    if(result != 0) {
        return result;
    }

    if(cfg->match_basename && (result = rm_file_basenames_cmp(file_a, file_b)) != 0) {
        return result;
    }

    if(cfg->match_with_extension &&
       (result = rm_file_cmp_with_extension(file_a, file_b)) != 0) {
        return result;
    }

    if(cfg->match_without_extension) {
        result = rm_file_cmp_without_extension(file_a, file_b);
    }
    return result;
}

gint rm_file_node_cmp(const RmFile *file_a, const RmFile *file_b) {
    gint result = SIGN_DIFF(file_a->dev, file_b->dev);
    if(result == 0) {
        return SIGN_DIFF(file_a->inode, file_b->inode);
    }
    return result;
}

gint rm_file_cmp_reverse_alphabetical(const RmFile *a, const RmFile *b) {
    RM_DEFINE_PATH(a);
    RM_DEFINE_PATH(b);
    return g_strcmp0(b_path, a_path);
}

static ino_t rm_file_parent_inode(const RmFile *file) {
    char parent_path[PATH_MAX];
    rm_trie_build_path((RmTrie *)&file->cfg->file_trie, file->folder->parent, parent_path,
                       PATH_MAX);
    RmStat stat_buf;
    int retval = rm_sys_stat(parent_path, &stat_buf);
    rm_assert_gentle(retval != -1);
    return stat_buf.st_ino;
}

gint rm_file_cmp_pathdouble(const RmFile *a, const RmFile *b) {
    rm_assert_gentle(a->dev == b->dev);
    rm_assert_gentle(a->inode == b->inode);

    /* a couple of cheap tests before we resort to parent inode checks */
    if(a->folder == b->folder) {
        /* identical paths (or pathtricia is broken) */
        return 0;
    }
    gint result = g_strcmp0(a->folder->basename, b->folder->basename);
    if(result != 0) {
        /* files with differing basenames are not path doubles */
        return result;
    }
    RmNode *pa = a->folder->parent;
    RmNode *pb = b->folder->parent;
    if(pa == pb) {
        /* files have same basename and identical parent folders */
        return 0;
    }

    /* final test is to compare parent folder dev & inodes; this will detect
     * for example the same file in two different mountpoints.  To get parent
     * inodes we first build the parent paths and then stat them.
     */
    return SIGN_DIFF(rm_file_parent_inode(a), rm_file_parent_inode(b));
}

RmDirInfo *rm_dir_info_new(RmTraversalType traversal) {
    RmDirInfo *self = g_slice_new0(RmDirInfo);
    self->hidden = TRUE;
    self->via_symlink = TRUE;
    self->traversal = traversal;
    return self;
}

void rm_dir_info_free(RmDirInfo *dirinfo) {
    if(dirinfo == NULL) {
        return;
    }
    g_slice_free(RmDirInfo, dirinfo);
}
