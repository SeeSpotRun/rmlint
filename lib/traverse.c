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
 *
 */

#include <glib.h>
#include <string.h>

#include "pathtricia.h"
#include "traverse.h"
#include "walk.h"
#include "xattr.h"

//////////////////////
// TRAVERSE SESSION //
//////////////////////

typedef struct RmTravSession {
    RmCfg *cfg;
    RmUserList *userlist;
    gboolean symlink_message_delivered;
    RmFmtTable *formats;
    RmCounters *counters;
    RmFileTables *tables;
} RmTravSession;

/** Process RmFiles from traversal.
 * Updates session counters;
 * Builds directory file counts;
 * Inserts file into traverser->tables->all_files if appropriate
 */
static void rm_traverse_process_file(RmFile *file, RmTravSession *traverser) {
    rm_assert_gentle(file);

    RmLintType lint_type = file->lint_type;
    if(lint_type == RM_LINT_TYPE_DIR) {
        /* create pathtricia data entry for dir */
        RmNode *node = file->folder;
        rm_assert_gentle(node);
        if(!node->data) {
            node->data = rm_dir_info_new(RM_TRAVERSAL_FULL);
        }
        RmDirInfo *dirinfo = node->data;
        if(dirinfo->traversal == RM_TRAVERSAL_NONE) {
            dirinfo->traversal = RM_TRAVERSAL_FULL;
        }
        dirinfo->hidden &= file->is_hidden;
        dirinfo->via_symlink &= file->via_symlink;
        rm_assert_gentle(!dirinfo->dir_as_file);
        dirinfo->dir_as_file = file;
        return;
    }

    /* add file towards parent dir's file count */
    RmNode *parent = file->folder->parent;
    rm_assert_gentle(parent);
    if(!parent->data) {
        parent->data = rm_dir_info_new(RM_TRAVERSAL_NONE);
    }
    RmDirInfo *parent_info = parent->data;
    if(RM_IS_COUNTED_FILE_TYPE(lint_type)) {
        parent_info->file_count++;
    }
    if(RM_IS_UNTRAVERSED_TYPE(lint_type)) {
        parent_info->traversal = RM_TRAVERSAL_PART;
    }

    RmCfg *cfg = traverser->cfg;
    if(lint_type == RM_LINT_TYPE_HIDDEN_DIR) {
        /* ignored hidden dir */
        traverser->counters->ignored_folders++;
    } else if(!RM_IS_REPORTING_TYPE(lint_type)) {
        /* info only; ignore */
        traverser->counters->ignored_files++;
    } else if(lint_type == RM_LINT_TYPE_EMPTY_FILE && !cfg->find_emptyfiles) {
        /* ignoring empty files */
        traverser->counters->ignored_files++;
    } else {
        if(cfg->clear_xattr_fields && lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
            rm_xattr_clear_hash(cfg, file);
        }
        if(file->is_hidden && traverser->cfg->partial_hidden &&
           RM_IS_OTHER_LINT_TYPE(file->lint_type)) {
            /* don't report hidden 'other' lint, it's only collected for
             * directory matching */
            if(file->file_size > file->hash_offset) {
                file->lint_type = RM_LINT_TYPE_DUPE_CANDIDATE;
            } else {
                traverser->counters->ignored_files++;
                rm_file_destroy(file);
                return;
            }
        }
        traverser->counters->total_files++;
        traverser->tables->all_files =
            g_slist_prepend(traverser->tables->all_files, file);
        traverser->counters->shred_bytes_remaining += file->file_size - file->hash_offset;
        rm_fmt_set_state(traverser->formats, RM_PROGRESS_STATE_TRAVERSE);
        return;
    }
    rm_file_destroy(file);
}

/* try to insert node by efficient rm_node_insert_unlocked() rather than
 * top-down rm_trie_insert()
 * a pointer to the result is stored in walkfile->user_data. */
static RmNode *rm_traverse_get_node(RmWalkFile *walkfile, RmTravSession *traverser) {
    RmNode **node = (RmNode **)&walkfile->user_data;
    if(!*node) {
        /* try to insert under parent node */
        if(walkfile->parent) {
            /* insert under parent node (recursive) */
            RmNode *parent_node = rm_traverse_get_node(walkfile->parent, traverser);
            if(parent_node) {
                *node = rm_node_insert_unlocked(&traverser->cfg->file_trie, parent_node,
                                                walkfile->bname);
            }
        } else {
            /* build node from full path */
            *node = rm_trie_insert_unlocked(&traverser->cfg->file_trie, walkfile->path);
        }
    }
    return *node;
}

/**
 * @brief converts walkfile to RmFile
 */
static RmFile *rm_traverse_convert(RmWalkFile *walkfile, RmTravSession *traverser,
                                   RmLintType lint_type, int mtime, gboolean is_prefd) {
    RmNode *node = rm_traverse_get_node(walkfile, traverser);
    rm_assert_gentle(node);

    RmFile *file = rm_file_new(traverser->cfg, node, walkfile->statp->st_size,
                               walkfile->statp->st_dev, walkfile->statp->st_ino, mtime,
                               lint_type, is_prefd, walkfile->index, walkfile->depth);
    rm_assert_gentle(file);
    file->is_hidden = walkfile->is_hidden;
    file->via_symlink = walkfile->via_symlink;
    file->is_symlink = walkfile->is_symlink;

    return file;
}

/**
 * threadpool pipe to receive results from walker */
static void rm_traverse_process(RmWalkFile *walkfile, RmTravSession *traverser) {
    const RmCfg *cfg = traverser->cfg;
    RmLintType lint_type = 0;

    /* do some screening */
    switch(walkfile->type) {
    case RM_WALK_REG:
    case RM_WALK_SL:
    case RM_WALK_OTHER:
    case RM_WALK_DIR:
    case RM_WALK_BADLINK:
        if(rm_fmt_is_a_output(traverser->formats, walkfile->path)) {
            lint_type = RM_LINT_TYPE_OUTPUT;
        } else if(cfg->permissions && access(walkfile->path, cfg->permissions) == -1) {
            lint_type = RM_LINT_TYPE_BADPERM;
        } else if(cfg->find_badids) {
            lint_type = rm_util_uid_gid_check(walkfile->statp, traverser->userlist);
        }
    default:
        break;
    }

    if(!lint_type) {
        switch(walkfile->type) {
        case RM_WALK_REG:
            lint_type = RM_LINT_TYPE_DUPE_CANDIDATE;
            break;
        case RM_WALK_DIR:
            lint_type = RM_LINT_TYPE_DIR;
            break;
        case RM_WALK_SL:
            if(!cfg->see_symlinks) {
                /* not following link but need to account for it for
                 * empty dir and dupe dir detection */
                lint_type = RM_LINT_TYPE_GOODLINK;
            } else {
                lint_type = RM_LINT_TYPE_DUPE_CANDIDATE;
            }
            break;
        case RM_WALK_DOT:
            rm_assert_gentle_not_reached();
            break;
        case RM_WALK_OTHER:
            lint_type = RM_LINT_TYPE_UNHANDLED;
            break;
        case RM_WALK_BADLINK:
            lint_type = RM_LINT_TYPE_BADLINK;
            break;
        case RM_WALK_HIDDEN_FILE:
            lint_type = RM_LINT_TYPE_HIDDEN_FILE;
            break;
        case RM_WALK_HIDDEN_DIR:
            lint_type = RM_LINT_TYPE_HIDDEN_DIR;
            break;
        case RM_WALK_WHITEOUT:
            lint_type = RM_LINT_TYPE_WHITEOUT;
            break;
        case RM_WALK_SKIPPED_ROOT:
            /* do nothing; dir was traversed elsewhere */
            /* TODO: maybe debug report? */
            break;
        case RM_WALK_MAX_DEPTH:
            lint_type = RM_LINT_TYPE_MAX_DEPTH;
            break;
        case RM_WALK_XDEV:
            lint_type = RM_LINT_TYPE_XDEV;
            break;
        case RM_WALK_EVILFS:
            lint_type = RM_LINT_TYPE_EVIL_DIR;
            break;
        case RM_WALK_DC:
            /* do nothing; we've been there before */
            /* TODO: maybe debug report ?*/
            break;
        case RM_WALK_PATHMAX:
            /* TODO: maybe debug report */
            rm_log_error_line("Maximum path length reached: %s/%s",
                              walkfile->parent->path, walkfile->bname);
            lint_type = RM_LINT_TYPE_TRAVERSE_ERROR;
            break;
        case RM_WALK_DNR:
            rm_log_error_line("Can't read dir %s (%s)", walkfile->path,
                              g_strerror(walkfile->err));
            lint_type = RM_LINT_TYPE_TRAVERSE_ERROR;
            break;
        case RM_WALK_NS:
            rm_log_error_line("Can't stat %s (%s)", walkfile->path,
                              g_strerror(walkfile->err));
            lint_type = RM_LINT_TYPE_TRAVERSE_ERROR;
            break;
        default:
            rm_assert_gentle_not_reached();
        }
    }

    if(lint_type) {
        int mtime = rm_sys_stat_mtime_seconds(walkfile->statp);
        gboolean is_prefd = (walkfile->index >= cfg->first_prefd);

        if(lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
            if(walkfile->statp->st_size == 0 && cfg->find_emptyfiles) {
                lint_type = RM_LINT_TYPE_EMPTY_FILE;
            } else if(cfg->find_nonstripped &&
                      rm_util_is_nonstripped(walkfile->path, walkfile->statp)) {
                lint_type = RM_LINT_TYPE_NONSTRIPPED;
            }
        }

        if(RM_IS_OTHER_LINT_TYPE(lint_type)) {
            /* check for 'other lint' in tagged (prefd) folders */
            if(cfg->keep_all_tagged && is_prefd) {
                lint_type = RM_LINT_TYPE_DUPE_CANDIDATE;
            } else {
                /* time filtering criteria that don't apply to dupe candidates
                 * since they might be valid "originals" */
                if(cfg->filter_mtime && mtime < cfg->min_mtime) {
                    lint_type = RM_LINT_TYPE_WRONG_TIME;
                }
            }
        }
        if(lint_type == RM_LINT_TYPE_DUPE_CANDIDATE) {
            /* size checks */
            RmOff file_size = walkfile->statp->st_size;
            if(file_size > cfg->maxsize || file_size < cfg->minsize) {
                lint_type = RM_LINT_TYPE_WRONG_SIZE;
            }
        }
        RmFile *file =
            rm_traverse_convert(walkfile, traverser, lint_type, mtime, is_prefd);
        rm_traverse_process_file(file, traverser);
    }

    rm_walk_file_free(walkfile);
}

////////////////
// PUBLIC API //
////////////////

void rm_traverse_tree(RmCfg *cfg, RmMDS *mds, RmFileTables *tables, RmFmtTable *formats,
                      RmMountTable *mounts, RmCounters *counters) {
    rm_assert_gentle(cfg);
    rm_assert_gentle(mds);
    RmTravSession traverser;
    traverser.cfg = cfg;
    traverser.userlist = rm_userlist_new();
    traverser.symlink_message_delivered = FALSE;
    traverser.formats = formats;
    traverser.counters = counters;
    traverser.tables = tables;

    GThreadPool *walk_pipe =
        rm_util_thread_pool_new((GFunc)rm_traverse_process, &traverser, 1, TRUE);
    RmWalkSession *walker = rm_walk_session_new(mds, walk_pipe, mounts);
    walker->do_links = cfg->follow_symlinks;
    walker->see_links = cfg->see_symlinks;
    walker->send_hidden = !cfg->ignore_hidden || cfg->partial_hidden;
    walker->walk_hidden = !cfg->ignore_hidden;
    walker->send_dirs = TRUE;  // TODO: maybe not always?
    walker->one_device = !cfg->crossdev;
    walker->send_errors = TRUE;
    walker->send_warnings = TRUE;  // TODO: maybe not always
    walker->send_badlinks = cfg->find_badlinks;

    walker->max_depth = cfg->depth;

    rm_walk_paths(cfg->paths, walker, cfg->threads_per_hdd, cfg->threads_per_ssd, 2);
    g_thread_pool_free(walk_pipe, FALSE, TRUE);

    rm_userlist_destroy(traverser.userlist);
}
