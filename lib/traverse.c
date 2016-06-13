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

//////////////////////
// TRAVERSE SESSION //
//////////////////////

typedef struct RmTravSession {
    RmCfg *cfg;
    RmUserList *userlist;
    GThreadPool *result_pipe; /* for sending to session.c */
    gboolean symlink_message_delivered;
    RmFmtTable *formats;
} RmTravSession;

//////////////////////
// ACTUAL WORK HERE //
//////////////////////


static void rm_traverse_send(RmWalkFile *walkfile, RmTravSession *traverser,
                             RmLintType lint_type, gboolean check_output,
                             gboolean check_perms) {
    RmCfg *cfg = traverser->cfg;
    rm_assert_gentle(walkfile->path);

    /*TODO: this is double-up of rm_traverse_reg() */
    if(check_output && rm_fmt_is_a_output(traverser->formats, walkfile->path)) {
        lint_type = RM_LINT_TYPE_OUTPUT;
    } else if(check_perms) {
        RmLintType gid_check;
        if(cfg->permissions && access(walkfile->path, cfg->permissions) == -1) {
            /* bad permissions; ignore file */
            lint_type = RM_LINT_TYPE_BADPERM;
        } else if(cfg->find_badids && (gid_check = rm_util_uid_gid_check(
                                           walkfile->statp, traverser->userlist))) {
            lint_type = gid_check;
        }
    }

    gboolean is_prefd = (walkfile->index >= cfg->first_prefd);

    if(lint_type <= RM_LINT_TYPE_LAST_OTHER && cfg->keep_all_tagged && is_prefd) {
        /* we can't delete 'other lint' in tagged folders */
        lint_type = RM_LINT_TYPE_DUPE_CANDIDATE;
    }

    int mtime = rm_sys_stat_mtime_seconds(walkfile->statp);
    if(lint_type != RM_LINT_TYPE_DUPE_CANDIDATE && lint_type != RM_LINT_TYPE_DIR) {
        /* some filtering criteria that don't apply to dupe candidates
         * since they might be valid "originals" */
        if(cfg->filter_mtime && mtime < cfg->min_mtime) {
            lint_type = RM_LINT_TYPE_WRONG_TIME;
        }
    }

    RmFile *file = rm_file_new(traverser->cfg, walkfile->path, walkfile->statp->st_size,
                           walkfile->statp->st_dev, walkfile->statp->st_ino, mtime,
                           lint_type, is_prefd, walkfile->index, walkfile->depth);
    rm_assert_gentle(file);
    file->is_hidden = walkfile->is_hidden;
    file->via_symlink = walkfile->via_symlink;
    file->is_symlink = walkfile->is_symlink;
    rm_util_thread_pool_push(traverser->result_pipe, file);
}

static void rm_traverse_reg(RmWalkFile *walkfile, RmTravSession *traverser) {
    if(rm_fmt_is_a_output(traverser->formats, walkfile->path)) {
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_OUTPUT, FALSE, FALSE);
        return;
    }

    RmCfg *cfg = traverser->cfg;
    RmLintType gid_check;
    if(cfg->permissions && access(walkfile->path, cfg->permissions) == -1) {
        /* bad permissions; ignore file */
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_BADPERM, FALSE, FALSE);
        return;
    } else if(cfg->find_badids &&
              (gid_check = rm_util_uid_gid_check(walkfile->statp, traverser->userlist))) {
        rm_traverse_send(walkfile, traverser, gid_check, FALSE, FALSE);
        return;
    }

    if(cfg->find_nonstripped && rm_util_is_nonstripped(walkfile->path, walkfile->statp)) {
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_NONSTRIPPED, FALSE, FALSE);
        return;
    }

    RmOff file_size = walkfile->statp->st_size;
    if(file_size == 0 && (!cfg->limits_specified || cfg->minsize > 0)) {
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_EMPTY_FILE, FALSE, FALSE);
        return;
    } else if(cfg->limits_specified &&
              (file_size > cfg->maxsize ||
               (cfg->minsize != (RmOff)-1 && file_size < cfg->minsize))) {
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_WRONG_SIZE, FALSE, FALSE);
        return;
    }
    rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_DUPE_CANDIDATE, FALSE, FALSE);
}

/**
 * threadpool pipe to receive results from walker */
static void rm_traverse_process(RmWalkFile *walkfile, RmTravSession *traverser) {
    const RmCfg *cfg = traverser->cfg;

    switch(walkfile->type) {
    /* TODO: split into two switch's with uid/gid check in between */
    case RM_WALK_REG:
        rm_traverse_reg(walkfile, traverser);
        break;
    case RM_WALK_DIR:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_DIR, FALSE, TRUE);
        break;
    case RM_WALK_SL:
        if(!cfg->see_symlinks) {
            /* not following link but need to account for it for
             * empty dir and dupe dir detection */
            rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_GOODLINK, TRUE, TRUE);
        }
        break;
    case RM_WALK_DOT:
        rm_assert_gentle_not_reached();
        break;
    case RM_WALK_OTHER:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_UNHANDLED, FALSE, TRUE);
        break;
    case RM_WALK_BADLINK:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_BADLINK, FALSE, TRUE);
        break;
    case RM_WALK_HIDDEN_FILE:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_HIDDEN_FILE, FALSE, FALSE);
        break;
    case RM_WALK_HIDDEN_DIR:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_HIDDEN_DIR, FALSE, FALSE);
        break;
    case RM_WALK_WHITEOUT:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_WHITEOUT, FALSE, FALSE);
        break;
    case RM_WALK_SKIPPED_ROOT:
        /* TODO: maybe debug report */
        break;
    case RM_WALK_MAX_DEPTH:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_MAX_DEPTH, FALSE, FALSE);
        break;
    case RM_WALK_XDEV:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_XDEV, FALSE, FALSE);
        break;
    case RM_WALK_EVILFS:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_EVIL_DIR, FALSE, TRUE);
        break;
    case RM_WALK_DC:
        /* TODO: maybe debug report */
        break;
    case RM_WALK_PATHMAX:
        /* TODO: maybe debug report */
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_TRAVERSE_ERROR, FALSE, FALSE);
        break;
    case RM_WALK_DNR:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_TRAVERSE_ERROR, FALSE, FALSE);
        break;
    case RM_WALK_NS:
        rm_traverse_send(walkfile, traverser, RM_LINT_TYPE_TRAVERSE_ERROR, FALSE, FALSE);
        break;
    default:
        rm_assert_gentle_not_reached();
    }
    rm_walk_file_free(walkfile);
}

////////////////
// PUBLIC API //
////////////////

void rm_traverse_tree(RmCfg *cfg, GThreadPool *result_pipe, RmMDS *mds,
                      RmFmtTable *formats, RmMountTable *mounts) {
    rm_assert_gentle(cfg);
    rm_assert_gentle(mds);
    RmTravSession traverser;
    traverser.cfg = cfg;
    traverser.result_pipe = result_pipe;
    traverser.userlist = rm_userlist_new();
    traverser.symlink_message_delivered = FALSE;
    traverser.formats = formats;

    GThreadPool *walk_pipe =
        rm_util_thread_pool_new((GFunc)rm_traverse_process, &traverser, 1, TRUE);
    RmWalkSession *walker = rm_walk_session_new(mds, walk_pipe, &cfg->file_trie, mounts);
    walker->do_links = cfg->follow_symlinks || cfg->see_symlinks;
    walker->see_links = cfg->see_symlinks;
    walker->send_hidden = !cfg->ignore_hidden || cfg->partial_hidden;
    walker->walk_hidden = !cfg->ignore_hidden;
    walker->send_dirs = TRUE;  // TODO: maybe not always?
    walker->one_device = !cfg->crossdev;
    walker->send_errors = TRUE;
    walker->send_warnings = TRUE;  // TODO: maybe not always
    walker->send_badlinks = cfg->find_badlinks;

    walker->max_depth = cfg->depth;

    rm_walk_paths(cfg->paths, walker, cfg->threads_per_hdd, cfg->threads_per_ssd, 10);
    g_thread_pool_free(walk_pipe, FALSE, TRUE);

    rm_userlist_destroy(traverser.userlist);
}
