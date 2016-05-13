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

#include <string.h>
#include <glib.h>

#include "traverse.h"
#include "fts/fts.h"

//////////////////////
// TRAVERSE SESSION //
//////////////////////

typedef struct RmTravSession {
    const RmCfg *cfg;
    RmUserList *userlist;
    GThreadPool *file_pool;
    GHashTable *roots;
} RmTravSession;

///////////////////////////////////////////
// BUFFER FOR STARTING TRAVERSAL THREADS //
///////////////////////////////////////////

typedef struct RmTravBuffer {
    RmStat stat_buf;   /* rm_sys_stat(2) information about the directory */
    char *path;        /* The path of the directory, as passed on command line. */
    bool is_prefd;     /* Was this file in a preferred path? */
    RmOff path_index;  /* Index of path, as passed on the commadline */
    RmMDSDevice *disk; /* md-scheduler device the buffer was pushed to */
} RmTravBuffer;

static RmTravBuffer *rm_trav_buffer_new(const RmCfg *cfg, char *path, bool is_prefd,
                                        unsigned long path_index) {
    RmTravBuffer *self = g_new0(RmTravBuffer, 1);
    self->path = path;
    self->is_prefd = is_prefd;
    self->path_index = path_index;

    int stat_state;
    if(cfg->follow_symlinks) {
        stat_state = rm_sys_stat(path, &self->stat_buf);
    } else {
        stat_state = rm_sys_lstat(path, &self->stat_buf);
    }

    if(stat_state == -1) {
        rm_log_perror("Unable to stat file");
    }
    return self;
}

static void rm_trav_buffer_free(RmTravBuffer *self) {
    g_free(self);
}

//////////////////////
// ACTUAL WORK HERE //
//////////////////////

void rm_traverse_file_destroy(RmTraverseFile *file) {
    g_free(file->path);
    g_slice_free(RmTraverseFile, file);
}

static void rm_traverse_file(RmTravSession *traverser, RmStat *statp, char *path,
                             bool is_prefd, unsigned long path_index,
                             RmLintType file_type, bool is_symlink, bool is_hidden,
                             short depth) {
    const RmCfg *cfg = traverser->cfg;

    /* Try to autodetect the type of the lint */
    if(file_type == RM_LINT_TYPE_UNKNOWN) {
        RmLintType gid_check;
        /* see if we can find a lint type */
        if(statp->st_size == 0) {
            file_type = RM_LINT_TYPE_EMPTY_FILE;
        } else if(cfg->permissions && access(path, cfg->permissions) == -1) {
            /* bad permissions; ignore file */
            file_type = RM_LINT_TYPE_BADPERM;
        } else if(cfg->find_badids &&
                  (gid_check = rm_util_uid_gid_check(statp, traverser->userlist))) {
            file_type = gid_check;
        } else if(cfg->find_nonstripped && rm_util_is_nonstripped(path, statp)) {
            file_type = RM_LINT_TYPE_NONSTRIPPED;
        } else {
            RmOff file_size = statp->st_size;
            if(cfg->limits_specified &&
               (file_size > cfg->maxsize ||
                (cfg->minsize != (RmOff)-1 && file_size < cfg->minsize))) {
                file_type = RM_LINT_TYPE_WRONG_SIZE;
            } else {
                file_type = RM_LINT_TYPE_DUPE_CANDIDATE;
            }
        }
    }

    if(file_type != RM_LINT_TYPE_DUPE_CANDIDATE) {
        /* some filtering criteria that don't apply to dupe candidates
         * since they might be valid "originals" */
        if(cfg->filter_mtime && rm_sys_stat_mtime_seconds(statp) < cfg->min_mtime) {
            file_type = RM_LINT_TYPE_WRONG_TIME;
        } else if(cfg->keep_all_tagged && is_prefd) {
            file_type = RM_LINT_TYPE_KEEP_TAGGED;
        }
    }

    RmTraverseFile *file = g_slice_new(RmTraverseFile);
    file->path = g_strdup(path);
    file->size = statp->st_size;
    file->inode = statp->st_ino;
    file->dev = statp->st_dev;
    file->mtime = rm_sys_stat_mtime_seconds(statp);
    file->lint_type = file_type;
    file->is_prefd = is_prefd;
    file->path_index = path_index;
    file->depth = depth;
    file->is_symlink = is_symlink;
    file->is_hidden = is_hidden;

    rm_util_thread_pool_push(traverser->file_pool, file);
}

static bool rm_traverse_is_hidden(const RmCfg *cfg, const char *basename, char *hierarchy,
                                  size_t hierarchy_len) {
    if(cfg->partial_hidden == false) {
        return false;
    } else if(*basename == '.') {
        return true;
    } else {
        return !!memchr(hierarchy, 1, hierarchy_len);
    }
}

/* Macro for rm_traverse_directory() for easy file adding */
#define _ADD_FILE(lint_type, is_symlink, stat_buf)                                   \
    rm_traverse_file(                                                                \
        traverser, (RmStat *)stat_buf, p->fts_path, is_prefd, path_index, lint_type, \
        is_symlink,                                                                  \
        rm_traverse_is_hidden(cfg, p->fts_name, is_hidden, p->fts_level + 1),        \
        p->fts_level);

#if RM_PLATFORM_32 && HAVE_STAT64

static void rm_traverse_convert_small_stat_buf(struct stat *fts_statp, RmStat *buf) {
    /* Break a leg for supporting large files on 32 bit,
     * and convert the needed fields to the large version.
     *
     * We can't use memcpy here, since the layout might be (fatally) different.
     * Yes, this is stupid. *Sigh*
     * */
    memset(buf, 0, sizeof(RmStat));
    buf->st_dev = fts_statp->st_dev;
    buf->st_ino = fts_statp->st_ino;
    buf->st_mode = fts_statp->st_mode;
    buf->st_nlink = fts_statp->st_nlink;
    buf->st_uid = fts_statp->st_uid;
    buf->st_gid = fts_statp->st_gid;
    buf->st_rdev = fts_statp->st_rdev;
    buf->st_size = fts_statp->st_size;
    buf->st_blksize = fts_statp->st_blksize;
    buf->st_blocks = fts_statp->st_blocks;
    buf->st_atim = fts_statp->st_atim;
    buf->st_mtim = fts_statp->st_mtim;
    buf->st_ctim = fts_statp->st_ctim;
}

#define ADD_FILE(lint_type, is_symlink)                         \
    {                                                           \
        RmStat buf;                                             \
        rm_traverse_convert_small_stat_buf(p->fts_statp, &buf); \
        _ADD_FILE(lint_type, is_symlink, &buf)                  \
    }

#else

#define ADD_FILE(lint_type, is_symlink) \
    _ADD_FILE(lint_type, is_symlink, (RmStat *)p->fts_statp)

#endif

static void rm_traverse_directory(RmTravBuffer *buffer, RmTravSession *traverser) {
    const RmCfg *cfg = traverser->cfg;

    char is_prefd = buffer->is_prefd;
    RmOff path_index = buffer->path_index;

    /* Initialize ftsp */
    int fts_flags = FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR;

    FTS *ftsp = fts_open((char * [2]){buffer->path, NULL}, fts_flags, NULL);

    if(ftsp == NULL) {
        rm_log_error_line("fts_open() == NULL");
        goto done;
    }

    FTSENT *p, *chp;
    chp = fts_children(ftsp, 0);
    if(chp == NULL) {
        rm_log_warning_line("fts_children() == NULL");
        goto done;
    }

    /* start main processing */
    char is_emptydir[PATH_MAX / 2 + 1];
    char is_hidden[PATH_MAX / 2 + 1];
    bool have_open_emptydirs = false;
    bool clear_emptydir_flags = false;
    bool next_is_symlink = false;
    bool symlink_message_delivered = false;

    memset(is_emptydir, 0, sizeof(is_emptydir) - 1);
    memset(is_hidden, 0, sizeof(is_hidden) - 1);

    while(!rm_session_was_aborted() && (p = fts_read(ftsp)) != NULL) {
        /* check for hidden file or folder */
        if(cfg->ignore_hidden && p->fts_level > 0 && p->fts_name[0] == '.') {
            /* ignoring hidden folders*/

            if(p->fts_info == FTS_D) {
                fts_set(ftsp, p, FTS_SKIP); /* do not recurse */
                ADD_FILE(RM_LINT_TYPE_HIDDEN_DIR, false);
            } else {
                ADD_FILE(RM_LINT_TYPE_HIDDEN_FILE, false);
            }

            clear_emptydir_flags = true; /* flag current dir as not empty */
            is_emptydir[p->fts_level] = 0;
        } else {
            switch(p->fts_info) {
            case FTS_D: /* preorder directory */
                if(p->fts_level >= cfg->depth) {
                    /* continuing into folder would exceed maxdepth*/
                    rm_log_debug_line("Not descending into %s because max depth reached",
                                      p->fts_path);
                } else if(p->fts_level > 0 && !(cfg->crossdev) &&
                          p->fts_dev != chp->fts_dev) {
                    /* continuing into folder would cross file systems*/
                    rm_log_info(
                        "Not descending into %s because it is a different filesystem\n",
                        p->fts_path);
                } else if(p->fts_level > 0 &&
                          g_hash_table_contains(traverser->roots, p->fts_path)) {
                    rm_log_info("Not descending into %s because it is a root path\n",
                                p->fts_path);
                } else {
                    /* recurse dir; assume empty until proven otherwise */
                    is_emptydir[p->fts_level + 1] = 1;
                    is_hidden[p->fts_level + 1] =
                        is_hidden[p->fts_level] | (p->fts_name[0] == '.');
                    have_open_emptydirs = true;
                    break;
                }
                fts_set(ftsp, p, FTS_SKIP);  /* do not recurse */
                clear_emptydir_flags = true; /* flag current dir as not empty */
                break;
            case FTS_DC: /* directory that causes cycles */
                rm_log_warning_line(_("filesystem loop detected at %s (skipping)"),
                                    p->fts_path);
                clear_emptydir_flags = true; /* current dir not empty */
                break;
            case FTS_DNR: /* unreadable directory */
                rm_log_warning_line(_("cannot read directory %s: %s"), p->fts_path,
                                    g_strerror(p->fts_errno));
                clear_emptydir_flags = true; /* current dir not empty */
                break;
            case FTS_DOT: /* dot or dot-dot */
                break;
            case FTS_DP: /* postorder directory */
                if(is_emptydir[p->fts_level + 1] && cfg->find_emptydirs) {
                    ADD_FILE(RM_LINT_TYPE_EMPTY_DIR, false);
                }
                is_hidden[p->fts_level + 1] = 0;
                break;
            case FTS_ERR: /* error; errno is set */
                rm_log_warning_line(_("error %d in fts_read for %s (skipping)"), errno,
                                    p->fts_path);
                clear_emptydir_flags = true; /*current dir not empty*/
                break;
            case FTS_INIT: /* initialized only */
                break;
            case FTS_SLNONE: /* symbolic link without target */
                if(cfg->find_badlinks) {
                    ADD_FILE(RM_LINT_TYPE_BADLINK, false);
                }
                clear_emptydir_flags = true; /*current dir not empty*/
                break;
            case FTS_W:                      /* whiteout object */
                clear_emptydir_flags = true; /*current dir not empty*/
                break;
            case FTS_NS: {                   /* rm_sys_stat(2) failed */
                clear_emptydir_flags = true; /*current dir not empty*/
                RmStat stat_buf;

                /* See if your stat can do better. */
                if(rm_sys_stat(p->fts_path, &stat_buf) != -1) {
                    /* normal stat failed but 64-bit stat worked
                     * -> must be a big file on 32 bit.
                     */
                    rm_traverse_file(traverser, &stat_buf, p->fts_path, is_prefd,
                                     path_index, RM_LINT_TYPE_UNKNOWN, false,
                                     rm_traverse_is_hidden(cfg, p->fts_name, is_hidden,
                                                           p->fts_level + 1),
                                     p->fts_level);
                    rm_log_warning_line(_("Added big file %s"), p->fts_path);
                } else {
                    rm_log_warning(_("cannot stat file %s (skipping)"), p->fts_path);
                }
            } break;
            case FTS_SL:                     /* symbolic link */
                clear_emptydir_flags = true; /* current dir not empty */
                if(!cfg->follow_symlinks) {
                    if(p->fts_level != 0 && !symlink_message_delivered) {
                        rm_log_debug_line(
                            "Not following symlink %s because of cfg\n"
                            "\t(further symlink messages suppressed for this cmdline "
                            "path)",
                            p->fts_path);
                        symlink_message_delivered = TRUE;
                    }

                    if(access(p->fts_path, R_OK) == -1 && errno == ENOENT) {
                        /* Oops, that's a badlink. */
                        if(cfg->find_badlinks) {
                            ADD_FILE(RM_LINT_TYPE_BADLINK, false);
                        }
                    } else if(cfg->see_symlinks) {
                        ADD_FILE(RM_LINT_TYPE_UNKNOWN, true);
                    }
                } else {
                    if(!symlink_message_delivered) {
                        rm_log_debug_line(
                            "Following symlink %s\n"
                            "\t(further symlink messages suppressed for this cmdline "
                            "path)",
                            p->fts_path);
                        symlink_message_delivered = TRUE;
                    }
                    next_is_symlink = true;
                    fts_set(ftsp, p, FTS_FOLLOW); /* do not recurse */
                }
                break;
            case FTS_NSOK:    /* no rm_sys_stat(2) requested */
            case FTS_F:       /* regular file */
            case FTS_DEFAULT: /* any file type not explicitly described by one of the
                                 above*/
                clear_emptydir_flags = true; /* current dir not empty*/
                ADD_FILE(RM_LINT_TYPE_UNKNOWN, next_is_symlink);
                next_is_symlink = false;
                break;
            default:
                /* unknown case; assume current dir not empty but otherwise do nothing */
                clear_emptydir_flags = true;
                rm_log_error_line(_("Unknown fts_info flag %d for file %s"), p->fts_info,
                                  p->fts_path);
                break;
            }

            if(clear_emptydir_flags) {
                /* non-empty dir found above; need to clear emptydir flags for all open
                 * levels */
                if(have_open_emptydirs) {
                    memset(is_emptydir, 0, sizeof(is_emptydir) - 1);
                    have_open_emptydirs = false;
                }
                clear_emptydir_flags = false;
            }
            /* current dir may not be empty; by association, all open dirs are non-empty
             */
        }
    }

    if(errno != 0 && !rm_session_was_aborted()) {
        rm_log_error_line(_("'%s': fts_read failed on %s"), g_strerror(errno),
                          ftsp->fts_path);
    }

#undef ADD_FILE

    fts_close(ftsp);

done:
    rm_mds_device_ref(buffer->disk, -1);
    rm_trav_buffer_free(buffer);
}

////////////////
// PUBLIC API //
////////////////

void rm_traverse_tree(const RmCfg *cfg, GThreadPool *file_pool, RmMDS *mds) {
    rm_assert_gentle(cfg);
    rm_assert_gentle(mds);

    /* hashtable to prevent traversing into other roots */
    RmTravBuffer *buffer;
    GHashTable *roots = g_hash_table_new(g_str_hash, g_str_equal);
    for(guint idx = 0; cfg->paths[idx] != NULL; ++idx) {
        buffer = g_hash_table_lookup(roots, cfg->paths[idx]);
        if(buffer) {
            rm_trav_buffer_free(buffer);
        }
        bool is_prefd = (idx >= cfg->first_prefd);
        buffer = rm_trav_buffer_new(cfg, cfg->paths[idx], is_prefd, idx);
        g_hash_table_insert(roots, cfg->paths[idx], buffer);
    }

    RmTravSession traverser;
    traverser.cfg = cfg;
    traverser.file_pool = file_pool;
    traverser.userlist = rm_userlist_new();
    traverser.roots = roots;

    rm_mds_configure(mds, (RmMDSFunc)rm_traverse_directory, &traverser, 0,
                     cfg->threads_per_disk, NULL);

    GHashTableIter iter;
    char *path;
    g_hash_table_iter_init(&iter, roots);
    while(g_hash_table_iter_next(&iter, (gpointer *)&path, (gpointer *)&buffer)) {
        if(S_ISREG(buffer->stat_buf.st_mode)) {
            /* Append normal paths directly */

            /* Top level paths not treated as hidden unless --partial-hidden */
            bool is_hidden = cfg->partial_hidden && rm_util_path_is_hidden(buffer->path);

            rm_traverse_file(&traverser, &buffer->stat_buf, buffer->path,
                             buffer->is_prefd, buffer->path_index, RM_LINT_TYPE_UNKNOWN,
                             false, is_hidden, 0);

            rm_trav_buffer_free(buffer);
        } else if(S_ISDIR(buffer->stat_buf.st_mode)) {
            /* It's a directory, traverse it. */
            buffer->disk =
                rm_mds_device_get(mds, buffer->path, (cfg->fake_pathindex_as_disk)
                                                         ? buffer->path_index + 1
                                                         : buffer->stat_buf.st_dev);
            rm_mds_device_ref(buffer->disk, 1);
            rm_mds_push_task(buffer->disk, buffer->stat_buf.st_dev, 0, buffer->path,
                             buffer);

        } else {
            /* Probably a block device, fifo or something weird. */
            rm_trav_buffer_free(buffer);
        }
    }
    rm_mds_start(mds);
    rm_mds_finish(mds);

    g_hash_table_unref(roots);
    rm_userlist_destroy(traverser.userlist);
}
