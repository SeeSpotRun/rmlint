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

#include "walk.h"
#include <glib.h>
#include <string.h>

//////////////////////
//    Structs       //
//////////////////////

/**
 * RmWalkDir is a struct for passing jobs to the directory
 * traverser threadpool
 */
typedef struct RmWalkDir {
    RmWalkFile file;   /* RmWalkFile representing the directory path */
    RmMDSDevice *disk; /* md-scheduler device the buffer was pushed to */
    gint ref_count;    /* atomic reference count:
                        * +1 when at start of traversal;
                        * +1 for each instance sent to result_pipe;
                        *    reversed by rm_walk_file_free(&dir->file)
                        * +1 for each subfile;
                        *    reversed by rm_walk_file_free(child)
                        * */
} RmWalkDir;

////////////////////////////
//  RmWalkDir Procedures  //
////////////////////////////

/**
 * @brief free the struct members allocated by rm_walk_file_new()
 */
static void rm_walk_file_clear(RmWalkFile *file) {
    g_free(file->path);
    g_free(file->bname);
    if(file->statp) {
        g_slice_free(RmStat, file->statp);
    }
}

/**
 * @brief adjust a dir's reference count and maybe free it
 * @param dir the dir (nullable)
 * @param count the amount to add to the ref_count
 */
static void rm_walk_dir_ref(RmWalkDir *dir, gint count) {
    if(!dir) {
        return;
    }
    if(g_atomic_int_add(&dir->ref_count, count) + count == 0) {
        rm_walk_dir_ref((RmWalkDir *)dir->file.parent, -1);
        rm_walk_file_clear(&dir->file);
        g_slice_free(RmWalkDir, dir);
    }
}

/**
 * @brief check if same (dev,inode) in dir's ancestry
 * @param dir the dir we are trying to match
 * @param iter the current iteration being compared (nullable)
 */
static bool rm_walk_is_cycle(dev_t dev, ino_t ino, RmWalkDir *iter) {
    if(!iter) {
        /* end of trail; no match found */
        return false;
    }
    if(iter->file.statp->st_dev == dev && iter->file.statp->st_ino == ino) {
        /* found matching inode in trail so must be a cycle */
        return true;
    }
    /* search upwards recursively until match found or trail ends */
    return rm_walk_is_cycle(dev, ino, (RmWalkDir *)iter->file.parent);
}

#define PARENT(dir) (RmWalkDir *)dir->file.parent
#define DEV(dir) dir->file.statp->st_dev
#define INO(dir) dir->file.statp->st_ino

/**
 * create an RmWalkDir struct for a dir and send it to the md-scheduler;
 * is freed by the threadpool worker rm_walk_dir();
 * steals the RmStat struct pointed to by **sp;
 */
static void rm_walk_schedule_dir(RmWalkDir *dir, RmWalkSession *walker) {
    rm_assert_gentle(dir->file.statp);

    RmWalkDir *parent = PARENT(dir);

    /* try to inherit some stuff from parent */
    gboolean same_device = parent && DEV(parent) == DEV(dir) && INO(parent) == INO(dir);
    dir->disk = (same_device) ? parent->disk
                              : rm_mds_device_get(walker->mds, dir->file.path, DEV(dir));

    rm_mds_device_ref(dir->disk, 1);
    rm_mds_push_task(dir->disk, DEV(dir), rm_mds_device_is_rotational(dir->disk) ? -1 : 0,
                     dir->file.path, dir);
}

#undef INO
#undef DEV
#undef PARENT

////////////////////////////////
//    RmWalkFile Procedures   //
////////////////////////////////

/**
 * create an RmWalkFile and send it to result_pipe;
 * steals the RmStat struct pointed to by **sp;
 * the result_pipe worker should free it via rm_walk_file_free()
 */
static RmWalkFile *rm_walk_file_new(char *path, char *bname, RmStat **sp, bool is_hidden,
                                    bool is_symlink, bool via_symlink, guint index,
                                    RmWalkType type, gint16 depth, RmWalkDir *parent,
                                    RmWalkSession *walker) {
    RmWalkFile *file = (type == RM_WALK_DIR) ? (RmWalkFile *)g_slice_new0(RmWalkDir)
                                             : g_slice_new0(RmWalkFile);
    file->path = (!parent || !walker->basename_only) ? g_strdup(path) : NULL;
    file->bname = g_strdup(bname);
    file->is_hidden = is_hidden;
    file->is_symlink = is_symlink;
    file->via_symlink = via_symlink;
    file->index = index;
    file->type = type;
    file->depth = depth;
    if(parent) {
        file->parent = &parent->file;
        rm_walk_dir_ref(parent, 1);
    }
    file->is_dir = (type == RM_WALK_DIR);

    file->err = errno;
    errno = 0;

    /* steal the stat struct */
    file->statp = *sp;
    *sp = NULL;

    return file;
}

////////////////////////
//   File Processing  //
////////////////////////

static void rm_walk_send(RmWalkFile *file, RmWalkSession *walker) {
    while(g_thread_pool_unprocessed(walker->result_pipe) > 1000) {
        /* avoid choking the threadpool */
        g_usleep(1000);
    }
    rm_util_thread_pool_push(walker->result_pipe, file);
}

/* Macros for rm_walk_path() for convenience;
 * calls rm_walk_file_send() if test evaluates to TRUE
 */
#define ISDOT(a) (a[0] == '.' && (a[1] == 0 || (a[1] == '.' && a[2] == 0)))

#define NEW_FILE(type)                                                               \
    rm_walk_file_new(path, bname, &statp, is_hidden, is_symlink, via_symlink, index, \
                     type, depth, parent_dir, walker)

#define SEND_FILE(test, type)                 \
    if(test) {                                \
        rm_walk_send(NEW_FILE(type), walker); \
    }

/**
 * process a path and categorise it;
 * maybe send it to result_pipe;
 * if it's a dir then maybe schedule traversal of the dir;
 */
void rm_walk_path(RmWalkSession *walker, char *path, char *bname, gboolean path_buf_of,
                  guint index, guint16 depth, bool is_hidden, bool via_symlink,
                  RmWalkDir *parent_dir) {
    RmStat *statp = NULL;   /* the statp that we will send */
    RmStat *targetp = NULL; /* if statp is a symlink, the stat of its target */
    bool is_symlink = FALSE;

    if(path_buf_of) {
        SEND_FILE(walker->send_errors, RM_WALK_PATHMAX)
        return;
    }

    /* process '.' and '..' */
    if(bname && ISDOT(bname)) {
        SEND_FILE(walker->see_dot, RM_WALK_DOT)
        return;
    }

    if(is_hidden && !walker->walk_hidden && !walker->send_hidden &&
       !walker->send_warnings) {
        /* can totally ignore hidden file/folder */
        return;
    }

    /* stat the physical file: */
    statp = g_slice_new(RmStat);
    if(rm_sys_lstat(path, statp)) {
        /* stat error on physical file */
        memset(statp, 0, sizeof(RmStat));
        SEND_FILE(walker->send_errors, RM_WALK_NS);
        goto done;
    }

    if(S_ISLNK(statp->st_mode)) {
        is_symlink = TRUE;
        if(walker->send_badlinks || walker->do_links || depth == 0) {
            /* stat the symlink target */
            targetp = g_slice_new(RmStat);
            if(rm_sys_stat(path, targetp)) {
                /* stat error, must be badlink */
                SEND_FILE(walker->send_badlinks, RM_WALK_BADLINK);
                goto done;
            }
        }
        /* maybe send the link itself */
        if(walker->see_links) {
            rm_log_info_line("seelink: %s", path);
            SEND_FILE(TRUE, RM_WALK_SL);
        }

        if(depth > 0 && !walker->do_links) {
            /* don't follow that link */
            if(!walker->see_links) {
                /* maybe warn that we skipped symlink */
                SEND_FILE(walker->send_warnings, RM_WALK_SL);
            }
            goto done;
        }

        /* free physical stat and replace it with logical one */
        if(statp) {
            g_slice_free(RmStat, statp);
        }
        rm_assert_gentle(targetp);
        statp = targetp;
        targetp = NULL;
    }

    /* handle subdirs */
    if(S_ISDIR(statp->st_mode)) {
        if(is_hidden && !walker->walk_hidden) {
            SEND_FILE(walker->send_warnings, RM_WALK_HIDDEN_DIR)
        } else if(depth > 0 && g_hash_table_contains(walker->roots, path)) {
            SEND_FILE(walker->send_warnings, RM_WALK_SKIPPED_ROOT)
        } else if(walker->one_device && parent_dir &&
                  parent_dir->file.statp->st_dev != statp->st_dev) {
            SEND_FILE(walker->send_warnings, RM_WALK_XDEV);
        } else if(rm_mounts_is_evil(walker->mounts, statp->st_dev)) {
            SEND_FILE(walker->send_warnings, RM_WALK_EVILFS);
        } else if(parent_dir &&
                  rm_walk_is_cycle(statp->st_dev, statp->st_ino, parent_dir)) {
            SEND_FILE(walker->send_warnings, RM_WALK_DC);
        } else {
            /* schedule dir recursion via a new thread */
            RmWalkFile *dirfile = NEW_FILE(RM_WALK_DIR);
            rm_walk_schedule_dir((RmWalkDir *)dirfile, walker);
        }
        goto done;
    }

    if(walker->ignore_files) {
        goto done;
    }

    if(is_hidden && !walker->send_hidden) {
        /* maybe send a warning that we skipped the file */
        SEND_FILE(walker->send_warnings, RM_WALK_HIDDEN_FILE);
        goto done;
    }

#ifdef DTF_HIDEW
    if(statp->d_type == DT_WHT) {
        ADD_FILE(walker->send_warnings, RM_WALK_WHITEOUT);
        goto done;
    }
#endif

    if(S_ISREG(statp->st_mode)) {
        SEND_FILE(TRUE, RM_WALK_REG);
        goto done;
    }

    SEND_FILE(TRUE, RM_WALK_OTHER);

done:
    if(statp) {
        g_slice_free(RmStat, statp);
    }
    if(targetp) {
        g_slice_free(RmStat, targetp);
    }
}

#undef SEND_FILE
#undef NEW_FILE
#undef ISDOT

////////////////////////////
//   Directory traversal  //
////////////////////////////

/* Macro for rm_walk_dir() for convenience;
 * calls rm_walk_file_send() if test evaluates to TRUE
 */
#define SEND_DIR(test, ftype)             \
    if(test) {                            \
        dir->file.type = ftype;           \
        rm_walk_dir_ref(dir, 1);          \
        rm_walk_send(&dir->file, walker); \
    }

/**
 * RmMDS callback to traverse a directory;
 * calls rm_walk_path() for each valid entry
 */
static void rm_walk_dir(RmWalkDir *dir, RmWalkSession *walker) {
    char *path = g_slice_alloc(PATH_MAX * sizeof(char));
    char *path_ptr = g_stpcpy(path, dir->file.path);
    rm_walk_dir_ref(dir, 1);
    /* add trailing / to path */
    if(path_ptr + 2 > path + PATH_MAX) {
        SEND_DIR(walker->send_errors, RM_WALK_PATHMAX)
        goto done;
    }
    path_ptr = g_stpcpy(path_ptr, "/");

    /* open dir */
    DIR *dirp = opendir(dir->file.path);
    if(!dirp) {
        SEND_DIR(walker->send_errors, RM_WALK_DNR)
        goto done;
    }

    dir->file.is_traversed = dir->file.depth + 1 <= walker->max_depth;
    SEND_DIR(walker->send_dirs, RM_WALK_DIR);

    if(dir->file.is_traversed) {
        /* iterate over dirent's in this dir */
        struct dirent *de = NULL;
        while(!rm_session_was_aborted() && (de = readdir(dirp)) != NULL) {
            gboolean is_hidden = dir->file.is_hidden || de->d_name[0] == '.';

/* build full path: */
#if defined(HAVE_STRUCT_DIRENT_D_NAMLEN)
            size_t dnamlen = de->d_namlen;
#else
            size_t dnamlen = strlen(de->d_name);
#endif
            gboolean path_buf_of = FALSE;
            if(path_ptr + dnamlen + 1 > path + PATH_MAX) {
                g_stpcpy(path_ptr, ".");
                path_buf_of = TRUE;
            } else {
                g_stpcpy(path_ptr, de->d_name);
            }

            /* process the dirent */
            rm_walk_path(walker, path, de->d_name, path_buf_of, dir->file.index,
                         dir->file.depth + 1, is_hidden, dir->file.via_symlink, dir);
        }
    }
    closedir(dirp);

done:
    g_slice_free1(PATH_MAX * sizeof(char), path);
    rm_mds_device_ref(dir->disk, -1);

    rm_walk_dir_ref(dir, -1);
}

#undef SEND_DIR

//////////////////////////////
//        WALK API          //
//////////////////////////////

RmWalkSession *rm_walk_session_new(RmMDS *mds, GThreadPool *result_pipe,
                                   RmMountTable *mounts) {
    RmWalkSession *walker = g_new0(RmWalkSession, 1);
    walker->mds = mds;
    walker->result_pipe = result_pipe;
    walker->mounts = mounts;
    walker->max_depth = (guint16)-1;
    return walker;
}

void rm_walk_paths(char **paths, RmWalkSession *walker, gint threads_per_hdd,
                   gint threads_per_ssd, gint sort_interval) {
    /* put paths into hashtable to prevent double-traversing overlapping paths */
    walker->roots = g_hash_table_new(g_str_hash, g_str_equal);
    for(guint index = 0; paths[index] != NULL; ++index) {
        g_hash_table_insert(walker->roots, paths[index], GUINT_TO_POINTER(index));
    }

    rm_mds_configure(walker->mds, (RmMDSFunc)rm_walk_dir, walker, sort_interval,
                     threads_per_hdd, threads_per_ssd, rm_mds_elevator_cmp, NULL);

    GHashTableIter iter;
    char *path = NULL;
    gpointer value = NULL;
    g_hash_table_iter_init(&iter, walker->roots);
    while(g_hash_table_iter_next(&iter, (gpointer)&path, &value)) {
        guint index = GPOINTER_TO_UINT(value);
        rm_walk_path(walker, path, NULL, FALSE, index, 0, FALSE, FALSE, NULL);
    }
    rm_mds_start(walker->mds);
    rm_mds_finish(walker->mds);

    g_hash_table_unref(walker->roots);
    g_free(walker);
}

void rm_walk_file_free(RmWalkFile *file) {
    if(file->is_dir) {
        rm_walk_dir_ref((RmWalkDir *)file, -1);
    } else {
        rm_walk_dir_ref((RmWalkDir *)file->parent, -1);
        rm_walk_file_clear(file);
        g_slice_free(RmWalkFile, file);
    }
}
