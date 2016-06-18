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

#define ISDOT(a) (a[0] == '.' && (a[1] == 0 || (a[1] == '.' && a[2] == 0)))
#define ISHIDDEN(a) (a[0] == '.')

//////////////////////
//    Structs       //
//////////////////////

/**
 * @brief RmWalkCrumb is a backwards-linked breadcrumb trail of inodes;
 * it is used for cyclic dir detection;
 * @note linkage is many-to-one so dynamic freeing is difficult;
 * instead we keep a GAsyncQueue of allocated crumbs for freeing
 * at the end of the session;
 */
typedef struct RmWalkCrumb {
    struct RmWalkCrumb *parent; /* many-to-one link to parent crumb */
    ino_t inode;
    dev_t dev;
} RmWalkCrumb;

/**
 * RmWalkDir is a struct for passing jobs to the directory
 * traverser threadpool
 */
typedef struct RmWalkDir {
    RmStat *statp; /* stat(2) information about the directory */
    char *path;
    char *path_ptr;
    char *bname;
    RmNode *node;      /* where stored in pathtricia trie */
    bool is_prefd;     /* Was this dir reached via a preferred path? */
    bool is_hidden;    /* Is the dir hidden or reached via a hidden dir? */
    bool via_symlink;  /* Was the dir reached (directly or indirectly) via symlink? */
    guint index;       /* Index of path, as passed on the commadline */
    RmMDSDevice *disk; /* md-scheduler device the buffer was pushed to */
    gint16 depth;      /* traversal depth from root path */
    /* shared with other RmTravJob's under the same root dir: */
    RmWalkCrumb *crumbs; /* cycle checker */
} RmWalkDir;

//////////////////////
//    RmWalkCrumb   //
//////////////////////

/**
 * @brief create new breadcrumb entry linked to parent crumb
 */
static RmWalkCrumb *rm_walk_crumb_new(ino_t inode, dev_t dev, RmWalkCrumb *parent,
                                      RmWalkSession *walker) {
    RmWalkCrumb *crumb = g_slice_new(RmWalkCrumb);
    crumb->inode = inode;
    crumb->dev = dev;
    crumb->parent = parent;

    /* add to free list */
    g_async_queue_push(walker->crumbs, crumb);
    return crumb;
}

/**
 * @brief free mem allocated by rm_walk_crumb_new()
 */
static void rm_walk_crumb_free(RmWalkCrumb *crumb) {
    g_slice_free(RmWalkCrumb, crumb);
}

/**
 * @brief check breadcrumb trail to see if same dir already in trail
 */
static bool rm_walk_is_cycle(dev_t dev, ino_t inode, RmWalkCrumb *crumbs) {
    return !!crumbs && ((dev == crumbs->dev && inode == crumbs->inode) ||
                        rm_walk_is_cycle(dev, inode, crumbs->parent));
}

//////////////////////
//    RmWalkDir     //
//////////////////////

/**
 * create an RmWalkDir struct for a dir and send it to the md-scheduler;
 * is freed by the threadpool worker rm_walk_dir();
 * steals the RmStat struct pointed to by **sp;
 */
static void rm_walk_schedule_dir(char *path, char *bname, RmStat **sp, guint index,
                                 gint depth, gboolean is_hidden, gboolean via_symlink,
                                 RmWalkDir *parent_dir, RmWalkSession *walker) {
    RmWalkDir *dir = g_slice_new0(RmWalkDir);

    dir->path = g_strdup(path);
    dir->bname = g_strdup(bname);
    dir->index = index;
    dir->depth = depth;
    dir->is_hidden = is_hidden;
    dir->via_symlink = via_symlink;

    /* steal the stat struct */
    dir->statp = *sp;
    *sp = NULL;

    /* try to inherit some stuff from parent */
    RmWalkCrumb *crumbs = NULL;
    if(parent_dir) {
        crumbs = parent_dir->crumbs;
        if(parent_dir->statp && dir->statp &&
           parent_dir->statp->st_dev == dir->statp->st_dev &&
           parent_dir->statp->st_ino == dir->statp->st_ino) {
            dir->disk = parent_dir->disk;
        }
    }

    if(walker->trie) {
        if(parent_dir && bname) {
            dir->node = rm_node_insert(walker->trie, parent_dir->node, bname);
        } else {
            dir->node = rm_trie_insert(walker->trie, path, NULL);
        }
    }

    if(!dir->disk) {
        dir->disk = rm_mds_device_get(walker->mds, path, dir->statp->st_dev);
    }

    dir->crumbs =
        rm_walk_crumb_new(dir->statp->st_ino, dir->statp->st_dev, crumbs, walker);

    rm_mds_device_ref(dir->disk, 1);
    rm_mds_push_task(dir->disk, dir->statp->st_dev,
                     rm_mds_device_is_rotational(dir->disk) ? -1 : 0, dir->path, dir);
}

/**
 * free the structs allocated by rm_walk_schedule_dir()
 */
static void rm_walk_dir_free(RmWalkDir *dir) {
    g_free(dir->path);
    g_free(dir->bname);
    if(dir->statp) {
        g_slice_free(RmStat, dir->statp);
    }
    g_slice_free(RmWalkDir, dir);
}

//////////////////////
//    RmWalkFile    //
//////////////////////

/**
 * create an RmWalkFile and send it to result_pipe;
 * steals the RmStat struct pointed to by **sp;
 * the result_pipe worker should free it via rm_walk_file_free()
 */
static void rm_walk_file_send(RmWalkSession *walker, char *path, char *bname,
                              RmNode *parent_node, RmStat **sp, bool is_hidden,
                              bool is_symlink, bool via_symlink, guint index,
                              RmWalkType type, gint16 depth) {
    RmWalkFile *file = g_slice_new(RmWalkFile);
    file->path = g_strdup(path);
    file->bname = g_strdup(bname);
    file->type = type;
    file->dir_node = parent_node;
    file->is_hidden = is_hidden;
    file->via_symlink = via_symlink;
    file->is_symlink = is_symlink;
    file->index = index;
    file->depth = depth;
    file->err = errno;
    errno = 0;

    /* steal the stat struct */
    file->statp = *sp;
    *sp = NULL;

    rm_util_thread_pool_push(walker->result_pipe, file);
}

/* Macro for rm_walk_path() for convenience;
 * calls rm_walk_file_send() if test evaluates to TRUE
 */
#define SEND_FILE(test, type)                                                  \
    if((test)) {                                                               \
        rm_walk_file_send(walker, path, bname, parent_node, &statp, is_hidden, \
                          is_symlink, via_symlink, index, (type), depth);      \
    }

/**
 * process a path and categorise it;
 * maybe send it to result_pipe;
 * if it's a dir then maybe schedule traversal of the dir;
 */
void rm_walk_path(RmWalkSession *walker, char *path, char *bname, guint index,
                  guint16 depth, bool is_hidden, bool via_symlink,
                  RmWalkDir *parent_dir) {
    RmStat *statp = NULL;
    RmStat *targetp = NULL;
    bool is_symlink = FALSE;

    RmNode *parent_node = NULL;
    if(parent_dir) {
        parent_node = parent_dir->node;
    }

    /* process '.' and '..' */
    if(bname && ISDOT(bname)) {
        SEND_FILE(walker->see_dot, RM_WALK_DOT)
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
        } else if(walker->one_device && parent_dir && parent_dir->statp &&
                  statp->st_dev != parent_dir->statp->st_dev) {
            rm_log_info_line("rm_walk_path: RM_WALK_XDEV");
            SEND_FILE(walker->send_warnings, RM_WALK_XDEV);
        } else if(rm_mounts_is_evil(walker->mounts, statp->st_dev)) {
            SEND_FILE(walker->send_warnings, RM_WALK_EVILFS);
        } else if(parent_dir &&
                  rm_walk_is_cycle(statp->st_dev, statp->st_ino, parent_dir->crumbs)) {
            SEND_FILE(walker->send_warnings, RM_WALK_DC);
        } else {
            /* schedule dir recursion via a new thread */
            rm_walk_schedule_dir(path, bname, &statp, index, depth + 1, is_hidden,
                                 via_symlink, parent_dir, walker);
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

/* Macro for rm_walk_dir() for convenience;
 * calls rm_walk_file_send() if test evaluates to TRUE
 */
#define SEND_DIR(test, type)                                                         \
    if(test) {                                                                       \
        rm_walk_file_send(walker, dir->path, NULL, dir->node, &dir->statp,           \
                          dir->is_hidden, FALSE, dir->via_symlink, dir->index, type, \
                          dir->depth);                                               \
    }

/**
 * RmMDS callback to traverse a directory;
 * calls rm_walk_path() for each valid entry
 */
static void rm_walk_dir(RmWalkDir *dir, RmWalkSession *walker) {
    char *path = g_slice_alloc(PATH_MAX * sizeof(char));
    char *path_ptr = g_stpcpy(path, dir->path);

    /* add trailing / to path */
    if(path_ptr + 2 > path + PATH_MAX) {
        SEND_DIR(walker->send_errors, RM_WALK_PATHMAX)
        goto done;
    }
    path_ptr = g_stpcpy(path_ptr, "/");

    /* open dir */
    DIR *dirp = opendir(dir->path);
    if(!dirp) {
        SEND_DIR(walker->send_errors, RM_WALK_DNR) {
        }
        goto done;
    }

    SEND_DIR(walker->send_dirs, RM_WALK_DIR);

    if(dir->depth + 1 > walker->max_depth) {
        closedir(dirp);
        goto done;
    }

    /* iterate over dirent's in this dir */
    struct dirent *de = NULL;
    while(!rm_session_was_aborted() && (de = readdir(dirp)) != NULL) {
        if(ISDOT(de->d_name) && !walker->see_dot) {
            continue;
        }

        gboolean is_hidden = dir->is_hidden || (dir->depth > 0 && ISHIDDEN(de->d_name));
        if(is_hidden && !walker->walk_hidden && !walker->send_hidden &&
           !walker->send_warnings) {
            /* can totally ignore hidden file/folder */
            continue;
        }

/* build full path: */
#if defined(HAVE_STRUCT_DIRENT_D_NAMLEN)
        size_t dnamlen = de->d_namlen;
#else
        size_t dnamlen = strlen(de->d_name);
#endif
        if(path_ptr + dnamlen + 1 > path + PATH_MAX) {
            if(walker->send_errors) {
                rm_walk_file_send(walker, path, de->d_name, dir->node, &dir->statp,
                                  is_hidden, FALSE, dir->via_symlink, dir->index,
                                  RM_WALK_PATHMAX, dir->depth + 1);
            }
            continue;
        }
        g_stpcpy(path_ptr, de->d_name);

        /* process the dirent */
        rm_walk_path(walker, path, de->d_name, dir->index, dir->depth + 1, is_hidden,
                     dir->via_symlink, dir);
    }
    closedir(dirp);

done:
    g_slice_free1(PATH_MAX * sizeof(char), path);
    rm_mds_device_ref(dir->disk, -1);
    rm_walk_dir_free(dir);
}

#undef SEND_DIR
#undef ISDOT
#undef ISHIDDEN

//////////////////////////////
//        WALK API          //
//////////////////////////////

RmWalkSession *rm_walk_session_new(RmMDS *mds, GThreadPool *result_pipe, RmTrie *trie,
                                   RmMountTable *mounts) {
    RmWalkSession *walker = g_new0(RmWalkSession, 1);
    walker->mds = mds;
    walker->result_pipe = result_pipe;
    walker->trie = trie;
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

    walker->crumbs = g_async_queue_new_full((GDestroyNotify)rm_walk_crumb_free);

    GHashTableIter iter;
    char *path = NULL;
    gpointer value = NULL;
    g_hash_table_iter_init(&iter, walker->roots);
    while(g_hash_table_iter_next(&iter, (gpointer)&path, &value)) {
        guint index = GPOINTER_TO_UINT(value);
        rm_walk_path(walker, path, NULL, index, 0, FALSE, FALSE, NULL);
    }
    rm_mds_start(walker->mds);
    rm_mds_finish(walker->mds);

    g_hash_table_unref(walker->roots);
    g_async_queue_unref(walker->crumbs);
    g_free(walker);
}

void rm_walk_file_free(RmWalkFile *file) {
    g_free(file->path);
    g_free(file->bname);
    if(file->statp) {
        g_slice_free(RmStat, file->statp);
    }
    g_slice_free(RmWalkFile, file);
}
