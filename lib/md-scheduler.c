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

#include "md-scheduler.h"

/* How many milliseconds to sleep if we encounter an empty file queue.
 * This prevents a "starving" RmShredDevice from hogging cpu and cluttering up
 * debug messages by continually recycling back to the joiner.
 */
#if _RM_MDS_DEBUG
#define MDS_EMPTYQUEUE_SLEEP_US (60 * 1000 * 1000) /* 60 seconds */
#else
#define MDS_EMPTYQUEUE_SLEEP_US (50 * 1000) /* 0.05 second */
#endif

///////////////////////////////////////
//            Structures             //
///////////////////////////////////////

struct _RmMDS {
    /* Structure for RmMDS object/session */

    /* The function called for each task */
    RmMDSFunc func;

    /* Threadpool for device workers */
    GThreadPool *pool;
    gint threads_per_hdd;
    gint threads_per_ssd;

    /* Sorting function for device task queues */
    RmMDSSortFunc hdd_prioritiser;
    RmMDSSortFunc ssd_prioritiser;

    /* Mounts table for grouping dev's by physical devices
     * and identifying rotationality */
    RmMountTable *mount_table;

    /* If true then don't use mount table; interpret user-supplied dev as disk id */
    bool fake_disk;

    /* Table of physical disk/devices */
    GHashTable *disks;

    /* Lock for access to:
     *  self->disks
     */
    GMutex lock;
    GCond cond;

    gint ref_count;

    /* flag for whether threadpool is running */
    gboolean running;

    gboolean paused;

    /* quota to limit number of tasks per pass of each device */
    guint pass_quota;

    /* pointer to user data to be passed to func */
    gpointer user_data;
};

typedef struct _RmMDSDevice {
    /* Structure containing data associated with one Device worker thread */

    /* The RmMDS session parent */
    RmMDS *mds;

    /* Device's physical disk ID (only used for debug info) */
    dev_t disk;

    /* threadpool for channelling tasks */
    GThreadPool *pool;

    /* maximum number of threads for this device */
    gint threads;

    /* used to keep track of dev & offset of last completed task */
    RmMDSTask prev;

    /* sort function for setting processing order */
    RmMDSSortFunc prioritiser;

    /* number of tasks remaining until next sort needed */
    guint sorted_tasks;

    /* Atomic reference count for self */
    gint ref_count;

    /* is disk rotational? */
    gboolean is_rotational;

    GMutex lock;

} RmMDSDevice;

//////////////////////////////////////////////
//  Internal Structure Init's & Destroyers  //
//////////////////////////////////////////////

/* RmMDSTask */
static RmMDSTask *rm_mds_task_new(const dev_t dev, const guint64 offset,
                                  const gpointer task_data) {
    RmMDSTask *self = g_slice_new(RmMDSTask);
    self->dev = dev;
    self->offset = offset;
    self->task_data = task_data;
    return self;
}

static void rm_mds_task_free(RmMDSTask *task) {
    g_slice_free(RmMDSTask, task);
}

/* RmMDSDevice */

/** @brief Allocate and configure a new RmMDSDevice
 **/
static RmMDSDevice *rm_mds_device_new(RmMDS *mds, const dev_t disk) {
    RmMDSDevice *self = g_slice_new0(RmMDSDevice);

    self->mds = mds;
    self->ref_count = 0;
    self->disk = disk;

    if(mds->fake_disk) {
        self->is_rotational = (disk % 2 == 0);
    } else {
        self->is_rotational = !rm_mounts_is_nonrotational(mds->mount_table, disk);
    }

    self->threads = (self->is_rotational) ? mds->threads_per_hdd : mds->threads_per_ssd;

    rm_log_debug_line("Created new RmMDSDevice for %srotational disk #%" LLU,
                      self->is_rotational ? "" : "non-", (RmOff)disk);
    return self;
}

/** @brief  Free mem allocated to an RmMDSDevice; prototyped for GRHFunc compatibility
 **/
static gboolean rm_mds_device_free(_UNUSED guint disk, RmMDSDevice *self,
                                   _UNUSED gpointer user_data) {
    rm_log_debug_line("rm_mds_device_free for disk %d", disk);
    g_thread_pool_free(self->pool, FALSE, TRUE);
    g_slice_free(RmMDSDevice, self);
    return TRUE;
}

///////////////////////////////////////
//    RmMDSDevice Implementation   //
///////////////////////////////////////

/** @brief GCompareDataFunc wrapper for mds->prioritiser
 **/
static gint rm_mds_compare(const RmMDSTask *a, const RmMDSTask *b,
                           RmMDSSortFunc prioritiser) {
    gint result = prioritiser(a, b);
    return result;
}

static void rm_mds_device_sort(_UNUSED dev_t disk, RmMDSDevice *device, RmMDS *mds) {
    rm_log_debug_line("Sorting disk %lu", disk);
    if(device->prioritiser) {
        g_thread_pool_set_sort_function(device->pool, (GCompareDataFunc)rm_mds_compare,
                                        device->prioritiser);
        g_thread_pool_set_sort_function(device->pool, NULL, NULL);
        device->sorted_tasks = g_thread_pool_unprocessed(device->pool);
        device->sorted_tasks = MAX(1, MIN(mds->pass_quota, device->sorted_tasks));
    }
}

/** @brief RmMDSDevice worker thread
 **/
static void rm_mds_factory(RmMDSTask *task, RmMDSDevice *device) {
    RmMDS *mds = device->mds;
    if(mds->paused) {
        rm_util_thread_pool_push(device->pool, task);
        g_usleep(1000);
        return;
    }

    device->mds->func(task->task_data, device->mds->user_data);
    rm_mds_task_free(task);
    if(device->prioritiser && g_atomic_int_dec_and_test(&device->sorted_tasks) && !rm_session_was_aborted()) {
        rm_mds_device_sort(device->disk, device, mds);
    }
}

/** @brief Start an RmMDSDevice (prototyped as GHFunc)
 **/
static void rm_mds_device_start(_UNUSED guint disk, RmMDSDevice *device,
                                RmMDS *mds) {
    rm_mds_device_ref(device, 1, TRUE);
    rm_log_info_line("rm_mds_device_start for %lu with %d threads", device->disk,
                     device->threads);

    device->prioritiser = (device->is_rotational) ? mds->hdd_prioritiser : mds->ssd_prioritiser;

    device->pool =
        rm_util_thread_pool_new((GFunc)rm_mds_factory, device, device->threads, FALSE);
}

static RmMDSDevice *rm_mds_device_get_by_disk(RmMDS *mds, const dev_t disk) {
    RmMDSDevice *result = NULL;
    g_mutex_lock(&mds->lock);
    {
        rm_assert_gentle(mds->disks);
        rm_assert_gentle(mds->running);

        result = g_hash_table_lookup(mds->disks, GINT_TO_POINTER(disk));
        if(!result) {
            result = rm_mds_device_new(mds, disk);
            g_hash_table_insert(mds->disks, GINT_TO_POINTER(disk), result);
            if(mds->running) {
                rm_mds_device_start(disk, result, mds);
            }
        }
    }
    g_mutex_unlock(&mds->lock);
    return result;
}

/** @brief update reference count for mds session; if result is zero then signal cond
 **/
static gint rm_mds_ref(RmMDS *mds, const gint ref_count, gboolean have_mds_lock) {
    gint result;
    if(!have_mds_lock) {
        g_mutex_lock(&mds->lock);
    }
    {
        rm_assert_gentle(mds->ref_count >= 0);
        mds->ref_count += ref_count;
        rm_assert_gentle(mds->ref_count >= 0);
        result = mds->ref_count;

        if(result == 0) {
            /* signal to rm_mds_finish */
            g_cond_signal(&mds->cond);
        }
    }
    if(!have_mds_lock) {
        g_mutex_unlock(&mds->lock);
    }

    return result;
}

/* GHFunc wrapper for rm_mds_device_ref */
static gint rm_mds_device_ref_ghfunc(_UNUSED dev_t disk, RmMDSDevice *device,
                                     gint ref_count) {
    return rm_mds_device_ref(device, ref_count, TRUE);
}

//////////////////////////
//  API Implementation  //
//////////////////////////

RmMDS *rm_mds_new(RmMountTable *mount_table, bool fake_disk) {
    RmMDS *self = g_slice_new0(RmMDS);

    g_mutex_init(&self->lock);
    g_cond_init(&self->cond);

    if(!mount_table && !fake_disk) {
        self->mount_table = rm_mounts_table_new(FALSE);
    } else {
        self->mount_table = mount_table;
    }

    self->fake_disk = fake_disk;
    self->disks = g_hash_table_new(g_direct_hash, g_direct_equal);
    self->running = FALSE;

    return self;
}

void rm_mds_configure(RmMDS *self,
                      const RmMDSFunc func,
                      const gpointer user_data,
                      const gint pass_quota,
                      const gint threads_per_hdd,
                      const gint threads_per_ssd,
                      RmMDSSortFunc hdd_prioritiser,
                      RmMDSSortFunc ssd_prioritiser) {
    rm_assert_gentle(self->running == FALSE);
    self->func = func;
    self->user_data = user_data;
    self->threads_per_hdd = threads_per_hdd;
    self->threads_per_ssd = threads_per_ssd;
    self->pass_quota = (pass_quota > 0) ? pass_quota : G_MAXINT;
    self->hdd_prioritiser = hdd_prioritiser;
    self->ssd_prioritiser = ssd_prioritiser;
}

void rm_mds_start(RmMDS *mds) {
    g_mutex_lock(&mds->lock);
    {
        rm_mds_ref(mds, 1, TRUE);
        mds->running = TRUE;
        g_hash_table_foreach(mds->disks, (GHFunc)rm_mds_device_start, mds);
    }
    g_mutex_unlock(&mds->lock);
}

void rm_mds_pause(RmMDS *mds) {
    mds->paused = TRUE;
}

void rm_mds_resume(RmMDS *mds) {
    g_hash_table_foreach(mds->disks, (GHFunc)rm_mds_device_sort, mds);
    mds->paused = FALSE;
}

void rm_mds_finish(RmMDS *mds) {
    g_mutex_lock(&mds->lock);
    {
        g_hash_table_foreach(mds->disks, (GHFunc)rm_mds_device_ref_ghfunc,
                             GINT_TO_POINTER(-1));
        rm_mds_ref(mds, -1, TRUE);

        while(g_atomic_int_get(&mds->ref_count) > 0) {
            g_cond_wait(&mds->cond, &mds->lock);
        }
        g_hash_table_foreach_remove(mds->disks, (GHRFunc)rm_mds_device_free, NULL);
    }
    mds->running = FALSE;
    g_mutex_unlock(&mds->lock);

    rm_log_debug_line("rm_mds_finish: done");
}

void rm_mds_free(RmMDS *mds, gboolean free_mount_table) {
    rm_mds_finish(mds);

    g_hash_table_destroy(mds->disks);

    if(free_mount_table && mds->mount_table) {
        rm_mounts_table_destroy(mds->mount_table);
    }
    g_mutex_clear(&mds->lock);
    g_cond_clear(&mds->cond);
    g_slice_free(RmMDS, mds);
}

gint rm_mds_device_ref(RmMDSDevice *device, const gint ref_count,
                       const gboolean have_mds_lock) {
    gint was = g_atomic_int_add(&device->ref_count, ref_count);
    gint is = was + ref_count;
    rm_assert_gentle(was >= 0);
    rm_assert_gentle(is >= 0);

    if(was == 0 && is > 0) {
        rm_mds_ref(device->mds, 1, have_mds_lock);
    } else if(was > 0 && is == 0) {
        rm_mds_ref(device->mds, -1, have_mds_lock);
    }

    return is;
}

RmMDSDevice *rm_mds_device_get(RmMDS *mds, const char *path, dev_t dev) {
    dev_t disk = 0;
    if(dev == 0) {
        dev = rm_mounts_get_disk_id_by_path(mds->mount_table, path);
    }
    if(mds->fake_disk) {
        disk = dev;
    } else {
        disk = rm_mounts_get_disk_id(mds->mount_table, dev, path);
    }
    return rm_mds_device_get_by_disk(mds, disk);
}

gboolean rm_mds_device_is_rotational(RmMDSDevice *device) {
    return device->is_rotational;
}

void rm_mds_push_task(RmMDSDevice *device, dev_t dev, gint64 offset, const char *path,
                      const gpointer task_data) {
    if(device->is_rotational && offset == -1) {
        offset = rm_offset_get_from_path(path, 0, NULL);
    }
    RmMDSTask *task = rm_mds_task_new(dev, offset, task_data);
    rm_util_thread_pool_push(device->pool, task);

    if (!device->mds->paused && !device->prioritiser) {
        g_thread_pool_move_to_front(device->pool, task);
    }
}

/**
 * @brief prioritiser function for basic elevator algorithm
 **/
gint rm_mds_elevator_cmp(const RmMDSTask *task_a, const RmMDSTask *task_b) {
    return (2 * SIGN_DIFF(task_a->dev, task_b->dev) +
            1 * SIGN_DIFF(task_a->offset, task_b->offset));
}
