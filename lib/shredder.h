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

#ifndef RM_SHREDDER_H
#define RM_SHREDDER_H

#include <glib.h>
#include "md-scheduler.h"
#include "session.h"

typedef enum RmShredGroupStatus {
    RM_SHRED_GROUP_DORMANT = 0,
    RM_SHRED_GROUP_START_HASHING,
    RM_SHRED_GROUP_HASHING,
    RM_SHRED_GROUP_FINISHING,
    RM_SHRED_GROUP_FINISHED
} RmShredGroupStatus;

/* buffer for sending progress updates and/or finished files to session.c */
typedef struct RmShredBuffer {
    gint64 delta_bytes;
    gint delta_files;
    GSList *finished_files;
} RmShredBuffer;

/**
 * @brief Find duplicate RmFile and pass them to postprocess; free/destroy all other
 *RmFiles.
 *
 * @param session: rmlint session containing all cfg and pseudo-globals
 */
void rm_shred_run(RmCfg *cfg, RmFileTables *tables, RmMDS *mds,
                  GThreadPool *shredder_pipe, guint total_files);

/**
 * @brief Find the original file in a group and mark it.
 * TODO: move this out of shredder
 */
GSList *rm_shred_group_find_original(RmCfg *cfg, GSList *group, RmLintType lint_type,
                                     RmDigest *digest);

/**
 * @brief create a new RmShredBuffer with the provided data
 */
RmShredBuffer *rm_shred_buffer_new(GSList *files, gint delta_files, gint64 delta_bytes);

/**
 * @brief free an RmShredBuffer
 * @note caller retains ownership of buffer->group
 */
void rm_shred_buffer_free(RmShredBuffer *buffer);

#endif
