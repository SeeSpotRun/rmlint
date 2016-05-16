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
** Authors:
 *
 *  - Christopher <sahib> Pahl 2010-2015 (https://github.com/sahib)
 *  - Daniel <SeeSpotRun> T.   2014-2015 (https://github.com/SeeSpotRun)
 *
** Hosted on http://github.com/sahib/rmlint
*
**/

#ifndef RM_TRAVERSE_H
#define RM_TRAVERSE_H

#include "formats.h"
#include "md-scheduler.h"

typedef struct RmTraverseFile {
    size_t size;
    ino_t inode;
    dev_t dev;
    time_t mtime;
    char *path;
    RmLintType lint_type;
    bool is_prefd;
    unsigned long path_index;
    short depth;
    bool is_symlink;
    bool is_hidden;
} RmTraverseFile;

/**
 * @brief Traverse all specified paths.
 * @param cfg the session configuration
 * @param
 */
void rm_traverse_tree(const RmCfg *cfg, GThreadPool *file_pool, RmMDS *mds);

void rm_traverse_file_destroy(RmTraverseFile *file);

#endif
