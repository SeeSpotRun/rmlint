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
 *  - Christopher <sahib> Pahl 2010-2017 (https://github.com/sahib)
 *  - Daniel <SeeSpotRun> T.   2014-2017 (https://github.com/SeeSpotRun)
 *
 * Hosted on http://github.com/sahib/rmlint
 *
 */

#include "../formats.h"

#include <glib.h>
#include <stdio.h>
#include <string.h>

typedef struct RmFmtHandlerUniques {
    /* must be first */
    RmFmtHandler parent;
} RmFmtHandlerUniques;

static void rm_fmt_elem(_UNUSED RmSession *session, _UNUSED RmFmtHandler *parent,
                        RmFile *file) {
    if(file->lint_type != RM_LINT_TYPE_UNIQUE_FILE) {
        /* we only not want to list unfinished files. */
        return;
    }
    if(session->cfg->keep_all_tagged && !file->is_prefd) {
        /* don't list 'untagged' files as unique */
        return;
    }
    if(session->cfg->keep_all_untagged && file->is_prefd) {
        /* don't list 'tagged' files as unique */
        return;
    }

    RM_DEFINE_PATH(file);
    fputs(file_path, parent->out);
    fputc('\n', parent->out);
}

/* API hooks for RM_FMT_REGISTER in formats.c */

const char *UNIQUES_HANDLER_NAME = "uniques";

const char *UNIQUES_HANDLER_VALID_KEYS[] = {NULL};

RmFmtHandler *UNIQUES_HANDLER_NEW(_UNUSED RmFmtTable *table) {
    RmFmtHandlerUniques *handler = g_new0(RmFmtHandlerUniques, 1);
    /* Initialize parent */
    handler->parent.elem = rm_fmt_elem;

    /* initialise any non-null handler-specific fields */

    return (RmFmtHandler *)handler;
};
