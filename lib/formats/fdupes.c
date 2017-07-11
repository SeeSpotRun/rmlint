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

typedef struct RmFmtHandlerFdupes {
    /* must be first */
    RmFmtHandler parent;

    /* Do not print original (fdupes emulation) */
    bool omit_first_line;

    /* Do not print newlines between files */
    bool use_same_line;
} RmFmtHandlerFdupes;

static void rm_fmt_elem(_UNUSED RmSession *session, RmFmtHandler *parent, RmFile *file) {
    RmFmtHandlerFdupes *self = (RmFmtHandlerFdupes *)parent;

    if(file->lint_type == RM_LINT_TYPE_UNIQUE_FILE) {
        /* we do not want to list unfinished files. */
        return;
    }

    char line[512 + 32];
    memset(line, 0, sizeof(line));

    RM_DEFINE_PATH(file);
    FILE *out = parent->out;

    switch(file->lint_type) {
    case RM_LINT_TYPE_DUPE_DIR_CANDIDATE:
    case RM_LINT_TYPE_DUPE_CANDIDATE:
        if(self->omit_first_line && file->is_original) {
            strcpy(line, "\n");
        } else {
            g_snprintf(line, sizeof(line), "%s%s%s%s%c", (file->is_original) ? "\n" : "",
                       (file->is_original) ? MAYBE_GREEN(out, session) : "", file_path,
                       (file->is_original) ? MAYBE_RESET(out, session) : "",
                       (self->use_same_line) ? ' ' : '\n');
        }
        break;
    default:
        g_snprintf(line, sizeof(line), "%s%s%s%c", MAYBE_BLUE(out, session), file_path,
                   MAYBE_RESET(out, session), (self->use_same_line) ? ' ' : '\n');
        break;
    }

    fputs(line, out);
}

static void rm_fmt_prog(RmSession *session,
                        _UNUSED RmFmtHandler *parent,
                        RmFmtProgressState state) {
    RmFmtHandlerFdupes *self = (RmFmtHandlerFdupes *)parent;

    if(state == RM_PROGRESS_STATE_INIT) {
        session->cfg->cache_file_structs = true;
        self->omit_first_line = (rm_fmt_get_config_value(session->cfg->formats, "fdupes",
                                                         "omitfirst") != NULL);
        self->use_same_line = (rm_fmt_get_config_value(session->cfg->formats, "fdupes",
                                                       "sameline") != NULL);
    }

    if(state == RM_PROGRESS_STATE_PRE_SHUTDOWN) {
        fprintf(parent->out, "\n");
    }
}

/* API hooks for RM_FMT_REGISTER in formats.c */

const char *FDUPES_HANDLER_NAME = "fdupes";

const char *FDUPES_HANDLER_VALID_KEYS[] = {"omitfirst", "sameline", NULL};

RmFmtHandler *FDUPES_HANDLER_NEW(_UNUSED RmFmtTable *table) {
    RmFmtHandlerFdupes *handler = g_new0(RmFmtHandlerFdupes, 1);
    /* Initialize parent */
    handler->parent.elem = rm_fmt_elem;
    handler->parent.prog = rm_fmt_prog;

    /* initialise any non-null handler-specific fields */

    return (RmFmtHandler *)handler;
};
