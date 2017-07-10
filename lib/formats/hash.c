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
#include "../utilities.h"

#include <glib.h>
#include <stdio.h>
#include <string.h>

typedef struct RmFmtHandlerHash {
    /* must be first */
    RmFmtHandler parent;
} RmFmtHandlerHash;

static void rm_fmt_head(RmSession *session, RmFmtHandler *parent) {
    if(rm_fmt_get_config_value("hash", "header")) {
        fprintf(parent->out, "%s    %s\n",
                rm_digest_type_to_string(session->cfg->checksum_type), "path");
    }
}

static void rm_fmt_elem(_UNUSED RmSession *session, _UNUSED RmFmtHandler *parent,
                        RmFile *file) {
    if(!file->digest) {
        /* unique file with no partial checksum */
        return;
    }

    char checksum_str[rm_digest_get_bytes(file->digest) * 2 + 1];
    memset(checksum_str, '0', sizeof(checksum_str));
    rm_digest_hexstring(file->digest, checksum_str);
    /* make sure we have a trailing null */
    checksum_str[sizeof(checksum_str) - 1] = 0;

    RM_DEFINE_PATH(file);

    fprintf(parent->out, "%s %s\n", checksum_str, file_path);
}

/* API hooks for RM_FMT_REGISTER in formats.c */

const char *HASH_HANDLER_NAME = "hash";

const char *HASH_HANDLER_VALID_KEYS[] = {"header", NULL};

RmFmtHandler *HASH_HANDLER_NEW(void) {
    RmFmtHandlerHash *handler = g_new0(RmFmtHandlerHash, 1);
    /* Initialize parent */
    handler->parent.head = rm_fmt_head;
    handler->parent.elem = rm_fmt_elem;

    /* initialise any non-null handler-specific fields */

    return (RmFmtHandler *)handler;
};
