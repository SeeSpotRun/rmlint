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

#include "../formats.h"

#include <glib.h>
#include <search.h>
#include <stdio.h>
#include <string.h>

#include <sys/ioctl.h>

typedef struct RmFmtHandlerStats {
    /* must be first */
    RmFmtHandler parent;
} RmFmtHandlerStats;

static void rm_fmt_prog(RmSession *session,
                        _UNUSED RmFmtHandler *parent,
                        _UNUSED FILE *out,
                        RmFmtProgressState state) {
    if(state != RM_PROGRESS_STATE_SUMMARY) {
        return;
    }

    RmCounters *counters = session->counters;

    if((counters->duplicate_bytes == 0 && counters->shred_bytes_read == 0) ||
       session->cfg->replay_files.length > 0) {
        fprintf(out, _("No shred stats.\n"));
        return;
    }

    if(rm_session_was_aborted()) {
        /* Clear the whole terminal line.
         * Progressbar might leave some junk.
         */
        struct winsize terminal;
        ioctl(fileno(out), TIOCGWINSZ, &terminal);
        for(int i = 0; i < terminal.ws_col; ++i) {
            fprintf(out, " ");
        }

        fprintf(out, "\n");
    }

    char numbers[64];

    fprintf(out, _("%sDuplicate finding stats (includes hardlinks):%s\n"),
            MAYBE_BLUE(out, session), MAYBE_RESET(out, session));

    rm_util_size_to_human_readable(counters->original_bytes, numbers, sizeof(numbers));
    fprintf(out, _("%s%s%s bytes of originals\n"), MAYBE_RED(out, session), numbers,
            MAYBE_RESET(out, session));

    rm_util_size_to_human_readable(counters->duplicate_bytes, numbers, sizeof(numbers));
    fprintf(out, _("%s%s%s bytes of duplicates\n"), MAYBE_RED(out, session), numbers,
            MAYBE_RESET(out, session));

    rm_util_size_to_human_readable(counters->unique_bytes, numbers, sizeof(numbers));
    fprintf(out, _("%s%s%s bytes of non-duplicates\n"), MAYBE_RED(out, session), numbers,
            MAYBE_RESET(out, session));

    rm_util_size_to_human_readable(counters->shred_bytes_read, numbers, sizeof(numbers));
    fprintf(out, _("%s%s%s bytes of files data actually read\n"), MAYBE_RED(out, session),
            numbers, MAYBE_RESET(out, session));

    char eff_total[64] = "NaN";
    char eff_dupes[64] = "NaN";
    if(counters->shred_bytes_read != 0) {
        gfloat efficiency = 100 * (counters->duplicate_bytes + counters->original_bytes +
                                   counters->unique_bytes) /
                            counters->shred_bytes_read;
        snprintf(eff_total, sizeof(eff_total), "%.0f%%", efficiency);
        efficiency = 100 * (counters->duplicate_bytes + counters->original_bytes) /
                     counters->shred_bytes_read;
        snprintf(eff_dupes, sizeof(eff_dupes), "%.1f%%", efficiency);
    }

    fprintf(out, _("Algorithm efficiency %s%s%s on total files basis and %s%s%s on "
                   "duplicates basis)\n"),
            MAYBE_RED(out, session), eff_total, MAYBE_RESET(out, session),
            MAYBE_RED(out, session), eff_dupes, MAYBE_RESET(out, session));
}

static RmFmtHandlerStats STATS_HANDLER_IMPL = {
    /* Initialize parent */
    .parent =
        {
            .size = sizeof(STATS_HANDLER_IMPL),
            .name = "stats",
            .head = NULL,
            .elem = NULL,
            .prog = rm_fmt_prog,
            .foot = NULL,
            .valid_keys = {NULL},
        },
};

RmFmtHandler *STATS_HANDLER = (RmFmtHandler *)&STATS_HANDLER_IMPL;
