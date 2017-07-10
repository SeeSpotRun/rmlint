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
#include <search.h>
#include <stdio.h>
#include <string.h>

#include <sys/ioctl.h>

typedef struct RmFmtHandlerSummary {
    /* must be first */
    RmFmtHandler parent;
    gboolean first_print_flag;
    RmSession *session;  // temporary hack; TODO: better way
} RmFmtHandlerSummary;

#define ARROW \
    fprintf(out, "%s==>%s ", MAYBE_YELLOW(out, session), MAYBE_RESET(out, session));

static void list_handlers(RmFmtHandler *handler, RmFmtHandlerSummary *self) {
    static const gchar *const forbidden[] = {"stdout", "stderr", "stdin", NULL};

    if(rm_util_strv_contains((const gchar *const *)&forbidden, handler->path)) {
        return;
    }

    /* Check if the file really exists, so we can print it for sure */
    if(access(handler->path, R_OK) == -1) {
        return;
    }

    FILE *out = self->parent.out;

    if(self->first_print_flag) {
        fprintf(out, "\n");
        self->first_print_flag = false;
    }

    fprintf(out, _("Wrote a %s%s%s file to: %s%s%s\n"), MAYBE_BLUE(out, self->session),
            handler->name, MAYBE_RESET(out, self->session),
            MAYBE_GREEN(out, self->session), handler->path,
            MAYBE_RESET(out, self->session));
}

static void rm_fmt_prog(RmSession *session,
                        RmFmtHandler *parent,
                        RmFmtProgressState state) {
    FILE *out = parent->out;
    RmFmtHandlerSummary *self = (RmFmtHandlerSummary *)parent;

    if(state != RM_PROGRESS_STATE_SUMMARY) {
        return;
    }

    if(rm_counter_get(RM_COUNTER_TOTAL_FILES) <= 1) {
        ARROW fprintf(out, "%s%" RM_COUNTER_FORMAT "%s", MAYBE_RED(out, session),
                      rm_counter_get(RM_COUNTER_TOTAL_FILES), MAYBE_RESET(out, session));
        fprintf(out, _(" file(s) after investigation, nothing to search through.\n"));
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
        ARROW fprintf(out, _("Early shutdown, probably not all lint was found.\n"));
    }

    if(rm_fmt_has_formatter("pretty") && rm_fmt_has_formatter("sh")) {
        ARROW fprintf(out, _("Note: Please use the saved script below for removal, not "
                             "the above output."));
        fprintf(out, "\n");
    }

    char numbers[3][512];
    snprintf(numbers[0], sizeof(numbers[0]), "%s%" RM_COUNTER_FORMAT "%s",
             MAYBE_RED(out, session), rm_counter_get(RM_COUNTER_TOTAL_FILES),
             MAYBE_RESET(out, session));
    snprintf(numbers[1], sizeof(numbers[1]), "%s%" RM_COUNTER_FORMAT "%s",
             MAYBE_RED(out, session), rm_counter_get(RM_COUNTER_DUP_COUNTER),
             MAYBE_RESET(out, session));
    snprintf(numbers[2], sizeof(numbers[2]), "%s%" LLU "%s", MAYBE_RED(out, session),
             rm_counter_get(RM_COUNTER_DUP_GROUP_COUNTER), MAYBE_RESET(out, session));

    ARROW fprintf(out, _("In total %s files, whereof %s are duplicates in %s groups.\n"),
                  numbers[0], numbers[1], numbers[2]);

    /* log10(2 ** 64) + 2 = 21; */
    char size_string_buf[22] = {0};
    rm_util_size_to_human_readable(rm_counter_get(RM_COUNTER_TOTAL_LINT_SIZE),
                                   size_string_buf, sizeof(size_string_buf));

    ARROW fprintf(out, _("This equals %s%s%s of duplicates which could be removed.\n"),
                  MAYBE_RED(out, session), size_string_buf, MAYBE_RESET(out, session));

    if(rm_counter_get(RM_COUNTER_OTHER_LINT_CNT) > 0) {
        ARROW fprintf(out, "%s%" LLU "%s ", MAYBE_RED(out, session),
                      rm_counter_get(RM_COUNTER_OTHER_LINT_CNT),
                      MAYBE_RESET(out, session));

        fprintf(out, _("other suspicious item(s) found, which may vary in size.\n"));
    }

    char *elapsed_time = rm_format_elapsed_time(rm_counter_elapsed_time(), 3);
    ARROW fprintf(out, _("Scanning took in total %s%s%s. Is that good enough?\n"),
                  MAYBE_RED(out, session), elapsed_time, MAYBE_RESET(out, session));
    g_free(elapsed_time);

    self->first_print_flag = true;
    self->session = session;
    rm_fmt_foreach((GFunc)list_handlers, self);
}

/* API hooks for RM_FMT_REGISTER in formats.c */

const char *SUMMARY_HANDLER_NAME = "summary";

const char *SUMMARY_HANDLER_VALID_KEYS[] = {NULL};

RmFmtHandler *SUMMARY_HANDLER_NEW(void) {
    RmFmtHandlerSummary *handler = g_new0(RmFmtHandlerSummary, 1);
    /* Initialize parent */
    handler->parent.prog = rm_fmt_prog;

    /* initialise any non-null handler-specific fields */
    handler->first_print_flag = true;

    return (RmFmtHandler *)handler;
};
