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

#ifndef RM_OUTPUTS_H
#define RM_OUTPUTS_H

#include <glib.h>
#include <stdbool.h>
#include <stdio.h>

#include "counters.h"
#include "file.h"
#include "session.h"

////////////////////
//  PUBLIC TYPES  //
////////////////////

/* Current state of rmlint */
typedef enum RmFmtProgressState {
    RM_PROGRESS_STATE_INIT,
    RM_PROGRESS_STATE_TRAVERSE,
    RM_PROGRESS_STATE_PREPROCESS,
    RM_PROGRESS_STATE_SHREDDER,
    RM_PROGRESS_STATE_MERGE,
    RM_PROGRESS_STATE_PRE_SHUTDOWN,
    RM_PROGRESS_STATE_SUMMARY,
    RM_PROGRESS_STATE_N
} RmFmtProgressState;

/* Opaque container for a set of RmFmtHandlers */
typedef struct _RmFmtTable RmFmtTable;

/* Callback definitions */
struct RmFmtHandler;

typedef void (*RmFmtHeadCallback)(RmSession *session, struct RmFmtHandler *self);
typedef void (*RmFmtFootCallback)(RmSession *session, struct RmFmtHandler *self);
typedef void (*RmFmtElemCallback)(RmSession *session, struct RmFmtHandler *self,
                                  RmFile *file);
typedef void (*RmFmtProgCallback)(RmSession *session, struct RmFmtHandler *self,
                                  RmFmtProgressState state);

/* Parent "class" for output handlers */
typedef struct RmFmtHandler {
    /* Name of the Handler */
    char *name;

    /* Path to which the Handler is pointed */
    char *path;

    /* False at beginning, is set to true once
     * the head() callback was called, i.e. on the
     * first write(). Used for lazy init.
     */
    bool was_initialized;

    /* Set to true (prior to calling head) if
     * the file of this handler already existed
     * on disk. */
    bool file_existed_already;

    /* Callbacks, might be NULL */
    RmFmtHeadCallback head;
    RmFmtElemCallback elem;
    RmFmtProgCallback prog;
    RmFmtFootCallback foot;

    /* mutex to protect against parallel calls.
     * Handlers do not need to care about it.
     */
    GMutex print_mtx;

    /* The output file */
    FILE *out;
} RmFmtHandler;

typedef RmFmtHandler *(RmFmtHandlerNew)(RmFmtTable *table);

////////////////////
//   PUBLIC API   //
////////////////////

/**
 * @brief Allocate a new RmFmtTable.
 *
 * The table can be used to multiplex a finished RmFile to several output files
 * with different formats for each.
 *
 * @return A newly allocated RmFmtTable.
 */
RmFmtTable *rm_fmt_open(RmSession *session);

/**
 * @brief Close all open file, but write a footer to them if the handler wants it.
 */
void rm_fmt_close(RmFmtTable *self);

/**
 * @brief If cfg->cache_file_structs is true,
 *        all files written by rm_fmt_write can
 *        be flushed at once with this function.
 *
 * @param self
 */
void rm_fmt_flush(RmFmtTable *self);

/**
 * @brief Get the number of added formatters.
 *
 * @param self The table.
 *
 * @return -1 or error, number on success
 */
int rm_fmt_len(RmFmtTable *self);

/**
 * @brief Clear all previously added formatters.
 *
 * @param self table to clear.
 */
void rm_fmt_clear(RmFmtTable *self);

/**
 * @brief Register a new handle to the table.
 *
 * This is only interesting to add new Handlers for new formats.
 */
void rm_fmt_register(RmFmtTable *self, RmFmtHandler *handler);

/**
 * @brief Register a new handler that handles writing to path when getting input.
 */
bool rm_fmt_add(RmFmtTable *self, const char *handler_name, const char *path);

/**
 * @brief Make all handlers write a ouput line to their respective file.
 *
 * The actual content of the line (or even lines) is subject to the
 * implementation of the handler - it might also do just nothing.
 * @note argument order is to enable calling via g_queue_foreach()
 */
void rm_fmt_write(RmFile *result, RmFmtTable *self, gint64 twin_count);

/**
 * @brief Change the state of rmlint.
 *
 * Some handlers might require this in order to print a progress indicator.
 * Calling the same state several times is allowed in order to update numbers
 *
 * Callers should make sure that this function is not called on every increment,
 * as it needs to iterate over all handlers:
 */
void rm_fmt_set_state(RmFmtTable *self, RmFmtProgressState state);

/**
 * @brief Convert state to a human readable string. Static storage, do not free.
 */
const char *rm_fmt_progress_to_string(RmFmtProgressState state);

/**
 * @brief Set a configuration value. Overwrites previously set.
 *
 * @param formatter Name of the formatter to configure.
 * @param key The key to set.
 * @param value The value to set.
 */
void rm_fmt_set_config_value(RmFmtTable *self, const char *formatter, const char *key,
                             const char *value);

/**
 * @brief Get a configuration value.
 *
 * @return NULL if not foumd, the value for this key. Memory owned by RmFmtTable.
 */
const char *rm_fmt_get_config_value(RmFmtTable *self, const char *formatter,
                                    const char *key);

/**
 * @brief Check if the formatter "formatter" has a config value called key.
 *
 * @return true if yes, false otherwise.
 */
bool rm_fmt_is_valid_key(const char *formatter, const char *key);

/**
 * @brief Check if path is a set output of RmFmtTable.
 *
 * @return true if it is.
 */
bool rm_fmt_is_a_output(RmFmtTable *self, const char *path);

/**
 * @brief Lock the state mutex.
 *
 * Use this to threadsafely update statistic counters.
 */
void rm_fmt_lock_state(RmFmtTable *self);

/**
 * @brief Pendant to rm_fmt_lock_state()
 */
void rm_fmt_unlock_state(RmFmtTable *self);

/**
 * @brief Check if a certain handler is writting to a stream.
 */
bool rm_fmt_is_stream(RmFmtTable *self, RmFmtHandler *handler);

/**
 * @brief Check if there is at least one formatter with `name`.
 */
bool rm_fmt_has_formatter(RmFmtTable *self, const char *name);

void rm_fmt_foreach_handler(RmFmtTable *self, GFunc func, gpointer user_data);

/**
 * You can use this template for implementing new RmFmtHandlers.
 * Remember to register the handler in rm_fmt_open().
 * Note: all callbacks are not required to be implemented, delete them
 * from FOO_HANDLER_NEW() if you do not implement them.

typedef struct RmFmtHandlerFoo {
    // must be first:
    RmFmtHandler parent;

    // handler-specific fields
    RmFmtProgressState last_state;
} RmFmtHandlerFoo;

static void rm_fmt_head(RmSession *session, RmFmtHandler *parent) {
    fprint(parent->file, "Header\n");
}

static void rm_fmt_elem(RmSession *session, RmFmtHandler *parent, RmFile *file){
    fprintf(parent->file, "File: %s\n", file->basename);
}

static void rm_fmt_prog(RmSession *session, RmFmtHandler *parent,
RmFmtProgressState state) {
    RmFmtHandlerFoo *self = (RmFmtHandlerFoo*) parent;
    if(state != self->last_state) {
        char *state_name = rm_fmt_progress_to_string(state);
        fprintf(parent->file, "Progress state: %s\n", state_name);
        g_free(state_name);
    }
}

static void rm_fmt_foot(RmSession *session, RmFmtHandler *parent) {
    fprint(parent->file, "Footer\n");
}

// API hooks for RM_FMT_REGISTER in formats.c:

const char *FOO_HANDLER_NAME = "foo";

const char *FOO_HANDLER_VALID_KEYS[] = {"bar", "baz", NULL};

RmFmtHandler *FOO_HANDLER_NEW(void) {
    RmFmtHandlerFoo *handler = g_new0(RmFmtHandlerFoo, 1);
    // Initialize parent
    handler->parent.head = rm_fmt_head;
    handler->parent.elem = rm_fmt_elem;
    handler->parent.prog = rm_fmt_prog;
    handler->parent.foot = rm_fmt_foot;

    // initialise any non-null handler-specific fields
    handler->last_state = RM_PROGRESS_STATE_INIT;

    return (RmFmtHandler *) handler;
};

*/

#endif /* end of include guard */
