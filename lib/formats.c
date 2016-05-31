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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "file.h"
#include "formats.h"

/* A group of output files.
 * These are only created when caching to the end of the run is requested.
 * Otherwise, files are directly outputed and not stored in groups.
 */
typedef struct RmFmtGroup {
    GQueue files;
    int index;
} RmFmtGroup;

static RmFmtGroup *rm_fmt_group_new(void) {
    RmFmtGroup *self = g_slice_new(RmFmtGroup);
    g_queue_init(&self->files);
    return self;
}

static void rm_fmt_group_destroy(RmFmtGroup *group) {
    g_queue_clear(&group->files);
    g_slice_free(RmFmtGroup, group);
}

static void rm_fmt_handler_free(RmFmtHandler *handler) {
    rm_assert_gentle(handler);

    g_free(handler->path);
    g_free(handler);
}

RmFmtTable *rm_fmt_open(RmSession *session) {
    RmFmtTable *self = g_slice_new0(RmFmtTable);

    self->name_to_handler = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

    self->path_to_handler = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

    /* Set of registered handler names */
    self->handler_set = g_hash_table_new(g_str_hash, g_str_equal);

    self->handler_to_file =
        g_hash_table_new_full(NULL, NULL, (GDestroyNotify)rm_fmt_handler_free, NULL);

    self->config = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
                                         (GDestroyNotify)g_hash_table_unref);

    self->session = session;
    g_queue_init(&self->groups);

    extern RmFmtHandler *PROGRESS_HANDLER;
    rm_fmt_register(self, PROGRESS_HANDLER);

    extern RmFmtHandler *CSV_HANDLER;
    rm_fmt_register(self, CSV_HANDLER);

    extern RmFmtHandler *PRETTY_HANDLER;
    rm_fmt_register(self, PRETTY_HANDLER);

    extern RmFmtHandler *SH_SCRIPT_HANDLER;
    rm_fmt_register(self, SH_SCRIPT_HANDLER);

    extern RmFmtHandler *SUMMARY_HANDLER;
    rm_fmt_register(self, SUMMARY_HANDLER);

    extern RmFmtHandler *STATS_HANDLER;
    rm_fmt_register(self, STATS_HANDLER);

    extern RmFmtHandler *TIMESTAMP_HANDLER;
    rm_fmt_register(self, TIMESTAMP_HANDLER);

    extern RmFmtHandler *JSON_HANDLER;
    rm_fmt_register(self, JSON_HANDLER);

    extern RmFmtHandler *PY_HANDLER;
    rm_fmt_register(self, PY_HANDLER);

    extern RmFmtHandler *FDUPES_HANDLER;
    rm_fmt_register(self, FDUPES_HANDLER);

    extern RmFmtHandler *UNIQUES_HANDLER;
    rm_fmt_register(self, UNIQUES_HANDLER);

    extern RmFmtHandler *NULL_HANDLER;
    rm_fmt_register(self, NULL_HANDLER);

    return self;
}

int rm_fmt_len(RmFmtTable *self) {
    if(self == NULL) {
        return -1;
    } else {
        return g_hash_table_size(self->handler_to_file);
    }
}

bool rm_fmt_is_valid_key(RmFmtTable *self, const char *formatter, const char *key) {
    RmFmtHandler *handler = g_hash_table_lookup(self->name_to_handler, formatter);
    if(handler == NULL) {
        return false;
    }

    for(int i = 0; handler->valid_keys[i]; ++i) {
        if(g_strcmp0(handler->valid_keys[i], key) == 0) {
            return true;
        }
    }

    return false;
}

void rm_fmt_clear(RmFmtTable *self) {
    if(rm_fmt_len(self) <= 0) {
        return;
    }

    g_hash_table_remove_all(self->handler_set);
    g_hash_table_remove_all(self->handler_to_file);
    g_hash_table_remove_all(self->path_to_handler);
    g_hash_table_remove_all(self->config);
}

void rm_fmt_register(RmFmtTable *self, RmFmtHandler *handler) {
    g_hash_table_insert(self->name_to_handler, (char *)handler->name, handler);
}

#define RM_FMT_FOR_EACH_HANDLER(self)                     \
    FILE *file = NULL;                                    \
    RmFmtHandler *handler = NULL;                         \
                                                          \
    GHashTableIter iter;                                  \
    g_hash_table_iter_init(&iter, self->handler_to_file); \
    while(g_hash_table_iter_next(&iter, (gpointer *)&handler, (gpointer *)&file))

#define RM_FMT_CALLBACK(func, ...)                           \
    if(func) {                                               \
        if(!handler->was_initialized && handler->head) {     \
            if(handler->head) {                              \
                handler->head(self->session, handler, file); \
            }                                                \
            handler->was_initialized = true;                 \
        }                                                    \
        func(self->session, handler, file, ##__VA_ARGS__);   \
    }

bool rm_fmt_add(RmFmtTable *self, const char *handler_name, const char *path) {
    RmFmtHandler *new_handler = g_hash_table_lookup(self->name_to_handler, handler_name);
    if(new_handler == NULL) {
        rm_log_warning_line(_("No such new_handler with this name: %s"), handler_name);
        return false;
    }

    g_return_val_if_fail(path, false);

    FILE *file_handle = NULL;
    bool needs_full_path = false;

    if(g_strcmp0(path, "stdout") == 0) {
        file_handle = stdout;
    } else if(g_strcmp0(path, "stderr") == 0) {
        file_handle = stderr;
    } else if(g_strcmp0(path, "stdin") == 0) {
        /* I bet someone finds a use for this :-) */
        file_handle = stdin;
    } else {
        needs_full_path = true;
        file_handle = fopen(path, "w");
    }

    if(file_handle == NULL) {
        rm_log_warning_line(_("Unable to open file for writing: %s"), path);
        return false;
    }

    /* Make a copy of the handler so we can more than one per handler type.
     * Plus we have to set the handler specific path.
     */
    RmFmtHandler *new_handler_copy = g_malloc0(new_handler->size);
    memcpy(new_handler_copy, new_handler, new_handler->size);

    if(needs_full_path == false) {
        new_handler_copy->path = g_strdup(path);
    } else {
        new_handler_copy->path = realpath(path, NULL);
    }

    g_hash_table_insert(self->handler_to_file, new_handler_copy, file_handle);
    g_hash_table_insert(self->path_to_handler, new_handler_copy->path, new_handler);
    g_hash_table_add(self->handler_set, (char *)new_handler_copy->name);

    return true;
}

static void rm_fmt_write_impl(RmFile *result, RmFmtTable *self) {
    RM_FMT_FOR_EACH_HANDLER(self) {
        RM_FMT_CALLBACK(handler->elem, result);
    }
}

static gint rm_fmt_rank_size(const RmFmtGroup *ga, const RmFmtGroup *gb) {
    RmFile *fa = ga->files.head->data;
    RmFile *fb = gb->files.head->data;

    RmOff sa = fa->file_size * (ga->files.length - 1);
    RmOff sb = fb->file_size * (gb->files.length - 1);

    /* Better do not compare big unsigneds via a - b... */
    if(sa < sb) {
        return -1;
    }

    if(sa > sb) {
        return +1;
    }

    return 0;
}

static gint rm_fmt_rank(const RmFmtGroup *ga, const RmFmtGroup *gb, RmFmtTable *self) {
    const char *rank_order = self->session->cfg->rank_criteria;

    RmFile *fa = ga->files.head->data;
    RmFile *fb = gb->files.head->data;

    if(fa->lint_type != RM_LINT_TYPE_DUPE_CANDIDATE &&
       fa->lint_type != RM_LINT_TYPE_DUPE_DIR_CANDIDATE) {
        return -1;
    }

    if(fb->lint_type != RM_LINT_TYPE_DUPE_CANDIDATE &&
       fb->lint_type != RM_LINT_TYPE_DUPE_DIR_CANDIDATE) {
        return +1;
    }

    for(int i = 0; rank_order[i]; ++i) {
        gint64 r = 0;
        switch(tolower((unsigned char)rank_order[i])) {
        case 's':
            r = rm_fmt_rank_size(ga, gb);
            break;
        case 'a':
            r = strcasecmp(fa->folder->basename, fb->folder->basename);
            break;
        case 'm':
            r = ((gint64)fa->mtime) - ((gint64)fb->mtime);
            break;
        case 'p':
            r = ((gint64)fa->path_index) - ((gint64)fb->path_index);
            break;
        case 'n':
            r = ((gint64)ga->files.length) - ((gint64)gb->files.length);
            break;
        case 'o':
            r = ga->index - gb->index;
            break;
        }

        if(r != 0) {
            r = CLAMP(r, -1, +1);
            return isupper((unsigned char)rank_order[i]) ? -r : r;
        }
    }

    return 0;
}

void rm_fmt_flush(RmFmtTable *self) {
    RmCfg *cfg = self->session->cfg;
    if(!cfg->cache_file_structs) {
        return;
    }

    if(*(cfg->rank_criteria)) {
        g_queue_sort(&self->groups, (GCompareDataFunc)rm_fmt_rank, self);
    }

    for(GList *iter = self->groups.head; iter; iter = iter->next) {
        RmFmtGroup *group = iter->data;
        g_queue_foreach(&group->files, (GFunc)rm_fmt_write_impl, self);
        g_queue_foreach(&group->files, (GFunc)rm_file_destroy, NULL);
    }
}

void rm_fmt_close(RmFmtTable *self) {
    for(GList *iter = self->groups.head; iter; iter = iter->next) {
        RmFmtGroup *group = iter->data;
        rm_fmt_group_destroy(group);
    }

    g_queue_clear(&self->groups);

    RM_FMT_FOR_EACH_HANDLER(self) {
        RM_FMT_CALLBACK(handler->foot);
        fclose(file);
    }

    g_hash_table_unref(self->name_to_handler);
    g_hash_table_unref(self->handler_to_file);
    g_hash_table_unref(self->path_to_handler);
    g_hash_table_unref(self->config);
    g_hash_table_unref(self->handler_set);
    g_slice_free(RmFmtTable, self);
}

void rm_fmt_write(RmFile *result, RmFmtTable *self, gint64 twin_count) {
    bool direct = !(self->session->cfg->cache_file_structs);

    result->twin_count = twin_count;

    if(direct) {
        rm_fmt_write_impl(result, self);
    } else {
        if(result->is_original || self->groups.length == 0) {
            g_queue_push_tail(&self->groups, rm_fmt_group_new());
        }

        RmFmtGroup *group = self->groups.tail->data;
        group->index = self->groups.length - 1;

        g_queue_push_tail(&group->files, result);
    }
}

void rm_fmt_set_state(RmFmtTable *self, RmFmtProgressState state) {
    RM_FMT_FOR_EACH_HANDLER(self) {
        RM_FMT_CALLBACK(handler->prog, state);
    }
}

void rm_fmt_set_config_value(RmFmtTable *self, const char *formatter, const char *key,
                             const char *value) {
    GHashTable *key_to_vals = g_hash_table_lookup(self->config, formatter);

    if(key_to_vals == NULL) {
        key_to_vals = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        g_hash_table_insert(self->config, (char *)g_strdup(formatter), key_to_vals);
    }
    g_hash_table_insert(key_to_vals, (char *)key, (char *)value);
}

const char *rm_fmt_get_config_value(RmFmtTable *self, const char *formatter,
                                    const char *key) {
    GHashTable *key_to_vals = g_hash_table_lookup(self->config, formatter);

    if(key_to_vals == NULL) {
        return NULL;
    }

    return g_hash_table_lookup(key_to_vals, key);
}

bool rm_fmt_is_a_output(RmFmtTable *self, const char *path) {
    return g_hash_table_contains(self->path_to_handler, path);
}

void rm_fmt_get_pair_iter(RmFmtTable *self, GHashTableIter *iter) {
    g_hash_table_iter_init(iter, self->path_to_handler);
}

bool rm_fmt_has_formatter(RmFmtTable *self, const char *name) {
    GHashTableIter iter;
    char *handler_name = NULL;

    g_hash_table_iter_init(&iter, self->handler_set);

    while(g_hash_table_iter_next(&iter, (gpointer *)&handler_name, NULL)) {
        if(!g_strcmp0(handler_name, name)) {
            return true;
        }
    }

    return false;
}

bool rm_fmt_is_stream(_UNUSED RmFmtTable *self, RmFmtHandler *handler) {
    if(0 || handler->path == NULL || strcmp(handler->path, "stdout") == 0 ||
       strcmp(handler->path, "stderr") == 0 || strcmp(handler->path, "stdin") == 0) {
        return true;
    }

    return (access(handler->path, W_OK) == -1);
}
