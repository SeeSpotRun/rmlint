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
#include <math.h>
#include <string.h>

#include <glib/gstdio.h>
#include <search.h>

#include "formats.h"

typedef struct RmCmdSession {
    RmCfg *cfg;

    /* count used for determining the paranoia level */
    int paranoia_count;

    /* count for -o and -O; initialized to -1 */
    int output_cnt[2];

    /* true if a cmdline parse error happened */
    bool cmdline_parse_error;

    /* Output formatting control */
    struct RmFmtTable *formats;
} RmCmdSession;

static void rm_cmd_show_version(void) {
    fprintf(stderr, "version %s compiled: %s at [%s] \"%s\" (rev %s)\n", RM_VERSION,
            __DATE__, __TIME__, RM_VERSION_NAME, RM_VERSION_GIT_REVISION);

    /* Make a list of all supported features from the macros in config.h */
    /* clang-format off */
    struct {
        bool enabled : 1;
        const char *name;
    } features[] = {{.name = "mounts",         .enabled = HAVE_BLKID & HAVE_GIO_UNIX},
                    {.name = "nonstripped",    .enabled = HAVE_LIBELF},
                    {.name = "fiemap",         .enabled = HAVE_FIEMAP},
                    {.name = "sha512",         .enabled = HAVE_SHA512},
                    {.name = "bigfiles",       .enabled = HAVE_BIGFILES},
                    {.name = "intl",           .enabled = HAVE_LIBINTL},
                    {.name = "replay",         .enabled = HAVE_JSON_GLIB},
                    {.name = "xattr",          .enabled = HAVE_XATTR},
                    {.name = "btrfs-support",  .enabled = HAVE_BTRFS_H},
                    {.name = NULL,             .enabled = 0}};
    /* clang-format on */

    fprintf(stderr, _("compiled with:"));
    for(int i = 0; features[i].name; ++i) {
        fprintf(stderr, " %c%s", (features[i].enabled) ? '+' : '-', features[i].name);
    }

    fprintf(stderr, RESET "\n\n");
    fprintf(stderr, _("rmlint was written by Christopher <sahib> Pahl and Daniel "
                      "<SeeSpotRun> Thomas."));
    fprintf(stderr, "\n");
    fprintf(stderr, _("The code at https://github.com/sahib/rmlint is licensed under the "
                      "terms of the GPLv3."));
    fprintf(stderr, "\n");
    exit(0);
}

static void rm_cmd_show_manpage(void) {
    static const char *commands[] = {"man %s docs/rmlint.1.gz 2> /dev/null",
                                     "man %s rmlint", NULL};

    bool found_manpage = false;

    for(int i = 0; commands[i] && !found_manpage; ++i) {
        char cmd_buf[512] = {0};
        if(snprintf(cmd_buf, sizeof(cmd_buf), commands[i],
                    (RM_MANPAGE_USE_PAGER) ? "" : "-P cat") == -1) {
            continue;
        }

        if(system(cmd_buf) == 0) {
            found_manpage = true;
        }
    }

    if(!found_manpage) {
        rm_log_warning_line(_("You seem to have no manpage for rmlint."));
    }

    exit(0);
}

/* clang-format off */
static const struct FormatSpec {
    const char *id;
    unsigned base;
    unsigned exponent;
} SIZE_FORMAT_TABLE[] = {
    /* This list is sorted, so bsearch() can be used */
    {.id = "b",  .base = 512,  .exponent = 1},
    {.id = "c",  .base = 1,    .exponent = 1},
    {.id = "e",  .base = 1000, .exponent = 6},
    {.id = "eb", .base = 1024, .exponent = 6},
    {.id = "g",  .base = 1000, .exponent = 3},
    {.id = "gb", .base = 1024, .exponent = 3},
    {.id = "k",  .base = 1000, .exponent = 1},
    {.id = "kb", .base = 1024, .exponent = 1},
    {.id = "m",  .base = 1000, .exponent = 2},
    {.id = "mb", .base = 1024, .exponent = 2},
    {.id = "p",  .base = 1000, .exponent = 5},
    {.id = "pb", .base = 1024, .exponent = 5},
    {.id = "t",  .base = 1000, .exponent = 4},
    {.id = "tb", .base = 1024, .exponent = 4},
    {.id = "w",  .base = 2,    .exponent = 1}
};
/* clang-format on */

typedef struct FormatSpec FormatSpec;

static const int SIZE_FORMAT_TABLE_N = sizeof(SIZE_FORMAT_TABLE) / sizeof(FormatSpec);

static int rm_cmd_compare_spec_elem(const void *fmt_a, const void *fmt_b) {
    return strcasecmp(((FormatSpec *)fmt_a)->id, ((FormatSpec *)fmt_b)->id);
}

static RmOff rm_cmd_size_string_to_bytes(const char *size_spec, GError **error) {
    if(size_spec == NULL) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Input size is empty"));
        return 0;
    }

    char *format = NULL;
    long double decimal = strtold(size_spec, &format);

    if(decimal == 0 && format == size_spec) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("This does not look like a number"));
        return 0;
    } else if(decimal < 0) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Negativ sizes are no good idea"));
        return 0;
    } else if(*format) {
        format = g_strstrip(format);
    } else {
        return round(decimal);
    }

    FormatSpec key = {.id = format};
    FormatSpec *found = bsearch(&key, SIZE_FORMAT_TABLE, SIZE_FORMAT_TABLE_N,
                                sizeof(FormatSpec), rm_cmd_compare_spec_elem);

    if(found != NULL) {
        /* No overflow check */
        return decimal * pow(found->base, found->exponent);
    } else {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Given format specifier not found"));
        return 0;
    }
}

/* Size spec parsing implemented by qitta (http://github.com/qitta)
 * Thanks and go blame him if this breaks!
 */
static gboolean rm_cmd_size_range_string_to_bytes(const char *range_spec, RmOff *min,
                                                  RmOff *max, GError **error) {
    *min = 0;
    *max = G_MAXULONG;

    range_spec = (const char *)g_strstrip((char *)range_spec);
    gchar **split = g_strsplit(range_spec, "-", 2);

    if(*range_spec == '-') {
        /* Act like it was "0-..." */
        split[0] = g_strdup("0");
    }

    if(split[0] != NULL) {
        *min = rm_cmd_size_string_to_bytes(split[0], error);
    }

    if(split[1] != NULL && *error == NULL) {
        *max = rm_cmd_size_string_to_bytes(split[1], error);
    }

    g_strfreev(split);

    if(*error == NULL && *max < *min) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Max is smaller than min"));
    }

    return (*error == NULL);
}

static gboolean rm_cmd_parse_limit_sizes(_UNUSED const char *option_name,
                                         const gchar *range_spec,
                                         RmCmdSession *cmd,
                                         GError **error) {
    if(!rm_cmd_size_range_string_to_bytes(range_spec, &cmd->cfg->minsize,
                                          &cmd->cfg->maxsize, error)) {
        g_prefix_error(error, _("cannot parse --size: "));
        return false;
    } else {
        cmd->cfg->limits_specified = true;
        return true;
    }
}

static bool rm_cmd_add_path(RmCfg *cfg, int index, const char *path) {
    int rc = 0;

#if HAVE_FACCESSAT
    rc = faccessat(AT_FDCWD, path, R_OK, AT_EACCESS);
#else
    rc = access(path, R_OK);
#endif

    if(rc != 0) {
        rm_log_warning_line(_("Can't open directory or file \"%s\": %s"), path,
                            strerror(errno));
        return FALSE;
    } else {
        cfg->paths = g_realloc(cfg->paths, sizeof(char *) * (index + 2));

        char *abs_path = NULL;
        if(strncmp(path, "//", 2) == 0) {
            abs_path = g_strdup(path);
        } else {
            abs_path = realpath(path, NULL);
        }

        cfg->paths[index] = abs_path ? abs_path : g_strdup(path);
        cfg->paths[index + 1] = NULL;
        return TRUE;
    }
}

static int rm_cmd_read_paths_from_stdin(RmCfg *cfg, int index) {
    int paths_added = 0;
    char path_buf[PATH_MAX];
    char *tokbuf = NULL;

    while(fgets(path_buf, PATH_MAX, stdin)) {
        paths_added +=
            rm_cmd_add_path(cfg, index + paths_added, strtok_r(path_buf, "\n", &tokbuf));
    }

    return paths_added;
}

static bool rm_cmd_parse_output_pair(RmCmdSession *cmd, const char *pair,
                                     GError **error) {
    rm_assert_gentle(cmd);
    rm_assert_gentle(pair);

    char *separator = strchr(pair, ':');
    char *full_path = NULL;
    char format_name[100];
    memset(format_name, 0, sizeof(format_name));

    if(separator == NULL) {
        /* default to stdout */
        char *extension = strchr(pair, '.');
        if(extension == NULL) {
            full_path = "stdout";
            strncpy(format_name, pair, strlen(pair));
        } else {
            extension += 1;
            full_path = (char *)pair;
            strncpy(format_name, extension, strlen(extension));
        }
    } else {
        full_path = separator + 1;
        strncpy(format_name, pair, MIN((long)sizeof(format_name), separator - pair));
    }

    if(!rm_fmt_add(cmd->formats, format_name, full_path)) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Adding -o %s as output failed"), pair);
        return false;
    }

    return true;
}

static bool rm_cmd_parse_config_pair(RmCmdSession *cmd, const char *pair,
                                     GError **error) {
    char *domain = strchr(pair, ':');
    if(domain == NULL) {
        g_set_error(error, RM_ERROR_QUARK, 0,
                    _("No format (format:key[=val]) specified in '%s'"), pair);
        return false;
    }

    char *key = NULL, *value = NULL;
    char **key_val = g_strsplit(&domain[1], "=", 2);
    int len = g_strv_length(key_val);
    bool result = true;

    if(len < 1) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Missing key (format:key[=val]) in '%s'"),
                    pair);
        g_strfreev(key_val);
        return false;
    }

    key = g_strdup(key_val[0]);
    if(len == 2) {
        value = g_strdup(key_val[1]);
    } else {
        value = g_strdup("1");
    }

    char *formatter = g_strndup(pair, domain - pair);
    if(!rm_fmt_is_valid_key(cmd->formats, formatter, key)) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Invalid key `%s' for formatter `%s'"),
                    key, formatter);
        g_free(key);
        g_free(value);
        result = false;
    } else {
        rm_fmt_set_config_value(cmd->formats, formatter, key, value);
    }

    g_free(formatter);
    g_strfreev(key_val);
    return result;
}

static gboolean rm_cmd_parse_config(_UNUSED const char *option_name,
                                    const char *pair,
                                    RmCmdSession *cmd,
                                    _UNUSED GError **error) {
    return rm_cmd_parse_config_pair(cmd, pair, error);
}

static double rm_cmd_parse_clamp_factor(const char *string, GError **error) {
    char *error_loc = NULL;
    gdouble factor = g_strtod(string, &error_loc);

    if(error_loc != NULL && *error_loc != '\0' && *error_loc != '%') {
        g_set_error(error, RM_ERROR_QUARK, 0,
                    _("Unable to parse factor \"%s\": error begins at %s"), string,
                    error_loc);
        return 0;
    }

    if(error_loc != NULL && *error_loc == '%') {
        factor /= 100;
    }

    if(0 > factor || factor > 1) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("factor value is not in range [0-1]: %f"),
                    factor);
        return 0;
    }

    return factor;
}

static RmOff rm_cmd_parse_clamp_offset(const char *string, GError **error) {
    RmOff offset = rm_cmd_size_string_to_bytes(string, error);

    if(*error != NULL) {
        g_prefix_error(error, _("Unable to parse offset \"%s\": "), string);
        return 0;
    }

    return offset;
}

static void rm_cmd_parse_clamp_option(RmCmdSession *cmd, const char *string,
                                      bool start_or_end, GError **error) {
    if(strchr(string, '.') || g_str_has_suffix(string, "%")) {
        gdouble factor = rm_cmd_parse_clamp_factor(string, error);
        if(start_or_end) {
            cmd->cfg->use_absolute_start_offset = false;
            cmd->cfg->skip_start_factor = factor;
        } else {
            cmd->cfg->use_absolute_end_offset = false;
            cmd->cfg->skip_end_factor = factor;
        }
    } else {
        RmOff offset = rm_cmd_parse_clamp_offset(string, error);
        if(start_or_end) {
            cmd->cfg->use_absolute_start_offset = true;
            cmd->cfg->skip_start_offset = offset;
        } else {
            cmd->cfg->use_absolute_end_offset = true;
            cmd->cfg->skip_end_offset = offset;
        }
    }
}

/* parse comma-separated strong of lint types and set cfg accordingly */
typedef struct RmLintTypeOption {
    const char **names;
    gboolean **enable;
} RmLintTypeOption;

/* compare function for parsing lint type arguments */
int rm_cmd_find_line_type_func(const void *v_input, const void *v_option) {
    const char *input = v_input;
    const RmLintTypeOption *option = v_option;

    for(int i = 0; option->names[i]; ++i) {
        if(strcmp(option->names[i], input) == 0) {
            return 0;
        }
    }
    return 1;
}

#define OPTS (gboolean *[])
#define NAMES (const char *[])

static char rm_cmd_find_lint_types_sep(const char *lint_string) {
    if(*lint_string == '+' || *lint_string == '-') {
        lint_string++;
    }

    while(isalpha((unsigned char)*lint_string)) {
        lint_string++;
    }

    return *lint_string;
}

static gboolean rm_cmd_parse_lint_types(_UNUSED const char *option_name,
                                        const char *lint_string,
                                        RmCmdSession *cmd,
                                        _UNUSED GError **error) {
    RmCfg *cfg = cmd->cfg;
    RmLintTypeOption option_table[] = {
        {.names = NAMES{"all", 0},
         .enable = OPTS{&cfg->find_badids, &cfg->find_badlinks, &cfg->find_emptydirs,
                        &cfg->find_emptyfiles, &cfg->find_nonstripped,
                        &cfg->find_duplicates, &cfg->merge_directories, 0}},
        {
            .names = NAMES{"minimal", 0},
            .enable =
                OPTS{&cfg->find_badids, &cfg->find_badlinks, &cfg->find_duplicates, 0},
        },
        {
            .names = NAMES{"minimaldirs", 0},
            .enable =
                OPTS{&cfg->find_badids, &cfg->find_badlinks, &cfg->merge_directories, 0},
        },
        {
            .names = NAMES{"defaults", 0},
            .enable = OPTS{&cfg->find_badids, &cfg->find_badlinks, &cfg->find_emptydirs,
                           &cfg->find_emptyfiles, &cfg->find_duplicates, 0},
        },
        {
            .names = NAMES{"none", 0}, .enable = OPTS{0},
        },
        {.names = NAMES{"badids", "bi", 0}, .enable = OPTS{&cfg->find_badids, 0}},
        {.names = NAMES{"badlinks", "bl", 0}, .enable = OPTS{&cfg->find_badlinks, 0}},
        {.names = NAMES{"emptydirs", "ed", 0}, .enable = OPTS{&cfg->find_emptydirs, 0}},
        {.names = NAMES{"emptyfiles", "ef", 0}, .enable = OPTS{&cfg->find_emptyfiles, 0}},
        {.names = NAMES{"nonstripped", "ns", 0},
         .enable = OPTS{&cfg->find_nonstripped, 0}},
        {.names = NAMES{"duplicates", "df", "dupes", 0},
         .enable = OPTS{&cfg->find_duplicates, 0}},
        {.names = NAMES{"duplicatedirs", "dd", "dupedirs", 0},
         .enable = OPTS{&cfg->merge_directories, 0}}};

    RmLintTypeOption *all_opts = &option_table[0];

    /* initialize all options to disabled by default */
    for(int i = 0; all_opts->enable[i]; i++) {
        *all_opts->enable[i] = false;
    }

    /* split the comma-separates list of options */
    char lint_sep[2] = {0, 0};
    lint_sep[0] = rm_cmd_find_lint_types_sep(lint_string);
    if(lint_sep[0] == 0) {
        lint_sep[0] = ',';
    }

    char **lint_types = g_strsplit(lint_string, lint_sep, -1);

    /* iterate over the separated option strings */
    for(int index = 0; lint_types[index]; index++) {
        char *lint_type = lint_types[index];
        int sign = 0;

        if(*lint_type == '+') {
            sign = +1;
        } else if(*lint_type == '-') {
            sign = -1;
        }

        if(sign == 0) {
            sign = +1;
        } else {
            /* get rid of prefix. */
            lint_type += ABS(sign);
        }

        /* use lfind to find matching option from array */
        size_t elems = sizeof(option_table) / sizeof(RmLintTypeOption);
        RmLintTypeOption *option =
            lfind(lint_type, &option_table, &elems, sizeof(RmLintTypeOption),
                  rm_cmd_find_line_type_func);

        /* apply the found option */
        if(option == NULL) {
            rm_log_warning(_("lint type '%s' not recognised"), lint_type);
            continue;
        }

        /* enable options as appropriate */
        for(int i = 0; option->enable[i]; i++) {
            *option->enable[i] = (sign == -1) ? false : true;
        }
    }

    /* clean up */
    g_strfreev(lint_types);
    return true;
}

static bool rm_cmd_timestamp_is_plain(const char *stamp) {
    return strchr(stamp, 'T') ? false : true;
}

static gboolean rm_cmd_parse_timestamp(_UNUSED const char *option_name,
                                       const gchar *string, RmCmdSession *cmd,
                                       GError **error) {
    time_t result = 0;
    bool plain = rm_cmd_timestamp_is_plain(string);
    cmd->cfg->filter_mtime = false;

    if(plain) {
        /* A simple integer is expected, just parse it as time_t */
        result = strtoll(string, NULL, 10);
    } else {
        /* Parse ISO8601 timestamps like 2006-02-03T16:45:09.000Z */
        result = rm_iso8601_parse(string);

        /* debug */
        {
            char time_buf[256];
            memset(time_buf, 0, sizeof(time_buf));
            rm_iso8601_format(time(NULL), time_buf, sizeof(time_buf));
            rm_log_debug_line("timestamp %s understood as %lu", time_buf, result);
        }
    }

    if(result <= 0) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Unable to parse time spec \"%s\""),
                    string);
        return false;
    }

    /* Some sort of success. */
    cmd->cfg->filter_mtime = true;

    time_t now = time(NULL);
    if(result > now) {
        /* Not critical, maybe there are some uses for this,
         * but print at least a small warning as indication.
         * */
        if(plain) {
            rm_log_warning_line(_("-n %lu is newer than current time (%lu)."),
                                (long)result, (long)now);
        } else {
            char time_buf[256];
            memset(time_buf, 0, sizeof(time_buf));
            rm_iso8601_format(time(NULL), time_buf, sizeof(time_buf));

            rm_log_warning_line("-N %s is newer than current time (%s) [%lu > %lu]",
                                string, time_buf, result, now);
        }
    }

    /* Remember our result */
    cmd->cfg->min_mtime = result;
    return true;
}

static gboolean rm_cmd_parse_timestamp_file(const char *option_name,
                                            const gchar *timestamp_path,
                                            RmCmdSession *cmd, GError **error) {
    bool plain = true, success = false;
    FILE *stamp_file = fopen(timestamp_path, "r");

    /* Assume failure */
    cmd->cfg->filter_mtime = false;

    if(stamp_file) {
        char stamp_buf[1024];
        memset(stamp_buf, 0, sizeof(stamp_buf));

        if(fgets(stamp_buf, sizeof(stamp_buf), stamp_file) != NULL) {
            success =
                rm_cmd_parse_timestamp(option_name, g_strstrip(stamp_buf), cmd, error);
            plain = rm_cmd_timestamp_is_plain(stamp_buf);
        }

        fclose(stamp_file);
    } else {
        /* Cannot read... */
        plain = false;
    }

    if(!success) {
        return false;
    }

    rm_fmt_add(cmd->formats, "stamp", timestamp_path);
    if(!plain) {
        /* Enable iso8601 timestamp output */
        rm_fmt_set_config_value(cmd->formats, "stamp", g_strdup("iso8601"),
                                g_strdup("true"));
    }

    return success;
}

static void rm_cmd_set_paranoia_from_cnt(RmCmdSession *cmd, int paranoia_counter,
                                         GError **error) {
    /* Handle the paranoia option */
    switch(paranoia_counter) {
    case -2:
        cmd->cfg->checksum_type = RM_DIGEST_XXHASH;
        break;
    case -1:
        cmd->cfg->checksum_type = RM_DIGEST_BASTARD;
        break;
    case 0:
        /* leave users choice of -a (default) */
        break;
    case 1:
#if HAVE_SHA512
        cmd->cfg->checksum_type = RM_DIGEST_SHA512;
#else
        cmd->cfg->checksum_type = RM_DIGEST_SHA256;
#endif
        break;
    case 2:
        cmd->cfg->checksum_type = RM_DIGEST_PARANOID;
        break;
    default:
        if(error && *error == NULL) {
            g_set_error(error, RM_ERROR_QUARK, 0,
                        _("Only up to -pp or down to -PP flags allowed"));
        }
        break;
    }
}

static void rm_cmd_on_error(_UNUSED GOptionContext *context, _UNUSED GOptionGroup *group,
                            RmCmdSession *cmd, GError **error) {
    if(error != NULL) {
        rm_log_error_line("%s.", (*error)->message);
        g_clear_error(error);
        cmd->cmdline_parse_error = true;
    }
}

static gboolean rm_cmd_parse_algorithm(_UNUSED const char *option_name,
                                       const gchar *value,
                                       RmCmdSession *cmd,
                                       GError **error) {
    cmd->cfg->checksum_type = rm_string_to_digest_type(value);

    if(cmd->cfg->checksum_type == RM_DIGEST_UNKNOWN) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Unknown hash algorithm: '%s'"), value);
        return false;
    } else if(cmd->cfg->checksum_type == RM_DIGEST_BASTARD) {
        cmd->cfg->hash_seed1 = time(NULL) * (GPOINTER_TO_UINT(cmd));
        cmd->cfg->hash_seed2 = GPOINTER_TO_UINT(&cmd);
    }
    return true;
}

static gboolean rm_cmd_parse_small_output(_UNUSED const char *option_name,
                                          const gchar *output_pair, RmCmdSession *cmd,
                                          _UNUSED GError **error) {
    cmd->output_cnt[0] = MAX(cmd->output_cnt[0], 0);
    cmd->output_cnt[0] += rm_cmd_parse_output_pair(cmd, output_pair, error);
    return true;
}

static gboolean rm_cmd_parse_large_output(_UNUSED const char *option_name,
                                          const gchar *output_pair, RmCmdSession *cmd,
                                          _UNUSED GError **error) {
    cmd->output_cnt[1] = MAX(cmd->output_cnt[1], 0);
    cmd->output_cnt[1] += rm_cmd_parse_output_pair(cmd, output_pair, error);
    return true;
}

static gboolean rm_cmd_parse_mem(const gchar *size_spec, GError **error, RmOff *target) {
    RmOff size = rm_cmd_size_string_to_bytes(size_spec, error);

    if(*error != NULL) {
        g_prefix_error(error, _("Invalid size description \"%s\": "), size_spec);
        return false;
    } else {
        *target = size;
        return true;
    }
}

static gboolean rm_cmd_parse_limit_mem(_UNUSED const char *option_name,
                                       const gchar *size_spec, RmCmdSession *cmd,
                                       GError **error) {
    return (rm_cmd_parse_mem(size_spec, error, &cmd->cfg->total_mem));
}

static gboolean rm_cmd_parse_sweep_count(_UNUSED const char *option_name,
                                         const gchar *size_spec, RmCmdSession *cmd,
                                         GError **error) {
    return (rm_cmd_parse_mem(size_spec, error, &cmd->cfg->sweep_count));
}

static gboolean rm_cmd_parse_clamp_low(_UNUSED const char *option_name, const gchar *spec,
                                       RmCmdSession *cmd, _UNUSED GError **error) {
    rm_cmd_parse_clamp_option(cmd, spec, true, error);
    return (error && *error == NULL);
}

static gboolean rm_cmd_parse_clamp_top(_UNUSED const char *option_name, const gchar *spec,
                                       RmCmdSession *cmd, _UNUSED GError **error) {
    rm_cmd_parse_clamp_option(cmd, spec, false, error);
    return (error && *error == NULL);
}

static gboolean rm_cmd_parse_progress(_UNUSED const char *option_name,
                                      _UNUSED const gchar *value, RmCmdSession *cmd,
                                      _UNUSED GError **error) {
    rm_fmt_clear(cmd->formats);
    rm_fmt_add(cmd->formats, "progressbar", "stdout");
    rm_fmt_add(cmd->formats, "summary", "stdout");

    cmd->cfg->progress_enabled = true;

    /* Set verbosity to minimal */
    cmd->cfg->verbosity = G_LOG_LEVEL_CRITICAL;
    return true;
}

static void rm_cmd_set_default_outputs(RmCmdSession *cmd) {
    rm_fmt_add(cmd->formats, "pretty", "stdout");
    rm_fmt_add(cmd->formats, "summary", "stdout");

    if(cmd->cfg->replay_files.length) {
        rm_fmt_add(cmd->formats, "sh", "rmlint.replay.sh");
        rm_fmt_add(cmd->formats, "json", "rmlint.replay.json");
    } else {
        rm_fmt_add(cmd->formats, "sh", "rmlint.sh");
        rm_fmt_add(cmd->formats, "json", "rmlint.json");
    }
}

static gboolean rm_cmd_parse_loud(_UNUSED const char *option_name,
                                  _UNUSED const gchar *count, RmCmdSession *cmd,
                                  _UNUSED GError **error) {
    switch(cmd->cfg->verbosity) {
    case G_LOG_LEVEL_CRITICAL:
        cmd->cfg->verbosity = G_LOG_LEVEL_WARNING;
        break;
    case G_LOG_LEVEL_WARNING:
        cmd->cfg->verbosity = G_LOG_LEVEL_INFO;
        break;
    default:
        cmd->cfg->verbosity = G_LOG_LEVEL_DEBUG;
    }
    return true;
}

static gboolean rm_cmd_parse_quiet(_UNUSED const char *option_name,
                                   _UNUSED const gchar *count, RmCmdSession *cmd,
                                   _UNUSED GError **error) {
    switch(cmd->cfg->verbosity) {
    case G_LOG_LEVEL_DEBUG:
        cmd->cfg->verbosity = G_LOG_LEVEL_INFO;
        break;
    case G_LOG_LEVEL_INFO:
        cmd->cfg->verbosity = G_LOG_LEVEL_WARNING;
        break;
    default:
        cmd->cfg->verbosity = G_LOG_LEVEL_CRITICAL;
    }
    return true;
}

static gboolean rm_cmd_parse_paranoid(_UNUSED const char *option_name,
                                      _UNUSED const gchar *count, RmCmdSession *cmd,
                                      _UNUSED GError **error) {
    rm_cmd_set_paranoia_from_cnt(cmd, ++cmd->paranoia_count, error);
    return true;
}

static gboolean rm_cmd_parse_less_paranoid(_UNUSED const char *option_name,
                                           _UNUSED const gchar *count, RmCmdSession *cmd,
                                           _UNUSED GError **error) {
    rm_cmd_set_paranoia_from_cnt(cmd, --cmd->paranoia_count, error);
    return true;
}

static gboolean rm_cmd_parse_partial_hidden(_UNUSED const char *option_name,
                                            _UNUSED const gchar *count, RmCmdSession *cmd,
                                            _UNUSED GError **error) {
    cmd->cfg->ignore_hidden = false;
    cmd->cfg->partial_hidden = true;

    return true;
}

static gboolean rm_cmd_parse_see_symlinks(_UNUSED const char *option_name,
                                          _UNUSED const gchar *count, RmCmdSession *cmd,
                                          _UNUSED GError **error) {
    cmd->cfg->see_symlinks = true;
    cmd->cfg->follow_symlinks = false;

    return true;
}

static gboolean rm_cmd_parse_follow_symlinks(_UNUSED const char *option_name,
                                             _UNUSED const gchar *count,
                                             RmCmdSession *cmd, _UNUSED GError **error) {
    cmd->cfg->see_symlinks = false;
    cmd->cfg->follow_symlinks = true;

    return true;
}

static gboolean rm_cmd_parse_no_partial_hidden(_UNUSED const char *option_name,
                                               _UNUSED const gchar *count,
                                               RmCmdSession *cmd,
                                               _UNUSED GError **error) {
    cmd->cfg->ignore_hidden = true;
    cmd->cfg->partial_hidden = false;

    return true;
}

static gboolean rm_cmd_parse_merge_directories(_UNUSED const char *option_name,
                                               _UNUSED const gchar *count,
                                               RmCmdSession *cmd,
                                               _UNUSED GError **error) {
    cmd->cfg->merge_directories = true;

    /* Pull in some options for convinience,
     * duplicate dir detection works better with them.
     *
     * They may be disabled explicitly though.
     */
    cmd->cfg->follow_symlinks = false;
    cmd->cfg->see_symlinks = true;
    rm_cmd_parse_partial_hidden(NULL, NULL, cmd, error);
    cmd->cfg->find_hardlinked_dupes = true;

    return true;
}

static gboolean rm_cmd_parse_permissions(_UNUSED const char *option_name,
                                         const gchar *perms, RmCmdSession *cmd,
                                         GError **error) {
    if(perms == NULL) {
        cmd->cfg->permissions = R_OK | W_OK;
    } else {
        while(*perms) {
            switch(*perms++) {
            case 'r':
                cmd->cfg->permissions |= R_OK;
                break;
            case 'w':
                cmd->cfg->permissions |= W_OK;
                break;
            case 'x':
                cmd->cfg->permissions |= X_OK;
                break;
            default:
                g_set_error(error, RM_ERROR_QUARK, 0,
                            _("Permissions string needs to be one or many of [rwx]"));
                return false;
            }
        }
    }

    return true;
}

static gboolean rm_cmd_check_lettervec(const char *option_name, const char *criteria,
                                       const char *valid, GError **error) {
    for(int i = 0; criteria[i]; ++i) {
        if(strchr(valid, criteria[i]) == NULL) {
            g_set_error(error, RM_ERROR_QUARK, 0, _("%s may only contain [%s], not `%c`"),
                        option_name, valid, criteria[i]);
            return false;
        }
    }

    return true;
}

static gboolean rm_cmd_parse_sortby(_UNUSED const char *option_name,
                                    const gchar *criteria, RmCmdSession *cmd,
                                    GError **error) {
    if(!rm_cmd_check_lettervec(option_name, criteria, "moanspMOANSP", error)) {
        return false;
    }

    /* Remember the criteria string */
    strncpy(cmd->cfg->rank_criteria, criteria, sizeof(cmd->cfg->rank_criteria));

    /* ranking the files depends on caching them to the end of the program */
    cmd->cfg->cache_file_structs = true;

    return true;
}

static size_t rm_cmd_parse_pattern(const char *pattern, GRegex **regex, GError **error) {
    if(*pattern != '<') {
        g_set_error(error, RM_ERROR_QUARK, 0, _("Pattern has to start with `<`"));
        return 0;
    }

    /* Balance of start and end markers */
    int balance = 1;
    char *iter = (char *)pattern;
    char *last = iter;

    while((iter = strpbrk(&iter[1], "<>"))) {
        if(iter[-1] == '\\') {
            /* escaped, skip */
            break;
        }

        if(iter && *iter == '<') {
            ++balance;
        } else if(iter) {
            --balance;
            last = iter;
        }

        if(balance == 0) {
            break;
        }
    }

    if(balance != 0) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("`<` or `>` imbalance: %d"), balance);
        return 0;
    }

    size_t src_len = (last - pattern - 1);

    if(src_len == 0) {
        g_set_error(error, RM_ERROR_QUARK, 0, _("empty pattern"));
        return 0;
    }

    GString *part = g_string_new_len(&pattern[1], src_len);

    rm_log_debug_line("Compiled pattern: %s\n", part->str);

    /* Actually compile the pattern: */
    *regex = g_regex_new(part->str, G_REGEX_RAW | G_REGEX_OPTIMIZE, 0, error);

    g_string_free(part, TRUE);

    /* Include <> in the result len */
    return src_len + 2;
}

/* Compile all regexes inside a sortcriteria string.
 * Every regex (enclosed in <>)  will be removed from the
 * sortcriteria spec, so that the returned string will
 * consist only of single letters.
 */
static char *rm_cmd_compile_patterns(RmCmdSession *cmd, const char *sortcrit,
                                     GError **error) {
    /* Total of encountered patterns */
    int pattern_count = 0;

    /* Copy of the sortcriteria without pattern specs in <> */
    size_t minified_cursor = 0;
    char *minified_sortcrit = g_strdup(sortcrit);

    for(size_t i = 0; sortcrit[i]; i++) {
        /* Copy everything that is not a regex pattern */
        minified_sortcrit[minified_cursor++] = sortcrit[i];
        char curr_crit = tolower((unsigned char)sortcrit[i]);

        /* Check if it's a non-regex sortcriteria */
        if(!((curr_crit == 'r' || curr_crit == 'x') && sortcrit[i + 1] == '<')) {
            continue;
        }

        GRegex *regex = NULL;

        /* Jump over the regex pattern part */
        i += rm_cmd_parse_pattern(&sortcrit[i + 1], &regex, error);

        if(regex != NULL) {
            if(pattern_count < (int)RM_PATTERN_N_MAX && pattern_count != -1) {
                /* Append to already compiled patterns */
                g_ptr_array_add(cmd->cfg->pattern_cache, regex);
                pattern_count++;
            } else if(pattern_count != -1) {
                g_set_error(error, RM_ERROR_QUARK, 0,
                            _("Cannot add more than %ld regex patterns."),
                            RM_PATTERN_N_MAX);

                /* Make sure to set the warning only once */
                pattern_count = -1;
                g_regex_unref(regex);
            } else {
                g_regex_unref(regex);
            }
        }
    }

    g_prefix_error(error, _("Error while parsing sortcriteria patterns: "));

    minified_sortcrit[minified_cursor] = 0;
    return minified_sortcrit;
}

static gboolean rm_cmd_parse_rankby(_UNUSED const char *option_name,
                                    const gchar *criteria, RmCmdSession *cmd,
                                    GError **error) {
    g_free(cmd->cfg->sort_criteria);

    cmd->cfg->sort_criteria = rm_cmd_compile_patterns(cmd, criteria, error);

    if(error && *error != NULL) {
        return false;
    }

    if(!rm_cmd_check_lettervec(option_name, cmd->cfg->sort_criteria, "dlafmprxDLAFFMPRX",
                               error)) {
        return false;
    }

    return true;
}

static gboolean rm_cmd_parse_replay(_UNUSED const char *option_name,
                                    const gchar *json_path, RmCmdSession *cmd,
                                    GError **error) {
    if(json_path == NULL) {
        json_path = "rmlint.json";
    }

    if(g_access(json_path, R_OK) == -1) {
        g_set_error(error, RM_ERROR_QUARK, 0, "--replay: `%s`: %s", json_path,
                    g_strerror(errno));
        return false;
    }

    g_queue_push_tail(&cmd->cfg->replay_files, g_strdup(json_path));
    cmd->cfg->cache_file_structs = true;
    return true;
}

static bool rm_cmd_set_cwd(RmCfg *cfg) {
    /* Get current directory */
    char cwd_buf[PATH_MAX + 1];
    memset(cwd_buf, 0, sizeof(cwd_buf));

    if(getcwd(cwd_buf, PATH_MAX) == NULL) {
        rm_log_perror("");
        return false;
    }

    cfg->iwd = g_strdup_printf("%s%s", cwd_buf, G_DIR_SEPARATOR_S);
    return true;
}

static bool rm_cmd_set_cmdline(RmCfg *cfg, int argc, char **argv) {
    /* Copy commandline rmlint was invoked with by copying argv into a
     * NULL padded array and join that with g_strjoinv. GLib made me lazy.
     */
    const char *argv_nul[argc + 1];
    memset(argv_nul, 0, sizeof(argv_nul));
    memcpy(argv_nul, argv, argc * sizeof(const char *));
    cfg->joined_argv = g_strjoinv(" ", (gchar **)argv_nul);

    /* This cannot fail currently */
    return true;
}

static bool rm_cmd_set_paths(RmCfg *cfg, char **paths) {
    int path_index = 0;
    bool not_all_paths_read = false;

    /* Check the directory to be valid */
    for(int i = 0; paths && paths[i]; ++i) {
        int read_paths = 0;
        const char *dir_path = paths[i];

        if(strncmp(dir_path, "-", 1) == 0) {
            read_paths = rm_cmd_read_paths_from_stdin(cfg, path_index);
        } else if(strncmp(dir_path, "//", 2) == 0 && strlen(dir_path) == 2) {
            if(cfg->first_prefd != 0) {
                rm_log_error_line("More that one // separator detected, ignoring...");
            } else {
                cfg->first_prefd = path_index;
            }
        } else {
            read_paths = rm_cmd_add_path(cfg, path_index, paths[i]);
        }

        if(read_paths == 0) {
            not_all_paths_read = true;
        } else {
            path_index += read_paths;
        }
    }

    g_strfreev(paths);

    if(path_index == 0 && not_all_paths_read == false) {
        /* Still no path set? - use `pwd` */
        rm_cmd_add_path(cfg, path_index, cfg->iwd);
    } else if(path_index == 0 && not_all_paths_read) {
        return false;
    }

    return true;
}

static bool rm_cmd_set_outputs(RmCmdSession *cmd, GError **error) {
    if(cmd->output_cnt[0] >= 0 && cmd->output_cnt[1] >= 0) {
        g_set_error(error, RM_ERROR_QUARK, 0,
                    _("Specifiyng both -o and -O is not allowed"));
        return false;
    } else if(cmd->output_cnt[0] < 0 && cmd->output_cnt[1] < 0 &&
              !rm_fmt_len(cmd->formats)) {
        rm_cmd_set_default_outputs(cmd);
    }

    return true;
}

/* Parse the commandline and set arguments in 'settings' (glob. var accordingly) */
bool rm_cmd_parse_args(int argc, char **argv, RmCfg *cfg, RmFmtTable *formats) {
    RmCmdSession *cmd = g_slice_new0(RmCmdSession);
    cmd->paranoia_count = 0;
    cmd->output_cnt[0] = -1;
    cmd->output_cnt[1] = -1;
    cmd->cfg = cfg;
    cmd->formats = formats;

    /* List of paths we got passed (or NULL) */
    char **paths = NULL;

    /* General error variable */
    GError *error = NULL;
    GOptionContext *option_parser = NULL;

#define FUNC(name) ((GOptionArgFunc)rm_cmd_parse_##name)
    const int DISABLE = G_OPTION_FLAG_REVERSE, EMPTY = G_OPTION_FLAG_NO_ARG,
              HIDDEN = G_OPTION_FLAG_HIDDEN, OPTIONAL = G_OPTION_FLAG_OPTIONAL_ARG;

    /* tests for dummy options */
    gboolean gui = FALSE;
    gboolean hash = FALSE;
    gboolean clone = FALSE;

    /* Free/Used Options:
       Used: abBcCdDeEfFgGHhiI  kKlLmMnNoOpPqQrRsStTuUvVwWxXyY
       Free:                  jJ                              zZ
    */

    /* clang-format off */
    const GOptionEntry main_option_entries[] = {
        /* Option with required arguments */
        {"max-depth"        , 'd' , 0        , G_OPTION_ARG_INT      , &cfg->depth          , _("Specify max traversal depth")          , "N"}                   ,
        {"rank-by"          , 'S' , 0        , G_OPTION_ARG_CALLBACK , FUNC(rankby)         , _("Select originals by given  criteria")  , "[dlafmprxDLAFMPRX]"}    ,
        {"sort-by"          , 'y' , 0        , G_OPTION_ARG_CALLBACK , FUNC(sortby)         , _("Sort rmlint output by given criteria") , "[moansMOANS]"}        ,
        {"types"            , 'T' , 0        , G_OPTION_ARG_CALLBACK , FUNC(lint_types)     , _("Specify lint types")                   , "T"}                   ,
        {"size"             , 's' , 0        , G_OPTION_ARG_CALLBACK , FUNC(limit_sizes)    , _("Specify size limits")                  , "m-M"}                 ,
        {"algorithm"        , 'a' , 0        , G_OPTION_ARG_CALLBACK , FUNC(algorithm)      , _("Choose hash algorithm")                , "A"}                   ,
        {"output"           , 'o' , 0        , G_OPTION_ARG_CALLBACK , FUNC(small_output)   , _("Add output (override default)")        , "FMT[:PATH]"}          ,
        {"add-output"       , 'O' , 0        , G_OPTION_ARG_CALLBACK , FUNC(large_output)   , _("Add output (add to defaults)")         , "FMT[:PATH]"}          ,
        {"newer-than-stamp" , 'n' , 0        , G_OPTION_ARG_CALLBACK , FUNC(timestamp_file) , _("Newer than stamp file")                , "PATH"}                ,
        {"newer-than"       , 'N' , 0        , G_OPTION_ARG_CALLBACK , FUNC(timestamp)      , _("Newer than timestamp")                 , "STAMP"}               ,
        {"replay"           , 'Y' , OPTIONAL , G_OPTION_ARG_CALLBACK , FUNC(replay)         , _("Re-output a json file")                , "path/to/rmlint.json"} ,
        {"config"           , 'c' , 0        , G_OPTION_ARG_CALLBACK , FUNC(config)         , _("Configure a formatter")                , "FMT:K[=V]"}           ,

        /* Non-trvial switches */
        {"progress" , 'g' , EMPTY , G_OPTION_ARG_CALLBACK , FUNC(progress) , _("Enable progressbar")                   , NULL} ,
        {"loud"     , 'v' , EMPTY , G_OPTION_ARG_CALLBACK , FUNC(loud)     , _("Be more verbose (-vvv for much more)") , NULL} ,
        {"quiet"    , 'V' , EMPTY , G_OPTION_ARG_CALLBACK , FUNC(quiet)    , _("Be less verbose (-VVV for much less)") , NULL} ,

        /* Trivial boolean options */
        {"no-with-color"            , 'W'  , DISABLE   , G_OPTION_ARG_NONE      , &cfg->with_color               , _("Be not that colorful")                                , NULL}      ,
        {"hidden"                   , 'r'  , DISABLE   , G_OPTION_ARG_NONE      , &cfg->ignore_hidden            , _("Find hidden files")                                   , NULL}      ,
        {"followlinks"              , 'f'  , EMPTY     , G_OPTION_ARG_CALLBACK  , FUNC(follow_symlinks)          , _("Follow symlinks")                                     , NULL}      ,
        {"no-followlinks"           , 'F'  , DISABLE   , G_OPTION_ARG_NONE      , &cfg->follow_symlinks          , _("Ignore symlinks")                                     , NULL}      ,
        {"paranoid"                 , 'p'  , EMPTY     , G_OPTION_ARG_CALLBACK  , FUNC(paranoid)                 , _("Use more paranoid hashing")                           , NULL}      ,
        {"no-crossdev"              , 'x'  , DISABLE   , G_OPTION_ARG_NONE      , &cfg->crossdev                 , _("Do not cross mounpoints")                             , NULL}      ,
        {"keep-all-tagged"          , 'k'  , 0         , G_OPTION_ARG_NONE      , &cfg->keep_all_tagged          , _("Keep all tagged files")                               , NULL}      ,
        {"must-match-tagged"        , 'm'  , 0         , G_OPTION_ARG_NONE      , &cfg->must_match_tagged        , _("Must have twin in tagged dir")                        , NULL}      ,
        {"match-basename"           , 'b'  , 0         , G_OPTION_ARG_NONE      , &cfg->match_basename           , _("Only find twins with same basename")                  , NULL}      ,
        {"match-extension"          , 'e'  , 0         , G_OPTION_ARG_NONE      , &cfg->match_with_extension     , _("Only find twins with same extension")                 , NULL}      ,
        {"match-without-extension"  , 'i'  , 0         , G_OPTION_ARG_NONE      , &cfg->match_without_extension  , _("Only find twins with same basename minus extension")  , NULL}      ,
        {"merge-directories"        , 'D'  , EMPTY     , G_OPTION_ARG_CALLBACK  , FUNC(merge_directories)        , _("Find duplicate directories")                          , NULL}      ,
        {"perms"                    , 'z'  , OPTIONAL  , G_OPTION_ARG_CALLBACK  , FUNC(permissions)              , _("Only use files with certain permissions")             , "[RWX]+"}  ,
        {"no-hardlinked"            , 'L'  , DISABLE   , G_OPTION_ARG_NONE      , &cfg->find_hardlinked_dupes    , _("Ignore hardlink twins")                               , NULL}      ,
        {"partial-hidden"           , 0    , EMPTY     , G_OPTION_ARG_CALLBACK  , FUNC(partial_hidden)           , _("Find hidden files in duplicate folders only")         , NULL}      ,

        /* Callback */
        {"show-man" , 'H' , EMPTY , G_OPTION_ARG_CALLBACK , rm_cmd_show_manpage , _("Show the manpage")            , NULL} ,
        {"version"  , 0   , EMPTY , G_OPTION_ARG_CALLBACK , rm_cmd_show_version , _("Show the version & features") , NULL} ,
        /* Dummy option for --help output only: */
        {"gui"         , 0 , 0 , G_OPTION_ARG_NONE , &gui   , _("If installed, start the optional gui with all following args")                 , NULL},
        {"hash"        , 0 , 0 , G_OPTION_ARG_NONE , &hash  , _("Work like sha1sum for all supported hash algorithms (see also --hash --help)") , NULL}                                            ,
        {"btrfs-clone" , 0 , 0 , G_OPTION_ARG_NONE , &clone , _("Clone extents from source to dest, if extents match")                          , NULL} ,

        /* Special case: accumulate leftover args (paths) in &paths */
        {G_OPTION_REMAINING , 0 , 0 , G_OPTION_ARG_FILENAME_ARRAY , &paths , ""   , NULL}   ,
        {NULL               , 0 , 0 , 0                           , NULL   , NULL , NULL}
    };

    const GOptionEntry inversed_option_entries[] = {
        {"less-paranoid"              , 'P' , EMPTY | HIDDEN   , G_OPTION_ARG_CALLBACK , FUNC(less_paranoid)           , "Use less paranoid hashing algorithm" , NULL} ,
        {"see-symlinks"               , '@' , EMPTY | HIDDEN   , G_OPTION_ARG_CALLBACK , FUNC(see_symlinks)            , "Treat symlinks a regular files"      , NULL} ,
        {"unmatched-basename"         , 'B',  HIDDEN           , G_OPTION_ARG_NONE     , &cfg->unmatched_basenames     , "Only find twins with differing names", NULL} ,
        {"no-partial-hidden"          , 0   , EMPTY | HIDDEN   , G_OPTION_ARG_CALLBACK , FUNC(no_partial_hidden)       , "Invert --partial-hidden"             , NULL} ,
        {NULL                         , 0   , 0                , 0                     , NULL                          , NULL                                  , NULL}
    };

    const GOptionEntry unusual_option_entries[] = {
        {"clamp-low"              , 'q' , HIDDEN           , G_OPTION_ARG_CALLBACK , FUNC(clamp_low)              , "Limit lower reading barrier"                                  , "P"}   ,
        {"clamp-top"              , 'Q' , HIDDEN           , G_OPTION_ARG_CALLBACK , FUNC(clamp_top)              , "Limit upper reading barrier"                                  , "P"}   ,
        {"limit-mem"              , 'u' , HIDDEN           , G_OPTION_ARG_CALLBACK , FUNC(limit_mem)              , "Specify max. memory usage target"                             , "S"}   ,
        {"sweep-files"            , 'u' , HIDDEN           , G_OPTION_ARG_CALLBACK , FUNC(sweep_count)            , "Specify max. file count per pass when scanning disks"         , "S"}   ,
        {"read-threads"           , 't' , HIDDEN           , G_OPTION_ARG_INT64    , &cfg->read_threads           , "Specify max. number of reader threads"                        , "N"}   ,
        {"hash-threads"           , 't' , HIDDEN           , G_OPTION_ARG_INT64    , &cfg->hash_threads           , "Specify max. number of hasher/sorter threads"                 , "N"}   ,
        {"threads-per-hdd"        , 0   , HIDDEN           , G_OPTION_ARG_INT      , &cfg->threads_per_hdd        , "Specify number of reader threads per rotational disk"        , NULL}   ,
        {"threads-per-ssd"        , 0   , HIDDEN           , G_OPTION_ARG_INT      , &cfg->threads_per_ssd        , "Specify number of reader threads per non-rotational disk"    , NULL}   ,
        {"write-unfinished"       , 'U' , HIDDEN           , G_OPTION_ARG_NONE     , &cfg->write_unfinished       , "Output unfinished checksums"                                 , NULL}   ,
        {"xattr-write"            , 0   , HIDDEN           , G_OPTION_ARG_NONE     , &cfg->write_cksum_to_xattr   , "Cache checksum in file attributes"                           , NULL}   ,
        {"xattr-read"             , 0   , HIDDEN           , G_OPTION_ARG_NONE     , &cfg->read_cksum_from_xattr  , "Read cached checksums from file attributes"                  , NULL}   ,
        {"xattr-clear"            , 0   , HIDDEN           , G_OPTION_ARG_NONE     , &cfg->clear_xattr_fields     , "Clear xattrs from all seen files"                            , NULL}   ,
        {"without-fiemap"         , 0   , DISABLE | HIDDEN , G_OPTION_ARG_NONE     , &cfg->build_fiemap           , "Do not use fiemap(2) in order to save memory"                , NULL}   ,
        {"fake-pathindex-as-disk" , 0   , HIDDEN           , G_OPTION_ARG_NONE     , &cfg->fake_pathindex_as_disk , "Pretends each input path is a separate physical disk"        , NULL}   ,
        {"fake-holdback"          , 0   , HIDDEN           , G_OPTION_ARG_NONE     , &cfg->cache_file_structs     , "Hold back all files to the end before outputting."           , NULL}   ,
        {"fake-fiemap"            , 0   , HIDDEN           , G_OPTION_ARG_NONE     , &cfg->fake_fiemap            , "Create faked fiemap data for all files"                      , NULL}   ,
        {"fake-abort"             , 0   , HIDDEN           , G_OPTION_ARG_NONE     , &cfg->fake_abort             , "Simulate interrupt after 10% shredder progress"              , NULL}   ,
        {"buffered-read"          , 0   , HIDDEN           , G_OPTION_ARG_NONE     , &cfg->use_buffered_read      , "Default to buffered reading calls (fread) during reading."   , NULL}   ,
        {"no-mount-table"         , 0   , DISABLE | HIDDEN , G_OPTION_ARG_NONE     , &cfg->list_mounts            , "Do not try to optimize by identifying physical disks"        , NULL}   ,
        {NULL                     , 0   , HIDDEN           , 0                     , NULL                         , NULL                                                          , NULL}
    };

    /* clang-format on */

    if(!rm_cmd_set_cwd(cfg)) {
        g_set_error(&error, RM_ERROR_QUARK, 0, _("Cannot set current working directory"));
        goto failure;
    }

    rm_cmd_set_cmdline(cfg, argc, argv);

    ////////////////////
    // OPTION PARSING //
    ////////////////////

    option_parser = g_option_context_new(
        _("[TARGET_DIR_OR_FILES …] [//] [TAGGED_TARGET_DIR_OR_FILES …] [-]"));
    g_option_context_set_translation_domain(option_parser, RM_GETTEXT_PACKAGE);

    GOptionGroup *main_group =
        g_option_group_new("rmlint", "main", "Most useful main options", cmd, NULL);
    GOptionGroup *inversion_group = g_option_group_new(
        "inversed", "inverted", "Options that enable defaults", cmd, NULL);
    GOptionGroup *unusual_group =
        g_option_group_new("unusual", "unusual", "Unusual options", cmd, NULL);

    g_option_group_add_entries(main_group, main_option_entries);
    g_option_group_add_entries(main_group, inversed_option_entries);
    g_option_group_add_entries(main_group, unusual_option_entries);

    g_option_context_add_group(option_parser, inversion_group);
    g_option_context_add_group(option_parser, unusual_group);
    g_option_context_set_main_group(option_parser, main_group);
    g_option_context_set_summary(option_parser,
                                 _("rmlint finds space waste and other broken things on "
                                   "your filesystem and offers to remove it.\n"
                                   "It is especially good at finding duplicates and "
                                   "offers a big variety of options to handle them."));
    g_option_context_set_description(
        option_parser,
        _("Only the most important options and options that alter the defaults are shown "
          "above.\n"
          "See the manpage (man 1 rmlint or rmlint --show-man) for far more detailed "
          "usage information,\n"
          "or http://rmlint.rtfd.org/en/latest/rmlint.1.html for the online manpage.\n"
          "Complementary tutorials can be found at: http://rmlint.rtfd.org"));

    g_option_group_set_error_hook(main_group, (GOptionErrorFunc)rm_cmd_on_error);

    if(!g_option_context_parse(option_parser, &argc, &argv, &error)) {
        goto failure;
    }

    /* screening of dummy options */
    if(gui) {
        rm_log_error_line("--gui must be first argument");
        cmd->cmdline_parse_error = TRUE;
    }
    if(hash) {
        rm_log_error_line("--hash must be first argument");
        cmd->cmdline_parse_error = TRUE;
    }
    if(clone) {
        rm_log_error_line("--btrfs-clone must be first argument");
        cmd->cmdline_parse_error = TRUE;
    }

    /* Silent fixes of invalid numberic input */
    cfg->read_threads = CLAMP(cfg->read_threads, 1, 128);
    cfg->hash_threads = CLAMP(cfg->hash_threads, 1, 128);
    cfg->depth = CLAMP(cfg->depth, 0, PATH_MAX / 2 + 1);

    if(cfg->partial_hidden && !cfg->merge_directories) {
        /* --partial-hidden only makes sense with --merge-directories.
         * If the latter is not specfified, ignore it all together */
        cfg->ignore_hidden = true;
        cfg->partial_hidden = false;
    }

    if(cfg->progress_enabled) {
        if(!rm_fmt_has_formatter(formats, "sh")) {
            rm_fmt_add(formats, "sh", "rmlint.sh");
        }

        if(!rm_fmt_has_formatter(formats, "json")) {
            rm_fmt_add(formats, "json", "rmlint.json");
        }
    }

    /* Overwrite color if we do not print to a terminal directly */
    if(cfg->with_color) {
        cfg->with_stdout_color = isatty(fileno(stdout));
        cfg->with_stderr_color = isatty(fileno(stderr));
        cfg->with_color = (cfg->with_stdout_color | cfg->with_stderr_color);
    } else {
        cfg->with_stdout_color = cfg->with_stderr_color = 0;
    }

    if(cfg->skip_start_factor >= cfg->skip_end_factor) {
        error = g_error_new(RM_ERROR_QUARK, 0,
                            _("-q (--clamp-low) should be lower than -Q (--clamp-top)"));
    } else if(!rm_cmd_set_paths(cfg, paths)) {
        error = g_error_new(RM_ERROR_QUARK, 0, _("No valid paths given."));
    } else if(!rm_cmd_set_outputs(cmd, &error)) {
        /* Something wrong with the outputs */
    } else if(cfg->follow_symlinks && cfg->see_symlinks) {
        rm_log_error("Program error: Cannot do both follow_symlinks and see_symlinks.");
        rm_assert_gentle_not_reached();
    }
failure:
    if(error != NULL) {
        rm_cmd_on_error(NULL, NULL, cmd, &error);
    }

    g_option_context_free(option_parser);
    bool result = !(cmd->cmdline_parse_error);
    g_slice_free(RmCmdSession, cmd);
    return result;
}
