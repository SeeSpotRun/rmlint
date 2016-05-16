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
 *  - Christopher <sahib> Pahl 2010-2014 (https://github.com/sahib)
 *  - Daniel <SeeSpotRun> T.   2014-2014 (https://github.com/SeeSpotRun)
 *
** Hosted on http://github.com/sahib/rmlint
*
**/

#include <locale.h>
#include <stdlib.h>
#include <string.h>

#include "../lib/api.h"
#include "../lib/config.h"
#include "../lib/hash-utility.h"

#if HAVE_JSON_GLIB && !GLIB_CHECK_VERSION(2, 36, 0)
#include <glib-object.h>
#endif

#if HAVE_BTRFS_H
#include <linux/btrfs.h>
#include <sys/ioctl.h>
#endif

static char *remove_color_escapes(char *message) {
    char *dst = message;
    for(char *src = message; src && *src; src++) {
        if(*src == '\x1b') {
            src = strchr(src, 'm');
        } else {
            *dst++ = *src;
        }
    }

    if(dst) {
        *dst = 0;
    }
    return message;
}

static void logging_callback(_UNUSED const gchar *log_domain,
                             GLogLevelFlags log_level,
                             const gchar *message,
                             gpointer user_data) {
    RmSession *session = user_data;
    if(session->cfg->verbosity >= log_level) {
        if(!session->cfg->with_stderr_color) {
            message = remove_color_escapes((char *)message);
        }
        fputs(message, stderr);
    }
}

static void signal_handler(int signum) {
    switch(signum) {
    case SIGINT:
        rm_session_abort();
        break;
    case SIGSEGV:
        /* logging messages might have unexpected effects in a signal handler,
         * but that's probably the least thing we have to worry about in case of
         * a segmentation fault.
         */
        rm_log_error_line(_("Aborting due to a fatal error. (signal received: %s)"),
                          g_strsignal(signum));
        rm_log_error_line(_("Please file a bug report (See rmlint -h)"));
    default:
        break;
    }
}

static void i18n_init(void) {
#if HAVE_LIBINTL
    /* Tell gettext where to search for .mo files */
    bindtextdomain(RM_GETTEXT_PACKAGE, INSTALL_PREFIX "/share/locale");
    bind_textdomain_codeset(RM_GETTEXT_PACKAGE, "UTF-8");

    /* Make printing umlauts work */
    setlocale(LC_ALL, "");

    /* Say we're the textdomain "rmlint"
     * so gettext can find us in
     * /usr/share/locale/de/LC_MESSAGEs/rmlint.mo
     * */
    textdomain(RM_GETTEXT_PACKAGE);
#endif
}

static void start_gui(int argc, const char **argv) {
    const char *commands[] = {"python3", "python", NULL};
    const char **command = &commands[0];

    while(*command) {
        const char *all_argv[512];
        const char **argp = &all_argv[0];
        memset(all_argv, 0, sizeof(all_argv));

        *argp++ = *command;
        *argp++ = "-m";
        *argp++ = "shredder";

        for(size_t i = 0; i < (size_t)argc && i < sizeof(all_argv) / 2; i++) {
            *argp++ = argv[i];
        }

        if(execvp(*command, (char *const *)all_argv) == -1) {
            rm_log_warning("Executed: %s ", *command);
            for(int j = 0; j < (argp - all_argv); j++) {
                rm_log_warning("%s ", all_argv[j]);
            }
            rm_log_warning("\n");
            rm_log_error_line("%s %d", g_strerror(errno), errno == ENOENT);
        } else {
            /* This is not reached anymore when execve suceeded */
            break;
        }

        /* Try next command... */
        command++;
    }
}

static int maybe_switch_to_gui(int argc, const char **argv) {
    if(g_strcmp0("--gui", argv[1]) == 0) {
        argv[1] = "shredder";
        start_gui(argc - 2, &argv[2]);

        /* We returned? Something's wrong */
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int maybe_switch_to_hasher(int argc, const char **argv) {
    if(g_strcmp0("--hash", argv[1]) == 0) {
        argv[1] = argv[0];
        exit(rm_hasher_main(argc - 1, &argv[1]));
    }
    return EXIT_SUCCESS;
}

void btrfs_clone_usage(void) {
    rm_log_error(_("Usage: rmlint --btrfs-clone source dest\n"));
}

static void btrfs_clone(const char *source, const char *dest) {
#if HAVE_BTRFS_H
    struct {
        struct btrfs_ioctl_same_args args;
        struct btrfs_ioctl_same_extent_info info;
    } extent_same;
    memset(&extent_same, 0, sizeof(extent_same));

    int source_fd = rm_sys_open(source, O_RDONLY);
    if(source_fd < 0) {
        rm_log_error_line(_("btrfs clone: failed to open source file"));
        return;
    }

    extent_same.info.fd = rm_sys_open(dest, O_RDWR);
    if(extent_same.info.fd < 0) {
        rm_log_error_line(_("btrfs clone: failed to open dest file."));
        rm_sys_close(source_fd);
        return;
    }

    struct stat source_stat;
    fstat(source_fd, &source_stat);

    guint64 bytes_deduped = 0;
    gint64 bytes_remaining = source_stat.st_size;
    int ret = 0;
    while(bytes_deduped < (guint64)source_stat.st_size && ret == 0 &&
          extent_same.info.status == 0 && bytes_remaining) {
        extent_same.args.dest_count = 1;
        extent_same.args.logical_offset = bytes_deduped;
        extent_same.info.logical_offset = bytes_deduped;

        /* BTRFS_IOC_FILE_EXTENT_SAME has an internal limit at 16MB */
        extent_same.args.length = MIN(16 * 1024 * 1024, bytes_remaining);
        if(extent_same.args.length == 0) {
            extent_same.args.length = bytes_remaining;
        }

        ret = ioctl(source_fd, BTRFS_IOC_FILE_EXTENT_SAME, &extent_same);
        if(ret == 0 && extent_same.info.status == 0) {
            bytes_deduped += extent_same.info.bytes_deduped;
            bytes_remaining -= extent_same.info.bytes_deduped;
        }
    }

    rm_sys_close(source_fd);
    rm_sys_close(extent_same.info.fd);

    if(ret < 0) {
        ret = errno;
        rm_log_error_line(_("BTRFS_IOC_FILE_EXTENT_SAME returned error: (%d) %s"), ret,
                          strerror(ret));
    } else if(extent_same.info.status == -22) {
        rm_log_error_line(
            _("BTRFS_IOC_FILE_EXTENT_SAME returned status -22 - you probably need kernel "
              "> 4.2"));
    } else if(extent_same.info.status < 0) {
        rm_log_error_line(_("BTRFS_IOC_FILE_EXTENT_SAME returned status %d for file %s"),
                          extent_same.info.status, dest);
    } else if(bytes_remaining > 0) {
        rm_log_info_line(_("Files don't match - not cloned"));
    }
#else

    (void)source;
    (void)dest;
    rm_log_error_line(_("rmlint was not compiled with btrfs support."))

#endif
}

static int maybe_btrfs_clone(int argc, const char **argv) {
    if(g_strcmp0("--btrfs-clone", argv[1]) == 0) {
        if(argc != 4) {
            btrfs_clone_usage();
            return EXIT_FAILURE;
        } else if(!rm_util_check_kernel_version(4, 2)) {
            rm_log_warning_line("This needs at least linux >= 4.2.");
            return EXIT_FAILURE;
        } else {
            btrfs_clone(argv[2], argv[3]);
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

int main(int argc, const char **argv) {
    int exit_state = EXIT_FAILURE;

    /* Check for redirect to different mains...  */
    if(maybe_switch_to_gui(argc, (const char **)argv) == EXIT_FAILURE) {
        rm_log_error_line(_("Could not start graphical user interface."));
        return EXIT_FAILURE;
    }

    if(maybe_switch_to_hasher(argc, (const char **)argv) == EXIT_FAILURE) {
        return EXIT_FAILURE;
    }

    if(maybe_btrfs_clone(argc, (const char **)argv) == EXIT_FAILURE) {
        return EXIT_FAILURE;
    }

    RmSession session;
    rm_session_init(&session);

    RmCfg cfg;
    rm_cfg_set_default(&cfg);
    session.cfg = &cfg;

    /* call logging_callback on every message */
    g_log_set_default_handler(logging_callback, &session);

    i18n_init();

    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = signal_handler;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);

#if !GLIB_CHECK_VERSION(2, 36, 0)
    /* Very old glib. Debian, Im looking at you. */
    g_type_init();
#endif

    /* Parse commandline */

    if(rm_cmd_parse_args(argc, (char **)argv, session.cfg, session.formats) != 0) {
        /* Do all the real work */
        exit_state = rm_session_run(&session);
    }

    rm_session_clear(&session);
    return exit_state;
}
