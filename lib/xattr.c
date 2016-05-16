/**
* This file is part of rmlint.
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
**/

#include "xattr.h"
#include "config.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>

#if HAVE_XATTR
#include <sys/xattr.h>
#endif

#ifndef ENODATA
#define ENODATA ENOMSG
#endif

////////////////////////////
//    UTILITY FUNCTIONS   //
////////////////////////////

#if HAVE_XATTR

/* Compat wrappers for MacOSX and other platforms.
 */

#if RM_IS_APPLE

ssize_t rm_sys_getxattr(const char *path, const char *name, void *value, size_t size) {
    return getxattr(path, name, value, size, 0, 0);
}

ssize_t rm_sys_setxattr(
    const char *path, const char *name, const void *value, size_t size, int flags) {
    return setxattr(path, name, value, size, 0, flags);
}

int rm_sys_removexattr(const char *path, const char *name) {
    return removexattr(path, name, 0);
}

#else

ssize_t rm_sys_getxattr(const char *path, const char *name, void *value, size_t size) {
    return getxattr(path, name, value, size);
}

ssize_t rm_sys_setxattr(
    const char *path, const char *name, const void *value, size_t size, int flags) {
    return setxattr(path, name, value, size, flags);
}

int rm_sys_removexattr(const char *path, const char *name) {
    return removexattr(path, name);
}

#endif

static int rm_xattr_build_key(RmCfg *cfg,
                              const char *suffix,
                              char *buf,
                              size_t buf_size) {
    rm_assert_gentle(cfg);

    /* Be safe, assume caller is not concentrated. */
    memset(buf, 0, sizeof(buf_size));

    const char *digest_name = rm_digest_type_to_string(cfg->checksum_type);
    if(cfg->checksum_type == RM_DIGEST_PARANOID) {
        digest_name = rm_digest_type_to_string(RM_DEFAULT_DIGEST);
    }

    return snprintf(buf, buf_size, "user.rmlint.%s.%s", digest_name, suffix) < 0;
}

static int rm_xattr_build_cksum(RmFile *file, char *buf, size_t buf_size) {
    rm_assert_gentle(file);
    rm_assert_gentle(file->digest);

    memset(buf, '0', buf_size);
    buf[buf_size - 1] = 0;

    if(file->digest->type == RM_DIGEST_PARANOID) {
        rm_assert_gentle(file->digest->paranoid->shadow_hash);
        return rm_digest_hexstring(file->digest->paranoid->shadow_hash, buf);
    } else {
        return rm_digest_hexstring(file->digest, buf);
    }
}

static int rm_xattr_is_fail(const char *name, int rc) {
    if(rc != -1) {
        return 0;
    }

    if(errno != ENOTSUP && errno != ENODATA) {
        rm_log_perror(name);
        return errno;
    }

    return 0;
}

static int rm_xattr_set(RmFile *file,
                        const char *key,
                        const char *value,
                        size_t value_size) {
    RM_DEFINE_PATH(file);
    return rm_xattr_is_fail("setxattr",
                            rm_sys_setxattr(file_path, key, value, value_size, 0));
}

static int rm_xattr_get(RmFile *file,
                        const char *key,
                        char *out_value,
                        size_t value_size) {
    RM_DEFINE_PATH(file);

    return rm_xattr_is_fail("getxattr",
                            rm_sys_getxattr(file_path, key, out_value, value_size));
}

static int rm_xattr_del(RmFile *file, const char *key) {
    RM_DEFINE_PATH(file);
    return rm_xattr_is_fail("removexattr", rm_sys_removexattr(file_path, key));
}

#endif

////////////////////////////
//  ACTUAL API FUNCTIONS  //
////////////////////////////

int rm_xattr_write_hash(RmCfg *cfg, RmFile *file) {
    rm_assert_gentle(file);
    rm_assert_gentle(file->digest);
    rm_assert_gentle(cfg);

#if HAVE_XATTR
    if(file->has_ext_cksum || cfg->write_cksum_to_xattr == false) {
        return EINVAL;
    }

    char cksum_key[64], mtime_key[64],
        cksum_hex_str[rm_digest_get_bytes(file->digest) * 2 + 1], timestamp[64] = {0};

    int timestamp_bytes = 0;
    double actual_time_sec = difftime(file->mtime, 0);

    if(rm_xattr_build_key(cfg, "cksum", cksum_key, sizeof(cksum_key)) ||
       rm_xattr_build_key(cfg, "mtime", mtime_key, sizeof(mtime_key)) ||
       rm_xattr_build_cksum(file, cksum_hex_str, sizeof(cksum_hex_str)) <= 0 ||
       rm_xattr_set(file, cksum_key, cksum_hex_str, sizeof(cksum_hex_str)) ||
       (timestamp_bytes = snprintf(
            timestamp, sizeof(timestamp), "%lld", (long long)actual_time_sec)) == -1 ||
       rm_xattr_set(file, mtime_key, timestamp, timestamp_bytes)) {
        return errno;
    }
#endif
    return 0;
}

char *rm_xattr_read_hash(RmCfg *cfg, RmFile *file) {
    rm_assert_gentle(file);
    rm_assert_gentle(cfg);

#if HAVE_XATTR
    if(cfg->read_cksum_from_xattr == false) {
        return NULL;
    }

    char cksum_key[64] = {0}, mtime_key[64] = {0}, mtime_buf[64] = {0},
         cksum_hex_str[512] = {0};

    memset(cksum_hex_str, '0', sizeof(cksum_hex_str));
    cksum_hex_str[sizeof(cksum_hex_str) - 1] = 0;

    if(0 || rm_xattr_build_key(cfg, "cksum", cksum_key, sizeof(cksum_key)) ||
       rm_xattr_get(file, cksum_key, cksum_hex_str, sizeof(cksum_hex_str) - 1) ||
       rm_xattr_build_key(cfg, "mtime", mtime_key, sizeof(mtime_key)) ||
       rm_xattr_get(file, mtime_key, mtime_buf, sizeof(mtime_buf) - 1)) {
        return NULL;
    }

    if(g_ascii_strtoll(mtime_buf, NULL, 10) < file->mtime) {
        /* Data is too old and not useful, autoclean it */
        rm_xattr_clear_hash(cfg, file);
        return NULL;
    }

    /* remember, this file is special. A unicorn amongst files. */
    file->has_ext_cksum = true;

    return g_strdup(cksum_hex_str);
#else
    return NULL;
#endif
}

int rm_xattr_clear_hash(RmCfg *cfg, RmFile *file) {
    rm_assert_gentle(file);
    rm_assert_gentle(cfg);

#if HAVE_XATTR
    int error = 0;
    const char *keys[] = {"cksum", "mtime", NULL};

    for(int i = 0; keys[i]; ++i) {
        char key[64] = {0};

        if(rm_xattr_build_key(cfg, keys[i], key, sizeof(key))) {
            error = EINVAL;
            continue;
        }

        if(rm_xattr_del(file, key)) {
            error = errno;
        }
    }

    return error;
#else
    return EXIT_FAILURE;
#endif
}
