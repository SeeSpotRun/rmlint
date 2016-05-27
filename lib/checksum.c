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

#include <glib.h>
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "checksum.h"

#include "checksums/cfarmhash.h"
#include "checksums/city.h"
#include "checksums/citycrc.h"
#include "checksums/murmur3.h"
#include "checksums/spooky-c.h"
#include "checksums/xxhash/xxhash.h"

#include "utilities.h"

#define _RM_CHECKSUM_DEBUG 0

///////////////////////////////////////
//    BUFFER POOL IMPLEMENTATION     //
///////////////////////////////////////

RmOff rm_buffer_size(RmBufferPool *pool) {
    return pool->buffer_size;
}

static RmBuffer *rm_buffer_new(RmBufferPool *pool) {
    RmBuffer *self = g_slice_new0(RmBuffer);
    self->pool = pool;
    self->data = g_slice_alloc(pool->buffer_size);
    return self;
}

static void rm_buffer_free(RmBuffer *buf) {
    g_slice_free1(buf->pool->buffer_size, buf->data);
    g_slice_free(RmBuffer, buf);
}

RmBufferPool *rm_buffer_pool_init(gsize buffer_size, gsize max_mem) {
    RmBufferPool *self = g_slice_new0(RmBufferPool);
    self->buffer_size = buffer_size;
    self->avail_buffers = max_mem ? MAX(max_mem / buffer_size, 1) : (gsize)-1;

    g_cond_init(&self->change);
    g_mutex_init(&self->lock);
    return self;
}

void rm_buffer_pool_destroy(RmBufferPool *pool) {
    g_slist_free_full(pool->stack, (GDestroyNotify)rm_buffer_free);

    g_mutex_clear(&pool->lock);
    g_cond_clear(&pool->change);
    g_slice_free(RmBufferPool, pool);
}

RmBuffer *rm_buffer_get(RmBufferPool *pool) {
    RmBuffer *buffer = NULL;
    g_mutex_lock(&pool->lock);
    {
        while(!buffer) {
            buffer = rm_util_slist_pop(&pool->stack, NULL);
            if(!buffer && pool->avail_buffers > 0) {
                buffer = rm_buffer_new(pool);
            }
            if(!buffer) {
                if(!pool->mem_warned) {
                    rm_log_warning_line(
                        "read buffer limit reached - waiting for "
                        "processing to catch up");
                    pool->mem_warned = true;
                }
                g_cond_wait(&pool->change, &pool->lock);
            }
        }
        pool->avail_buffers--;
    }
    g_mutex_unlock(&pool->lock);

    rm_assert_gentle(buffer);
    buffer->user_data = NULL;
    buffer->len = 0;
    return buffer;
}

void rm_buffer_release(RmBuffer *buf) {
    RmBufferPool *pool = buf->pool;
    g_mutex_lock(&pool->lock);
    {
        pool->avail_buffers++;
        g_cond_signal(&pool->change);
        pool->stack = g_slist_prepend(pool->stack, buf);
    }
    g_mutex_unlock(&pool->lock);
}

static gboolean rm_buffer_equal(RmBuffer *a, RmBuffer *b) {
    return (a->len == b->len && memcmp(a->data, b->data, a->len) == 0);
}

///////////////////////////////////////
//      RMDIGEST IMPLEMENTATION      //
///////////////////////////////////////

RmDigestType rm_string_to_digest_type(const char *string) {
    if(string == NULL) {
        return RM_DIGEST_UNKNOWN;
    } else if(!strcasecmp(string, "md5")) {
        return RM_DIGEST_MD5;
#if HAVE_SHA512
    } else if(!strcasecmp(string, "sha512")) {
        return RM_DIGEST_SHA512;
#endif
    } else if(!strcasecmp(string, "city512")) {
        return RM_DIGEST_CITY512;
    } else if(!strcasecmp(string, "xxhash")) {
        return RM_DIGEST_XXHASH;
    } else if(!strcasecmp(string, "farmhash")) {
        return RM_DIGEST_XXHASH;
    } else if(!strcasecmp(string, "murmur512")) {
        return RM_DIGEST_MURMUR512;
    } else if(!strcasecmp(string, "sha256")) {
        return RM_DIGEST_SHA256;
    } else if(!strcasecmp(string, "city256")) {
        return RM_DIGEST_CITY256;
    } else if(!strcasecmp(string, "murmur256")) {
        return RM_DIGEST_MURMUR256;
    } else if(!strcasecmp(string, "sha1")) {
        return RM_DIGEST_SHA1;
    } else if(!strcasecmp(string, "spooky32")) {
        return RM_DIGEST_SPOOKY32;
    } else if(!strcasecmp(string, "spooky64")) {
        return RM_DIGEST_SPOOKY64;
    } else if(!strcasecmp(string, "murmur") || !strcasecmp(string, "murmur128")) {
        return RM_DIGEST_MURMUR;
    } else if(!strcasecmp(string, "spooky") || !strcasecmp(string, "spooky128")) {
        return RM_DIGEST_SPOOKY;
    } else if(!strcasecmp(string, "city") || !strcasecmp(string, "city128")) {
        return RM_DIGEST_CITY;
    } else if(!strcasecmp(string, "bastard") || !strcasecmp(string, "bastard256")) {
        return RM_DIGEST_BASTARD;
    } else if(!strcasecmp(string, "ext")) {
        return RM_DIGEST_EXT;
    } else if(!strcasecmp(string, "cumulative")) {
        return RM_DIGEST_CUMULATIVE;
    } else if(!strcasecmp(string, "paranoid")) {
        return RM_DIGEST_PARANOID;
    } else {
        return RM_DIGEST_UNKNOWN;
    }
}

const char *rm_digest_type_to_string(RmDigestType type) {
    static const char *names[] = {[RM_DIGEST_UNKNOWN] = "unknown",
                                  [RM_DIGEST_MURMUR] = "murmur",
                                  [RM_DIGEST_SPOOKY] = "spooky",
                                  [RM_DIGEST_SPOOKY32] = "spooky32",
                                  [RM_DIGEST_SPOOKY64] = "spooky64",
                                  [RM_DIGEST_CITY] = "city",
                                  [RM_DIGEST_MD5] = "md5",
                                  [RM_DIGEST_SHA1] = "sha1",
                                  [RM_DIGEST_SHA256] = "sha256",
                                  [RM_DIGEST_SHA512] = "sha512",
                                  [RM_DIGEST_MURMUR256] = "murmur256",
                                  [RM_DIGEST_CITY256] = "city256",
                                  [RM_DIGEST_BASTARD] = "bastard",
                                  [RM_DIGEST_MURMUR512] = "murmur512",
                                  [RM_DIGEST_CITY512] = "city512",
                                  [RM_DIGEST_EXT] = "ext",
                                  [RM_DIGEST_CUMULATIVE] = "cumulative",
                                  [RM_DIGEST_PARANOID] = "paranoid",
                                  [RM_DIGEST_FARMHASH] = "farmhash",
                                  [RM_DIGEST_XXHASH] = "xxhash"};

    return names[MIN(type, sizeof(names) / sizeof(names[0]))];
}

int rm_digest_type_to_multihash_id(RmDigestType type) {
    static int ids[] = {[RM_DIGEST_UNKNOWN] = -1,  [RM_DIGEST_MURMUR] = 17,
                        [RM_DIGEST_SPOOKY] = 14,   [RM_DIGEST_SPOOKY32] = 16,
                        [RM_DIGEST_SPOOKY64] = 18, [RM_DIGEST_CITY] = 15,
                        [RM_DIGEST_MD5] = 1,       [RM_DIGEST_SHA1] = 2,
                        [RM_DIGEST_SHA256] = 4,    [RM_DIGEST_SHA512] = 6,
                        [RM_DIGEST_MURMUR256] = 7, [RM_DIGEST_CITY256] = 8,
                        [RM_DIGEST_BASTARD] = 9,   [RM_DIGEST_MURMUR512] = 10,
                        [RM_DIGEST_CITY512] = 11,  [RM_DIGEST_EXT] = 12,
                        [RM_DIGEST_FARMHASH] = 19, [RM_DIGEST_CUMULATIVE] = 13,
                        [RM_DIGEST_PARANOID] = 14};

    return ids[MIN(type, sizeof(ids) / sizeof(ids[0]))];
}

#define ADD_SEED(digest, seed)                                              \
    {                                                                       \
        if(seed) {                                                          \
            g_checksum_update(digest->glib_checksum, (const guchar *)&seed, \
                              sizeof(RmOff));                               \
        }                                                                   \
    }

RmDigest *rm_digest_new(RmDigestType type, RmOff seed1, RmOff seed2, RmOff ext_size,
                        bool use_shadow_hash) {
    RmDigest *digest = g_slice_new0(RmDigest);

    digest->checksum = NULL;
    digest->type = type;
    digest->bytes = 0;

    switch(type) {
    case RM_DIGEST_SPOOKY32:
        /* cannot go lower than 64, since we read 8 byte in some places.
         * simulate by leaving the part at the end empty
         */
        digest->bytes = 64 / 8;
        break;
    case RM_DIGEST_XXHASH:
    case RM_DIGEST_FARMHASH:
    case RM_DIGEST_SPOOKY64:
        digest->bytes = 64 / 8;
        break;
    case RM_DIGEST_MD5:
        digest->glib_checksum = g_checksum_new(G_CHECKSUM_MD5);
        ADD_SEED(digest, seed1);
        digest->bytes = 128 / 8;
        return digest;
#if HAVE_SHA512
    case RM_DIGEST_SHA512:
        digest->glib_checksum = g_checksum_new(G_CHECKSUM_SHA512);
        ADD_SEED(digest, seed1);
        digest->bytes = 512 / 8;
        return digest;
#endif
    case RM_DIGEST_SHA256:
        digest->glib_checksum = g_checksum_new(G_CHECKSUM_SHA256);
        ADD_SEED(digest, seed1);
        digest->bytes = 256 / 8;
        return digest;
    case RM_DIGEST_SHA1:
        digest->glib_checksum = g_checksum_new(G_CHECKSUM_SHA1);
        ADD_SEED(digest, seed1);
        digest->bytes = 160 / 8;
        return digest;
    case RM_DIGEST_MURMUR512:
    case RM_DIGEST_CITY512:
        digest->bytes = 512 / 8;
        break;
    case RM_DIGEST_EXT:
        /* gets allocated on rm_digest_update() */
        digest->bytes = ext_size;
        break;
    case RM_DIGEST_MURMUR256:
    case RM_DIGEST_CITY256:
    case RM_DIGEST_BASTARD:
        digest->bytes = 256 / 8;
        break;
    case RM_DIGEST_SPOOKY:
    case RM_DIGEST_MURMUR:
    case RM_DIGEST_CITY:
    case RM_DIGEST_CUMULATIVE:
        digest->bytes = 128 / 8;
        break;
    case RM_DIGEST_PARANOID:
        digest->bytes = 0;
        digest->paranoid = g_slice_new0(RmParanoid);
        if(use_shadow_hash) {
            digest->paranoid->shadow_hash =
                rm_digest_new(RM_DIGEST_XXHASH, seed1, seed2, 0, false);
        }
        break;
    default:
        rm_assert_gentle_not_reached();
    }

    /* starting values to let us generate up to 4 different hashes in parallel with
     * different starting seeds:
     * */
    static const RmOff seeds[4] = {0x0000000000000000, 0xf0f0f0f0f0f0f0f0,
                                   0x3333333333333333, 0xaaaaaaaaaaaaaaaa};

    if(digest->bytes > 0 && type != RM_DIGEST_PARANOID) {
        const int n_seeds = sizeof(seeds) / sizeof(seeds[0]);

        /* checksum type - allocate memory and initialise */
        digest->checksum = g_slice_alloc0(digest->bytes);
        for(gsize block = 0; block < (digest->bytes / 16); block++) {
            digest->checksum[block].first = seeds[block % n_seeds] ^ seed1;
            digest->checksum[block].second = seeds[block % n_seeds] ^ seed2;
        }
    }

    if(digest->type == RM_DIGEST_BASTARD) {
        /* bastard type *always* has *pure* murmur hash for first checksum
         * and seeded city for second checksum */
        digest->checksum[0].first = digest->checksum[0].second = 0;
    }
    return digest;
}

void rm_digest_paranoia_shrink(RmDigest *digest, gsize new_size) {
    rm_assert_gentle(digest->type == RM_DIGEST_PARANOID);
    digest->bytes = new_size;
}

void rm_digest_free(RmDigest *digest) {
    switch(digest->type) {
    case RM_DIGEST_MD5:
    case RM_DIGEST_SHA512:
    case RM_DIGEST_SHA256:
    case RM_DIGEST_SHA1:
        g_checksum_free(digest->glib_checksum);
        digest->glib_checksum = NULL;
        break;
    case RM_DIGEST_PARANOID:
        if(digest->paranoid->shadow_hash) {
            rm_digest_free(digest->paranoid->shadow_hash);
        }
        g_slist_free_full(digest->paranoid->buffers, (GDestroyNotify)rm_buffer_release);
        g_slice_free(RmParanoid, digest->paranoid);
        break;
    case RM_DIGEST_EXT:
    case RM_DIGEST_CUMULATIVE:
    case RM_DIGEST_MURMUR512:
    case RM_DIGEST_XXHASH:
    case RM_DIGEST_CITY512:
    case RM_DIGEST_MURMUR256:
    case RM_DIGEST_CITY256:
    case RM_DIGEST_BASTARD:
    case RM_DIGEST_SPOOKY:
    case RM_DIGEST_SPOOKY32:
    case RM_DIGEST_SPOOKY64:
    case RM_DIGEST_FARMHASH:
    case RM_DIGEST_MURMUR:
    case RM_DIGEST_CITY:
        if(digest->checksum) {
            g_slice_free1(digest->bytes, digest->checksum);
            digest->checksum = NULL;
        }
        break;
    default:
        rm_assert_gentle_not_reached();
    }
    g_slice_free(RmDigest, digest);
}

void rm_digest_update(RmDigest *digest, const unsigned char *data, RmOff size) {
    switch(digest->type) {
    case RM_DIGEST_EXT:
/* Data is assumed to be a hex representation of a cchecksum.
 * Needs to be compressed in pure memory first.
 *
 * Checksum is not updated but rather overwritten.
 * */
#define CHAR_TO_NUM(c) (unsigned char)(g_ascii_isdigit(c) ? c - '0' : (c - 'a') + 10)

        rm_assert_gentle(data);

        digest->bytes = size / 2;
        digest->checksum = g_slice_alloc0(digest->bytes);

        for(unsigned i = 0; i < digest->bytes; ++i) {
            ((guint8 *)digest->checksum)[i] =
                (CHAR_TO_NUM(data[2 * i]) << 4) + CHAR_TO_NUM(data[2 * i + 1]);
        }

        break;
    case RM_DIGEST_MD5:
    case RM_DIGEST_SHA512:
    case RM_DIGEST_SHA256:
    case RM_DIGEST_SHA1:
        g_checksum_update(digest->glib_checksum, (const guchar *)data, size);
        break;
    case RM_DIGEST_SPOOKY32:
        digest->checksum[0].first = spooky_hash32(data, size, digest->checksum[0].first);
        break;
    case RM_DIGEST_SPOOKY64:
        digest->checksum[0].first = spooky_hash64(data, size, digest->checksum[0].first);
        break;
    case RM_DIGEST_SPOOKY:
        spooky_hash128(data, size, (uint64_t *)&digest->checksum[0].first,
                       (uint64_t *)&digest->checksum[0].second);
        break;
    case RM_DIGEST_XXHASH:
        digest->checksum[0].first = XXH64(data, size, digest->checksum[0].first);
        break;
    case RM_DIGEST_FARMHASH:
        digest->checksum[0].first = cfarmhash((const char *)data, size);
        break;
    case RM_DIGEST_MURMUR512:
    case RM_DIGEST_MURMUR256:
    case RM_DIGEST_MURMUR:
        for(guint8 block = 0; block < (digest->bytes / 16); block++) {
#if RM_PLATFORM_32
            MurmurHash3_x86_128(data, size, (uint32_t)digest->checksum[block].first,
                                &digest->checksum[block]);  //&
#elif RM_PLATFORM_64
            MurmurHash3_x64_128(data, size, (uint32_t)digest->checksum[block].first,
                                &digest->checksum[block]);
#else
#error "Probably not a good idea to compile rmlint on 16bit."
#endif
        }
        break;
    case RM_DIGEST_CITY:
    case RM_DIGEST_CITY256:
    case RM_DIGEST_CITY512:
        for(guint8 block = 0; block < (digest->bytes / 16); block++) {
            /* Opt out for the more optimized version.
            * This needs the crc command of sse4.2
            * (available on Intel Nehalem and up; my amd box doesn't have this though)
            */
            uint128 old = {digest->checksum[block].first, digest->checksum[block].second};
            old = CityHash128WithSeed((const char *)data, size, old);
            memcpy(&digest->checksum[block], &old, sizeof(uint128));
        }
        break;
    case RM_DIGEST_BASTARD:
        MurmurHash3_x86_128(data, size, (uint32_t)digest->checksum[0].first,
                            &digest->checksum[0]);

        uint128 old = {digest->checksum[1].first, digest->checksum[1].second};
        old = CityHash128WithSeed((const char *)data, size, old);
        memcpy(&digest->checksum[1], &old, sizeof(uint128));
        break;
    case RM_DIGEST_CUMULATIVE: {
        /* This is basically FNV1a, it is just important that the order of
         * adding data to the hash has no effect on the result, so it can
         * be used as a lookup key:
         *
         * http://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
         * */
        RmOff hash = 0xcbf29ce484222325;
        for(gsize i = 0; i < digest->bytes; ++i) {
            hash ^= ((guint8 *)data)[i % size];
            hash *= 0x100000001b3;
            ((guint8 *)digest->checksum)[i] += hash;
        }
    } break;
    case RM_DIGEST_PARANOID:
    default:
        rm_assert_gentle_not_reached();
    }
}

void rm_digest_buffered_update(RmBuffer *buffer) {
    RmDigest *digest = buffer->digest;
    if(digest->type != RM_DIGEST_PARANOID) {
        rm_digest_update(digest, buffer->data, buffer->len);
        rm_buffer_release(buffer);
    } else {
        RmParanoid *paranoid = digest->paranoid;

        /* efficiently append buffer to buffers GSList */
        if(!paranoid->buffers) {
            /* first buffer */
            paranoid->buffers = g_slist_prepend(NULL, buffer);
            paranoid->buffer_tail = paranoid->buffers;
        } else {
            paranoid->buffer_tail = g_slist_append(paranoid->buffer_tail, buffer)->next;
        }

        digest->bytes += buffer->len;

        if(paranoid->shadow_hash) {
            rm_digest_update(paranoid->shadow_hash, buffer->data, buffer->len);
        }
    }
}

RmDigest *rm_digest_copy(RmDigest *digest) {
    rm_assert_gentle(digest);

    RmDigest *self = NULL;

    switch(digest->type) {
    case RM_DIGEST_MD5:
    case RM_DIGEST_SHA512:
    case RM_DIGEST_SHA256:
    case RM_DIGEST_SHA1:
        self = g_slice_new0(RmDigest);
        self->bytes = digest->bytes;
        self->type = digest->type;
        self->glib_checksum = g_checksum_copy(digest->glib_checksum);
        break;
    case RM_DIGEST_SPOOKY:
    case RM_DIGEST_SPOOKY32:
    case RM_DIGEST_SPOOKY64:
    case RM_DIGEST_MURMUR:
    case RM_DIGEST_CITY:
    case RM_DIGEST_CITY256:
    case RM_DIGEST_MURMUR256:
    case RM_DIGEST_CITY512:
    case RM_DIGEST_MURMUR512:
    case RM_DIGEST_XXHASH:
    case RM_DIGEST_FARMHASH:
    case RM_DIGEST_BASTARD:
    case RM_DIGEST_CUMULATIVE:
    case RM_DIGEST_EXT:
        self = rm_digest_new(digest->type, 0, 0, digest->bytes, FALSE);

        if(self->checksum && digest->checksum) {
            memcpy((char *)self->checksum, (char *)digest->checksum, self->bytes);
        }

        break;
    case RM_DIGEST_PARANOID:
        /* this is a bit hacky but we basically take over 'digest's
         * data and reset 'digest' to zero */
        self = g_slice_new0(RmDigest);
        self->type = RM_DIGEST_PARANOID;
        self->paranoid = digest->paranoid;
        self->bytes = digest->bytes;
        digest->bytes = 0;
        digest->paranoid = g_slice_new0(RmParanoid);
        if(self->paranoid->shadow_hash) {
            digest->paranoid->shadow_hash = rm_digest_copy(self->paranoid->shadow_hash);
        }
        break;
    default:
        rm_assert_gentle_not_reached();
    }

    return self;
}

static gboolean rm_digest_needs_steal(RmDigestType digest_type) {
    switch(digest_type) {
    case RM_DIGEST_MD5:
    case RM_DIGEST_SHA512:
    case RM_DIGEST_SHA256:
    case RM_DIGEST_SHA1:
        /* for all of the above, reading the digest is destructive, so we
         * need to take a copy */
        return TRUE;
    case RM_DIGEST_SPOOKY32:
    case RM_DIGEST_SPOOKY64:
    case RM_DIGEST_SPOOKY:
    case RM_DIGEST_MURMUR:
    case RM_DIGEST_CITY:
    case RM_DIGEST_CITY256:
    case RM_DIGEST_CITY512:
    case RM_DIGEST_XXHASH:
    case RM_DIGEST_FARMHASH:
    case RM_DIGEST_MURMUR256:
    case RM_DIGEST_MURMUR512:
    case RM_DIGEST_BASTARD:
    case RM_DIGEST_CUMULATIVE:
    case RM_DIGEST_EXT:
    case RM_DIGEST_PARANOID:
        return FALSE;
    default:
        rm_assert_gentle_not_reached();
        return FALSE;
    }
}

RmDigestSum *rm_digest_sum(RmDigest *digest) {
    RmDigestSum *sum = g_slice_new(RmDigestSum);
    sum->type = digest->type;
    sum->bytes = digest->bytes;
    if(digest->type == RM_DIGEST_PARANOID) {
        sum->buffers = digest->paranoid->buffers;
        digest->paranoid->buffers = NULL;
        digest->paranoid->buffer_tail = NULL;
    } else {
        sum->sum = g_slice_alloc0(digest->bytes);
        if(rm_digest_needs_steal(digest->type)) {
            /* reading the digest is destructive, so we need to take a copy */
            RmDigest *copy = rm_digest_copy(digest);
            g_checksum_get_digest(copy->glib_checksum, sum->sum, &sum->bytes);
            rm_assert_gentle(sum->bytes == digest->bytes);
            rm_digest_free(copy);
        } else {
            memcpy(sum->sum, digest->checksum, digest->bytes);
        }
    }
    return sum;
}

void rm_digest_sum_free(RmDigestSum *sum) {
    if(sum->type == RM_DIGEST_PARANOID) {
        g_slist_free_full(sum->buffers, (GDestroyNotify)rm_buffer_release);
    } else {
        g_slice_free1(sum->bytes, sum->sum);
    }
    g_slice_free(RmDigestSum, sum);
}

gboolean rm_digest_sum_equal(RmDigestSum *a, RmDigestSum *b) {
    if(a->type != b->type) {
        return FALSE;
    }
    if(a->bytes != b->bytes) {
        return FALSE;
    }
    if(a->type == RM_DIGEST_PARANOID) {
        /* assumes all buffers have same length */
        for(GSList *ia = a->buffers, *ib = b->buffers; ia && ib;
            ia = ia->next, ib = ib->next) {
            if(!rm_buffer_equal(ia->data, ib->data)) {
                return FALSE;
            }
        }
        return TRUE;
    } else {
        return !memcmp(a->sum, b->sum, a->bytes);
    }
}

guint rm_digest_hash(RmDigest *digest) {
    RmDigestSum *sum = NULL;
    guint hash = 0;

    if(digest->type == RM_DIGEST_PARANOID) {
        if(digest->paranoid->shadow_hash) {
            sum = rm_digest_sum(digest->paranoid->shadow_hash);
        } else {
            /* steal the first few bytes of the first buffer */
            if(digest->paranoid->buffers) {
                RmBuffer *buffer = digest->paranoid->buffers->data;
                if(buffer->len >= sizeof(guint)) {
                    hash = *(guint *)buffer->data;
                    return hash;
                }
            }
        }
    } else {
        sum = rm_digest_sum(digest);
    }

    if(sum != NULL) {
        rm_assert_gentle(sum->bytes >= sizeof(guint));
        hash = *(guint *)sum->sum;
        rm_digest_sum_free(sum);
    }
    return hash;
}

gboolean rm_digest_equal(RmDigest *a, RmDigest *b) {
    rm_assert_gentle(a && b);

    if(a->type != b->type) {
        return false;
    }

    if(a->bytes != b->bytes) {
        return false;
    }

    if(a->type == RM_DIGEST_PARANOID) {
        if(!a->paranoid->buffers) {
            /* buffers have been freed so we need to rely on shadow hash */
            rm_assert_gentle(a->paranoid->shadow_hash);
            rm_assert_gentle(b->paranoid->shadow_hash);
            return rm_digest_equal(a->paranoid->shadow_hash, b->paranoid->shadow_hash);
        }
        /* all the "easy" ways failed... do manual check of all buffers */
        GSList *a_iter = a->paranoid->buffers;
        GSList *b_iter = b->paranoid->buffers;
        guint bytes = 0;
        while(a_iter && b_iter) {
            if(!rm_buffer_equal(a_iter->data, b_iter->data)) {
                if(a->paranoid->shadow_hash &&
                   rm_digest_equal(a->paranoid->shadow_hash, b->paranoid->shadow_hash)) {
                    rm_log_warning_line("Hash collision in shadow hash (wow!)");
                }
                return false;
            }
            bytes += ((RmBuffer *)a_iter->data)->len;
            a_iter = a_iter->next;
            b_iter = b_iter->next;
        }

        return (!a_iter && !b_iter && bytes == a->bytes);

    } else if(rm_digest_needs_steal(a->type)) {
        RmDigestSum *sum_a = rm_digest_sum(a);
        RmDigestSum *sum_b = rm_digest_sum(b);

        gboolean result = rm_digest_sum_equal(sum_a, sum_b);

        rm_digest_sum_free(sum_a);
        rm_digest_sum_free(sum_b);
        return result;
    } else {
        return !memcmp(a->checksum, b->checksum, MIN(a->bytes, b->bytes));
    }
}

int rm_digest_hexstring(RmDigest *digest, char *buffer) {
    if(digest == NULL) {
        return 0;
    }

    static const char *hex = "0123456789abcdef";
    RmDigestSum *sum = NULL;

    if(digest->type == RM_DIGEST_PARANOID) {
        if(digest->paranoid->shadow_hash) {
            sum = rm_digest_sum(digest->paranoid->shadow_hash);
        } else {
            return 0;
        }
    } else {
        sum = rm_digest_sum(digest);
    }
    int bytes = sum->bytes;
    for(int i = 0; i < bytes; ++i) {
        buffer[0] = hex[sum->sum[i] / 16];
        buffer[1] = hex[sum->sum[i] % 16];

        if(i == bytes - 1) {
            buffer[2] = '\0';
        }

        buffer += 2;
    }

    rm_digest_sum_free(sum);
    return bytes * 2 + 1;
}

int rm_digest_get_bytes(RmDigest *self) {
    if(self == NULL) {
        return 0;
    }

    if(self->type != RM_DIGEST_PARANOID) {
        return self->bytes;
    } else if(self->paranoid->shadow_hash) {
        return self->paranoid->shadow_hash->bytes;
    } else {
        return 0;
    }
}
