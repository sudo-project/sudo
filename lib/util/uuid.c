/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2020 Todd C. Miller <Todd.Miller@sudo.ws>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <stdlib.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <string.h>
#include <arpa/inet.h>

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_rand.h"

struct uuid {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_high_and_version;
    uint16_t clock_seq_and_variant;
    unsigned char node[6];
};

/*
 * Create a type 4 (random), variant 1 universally unique identifier (UUID).
 */
void
sudo_uuid_create_v1(unsigned char uuid_out[16])
{
    union {
	struct uuid id;
	unsigned char u8[16];
    } uuid;

    arc4random_buf(&uuid, sizeof(uuid));

    /* Convert fields to host by order. */
    uuid.id.time_low = ntohl(uuid.id.time_low);
    uuid.id.time_mid = ntohs(uuid.id.time_mid);
    uuid.id.time_high_and_version = ntohs(uuid.id.time_high_and_version);
    uuid.id.clock_seq_and_variant = ntohs(uuid.id.clock_seq_and_variant);

    /* Set version to 4 (random) in the high nibble. */
    uuid.id.time_high_and_version &= 0x0fff;
    uuid.id.time_high_and_version |= 0x4000;

    /* Set variant to 1 (first two bits are 10) */
    uuid.id.clock_seq_and_variant &= 0x3fff;
    uuid.id.clock_seq_and_variant |= 0x8000;

    /* Store fields in network byte order (big endian). */
    uuid.id.time_low = htonl(uuid.id.time_low);
    uuid.id.time_mid = htons(uuid.id.time_mid);
    uuid.id.time_high_and_version = htons(uuid.id.time_high_and_version);
    uuid.id.clock_seq_and_variant = htons(uuid.id.clock_seq_and_variant);
    memcpy(uuid_out, &uuid, 16);
}

/*
 * Format a uuid as a 36-byte string (plus one for the NUL).
 */
char *
sudo_uuid_to_string_v1(unsigned char uuid[16], char *dst, size_t dstsiz)
{
    const char hex[] = "0123456789abcdef";
    char *cp = dst;
    int i;

    if (dstsiz < sizeof("123e4567-e89b-12d3-a456-426655440000"))
	return NULL;

    for (i = 0; i < 16; i++) {
	*cp++ = hex[uuid[i] >> 4];
	*cp++ = hex[uuid[i] & 0x0f];

	switch (i) {
	case 4:
	case 6:
	case 8:
	case 10:
	    *cp++ = '-';
	    break;
	}
    }
    *cp = '\0';

    return dst;
}
