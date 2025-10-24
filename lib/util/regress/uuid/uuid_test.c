/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2021, 2025 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <config.h>

#include <stdlib.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SUDO_ERROR_WRAP 0

#include <sudo_compat.h>
#include <sudo_fatal.h>
#include <sudo_util.h>

sudo_dso_public int main(int argc, char *argv[]);

/*
 * Test that sudo_uuid_create() generates a variant 1, version 4 uuid.
 */

/* From RFC 4122. */
struct uuid {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq_hi_and_reserved;
    uint8_t clock_seq_low;
    uint8_t node[6];
};

int
main(int argc, char *argv[])
{
    int ch, errors = 0, ntests = 0;
    union {
        struct uuid id;
        unsigned char u8[16];
    } uuid;

    initprogname(argc > 0 ? argv[0] : "uuid_test");

    while ((ch = getopt(argc, argv, "v")) != -1) {
	switch (ch) {
	case 'v':
	    /* ignore */
	    break;
	default:
	    fprintf(stderr, "usage: %s [-v]\n", getprogname());
	    return EXIT_FAILURE;
	}
    }
    argc -= optind;
    argv += optind;

    /* Do 16 passes. */
    for (ntests = 0; ntests < 16; ntests++) {
	uint16_t time_hi_and_version;
	unsigned char uuid_buf[16];
	char uuid_str[37];

	sudo_uuid_create(uuid.u8);

	/* Variant: two most significant bits (6 and 7) are 0 and 1. */
	if (ISSET(uuid.id.clock_seq_hi_and_reserved, (1 << 6))) {
	    sudo_warnx("uuid bit 6 set, should be clear");
	    errors++;
	    continue;
	}
	if (!ISSET(uuid.id.clock_seq_hi_and_reserved, (1 << 7))) {
	    sudo_warnx("uuid bit 7 clear, should be set");
	    errors++;
	    continue;
	}

	/* Version: bits 12-15 are 0010. */
	time_hi_and_version = ntohs(uuid.id.time_hi_and_version);
	if ((time_hi_and_version & 0xf000) != 0x4000) {
	    sudo_warnx("bad version: 0x%x", (unsigned int)time_hi_and_version);
	    errors++;
	    continue;
	}

	/* Test round-tripping uuid -> string -> uuid */
	if (sudo_uuid_to_string(uuid.u8, uuid_str, sizeof(uuid_str)) == NULL) {
	    sudo_warnx("unable to convert uuid to string form");
	    errors++;
	    continue;
	}
	if (sudo_uuid_from_string(uuid_str, uuid_buf) != 0) {
	    sudo_warnx("unable to parse uuid string \"%s\" to binary",
		uuid_str);
	    errors++;
	    continue;
	}
	if (memcmp(uuid.u8, uuid_buf, sizeof(uuid_buf)) != 0) {
	    sudo_warnx("binary uuid mismatch");
	    errors++;
	    continue;
	}
    }

    if (ntests != 0) {
	printf("%s: %d tests run, %d errors, %d%% success rate\n",
	    getprogname(), ntests, errors, (ntests - errors) * 100 / ntests);
    }
    return errors;
}
