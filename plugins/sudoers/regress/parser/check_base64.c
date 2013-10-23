/*
 * Copyright (c) 2013 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif

#define SUDO_ERROR_WRAP 0

#include "missing.h"

extern size_t base64_decode(const char *str, unsigned char *dst, size_t dsize);

__dso_public int main(int argc, char *argv[]);

struct base64_test {
    const char *ascii;
    const char *encoded;
} test_strings[] = {
    {
	"any carnal pleasure.",
	"YW55IGNhcm5hbCBwbGVhc3VyZS4="
    },
    {
	"any carnal pleasure",
	"YW55IGNhcm5hbCBwbGVhc3VyZQ=="
    },
    {
	"any carnal pleasur",
	"YW55IGNhcm5hbCBwbGVhc3Vy"
    },
    {
	"any carnal pleasu",
	"YW55IGNhcm5hbCBwbGVhc3U="
    },
    {
	"any carnal pleas",
	"YW55IGNhcm5hbCBwbGVhcw=="
    }
};

int
main(int argc, char *argv[])
{
    const int ntests = (sizeof(test_strings) / sizeof(test_strings[0]));
    int i, errors = 0;
    unsigned char buf[32];
    size_t len;

    for (i = 0; i < ntests; i++) {
	len = base64_decode(test_strings[i].encoded, buf, sizeof(buf));
	buf[len] = '\0';
	if (strcmp(test_strings[i].ascii, (char *)buf) != 0) {
	    fprintf(stderr, "check_base64: expected %s, got %s",
		test_strings[i].ascii, buf);
	    errors++;
	}
    }
    printf("check_base64: %d tests run, %d errors, %d%% success rate\n",
	ntests, errors, (ntests - errors) * 100 / ntests);
    exit(errors);
}
