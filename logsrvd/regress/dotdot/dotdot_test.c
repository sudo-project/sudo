/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2025 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include <compat/stdbool.h>
#endif /* HAVE_STDBOOL_H */

#define SUDO_ERROR_WRAP 0

#include <sudo_compat.h>
#include <sudo_util.h>
#include <sudo_fatal.h>
#include <sudo_queue.h>

#include <logsrv_util.h>

sudo_dso_public int main(int argc, char *argv[]);

struct test_data {
    const char *str;		/* input string */
    bool expected;		/* expected result */
};

static struct test_data test_data[] = {
    {
	"/foo/bar",
	false
    }, {
	"..",
	true
    }, {
	"../",
	true
    }, {
	"/..",
	true
    }, {
	"/../",
	true
    }, {
	"foo/../",
	true
    }, {
	"foo/..",
	true
    }, {
	"foo/../bar",
	true
    }, {
	"../bar",
	true
    }, {
	"foo../bar",
	false
    }, {
	"foo/..bar",
	false
    }, {
	"...",
	false
    }, {
	".../",
	false
    }, {
	"/...",
	false
    }, {
	"/.../",
	false
    }, {
	NULL,
	false
    }
};

/*
 * Verify contains_dot_dot() behavior
 */
int
main(int argc, char *argv[])
{
    int errors = 0, ntests = 0;
    size_t i;
    int ch;

    initprogname(argc > 0 ? argv[0] : "dotdot_test");

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

    for (i = 0; test_data[i].str != NULL; i++) {
	bool result = contains_dot_dot(test_data[i].str);
	if (result != test_data[i].expected) {
	    sudo_warnx("test %zu:%s: expected %s, got %s", i,
		test_data[i].str, test_data[i].expected ? "true" : "false",
		result ? "true" : "false");
	    errors++;
	}
	ntests++;
    }

    if (ntests != 0) {
	printf("%s: %d tests run, %d errors, %d%% success rate\n",
	    getprogname(), ntests, errors, (ntests - errors) * 100 / ntests);
    }

    return errors;
}
