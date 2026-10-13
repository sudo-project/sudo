/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2026 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <errno.h>

#define SUDO_ERROR_WRAP 0

#include <sudoers.h>

struct test_data {
    const char *input;
    const char *result;
};

static struct test_data rationalize_test_data[] = {
    { "./bin/ls", "./bin/ls" },			/* 1 */
    { "/usr//bin/who", "/usr/bin/who" },	/* 2 */
    { "//usr//bin/who", "/usr/bin/who" },	/* 3 */
    { "/etc/./shadow", "/etc/shadow" },		/* 4 */
    { "//etc/./shadow", "/etc/shadow" },	/* 5 */
    { "/usr/bin//", "/usr/bin/" },		/* 6 */
    { "//usr///bin////", "/usr/bin/" },		/* 7 */
    { "/./usr/bin", "/usr/bin" },		/* 8 */
    { "/usr/bin/.//", "/usr/bin/" },		/* 9 */
    { "/usr/bin/.", "/usr/bin" },		/* 10 */
    { "/usr/bin//.", "/usr/bin" },		/* 11 */
    { "/usr//..", "/" },			/* 12 */
    { "/../", "/" },				/* 13 */
    { "/..", "/" },				/* 14 */
    { "/../..", "/" },				/* 15 */
    { "/../etc", "/etc" },			/* 16 */
    { "/.../etc", "/.../etc" },			/* 17 */
    { "./../etc", "./etc" },			/* 18 */
    { "/etc/../usr/lib", "/usr/lib" },		/* 19 */
    { "/etc/../usr/..", "/" },			/* 20 */
    { "/usr/lib/../../etc", "/etc" },		/* 21 */
    { "/.", "/" },				/* 22 */
    { "//.", "/" },				/* 23 */
    { "/.//.", "/" },				/* 24 */
    { "/usr/..//.", "/" },			/* 25 */
    { NULL }
};

sudo_dso_public int main(int argc, char *argv[]);

static void
test_rationalize_path(int *ntests_out, int *errors_out)
{
    int ntests = *ntests_out;
    int errors = *errors_out;
    struct test_data *td;
    char buf[1024];

    for (td = rationalize_test_data; td->input != NULL; td++) {
	ntests++;
	if (strlcpy(buf, td->input, sizeof(buf)) >= sizeof(buf)) {
	    errno = ENAMETOOLONG;
	    sudo_warn("%d: \"%s\"", ntests, td->input);
	    errors++;
	    continue;
	}
	if (strcmp(td->result, rationalize_path(buf, true)) != 0) {
	    sudo_warnx("%d: \"%s\": got \"%s\", expected \"%s\"",
		ntests, td->input, buf, td->result);
	    errors++;
	}
    }

    *ntests_out = ntests;
    *errors_out = errors;
}

int
main(int argc, char *argv[])
{
    int ch, ntests = 0, errors = 0;

    initprogname(argc > 0 ? argv[0] : "check_rationalize");

    while ((ch = getopt(argc, argv, "v")) != -1) {
	switch (ch) {
	case 'v':
	    /* ignored */
	    break;
	default:
	    fprintf(stderr, "usage: %s [-v]\n", getprogname());
	    return EXIT_FAILURE;
	}
    }
    argc -= optind;
    argv += optind;

    test_rationalize_path(&ntests, &errors);

    if (ntests != 0) {
	printf("%s: %d tests run, %d errors, %d%% success rate\n",
	    getprogname(), ntests, errors, (ntests - errors) * 100 / ntests);
    }

    exit(errors);
}
