/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2021 Todd C. Miller <Todd.Miller@sudo.ws>
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

#define SUDO_ERROR_WRAP 0

#include "sudoers.h"

struct test_data {
    char *input;
    char *result;
    size_t result_len;
    size_t bufsize;
} test_data[] = {
    { "\\\0ABC", "\\", 1, 2 },			/* 1 */
    { "\\ \\;", "\\ ;", 3, 4 },			/* 2 */
    { "\\\t\\;", "\\\t;", 3, 4 },		/* 3 */
    { "\\foo", "foo", 3, 4 },			/* 4 */
    { "foo\\ bar", "foo\\ bar", 8, 9 },		/* 5 */
    { "foo bar", "f", 7, 2 },			/* 6 */
    { "foo bar", "", 7, 1 },			/* 7 */
    { "foo bar", NULL, 7, 0 },			/* 8 */
    { NULL }
};

sudo_dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    int ntests = 0, errors = 0;
    struct test_data *td;
    char buf[1024];
    size_t len;

    initprogname(argc > 0 ? argv[0] : "check_unesc");

    for (td = test_data; td->input != NULL; td++) {
	ntests++;
	memset(buf, 'A', sizeof(buf));
	len = strlcpy_unescape(buf, td->input, td->bufsize);
	if (len != td->result_len) {
	    sudo_warnx("%d: \"%s\": bad return %zu, expected %zu",
		ntests, td->input, len, td->result_len);
	    errors++;
	}
	len = td->result ? strlen(td->result) : 0;
	if ((len != 0 || td->bufsize != 0) && len >= td->bufsize) {
	    sudo_warnx("%d: \"%s\": bad length %zu >= %zu",
		ntests, td->input, len, td->bufsize);
	    errors++;
	}
	if (td->result != NULL && strcmp(td->result, buf) != 0) {
	    sudo_warnx("%d: \"%s\": got \"%s\", expected \"%s\"",
		ntests, td->input, buf, td->result);
	    errors++;
	}
	if (buf[td->bufsize] != 'A') {
	    sudo_warnx("%d: \"%s\": wrote past end of buffer at %zu (0x%x)",
		ntests, td->input, td->bufsize, buf[td->bufsize]);
	    errors++;
	}
    }

    printf("%s: %d tests run, %d errors, %d%% success rate\n", getprogname(),
	ntests, errors, (ntests - errors) * 100 / ntests);

    exit(errors);
}
