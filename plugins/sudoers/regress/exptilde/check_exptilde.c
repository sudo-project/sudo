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

#include <config.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SUDO_ERROR_WRAP 0

#include "sudoers.h"

#include <def_data.c>

struct sudo_user sudo_user;

struct test_data {
    char *input;
    char *output;
    char *user;
    bool result;
} test_data[] = {
    { "foo/bar", NULL, NULL, false },
    { "~root", "/", NULL, true },
    { "~", "/home/millert", "millert", true },
    { "~millert", "/home/millert", "millert", true },
    { NULL }
};

sudo_dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    int ntests = 0, errors = 0;
    struct test_data *td;
    struct passwd *pw;
    char *path = NULL;
    bool result;

    initprogname(argc > 0 ? argv[0] : "check_exptilde");

    /* Prime the passwd cache */
    pw = sudo_mkpwent("root", 0, 0, "/", "/bin/sh");
    if (pw == NULL)
	sudo_fatalx("unable to create passwd entry for root");
    sudo_pw_delref(pw);

    pw = sudo_mkpwent("millert", 8036, 20, "/home/millert", "/bin/tcsh");
    if (pw == NULL)
	sudo_fatalx("unable to create passwd entry for millert");
    sudo_pw_delref(pw);

    for (td = test_data; td->input != NULL; td++) {
	ntests++;
	free(path);
	if ((path = strdup(td->input)) == NULL)
	    sudo_fatal(NULL);
	result = expand_tilde(&path, td->user);
	if (result != td->result) {
	    errors++;
	    if (result) {
		sudo_warnx("unexpected success: input %s, output %s", 
		    td->input, path);
	    } else {
		sudo_warnx("unexpected failure: input %s", td->input);
	    }
	    continue;
	}
	if (td->result && strcmp(path, td->output) != 0) {
	    errors++;
	    sudo_warnx("incorrect output for input %s: expected %s, got %s",
		td->input, td->output, path);
	    continue;
	}
    }

    printf("%s: %d tests run, %d errors, %d%% success rate\n", getprogname(),
	ntests, errors, (ntests - errors) * 100 / ntests);

    exit(errors);
}
