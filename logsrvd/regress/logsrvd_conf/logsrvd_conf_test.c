/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2022 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/socket.h>

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include <compat/stdbool.h>
#endif /* HAVE_STDBOOL_H */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sudo_compat.h>
#include <sudo_util.h>
#include <sudo_iolog.h>
#include <sudo_queue.h>
#include <logsrvd.h>

sudo_dso_public int main(int argc, char *argv[]);

static const struct {
    const char *dir;
    const char *base;
} base_tests[] = {
    { "/tmp/sudo-io", "/tmp/sudo-io" },
    { "/tmp/%%%%", "/tmp" },
    { "/tmp/%%/logs", "/tmp" },
    { "/tmp/%Y/logs", "/tmp" },
    { "/tmp/%{user}/logs", "/tmp" },
    { "///tmp/sudo-io", "/tmp/sudo-io" },
    { "/tmp/sudo-io///", "/tmp/sudo-io" },
    { "///tmp/%%%%///", "/tmp" },
    { "/tmp//%%%%", "/tmp" },
    { "/", "" },
    { "////", "" }
};

static size_t
fill_test_user(char * restrict dst, size_t size, void * restrict closure)
{
    return strlcpy(dst, "testuser", size);
}

static int
test_iolog_base(void)
{
    static const struct iolog_path_escape escapes[] = {
	{ "user", fill_test_user },
	{ NULL, NULL }
    };
    int errors = 0;

    for (size_t i = 0; i < nitems(base_tests); i++) {
	char path[] = "/tmp/logsrvd_conf_test.XXXXXX";
	char expanded[256], full[256], restored[256];
	int fd = mkstemp(path);
	FILE *fp = fd == -1 ? NULL : fdopen(fd, "w");
	bool ok = false;

	if (fp == NULL) {
	    if (fd != -1) {
		close(fd);
		unlink(path);
	    }
	    errors++;
	    continue;
	}
	fprintf(fp, "[iolog]\niolog_dir = %s\n", base_tests[i].dir);
	if (fclose(fp) == 0 && logsrvd_conf_read(path) &&
	    strcmp(logsrvd_conf_iolog_base(), base_tests[i].base) == 0 &&
	    expand_iolog_path(logsrvd_conf_iolog_dir(), expanded,
		sizeof(expanded), escapes, NULL)) {
	    size_t offset = strlen(logsrvd_conf_iolog_base()) + 1;
	    int len = snprintf(full, sizeof(full), "%s/x", expanded);

	    /* Validate before using the relative pointer, then check reconnect. */
	    if (len >= 0 && (size_t)len < sizeof(full) && offset <= (size_t)len) {
		len = snprintf(restored, sizeof(restored), "%s/%s",
		    logsrvd_conf_iolog_base(), full + offset);
		ok = len >= 0 && (size_t)len < sizeof(restored) &&
		    strcmp(full, restored) == 0;
	    }
	}
	unlink(path);
	if (!ok) {
	    fprintf(stderr, "iolog base/relative path mismatch for %s\n",
		base_tests[i].dir);
	    errors++;
	}
    }
    return errors;
}

sudo_noreturn static void
usage(void)
{
    fprintf(stderr, "usage: %s [-v] conf_file\n", getprogname());
    exit(EXIT_FAILURE);
}

/*
 * Simple test driver for logsrvd_conf_read().
 * Just pases the file, errors to standard error.
 */
int
main(int argc, char *argv[])
{
    bool verbose = false;
    int ch, ntests, errors = 0;

    initprogname(argc > 0 ? argv[0] : "conf_test");

    while ((ch = getopt(argc, argv, "v")) != -1) {
	switch (ch) {
	case 'v':
	    verbose = true;
	    break;
	default:
	    usage();
	    /* NOTREACHED */
	}
    }
    argc -= optind;
    argv += optind;

    if (argc < 1)
	usage();

    for (ntests = 0; ntests < argc; ntests++) {
	const char *path = argv[ntests];
	if (verbose)
	    printf("reading %s\n", path);
	if (!logsrvd_conf_read(path))
	    errors++;
    }
    errors += test_iolog_base();
    ntests += nitems(base_tests);
    logsrvd_conf_cleanup();

    if (ntests != 0) {
	printf("%s: %d tests run, %d errors, %d%% success rate\n",
	    getprogname(), ntests, errors, (ntests - errors) * 100 / ntests);
    }
    return errors;
}
