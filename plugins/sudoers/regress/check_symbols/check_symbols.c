/*
 * Copyright (c) 2012 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <sys/types.h>
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
#ifdef HAVE_DLOPEN
# include <dlfcn.h>
#else
# include "compat/dlfcn.h"
#endif
#include <errno.h>
#include <limits.h>

#include "missing.h"
#include "error.h"

#ifndef LINE_MAX
# define LINE_MAX 2048
#endif

static void
usage(void)
{
    fprintf(stderr, "usage: load_symbols plugin.so symbols_file\n");
    exit(1);
}

int
main(int argc, char *argv[])
{
    void *handle, *sym;
    const char *plugin_path;
    const char *symbols_file;
    char *cp, line[LINE_MAX];
    FILE *fp;
    int ntests = 0, errors = 0;

#if !defined(HAVE_GETPROGNAME) && !defined(HAVE___PROGNAME)
    setprogname(argc > 0 ? argv[0] : "check_symbols");
#endif

    if (argc != 3)
	usage();
    plugin_path = argv[1];
    symbols_file = argv[2];

    handle = dlopen(plugin_path, RTLD_LAZY|RTLD_GLOBAL);
    if (handle == NULL)
	errorx2(1, "unable to dlopen %s: %s", plugin_path, dlerror());

    fp = fopen(symbols_file, "r");
    if (fp == NULL)
	error2(1, "unable to open %s", symbols_file);

    while (fgets(line, sizeof(line), fp) != NULL) {
	ntests++;
	if ((cp = strchr(line, '\n')) != NULL)
	    *cp = '\0';
	sym = dlsym(handle, line);
	if (sym == NULL) {
	    warningx2("unable to resolve symbol %s: %s", line, dlerror());
	    errors++;
	}
    }

    /*
     * Make sure unexported symbols are not available.
     */
    sym = dlsym(handle, "user_in_group");
    if (sym != NULL) {
	warningx2("able to resolve local symbol user_in_group");
	errors++;
    }
    ntests++;

    dlclose(handle);

    printf("check_symbols: %d tests run, %d errors, %d%% success rate\n",
	ntests, errors, (ntests - errors) * 100 / ntests);

    exit(errors);
}

void
cleanup(int gotsig)
{
    return;
}
