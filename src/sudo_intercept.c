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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#if defined(HAVE_SHL_LOAD)
# include <dl.h>
#elif defined(HAVE_DLOPEN)
# include <dlfcn.h>
#endif

#include "sudo_compat.h"
#include "pathnames.h"

extern bool command_allowed(const char *cmnd, char * const argv[], char * const envp[], char **ncmnd, char ***nargv, char ***nenvp);

#ifdef HAVE___INTERPOSE
/*
 * Mac OS X 10.4 and above has support for library symbol interposition.
 * There is a good explanation of this in the Mac OS X Internals book.
 */
typedef struct interpose_s {
    void *new_func;
    void *orig_func;
} interpose_t;

static int
my_execve(const char *cmnd, char * const argv[], char * const envp[])
{
    char *ncmnd = NULL, **nargv = NULL, **nenvp = NULL;

    if (command_allowed(cmnd, argv, envp, &ncmnd, &nargv, &nenvp)) {
	/* Execute the command using the "real" execve() function. */
	execve(ncmnd, nargv, nenvp);
    } else {
	errno = EACCES;
    }
    if (ncmnd != cmnd)
	free(ncmnd);
    if (nargv != argv)
	free(nargv);
    if (nenvp != envp)
	free(nenvp);

    return -1;
}

/* Magic to tell dyld to do symbol interposition. */
__attribute__((__used__)) static const interpose_t interposers[]
__attribute__((__section__("__DATA,__interpose"))) = {
    { (void *)my_execve, (void *)execve }
};

#else /* HAVE___INTERPOSE */

typedef int (*sudo_fn_execve_t)(const char *, char *const *, char *const *);

sudo_dso_public int
execve(const char *cmnd, char * const argv[], char * const envp[])
{
    char *ncmnd = NULL, **nargv = NULL, **nenvp = NULL;
# if defined(HAVE_DLOPEN)
    void *fn = dlsym(RTLD_NEXT, "execve");
# elif defined(HAVE_SHL_LOAD)
    const char *name, *myname = _PATH_SUDO_INTERCEPT;
    struct shl_descriptor *desc;
    void *fn = NULL;
    int idx = 0;

    /* Search for execve() but skip this shared object. */
    myname = sudo_basename(myname);
    while (shl_get(idx++, &desc) == 0) {
        name = sudo_basename(desc->filename);
        if (strcmp(name, myname) == 0)
            continue;
        if (shl_findsym(&desc->handle, "execve", TYPE_PROCEDURE, &fn) == 0)
            break;
    }
# else
    void *fn = NULL;
# endif
    if (fn == NULL) {
        errno = EACCES;
        return -1;
    }

    if (command_allowed(cmnd, argv, envp, &ncmnd, &nargv, &nenvp)) {
	/* Execute the command using the "real" execve() function. */
	return ((sudo_fn_execve_t)fn)(ncmnd, nargv, nenvp);
    } else {
	errno = EACCES;
    }
    if (ncmnd != cmnd)
	free(ncmnd);
    if (nargv != argv)
	free(nargv);
    if (nenvp != envp)
	free(nenvp);

    return -1;
}
#endif /* HAVE___INTERPOSE) */
