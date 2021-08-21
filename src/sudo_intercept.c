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
#include "sudo_debug.h"
#include "sudo_util.h"
#include "pathnames.h"

extern char **environ;
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

static int
my_execv(const char *cmnd, char * const argv[])
{
    return my_execve(cmnd, argv, environ);
}

/* Magic to tell dyld to do symbol interposition. */
__attribute__((__used__)) static const interpose_t interposers[]
__attribute__((__section__("__DATA,__interpose"))) = {
    { (void *)my_execve, (void *)execve }
    { (void *)my_execv, (void *)execv }
};

#else /* HAVE___INTERPOSE */

typedef int (*sudo_fn_execve_t)(const char *, char *const *, char *const *);

# if defined(HAVE_SHL_LOAD)
static void *
sudo_shl_get_next(const char *symbol, short type)
{
    const char *name, *myname;
    struct shl_descriptor *desc;
    void *fn = NULL;
    int idx = 0;
    debug_decl(sudo_shl_get_next, SUDO_DEBUG_EXEC);

    /* Search for symbol but skip this shared object. */
    /* XXX - could be set to a different path in sudo.conf */
    myname = sudo_basename(_PATH_SUDO_INTERCEPT);
    while (shl_get(idx++, &desc) == 0) {
        name = sudo_basename(desc->filename);
        if (strcmp(name, myname) == 0)
            continue;
        if (shl_findsym(&desc->handle, symbol, type, &fn) == 0)
            break;
    }

    debug_return_ptr(fn);
}
# endif /* HAVE_SHL_LOAD */

sudo_dso_public int
execve(const char *cmnd, char * const argv[], char * const envp[])
{
    char *ncmnd = NULL, **nargv = NULL, **nenvp = NULL;
    void *fn = NULL;
    debug_decl(execve, SUDO_DEBUG_EXEC);

# if defined(HAVE_DLOPEN)
    fn = dlsym(RTLD_NEXT, "execve");
# elif defined(HAVE_SHL_LOAD)
    fn = sudo_shl_get_next("execve", TYPE_PROCEDURE);
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

sudo_dso_public int
execv(const char *cmnd, char * const argv[])
{
    return execve(cmnd, argv, environ);
}
#endif /* HAVE___INTERPOSE) */
