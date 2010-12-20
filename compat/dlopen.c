/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <errno.h>

#include "compat/dlfcn.h"
#include "missing.h"

#ifdef HAVE_SHL_LOAD
/*
 * Emulate dlopen() using shl_load().
 */
#include <dl.h>

#ifndef DYNAMIC_PATH
# define DYNAMIC_PATH	0
#endif

void *
sudo_dlopen(const char *path, int mode)
{
    int flags = DYNAMIC_PATH;

    if (mode == 0)
	mode = RTLD_LAZY;	/* default behavior */

    /* We don't support RTLD_GLOBAL or RTLD_LOCAL yet. */
    if (ISSET(mode, RTLD_LAZY))
	flags |= BIND_DEFERRED;
    if (ISSET(mode, RTLD_NOW))
	flags |= BIND_IMMEDIATE;

    return (void *)shl_load(path, flags, 0L);
}

int
sudo_dlclose(void *handle)
{
    return shl_unload((shl_t)handle);
}

void *
sudo_dlsym(void *vhandle, const char *symbol)
{
    shl_t handle = vhandle;
    void *value = NULL;

    (void)shl_findsym(&handle, symbol, TYPE_UNDEFINED, &value);

    return value;
}

char *
sudo_dlerror(void)
{
    return strerror(errno);
}

#else /* !HAVE_SHL_LOAD */

/*
 * Emulate dlopen() using a static list of symbols compiled into sudo.
 */

struct sudo_preload_table {
    const char *name;
    void *address;
};
extern struct sudo_preload_table sudo_preload_table[];

void *
sudo_dlopen(const char *path, int mode)
{
    return (void *)path;
}

int
sudo_dlclose(void *handle)
{
    return 0;
}

void *
sudo_dlsym(void *handle, const char *symbol)
{
    struct sudo_preload_table *sym;

    for (sym = sudo_preload_table; sym->name != NULL; sym++) {
	if (strcmp(symbol, sym->name) == 0)
	    return sym->address;
    }
    return NULL;
}

char *
sudo_dlerror(void)
{
    return strerror(errno);
}

#endif /* HAVE_SHL_LOAD */
