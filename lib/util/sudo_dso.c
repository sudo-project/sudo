/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2010, 2012-2014, 2021-2022 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifdef __linux__
# include <sys/utsname.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_SHL_LOAD)
# include <dl.h>
#elif defined(HAVE_DLOPEN)
# include <dlfcn.h>
#endif
#include <errno.h>

#include "sudo_compat.h"
#include "sudo_dso.h"

/*
 * Pointer for statically compiled symbols.
 */
static struct sudo_preload_table *preload_table;

void
sudo_dso_preload_table_v1(struct sudo_preload_table *table)
{
    preload_table = table;
}

#if defined(HAVE_SHL_LOAD)

# ifndef DYNAMIC_PATH
#  define DYNAMIC_PATH	0
# endif

void *
sudo_dso_load_v1(const char *path, int mode)
{
    struct sudo_preload_table *pt;
    int flags = DYNAMIC_PATH | BIND_VERBOSE;

    if (mode == 0)
	mode = SUDO_DSO_LAZY;	/* default behavior */

    /* Check prelinked symbols first. */
    if (preload_table != NULL) {
	for (pt = preload_table; pt->handle != NULL; pt++) {
	    if (pt->path != NULL && strcmp(path, pt->path) == 0)
		return pt->handle;
	}
    }

    /* We don't support SUDO_DSO_GLOBAL or SUDO_DSO_LOCAL yet. */
    if (ISSET(mode, SUDO_DSO_LAZY))
	flags |= BIND_DEFERRED;
    if (ISSET(mode, SUDO_DSO_NOW))
	flags |= BIND_IMMEDIATE;

    return (void *)shl_load(path, flags, 0L);
}

int
sudo_dso_unload_v1(void *handle)
{
    struct sudo_preload_table *pt;

    /* Check prelinked symbols first. */
    if (preload_table != NULL) {
	for (pt = preload_table; pt->handle != NULL; pt++) {
	    if (pt->handle == handle)
		return 0;
	}
    }

    return shl_unload((shl_t)handle);
}

void *
sudo_dso_findsym_v1(void *vhandle, const char *symbol)
{
    struct sudo_preload_table *pt;
    shl_t handle = vhandle;
    void *value = NULL;

    /* Check prelinked symbols first. */
    if (preload_table != NULL) {
	for (pt = preload_table; pt->handle != NULL; pt++) {
	    if (pt->handle == handle) {
		struct sudo_preload_symbol *sym;
		for (sym = pt->symbols; sym->name != NULL; sym++) {
		    if (strcmp(sym->name, symbol) == 0)
			return sym->addr;
		}
		errno = ENOENT;
		return NULL;
	    }
	}
    }

    /*
     * Note that the behavior of of SUDO_DSO_NEXT and SUDO_DSO_SELF 
     * differs from most implementations when called from
     * a shared library.
     */
    if (vhandle == SUDO_DSO_NEXT) {
	/* Iterate over all shared libs looking for symbol. */
	shl_t myhandle = PROG_HANDLE;
	struct shl_descriptor *desc;
	int idx = 0;

	/* Find program's real handle. */
	if (shl_gethandle(PROG_HANDLE, &desc) == 0)
	    myhandle = desc->handle;
	while (shl_get(idx++, &desc) == 0) {
	    if (desc->handle == myhandle)
		continue;
	    if (shl_findsym(&desc->handle, symbol, TYPE_UNDEFINED, &value) == 0)
		break;
	}
    } else {
	if (vhandle == SUDO_DSO_DEFAULT)
	    handle = NULL;
	else if (vhandle == SUDO_DSO_SELF)
	    handle = PROG_HANDLE;
	(void)shl_findsym(&handle, symbol, TYPE_UNDEFINED, &value);
    }

    return value;
}

char *
sudo_dso_strerror_v1(void)
{
    return strerror(errno);
}

#elif defined(HAVE_DLOPEN)

# ifndef RTLD_GLOBAL
#  define RTLD_GLOBAL	0
# endif

/* Default member names for AIX when dlopen()ing an ar (.a) file. */
# ifdef RTLD_MEMBER
#  ifdef __LP64__
#   define SUDO_DSO_MEMBER	"shr_64.o"
#  else
#   define SUDO_DSO_MEMBER	"shr.o"
#  endif
# endif

# if defined(__linux__)
/* 
 * On Linux systems that use muti-arch, the actual DSO may be
 * in a machine-specific subdirectory.  If the specified path
 * contains /lib/ or /libexec/, insert a multi-arch directory
 * after it.
 */
static void *
dlopen_multi_arch(const char *path, int flags)
{
#  if defined(__ILP32__)
    const char *libdirs[] = { "/libx32/", "/lib/", "/libexec/", NULL };
#  elif defined(__LP64__)
    const char *libdirs[] = { "/lib64/", "/lib/", "/libexec/", NULL };
#  else
    const char *libdirs[] = { "/lib32/", "/lib/", "/libexec/", NULL };
#  endif
    const char **lp, *lib, *slash;
    struct utsname unamebuf;
    void *ret = NULL;
    struct stat sb;
    char *newpath;
    int len;

    /* Only try multi-arch if the original path does not exist.  */
    if (stat(path, &sb) == -1 && errno == ENOENT && uname(&unamebuf) == 0) {
	for (lp = libdirs; *lp != NULL; lp++) {
	    /* Replace lib64, lib32, libx32 with lib in new path. */
	    const char *newlib = lp == libdirs ? "/lib/" : *lp;

	    /* Search for lib dir in path, find the trailing slash. */
	    lib = strstr(path, *lp);
	    if (lib == NULL)
		continue;
	    slash = lib + strlen(*lp) - 1;

	    /* Add machine-linux-gnu dir after /lib/ or /libexec/. */
	    len = asprintf(&newpath, "%.*s%s%s-linux-gnu%s",
		(int)(lib - path), path, newlib, unamebuf.machine, slash);
	    if (len == -1)
		break;
	    if (stat(newpath, &sb) == 0)
		ret = dlopen(newpath, flags);
	    free(newpath);
	    if (ret != NULL)
		break;
	}
    }
    return ret;
}
#endif /* __linux__ */

void *
sudo_dso_load_v1(const char *path, int mode)
{
    struct sudo_preload_table *pt;
    int flags = 0;
    void *ret;
#ifdef RTLD_MEMBER
    char *cp;
#endif

    /* Check prelinked symbols first. */
    if (preload_table != NULL) {
	for (pt = preload_table; pt->handle != NULL; pt++) {
	    if (pt->path != NULL && strcmp(path, pt->path) == 0)
		return pt->handle;
	}
    }

    /* Map SUDO_DSO_* -> RTLD_* */
    if (ISSET(mode, SUDO_DSO_LAZY))
	SET(flags, RTLD_LAZY);
    if (ISSET(mode, SUDO_DSO_NOW))
	SET(flags, RTLD_NOW);
    if (ISSET(mode, SUDO_DSO_GLOBAL))
	SET(flags, RTLD_GLOBAL);
    if (ISSET(mode, SUDO_DSO_LOCAL))
	SET(flags, RTLD_LOCAL);

#ifdef RTLD_MEMBER
    /* Check for AIX path(module) syntax and add RTLD_MEMBER for a module. */
    cp = strrchr(path, '(');
    if (cp != NULL) {
	size_t len = strlen(cp);
	if (len > 2 && cp[len - 1] == '\0')
	    SET(flags, RTLD_MEMBER);
    }
#endif /* RTLD_MEMBER */
    ret = dlopen(path, flags);
#if defined(RTLD_MEMBER)
    /*
     * If we try to dlopen() an AIX .a file without an explicit member
     * it will fail with ENOEXEC.  Try again using the default member.
     */
    if (ret == NULL && !ISSET(flags, RTLD_MEMBER) && errno == ENOEXEC) {
	if (asprintf(&cp, "%s(%s)", path, SUDO_DSO_MEMBER) != -1) {
	    ret = dlopen(cp, flags|RTLD_MEMBER);
	    free(cp);
	}
	if (ret == NULL) {
	    /* Retry with the original path so we get the correct error. */
	    ret = dlopen(path, flags);
	}
    }
#elif defined(__linux__)
    /* On failure, try again with a muti-arch path where possible. */
    if (ret == NULL)
	ret = dlopen_multi_arch(path, flags);
#endif /* RTLD_MEMBER */

    return ret;
}

int
sudo_dso_unload_v1(void *handle)
{
    struct sudo_preload_table *pt;

    /* Check prelinked symbols first. */
    if (preload_table != NULL) {
	for (pt = preload_table; pt->handle != NULL; pt++) {
	    if (pt->handle == handle)
		return 0;
	}
    }

    return dlclose(handle);
}

void *
sudo_dso_findsym_v1(void *handle, const char *symbol)
{
    struct sudo_preload_table *pt;

    /* Check prelinked symbols first. */
    if (preload_table != NULL) {
	for (pt = preload_table; pt->handle != NULL; pt++) {
	    if (pt->handle == handle) {
		struct sudo_preload_symbol *sym;
		for (sym = pt->symbols; sym->name != NULL; sym++) {
		    if (strcmp(sym->name, symbol) == 0)
			return sym->addr;
		}
		errno = ENOENT;
		return NULL;
	    }
	}
    }

    /*
     * Not all implementations support the special handles.
     */
    if (handle == SUDO_DSO_NEXT) {
# ifdef RTLD_NEXT
	handle = RTLD_NEXT;
# else
	errno = ENOENT;
	return NULL;
# endif
    } else if (handle == SUDO_DSO_DEFAULT) {
# ifdef RTLD_DEFAULT
	handle = RTLD_DEFAULT;
# else
	errno = ENOENT;
	return NULL;
# endif
    } else if (handle == SUDO_DSO_SELF) {
# ifdef RTLD_SELF
	handle = RTLD_SELF;
# else
	errno = ENOENT;
	return NULL;
# endif
    }

    return dlsym(handle, symbol);
}

char *
sudo_dso_strerror_v1(void)
{
    return dlerror();
}

#else /* !HAVE_SHL_LOAD && !HAVE_DLOPEN */

/*
 * Emulate dlopen() using a static list of symbols compiled into sudo.
 */
void *
sudo_dso_load_v1(const char *path, int mode)
{
    struct sudo_preload_table *pt;

    /* Check prelinked symbols first. */
    if (preload_table != NULL) {
	for (pt = preload_table; pt->handle != NULL; pt++) {
	    if (pt->path != NULL && strcmp(path, pt->path) == 0)
		return pt->handle;
	}
    }
    return NULL;
}

int
sudo_dso_unload_v1(void *handle)
{
    struct sudo_preload_table *pt;

    if (preload_table != NULL) {
	for (pt = preload_table; pt->handle != NULL; pt++) {
	    if (pt->handle == handle)
		return 0;
	}
    }
    return -1;
}

void *
sudo_dso_findsym_v1(void *handle, const char *symbol)
{
    struct sudo_preload_table *pt;

    if (preload_table != NULL) {
	for (pt = preload_table; pt->handle != NULL; pt++) {
	    if (pt->handle == handle) {
		struct sudo_preload_symbol *sym;
		for (sym = pt->symbols; sym->name != NULL; sym++) {
		    if (strcmp(sym->name, symbol) == 0)
			return sym->addr;
		}
	    }
	}
    }
    errno = ENOENT;
    return NULL;
}

char *
sudo_dso_strerror_v1(void)
{
    return strerror(errno);
}
#endif /* !HAVE_SHL_LOAD && !HAVE_DLOPEN */
