/*
 * Copyright (c) 2010, 2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <errno.h>
#ifdef HAVE_DLOPEN
# include <dlfcn.h>
#else
# include "compat/dlfcn.h"
#endif

#include "sudo.h"
#include "sudo_plugin.h"

extern char **environ;		/* global environment pointer */
static char **priv_environ;	/* private environment pointer */

static char *
rpl_getenv(const char *name)
{
    char **ep, *val = NULL;
    size_t namelen = 0;

    /* For BSD compatibility, treat '=' in name like end of string. */
    while (name[namelen] != '\0' && name[namelen] != '=')
	namelen++;
    for (ep = environ; *ep != NULL; ep++) {
	if (strncmp(*ep, name, namelen) == 0 && (*ep)[namelen] == '=') {
	    val = *ep + namelen + 1;
	    break;
	}
    }
    return val;
}

char *
getenv(const char *name)
{
    char *val = NULL;

    switch (process_hooks_getenv(name, &val)) {
	case SUDO_HOOK_RET_STOP:
	    return val;
	case SUDO_HOOK_RET_ERROR:
	    return NULL;
	default: {
#if defined(HAVE_DLOPEN)
	    char * (*fn)(const char *);

	    fn = dlsym(RTLD_NEXT, "getenv");
	    if (fn != NULL)
		return fn(name);
#endif /* HAVE_DLOPEN */
	    return rpl_getenv(name);
	}
    }
}

static int
rpl_putenv(PUTENV_CONST char *string)
{
    char **ep;
    size_t len;
    bool found = false;

    /* Look for existing entry. */
    len = (strchr(string, '=') - string) + 1;
    for (ep = environ; *ep != NULL; ep++) {
	if (strncmp(string, *ep, len) == 0) {
	    *ep = (char *)string;
	    found = true;
	    break;
	}
    }
    /* Prune out duplicate variables. */
    if (found) {
	while (*ep != NULL) {
	    if (strncmp(string, *ep, len) == 0) {
		char **cur = ep;
		while ((*cur = *(cur + 1)) != NULL)
		    cur++;
	    } else {
		ep++;
	    }
	}
    }

    /* Append at the end if not already found. */
    if (!found) {
	size_t env_len = (size_t)(ep - environ);
	char **envp = erealloc3(priv_environ, env_len + 2, sizeof(char *));
	if (environ != priv_environ)
	    memcpy(envp, environ, env_len * sizeof(char *));
	envp[env_len++] = (char *)string;
	envp[env_len] = NULL;
	priv_environ = environ = envp;
    }
    return 0;
}

int
putenv(PUTENV_CONST char *string)
{
    switch (process_hooks_putenv((char *)string)) {
	case SUDO_HOOK_RET_STOP:
	    return 0;
	case SUDO_HOOK_RET_ERROR:
	    return -1;
	default: {
#if defined(HAVE_DLOPEN)
	    int (*fn)(PUTENV_CONST char *);

	    fn = dlsym(RTLD_NEXT, "putenv");
	    if (fn != NULL)
		return fn(string);
#endif /* HAVE_DLOPEN */
	    return rpl_putenv(string);
	}
    }
}

static int
rpl_setenv(const char *var, const char *val, int overwrite)
{
    char *envstr, *dst;
    const char *src;
    size_t esize;

    if (!var || *var == '\0') {
	errno = EINVAL;
	return -1;
    }

    /*
     * POSIX says a var name with '=' is an error but BSD
     * just ignores the '=' and anything after it.
     */
    for (src = var; *src != '\0' && *src != '='; src++)
	;
    esize = (size_t)(src - var) + 2;
    if (val) {
        esize += strlen(val);	/* glibc treats a NULL val as "" */
    }

    /* Allocate and fill in envstr. */
    if ((envstr = malloc(esize)) == NULL)
	return -1;
    for (src = var, dst = envstr; *src != '\0' && *src != '=';)
	*dst++ = *src++;
    *dst++ = '=';
    if (val) {
	for (src = val; *src != '\0';)
	    *dst++ = *src++;
    }
    *dst = '\0';

    if (!overwrite && getenv(var) != NULL) {
	free(envstr);
	return 0;
    }
    return rpl_putenv(envstr);
}

int
setenv(const char *var, const char *val, int overwrite)
{
    switch (process_hooks_setenv(var, val, overwrite)) {
	case SUDO_HOOK_RET_STOP:
	    return 0;
	case SUDO_HOOK_RET_ERROR:
	    return -1;
	default: {
#if defined(HAVE_SETENV) && defined(HAVE_DLOPEN)
	    int (*fn)(const char *, const char *, int);

	    fn = dlsym(RTLD_NEXT, "setenv");
	    if (fn != NULL)
		return fn(var, val, overwrite);
#endif /* HAVE_SETENV && HAVE_DLOPEN */
	    return rpl_setenv(var, val, overwrite);
	}
    }
}

#ifdef UNSETENV_VOID
static void
#else
int
#endif
rpl_unsetenv(const char *var)
{
    char **ep = environ;
    size_t len;

    if (var == NULL || *var == '\0' || strchr(var, '=') != NULL) {
	errno = EINVAL;
#ifdef UNSETENV_VOID
	return;
#else
	return -1;
#endif
    }

    len = strlen(var);
    while (*ep != NULL) {
	if (strncmp(var, *ep, len) == 0 && (*ep)[len] == '=') {
	    /* Found it; shift remainder + NULL over by one. */
	    char **cur = ep;
	    while ((*cur = *(cur + 1)) != NULL)
		cur++;
	    /* Keep going, could be multiple instances of the var. */
	} else {
	    ep++;
	}
    }
#ifndef UNSETENV_VOID
    return 0;
#endif
}

#ifdef UNSETENV_VOID
void
unsetenv(const char *var)
{
    switch (process_hooks_unsetenv(var)) {
	case SUDO_HOOK_RET_STOP:
	    return 0;
	case SUDO_HOOK_RET_ERROR:
	    return -1;
	default: {
#if defined(HAVE_UNSETENV) && defined(HAVE_DLOPEN)
	    void (*fn)(const char *);

	    fn = dlsym(RTLD_NEXT, "unsetenv");
	    if (fn != NULL)
		fn(var);
	    else
#endif /* HAVE_UNSETENV && HAVE_DLOPEN */
		rpl_unsetenv(var);
	}
    }
}
#else
int
unsetenv(const char *var)
{
    switch (process_hooks_unsetenv(var)) {
	case SUDO_HOOK_RET_STOP:
	    return 0;
	case SUDO_HOOK_RET_ERROR:
	    return -1;
	default: {
#if defined(HAVE_UNSETENV) && defined(HAVE_DLOPEN)
	    int (*fn)(const char *);

	    fn = dlsym(RTLD_NEXT, "unsetenv");
	    if (fn != NULL)
		return fn(var);
#endif /* HAVE_UNSETENV && HAVE_DLOPEN */
	    return rpl_unsetenv(var);
	}
    }
}
#endif /* UNSETENV_VOID */
