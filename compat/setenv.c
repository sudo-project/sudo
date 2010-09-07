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
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <errno.h>

#include "missing.h"

int
setenv(const char *var, const char *val, int overwrite)
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
    return putenv(envstr);
}
