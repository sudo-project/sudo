/*
 * Copyright (c) 2009-2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <limits.h>

#include "missing.h"
#include "alloc.h"

#ifndef LINE_MAX
# define LINE_MAX 2048
#endif

#ifdef HAVE_FGETLN
ssize_t
getline(bufp, bufsizep, fp)
    char **bufp;
    size_t *bufsizep;
    FILE *fp;
{
    char *buf;
    size_t bufsize;
    size_t len;

    buf = fgetln(fp, &len);
    if (buf) {
	bufsize = *bufp ? *bufsizep : 0;
	if (bufsize == 0 || bufsize < len + 1) {
	    bufsize = len + 1;
	    *bufp = erealloc(*bufp, bufsize);
	    *bufsizep = bufsize;
	}
	memcpy(*bufp, buf, len);
	(*bufp)[len] = '\0';
    }
    return buf ? len : -1;
}
#else
ssize_t
getline(bufp, bufsizep, fp)
    char **bufp;
    size_t *bufsizep;
    FILE *fp;
{
    char *buf;
    size_t bufsize;
    ssize_t len = 0;

    buf = *bufp;
    bufsize = *bufsizep;
    if (buf == NULL || bufsize == 0) {
	bufsize = LINE_MAX;
	buf = erealloc(buf, LINE_MAX);
    }

    for (;;) {
	if (fgets(buf + len, bufsize - len, fp) == NULL) {
	    len = -1;
	    break;
	}
	len = strlen(buf);
	if (!len || buf[len - 1] == '\n' || feof(fp))
	    break;
	bufsize *= 2;
	buf = erealloc(buf, bufsize);
    }
    *bufp = buf;
    *bufsizep = bufsize;
    return len;
}
#endif
