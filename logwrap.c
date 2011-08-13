/*
 * Copyright (c) 2011 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include "sudo.h"

void
writeln_wrap(fp, line, len, maxlen)
    FILE *fp;
    char *line;
    size_t len;
    size_t maxlen;
{
    char *indent = "";
    char *beg = line;
    char *end;

    /*
     * Print out line with word wrap around maxlen characters.
     */
    beg = line;
    while (len > maxlen) {
	end = beg + maxlen;
	while (end != beg && *end != ' ')
	    end--;
	if (beg == end) {
	    /* Unable to find word break within maxlen, look beyond. */
	    end = strchr(beg + maxlen, ' ');
	    if (end == NULL)
		break;	/* no word break */
	}
	fprintf(fp, "%s%.*s\n", indent, (int)(end - beg), beg);
	while (*end == ' ')
	    end++;
	len -= (end - beg);
	beg = end;
	if (indent[0] == '\0') {
	    indent = LOG_INDENT;
	    maxlen -= sizeof(LOG_INDENT) - 1;
	}
    }
    /* Print remainder, if any. */
    if (len)
	fprintf(fp, "%s%s\n", indent, beg);
}
