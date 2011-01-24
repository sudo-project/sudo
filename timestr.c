/*
 * Copyright (c) 1999, 2009 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <time.h>

#include "missing.h"

char *get_timestr	__P((time_t, int));

/*
 * Return an ascii string with the current date + time
 * Uses strftime() if available, else falls back to ctime().
 */
char *
get_timestr(tstamp, log_year)
    time_t tstamp;
    int log_year;
{
    char *s;
#ifdef HAVE_STRFTIME
    static char buf[128];
    struct tm *timeptr;

    timeptr = localtime(&tstamp);
    if (log_year)
	s = "%h %e %T %Y";
    else
	s = "%h %e %T";

    /* strftime() does not guarantee to NUL-terminate so we must check. */
    buf[sizeof(buf) - 1] = '\0';
    if (strftime(buf, sizeof(buf), s, timeptr) && buf[sizeof(buf) - 1] == '\0')
	return buf;

#endif /* HAVE_STRFTIME */

    s = ctime(&tstamp) + 4;		/* skip day of the week */
    if (log_year)
	s[20] = '\0';			/* avoid the newline */
    else
	s[15] = '\0';			/* don't care about year */

    return s;
}
