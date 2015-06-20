/*
 * Copyright (c) 1999, 2009-2011 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <stdlib.h>
#include <time.h>

#include "sudo_compat.h"

char *get_timestr(time_t, int);

/*
 * Return a static buffer with the current date + time.
 * Uses strftime() if available, else falls back to ctime().
 */
char *
get_timestr(time_t tstamp, int log_year)
{
    char *s;
#ifdef HAVE_STRFTIME
    static char buf[128];
    struct tm *timeptr;

    if ((timeptr = localtime(&tstamp)) != NULL) {
	/* strftime() does not guarantee to NUL-terminate so we must check. */
	buf[sizeof(buf) - 1] = '\0';
	if (strftime(buf, sizeof(buf), log_year ? "%h %e %T %Y" : "%h %e %T",
	    timeptr) != 0 && buf[sizeof(buf) - 1] == '\0')
	    return buf;
    }

#endif /* HAVE_STRFTIME */

    s = ctime(&tstamp);
    if (s != NULL) {
	s += 4;				/* skip day of the week */
	if (log_year)
	    s[20] = '\0';		/* avoid the newline */
	else
	    s[15] = '\0';		/* don't care about year */
    }

    return s;
}
