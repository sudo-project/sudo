/*
 * Copyright (c) 2004-2005, 2008, 2010
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/time.h>
#include <stdio.h>
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif

#include <compat.h>

/*
 * Get the current time via gettimeofday() for systems with
 * timespecs in struct stat or, otherwise, using time().
 */
int
gettime(tv)
    struct timeval *tv;
{
    int rval;
#if defined(HAVE_GETTIMEOFDAY) && (defined(HAVE_ST_MTIM) || defined(HAVE_ST_MTIMESPEC))
    rval = gettimeofday(tv, NULL);
#else
    rval = (int)time(&tv->tv_sec);
    tv->tv_usec = 0;
#endif
    return (rval);
}
