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
#include <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifndef HAVE_TIMESPEC
# include <emul/timespec.h>
#endif
#include <errno.h>

#include "compat.h"

int
nanosleep(ts, rts)
    const struct timespec *ts;
    struct timespec *rts;
{
    struct timeval timeout, endtime, now;
    int rval;

    timeout.tv_sec = ts->tv_sec;
    timeout.tv_usec = ts->tv_nsec / 1000;
    if (rts != NULL) {
	gettimeofday(&endtime, NULL);
	timevaladd(&endtime, &timeout);
    }
    rval = select(0, NULL, NULL, NULL, &timeout);
    if (rts != NULL && rval == -1 && errno == EINTR) {
	gettimeofday(&now, NULL);
	timevalsub(&endtime, &now);
	rts->tv_sec = endtime.tv_sec;
	rts->tv_nsec = endtime.tv_usec * 1000;
    }
    return(rval);
}
