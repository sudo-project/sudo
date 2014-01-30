/*
 * Copyright (c) 2014 Todd C. Miller <Todd.Miller@courtesan.com>
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

#if !defined(HAVE_CLOCK_GETTIME)

#include <sys/types.h>
#include <sys/time.h>

#include <errno.h>
#include <stdio.h>
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifndef HAVE_STRUCT_TIMESPEC
# include "compat/timespec.h"
#endif

#include "missing.h"

#ifdef __MACH__
# include <mach/mach.h>
# include <mach/mach_time.h>
# include <mach/clock.h>
#endif

/*
 * Trivial clock_gettime() that supports CLOCK_REALTIME
 * (and CLOCK_MONOTONIC on Mach).
 */
int
clock_gettime(clockid_t clock_id, struct timespec *ts)
{

    switch (clock_id) {
#ifdef __MACH__
    case CLOCK_MONOTONIC:
	{
	    uint64_t abstime, nsec;
	    static mach_timebase_info_data_t timebase_info;

	    if (timebase_info.denom == 0)
		(void) mach_timebase_info(&timebase_info);
	    abstime = mach_absolute_time();
	    nsec = abstime * timebase_info.numer / timebase_info.denom;
	    ts->tv_sec = nsec / 1000000000;
	    ts->tv_nsec = nsec % 1000000000;
	    return 0;
	}
#endif
    case CLOCK_REALTIME:
	{
	    struct timeval tv;

	    gettimeofday(&tv, NULL);
	    ts->tv_sec = tv.tv_sec;
	    ts->tv_nsec = tv.tv_usec * 1000;
	    return 0;
	}
    default:
	errno = EINVAL;
	return -1;
    }
}

#endif /* !HAVE_CLOCK_GETTIME */
