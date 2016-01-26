/*
 * Copyright (c) 2014-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <stdlib.h>
#include <unistd.h>
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#include <errno.h>

#if defined(__MACH__) && !defined(HAVE_CLOCK_GETTIME)
# include <mach/mach.h>
# include <mach/mach_time.h>
# include <mach/clock.h>
#endif

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"

/* On Linux, CLOCK_MONOTONIC does not run while suspended. */
#if defined(CLOCK_BOOTTIME)
# define SUDO_CLOCK_MONOTONIC	CLOCK_BOOTTIME
#elif defined(CLOCK_MONOTONIC)
# define SUDO_CLOCK_MONOTONIC	CLOCK_MONOTONIC
#endif

#if defined(HAVE_CLOCK_GETTIME)
int
sudo_gettime_real_v1(struct timespec *ts)
{
    debug_decl(sudo_gettime_real, SUDO_DEBUG_UTIL)

    if (clock_gettime(CLOCK_REALTIME, ts) == -1) {
	struct timeval tv;

	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "clock_gettime(CLOCK_REALTIME) failed, trying gettimeofday()");
	if (gettimeofday(&tv, NULL) == -1)
	    debug_return_int(-1);
	TIMEVAL_TO_TIMESPEC(&tv, ts);
    }
    debug_return_int(0);
}
#else
int
sudo_gettime_real_v1(struct timespec *ts)
{
    struct timeval tv;
    debug_decl(sudo_gettime_real, SUDO_DEBUG_UTIL)

    if (gettimeofday(&tv, NULL) == -1)
	debug_return_int(-1);
    TIMEVAL_TO_TIMESPEC(&tv, ts);
    debug_return_int(0);
}
#endif

#if defined(HAVE_CLOCK_GETTIME) && defined(SUDO_CLOCK_MONOTONIC)
int
sudo_gettime_mono_v1(struct timespec *ts)
{
    static int has_monoclock = -1;
    debug_decl(sudo_gettime_mono, SUDO_DEBUG_UTIL)

    /* Check whether the kernel/libc actually supports CLOCK_MONOTONIC. */
# ifdef _SC_MONOTONIC_CLOCK
    if (has_monoclock == -1)
	has_monoclock = sysconf(_SC_MONOTONIC_CLOCK) != -1;
# endif
    if (!has_monoclock)
	debug_return_int(sudo_gettime_real(ts));
    if (clock_gettime(SUDO_CLOCK_MONOTONIC, ts) == -1) {
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "clock_gettime(%d) failed, using wall clock",
	    (int)SUDO_CLOCK_MONOTONIC);
	has_monoclock = 0;
	debug_return_int(sudo_gettime_real(ts));
    }
    debug_return_int(0);
}
#elif defined(__MACH__)
int
sudo_gettime_mono_v1(struct timespec *ts)
{
    uint64_t abstime, nsec;
    static mach_timebase_info_data_t timebase_info;
    debug_decl(sudo_gettime_mono, SUDO_DEBUG_UTIL)

    if (timebase_info.denom == 0)
	(void) mach_timebase_info(&timebase_info);
    abstime = mach_absolute_time();
    nsec = abstime * timebase_info.numer / timebase_info.denom;
    ts->tv_sec = nsec / 1000000000;
    ts->tv_nsec = nsec % 1000000000;
    debug_return_int(0);
}
#else
int
sudo_gettime_mono_v1(struct timespec *ts)
{
    /* No monotonic clock available, use wall clock. */
    return sudo_gettime_real(ts);
}
#endif
