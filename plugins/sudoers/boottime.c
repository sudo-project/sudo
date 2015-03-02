/*
 * Copyright (c) 2009-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#ifdef HAVE_STRING_H
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <limits.h>
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifndef __linux__
# if defined(HAVE_SYSCTL) && defined(KERN_BOOTTIME)
#  include <sys/sysctl.h>
# elif defined(HAVE_GETUTXID)
#  include <utmpx.h>
# elif defined(HAVE_GETUTID)
#  include <utmp.h>
# endif
#endif /* !__linux__ */

#include "sudoers.h"

/*
 * Fill in a struct timespec with the time the system booted.
 * Returns 1 on success and 0 on failure.
 */

#if defined(__linux__)
bool
get_boottime(struct timespec *ts)
{
    char *line = NULL;
    size_t linesize = 0;
    bool found = false;
    ssize_t len;
    FILE *fp;
    debug_decl(get_boottime, SUDOERS_DEBUG_UTIL)

    /* read btime from /proc/stat */
    fp = fopen("/proc/stat", "r");
    if (fp != NULL) {
	while ((len = getline(&line, &linesize, fp)) != -1) {
	    if (strncmp(line, "btime ", 6) == 0) {
		long long llval = strtonum(line + 6, 1, LLONG_MAX, NULL);
		if (llval > 0) {
		    ts->tv_sec = (time_t)llval;
		    ts->tv_nsec = 0;
		    found = true;
		    break;
		}
	    }
	}
	fclose(fp);
	free(line);
    }

    debug_return_bool(found);
}

#elif defined(HAVE_SYSCTL) && defined(KERN_BOOTTIME)

bool
get_boottime(struct timespec *ts)
{
    size_t size;
    int mib[2];
    struct timeval tv;
    debug_decl(get_boottime, SUDOERS_DEBUG_UTIL)

    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;
    size = sizeof(tv);
    if (sysctl(mib, 2, &tv, &size, NULL, 0) != -1) {
	TIMEVAL_TO_TIMESPEC(&tv, ts);
	debug_return_bool(true);
    }

    debug_return_bool(false);
}

#elif defined(HAVE_GETUTXID)

bool
get_boottime(struct timespec *ts)
{
    struct utmpx *ut, key;
    debug_decl(get_boottime, SUDOERS_DEBUG_UTIL)

    memset(&key, 0, sizeof(key));
    key.ut_type = BOOT_TIME;
    setutxent();
    if ((ut = getutxid(&key)) != NULL)
	TIMEVAL_TO_TIMESPEC(&ut->ut_tv, ts);
    endutxent();
    debug_return_bool(ut != NULL);
}

#elif defined(HAVE_GETUTID)

bool
get_boottime(struct timespec *ts)
{
    struct utmp *ut, key;
    debug_decl(get_boottime, SUDOERS_DEBUG_UTIL)

    memset(&key, 0, sizeof(key));
    key.ut_type = BOOT_TIME;
    setutent();
    if ((ut = getutid(&key)) != NULL) {
	ts->tv_sec = ut->ut_time;
	ts->tv_nsec = 0;
    }
    endutent();
    debug_return_bool(ut != NULL);
}

#else

bool
get_boottime(struct timespec *ts)
{
    debug_decl(get_boottime, SUDOERS_DEBUG_UTIL)
    debug_return_bool(false);
}
#endif
