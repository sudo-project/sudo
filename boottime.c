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

#include <sys/param.h>
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
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifdef HAVE_GETUTXID
# include <utmpx.h>
#endif
#ifdef HAVE_GETUTID
# include <utmp.h>
#endif
#ifdef HAVE_SYSCTL
# include <sys/sysctl.h>
#endif

#include "missing.h"

/*
 * Fill in a struct timeval with the time the system booted.
 * Returns 1 on success and 0 on failure.
 */

#if defined(__linux__)
int
get_boottime(tv)
    struct timeval *tv;
{
    char *line = NULL;
    size_t linesize = 0;
    ssize_t len;
    FILE * fp;

    /* read btime from /proc/stat */
    fp = fopen("/proc/stat", "r");
    if (fp != NULL) {
	while ((len = getline(&line, &linesize, fp)) != -1) {
	    if (strncmp(line, "btime ", 6) == 0) {
		tv->tv_sec = atoi(line + 6);
		tv->tv_usec = 0;
		return 1;
	    }
	}
	fclose(fp);
	free(line);
    }

    return 0;
}

#elif defined(HAVE_SYSCTL) && defined(KERN_BOOTTIME)

int
get_boottime(tv)
    struct timeval *tv;
{
    size_t size;
    int mib[2];

    mib[0] = CTL_KERN;
    mib[1] = KERN_BOOTTIME;
    size = sizeof(*tv);
    if (sysctl(mib, 2, tv, &size, NULL, 0) != -1)
	return 1;

    return 0;
}

#elif defined(HAVE_GETUTXID)

int
get_boottime(tv)
    struct timeval *tv;
{
    struct utmpx *ut, key;

    memset(&key, 0, sizeof(key));
    key.ut_type = BOOT_TIME;
    if ((ut = getutxid(&key)) != NULL) {
	tv->tv_sec = ut->ut_tv.tv_sec;
	tv->tv_usec = ut->ut_tv.tv_usec;
	endutxent();
    }
    return ut != NULL;
}

#elif defined(HAVE_GETUTID)

int
get_boottime(tv)
    struct timeval *tv;
{
    struct utmp *ut, key;

    memset(&key, 0, sizeof(key));
    key.ut_type = BOOT_TIME;
    if ((ut = getutid(&key)) != NULL) {
	tv->tv_sec = ut->ut_time;
	tv->tv_usec = 0;
	endutent();
    }
    return ut != NULL;
}

#else

int
get_boottime(tv)
    struct timeval *tv;
{
    return 0;
}
#endif
