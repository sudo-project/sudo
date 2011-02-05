/*
 * Copyright (c) 2004-2005, 2007 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifdef HAVE_UTIME_H
# include <utime.h>
#else
# include "emul/utime.h"
#endif

#include "missing.h"

#ifndef HAVE_UTIMES
/*
 * Emulate utimes() via utime()
 */
int
utimes(file, times)
    const char *file;
    const struct timeval *times;
{
    if (times != NULL) {
	struct utimbuf utb;

	utb.actime = (time_t)(times[0].tv_sec + times[0].tv_usec / 1000000);
	utb.modtime = (time_t)(times[1].tv_sec + times[1].tv_usec / 1000000);
	return utime(file, &utb);
    } else
	return utime(file, NULL);
}
#endif /* !HAVE_UTIMES */

#ifdef HAVE_FUTIME
/*
 * Emulate futimes() via futime()
 */
int
futimes(fd, times)
    int fd;
    const struct timeval *times;
{
    if (times != NULL) {
	struct utimbuf utb;

	utb.actime = (time_t)(times[0].tv_sec + times[0].tv_usec / 1000000);
	utb.modtime = (time_t)(times[1].tv_sec + times[1].tv_usec / 1000000);
	return futime(fd, &utb);
    } else
	return futime(fd, NULL);
}
#endif /* HAVE_FUTIME */
