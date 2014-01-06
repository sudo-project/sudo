/*
 * Copyright (c) 1999-2005, 2007, 2009-2013
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_FLOCK
# include <sys/file.h>
#endif /* HAVE_FLOCK */
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
#endif /* HAVE_STRING_H */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <ctype.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <fcntl.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifndef HAVE_STRUCT_TIMESPEC
# include "compat/timespec.h"
#endif

#include "missing.h"
#include "fileops.h"
#include "sudo_debug.h"

/*
 * Update the access and modify times on an fd or file.
 */
int
touch(int fd, char *path, struct timeval *tvp)
{
    struct timeval times[2];
    int rval = -1;
    debug_decl(touch, SUDO_DEBUG_UTIL)

    if (tvp != NULL) {
	times[0].tv_sec = times[1].tv_sec = tvp->tv_sec;
	times[0].tv_usec = times[1].tv_usec = tvp->tv_usec;
    }

#if defined(HAVE_FUTIME) || defined(HAVE_FUTIMES)
    if (fd != -1)
	rval = futimes(fd, tvp ? times : NULL);
    else
#endif
    if (path != NULL)
	rval = utimes(path, tvp ? times : NULL);
    debug_return_int(rval);
}

/*
 * Lock/unlock a file.
 */
#ifdef HAVE_LOCKF
bool
lock_file(int fd, int lockit)
{
    int op = 0;
    debug_decl(lock_file, SUDO_DEBUG_UTIL)

    switch (lockit) {
	case SUDO_LOCK:
	    op = F_LOCK;
	    break;
	case SUDO_TLOCK:
	    op = F_TLOCK;
	    break;
	case SUDO_UNLOCK:
	    op = F_ULOCK;
	    break;
    }
    debug_return_bool(lockf(fd, op, 0) == 0);
}
#elif defined(HAVE_FLOCK)
bool
lock_file(int fd, int lockit)
{
    int op = 0;
    debug_decl(lock_file, SUDO_DEBUG_UTIL)

    switch (lockit) {
	case SUDO_LOCK:
	    op = LOCK_EX;
	    break;
	case SUDO_TLOCK:
	    op = LOCK_EX | LOCK_NB;
	    break;
	case SUDO_UNLOCK:
	    op = LOCK_UN;
	    break;
    }
    debug_return_bool(flock(fd, op) == 0);
}
#else
bool
lock_file(int fd, int lockit)
{
#ifdef F_SETLK
    int func;
    struct flock lock;
    debug_decl(lock_file, SUDO_DEBUG_UTIL)

    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_pid = getpid();
    lock.l_type = (lockit == SUDO_UNLOCK) ? F_UNLCK : F_WRLCK;
    lock.l_whence = SEEK_SET;
    func = (lockit == SUDO_LOCK) ? F_SETLKW : F_SETLK;

    debug_return_bool(fcntl(fd, func, &lock) == 0);
#else
    return true;
#endif
}
#endif

/*
 * Read a line of input, honoring line continuation chars.
 * Remove comments and strips off leading and trailing spaces.
 * Returns the line length and updates the buf and bufsize pointers.
 * XXX - just use a struct w/ state, including getline buffer?
 *       could also make comment char and line continuation configurable
 */
ssize_t
sudo_parseln(char **bufp, size_t *bufsizep, unsigned int *lineno, FILE *fp)
{
    size_t linesize = 0, total = 0;
    ssize_t len;
    char *cp, *line = NULL;
    bool continued;
    debug_decl(sudo_parseln, SUDO_DEBUG_UTIL)

    do {
	continued = false;
	len = getline(&line, &linesize, fp);
	if (len == -1)
	    break;
	if (lineno != NULL)
	    (*lineno)++;

	/* Remove trailing newline(s) if present. */
	while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
	    line[--len] = '\0';

	/* Remove comments or check for line continuation (but not both) */
	if ((cp = strchr(line, '#')) != NULL) {
	    *cp = '\0';
	    len = (size_t)(cp - line);
	} else if (len > 0 && line[len - 1] == '\\' && (len == 1 || line[len - 2] != '\\')) {
	    line[--len] = '\0';
	    continued = true;
	}

	/* Trim leading and trailing whitespace */
	if (!continued) {
	    while (len > 0 && isblank((unsigned char)line[len - 1]))
		line[--len] = '\0';
	}
	for (cp = line; isblank((unsigned char)*cp); cp++)
	    len--;

	if (*bufp == NULL || total + len >= *bufsizep) {
	    void *tmp;
	    size_t size = total + len + 1;

	    if (size < 64) {
		size = 64;
	    } else if (size <= 0x80000000) {
		/* Round up to next highest power of two. */
		size--;
		size |= size >> 1;
		size |= size >> 2;
		size |= size >> 4;
		size |= size >> 8;
		size |= size >> 16;
		size++;
	    }
	    if ((tmp = realloc(*bufp, size)) == NULL)
		break;
	    *bufp = tmp;
	    *bufsizep = size;
	}
	memcpy(*bufp + total, cp, len + 1);
	total += len;
    } while (continued);
    free(line);
    if (len == -1 && total == 0)
	debug_return_size_t((size_t)-1);
    debug_return_size_t(total);
}
