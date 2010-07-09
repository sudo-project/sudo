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

#ifndef _SUDO_MISSING_H
#define _SUDO_MISSING_H

#ifdef __STDC__
# include <stdarg.h>
#else
# include <varargs.h>
#endif

/* Functions "missing" from libc. */

struct timeval;
struct timespec;

#ifndef HAVE_CLOSEFROM
void closefrom		__P((int));
#endif
#ifndef HAVE_GETCWD
char *getcwd		__P((char *, size_t size));
#endif
#ifndef HAVE_GETLINE
ssize_t getline		__P((char **, size_t *, FILE *));
#endif
#ifndef HAVE_UTIMES
int utimes		__P((const char *, const struct timeval *));
#endif
#ifdef HAVE_FUTIME
int futimes		__P((int, const struct timeval *));
#endif
#ifndef HAVE_SNPRINTF
int snprintf		__P((char *, size_t, const char *, ...))
			    __printflike(3, 4);
#endif
#ifndef HAVE_VSNPRINTF
int vsnprintf		__P((char *, size_t, const char *, va_list))
			    __printflike(3, 0);
#endif
#ifndef HAVE_ASPRINTF
int asprintf		__P((char **, const char *, ...))
			    __printflike(2, 3);
#endif
#ifndef HAVE_VASPRINTF
int vasprintf		__P((char **, const char *, va_list))
			    __printflike(2, 0);
#endif
#ifndef HAVE_STRCASECMP
int strcasecmp		__P((const char *, const char *));
#endif
#ifndef HAVE_STRLCAT
size_t strlcat		__P((char *, const char *, size_t));
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy		__P((char *, const char *, size_t));
#endif
#ifndef HAVE_MEMRCHR
void *memrchr		__P((const void *, int, size_t));
#endif
#ifndef HAVE_MKSTEMPS
int mkstemps		__P((char *, int));
#endif
#ifndef HAVE_NANOSLEEP
int nanosleep		__P((const struct timespec *, struct timespec *));
#endif
#ifndef HAVE_SETENV
int setenv		__P((const char *, const char *, int));
#endif
#ifndef HAVE_UNSETENV
int unsetenv		__P((const char *));
#endif
#ifndef HAVE_STRSIGNAL
char *strsignal		__P((int));
#endif
#ifndef HAVE_SETSID
pid_t setsid		__P((void));
#endif

#endif /* _SUDO_MISSING_H */
