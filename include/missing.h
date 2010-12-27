/*
 * Copyright (c) 1996, 1998-2005, 2008, 2009-2010
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

#ifndef _SUDO_MISSING_H
#define _SUDO_MISSING_H

#include <stdio.h>
#include <stdarg.h>

/*
 * Macros and functions that may be missing on some operating systems.
 */

/* Define away __attribute__ for non-gcc or old gcc */
#if !defined(__GNUC__) || __GNUC__ < 2 || __GNUC__ == 2 && __GNUC_MINOR__ < 5
# define __attribute__(x)
#endif

/* For silencing gcc warnings about rcsids */
#ifndef __unused
# if defined(__GNUC__) && (__GNUC__ > 2 || __GNUC__ == 2 && __GNUC_MINOR__ > 7)
#  define __unused	__attribute__((__unused__))
# else
#  define __unused
# endif
#endif

/* For catching format string mismatches */
#ifndef __printflike
# if defined(__GNUC__) && (__GNUC__ > 2 || __GNUC__ == 2 && __GNUC_MINOR__ >= 7)
#  define __printflike(f, v) 	__attribute__((__format__ (__printf__, f, v)))
# else
#  define __printflike(f, v)
# endif
#endif

/*
 * Some systems lack full limit definitions.
 */
#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#ifndef INT_MAX
# define INT_MAX	0x7fffffff
#endif

#ifndef PATH_MAX
# ifdef MAXPATHLEN
#  define PATH_MAX		MAXPATHLEN
# else
#  ifdef _POSIX_PATH_MAX
#   define PATH_MAX		_POSIX_PATH_MAX
#  else
#   define PATH_MAX		1024
#  endif
# endif
#endif

#ifndef MAXHOSTNAMELEN
# define MAXHOSTNAMELEN		64
#endif

/*
 * Posix versions for those without...
 */
#ifndef _S_IFMT
# define _S_IFMT		S_IFMT
#endif /* _S_IFMT */
#ifndef _S_IFREG
# define _S_IFREG		S_IFREG
#endif /* _S_IFREG */
#ifndef _S_IFDIR
# define _S_IFDIR		S_IFDIR
#endif /* _S_IFDIR */
#ifndef _S_IFLNK
# define _S_IFLNK		S_IFLNK
#endif /* _S_IFLNK */
#ifndef S_ISREG
# define S_ISREG(m)		(((m) & _S_IFMT) == _S_IFREG)
#endif /* S_ISREG */
#ifndef S_ISDIR
# define S_ISDIR(m)		(((m) & _S_IFMT) == _S_IFDIR)
#endif /* S_ISDIR */

/*
 * Some OS's may not have this.
 */
#ifndef S_IRWXU
# define S_IRWXU		0000700		/* rwx for owner */
#endif /* S_IRWXU */

/*
 * These should be defined in <unistd.h> but not everyone has them.
 */
#ifndef STDIN_FILENO
# define	STDIN_FILENO	0
#endif
#ifndef STDOUT_FILENO
# define	STDOUT_FILENO	1
#endif
#ifndef STDERR_FILENO
# define	STDERR_FILENO	2
#endif

/*
 * BSD defines these in <sys/param.h> but others may not.
 */
#ifndef MIN
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif

/*
 * Simple isblank() macro and function for systems without it.
 */
#ifndef HAVE_ISBLANK
int isblank(int);
# define isblank(_x)	((_x) == ' ' || (_x) == '\t')
#endif

/*
 * NCR's SVr4 has _innetgr(3) instead of innetgr(3) for some reason.
 */
#ifdef HAVE__INNETGR
# define innetgr(n, h, u, d)	(_innetgr(n, h, u, d))
# define HAVE_INNETGR 1
#endif /* HAVE__INNETGR */

/*
 * On POSIX systems, O_NOCTTY is the default so some OS's may lack this define.
 */
#ifndef O_NOCTTY
# define O_NOCTTY	0
#endif /* O_NOCTTY */

/*
 * Add IRIX-like sigaction_t for those without it.
 * SA_RESTART is not required by POSIX; SunOS has SA_INTERRUPT instead.
 */
#ifndef HAVE_SIGACTION_T
typedef struct sigaction sigaction_t;
#endif
#ifndef SA_INTERRUPT
# define SA_INTERRUPT	0
#endif
#ifndef SA_RESTART
# define SA_RESTART	0
#endif

/*
 * If dirfd() does not exists, hopefully dd_fd does.
 */
#if !defined(HAVE_DIRFD) && defined(HAVE_DD_FD)
# define dirfd(_d)	((_d)->dd_fd)
# define HAVE_DIRFD
#endif

/*
 * Define futimes() in terms of futimesat() if needed.
 */
#if !defined(HAVE_FUTIMES) && defined(HAVE_FUTIMESAT)
# define futimes(_f, _tv)	futimesat(_f, NULL, _tv)
# define HAVE_FUTIMES
#endif

#if !defined(HAVE_KILLPG) && !defined(killpg)
# define killpg(s)	kill(-(s))
#endif

/*
 * If we lack getprogname(), emulate with __progname if possible.
 * Otherwise, add a prototype for use with our own getprogname.c.
 */
#ifndef HAVE_GETPROGNAME
# ifdef HAVE___PROGNAME
extern const char *__progname;
#  define getprogname()          (__progname)
# else
const char *getprogname(void);
void setprogname(const char *);
#endif /* HAVE___PROGNAME */
#endif /* !HAVE_GETPROGNAME */

#ifndef timevalclear
# define timevalclear(tv)	((tv)->tv_sec = (tv)->tv_usec = 0)
#endif
#ifndef timevalisset
# define timevalisset(tv)	((tv)->tv_sec || (tv)->tv_usec)
#endif
#ifndef timevalcmp
# define timevalcmp(tv1, tv2, op)					       \
    (((tv1)->tv_sec == (tv2)->tv_sec) ?					       \
	((tv1)->tv_usec op (tv2)->tv_usec) :				       \
	((tv1)->tv_sec op (tv2)->tv_sec))
#endif
#ifndef timevaladd
# define timevaladd(tv1, tv2)						       \
    do {								       \
	(tv1)->tv_sec += (tv2)->tv_sec;					       \
	(tv1)->tv_usec += (tv2)->tv_usec;				       \
	if ((tv1)->tv_usec >= 1000000) {				       \
	    (tv1)->tv_sec++;						       \
	    (tv1)->tv_usec -= 1000000;					       \
	}								       \
    } while (0)
#endif
#ifndef timevalsub
# define timevalsub(tv1, tv2)						       \
    do {								       \
	(tv1)->tv_sec -= (tv2)->tv_sec;					       \
	(tv1)->tv_usec -= (tv2)->tv_usec;				       \
	if ((tv1)->tv_usec < 0) {					       \
	    (tv1)->tv_sec--;						       \
	    (tv1)->tv_usec += 1000000;					       \
	}								       \
    } while (0)
#endif

/* Not all systems define NSIG in signal.h */
#if !defined(NSIG)
# if defined(_NSIG)
#  define NSIG _NSIG
# elif defined(__NSIG)
#  define NSIG __NSIG
# else
#  define NSIG 64
# endif
#endif

#ifndef WCOREDUMP
# define WCOREDUMP(x)	((x) & 0x80)
#endif

#ifndef HAVE_SETEUID
#  if defined(HAVE_SETRESUID)
#    define seteuid(u)	setresuid(-1, (u), -1)
#    define setegid(g)	setresgid(-1, (g), -1)
#    define HAVE_SETEUID 1
#  elif defined(HAVE_SETREUID)
#    define seteuid(u)	setreuid(-1, (u))
#    define setegid(g)	setregid(-1, (g))
#    define HAVE_SETEUID 1
#  endif
#endif /* HAVE_SETEUID */

/*
 * HP-UX does not declare innetgr() or getdomainname().
 * Solaris does not declare getdomainname().
 */
#if defined(__hpux)
int innetgr(const char *, const char *, const char *, const char *);
#endif
#if defined(__hpux) || defined(__sun)
int getdomainname(char *, size_t);
#endif

/* Functions "missing" from libc. */

struct timeval;
struct timespec;

#ifndef HAVE_CLOSEFROM
void closefrom(int);
#endif
#ifndef HAVE_GETCWD
char *getcwd(char *, size_t size);
#endif
#ifndef HAVE_GETLINE
ssize_t getline(char **, size_t *, FILE *);
#endif
#ifndef HAVE_UTIMES
int utimes(const char *, const struct timeval *);
#endif
#ifdef HAVE_FUTIME
int futimes(int, const struct timeval *);
#endif
#ifndef HAVE_SNPRINTF
int snprintf(char *, size_t, const char *, ...) __printflike(3, 4);
#endif
#ifndef HAVE_VSNPRINTF
int vsnprintf(char *, size_t, const char *, va_list) __printflike(3, 0);
#endif
#ifndef HAVE_ASPRINTF
int asprintf(char **, const char *, ...) __printflike(2, 3);
#endif
#ifndef HAVE_VASPRINTF
int vasprintf(char **, const char *, va_list) __printflike(2, 0);
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *, const char *, size_t);
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif
#ifndef HAVE_MEMRCHR
void *memrchr(const void *, int, size_t);
#endif
#ifndef HAVE_MKDTEMP
char *mkdtemp(char *);
#endif
#ifndef HAVE_MKSTEMPS
int mkstemps(char *, int);
#endif
#ifndef HAVE_NANOSLEEP
int nanosleep(const struct timespec *, struct timespec *);
#endif
#ifndef HAVE_SETENV
int setenv(const char *, const char *, int);
#endif
#ifndef HAVE_UNSETENV
int unsetenv(const char *);
#endif
#ifndef HAVE_STRSIGNAL
char *strsignal(int);
#endif

#endif /* _SUDO_MISSING_H */
