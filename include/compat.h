/*
 * Copyright (c) 1996, 1998-2005, 2008, 2010
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

#ifndef _SUDO_COMPAT_H
#define _SUDO_COMPAT_H

/*
 * Macros that may be missing on some Operating Systems
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
 * These should be defined in <unistd.h> but not everyone has them.
 */
#ifndef SEEK_SET
# define	SEEK_SET	0
#endif
#ifndef SEEK_CUR
# define	SEEK_CUR	1
#endif
#ifndef SEEK_END
# define	SEEK_END	2
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
 * Old BSD systems lack strchr(), strrchr(), memset() and memcpy()
 */
#if !defined(HAVE_STRCHR) && !defined(strchr)
# define strchr(_s, _c)	index(_s, _c)
#endif
#if !defined(HAVE_STRRCHR) && !defined(strrchr)
# define strrchr(_s, _c)	rindex(_s, _c)
#endif
#if !defined(HAVE_MEMCPY) && !defined(memcpy)
# define memcpy(_d, _s, _n)	(bcopy(_s, _d, _n))
#endif
#if !defined(HAVE_MEMSET) && !defined(memset)
# define memset(_s, _x, _n)	(bzero(_s, _n))
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
 * Emulate POSIX signals via sigvec(2)
 */
#ifndef HAVE_SIGACTION
# define SA_ONSTACK	SV_ONSTACK
# define SA_RESTART	SV_INTERRUPT		/* opposite effect */
# define SA_RESETHAND	SV_RESETHAND
# define SA_NOCLDSTOP	SV_NOCLDSTOP
# define sa_handler	sv_handler
# define sa_mask	sv_mask
# define sa_flags	sv_flags
typedef struct sigvec sigaction_t;
typedef int sigset_t;
int sigaction(int sig, const sigaction_t *act, sigaction_t *oact);
int sigemptyset(sigset_t *);
int sigfillset(sigset_t *);
int sigaddset(sigset_t *, int);
int sigdelset(sigset_t *, int);
int sigismember(sigset_t *, int);
int sigprocmask(int, const sigset_t *, sigset_t *);
#endif

/*
 * Extra sugar for POSIX signals to deal with the above emulation
 * as well as the fact that SunOS has a SA_INTERRUPT flag.
 */
#ifdef HAVE_SIGACTION
# ifndef HAVE_SIGACTION_T
typedef struct sigaction sigaction_t;
# endif
# ifndef SA_INTERRUPT
#  define SA_INTERRUPT	0
# endif
# ifndef SA_RESTART
#  define SA_RESTART	0
# endif
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

#ifndef timerclear
# define timerclear(ts)	(ts)->tv_sec = (ts)->tv_nsec = 0
#endif
#ifndef timerisset
# define timerisset(ts)	((ts)->tv_sec || (ts)->tv_nsec)
#endif
#ifndef timeradd
# define timeradd(tv1, tv2, total)					       \
    do {								       \
	(total)->tv_sec = (tv1)->tv_sec + (tv2)->tv_sec;		       \
	(total)->tv_usec = (tv1)->tv_usec + (tv2)->tv_usec;		       \
	if ((total)->tv_usec >= 1000000) {				       \
	    (total)->tv_sec++;						       \
	    (total)->tv_usec -= 1000000;				       \
	}								       \
    } while (0)
#endif
#ifndef timersub
# define timersub(minuend, subrahend, difference)			       \
    do {								       \
	(difference)->tv_sec = (minuend)->tv_sec - (subrahend)->tv_sec;	       \
	(difference)->tv_usec = (minuend)->tv_usec - (subrahend)->tv_usec;     \
	if ((difference)->tv_usec < 0) {				       \
	    (difference)->tv_sec--;					       \
	    (difference)->tv_usec += 1000000;				       \
	}								       \
    } while (0)
#endif
#ifndef timercmp
#define timercmp(tv1, tv2, cmp)						       \
    (((tv1)->tv_sec == (tv2)->tv_sec) ?					       \
	((tv1)->tv_usec cmp (tv2)->tv_usec) :				       \
	((tv1)->tv_sec cmp (tv2)->tv_sec))
#endif

#ifndef WCOREDUMP
# define WCOREDUMP(x)	((x) & 0x80)
#endif

#ifndef NGROUPS_MAX
# ifdef NGROUPS
#  define NGROUPS_MAX NGROUPS
# else
#  define NGROUPS_MAX 16
# endif
#endif

#ifndef HAVE_SETEUID
#  if defined(HAVE_SETRESUID)
#    define seteuid(u)	setresuid(-1, (u), -1)
#    define setegid(g)	setresgid(-1, (g), -1)
#    HAVE_SETEUID 1
#  elif defined(HAVE_SETREUID)
#    define seteuid(u)	setreuid(-1, (u))
#    define setegid(g)	setregid(-1, (g))
#    HAVE_SETEUID 1
#  endif
#endif /* HAVE_SETEUID */

#endif /* _SUDO_COMPAT_H */
