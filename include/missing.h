/*
 * Copyright (c) 1996, 1998-2005, 2008, 2009-2014
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
#ifdef STDC_HEADERS
# include <stddef.h>
#endif
#include <stdarg.h>

/*
 * Macros and functions that may be missing on some operating systems.
 */

#ifndef __GNUC_PREREQ__
# ifdef __GNUC__
#  define __GNUC_PREREQ__(ma, mi) \
	((__GNUC__ > (ma)) || (__GNUC__ == (ma) && __GNUC_MINOR__ >= (mi)))
# else
#  define __GNUC_PREREQ__(ma, mi)	0
# endif
#endif

/* Define away __attribute__ for non-gcc or old gcc */
#if !defined(__attribute__) && !__GNUC_PREREQ__(2, 5)
# define __attribute__(x)
#endif

/* For catching format string mismatches */
#ifndef __printflike
# if __GNUC_PREREQ__(3, 3)
#  define __printflike(f, v) 	__attribute__((__format__ (__printf__, f, v))) __attribute__((__nonnull__ (f)))
# elif __GNUC_PREREQ__(2, 7)
#  define __printflike(f, v) 	__attribute__((__format__ (__printf__, f, v)))
# else
#  define __printflike(f, v)
# endif
#endif
#ifndef __printf0like
# if __GNUC_PREREQ__(2, 7)
#  define __printf0like(f, v) 	__attribute__((__format__ (__printf__, f, v)))
# else
#  define __printf0like(f, v)
# endif
#endif
#ifndef __format_arg
# if __GNUC_PREREQ__(2, 7)
#  define __format_arg(f) 	__attribute__((__format_arg__ (f)))
# else
#  define __format_arg(f)
# endif
#endif

/* Hint to compiler that returned pointer is unique (malloc but not realloc). */
#ifndef __malloc_like
# if __GNUC_PREREQ__(2, 96)
#  define __malloc_like 	__attribute__((__malloc__))
# else
#  define __malloc_like
# endif
#endif

/*
 * Given the pointer x to the member m of the struct s, return
 * a pointer to the containing structure.
 */
#ifndef __containerof
# define __containerof(x, s, m)	((s *)((char *)(x) - offsetof(s, m)))
#endif

#ifndef __dso_public
# ifdef HAVE_DSO_VISIBILITY
#  if defined(__GNUC__)
#   define __dso_public	__attribute__((__visibility__("default")))
#   define __dso_hidden	__attribute__((__visibility__("hidden")))
#  elif defined(__SUNPRO_C)
#   define __dso_public	__global
#   define __dso_hidden __hidden
#  else
#   define __dso_public	__declspec(dllexport)
#   define __dso_hidden
#  endif
# else
#  define __dso_public
#  define __dso_hidden
# endif
#endif

/*
 * Pre-C99 compilers may lack a va_copy macro.
 */
#ifndef va_copy
# ifdef __va_copy
#  define va_copy(d, s) __va_copy(d, s)
# else
#  define va_copy(d, s) memcpy(&(d), &(s), sizeof(d));
# endif
#endif

/*
 * Some systems lack full limit definitions.
 */
#ifndef OPEN_MAX
# define OPEN_MAX	256
#endif

#ifndef LLONG_MAX
# if defined(QUAD_MAX)
#  define LLONG_MAX	QUAD_MAX
# else
#  define LLONG_MAX	0x7fffffffffffffffLL
# endif
#endif

#ifndef LLONG_MIN
# if defined(QUAD_MIN)
#  define LLONG_MIN	QUAD_MIN
# else
#  define LLONG_MIN	(-0x7fffffffffffffffLL-1)
# endif
#endif

#ifndef ULLONG_MAX
# if defined(UQUAD_MAX)
#  define ULLONG_MAX	UQUAD_MAX
# else
#  define ULLONG_MAX	0xffffffffffffffffULL
# endif
#endif

#ifndef PATH_MAX
# ifdef _POSIX_PATH_MAX
#  define PATH_MAX		_POSIX_PATH_MAX
# else
#  define PATH_MAX		256
# endif
#endif

#ifndef HOST_NAME_MAX
# ifdef _POSIX_HOST_NAME_MAX
#  define HOST_NAME_MAX		_POSIX_HOST_NAME_MAX
# else
#  define HOST_NAME_MAX		255
# endif
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
 * BSD defines these in <sys/param.h> but we don't include that anymore.
 */
#ifndef MIN
# define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#ifndef MAX
# define MAX(a,b) (((a)>(b))?(a):(b))
#endif

/* Macros to set/clear/test flags. */
#undef SET
#define SET(t, f)	((t) |= (f))
#undef CLR
#define CLR(t, f)	((t) &= ~(f))
#undef ISSET
#define ISSET(t, f)     ((t) & (f))

/*
 * Older systems may be missing stddef.h and/or offsetof macro
 */
#ifndef offsetof
# ifdef __offsetof
#  define offsetof(type, field) __offsetof(type, field)
# else
#  define offsetof(type, field) ((size_t)(&((type *)0)->field))
# endif
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
#  define getprogname()		(__progname)
# else
const char *getprogname(void);
# endif /* HAVE___PROGNAME */
#endif /* !HAVE_GETPROGNAME */

/*
 * Declare errno if errno.h doesn't do it for us.
 */
#if defined(HAVE_DECL_ERRNO) && !HAVE_DECL_ERRNO
extern int errno;
#endif /* !HAVE_DECL_ERRNO */

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

/* For sig2str() */
#ifndef SIG2STR_MAX
# define SIG2STR_MAX 32
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
#ifndef HAVE_GETGROUPLIST
int getgrouplist(const char *, gid_t, gid_t *, int *);
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
#if !defined(HAVE_SNPRINTF) || defined(PREFER_PORTABLE_SNPRINTF)
int rpl_snprintf(char *, size_t, const char *, ...) __printflike(3, 4);
# undef snprintf
# define snprintf rpl_snprintf
#endif
#if !defined(HAVE_VSNPRINTF) || defined(PREFER_PORTABLE_SNPRINTF)
int rpl_vsnprintf(char *, size_t, const char *, va_list) __printflike(3, 0);
# undef vsnprintf
# define vsnprintf rpl_vsnprintf
#endif
#if !defined(HAVE_ASPRINTF) || defined(PREFER_PORTABLE_SNPRINTF)
int rpl_asprintf(char **, const char *, ...) __printflike(2, 3);
# undef asprintf
# define asprintf rpl_asprintf
#endif
#if !defined(HAVE_VASPRINTF) || defined(PREFER_PORTABLE_SNPRINTF)
int rpl_vasprintf(char **, const char *, va_list) __printflike(2, 0);
# undef vasprintf
# define vasprintf rpl_vasprintf
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
#ifndef HAVE_MEMSET_S
errno_t memset_s(void *, rsize_t, int, rsize_t);
#endif
#ifndef HAVE_MKDTEMP
char *mkdtemp(char *);
#endif
#ifndef HAVE_MKSTEMPS
int mkstemps(char *, int);
#endif
#ifndef HAVE_PW_DUP
struct passwd *pw_dup(const struct passwd *);
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
#ifndef HAVE_SIG2STR
int sig2str(int, char *);
#endif
#ifndef HAVE_STRTONUM
long long rpl_strtonum(const char *, long long, long long, const char **);
# undef strtonum
# define strtonum rpl_strtonum
#endif
#ifndef HAVE_CLOCK_GETTIME
# define CLOCK_REALTIME 0
# ifdef __MACH__
#  define CLOCK_MONOTONIC 1
# endif
int clock_gettime(clockid_t clock_id, struct timespec *tp);
#endif
#ifndef HAVE_INET_PTON
int inet_pton(int af, const char *src, void *dst);
#endif

#endif /* _SUDO_MISSING_H */
