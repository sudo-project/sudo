/*
 * Copyright (c) 2013-2014 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_UTIL_H
#define _SUDO_UTIL_H

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

/*
 * Macros for operating on struct timeval.
 */
#define sudo_timevalclear(tv)	((tv)->tv_sec = (tv)->tv_usec = 0)

#define sudo_timevalisset(tv)	((tv)->tv_sec || (tv)->tv_usec)

#define sudo_timevalcmp(tv1, tv2, op)					       \
    (((tv1)->tv_sec == (tv2)->tv_sec) ?					       \
	((tv1)->tv_usec op (tv2)->tv_usec) :				       \
	((tv1)->tv_sec op (tv2)->tv_sec))

#define sudo_timevaladd(tv1, tv2, tv3)					       \
    do {								       \
	(tv3)->tv_sec = (tv1)->tv_sec + (tv2)->tv_sec;			       \
	(tv3)->tv_usec = (tv1)->tv_usec + (tv2)->tv_usec;		       \
	if ((tv3)->tv_usec >= 1000000) {				       \
	    (tv3)->tv_sec++;						       \
	    (tv3)->tv_usec -= 1000000;					       \
	}								       \
    } while (0)

#define sudo_timevalsub(tv1, tv2, tv3)					       \
    do {								       \
	(tv3)->tv_sec = (tv1)->tv_sec - (tv2)->tv_sec;			       \
	(tv3)->tv_usec = (tv1)->tv_usec - (tv2)->tv_usec;		       \
	if ((tv3)->tv_usec < 0) {					       \
	    (tv3)->tv_sec--;						       \
	    (tv3)->tv_usec += 1000000;					       \
	}								       \
    } while (0)

#ifndef TIMEVAL_TO_TIMESPEC
# define TIMEVAL_TO_TIMESPEC(tv, ts)					       \
    do {								       \
	(ts)->tv_sec = (tv)->tv_sec;					       \
	(ts)->tv_nsec = (tv)->tv_usec * 1000;				       \
    } while (0)
#endif

/*
 * Macros for operating on struct timespec.
 */
#define sudo_timespecclear(ts)	((ts)->tv_sec = (ts)->tv_nsec = 0)

#define sudo_timespecisset(ts)	((ts)->tv_sec || (ts)->tv_nsec)

#define sudo_timespeccmp(ts1, ts2, op)					       \
    (((ts1)->tv_sec == (ts2)->tv_sec) ?					       \
	((ts1)->tv_nsec op (ts2)->tv_nsec) :				       \
	((ts1)->tv_sec op (ts2)->tv_sec))

#define sudo_timespecadd(ts1, ts2, ts3)					       \
    do {								       \
	(ts3)->tv_sec = (ts1)->tv_sec + (ts2)->tv_sec;			       \
	(ts3)->tv_nsec = (ts1)->tv_nsec + (ts2)->tv_nsec;		       \
	while ((ts3)->tv_nsec >= 1000000000) {				       \
	    (ts3)->tv_sec++;						       \
	    (ts3)->tv_nsec -= 1000000000;				       \
	}								       \
    } while (0)

#define sudo_timespecsub(ts1, ts2, ts3)					       \
    do {								       \
	(ts3)->tv_sec = (ts1)->tv_sec - (ts2)->tv_sec;			       \
	(ts3)->tv_nsec = (ts1)->tv_nsec - (ts2)->tv_nsec;		       \
	while ((ts3)->tv_nsec < 0) {					       \
	    (ts3)->tv_sec--;						       \
	    (ts3)->tv_nsec += 1000000000;				       \
	}								       \
    } while (0)

#ifndef TIMESPEC_TO_TIMEVAL
# define TIMESPEC_TO_TIMEVAL(tv, ts)					       \
    do {								       \
	(tv)->tv_sec = (ts)->tv_sec;					       \
	(tv)->tv_usec = (ts)->tv_nsec / 1000;				       \
    } while (0)
#endif

/*
 * Macros to extract ctime and mtime as timevals.
 */
#ifdef HAVE_ST_MTIM
# ifdef HAVE_ST__TIM
#  define ctim_get(_x, _y)	TIMESPEC_TO_TIMEVAL((_y), &(_x)->st_ctim.st__tim)
#  define mtim_get(_x, _y)	TIMESPEC_TO_TIMEVAL((_y), &(_x)->st_mtim.st__tim)
# else
#  define ctim_get(_x, _y)	TIMESPEC_TO_TIMEVAL((_y), &(_x)->st_ctim)
#  define mtim_get(_x, _y)	TIMESPEC_TO_TIMEVAL((_y), &(_x)->st_mtim)
# endif
#else
# ifdef HAVE_ST_MTIMESPEC
#  define ctim_get(_x, _y)	TIMESPEC_TO_TIMEVAL((_y), &(_x)->st_ctimespec)
#  define mtim_get(_x, _y)	TIMESPEC_TO_TIMEVAL((_y), &(_x)->st_mtimespec)
# else
#  define ctim_get(_x, _y)	do { (_y)->tv_sec = (_x)->st_ctime; (_y)->tv_usec = 0; } while (0)
#  define mtim_get(_x, _y)	do { (_y)->tv_sec = (_x)->st_mtime; (_y)->tv_usec = 0; } while (0)
# endif /* HAVE_ST_MTIMESPEC */
#endif /* HAVE_ST_MTIM */

/*
 * Macros to quiet gcc's warn_unused_result attribute.
 */
#ifdef __GNUC__
# define ignore_result(x) do {						       \
    __typeof__(x) y = (x);						       \
    (void)y;								       \
} while(0)
#else
# define ignore_result(x)	(void)(x)
#endif

/* aix.c */
void aix_prep_user(char *user, const char *tty);
void aix_restoreauthdb(void);
void aix_setauthdb(char *user);

/* atobool.c */
int atobool(const char *str);

/* atoid.c */
id_t atoid(const char *str, const char *sep, char **endp, const char **errstr);

/* atomode.c */
int atomode(const char *cp, const char **errstr);

/* fmt_string.h */
char *fmt_string(const char *var, const char *value);

/* gidlist.c */
int parse_gid_list(const char *gidstr, const gid_t *basegid, GETGROUPS_T **gidsp);

/* progname.c */
void initprogname(const char *);

/* setgroups.c */
int sudo_setgroups(int ngids, const GETGROUPS_T *gids);

/* term.c */
bool term_cbreak(int);
bool term_copy(int, int);
bool term_noecho(int);
bool term_raw(int, int);
bool term_restore(int, bool);

/* ttysize.c */
void get_ttysize(int *rowp, int *colp);

#endif /* _SUDO_UTIL_H */
