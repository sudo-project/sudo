/*
 * Copyright (c) 2009 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifndef HAVE_TIMESPEC
# include <emul/timespec.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include <pathnames.h>

#include "compat.h"
#include "error.h"

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

/* For getopt(3) */
extern char *optarg;
extern int optind;

int Argc;
char **Argv;
const char *session_dir = _PATH_SUDO_SESSDIR;

void usage __P((void));
void delay __P((double));
int list_sessions __P((int, char **));

/*
 * TODO: expand ability to scan for session files:
 *       scan by command (regex?), user, tty, provide summary
 */

int
main(argc, argv)
    int argc;
    char **argv;
{
    int ch, plen;
    int listonly = 0;
    char path[PATH_MAX];
    char buf[BUFSIZ];
    const char *user, *id, *tty = NULL;
    char *cp, *ep;
    FILE *tfile, *sfile, *lfile;
    double seconds;
    unsigned long nbytes;
    size_t len, nread;
    double speed = 1.0;

    Argc = argc;
    Argv = argv;

    while ((ch = getopt(argc, argv, "d:ls:t:")) != -1) {
	switch(ch) {
	case 'd':
	    session_dir = optarg;
	    break;
	case 'l':
	    listonly = 1;
	    break;
	case 's':
	    errno = 0;
	    speed = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		error(1, "invalid speed factor: %s", optarg);
	    break;
	case 't':
	    tty = optarg;
	    break;
	default:
	    usage();
	    /* NOTREACHED */
	}

    }
    argc -= optind;
    argv += optind;

    if (listonly) {
	exit(list_sessions(argc, argv));
    }

    if (argc != 2 && argc != 3)
	usage();

    user = argv[0];
    id = argv[1];

    plen = snprintf(path, sizeof(path), "%s/%s/%s.tim", session_dir, user, id);
    if (plen <= 0 || plen >= sizeof(path))
	errorx(1, "%s/%s/%s: %s", session_dir, user, id, strerror(ENAMETOOLONG));

    /* timing file */
    tfile = fopen(path, "r");
    if (tfile == NULL)
	error(1, "unable to open %s", path);

    /* script file */
    memcpy(&path[plen - 3], "scr", 3);
    sfile = fopen(path, "r");
    if (sfile == NULL)
	error(1, "unable to open %s", path);

    /* log file */
    path[plen - 4] = '\0';
    lfile = fopen(path, "r");
    if (lfile == NULL)
	error(1, "unable to open %s", path);

    /* XXX - better */
    fgets(buf, sizeof(buf), lfile); /* XXX - ignore first line */
    fgets(buf, sizeof(buf), lfile);
    printf("Replaying sudo session: %s", buf);

    /*
     * Timing file consists of line of the format: "%f %d\n"
     */
    while (fgets(buf, sizeof(buf), tfile) != NULL) {
	errno = 0;
	seconds = strtod(buf, &ep);
	if (errno != 0 || !isspace((unsigned char) *ep))
	    error(1, "invalid timing file line: %s", buf);
	for (cp = ep + 1; isspace((unsigned char) *cp); cp++)
	    continue;
	errno = 0;
	nbytes = strtoul(cp, &ep, 10);
	if (errno == ERANGE && nbytes == ULONG_MAX)
	    error(1, "invalid timing file byte count: %s", cp);

	fflush(stdout);
	delay(seconds / speed);
	while (nbytes != 0) {
	    if (nbytes > sizeof(buf))
		len = sizeof(buf);
	    else
		len = nbytes;
	    /* XXX - read/write all of len */
	    nread = fread(buf, 1, len, sfile);
	    fwrite(buf, nread, 1, stdout);
	    nbytes -= nread;
	}
    }
    exit(0);
}

#ifndef HAVE_NANOSLEEP
static int
nanosleep(ts, rts)
    const struct timespec *ts;
    struct timespec *rts;
{
    struct timeval timeout, endtime, now;
    int rval;

    timeout.tv_sec = ts->tv_sec;
    timeout.tv_usec = ts->tv_nsecs / 1000;
    if (rts != NULL) {
	gettimeofday(&endtime, NULL);
	timeradd(&endtime, &timeout, &endtime);
    }
    rval = select(NULL, NULL, NULL, &timeout);
    if (rts != NULL && rval == -1 && errno == EINTR) {
	gettimeofday(&now, NULL);
	timersub(&endtime, &now, &timeout);
	rts->tv_sec = timeout.tv_sec;
	rts->tv_nsec = timeout.tv_usec * 1000;
    }
    return(rval);
}
#endif

void
delay(secs)
    double secs;
{
    struct timespec ts, rts;
    int rval;

    /*
     * Typical max resolution is 1/HZ but we can't portably check that.
     * If the interval is small enough, just ignore it.
     */
    if (secs < 0.0001)
	return;

    rts.tv_sec = secs;
    rts.tv_nsec = (secs - (double) rts.tv_sec) * 1000000000.0;
    do {
      memcpy(&ts, &rts, sizeof(ts));
      rval = nanosleep(&ts, &rts);
    } while (rval == -1 && errno == EINTR);
    if (rval == -1)
	error(1, "nanosleep: tv_sec %ld, tv_nsec %ld", ts.tv_sec, ts.tv_nsec);
}

int
list_sessions(argc, argv)
    int argc;
    char **argv;
{
    FILE *fp;
    DIR *sess_d, *user_d;
    struct dirent *dp;
    char path[PATH_MAX];
    char buf[BUFSIZ];
    int len, plen;

    sess_d = opendir(session_dir);
    if (sess_d == NULL)
	error(1, "unable to open %s", session_dir);

    /* XXX - ignores optional user and tty for now */

    while ((dp = readdir(sess_d)) != NULL) {
	if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
	    continue;
	plen = snprintf(path, sizeof(path), "%s/%s/", session_dir, dp->d_name);
	if (plen <= 0 || plen >= sizeof(path)) {
	    /* XXX - warn */
	    continue;
	}
	path[--plen] = '\0'; /* chop off the '/' for now */
	user_d = opendir(path);
	if (user_d == NULL && errno != ENOTDIR) {
	    warning("cannot opendir %s", path);
	    continue;
	}
	while ((dp = readdir(user_d)) != NULL) {
	    /* base session (log) file name is 10 characters */
	    len = NAMLEN(dp);
	    if (len != 10)
		continue;
	    /* open log file, print id and command */
	    path[plen] = '/'; /* restore dir separator */
	    strlcpy(path + plen + 1, dp->d_name, sizeof(path) - plen - 1); /* XXX - check */
	    fp = fopen(path, "r");
	    fgets(buf, sizeof(buf), fp); /* XXX - ignore first line */
	    fgets(buf, sizeof(buf), fp);
	    printf("%s: %s", dp->d_name, buf);
	}
    }
    closedir(sess_d);
    return(0);
}

void
usage()
{
    fprintf(stderr, "usage: %s [-d directory] username ID [speed_factor]\n",
	getprogname());
    exit(1);
}

/*
 * Cleanup hook for error()/errorx()
  */
void
cleanup(gotsignal)
  int gotsignal;
{
    /* nothing yet */
}
