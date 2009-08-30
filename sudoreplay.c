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
#ifdef HAVE_REGCOMP
# include <regex.h>
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
int list_sessions __P((int, char **, const char *, const char *, const char *));

#ifdef HAVE_REGCOMP
# define REGEX_T	regex_t
#else
# define REGEX_T	char
#endif

#define VALID_ID(s) (isalnum((s)[0]) && isalnum((s)[1]) && isalnum((s)[2]) && \
    isalnum((s)[3]) && isalnum((s)[4]) && isalnum((s)[5]) && (s)[6] == '\0')

/*
 * TODO:
 *  add find-like search language?
 *  timestamp option? (begin,end)
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
    const char *user = NULL, *id, *pattern = NULL, *tty = NULL;
    char *cp, *ep;
    FILE *tfile, *sfile, *lfile;
    double seconds;
    unsigned long nbytes;
    size_t len, nread;
    double speed = 1.0;
    double max_wait = 0;
    double to_wait;

    Argc = argc;
    Argv = argv;

    /* XXX - timestamp option? (begin,end) */
    while ((ch = getopt(argc, argv, "d:lm:p:s:t:u:w:")) != -1) {
	switch(ch) {
	case 'd':
	    session_dir = optarg;
	    break;
	case 'l':
	    listonly = 1;
	    break;
	case 'm':
	    errno = 0;
	    max_wait = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		error(1, "invalid max wait: %s", optarg);
	    break;
	case 'p':
	    pattern = optarg;
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
	case 'u':
	    user = optarg;
	    break;
	default:
	    usage();
	    /* NOTREACHED */
	}

    }
    argc -= optind;
    argv += optind;

    if (listonly) {
	exit(list_sessions(argc, argv, pattern, user, tty));
    }

    if (argc != 1)
	usage();

    /* 6 digit ID in base 36, e.g. 01G712AB */
    id = argv[0];
    if (!VALID_ID(id))
	errorx(1, "invalid ID %s", id);

    plen = snprintf(path, sizeof(path), "%s/%.2s/%.2s/%.2s.tim",
	session_dir, id, &id[2], &id[4]);
    if (plen <= 0 || plen >= sizeof(path))
	errorx(1, "%s/%.2s/%.2s/%.2s/%.2s.tim: %s", session_dir,
	    id, &id[2], &id[4], strerror(ENAMETOOLONG));

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

    if (!fgets(buf, sizeof(buf), lfile) || !fgets(buf, sizeof(buf), lfile))
	errorx(1, "incomplete log file: %s", path);
    fclose(lfile);
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

	/* Adjust delay using speed factor and clamp to max_wait */
	to_wait = seconds / speed;
	if (to_wait > max_wait)
	    to_wait = max_wait;
	delay(to_wait);

	fflush(stdout);
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

struct log_info {
    char *user;
    char *runas_user;
    char *runas_group;
    char *tty;
    char *cmd;
    time_t tstamp;
};

static int
list_session_dir(pathbuf, re, user, tty)
    char *pathbuf;
    REGEX_T *re;
    const char *user;
    const char *tty;
{
    FILE *fp;
    DIR *d;
    struct dirent *dp;
    char buf[BUFSIZ], cmdbuf[BUFSIZ], idstr[7], *cp;
    struct log_info li;
    int len, plen;

    plen = strlen(pathbuf);
    d = opendir(pathbuf);
    if (d == NULL && errno != ENOTDIR) {
	warning("cannot opendir %s", pathbuf);
	return(-1);
    }
    while ((dp = readdir(d)) != NULL) {
	if (NAMLEN(dp) != 2 || !isalnum(dp->d_name[0]) ||
	    !isalnum(dp->d_name[1]))
	    continue;

	/* open log file, print id and command */
	pathbuf[plen + 0] = '/';
	pathbuf[plen + 1] = dp->d_name[0];
	pathbuf[plen + 2] = dp->d_name[1];
	pathbuf[plen + 3] = '\0';
	fp = fopen(pathbuf, "r");
	if (fp == NULL) {
	    warning("unable to open %s", pathbuf);
	    continue;
	}
	/*
	 * ID file has two lines, a log info line followed by a command line.
	 */
	/* XXX - BUFSIZ might not be enough, implement getline? */
	if (!fgets(buf, sizeof(buf), fp) || !fgets(cmdbuf, sizeof(cmdbuf), fp)) {
	    fclose(fp);
	    continue;
	}
	fclose(fp);

	/* crack the log line: timestamp:user:runas_user:runas_group:tty */
	buf[strcspn(buf, "\n")] = '\0';
	if ((li.tstamp = atoi(buf)) == 0)
	    continue;

	if ((cp = strchr(buf, ':')) == NULL)
	    continue;
	*cp++ = '\0';
	li.user = cp;

	if ((cp = strchr(cp, ':')) == NULL)
	    continue;
	*cp++ = '\0';
	li.runas_user = cp;

	if ((cp = strchr(cp, ':')) == NULL)
	    continue;
	*cp++ = '\0';
	li.runas_group = cp;

	if ((cp = strchr(cp, ':')) == NULL)
	    continue;
	*cp++ = '\0';
	li.tty = cp;

	cmdbuf[strcspn(cmdbuf, "\n")] = '\0';
	li.cmd = cmdbuf;

	/*
	 * Select based on user/tty/regex if applicable.
	 * XXX - select on time and/or runas bits too?
	 */
	if (user && strcmp(user, li.user) != 0)
	    continue;
	if (tty && strcmp(tty, li.tty) != 0)
	    continue;
	if (re) {
#ifdef HAVE_REGCOMP
	    int rc = regexec(re, li.cmd, 0, NULL, 0);
	    if (rc) {
		if (rc == REG_NOMATCH)
		    continue;
		regerror(rc, re, buf, sizeof(buf));
		errorx(1, "%s", buf);
	    }
#else
	    if (strstr(li.cmd, re) == NULL)
		continue;
#endif /* HAVE_REGCOMP */
	}

	/* Convert from /var/log/sudo-sessions/00/00/01 to 000001 */
	idstr[0] = pathbuf[plen - 5];
	idstr[1] = pathbuf[plen - 4];
	idstr[2] = pathbuf[plen - 2];
	idstr[3] = pathbuf[plen - 1];
	idstr[4] = pathbuf[plen + 1];
	idstr[5] = pathbuf[plen + 2];
	idstr[6] = '\0';
	/* XXX - better format (timestamp?) */
	printf("%s: %s %d (%s:%s) %s\n", idstr, li.user, li.tstamp,
	    li.runas_user, li.runas_group, li.cmd);
    }
    return(0);
}

int
list_sessions(argc, argv, pattern, user, tty)
    int argc;
    char **argv;
    const char *pattern;
    const char *user;
    const char *tty;
{
    DIR *d1, *d2;
    struct dirent *dp1, *dp2;
    REGEX_T rebuf, *re = NULL;
    size_t sdlen;
    char pathbuf[PATH_MAX];

    d1 = opendir(session_dir);
    if (d1 == NULL)
	error(1, "unable to open %s", session_dir);

#ifdef HAVE_REGCOMP
    /* optional regex */
    if (pattern) {
	re = &rebuf;
	if (regcomp(re, pattern, REG_EXTENDED|REG_NOSUB) != 0)
	    errorx(1, "invalid regex: %s", pattern);
    }
#else
    re = (char *) pattern;
#endif /* HAVE_REGCOMP */

    sdlen = strlcpy(pathbuf, session_dir, sizeof(pathbuf));

    /*
     * Three levels of directory, e.g. 00/00/00 .. ZZ/ZZ/ZZ
     * We do a depth-first traversal.
     */
    while ((dp1 = readdir(d1)) != NULL) {
	if (NAMLEN(dp1) != 2 || !isalnum(dp1->d_name[0]) ||
	    !isalnum(dp1->d_name[1]))
	    continue;

	pathbuf[sdlen + 0] = '/';
	pathbuf[sdlen + 1] = dp1->d_name[0];
	pathbuf[sdlen + 2] = dp1->d_name[1];
	pathbuf[sdlen + 3] = '\0';
	d2 = opendir(pathbuf);
	if (d2 == NULL)
	    continue;

	while ((dp2 = readdir(d2)) != NULL) {
	    if (NAMLEN(dp2) != 2 || !isalnum(dp2->d_name[0]) ||
		!isalnum(dp2->d_name[1]))
		continue;

	    pathbuf[sdlen + 3] = '/';
	    pathbuf[sdlen + 4] = dp2->d_name[0];
	    pathbuf[sdlen + 5] = dp2->d_name[1];
	    pathbuf[sdlen + 6] = '\0';
	    list_session_dir(pathbuf, re, user, tty);
	}
	closedir(d2);
    }
    closedir(d1);
    return(0);
}

void
usage()
{
    fprintf(stderr,
	"usage: %s [-d directory] [-m max_wait] [-s speed_factor] ID\n",
	getprogname());
    fprintf(stderr,
	"usage: %s [-d directory] [-p pattern] [-t tty] [-u username] -l\n",
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
