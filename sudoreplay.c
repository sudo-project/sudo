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

/*
 * Info present in the transcript log file
 */
struct log_info {
    char *cwd;
    char *user;
    char *runas_user;
    char *runas_group;
    char *tty;
    char *cmd;
    time_t tstamp;
};

/*
 * Handle expressions like:
 * ( user millert or user root ) and tty console and command /bin/sh
 */
struct search_node {
    struct search_node *next;
#define ST_EXPR		1
#define ST_TTY		2
#define ST_USER		3
#define ST_PATTERN	4
#define ST_RUNASUSER	5
#define ST_RUNASGROUP	6
#define ST_FROMDATE	7
#define ST_TODATE	8
#define ST_CWD		9
    char type;
    char negated;
    char or;
    char pad;
    union {
#ifdef HAVE_REGCOMP
	regex_t cmdre;
#endif
	time_t tstamp;
	char *cwd;
	char *tty;
	char *user;
	char *pattern;
	char *runas_group;
	char *runas_user;
	struct search_node *expr;
	void *ptr;
    } u;
} *search_expr;

#define STACK_NODE_SIZE	32
static struct search_node *node_stack[32];
static int stack_top;

extern void *emalloc __P((size_t));
extern void *erealloc __P((void *, size_t));
extern void efree __P((void *));
extern time_t get_date __P((char *));
extern char *get_timestr __P((time_t, int));
#ifndef HAVE_GETLINE
extern ssize_t getline __P((char **, size_t *, FILE *));
#endif

static int list_sessions __P((int, char **, const char *, const char *, const char *));
static int parse_expr __P((struct search_node **, char **));
static void delay __P((double));
static void usage __P((void));

#ifdef HAVE_REGCOMP
# define REGEX_T	regex_t
#else
# define REGEX_T	char
#endif

#define VALID_ID(s) (isalnum((s)[0]) && isalnum((s)[1]) && isalnum((s)[2]) && \
    isalnum((s)[3]) && isalnum((s)[4]) && isalnum((s)[5]) && (s)[6] == '\0')

int
main(argc, argv)
    int argc;
    char **argv;
{
    int ch, plen, listonly = 0;
    const char *id, *user = NULL, *pattern = NULL, *tty = NULL;
    char path[PATH_MAX], buf[LINE_MAX], *cp, *ep;
    FILE *tfile, *sfile, *lfile;
    double seconds;
    unsigned long nbytes;
    size_t len, nread;
    double speed = 1.0;
    double max_wait = 0;
    double to_wait;

    Argc = argc;
    Argv = argv;

    while ((ch = getopt(argc, argv, "d:lm:s:V")) != -1) {
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
	case 's':
	    errno = 0;
	    speed = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		error(1, "invalid speed factor: %s", optarg);
	    break;
	case 'V':
	    (void) printf("%s version %s\n", getprogname(), PACKAGE_VERSION);
	    exit(0);
	default:
	    usage();
	    /* NOTREACHED */
	}

    }
    argc -= optind;
    argv += optind;

    if (listonly)
	exit(list_sessions(argc, argv, pattern, user, tty));

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

    cp = NULL;
    getline(&cp, &len, lfile); /* log */
    getline(&cp, &len, lfile); /* cwd */
    getline(&cp, &len, lfile); /* command */
    printf("Replaying sudo session: %s", cp);
    free(cp);
    fclose(lfile);

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

static void
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

/*
 * Build expression list from search args
 */
static int
parse_expr(headp, argv)
    struct search_node **headp;
    char **argv;
{
    struct search_node *sn, *newsn;
    char or = 0, not = 0, type, **av;

    sn = *headp;
    for (av = argv; *av; av++) {
	switch (*av[0]) {
	case 'a': /* and (ignore) */
	    if (strncmp(*av, "and", strlen(*av)) != 0)
		goto bad;
	    continue;
	case 'o': /* or */
	    if (strncmp(*av, "or", strlen(*av)) != 0)
		goto bad;
	    or = 1;
	    continue;
	case '!': /* negate */
	    if (*av[1] != '\0')
		goto bad;
	    not = 1;
	    continue;
	case 'c': /* command */
	    if (*av[1] == '\0')
		errorx(1, "ambiguous expression \"%s\"", *av);
	    if (strncmp(*av, "cwd", strlen(*av)) == 0)
		type = ST_CWD;
	    else if (strncmp(*av, "command", strlen(*av)) == 0)
		type = ST_PATTERN;
	    else
		goto bad;
	    break;
	case 'f': /* from date */
	    if (strncmp(*av, "fromdate", strlen(*av)) != 0)
		goto bad;
	    type = ST_FROMDATE;
	    break;
	case 'g': /* runas group */
	    if (strncmp(*av, "group", strlen(*av)) != 0)
		goto bad;
	    type = ST_RUNASGROUP;
	    break;
	case 'r': /* runas user */
	    if (strncmp(*av, "runas", strlen(*av)) != 0)
		goto bad;
	    type = ST_RUNASUSER;
	    break;
	case 't': /* tty or to date */
	    if (*av[1] == '\0')
		errorx(1, "ambiguous expression \"%s\"", *av);
	    if (strncmp(*av, "todate", strlen(*av)) == 0)
		type = ST_TODATE;
	    else if (strncmp(*av, "tty", strlen(*av)) == 0)
		type = ST_TTY;
	    else
		goto bad;
	    break;
	case 'u': /* user */
	    if (strncmp(*av, "user", strlen(*av)) != 0)
		goto bad;
	    type = ST_USER;
	    break;
	case '(': /* start sub-expression */
	    if (*av[1] != '\0')
		goto bad;
	    if (stack_top + 1 == STACK_NODE_SIZE) {
		errorx(1, "too many parenthesized expressions, max %d",
		    STACK_NODE_SIZE);
	    }
	    node_stack[stack_top++] = sn;
	    type = ST_EXPR;
	    break;
	case ')': /* end sub-expression */
	    if (*av[1] != '\0')
		goto bad;
	    /* pop */
	    if (--stack_top < 0)
		errorx(1, "unmatched ')' in expression");
	    if (node_stack[stack_top])
		sn->next = node_stack[stack_top]->next;
	    return(av - argv + 1);
	bad:
	default:
	    errorx(1, "unknown search term \"%s\"", *av);
	    /* NOTREACHED */
	}

	/* Allocate new search node */
	newsn = emalloc(sizeof(*newsn));
	newsn->next = NULL;
	newsn->type = type;
	newsn->or = or;
	newsn->negated = not;
	if (type == ST_EXPR) {
	    av += parse_expr(&newsn->u.expr, av + 1);
	} else {
	    if (*(++av) == NULL)
		errorx(1, "%s requires an argument", av[-1]);
#ifdef HAVE_REGCOMP
	    if (type == ST_PATTERN) {
		if (regcomp(&newsn->u.cmdre, *av, REG_EXTENDED|REG_NOSUB) != 0)
		    errorx(1, "invalid regex: %s", *av);
	    } else
#endif
	    if (type == ST_TODATE || type == ST_FROMDATE) {
		newsn->u.tstamp = get_date(*av);
		if (newsn->u.tstamp == -1)
		    errorx(1, "could not parse date \"%s\"", *av);
	    } else {
		newsn->u.ptr = *av;
	    }
	}
	not = or = 0; /* reset state */
	if (sn)
	    sn->next = newsn;
	else
	    *headp = newsn;
	sn = newsn;
    }
    if (stack_top)
	errorx(1, "unmatched '(' in expression");
    if (or)
	errorx(1, "illegal trailing \"or\"");
    if (not)
	errorx(1, "illegal trailing \"!\"");

    return(av - argv);
}

static int
match_expr(head, log)
    struct search_node *head;
    struct log_info *log;
{
    struct search_node *sn;
    int matched = 1, rc;

    for (sn = head; sn; sn = sn->next) {
	/* If we have no match, skip ahead to the next OR entry. */
	if (!matched && !sn->or)
	    continue;

	switch (sn->type) {
	case ST_EXPR:
	    matched = match_expr(sn->u.expr, log);
	    break;
	case ST_CWD:
	    matched = strcmp(sn->u.cwd, log->cwd) == 0;
	    break;
	case ST_TTY:
	    matched = strcmp(sn->u.tty, log->tty) == 0;
	    break;
	case ST_RUNASGROUP:
	    matched = strcmp(sn->u.runas_group, log->runas_group) == 0;
	    break;
	case ST_RUNASUSER:
	    matched = strcmp(sn->u.runas_user, log->runas_user) == 0;
	    break;
	case ST_USER:
	    matched = strcmp(sn->u.user, log->user) == 0;
	    break;
	case ST_PATTERN:
#ifdef HAVE_REGCOMP
	    rc = regexec(&sn->u.cmdre, log->cmd, 0, NULL, 0);
	    if (rc && rc != REG_NOMATCH) {
		char buf[BUFSIZ];
		regerror(rc, &sn->u.cmdre, buf, sizeof(buf));
		errorx(1, "%s", buf);
	    }
	    matched = rc == REG_NOMATCH ? 0 : 1;
#else
	    matched = strstr(log.cmd, sn->u.pattern) != NULL;
#endif
	    break;
	case ST_FROMDATE:
	    matched = log->tstamp >= sn->u.tstamp;
	    break;
	case ST_TODATE:
	    matched = log->tstamp <= sn->u.tstamp;
	    break;
	}
	if (sn->negated)
	    matched = !matched;
    }
    return(matched);
}

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
    char *buf = NULL, *cmd = NULL, *cwd = NULL, idstr[7], *cp;
    struct log_info li;
    size_t bufsize = 0, cwdsize = 0, cmdsize = 0, plen;

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
	 * ID file has three lines:
	 *  1) a log info line
	 *  2) cwd
	 *  3) command with args
	 */
	if (getline(&buf, &bufsize, fp) == -1 ||
	    getline(&cwd, &cwdsize, fp) == -1 ||
	    getline(&cmd, &cmdsize, fp)) {
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

	cwd[strcspn(cwd, "\n")] = '\0';
	li.cwd = cwd;

	cmd[strcspn(cmd, "\n")] = '\0';
	li.cmd = cmd;

	/* Match on search expression if there is one. */
	if (search_expr && !match_expr(search_expr, &li))
	    continue;

	/* Convert from /var/log/sudo-sessions/00/00/01 to 000001 */
	idstr[0] = pathbuf[plen - 5];
	idstr[1] = pathbuf[plen - 4];
	idstr[2] = pathbuf[plen - 2];
	idstr[3] = pathbuf[plen - 1];
	idstr[4] = pathbuf[plen + 1];
	idstr[5] = pathbuf[plen + 2];
	idstr[6] = '\0';
	printf("%s : %s : TTY=%s ; CWD=%s ; USER=%s ; ",
	    get_timestr(li.tstamp, 0), li.user, li.tty, li.cwd, li.runas_user);
	if (*li.runas_group)
	    printf("GROUP=%s ; ", li.runas_group);
	printf("TSID=%s ; COMMAND=%s\n", idstr, li.cmd);
    }
    return(0);
}

static int
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

    /* Parse search expression if present */
    parse_expr(&search_expr, argv);

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

static void
usage()
{
    fprintf(stderr,
	"usage: %s [-d directory] [-m max_wait] [-s speed_factor] ID\n",
	getprogname());
    fprintf(stderr,
	"usage: %s [-d directory] -l [search expression]\n",
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
