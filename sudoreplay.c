/*
 * Copyright (c) 2009-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/uio.h>
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>
#endif
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
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifndef HAVE_STRUCT_TIMESPEC
# include "emul/timespec.h"
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
#ifdef HAVE_ZLIB_H
# include <zlib.h>
#endif
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif
#include <signal.h>

#include <pathnames.h>

#include "missing.h"
#include "alloc.h"
#include "error.h"

#ifndef LINE_MAX
# define LINE_MAX 2048
#endif

/* Must match the defines in iolog.c */
#define IOFD_STDIN      0
#define IOFD_STDOUT     1
#define IOFD_STDERR     2
#define IOFD_TTYIN      3
#define IOFD_TTYOUT     4
#define IOFD_TIMING     5
#define IOFD_MAX        6

/* Bitmap of iofds to be replayed */
unsigned int replay_filter = (1 << IOFD_STDOUT) | (1 << IOFD_STDERR) |
			     (1 << IOFD_TTYOUT);

/* For getopt(3) */
extern char *optarg;
extern int optind;

int Argc;
char **Argv;

union io_fd {
    FILE *f;
#ifdef HAVE_ZLIB_H
    gzFile g;
#endif
    void *v;
};

/*
 * Info present in the I/O log file
 */
struct log_info {
    char *cwd;
    char *user;
    char *runas_user;
    char *runas_group;
    char *tty;
    char *cmd;
    time_t tstamp;
    int rows;
    int cols;
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

static const char *session_dir = _PATH_SUDO_IO_LOGDIR;

static union io_fd io_fds[IOFD_MAX];
static const char *io_fnames[IOFD_MAX] = {
    "/stdin",
    "/stdout",
    "/stderr",
    "/ttyin",
    "/ttyout",
    "/timing"
};

extern time_t get_date __P((char *));
extern char *get_timestr __P((time_t, int));
extern int term_raw __P((int, int));
extern int term_restore __P((int, int));
extern void get_ttysize __P((int *rowp, int *colp));
RETSIGTYPE cleanup __P((int));

static int list_sessions __P((int, char **, const char *, const char *, const char *));
static int parse_expr __P((struct search_node **, char **));
static void check_input __P((int, double *));
static void delay __P((double));
static void help __P((void)) __attribute__((__noreturn__));
static void usage __P((int));
static int open_io_fd __P((char *pathbuf, int len, const char *suffix, union io_fd *fdp));
static int parse_timing __P((const char *buf, const char *decimal, int *idx, double *seconds, size_t *nbytes));
static struct log_info *parse_logfile __P((char *logfile));
static void free_log_info __P((struct log_info *li));
static size_t atomic_writev __P((int fd, struct iovec *iov, int iovcnt));

#ifdef HAVE_REGCOMP
# define REGEX_T	regex_t
#else
# define REGEX_T	char
#endif

#define VALID_ID(s) (isalnum((unsigned char)(s)[0]) && \
    isalnum((unsigned char)(s)[1]) && isalnum((unsigned char)(s)[2]) && \
    isalnum((unsigned char)(s)[3]) && isalnum((unsigned char)(s)[4]) && \
    isalnum((unsigned char)(s)[5]) && (s)[6] == '\0')

#define IS_IDLOG(s) ( \
    isalnum((unsigned char)(s)[0]) && isalnum((unsigned char)(s)[1]) && \
    (s)[2] == '/' && \
    isalnum((unsigned char)(s)[3]) && isalnum((unsigned char)(s)[4]) && \
    (s)[5] == '/' && \
    isalnum((unsigned char)(s)[6]) && isalnum((unsigned char)(s)[7]) && \
    (s)[8] == '/' && (s)[9] == 'l' && (s)[10] == 'o' && (s)[11] == 'g' && \
    (s)[12] == '\0')

int
main(argc, argv)
    int argc;
    char *argv[];
{
    int ch, idx, plen, interactive = 0, listonly = 0, need_nlcr = 0;
    int rows = 0, cols = 0;
    const char *id, *user = NULL, *pattern = NULL, *tty = NULL, *decimal = ".";
    char path[PATH_MAX], buf[LINE_MAX], *cp, *ep;
    double seconds, to_wait, speed = 1.0, max_wait = 0;
    sigaction_t sa;
    size_t len, nbytes, nread;
    struct log_info *li;
    struct iovec *iov = NULL;
    int iovcnt = 0, iovmax = 0;

    Argc = argc;
    Argv = argv;

#ifdef HAVE_SETLOCALE
    setlocale(LC_ALL, "");
    decimal = localeconv()->decimal_point;
#endif

    while ((ch = getopt(argc, argv, "d:f:hlm:s:V")) != -1) {
	switch(ch) {
	case 'd':
	    session_dir = optarg;
	    break;
	case 'f':
	    /* Set the replay filter. */
	    replay_filter = 0;
	    for (cp = strtok(optarg, ","); cp; cp = strtok(NULL, ",")) {
		if (strcmp(cp, "stdout") == 0)
		    SET(replay_filter, 1 << IOFD_STDOUT);
		else if (strcmp(cp, "stderr") == 0)
		    SET(replay_filter, 1 << IOFD_STDERR);
		else if (strcmp(cp, "ttyout") == 0)
		    SET(replay_filter, 1 << IOFD_TTYOUT);
		else
		    errorx(1, "invalid filter option: %s", optarg);
	    }
	    break;
	case 'h':
	    help();
	    /* NOTREACHED */
	case 'l':
	    listonly = 1;
	    break;
	case 'm':
	    errno = 0;
	    max_wait = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		errorx(1, "invalid max wait: %s", optarg);
	    break;
	case 's':
	    errno = 0;
	    speed = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		errorx(1, "invalid speed factor: %s", optarg);
	    break;
	case 'V':
	    (void) printf("%s version %s\n", getprogname(), PACKAGE_VERSION);
	    exit(0);
	default:
	    usage(1);
	    /* NOTREACHED */
	}

    }
    argc -= optind;
    argv += optind;

    if (listonly)
	exit(list_sessions(argc, argv, pattern, user, tty));

    if (argc != 1)
	usage(1);

    /* 6 digit ID in base 36, e.g. 01G712AB or free-form name */
    id = argv[0];
    if (VALID_ID(id)) {
	plen = snprintf(path, sizeof(path), "%s/%.2s/%.2s/%.2s/timing",
	    session_dir, id, &id[2], &id[4]);
	if (plen <= 0 || plen >= sizeof(path))
	    errorx(1, "%s/%.2s/%.2s/%.2s/timing: %s", session_dir,
		id, &id[2], &id[4], strerror(ENAMETOOLONG));
    } else {
	plen = snprintf(path, sizeof(path), "%s/%s/timing",
	    session_dir, id);
	if (plen <= 0 || plen >= sizeof(path))
	    errorx(1, "%s/%s/timing: %s", session_dir,
		id, strerror(ENAMETOOLONG));
    }
    plen -= 7;

    /* Open files for replay, applying replay filter for the -f flag. */
    for (idx = 0; idx < IOFD_MAX; idx++) {
	if (ISSET(replay_filter, 1 << idx) || idx == IOFD_TIMING) {
	    if (open_io_fd(path, plen, io_fnames[idx], &io_fds[idx]) == -1)
		error(1, "unable to open %s", path);
	}
    }

    /* Parse log file. */
    path[plen] = '\0';
    strlcat(path, "/log", sizeof(path));
    if ((li = parse_logfile(path)) == NULL)
	exit(1);
    printf("Replaying sudo session: %s\n", li->cmd);

    /* Make sure the terminal is large enough. */
    get_ttysize(&rows, &cols);
    if (li->rows != 0 && li->cols != 0) {
	if (li->rows > rows) {
	    printf("Warning: your terminal is too small to properly replay the log.\n");
	    printf("Log geometry is %d x %d, your terminal's geometry is %d x %d.", li->rows, li->cols, rows, cols);
	}
    }

    /* Done with parsed log file. */
    free_log_info(li);
    li = NULL;

    fflush(stdout);
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sa.sa_handler = cleanup;
    (void) sigaction(SIGINT, &sa, NULL);
    (void) sigaction(SIGKILL, &sa, NULL);
    (void) sigaction(SIGTERM, &sa, NULL);
    (void) sigaction(SIGHUP, &sa, NULL);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGTSTP, &sa, NULL);
    (void) sigaction(SIGQUIT, &sa, NULL);

    /* XXX - read user input from /dev/tty and set STDOUT to raw if not a pipe */
    /* Set stdin to raw mode if it is a tty */
    interactive = isatty(STDIN_FILENO);
    if (interactive) {
	ch = fcntl(STDIN_FILENO, F_GETFL, 0);
	if (ch != -1)
	    (void) fcntl(STDIN_FILENO, F_SETFL, ch | O_NONBLOCK);
	if (!term_raw(STDIN_FILENO, 1))
	    error(1, "cannot set tty to raw mode");
	iovcnt = 0;
	iovmax = 32;
	iov = ecalloc(iovmax, sizeof(*iov));
    }

    /*
     * Timing file consists of line of the format: "%f %d\n"
     */
#ifdef HAVE_ZLIB_H
    while (gzgets(io_fds[IOFD_TIMING].g, buf, sizeof(buf)) != NULL) {
#else
    while (fgets(buf, sizeof(buf), io_fds[IOFD_TIMING].f) != NULL) {
#endif
	char last_char = '\0';

	if (!parse_timing(buf, decimal, &idx, &seconds, &nbytes))
	    errorx(1, "invalid timing file line: %s", buf);

	if (interactive)
	    check_input(STDIN_FILENO, &speed);

	/* Adjust delay using speed factor and clamp to max_wait */
	to_wait = seconds / speed;
	if (max_wait && to_wait > max_wait)
	    to_wait = max_wait;
	delay(to_wait);

	/* Even if we are not relaying, we still have to delay. */
	if (io_fds[idx].v == NULL)
	    continue;

	/* Check whether we need to convert newline to CR LF pairs. */
	if (interactive) 
	    need_nlcr = (idx == IOFD_STDOUT || idx == IOFD_STDERR);

	/* All output is sent to stdout. */
	while (nbytes != 0) {
	    if (nbytes > sizeof(buf))
		len = sizeof(buf);
	    else
		len = nbytes;
#ifdef HAVE_ZLIB_H
	    nread = gzread(io_fds[idx].g, buf, len);
#else
	    nread = fread(buf, 1, len, io_fds[idx].f);
#endif
	    nbytes -= nread;

	    /* Convert newline to carriage return + linefeed if needed. */
	    if (need_nlcr) {
		size_t remainder = nread;
		size_t linelen;
		iovcnt = 0;
		cp = buf;
		ep = cp - 1;
		/* Handle a "\r\n" pair that spans a buffer. */
		if (last_char == '\r' && buf[0] == '\n') {
		    ep++;
		    remainder--;
		}
		while ((ep = memchr(ep + 1, '\n', remainder)) != NULL) {
		    /* Is there already a carriage return? */
		    if (cp != ep && ep[-1] == '\r') {
			remainder = (size_t)(&buf[nread - 1] - ep);
		    	continue;
		    }

		    /* Store the line in iov followed by \r\n pair. */
		    if (iovcnt + 3 > iovmax) {
			iovmax <<= 1;
			iov = erealloc3(iov, iovmax, sizeof(*iov));
		    }
		    linelen = (size_t)(ep - cp) + 1;
		    iov[iovcnt].iov_base = cp;
		    iov[iovcnt].iov_len = linelen - 1; /* not including \n */
		    iovcnt++;
		    iov[iovcnt].iov_base = "\r\n";
		    iov[iovcnt].iov_len = 2;
		    iovcnt++;
		    cp = ep + 1;
		    remainder -= linelen;
		}
		if (cp - buf != nread) {
		    /*
		     * Partial line without a linefeed or multiple lines
		     * with \r\n pairs.
		     */
		    iov[iovcnt].iov_base = cp;
		    iov[iovcnt].iov_len = nread - (cp - buf);
		    iovcnt++;
		}
		last_char = buf[nread - 1]; /* stash last char of old buffer */
	    } else {
		/* No conversion needed. */
		iov[0].iov_base = buf;
		iov[0].iov_len = nread;
		iovcnt = 1;
	    }
	    if (atomic_writev(STDOUT_FILENO, iov, iovcnt) == -1)
		error(1, "writing to standard output");
	}
    }
    term_restore(STDIN_FILENO, 1);
    exit(0);
}

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
    if (rval == -1) {
	error(1, "nanosleep: tv_sec %ld, tv_nsec %ld",
	    (long)ts.tv_sec, (long)ts.tv_nsec);
    }
}

static int
open_io_fd(path, len, suffix, fdp)
    char *path;
    int len;
    const char *suffix;
    union io_fd *fdp;
{
    path[len] = '\0';
    strlcat(path, suffix, PATH_MAX);

#ifdef HAVE_ZLIB_H
    fdp->g = gzopen(path, "r");
    return fdp->g ? 0 : -1;
#else
    fdp->f = fopen(path, "r");
    return fdp->f ? 0 : -1;
#endif
}

/*
 * Call writev(), restarting as needed and handling EAGAIN since
 * fd may be in non-blocking mode.
 */
static size_t
atomic_writev(fd, iov, iovcnt)
    int fd;
    struct iovec *iov;
    int iovcnt;
{
    ssize_t n, nwritten = 0;
    size_t count, remainder, nbytes = 0;
    int i;

    for (i = 0; i < iovcnt; i++)
	nbytes += iov[i].iov_len;

    for (;;) {
	n = writev(STDOUT_FILENO, iov, iovcnt);
	if (n > 0) {
	    nwritten += n;
	    remainder = nbytes - nwritten;
	    if (remainder == 0)
		break;
	    /* short writev, adjust iov and do the rest. */
	    count = 0;
	    i = iovcnt;
	    while (i--) {
		count += iov[i].iov_len;
		if (count == remainder) {
		    iov += i;
		    iovcnt -= i;
		    break;
		}
		if (count > remainder) {
		    size_t off = (count - remainder);
		    /* XXX - side effect prevents iov from being const */
		    iov[i].iov_base = (char *)iov[i].iov_base + off;
		    iov[i].iov_len -= off;
		    iov += i;
		    iovcnt -= i;
		    break;
		}
	    }
	    continue;
	}
	if (n == 0 || errno == EAGAIN) {
	    int nready;
	    fd_set fdsw;
	    FD_ZERO(&fdsw);
	    FD_SET(STDOUT_FILENO, &fdsw);
	    do {
		nready = select(STDOUT_FILENO + 1, NULL, &fdsw, NULL, NULL);
	    } while (nready == -1 && errno == EINTR);
	    if (nready == 1)
		continue;
	}
	if (errno == EINTR)
	    continue;
	nwritten = -1;
	break;
    }
    return nwritten;
}

/*
 * Build expression list from search args
 */
static int
parse_expr(headp, argv)
    struct search_node **headp;
    char *argv[];
{
    struct search_node *sn, *newsn;
    char or = 0, not = 0, type, **av;

    sn = *headp;
    for (av = argv; *av; av++) {
	switch (av[0][0]) {
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
	    if (av[0][1] != '\0')
		goto bad;
	    not = 1;
	    continue;
	case 'c': /* command */
	    if (av[0][1] == '\0')
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
	    if (av[0][1] == '\0')
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
	    if (av[0][1] != '\0')
		goto bad;
	    if (stack_top + 1 == STACK_NODE_SIZE) {
		errorx(1, "too many parenthesized expressions, max %d",
		    STACK_NODE_SIZE);
	    }
	    node_stack[stack_top++] = sn;
	    type = ST_EXPR;
	    break;
	case ')': /* end sub-expression */
	    if (av[0][1] != '\0')
		goto bad;
	    /* pop */
	    if (--stack_top < 0)
		errorx(1, "unmatched ')' in expression");
	    if (node_stack[stack_top])
		sn->next = node_stack[stack_top]->next;
	    return av - argv + 1;
	bad:
	default:
	    errorx(1, "unknown search term \"%s\"", *av);
	    /* NOTREACHED */
	}

	/* Allocate new search node */
	newsn = ecalloc(1, sizeof(*newsn));
	newsn->type = type;
	newsn->or = or;
	newsn->negated = not;
	/* newsn->next = NULL; */
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

    return av - argv;
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
    return matched;
}

static struct log_info *
parse_logfile(logfile)
    char *logfile;
{
    FILE *fp;
    char *buf = NULL, *cp, *ep;
    size_t bufsize = 0, cwdsize = 0, cmdsize = 0;
    struct log_info *li = NULL;

    fp = fopen(logfile, "r");
    if (fp == NULL) {
	warning("unable to open %s", logfile);
	goto bad;
    }

    /*
     * ID file has three lines:
     *  1) a log info line
     *  2) cwd
     *  3) command with args
     */
    li = ecalloc(1, sizeof(*li));
    if (getline(&buf, &bufsize, fp) == -1 ||
	getline(&li->cwd, &cwdsize, fp) == -1 ||
	getline(&li->cmd, &cmdsize, fp) == -1) {
	goto bad;
    }

    /* Strip the newline from the cwd and command. */
    li->cwd[strcspn(li->cwd, "\n")] = '\0';
    li->cmd[strcspn(li->cmd, "\n")] = '\0';

    /*
     * Crack the log line (rows and cols not present in old versions).
     * timestamp:user:runas_user:runas_group:tty:rows:cols
     */
    buf[strcspn(buf, "\n")] = '\0';

    /* timestamp */
    if ((ep = strchr(buf, ':')) == NULL)
	goto bad;
    if ((li->tstamp = atoi(buf)) == 0)
	goto bad;

    /* user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL)
	goto bad;
    li->user = estrndup(cp, (size_t)(ep - cp));

    /* runas user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL)
	goto bad;
    li->runas_user = estrndup(cp, (size_t)(ep - cp));

    /* runas group */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL)
	goto bad;
    if (cp != ep)
	li->runas_group = estrndup(cp, (size_t)(ep - cp));

    /* tty, followed by optional rows + columns */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	li->tty = estrdup(cp);
    } else {
	li->tty = estrndup(cp, (size_t)(ep - cp));
	cp = ep + 1;
	li->rows = atoi(cp);
	if ((ep = strchr(cp, ':')) != NULL) {
	    cp = ep + 1;
	    li->cols = atoi(cp);
	}
    }
    fclose(fp);
    efree(buf);
    return li;

bad:
    if (fp != NULL)
	fclose(fp);
    efree(buf);
    free_log_info(li);
    return NULL;
}

static void
free_log_info(li)
    struct log_info *li;
{
    if (li != NULL) {
	efree(li->cwd);
	efree(li->user);
	efree(li->runas_user);
	efree(li->runas_group);
	efree(li->tty);
	efree(li->cmd);
	efree(li);
    }
}

static int
list_session(logfile, re, user, tty)
    char *logfile;
    REGEX_T *re;
    const char *user;
    const char *tty;
{
    char idbuf[7], *idstr, *cp;
    struct log_info *li;
    int rval = -1;

    if ((li = parse_logfile(logfile)) == NULL)
	goto done;

    /* Match on search expression if there is one. */
    if (search_expr && !match_expr(search_expr, li))
	goto done;

    /* Convert from /var/log/sudo-sessions/00/00/01/log to 000001 */
    cp = logfile + strlen(session_dir) + 1;
    if (IS_IDLOG(cp)) {
	idbuf[0] = cp[0];
	idbuf[1] = cp[1];
	idbuf[2] = cp[3];
	idbuf[3] = cp[4];
	idbuf[4] = cp[6];
	idbuf[5] = cp[7];
	idbuf[6] = '\0';
	idstr = idbuf;
    } else {
	/* Not an id, just use the iolog_file portion. */
	cp[strlen(cp) - 4] = '\0';
	idstr = cp;
    }
    /* XXX - print rows + cols? */
    printf("%s : %s : TTY=%s ; CWD=%s ; USER=%s ; ",
	get_timestr(li->tstamp, 1), li->user, li->tty, li->cwd, li->runas_user);
    if (li->runas_group)
	printf("GROUP=%s ; ", li->runas_group);
    printf("TSID=%s ; COMMAND=%s\n", idstr, li->cmd);

    rval = 0;

done:
    free_log_info(li);
    return rval;
}

static int
session_compare(v1, v2)
    const void *v1;
    const void *v2;
{
    const char *s1 = *(const char **)v1;
    const char *s2 = *(const char **)v2;
    return strcmp(s1, s2);
}

static int
find_sessions(dir, re, user, tty)
    const char *dir;
    REGEX_T *re;
    const char *user;
    const char *tty;
{
    DIR *d;
    struct dirent *dp;
    struct stat sb;
    size_t sdlen, sessions_len = 0, sessions_size = 36*36;
    int i, len;
#ifdef HAVE_STRUCT_DIRENT_D_TYPE
    int checked_type = 1;
#else
    const int checked_type = 0;
#endif
    char pathbuf[PATH_MAX], **sessions = NULL;

    d = opendir(dir);
    if (d == NULL)
	error(1, "unable to open %s", dir);

    /* XXX - would be faster to chdir and use relative names */
    sdlen = strlcpy(pathbuf, dir, sizeof(pathbuf));
    if (sdlen + 1 >= sizeof(pathbuf)) {
	errno = ENAMETOOLONG;
	error(1, "%s/", dir);
    }
    pathbuf[sdlen++] = '/';
    pathbuf[sdlen] = '\0';

    /* Store potential session dirs for sorting. */
    sessions = emalloc2(sessions_size, sizeof(char *));
    while ((dp = readdir(d)) != NULL) {
	/* Skip "." and ".." */
	if (dp->d_name[0] == '.' && (dp->d_name[1] == '\0' ||
	    (dp->d_name[1] == '.' && dp->d_name[2] == '\0')))
	    continue;
#ifdef HAVE_STRUCT_DIRENT_D_TYPE
	if (checked_type) {
	    if (dp->d_type != DT_DIR) {
		/* Not all file systems support d_type. */
		if (dp->d_type != DT_UNKNOWN)
		    continue;
		checked_type = 0;
	    }
	}
#endif

	/* Add name to session list. */
	if (sessions_len + 1 > sessions_size) {
	    sessions_size <<= 1;
	    sessions = erealloc3(sessions, sessions_size, sizeof(char *));
	}
	sessions[sessions_len++] = estrdup(dp->d_name);
    }
    closedir(d);

    /* Sort and list the sessions. */
    qsort(sessions, sessions_len, sizeof(char *), session_compare);
    for (i = 0; i < sessions_len; i++) {
	len = snprintf(&pathbuf[sdlen], sizeof(pathbuf) - sdlen,
	    "%s/log", sessions[i]);
	if (len <= 0 || len >= sizeof(pathbuf) - sdlen) {
	    errno = ENAMETOOLONG;
	    error(1, "%s/%s/log", dir, sessions[i]);
	}
	efree(sessions[i]);

	/* Check for dir with a log file. */
	if (lstat(pathbuf, &sb) == 0 && S_ISREG(sb.st_mode)) {
	    list_session(pathbuf, re, user, tty);
	} else {
	    /* Strip off "/log" and recurse if a dir. */
	    pathbuf[sdlen + len - 4] = '\0';
	    if (checked_type || (lstat(pathbuf, &sb) == 0 && S_ISDIR(sb.st_mode)))
		find_sessions(pathbuf, re, user, tty);
	}
    }
    efree(sessions);

    return 0;
}

static int
list_sessions(argc, argv, pattern, user, tty)
    int argc;
    char **argv;
    const char *pattern;
    const char *user;
    const char *tty;
{
    REGEX_T rebuf, *re = NULL;

    /* Parse search expression if present */
    parse_expr(&search_expr, argv);

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

    return find_sessions(session_dir, re, user, tty);
}

/*
 * Check input for ' ', '<', '>'
 * pause, slow, fast
 */
static void
check_input(ttyfd, speed)
    int ttyfd;
    double *speed;
{
    fd_set *fdsr;
    int nready, paused = 0;
    struct timeval tv;
    char ch;
    ssize_t n;

    fdsr = ecalloc(howmany(ttyfd + 1, NFDBITS), sizeof(fd_mask));

    for (;;) {
	FD_SET(ttyfd, fdsr);
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	nready = select(ttyfd + 1, fdsr, NULL, NULL, paused ? NULL : &tv);
	if (nready != 1)
	    break;
	n = read(ttyfd, &ch, 1);
	if (n == 1) {
	    if (paused) {
		paused = 0;
		continue;
	    }
	    switch (ch) {
	    case ' ':
		paused = 1;
		break;
	    case '<':
		*speed /= 2;
		break;
	    case '>':
		*speed *= 2;
		break;
	    }
	}
    }
    free(fdsr);
}

/*
 * Parse a timing line, which is formatted as:
 *	index sleep_time num_bytes
 * Where index is IOFD_*, sleep_time is the number of seconds to sleep
 * before writing the data and num_bytes is the number of bytes to output.
 * Returns 1 on success and 0 on failure.
 */
static int
parse_timing(buf, decimal, idx, seconds, nbytes)
    const char *buf;
    const char *decimal;
    int *idx;
    double *seconds;
    size_t *nbytes;
{
    unsigned long ul;
    long l;
    double d, fract = 0;
    char *cp, *ep;

    /* Parse index */
    ul = strtoul(buf, &ep, 10);
    if (ul > IOFD_MAX)
	goto bad;
    *idx = (int)ul;
    for (cp = ep + 1; isspace((unsigned char) *cp); cp++)
	continue;

    /*
     * Parse number of seconds.  Sudo logs timing data in the C locale
     * but this may not match the current locale so we cannot use strtod().
     * Furthermore, sudo < 1.7.4 logged with the user's locale so we need
     * to be able to parse those logs too.
     */
    errno = 0;
    l = strtol(cp, &ep, 10);
    if ((errno == ERANGE && (l == LONG_MAX || l == LONG_MIN)) ||
	l < 0 || l > INT_MAX ||
	(*ep != '.' && strncmp(ep, decimal, strlen(decimal)) != 0)) {
	goto bad;
    }
    *seconds = (double)l;
    cp = ep + (*ep == '.' ? 1 : strlen(decimal));
    d = 10.0;
    while (isdigit((unsigned char) *cp)) {
	fract += (*cp - '0') / d;
	d *= 10;
	cp++;
    }
    *seconds += fract;
    while (isspace((unsigned char) *cp))
	cp++;

    errno = 0;
    ul = strtoul(cp, &ep, 10);
    if (errno == ERANGE && ul == ULONG_MAX)
	goto bad;
    *nbytes = (size_t)ul;

    return 1;
bad:
    return 0;
}

static void
usage(fatal)
    int fatal;
{
    fprintf(fatal ? stderr : stdout,
	"usage: %s [-h] [-d directory] [-f filter] [-m max_wait] [-s speed_factor] ID\n",
	getprogname());
    fprintf(fatal ? stderr : stdout,
	"usage: %s [-h] [-d directory] -l [search expression]\n",
	getprogname());
    if (fatal)
	exit(1);
}

static void
help()
{
    (void) printf("%s - replay sudo session logs\n\n", getprogname());
    usage(0);
    (void) puts("\nOptions:");
    (void) puts("  -d directory     specify directory for session logs");
    (void) puts("  -f filter        specify which I/O type to display");
    (void) puts("  -h               display help message and exit");
    (void) puts("  -l [expression]  list available session IDs that match expression");
    (void) puts("  -m max_wait      max number of seconds to wait between events");
    (void) puts("  -s speed_factor  speed up or slow down output");
    (void) puts("  -V               display version information and exit");
    exit(0);
}

/*
 * Cleanup hook for error()/errorx()
  */
RETSIGTYPE
cleanup(signo)
    int signo;
{
    term_restore(STDIN_FILENO, 0);
    if (signo)
	kill(getpid(), signo);
}
