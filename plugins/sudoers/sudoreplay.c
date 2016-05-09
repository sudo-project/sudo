/*
 * Copyright (c) 2009-2016 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#include <regex.h>
#include <signal.h>
#ifdef HAVE_ZLIB_H
# include <zlib.h>
#endif

#include <pathnames.h>

#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "logging.h"
#include "iolog.h"
#include "sudo_queue.h"
#include "sudo_plugin.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_event.h"
#include "sudo_util.h"

#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

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

/* Closure for write_output */
struct write_closure {
    struct sudo_event *wevent;
    struct iovec *iov;
    unsigned int iovcnt;
    size_t nbytes;
};

/*
 * Handle expressions like:
 * ( user millert or user root ) and tty console and command /bin/sh
 */
STAILQ_HEAD(search_node_list, search_node);
struct search_node {
    STAILQ_ENTRY(search_node) entries;
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
    bool negated;
    bool or;
    union {
	regex_t cmdre;
	time_t tstamp;
	char *cwd;
	char *tty;
	char *user;
	char *runas_group;
	char *runas_user;
	struct search_node_list expr;
	void *ptr;
    } u;
};

static struct search_node_list search_expr = STAILQ_HEAD_INITIALIZER(search_expr);

static int timing_idx_adj;

static double speed_factor = 1.0;

static const char *session_dir = _PATH_SUDO_IO_LOGDIR;

static const char short_opts[] =  "d:f:hlm:s:V";
static struct option long_opts[] = {
    { "directory",	required_argument,	NULL,	'd' },
    { "filter",		required_argument,	NULL,	'f' },
    { "help",		no_argument,		NULL,	'h' },
    { "list",		no_argument,		NULL,	'l' },
    { "max-wait",	required_argument,	NULL,	'm' },
    { "speed",		required_argument,	NULL,	's' },
    { "version",	no_argument,		NULL,	'V' },
    { NULL,		no_argument,		NULL,	'\0' },
};

/* XXX move to separate header? */
extern char *get_timestr(time_t, int);
extern time_t get_date(char *);

static int list_sessions(int, char **, const char *, const char *, const char *);
static int open_io_fd(char *path, int len, struct io_log_file *iol);
static int parse_expr(struct search_node_list *, char **, bool);
static int parse_timing(const char *buf, const char *decimal, int *idx, double *seconds, size_t *nbytes);
static struct log_info *parse_logfile(char *logfile);
static void check_input(int fd, int what, void *v);
static void free_log_info(struct log_info *li);
static void help(void) __attribute__((__noreturn__));
static void replay_session(const double max_wait, const char *decimal);
static void sudoreplay_cleanup(void);
static void sudoreplay_handler(int);
static void usage(int);
static void write_output(int fd, int what, void *v);

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

__dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    int ch, idx, plen, exitcode = 0, rows = 0, cols = 0;
    bool def_filter = true, listonly = false;
    const char *decimal, *id, *user = NULL, *pattern = NULL, *tty = NULL;
    char *cp, *ep, path[PATH_MAX];
    struct log_info *li;
    double max_wait = 0;
    debug_decl(main, SUDO_DEBUG_MAIN)

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    {
	extern char *malloc_options;
	malloc_options = "AFGJPR";
    }  
#endif

    initprogname(argc > 0 ? argv[0] : "sudoreplay");
    setlocale(LC_ALL, "");
    decimal = localeconv()->decimal_point;
    bindtextdomain("sudoers", LOCALEDIR); /* XXX - should have sudoreplay domain */
    textdomain("sudoers");

    /* Register fatal/fatalx callback. */
    sudo_fatal_callback_register(sudoreplay_cleanup);

    /* Read sudo.conf and initialize the debug subsystem. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
	exit(EXIT_FAILURE);
    sudo_debug_register(getprogname(), NULL, NULL,
	sudo_conf_debug_files(getprogname()));

    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	case 'd':
	    session_dir = optarg;
	    break;
	case 'f':
	    /* Set the replay filter. */
	    def_filter = false;
	    for (cp = strtok_r(optarg, ",", &ep); cp; cp = strtok_r(NULL, ",", &ep)) {
		if (strcmp(cp, "stdout") == 0)
		    io_log_files[IOFD_STDOUT].enabled = true;
		else if (strcmp(cp, "stderr") == 0)
		    io_log_files[IOFD_STDERR].enabled = true;
		else if (strcmp(cp, "ttyout") == 0)
		    io_log_files[IOFD_TTYOUT].enabled = true;
		else
		    sudo_fatalx(U_("invalid filter option: %s"), optarg);
	    }
	    break;
	case 'h':
	    help();
	    /* NOTREACHED */
	case 'l':
	    listonly = true;
	    break;
	case 'm':
	    errno = 0;
	    max_wait = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		sudo_fatalx(U_("invalid max wait: %s"), optarg);
	    break;
	case 's':
	    errno = 0;
	    speed_factor = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		sudo_fatalx(U_("invalid speed factor: %s"), optarg);
	    break;
	case 'V':
	    (void) printf(_("%s version %s\n"), getprogname(), PACKAGE_VERSION);
	    goto done;
	default:
	    usage(1);
	    /* NOTREACHED */
	}

    }
    argc -= optind;
    argv += optind;

    if (listonly) {
	exitcode = list_sessions(argc, argv, pattern, user, tty);
	goto done;
    }

    if (argc != 1)
	usage(1);

    /* By default we replay stdout, stderr and ttyout. */
    if (def_filter) {
	io_log_files[IOFD_STDOUT].enabled = true;
	io_log_files[IOFD_STDERR].enabled = true;
	io_log_files[IOFD_TTYOUT].enabled = true;
    }

    /* 6 digit ID in base 36, e.g. 01G712AB or free-form name */
    id = argv[0];
    if (VALID_ID(id)) {
	plen = snprintf(path, sizeof(path), "%s/%.2s/%.2s/%.2s/timing",
	    session_dir, id, &id[2], &id[4]);
	if (plen <= 0 || (size_t)plen >= sizeof(path))
	    sudo_fatalx(U_("%s/%.2s/%.2s/%.2s/timing: %s"), session_dir,
		id, &id[2], &id[4], strerror(ENAMETOOLONG));
    } else {
	plen = snprintf(path, sizeof(path), "%s/%s/timing",
	    session_dir, id);
	if (plen <= 0 || (size_t)plen >= sizeof(path))
	    sudo_fatalx(U_("%s/%s/timing: %s"), session_dir,
		id, strerror(ENAMETOOLONG));
    }
    plen -= 7;

    /* Open files for replay, applying replay filter for the -f flag. */
    for (idx = 0; idx < IOFD_MAX; idx++) {
	if (open_io_fd(path, plen, &io_log_files[idx]) == -1) 
	    sudo_fatal(U_("unable to open %s"), path);
    }

    /* Parse log file. */
    path[plen] = '\0';
    strlcat(path, "/log", sizeof(path));
    if ((li = parse_logfile(path)) == NULL)
	exit(1);
    printf(_("Replaying sudo session: %s\n"), li->cmd);

    /* Make sure the terminal is large enough. */
    sudo_get_ttysize(&rows, &cols);
    if (li->rows != 0 && li->cols != 0) {
	if (li->rows > rows) {
	    printf(_("Warning: your terminal is too small to properly replay the log.\n"));
	    printf(_("Log geometry is %d x %d, your terminal's geometry is %d x %d."), li->rows, li->cols, rows, cols);
	}
    }

    /* Done with parsed log file. */
    free_log_info(li);
    li = NULL;

    /* Replay session corresponding to io_log_files[]. */
    replay_session(max_wait, decimal);

    sudo_term_restore(STDIN_FILENO, 1);
done:
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);
    exit(exitcode);
}

/*
 * Call gzread() or fread() for the I/O log file in question.
 * Return 0 for EOF or -1 on error.
 */
static ssize_t
io_log_read(int idx, char *buf, size_t nbytes)
{
    ssize_t nread;
    debug_decl(io_log_read, SUDO_DEBUG_UTIL)

    if (nbytes > INT_MAX) {
	errno = EINVAL;
	debug_return_ssize_t(-1);
    }
#ifdef HAVE_ZLIB_H
    nread = gzread(io_log_files[idx].fd.g, buf, nbytes);
#else
    nread = (ssize_t)fread(buf, 1, nbytes, io_log_files[idx].fd.f);
    if (nread == 0 && ferror(io_log_files[idx].fd.f))
	nread = -1;
#endif
    debug_return_ssize_t(nread);
}

static char *
io_log_gets(int idx, char *buf, size_t nbytes)
{
    char *str;
    debug_decl(io_log_gets, SUDO_DEBUG_UTIL)

#ifdef HAVE_ZLIB_H
    str = gzgets(io_log_files[idx].fd.g, buf, nbytes);
#else
    str = fgets(buf, nbytes, io_log_files[idx].fd.f);
#endif
    debug_return_str(str);
}

static void
replay_session(const double max_wait, const char *decimal)
{
    struct sudo_event *input_ev, *output_ev;
    unsigned int i, iovcnt = 0, iovmax = 0;
    struct sudo_event_base *evbase;
    struct iovec iovb, *iov = &iovb;
    bool interactive;
    struct write_closure wc;
    char buf[LINE_MAX];
    sigaction_t sa;
    int idx;
    debug_decl(replay_session, SUDO_DEBUG_UTIL)

    /* Restore tty settings if interupted. */
    fflush(stdout);
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND;
    sa.sa_handler = sudoreplay_handler;
    (void) sigaction(SIGINT, &sa, NULL);
    (void) sigaction(SIGTERM, &sa, NULL);
    (void) sigaction(SIGHUP, &sa, NULL);
    (void) sigaction(SIGQUIT, &sa, NULL);

    /* Don't suspend as we cannot restore the screen on resume. */
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGTSTP, &sa, NULL);

    /* XXX - read user input from /dev/tty and set STDOUT to raw if not a pipe */
    /* Set stdin to raw mode if it is a tty */
    interactive = isatty(STDIN_FILENO);
    if (interactive) {
	while (!sudo_term_raw(STDIN_FILENO, 1)) {
	    if (errno != EINTR)
		sudo_fatal(U_("unable to set tty to raw mode"));
	    kill(getpid(), SIGTTOU);
	}
    }

    /* Setup event base and input/output events. */
    evbase = sudo_ev_base_alloc();
    if (evbase == NULL)
	sudo_fatal(NULL);
    input_ev = sudo_ev_alloc(STDIN_FILENO, interactive ? SUDO_EV_READ :
	SUDO_EV_TIMEOUT, check_input, sudo_ev_self_cbarg());
    if (input_ev == NULL)
        sudo_fatal(NULL);
    output_ev = sudo_ev_alloc(STDIN_FILENO, SUDO_EV_WRITE, write_output, &wc);
    if (output_ev == NULL)
        sudo_fatal(NULL);

    /*
     * Read each line of the timing file, displaying the output streams.
     */
    while (io_log_gets(IOFD_TIMING, buf, sizeof(buf)) != NULL) {
	size_t len, nbytes, nread;
	double seconds, to_wait;
	struct timeval timeout;
	bool need_nlcr = false;
	char last_char = '\0';

	buf[strcspn(buf, "\n")] = '\0';
	if (!parse_timing(buf, decimal, &idx, &seconds, &nbytes))
	    sudo_fatalx(U_("invalid timing file line: %s"), buf);

	/* Adjust delay using speed factor and clamp to max_wait */
	to_wait = seconds / speed_factor;
	if (max_wait && to_wait > max_wait)
	    to_wait = max_wait;

	/* Convert delay to a timeval. */
	timeout.tv_sec = to_wait;
	timeout.tv_usec = (to_wait - timeout.tv_sec) * 1000000.0;

	/* Run event event loop to delay and get keyboard input. */
	sudo_ev_add(evbase, input_ev, &timeout, false);
	sudo_ev_loop(evbase, 0);

	/* Even if we are not replaying, we still have to delay. */
	if (idx >= IOFD_MAX || io_log_files[idx].fd.v == NULL)
	    continue;

	/* Check whether we need to convert newline to CR LF pairs. */
	if (interactive) 
	    need_nlcr = (idx == IOFD_STDOUT || idx == IOFD_STDERR);

	/* All output is sent to stdout. */
	/* XXX - assumes no wall clock time spent writing output. */
	while (nbytes != 0) {
	    if (nbytes > sizeof(buf))
		len = sizeof(buf);
	    else
		len = nbytes;
	    nread = io_log_read(idx, buf, len);
	    if (nread <= 0) {
		if (nread == 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"%s: premature EOF, expected %zu bytes",
			io_log_files[idx].suffix, nbytes);
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
			"%s: read error", io_log_files[idx].suffix);
		}
		break;
	    }
	    nbytes -= nread;

	    /* Convert newline to carriage return + linefeed if needed. */
	    if (need_nlcr) {
		size_t remainder = nread;
		size_t linelen;
		char *line = buf;
		char *nl, *cp = buf;

		/*
		 * Handle a "\r\n" pair that spans a buffer.
		 * The newline will be written as part of the next line.
		 */
		if (last_char == '\r' && *cp == '\n') {
		    cp++;
		    remainder--;
		}

		iovcnt = 0;
		while ((nl = memchr(cp, '\n', remainder)) != NULL) {
		    /*
		     * If there is already a carriage return, keep going.
		     * We'll include it as part of the next line written.
		     */
		    if (cp != nl && nl[-1] == '\r') {
			remainder = (size_t)(&buf[nread - 1] - nl);
			cp = nl + 1;
		    	continue;
		    }

		    /* Store the line in iov followed by \r\n pair. */
		    if (iovcnt + 3 > iovmax) {
			iov = iovmax ?
			    reallocarray(iov, iovmax <<= 1, sizeof(*iov)) :
			    reallocarray(NULL, iovmax = 32, sizeof(*iov));
			if (iov == NULL)
			    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
		    }
		    linelen = (size_t)(nl - line) + 1;
		    iov[iovcnt].iov_base = line;
		    iov[iovcnt].iov_len = linelen - 1; /* not including \n */
		    iovcnt++;
		    iov[iovcnt].iov_base = "\r\n";
		    iov[iovcnt].iov_len = 2;
		    iovcnt++;
		    line = cp = nl + 1;
		    remainder -= linelen;
		}
		if ((size_t)(line - buf) != nread) {
		    /*
		     * Partial line without a linefeed or multiple lines
		     * that already had \r\n pairs.
		     */
		    iov[iovcnt].iov_base = line;
		    iov[iovcnt].iov_len = nread - (line - buf);
		    iovcnt++;
		}
		last_char = buf[nread - 1]; /* stash last char of old buffer */
	    } else {
		/* No conversion needed. */
		iov[0].iov_base = buf;
		iov[0].iov_len = nread;
		iovcnt = 1;
	    }

	    /* Setup closure for write_output. */
	    wc.wevent = output_ev;
	    wc.iov = iov;
	    wc.iovcnt = iovcnt;
	    wc.nbytes = 0;
	    for (i = 0; i < iovcnt; i++)
		wc.nbytes += iov[i].iov_len;

	    /* Run event event loop to write output. */
	    /* XXX - should use a single event loop with a circular buffer. */
	    sudo_ev_add(evbase, output_ev, NULL, false);
	    sudo_ev_loop(evbase, 0);
	}
    }
    if (iov != &iovb)
	free(iov);
    sudo_ev_base_free(evbase);
    sudo_ev_free(input_ev);
    sudo_ev_free(output_ev);
    debug_return;
}

static int
open_io_fd(char *path, int len, struct io_log_file *iol)
{
    debug_decl(open_io_fd, SUDO_DEBUG_UTIL)

    if (!iol->enabled)
	debug_return_int(0);

    path[len] = '\0';
    strlcat(path, iol->suffix, PATH_MAX);
#ifdef HAVE_ZLIB_H
    iol->fd.g = gzopen(path, "r");
#else
    iol->fd.f = fopen(path, "r");
#endif
    debug_return_int(iol->fd.v ? 0 : -1);
}

static void
write_output(int fd, int what, void *v)
{
    struct write_closure *wc = v;
    size_t nwritten;
    unsigned int i;
    debug_decl(write_output, SUDO_DEBUG_UTIL)

    nwritten = writev(STDOUT_FILENO, wc->iov, wc->iovcnt);
    switch ((ssize_t)nwritten) {
    case -1:
	if (errno != EINTR && errno != EAGAIN)
	    sudo_fatal(U_("unable to write to %s"), "stdout");
	break;
    case 0:
	break;
    default:
	if (wc->nbytes == nwritten) {
	    /* writev completed */
	    debug_return;
	}

	/* short writev, adjust iov so we can write the remainder. */
	wc->nbytes -= nwritten;
	i = wc->iovcnt;
	while (i--) {
	    if (wc->iov[0].iov_len > nwritten) {
		/* Partial write, adjust base and len and reschedule. */
		wc->iov[0].iov_base = (char *)wc->iov[0].iov_base + nwritten;
		wc->iov[0].iov_len -= nwritten;
		break;
	    }
	    nwritten -= wc->iov[0].iov_len;
	    wc->iov++;
	    wc->iovcnt--;
	}
	break;
    }

    /* Reschedule event to write remainder. */
    sudo_ev_add(sudo_ev_get_base(wc->wevent), wc->wevent, NULL, false);
    debug_return;
}

/*
 * Build expression list from search args
 */
static int
parse_expr(struct search_node_list *head, char *argv[], bool sub_expr)
{
    bool or = false, not = false;
    struct search_node *sn;
    char type, **av;
    debug_decl(parse_expr, SUDO_DEBUG_UTIL)

    for (av = argv; *av != NULL; av++) {
	switch (av[0][0]) {
	case 'a': /* and (ignore) */
	    if (strncmp(*av, "and", strlen(*av)) != 0)
		goto bad;
	    continue;
	case 'o': /* or */
	    if (strncmp(*av, "or", strlen(*av)) != 0)
		goto bad;
	    or = true;
	    continue;
	case '!': /* negate */
	    if (av[0][1] != '\0')
		goto bad;
	    not = true;
	    continue;
	case 'c': /* cwd or command */
	    if (av[0][1] == '\0')
		sudo_fatalx(U_("ambiguous expression \"%s\""), *av);
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
		sudo_fatalx(U_("ambiguous expression \"%s\""), *av);
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
	    type = ST_EXPR;
	    break;
	case ')': /* end sub-expression */
	    if (av[0][1] != '\0')
		goto bad;
	    if (!sub_expr)
		sudo_fatalx(U_("unmatched ')' in expression"));
	    debug_return_int(av - argv + 1);
	default:
	bad:
	    sudo_fatalx(U_("unknown search term \"%s\""), *av);
	    /* NOTREACHED */
	}

	/* Allocate new search node */
	if ((sn = calloc(1, sizeof(*sn))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	sn->type = type;
	sn->or = or;
	sn->negated = not;
	if (type == ST_EXPR) {
	    STAILQ_INIT(&sn->u.expr);
	    av += parse_expr(&sn->u.expr, av + 1, true);
	} else {
	    if (*(++av) == NULL)
		sudo_fatalx(U_("%s requires an argument"), av[-1]);
	    if (type == ST_PATTERN) {
		if (regcomp(&sn->u.cmdre, *av, REG_EXTENDED|REG_NOSUB) != 0)
		    sudo_fatalx(U_("invalid regular expression: %s"), *av);
	    } else if (type == ST_TODATE || type == ST_FROMDATE) {
		sn->u.tstamp = get_date(*av);
		if (sn->u.tstamp == -1)
		    sudo_fatalx(U_("could not parse date \"%s\""), *av);
	    } else {
		sn->u.ptr = *av;
	    }
	}
	not = or = false; /* reset state */
	STAILQ_INSERT_TAIL(head, sn, entries);
    }
    if (sub_expr)
	sudo_fatalx(U_("unmatched '(' in expression"));
    if (or)
	sudo_fatalx(U_("illegal trailing \"or\""));
    if (not)
	sudo_fatalx(U_("illegal trailing \"!\""));

    debug_return_int(av - argv);
}

static bool
match_expr(struct search_node_list *head, struct log_info *log, bool last_match)
{
    struct search_node *sn;
    bool res, matched = last_match;
    int rc;
    debug_decl(match_expr, SUDO_DEBUG_UTIL)

    STAILQ_FOREACH(sn, head, entries) {
	switch (sn->type) {
	case ST_EXPR:
	    res = match_expr(&sn->u.expr, log, matched);
	    break;
	case ST_CWD:
	    res = strcmp(sn->u.cwd, log->cwd) == 0;
	    break;
	case ST_TTY:
	    res = strcmp(sn->u.tty, log->tty) == 0;
	    break;
	case ST_RUNASGROUP:
	    res = strcmp(sn->u.runas_group, log->runas_group) == 0;
	    break;
	case ST_RUNASUSER:
	    res = strcmp(sn->u.runas_user, log->runas_user) == 0;
	    break;
	case ST_USER:
	    res = strcmp(sn->u.user, log->user) == 0;
	    break;
	case ST_PATTERN:
	    rc = regexec(&sn->u.cmdre, log->cmd, 0, NULL, 0);
	    if (rc && rc != REG_NOMATCH) {
		char buf[BUFSIZ];
		regerror(rc, &sn->u.cmdre, buf, sizeof(buf));
		sudo_fatalx("%s", buf);
	    }
	    res = rc == REG_NOMATCH ? 0 : 1;
	    break;
	case ST_FROMDATE:
	    res = log->tstamp >= sn->u.tstamp;
	    break;
	case ST_TODATE:
	    res = log->tstamp <= sn->u.tstamp;
	    break;
	default:
	    sudo_fatalx(U_("unknown search type %d"), sn->type);
	    /* NOTREACHED */
	}
	if (sn->negated)
	    res = !res;
	matched = sn->or ? (res || last_match) : (res && last_match);
	last_match = matched;
    }
    debug_return_bool(matched);
}

static struct log_info *
parse_logfile(char *logfile)
{
    FILE *fp;
    char *buf = NULL, *cp, *ep;
    const char *errstr;
    size_t bufsize = 0, cwdsize = 0, cmdsize = 0;
    struct log_info *li = NULL;
    debug_decl(parse_logfile, SUDO_DEBUG_UTIL)

    fp = fopen(logfile, "r");
    if (fp == NULL) {
	sudo_warn(U_("unable to open %s"), logfile);
	goto bad;
    }

    /*
     * ID file has three lines:
     *  1) a log info line
     *  2) cwd
     *  3) command with args
     */
    if ((li = calloc(1, sizeof(*li))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (getline(&buf, &bufsize, fp) == -1 ||
	getline(&li->cwd, &cwdsize, fp) == -1 ||
	getline(&li->cmd, &cmdsize, fp) == -1) {
	sudo_warn(U_("%s: invalid log file"), logfile);
	goto bad;
    }

    /* Strip the newline from the cwd and command. */
    li->cwd[strcspn(li->cwd, "\n")] = '\0';
    li->cmd[strcspn(li->cmd, "\n")] = '\0';

    /*
     * Crack the log line (rows and cols not present in old versions).
     *	timestamp:user:runas_user:runas_group:tty:rows:cols
     * XXX - probably better to use strtok and switch on the state.
     */
    buf[strcspn(buf, "\n")] = '\0';
    cp = buf;

    /* timestamp */
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: time stamp field is missing"), logfile);
	goto bad;
    }
    *ep = '\0';
    li->tstamp = sizeof(time_t) == 4 ? strtonum(cp, INT_MIN, INT_MAX, &errstr) :
	strtonum(cp, LLONG_MIN, LLONG_MAX, &errstr);
    if (errstr != NULL) {
	sudo_warn(U_("%s: time stamp %s: %s"), logfile, cp, errstr);
	goto bad;
    }

    /* user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: user field is missing"), logfile);
	goto bad;
    }
    if ((li->user = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* runas user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: runas user field is missing"), logfile);
	goto bad;
    }
    if ((li->runas_user = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* runas group */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: runas group field is missing"), logfile);
	goto bad;
    }
    if (cp != ep) {
	if ((li->runas_group = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }

    /* tty, followed by optional rows + columns */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	/* just the tty */
	if ((li->tty = strdup(cp)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    } else {
	/* tty followed by rows + columns */
	if ((li->tty = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	cp = ep + 1;
	/* need to NULL out separator to use strtonum() */
	if ((ep = strchr(cp, ':')) != NULL) {
	    *ep = '\0';
	}
	li->rows = strtonum(cp, 1, INT_MAX, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: tty rows %s: %s", logfile, cp, errstr);
	}
	if (ep != NULL) {
	    cp = ep + 1;
	    li->cols = strtonum(cp, 1, INT_MAX, &errstr);
	    if (errstr != NULL) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "%s: tty cols %s: %s", logfile, cp, errstr);
	    }
	}
    }
    fclose(fp);
    free(buf);
    debug_return_ptr(li);

bad:
    if (fp != NULL)
	fclose(fp);
    free(buf);
    free_log_info(li);
    debug_return_ptr(NULL);
}

static void
free_log_info(struct log_info *li)
{
    if (li != NULL) {
	free(li->cwd);
	free(li->user);
	free(li->runas_user);
	free(li->runas_group);
	free(li->tty);
	free(li->cmd);
	free(li);
    }
}

static int
list_session(char *logfile, regex_t *re, const char *user, const char *tty)
{
    char idbuf[7], *idstr, *cp;
    const char *timestr;
    struct log_info *li;
    int rval = -1;
    debug_decl(list_session, SUDO_DEBUG_UTIL)

    if ((li = parse_logfile(logfile)) == NULL)
	goto done;

    /* Match on search expression if there is one. */
    if (!STAILQ_EMPTY(&search_expr) && !match_expr(&search_expr, li, true))
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
    timestr = get_timestr(li->tstamp, 1);
    printf("%s : %s : TTY=%s ; CWD=%s ; USER=%s ; ",
	timestr ? timestr : "invalid date",
	li->user, li->tty, li->cwd, li->runas_user);
    if (li->runas_group)
	printf("GROUP=%s ; ", li->runas_group);
    printf("TSID=%s ; COMMAND=%s\n", idstr, li->cmd);

    rval = 0;

done:
    free_log_info(li);
    debug_return_int(rval);
}

static int
session_compare(const void *v1, const void *v2)
{
    const char *s1 = *(const char **)v1;
    const char *s2 = *(const char **)v2;
    return strcmp(s1, s2);
}

/* XXX - always returns 0, calls sudo_fatal() on failure */
static int
find_sessions(const char *dir, regex_t *re, const char *user, const char *tty)
{
    DIR *d;
    struct dirent *dp;
    struct stat sb;
    size_t sdlen, sessions_len = 0, sessions_size = 0;
    unsigned int i;
    int len;
    char pathbuf[PATH_MAX], **sessions = NULL;
#ifdef HAVE_STRUCT_DIRENT_D_TYPE
    bool checked_type = true;
#else
    const bool checked_type = false;
#endif
    debug_decl(find_sessions, SUDO_DEBUG_UTIL)

    d = opendir(dir);
    if (d == NULL)
	sudo_fatal(U_("unable to open %s"), dir);

    /* XXX - would be faster to chdir and use relative names */
    sdlen = strlcpy(pathbuf, dir, sizeof(pathbuf));
    if (sdlen + 1 >= sizeof(pathbuf)) {
	errno = ENAMETOOLONG;
	sudo_fatal("%s/", dir);
    }
    pathbuf[sdlen++] = '/';
    pathbuf[sdlen] = '\0';

    /* Store potential session dirs for sorting. */
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
		checked_type = false;
	    }
	}
#endif

	/* Add name to session list. */
	if (sessions_len + 1 > sessions_size) {
	    if (sessions_size == 0)
		sessions_size = 36 * 36 / 2;
	    sessions = reallocarray(sessions, sessions_size, 2 * sizeof(char *));
	    if (sessions == NULL)
		sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    sessions_size *= 2;
	}
	if ((sessions[sessions_len] = strdup(dp->d_name)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	sessions_len++;
    }
    closedir(d);

    /* Sort and list the sessions. */
    if (sessions != NULL) {
	qsort(sessions, sessions_len, sizeof(char *), session_compare);
	for (i = 0; i < sessions_len; i++) {
	    len = snprintf(&pathbuf[sdlen], sizeof(pathbuf) - sdlen,
		"%s/log", sessions[i]);
	    if (len <= 0 || (size_t)len >= sizeof(pathbuf) - sdlen) {
		errno = ENAMETOOLONG;
		sudo_fatal("%s/%s/log", dir, sessions[i]);
	    }
	    free(sessions[i]);

	    /* Check for dir with a log file. */
	    if (lstat(pathbuf, &sb) == 0 && S_ISREG(sb.st_mode)) {
		list_session(pathbuf, re, user, tty);
	    } else {
		/* Strip off "/log" and recurse if a dir. */
		pathbuf[sdlen + len - 4] = '\0';
		if (checked_type ||
		    (lstat(pathbuf, &sb) == 0 && S_ISDIR(sb.st_mode)))
		    find_sessions(pathbuf, re, user, tty);
	    }
	}
	free(sessions);
    }

    debug_return_int(0);
}

/* XXX - always returns 0, calls sudo_fatal() on failure */
static int
list_sessions(int argc, char **argv, const char *pattern, const char *user,
    const char *tty)
{
    regex_t rebuf, *re = NULL;
    debug_decl(list_sessions, SUDO_DEBUG_UTIL)

    /* Parse search expression if present */
    parse_expr(&search_expr, argv, false);

    /* optional regex */
    if (pattern) {
	re = &rebuf;
	if (regcomp(re, pattern, REG_EXTENDED|REG_NOSUB) != 0)
	    sudo_fatalx(U_("invalid regular expression: %s"), pattern);
    }

    debug_return_int(find_sessions(session_dir, re, user, tty));
}

/*
 * Check input for ' ', '<', '>', return
 * pause, slow, fast, next
 */
static void
check_input(int fd, int what, void *v)
{
    struct sudo_event *ev = v;
    struct sudo_event_base *evbase = sudo_ev_get_base(ev);
    struct timeval tv, *timeout = NULL;
    static bool paused = 0;
    char ch;
    debug_decl(check_input, SUDO_DEBUG_UTIL)

    if (ISSET(what, SUDO_EV_READ)) {
	switch (read(fd, &ch, 1)) {
	case -1:
	    if (errno != EINTR && errno != EAGAIN)
		sudo_fatal(U_("unable to read %s"), "stdin");
	    break;
	case 0:
	    /* Ignore EOF. */
	    break;
	case 1:
	    if (paused) {
		/* Any key will unpause, event is finished. */
		/* XXX - pause time could be less than timeout */
		paused = false;
		debug_return; /* XXX */
	    }
	    switch (ch) {
	    case ' ':
		paused = true;
		break;
	    case '<':
		speed_factor /= 2;
		break;
	    case '>':
		speed_factor *= 2;
		break;
	    case '\r':
	    case '\n':
		debug_return; /* XXX */
	    }
	    break;
	}
	if (!paused) {
	    /* Determine remaining timeout, if any. */
	    sudo_ev_get_timeleft(ev, &tv);
	    if (!sudo_timevalisset(&tv)) {
		/* No time left, event is done. */
		debug_return;
	    }
	    timeout = &tv;
	}
	/* Re-enable event. */
	sudo_ev_add(evbase, ev, timeout, false);
    }
    debug_return;
}

/*
 * Parse a timing line, which is formatted as:
 *	index sleep_time num_bytes
 * Where index is IOFD_*, sleep_time is the number of seconds to sleep
 * before writing the data and num_bytes is the number of bytes to output.
 * Returns 1 on success and 0 on failure.
 */
static int
parse_timing(const char *buf, const char *decimal, int *idx, double *seconds,
    size_t *nbytes)
{
    unsigned long ul;
    long l;
    double d, fract = 0;
    char *cp, *ep;
    debug_decl(parse_timing, SUDO_DEBUG_UTIL)

    /* Parse index */
    ul = strtoul(buf, &ep, 10);
    if (ep == buf || !isspace((unsigned char) *ep))
	goto bad;
    if (ul >= IOFD_TIMING) {
	if (ul != 6)
	    goto bad;
	/* work around a bug in timing files generated by sudo 1.8.7 */
	timing_idx_adj = 2;
    }
    *idx = (int)ul - timing_idx_adj;
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
    if (ep == cp || (*ep != '.' && strncmp(ep, decimal, strlen(decimal)) != 0))
	goto bad;
    if (l < 0 || l > INT_MAX || (errno == ERANGE && l == LONG_MAX))
	goto bad;
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
    if (ep == cp || *ep != '\0' || (errno == ERANGE && ul == ULONG_MAX))
	goto bad;
    *nbytes = (size_t)ul;

    debug_return_int(1);
bad:
    debug_return_int(0);
}

static void
usage(int fatal)
{
    fprintf(fatal ? stderr : stdout,
	_("usage: %s [-h] [-d dir] [-m num] [-s num] ID\n"),
	getprogname());
    fprintf(fatal ? stderr : stdout,
	_("usage: %s [-h] [-d dir] -l [search expression]\n"),
	getprogname());
    if (fatal)
	exit(1);
}

static void
help(void)
{
    (void) printf(_("%s - replay sudo session logs\n\n"), getprogname());
    usage(0);
    (void) puts(_("\nOptions:\n"
	"  -d, --directory=dir  specify directory for session logs\n"
	"  -f, --filter=filter  specify which I/O type(s) to display\n"
	"  -h, --help           display help message and exit\n"
	"  -l, --list           list available session IDs, with optional expression\n"
	"  -m, --max-wait=num   max number of seconds to wait between events\n"
	"  -s, --speed=num      speed up or slow down output\n"
	"  -V, --version        display version information and exit"));
    exit(0);
}

/*
 * Cleanup hook for sudo_fatal()/sudo_fatalx()
  */
static void
sudoreplay_cleanup(void)
{
    sudo_term_restore(STDIN_FILENO, 0);
}

/*
 * Signal handler for SIGINT, SIGTERM, SIGHUP, SIGQUIT
 * Must be installed with SA_RESETHAND enabled.
 */
static void
sudoreplay_handler(int signo)
{
    sudo_term_restore(STDIN_FILENO, 0);
    kill(getpid(), signo);
}
