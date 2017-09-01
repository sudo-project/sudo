/*
 * Copyright (c) 2009-2017 Todd C. Miller <Todd.Miller@courtesan.com>
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
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
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

struct replay_closure {
    struct sudo_event_base *evbase;
    struct sudo_event *delay_ev;
    struct sudo_event *keyboard_ev;
    struct sudo_event *output_ev;
    struct sudo_event *sighup_ev;
    struct sudo_event *sigint_ev;
    struct sudo_event *sigquit_ev;
    struct sudo_event *sigterm_ev;
    struct sudo_event *sigtstp_ev;
    struct timing_closure {
	const char *decimal;
	double max_delay;
	int idx;
	union {
	    struct {
		int rows;
		int cols;
	    } winsize;
	    size_t nbytes; // XXX
	} u;
    } timing;
    bool interactive;
    struct io_buffer {
	unsigned int len; /* buffer length (how much produced) */
	unsigned int off; /* write position (how much already consumed) */
	unsigned int toread; /* how much remains to be read */
	int lastc;	  /* last char written */
	char buf[64 * 1024];
    } iobuf;
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

static bool terminal_can_resize, terminal_was_resized;

static int terminal_rows, terminal_cols;

static int ttyfd = -1;

static const char short_opts[] =  "d:f:hlm:nRs:V";
static struct option long_opts[] = {
    { "directory",	required_argument,	NULL,	'd' },
    { "filter",		required_argument,	NULL,	'f' },
    { "help",		no_argument,		NULL,	'h' },
    { "list",		no_argument,		NULL,	'l' },
    { "max-wait",	required_argument,	NULL,	'm' },
    { "non-interactive", no_argument,		NULL,	'n' },
    { "no-resize",	no_argument,		NULL,	'R' },
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
static bool parse_timing(const char *buf, double *seconds, struct timing_closure *timing);
static struct log_info *parse_logfile(char *logfile);
static void read_keyboard(int fd, int what, void *v);
static void free_log_info(struct log_info *li);
static void help(void) __attribute__((__noreturn__));
static int replay_session(double max_wait, const char *decimal, bool interactive);
static void sudoreplay_cleanup(void);
static void usage(int);
static void write_output(int fd, int what, void *v);
static void restore_terminal_size(void);
static void setup_terminal(struct log_info *li, bool interactive, bool resize);

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
    int ch, idx, plen, exitcode = 0;
    bool def_filter = true, listonly = false;
    bool interactive = true, resize = true;
    const char *decimal, *id, *user = NULL, *pattern = NULL, *tty = NULL;
    char *cp, *ep, path[PATH_MAX];
    struct log_info *li;
    double max_delay = 0;
    debug_decl(main, SUDO_DEBUG_MAIN)

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    {
	extern char *malloc_options;
	malloc_options = "S";
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
		if (strcmp(cp, "stdin") == 0)
		    io_log_files[IOFD_STDIN].enabled = true;
		else if (strcmp(cp, "stdout") == 0)
		    io_log_files[IOFD_STDOUT].enabled = true;
		else if (strcmp(cp, "stderr") == 0)
		    io_log_files[IOFD_STDERR].enabled = true;
		else if (strcmp(cp, "ttyin") == 0)
		    io_log_files[IOFD_TTYIN].enabled = true;
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
	    max_delay = strtod(optarg, &ep);
	    if (*ep != '\0' || errno != 0)
		sudo_fatalx(U_("invalid max wait: %s"), optarg);
	    break;
	case 'n':
	    interactive = false;
	    break;
	case 'R':
	    resize = false;
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
    printf(_("Replaying sudo session: %s"), li->cmd);

    /* Setup terminal if appropriate. */
    if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO))
	interactive = false;
    setup_terminal(li, interactive, resize);
    putchar('\r');
    putchar('\n');

    /* Done with parsed log file. */
    free_log_info(li);
    li = NULL;

    /* Replay session corresponding to io_log_files[]. */
    exitcode = replay_session(max_delay, decimal, interactive);

    restore_terminal_size();
    sudo_term_restore(ttyfd, true);
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

static int
io_log_eof(int idx)
{
    int ret;
    debug_decl(io_log_eof, SUDO_DEBUG_UTIL)

#ifdef HAVE_ZLIB_H
    ret = gzeof(io_log_files[idx].fd.g);
#else
    ret = feof(io_log_files[idx].fd.f);
#endif
    debug_return_int(ret);
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

/*
 * List of terminals that support xterm-like resizing.
 * This is not an exhaustive list.
 * For a list of VT100 style escape codes, see:
 *  http://invisible-island.net/xterm/ctlseqs/ctlseqs.html#VT100%20Mode
 */
struct term_names {
    const char *name;
    unsigned int len;
} compatible_terms[] = {
    { "Eterm", 5 },
    { "aterm", 5 },
    { "dtterm", 6 },
    { "gnome", 5 },
    { "konsole", 7 },
    { "kvt\0", 4 },
    { "mlterm", 6 },
    { "rxvt", 4 },
    { "xterm", 5 },
    { NULL, 0 }
};

struct getsize_closure {
    int nums[2];
    int nums_depth;
    int nums_maxdepth;
    int state;
    const char *cp;
    struct sudo_event *ev;
    struct timeval timeout;
};

/* getsize states */
#define INITIAL		0x00
#define NEW_NUMBER	0x01
#define NUMBER		0x02
#define GOTSIZE		0x04
#define READCHAR	0x10

/*
 * Callback for reading the terminal size response.
 * We use an event for this to support timeouts.
 */
static void
getsize_cb(int fd, int what, void *v)
{
    struct getsize_closure *gc = v;
    unsigned char ch = '\0';
    debug_decl(getsize_cb, SUDO_DEBUG_UTIL)

    for (;;) {
	if (gc->cp[0] == '\0') {
	    gc->state = GOTSIZE;
	    goto done;
	}
	if (ISSET(gc->state, READCHAR)) {
	    ssize_t nread = read(ttyfd, &ch, 1);
	    switch (nread) {
	    case -1:
		if (errno == EAGAIN)
		    goto another;
		/* FALLTHROUGH */
	    case 0:
		goto done;
	    default:
		CLR(gc->state, READCHAR);
		break;
	    }
	}
	switch (gc->state) {
	case INITIAL:
	    if (ch == 0233 && gc->cp[0] == '\033') {
		/* meta escape, equivalent to ESC[ */
		ch = '[';
		gc->cp++;
	    }
	    if (gc->cp[0] == '%' && gc->cp[1] == 'd') {
		gc->state = NEW_NUMBER;
		continue;
	    }
	    if (gc->cp[0] != ch) {
		sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
		    "got %d, expected %d", ch, gc->cp[0]);
		goto done;
	    }
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"got %d", ch);
	    SET(gc->state, READCHAR);
	    gc->cp++;
	    break;
	case NEW_NUMBER:
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"parsing number");
	    if (!isdigit(ch))
		goto done;
	    gc->cp += 2;
	    if (gc->nums_depth > gc->nums_maxdepth)
		goto done;
	    gc->nums[gc->nums_depth] = 0;
	    gc->state = NUMBER;
	    /* FALLTHROUGH */
	case NUMBER:
	    if (!isdigit(ch)) {
		/* done with number, reparse ch */
		sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		    "number %d (ch %d)", gc->nums[gc->nums_depth], ch);
		gc->nums_depth++;
		gc->state = INITIAL;
		continue;
	    }
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"got %d", ch);
	    if (gc->nums[gc->nums_depth] > INT_MAX / 10)
		goto done;
	    gc->nums[gc->nums_depth] *= 10;
	    gc->nums[gc->nums_depth] += (ch - '0');
	    SET(gc->state, READCHAR);
	    break;
	}
    }

another:
    if (sudo_ev_add(NULL, gc->ev, &gc->timeout, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));
done:
    debug_return;
}


/*
 * Get the terminal size using vt100 terminal escapes.
 */
static bool
xterm_get_size(int *new_rows, int *new_cols)
{
    struct sudo_event_base *evbase;
    struct getsize_closure gc;
    const char getsize_request[] = "\0337\033[r\033[999;999H\033[6n";
    const char getsize_response[] = "\033[%d;%dR";
    bool ret = false;
    debug_decl(xterm_get_size, SUDO_DEBUG_UTIL)

    /* request the terminal's size */
    if (write(ttyfd, getsize_request, strlen(getsize_request)) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "%s: error writing xterm size request", __func__);
	goto done;
    }

    /*
     * Callback info for reading back the size with a 10 second timeout.
     * We expect two numbers (rows and cols).
     */
    gc.state = INITIAL|READCHAR;
    gc.nums_depth = 0;
    gc.nums_maxdepth = 1;
    gc.cp = getsize_response;
    gc.timeout.tv_sec = 10;
    gc.timeout.tv_usec = 0;

    /* Setup an event for reading the terminal size */
    evbase = sudo_ev_base_alloc();
    if (evbase == NULL)
	sudo_fatal(NULL);
    gc.ev = sudo_ev_alloc(ttyfd, SUDO_EV_READ, getsize_cb, &gc);
    if (gc.ev == NULL)
        sudo_fatal(NULL);

    /* Read back terminal size response */
    if (sudo_ev_add(evbase, gc.ev, &gc.timeout, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));
    sudo_ev_loop(evbase, 0);

    if (gc.state == GOTSIZE) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "terminal size %d x %x", gc.nums[0], gc.nums[1]);
	*new_rows = gc.nums[0];
	*new_cols = gc.nums[1];
	ret = true;
    }

    sudo_ev_base_free(evbase);
    sudo_ev_free(gc.ev);

done:
    debug_return_bool(ret);
}

/*
 * Set the size of the text area to rows and cols.
 * Depending on the terminal implementation, the window itself may
 * or may not shrink to a smaller size.
 */
static bool
xterm_set_size(int rows, int cols)
{
    const char setsize_fmt[] = "\033[8;%d;%dt";
    int len, new_rows, new_cols;
    bool ret = false;
    char buf[1024];
    debug_decl(xterm_set_size, SUDO_DEBUG_UTIL)

    /* XXX - save cursor and position restore after resizing */
    len = snprintf(buf, sizeof(buf), setsize_fmt, rows, cols);
    if (len < 0 || len >= (int)sizeof(buf)) {
	/* not possible due to size of buf */
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: internal error, buffer too small?", __func__);
	goto done;
    }
    if (write(ttyfd, buf, strlen(buf)) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "%s: error writing xterm resize request", __func__);
	goto done;
    }
    /* XXX - keyboard input will interfere with this */
    if (!xterm_get_size(&new_rows, &new_cols))
	goto done;
    if (rows == new_rows && cols == new_cols)
	ret = true;

done:
    debug_return_bool(ret);
}

static void
setup_terminal(struct log_info *li, bool interactive, bool resize)
{
    const char *term;
    debug_decl(check_terminal, SUDO_DEBUG_UTIL)

    fflush(stdout);

    /* Open fd for /dev/tty and set to raw mode. */
    if (interactive) {
	ttyfd = open(_PATH_TTY, O_RDWR);
	while (!sudo_term_raw(ttyfd, 1)) {
	    if (errno != EINTR)
		sudo_fatal(U_("unable to set tty to raw mode"));
	    kill(getpid(), SIGTTOU);
	}
    }

    /* Find terminal size if the session has size info. */
    if (li->rows == 0 && li->cols == 0) {
	/* no tty size info, hope for the best... */
	debug_return;
    }

    if (resize && ttyfd != -1) {
	term = getenv("TERM");
	if (term != NULL && *term != '\0') {
	    struct term_names *tn;

	    for (tn = compatible_terms; tn->name != NULL; tn++) {
		if (strncmp(term, tn->name, tn->len) == 0) {
		    /* xterm-like terminals can resize themselves. */
		    if (xterm_get_size(&terminal_rows, &terminal_cols))
			terminal_can_resize = true;
		    break;
		}
	    }
	}
    }

    if (!terminal_can_resize) {
	/* either not xterm or not interactive */
	sudo_get_ttysize(&terminal_rows, &terminal_cols);
    }

    if (li->rows == terminal_rows && li->cols == terminal_cols) {
	/* nothing to change */
	debug_return;
    }

    if (terminal_can_resize) {
	/* session terminal size is different, try to resize ours */
	if (xterm_set_size(li->rows, li->cols)) {
	    /* success */
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"resized terminal to %d x %x", li->rows, li->cols);
	    terminal_was_resized = true;
	    debug_return;
	}
	/* resize failed, don't try again */
	terminal_can_resize = false;
    }

    if (li->rows > terminal_rows || li->cols > terminal_cols) {
	printf(_("Warning: your terminal is too small to properly replay the log.\n"));
	printf(_("Log geometry is %d x %d, your terminal's geometry is %d x %d."), li->rows, li->cols, terminal_rows, terminal_cols);
    }
    debug_return;
}

static void
resize_terminal(int rows, int cols)
{
    debug_decl(resize_terminal, SUDO_DEBUG_UTIL)

    if (terminal_can_resize) {
	if (xterm_set_size(rows, cols))
	    terminal_was_resized = true;
	else
	    terminal_can_resize = false;
    }

    debug_return;
}

static void
restore_terminal_size(void)
{
    debug_decl(restore_terminal, SUDO_DEBUG_UTIL)

    if (terminal_was_resized) {
	/* We are still in raw mode, hence the carriage return. */
	printf(U_("Replay finished, press any key to restore the terminal."));
	fflush(stdout);
	(void)getchar();
	xterm_set_size(terminal_rows, terminal_cols);
	putchar('\r');
	putchar('\n');
    }

    debug_return;
}

/*
 * Read the next record from the timing file and schedule a delay
 * event with the specified timeout.
 * Return 0 on success, 1 on EOF and -1 on error.
 */
static int
read_timing_record(struct replay_closure *closure)
{
    struct timeval timeout;
    char buf[LINE_MAX];
    double delay;
    debug_decl(read_timing_record, SUDO_DEBUG_UTIL)

    /* Read next record from timing file. */
    if (io_log_gets(IOFD_TIMING, buf, sizeof(buf)) == NULL) {
	/* EOF or error reading timing file, we are done. */
	debug_return_int(io_log_eof(IOFD_TIMING) ? 1 : -1);
    }

    /* Parse timing file record. */
    buf[strcspn(buf, "\n")] = '\0';
    if (!parse_timing(buf, &delay, &closure->timing))
	sudo_fatalx(U_("invalid timing file line: %s"), buf);

    /* Record number bytes to read. */
    /* XXX - remove timing->nbytes? */
    if (closure->timing.idx != IOFD_TIMING) {
    	closure->iobuf.len = 0;
    	closure->iobuf.off = 0;
    	closure->iobuf.lastc = '\0';
    	closure->iobuf.toread = closure->timing.u.nbytes;
    }

    /* Adjust delay using speed factor and clamp to max_delay */
    delay /= speed_factor;
    if (closure->timing.max_delay && delay > closure->timing.max_delay)
	delay = closure->timing.max_delay;

    /* Convert delay to a timeval. */
    timeout.tv_sec = delay;
    timeout.tv_usec = (delay - timeout.tv_sec) * 1000000.0;

    /* Schedule the delay event. */
    if (sudo_ev_add(closure->evbase, closure->delay_ev, &timeout, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    debug_return_int(0);
}

/*
 * Read next timing record.
 * Exits the event loop on EOF, breaks out on error.
 */
static void
next_timing_record(struct replay_closure *closure)
{
    debug_decl(next_timing_record, SUDO_DEBUG_UTIL)

    switch (read_timing_record(closure)) {
    case 0:
	/* success */
	break;
    case 1:
	/* EOF */
	sudo_ev_loopexit(closure->evbase);
	break;
    default:
	/* error */
	sudo_ev_loopbreak(closure->evbase);
	break;
    }
    debug_return;
}

static bool
fill_iobuf(struct replay_closure *closure)
{
    const size_t space = sizeof(closure->iobuf.buf) - closure->iobuf.len;
    const struct timing_closure *timing = &closure->timing;
    ssize_t nread;
    size_t len;
    debug_decl(fill_iobuf, SUDO_DEBUG_UTIL)

    if (closure->iobuf.toread != 0 && space != 0) {
	len = closure->iobuf.toread < space ? closure->iobuf.toread : space;
	nread = io_log_read(timing->idx,
	    closure->iobuf.buf + closure->iobuf.off, len);
	if (nread <= 0) {
	    if (nread == 0) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "%s: premature EOF, expected %u bytes",
		    io_log_files[timing->idx].suffix, closure->iobuf.toread);
	    } else {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
		    "%s: read error", io_log_files[timing->idx].suffix);
	    }
	    sudo_warnx(U_("unable to read %s"),
		io_log_files[timing->idx].suffix);
	    debug_return_bool(false);
	}
	closure->iobuf.toread -= nread;
	closure->iobuf.len += nread;
    }

    debug_return_bool(true);
}

/*
 * Called when the inter-record delay has expired.
 * Depending on the record type, either reads the next
 * record or changes window size.
 */
static void
delay_cb(int fd, int what, void *v)
{
    struct replay_closure *closure = v;
    const struct timing_closure *timing = &closure->timing;
    debug_decl(delay_cb, SUDO_DEBUG_UTIL)

    /* Check for window change event and resize as needed. */
    if (timing->idx == IOFD_TIMING) {
	resize_terminal(timing->u.winsize.rows, timing->u.winsize.cols);
	next_timing_record(closure);
	debug_return;
    }

    /* If we are not replaying this stream, just read the next record. */
    if (timing->idx >= IOFD_MAX || !io_log_files[timing->idx].enabled) {
	next_timing_record(closure);
	debug_return;
    }

    /* We are replaying this strean, enable write event. */
    if (sudo_ev_add(closure->evbase, closure->output_ev, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    debug_return;
}

static void
replay_closure_free(struct replay_closure *closure)
{
    /*
     * Free events and event base, then the closure itself.
     */
    sudo_ev_free(closure->delay_ev);
    sudo_ev_free(closure->keyboard_ev);
    sudo_ev_free(closure->output_ev);
    sudo_ev_free(closure->sighup_ev);
    sudo_ev_free(closure->sigint_ev);
    sudo_ev_free(closure->sigquit_ev);
    sudo_ev_free(closure->sigterm_ev);
    sudo_ev_free(closure->sigtstp_ev);
    sudo_ev_base_free(closure->evbase);
    free(closure);
}

static void
signal_cb(int signo, int what, void *v)
{
    struct replay_closure *closure = v;
    debug_decl(signal_cb, SUDO_DEBUG_UTIL)

    switch (signo) {
    case SIGHUP:
    case SIGINT:
    case SIGQUIT:
    case SIGTERM:
	/* Free the event base and restore signal handlers. */
	replay_closure_free(closure);

	/* Restore the terminal and die. */
	sudoreplay_cleanup();
	kill(getpid(), signo);
	break;
    case SIGTSTP:
	/* Ignore ^Z since we have no way to restore the screen. */
	break;
    }

    debug_return;
}

static struct replay_closure *
replay_closure_alloc(double max_delay, const char *decimal, bool interactive)
{
    struct replay_closure *closure;
    debug_decl(replay_closure_alloc, SUDO_DEBUG_UTIL)

    if ((closure = calloc(1, sizeof(*closure))) == NULL)
	debug_return_ptr(NULL);

    closure->interactive = interactive;
    closure->timing.max_delay = max_delay;
    closure->timing.decimal = decimal;

    /*
     * Setup event base and delay, input and output events.
     * If interactive, take input from and write to /dev/tty.
     * If not interactive there is no input event.
     */
    closure->evbase = sudo_ev_base_alloc();
    if (closure->evbase == NULL)
	goto bad;
    closure->delay_ev = sudo_ev_alloc(-1, SUDO_EV_TIMEOUT, delay_cb, closure);
    if (closure->delay_ev == NULL)
        goto bad;
    if (interactive) {
	closure->keyboard_ev = sudo_ev_alloc(ttyfd, SUDO_EV_READ|SUDO_EV_PERSIST,
	    read_keyboard, closure);
	if (closure->keyboard_ev == NULL)
	    goto bad;
	if (sudo_ev_add(closure->evbase, closure->keyboard_ev, NULL, false) == -1)
	    sudo_fatal(U_("unable to add event to queue"));
    }
    closure->output_ev = sudo_ev_alloc(interactive ? ttyfd : STDOUT_FILENO,
	SUDO_EV_WRITE, write_output, closure);
    if (closure->output_ev == NULL)
        goto bad;

    /*
     * Setup signal events, we need to restore the terminal if killed.
     */
    closure->sighup_ev = sudo_ev_alloc(SIGHUP, SUDO_EV_SIGNAL, signal_cb,
	closure);
    if (closure->sighup_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sighup_ev, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    closure->sigint_ev = sudo_ev_alloc(SIGINT, SUDO_EV_SIGNAL, signal_cb,
	closure);
    if (closure->sigint_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sigint_ev, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    closure->sigquit_ev = sudo_ev_alloc(SIGQUIT, SUDO_EV_SIGNAL, signal_cb,
	closure);
    if (closure->sigquit_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sigquit_ev, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    closure->sigterm_ev = sudo_ev_alloc(SIGTERM, SUDO_EV_SIGNAL, signal_cb,
	closure);
    if (closure->sigterm_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sigterm_ev, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    closure->sigtstp_ev = sudo_ev_alloc(SIGTSTP, SUDO_EV_SIGNAL, signal_cb,
	closure);
    if (closure->sigtstp_ev == NULL)
	goto bad;
    if (sudo_ev_add(closure->evbase, closure->sigtstp_ev, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    debug_return_ptr(closure);
bad:
    replay_closure_free(closure);
    debug_return_ptr(NULL);
}

static int
replay_session(double max_delay, const char *decimal, bool interactive)
{
    struct replay_closure *closure;
    int ret = 0;
    debug_decl(replay_session, SUDO_DEBUG_UTIL)

    /* Allocate the delay closure and read the first timing record. */
    closure = replay_closure_alloc(max_delay, decimal, interactive);
    if (read_timing_record(closure) != 0) {
	ret = 1;
	goto done;
    }

    /* Run event loop. */
    sudo_ev_loop(closure->evbase, 0);
    if (sudo_ev_got_break(closure->evbase))
	ret = 1;

done:
    /* Clean up and return. */
    replay_closure_free(closure);
    debug_return_int(ret);
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
    if (iol->fd.v == NULL) {
	iol->enabled = false;
	debug_return_int(-1);
    }
    debug_return_int(0);
}

/*
 * Write the I/O buffer.
 */
static void
write_output(int fd, int what, void *v)
{
    struct replay_closure *closure = v;
    const struct timing_closure *timing = &closure->timing;
    struct io_buffer *iobuf = &closure->iobuf;
    unsigned iovcnt = 1;
    struct iovec iov[2];
    bool added_cr = false;
    size_t nbytes, nwritten;
    debug_decl(write_output, SUDO_DEBUG_UTIL)

    /* Refill iobuf if there is more to read and buf is empty. */
    if (!fill_iobuf(closure)) {
	sudo_ev_loopbreak(closure->evbase);
	debug_return;
    }

    nbytes = iobuf->len - iobuf->off;
    iov[0].iov_base = iobuf->buf + iobuf->off;
    iov[0].iov_len = nbytes;

    if (closure->interactive &&
	(timing->idx == IOFD_STDOUT || timing->idx == IOFD_STDERR)) {
	char *nl;

	/*
	 * We may need to insert a carriage return before the newline.
	 * Note that the carriage return may have already been written.
	 */
	nl = memchr(iov[0].iov_base, '\n', iov[0].iov_len);
	if (nl != NULL) {
	    size_t len = (size_t)(nl - (char *)iov[0].iov_base);
	    if ((nl == iov[0].iov_base && iobuf->lastc != '\r') ||
		(nl != iov[0].iov_base && nl[-1] != '\r')) {
		iov[0].iov_len = len;
		iov[1].iov_base = "\r\n";
		iov[1].iov_len = 2;
		iovcnt = 2;
		nbytes = iov[0].iov_len + iov[1].iov_len;
		added_cr = true;
	    }
	}
    }

    nwritten = writev(fd, iov, iovcnt);
    switch ((ssize_t)nwritten) {
    case -1:
	if (errno != EINTR && errno != EAGAIN)
	    sudo_fatal(U_("unable to write to %s"), "stdout");
	break;
    case 0:
	/* Should not happen. */
	break;
    default:
	if (added_cr && nwritten >= nbytes - 1) {
	    /* The last char written was either '\r' or '\n'. */
	    iobuf->lastc = nwritten == nbytes ? '\n' : '\r';
	} else {
	    /* Stash the last char written. */
	    iobuf->lastc = *((char *)iov[0].iov_base + nwritten);
	}
	if (added_cr) {
	    /* Subtract one for the carriage return we added above. */
	    nwritten--;
	}
	iobuf->off += nwritten;
	break;
    }

    if (iobuf->off == iobuf->len) {
	/* Write complete, go to next timing entry if possible. */
	switch (read_timing_record(closure)) {
	case 0:
	    /* success */
	    break;
	case 1:
	    /* EOF */
	    sudo_ev_loopexit(closure->evbase);
	    break;
	default:
	    /* error */
	    sudo_ev_loopbreak(closure->evbase);
	    break;
	}
    } else {
	/* Reschedule event to write remainder. */
	if (sudo_ev_add(NULL, closure->output_ev, NULL, false) == -1)
	    sudo_fatal(U_("unable to add event to queue"));
    }
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
    int ret = -1;
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

    ret = 0;

done:
    free_log_info(li);
    debug_return_int(ret);
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

    /* XXX - would be faster to use openat() and relative names */
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
 * Check keyboard for ' ', '<', '>', return
 * pause, slow, fast, next
 */
static void
read_keyboard(int fd, int what, void *v)
{
    struct replay_closure *closure = v;
    static bool paused = false;
    struct timeval tv;
    ssize_t nread;
    char ch;
    debug_decl(read_keyboard, SUDO_DEBUG_UTIL)

    nread = read(fd, &ch, 1);
    switch (nread) {
    case -1:
	if (errno != EINTR && errno != EAGAIN)
	    sudo_fatal(U_("unable to read %s"), "stdin");
	break;
    case 0:
	/* Ignore EOF. */
	break;
    default:
	if (paused) {
	    /* Any key will unpause, run the delay callback directly. */
	    paused = false;
	    delay_cb(-1, SUDO_EV_TIMEOUT, closure);
	    debug_return;
	}
	switch (ch) {
	case ' ':
	    paused = true;
	    /* Disable the delay event until we unpause. */
	    sudo_ev_del(closure->evbase, closure->delay_ev);
	    break;
	case '<':
	    speed_factor /= 2;
            sudo_ev_get_timeleft(closure->delay_ev, &tv);
            if (sudo_timevalisset(&tv)) {
		/* Double remaining timeout. */
		tv.tv_sec *= 2;
		tv.tv_usec *= 2;
		if (tv.tv_usec >= 1000000) {
		    tv.tv_sec++;
		    tv.tv_usec -= 1000000;
		}
		if (sudo_ev_add(NULL, closure->delay_ev, &tv, false) == -1) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"failed to double remaining delay timeout");
		}
            }
	    break;
	case '>':
	    speed_factor *= 2;
            sudo_ev_get_timeleft(closure->delay_ev, &tv);
            if (sudo_timevalisset(&tv)) {
		/* Halve remaining timeout. */
		if (tv.tv_sec & 1)
		    tv.tv_usec += 500000;
		tv.tv_sec /= 2;
		tv.tv_usec /= 2;
		if (sudo_ev_add(NULL, closure->delay_ev, &tv, false) == -1) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"failed to halve remaining delay timeout");
		}
            }
	    break;
	case '\r':
	case '\n':
	    /* Cancel existing delay, run callback directly. */
	    sudo_ev_del(closure->evbase, closure->delay_ev);
	    delay_cb(-1, SUDO_EV_TIMEOUT, closure);
	    break;
	default:
	    /* Unknown key, nothing to do. */
	    break;
	}
	break;
    }
    debug_return;
}

/*
 * Parse a timing line, which is formatted as:
 *	index sleep_time num_bytes
 * Where index is IOFD_*, sleep_time is the number of seconds to sleep
 * before writing the data and num_bytes is the number of bytes to output.
 * Returns true on success and false on failure.
 */
static bool
parse_timing(const char *buf, double *seconds, struct timing_closure *timing)
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
    if (ul >= IOFD_MAX) {
	if (ul != 6)
	    goto bad;
	/* work around a bug in timing files generated by sudo 1.8.7 */
	timing_idx_adj = 2;
    }
    timing->idx = (int)ul - timing_idx_adj;
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
    if (ep == cp || (*ep != '.' && strncmp(ep, timing->decimal, strlen(timing->decimal)) != 0))
	goto bad;
    if (l < 0 || l > INT_MAX || (errno == ERANGE && l == LONG_MAX))
	goto bad;
    *seconds = (double)l;
    cp = ep + (*ep == '.' ? 1 : strlen(timing->decimal));
    d = 10.0;
    while (isdigit((unsigned char) *cp)) {
	fract += (*cp - '0') / d;
	d *= 10;
	cp++;
    }
    *seconds += fract;
    while (isspace((unsigned char) *cp))
	cp++;

    if (timing->idx == IOFD_TIMING) {
	errno = 0;
	ul = strtoul(cp, &ep, 10);
	if (ep == cp || !isspace((unsigned char) *ep))
	    goto bad;
	if (ul > INT_MAX || (errno == ERANGE && ul == ULONG_MAX))
	    goto bad;
	timing->u.winsize.rows = (int)ul;
	for (cp = ep + 1; isspace((unsigned char) *cp); cp++)
	    continue;

	errno = 0;
	ul = strtoul(cp, &ep, 10);
	if (ep == cp || *ep != '\0')
	    goto bad;
	if (ul > INT_MAX || (errno == ERANGE && ul == ULONG_MAX))
	    goto bad;
	timing->u.winsize.cols = (int)ul;
    } else {
	errno = 0;
	ul = strtoul(cp, &ep, 10);
	if (ep == cp || *ep != '\0')
	    goto bad;
	if (ul > SIZE_MAX || (errno == ERANGE && ul == ULONG_MAX))
	    goto bad;
	timing->u.nbytes = (size_t)ul;
    }

    debug_return_bool(true);
bad:
    debug_return_bool(false);
}

static void
usage(int fatal)
{
    fprintf(fatal ? stderr : stdout,
	_("usage: %s [-hnR] [-d dir] [-m num] [-s num] ID\n"),
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
    restore_terminal_size();
    sudo_term_restore(ttyfd, false);
}
