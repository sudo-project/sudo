/*
 * Copyright (c) 2019 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include "config.h"

#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log_server.pb-c.h"
#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "sudo_fatal.h"
#include "iolog.h"
#include "sendlog.h"

static int timing_event_adj;
static gzFile io_fds[IOFD_MAX];

/* I/O log file names relative to iolog_dir. */
/* XXX - duplicated with server */
static const char *iolog_names[] = {
    "stdin",	/* IOFD_STDIN */
    "stdout",	/* IOFD_STDOUT */
    "stderr",	/* IOFD_STDERR */
    "ttyin",	/* IOFD_TTYIN  */
    "ttyout",	/* IOFD_TTYOUT */
    "timing",	/* IOFD_TIMING */
    NULL	/* IOFD_MAX */
};

void
free_log_info(struct log_info *li)
{
    if (li != NULL) {
	free(li->cwd);
	free(li->submituser);
	free(li->runuser);
	free(li->rungroup);
	free(li->ttyname);
	free(li->command);
	free(li);
    }
}

/*
 * Open any I/O log files that are present.
 * The timing file must always exist.
 */
bool
iolog_open(const char *iolog_path)
{
    char fname[PATH_MAX];
    int i, len;
    debug_decl(iolog_open, SUDO_DEBUG_UTIL)

    for (i = 0; iolog_names[i] != NULL; i++) {
	len = snprintf(fname, sizeof(fname), "%s/%s", iolog_path,
	    iolog_names[i]);
	if (len < 0 || len >= ssizeof(fname)) {
	    errno = ENAMETOOLONG;
	    sudo_warn("%s/%s", iolog_path, iolog_names[i]);
	}
	io_fds[i] = gzopen(fname, "r");
	if (io_fds[i] == NULL && i == IOFD_TIMING) {
	    /* The timing file is not optional. */
	    sudo_warn("unable to open %s/%s", iolog_path, iolog_names[i]);
	    debug_return_bool(false);
	}
    }
    debug_return_bool(true);
}

struct log_info *
parse_logfile(const char *logfile)
{
    FILE *fp;
    char *buf = NULL, *cp, *ep;
    size_t bufsize = 0, cwdsize = 0, cmdsize = 0;
    long long llval;
    struct log_info *li = NULL;
    debug_decl(parse_logfile, SUDO_DEBUG_UTIL)

    fp = fopen(logfile, "r");
    if (fp == NULL) {
	sudo_warn("unable to open %s", logfile);
	goto bad;
    }

    /*
     * ID file has three lines:
     *  1) a log info line
     *  2) cwd
     *  3) command with args
     */
    if ((li = calloc(1, sizeof(*li))) == NULL)
	sudo_fatalx("%s: %s", __func__, "unable to allocate memory");
    if (getdelim(&buf, &bufsize, '\n', fp) == -1 ||
	getdelim(&li->cwd, &cwdsize, '\n', fp) == -1 ||
	getdelim(&li->command, &cmdsize, '\n', fp) == -1) {
	sudo_warn("%s: invalid log file", logfile);
	goto bad;
    }

    /* Strip the newline from the cwd and command. */
    li->cwd[strcspn(li->cwd, "\n")] = '\0';
    li->command[strcspn(li->command, "\n")] = '\0';

    /*
     * Crack the log line (lines and columns not present in old versions).
     *	timestamp:submituser:runuser:rungroup:ttyname:lines:columns
     * XXX - probably better to use strtok and switch on the state.
     */
    buf[strcspn(buf, "\n")] = '\0';
    cp = buf;

    /* timestamp */
    errno = 0;
    llval = strtoll(cp, &ep, 10);
    if (cp == ep || *ep != ':') {
	sudo_warn("%s: time stamp field is missing", logfile);
	goto bad;
    }
    if (errno == ERANGE && (llval == LLONG_MAX || llval == LLONG_MIN)) {
	sudo_warn("%s: time stamp %s: out of range", logfile, cp);
	goto bad;
    }
    li->start_time = llval;

    /* submituser */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn("%s: submituser field is missing", logfile);
	goto bad;
    }
    if ((li->submituser = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx("%s: %s", __func__, "unable to allocate memory");

    /* runuser */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn("%s: runuser field is missing", logfile);
	goto bad;
    }
    if ((li->runuser = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx("%s: %s", __func__, "unable to allocate memory");

    /* rungroup */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn("%s: rungroup field is missing", logfile);
	goto bad;
    }
    if (cp != ep) {
	if ((li->rungroup = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx("%s: %s", __func__, "unable to allocate memory");
    }

    /* ttyname, followed by optional lines + columns */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	/* just the ttyname */
	if ((li->ttyname = strdup(cp)) == NULL)
	    sudo_fatalx("%s: %s", __func__, "unable to allocate memory");
    } else {
	/* ttyname followed by lines + columns */
	unsigned long ulval;

	if ((li->ttyname = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx("%s: %s", __func__, "unable to allocate memory");

	/* lines */
	cp = ep + 1;
	errno = 0;
	ulval = strtoul(cp, &ep, 10);
	if (cp == ep || *ep != ':') {
	    sudo_warn("%s: terminal lines field is missing", logfile);
	    goto bad;
	}
	if ((errno == ERANGE && ulval == ULONG_MAX) || ulval > INT_MAX) {
	    sudo_warn("%s: terminal lines %s: out of range", logfile, cp);
	    goto bad;
	}
	li->lines = (int)ulval;

	/* columns */
	cp = ep + 1;
	errno = 0;
	ulval = strtoul(cp, &ep, 10);
	if (cp == ep || (*ep != ':' && *ep != '\0')) {
	    sudo_warn("%s: terminal columns field is missing", logfile);
	    goto bad;
	}
	if ((errno == ERANGE && ulval == ULONG_MAX) || ulval > INT_MAX) {
	    sudo_warn("%s: terminal columns %s: out of range", logfile, cp);
	    goto bad;
	}
	li->columns = (int)ulval;
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

/*
 * Parse the delay as seconds and nanoseconds: %lld.%09ld
 * Sudo used to write this as a double, but since timing data is logged
 * in the C locale this may not match the current locale.
 */
static char *
parse_delay(const char *cp, struct timespec *delay)
{
    long long llval;
    size_t len;
    char *ep;
    debug_decl(parse_delay, SUDO_DEBUG_UTIL)

    /* Parse seconds (whole number portion). */
    errno = 0;
    llval = strtoll(cp, &ep, 10);
    /* Radix may be in user's locale for sudo < 1.7.4 so accept that too. */
    if (cp == ep || *ep != '.') {
	sudo_warnx("invalid characters after seconds: %s", ep);
	debug_return_ptr(NULL);
    }
    if (errno == ERANGE && (llval == LLONG_MAX || llval == LLONG_MIN)) {
	sudo_warnx("%s: number of seconds out of range", cp);
	debug_return_ptr(NULL);
    }
    delay->tv_sec = (time_t)llval;
    cp = ep + 1;

    /* Parse fractional part, we may read more precision than we can store. */
    errno = 0;
    llval = strtoll(cp, &ep, 10);
    if (cp == ep || (*ep != ' ' && *ep != '\0')) {
	sudo_warnx("invalid characters after nanoseconds: %s", ep);
	debug_return_ptr(NULL);
    }
    if (errno == ERANGE && (llval == LLONG_MAX || llval == LLONG_MIN)) {
	sudo_warnx("%s: number of nanoseconds out of range", cp);
	debug_return_ptr(NULL);
    }

    /* Adjust fractional part to nanosecond precision. */
    len = (size_t)(ep - cp);
    if (len < 9) {
	/* Convert to nanosecond precision. */
	do {
	    llval *= 10;
	} while (++len < 9);
    } else if (len > 9) {
	/* Clamp to nanoseconds. */
	do {
	    llval /= 10;
	} while (--len > 9);
    }
    delay->tv_nsec = (long)llval;

    /* Advance to the next field. */
    while (isspace((unsigned char)*ep))
	ep++;

    debug_return_str((char *)ep);
}

/*
 * Parse a timing line, which is formatted as:
 *	IO_EVENT_TTYOUT sleep_time num_bytes
 *	IO_EVENT_WINSIZE sleep_time lines columns
 *	IO_EVENT_SUSPEND sleep_time signal
 * Where type is IO_EVENT_*, sleep_time is the number of seconds to sleep
 * before writing the data and num_bytes is the number of bytes to output.
 * Returns true on success and false on failure.
 */
static bool
parse_timing(const char *buf, struct timing_closure *timing)
{
    unsigned long ulval;
    char *cp, *ep;
    debug_decl(parse_timing, SUDO_DEBUG_UTIL)

    /* Parse event type. */
    ulval = strtoul(buf, &ep, 10);
    if (ep == buf || !isspace((unsigned char) *ep))
	goto bad;
    if (ulval >= IO_EVENT_COUNT)
	goto bad;
    if (ulval == IO_EVENT_TTYOUT_1_8_7) {
	/* work around a bug in timing files generated by sudo 1.8.7 */
	timing_event_adj = 2;
    }
    timing->event = (int)ulval - timing_event_adj;
    for (cp = ep + 1; isspace((unsigned char) *cp); cp++)
	continue;

    /* Parse delay, returns the next field or NULL on error. */
    if ((cp = parse_delay(cp, &timing->delay)) == NULL)
	goto bad;

    switch (timing->event) {
    case IO_EVENT_SUSPEND:
	/* Signal name (no leading SIG prefix) or number. */
	if (isdigit((unsigned char)*cp)) {
	    /* Signal number, convert to name. */
	    ulval = strtoul(cp, &ep, 10);
	    if (ep == cp || *ep != '\0')
		goto bad;
	    if (ulval > INT_MAX)
		goto bad;
	    if (sig2str(ulval, timing->buf) == -1)
		goto bad;
	} else {
	    /* Signal name. */
	    if (strlcpy(timing->buf, cp, timing->bufsize) >= timing->bufsize)
		goto bad;
	}
	break;
    case IO_EVENT_WINSIZE:
	ulval = strtoul(cp, &ep, 10);
	if (ep == cp || !isspace((unsigned char) *ep))
	    goto bad;
	if (ulval > INT_MAX)
	    goto bad;
	timing->u.winsize.lines = (int)ulval;
	for (cp = ep + 1; isspace((unsigned char) *cp); cp++)
	    continue;

	ulval = strtoul(cp, &ep, 10);
	if (ep == cp || *ep != '\0')
	    goto bad;
	if (ulval > INT_MAX)
	    goto bad;
	timing->u.winsize.columns = (int)ulval;
	break;
    default:
	errno = 0;
	ulval = strtoul(cp, &ep, 10);
	if (ep == cp || *ep != '\0')
	    goto bad;
	/* Note: assumes SIZE_MAX == ULONG_MAX */
	if (errno == ERANGE && ulval == ULONG_MAX)
	    goto bad;
	timing->u.nbytes = (size_t)ulval;
	break;
    }

    debug_return_bool(true);
bad:
    debug_return_bool(false);
}

/*
 * Read the next record from the timing file.
 * Return 0 on success, 1 on EOF and -1 on error.
 */
int
read_timing_record(struct timing_closure *timing)
{
    const char *errstr;
    char line[LINE_MAX];
    int errnum;
    debug_decl(read_timing_record, SUDO_DEBUG_UTIL)

    /* Read next record from timing file. */
    if (gzgets(io_fds[IOFD_TIMING], line, sizeof(line)) == NULL) {
	/* EOF or error reading timing file, we are done. */
	if (gzeof(io_fds[IOFD_TIMING]))
	    debug_return_int(1);	/* EOF */
	if ((errstr = gzerror(io_fds[IOFD_TIMING], &errnum)) == NULL)
	    errstr = strerror(errno);
	sudo_warnx("error reading timing file: %s", errstr);
	debug_return_int(-1);
    }

    /* Parse timing file record. */
    line[strcspn(line, "\n")] = '\0';
    if (!parse_timing(line, timing)) {
	sudo_warnx("invalid timing file line: %s", line);
	debug_return_int(-1);
    }

    debug_return_int(0);
}

bool
read_io_buf(struct timing_closure *timing)
{
    size_t nread;
    debug_decl(read_io_buf, SUDO_DEBUG_UTIL)

    if (io_fds[timing->event] == NULL) {
	sudo_warnx("%s file not open", iolog_names[timing->event]);
	debug_return_bool(false);
    }

    /* Expand buf as needed. */
    if (timing->u.nbytes > timing->bufsize) {
	free(timing->buf);
	do {
	    timing->bufsize *= 2;
	} while (timing->u.nbytes > timing->bufsize);
	if ((timing->buf = malloc(timing->bufsize)) == NULL) {
	    sudo_warn("malloc %zu", timing->bufsize);
	    timing->u.nbytes = 0;
	    debug_return_bool(false);
	}
    }

    nread = gzread(io_fds[timing->event], timing->buf, timing->u.nbytes);
    if (nread != timing->u.nbytes) {
	int errnum;
	const char *errstr;

	if ((errstr = gzerror(io_fds[timing->event], &errnum)) == NULL)
	    errstr = strerror(errno);
	sudo_warnx("unable to read %s file: %s", iolog_names[timing->event], errstr);
	debug_return_bool(false);
    }
    debug_return_bool(true);
}
