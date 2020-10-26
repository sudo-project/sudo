/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <time.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_eventlog.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_iolog.h"
#include "sudo_util.h"

static int timing_event_adj;

static bool
iolog_parse_loginfo_legacy(FILE *fp, const char *iolog_dir,
    struct eventlog *evlog)
{
    char *buf = NULL, *cp, *ep;
    const char *errstr;
    size_t bufsize = 0, cwdsize = 0, cmdsize = 0;
    bool ret = false;
    debug_decl(iolog_parse_loginfo_legacy, SUDO_DEBUG_UTIL);

    /*
     * Info file has three lines:
     *  1) a log info line
     *  2) cwd
     *  3) command with args
     */
    if (getdelim(&buf, &bufsize, '\n', fp) == -1 ||
	getdelim(&evlog->cwd, &cwdsize, '\n', fp) == -1 ||
	getdelim(&evlog->command, &cmdsize, '\n', fp) == -1) {
	sudo_warn(U_("%s: invalid log file"), iolog_dir);
	goto done;
    }

    /* Strip the newline from the cwd and command. */
    evlog->cwd[strcspn(evlog->cwd, "\n")] = '\0';
    evlog->command[strcspn(evlog->command, "\n")] = '\0';

    /*
     * Crack the log line (lines and cols not present in old versions).
     *	timestamp:user:runas_user:runas_group:tty:lines:cols
     * XXX - probably better to use strtok and switch on the state.
     */
    buf[strcspn(buf, "\n")] = '\0';
    cp = buf;

    /* timestamp */
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: time stamp field is missing"), iolog_dir);
	goto done;
    }
    *ep = '\0';
    evlog->submit_time.tv_sec = sudo_strtonum(cp, 0, TIME_T_MAX, &errstr);
    if (errstr != NULL) {
	sudo_warn(U_("%s: time stamp %s: %s"), iolog_dir, cp, errstr);
	goto done;
    }

    /* submit user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: user field is missing"), iolog_dir);
	goto done;
    }
    if ((evlog->submituser = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* runas user */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: runas user field is missing"), iolog_dir);
	goto done;
    }
    if ((evlog->runuser = strndup(cp, (size_t)(ep - cp))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* runas group */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warn(U_("%s: runas group field is missing"), iolog_dir);
	goto done;
    }
    if (cp != ep) {
	if ((evlog->rungroup = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }

    /* tty, followed by optional lines + cols */
    cp = ep + 1;
    if ((ep = strchr(cp, ':')) == NULL) {
	/* just the tty */
	if ((evlog->ttyname = strdup(cp)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    } else {
	/* tty followed by lines + cols */
	if ((evlog->ttyname = strndup(cp, (size_t)(ep - cp))) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	cp = ep + 1;
	/* need to NULL out separator to use sudo_strtonum() */
	/* XXX - use sudo_strtonumx */
	if ((ep = strchr(cp, ':')) != NULL) {
	    *ep = '\0';
	}
	evlog->lines = sudo_strtonum(cp, 1, INT_MAX, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: tty lines %s: %s", iolog_dir, cp, errstr);
	}
	if (ep != NULL) {
	    cp = ep + 1;
	    evlog->columns = sudo_strtonum(cp, 1, INT_MAX, &errstr);
	    if (errstr != NULL) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "%s: tty cols %s: %s", iolog_dir, cp, errstr);
	    }
	}
    }

    ret = true;

done:
    free(buf);
    debug_return_bool(ret);
}

struct eventlog *
iolog_parse_loginfo(int dfd, const char *iolog_dir)
{
    struct eventlog *evlog = NULL;
    FILE *fp = NULL;
    int fd = -1;
    int tmpfd = -1;
    bool ok, legacy = false;
    debug_decl(iolog_parse_loginfo, SUDO_DEBUG_UTIL);

    if (dfd == -1) {
	if ((tmpfd = open(iolog_dir, O_RDONLY)) == -1) {
	    sudo_warn("%s", iolog_dir);
	    goto bad;
	}
	dfd = tmpfd;
    }
    if ((fd = openat(dfd, "log.json", O_RDONLY, 0)) == -1) {
	fd = openat(dfd, "log", O_RDONLY, 0);
	legacy = true;
    }
    if (tmpfd != -1)
	close(tmpfd);
    if (fd == -1 || (fp = fdopen(fd, "r")) == NULL) {
	sudo_warn("%s/log", iolog_dir);
	goto bad;
    }
    fd = -1;

    if ((evlog = calloc(1, sizeof(*evlog))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    evlog->runuid = (uid_t)-1;
    evlog->rungid = (gid_t)-1;

    ok = legacy ? iolog_parse_loginfo_legacy(fp, iolog_dir, evlog) :
	iolog_parse_loginfo_json(fp, iolog_dir, evlog);
    if (ok) {
	fclose(fp);
	debug_return_ptr(evlog);
    }

bad:
    if (fd != -1)
	close(fd);
    if (fp != NULL)
	fclose(fp);
    eventlog_free(evlog);
    debug_return_ptr(NULL);
}

void
iolog_adjust_delay(struct timespec *delay, struct timespec *max_delay,
     double scale_factor)
{
    double seconds;
    debug_decl(iolog_adjust_delay, SUDO_DEBUG_UTIL);

    if (scale_factor != 1.0) {
	/* Order is important: we don't want to double the remainder. */
        seconds = (double)delay->tv_sec / scale_factor;
        delay->tv_sec = (time_t)seconds;
        delay->tv_nsec /= scale_factor;
        delay->tv_nsec += (seconds - delay->tv_sec) * 1000000000;
        while (delay->tv_nsec >= 1000000000) {
            delay->tv_sec++;
            delay->tv_nsec -= 1000000000;
        }
    }

    /* Clamp to max delay. */
    if (max_delay != NULL) {
	if (sudo_timespeccmp(delay, max_delay, >)) {
	    delay->tv_sec = max_delay->tv_sec;
	    delay->tv_nsec = max_delay->tv_nsec;
	}
    }

    debug_return;
}

/*
 * Parse the delay as seconds and nanoseconds: %lld.%09ld
 * Sudo used to write this as a double, but since timing data is logged
 * in the C locale this may not match the current locale.
 */
char *
iolog_parse_delay(const char *cp, struct timespec *delay,
    const char *decimal_point)
{
    char numbuf[(((sizeof(long long) * 8) + 2) / 3) + 2];
    const char *errstr, *ep;
    long long llval;
    size_t len;
    debug_decl(iolog_parse_delay, SUDO_DEBUG_UTIL);

    /* Parse seconds (whole number portion). */
    for (ep = cp; isdigit((unsigned char)*ep); ep++)
	continue;
    len = (size_t)(ep - cp);
    if (len >= sizeof(numbuf)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: number of seconds is too large", cp);
	debug_return_ptr(NULL);
    }
    memcpy(numbuf, cp, len);
    numbuf[len] = '\0';
    delay->tv_sec = sudo_strtonum(numbuf, 0, TIME_T_MAX, &errstr);
    if (errstr != NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: number of seconds is %s", numbuf, errstr);
	debug_return_ptr(NULL);
    }

    /* Radix may be in user's locale for sudo < 1.7.4 so accept that too. */
    if (*ep != '.' && *ep != *decimal_point) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid characters after seconds: %s", ep);
	debug_return_ptr(NULL);
    }
    cp = ep + 1;

    /* Parse fractional part, we may read more precision than we can store. */
    for (ep = cp; isdigit((unsigned char)*ep); ep++)
	continue;
    len = (size_t)(ep - cp);
    if (len >= sizeof(numbuf)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: number of nanoseconds is too large", cp);
	debug_return_ptr(NULL);
    }
    memcpy(numbuf, cp, len);
    numbuf[len] = '\0';
    llval = sudo_strtonum(numbuf, 0, LLONG_MAX, &errstr);
    if (errstr != NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "%s: number of nanoseconds is %s", numbuf, errstr);
	debug_return_ptr(NULL);
    }

    /* Adjust fractional part to nanosecond precision. */
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
 *	IO_EVENT_WINSIZE sleep_time lines cols
 *	IO_EVENT_SUSPEND sleep_time signo
 * Where type is IO_EVENT_*, sleep_time is the number of seconds to sleep
 * before writing the data and num_bytes is the number of bytes to output.
 * Returns true on success and false on failure.
 */
bool
iolog_parse_timing(const char *line, struct timing_closure *timing)
{
    unsigned long ulval;
    char *cp, *ep;
    debug_decl(iolog_parse_timing, SUDO_DEBUG_UTIL);

    /* Clear iolog descriptor. */
    timing->iol = NULL;

    /* Parse event type. */
    ulval = strtoul(line, &ep, 10);
    if (ep == line || !isspace((unsigned char) *ep))
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
    if ((cp = iolog_parse_delay(cp, &timing->delay, timing->decimal)) == NULL)
	goto bad;

    switch (timing->event) {
    case IO_EVENT_SUSPEND:
	/* Signal name (no leading SIG prefix) or number. */
	if (str2sig(cp, &timing->u.signo) == -1)
	    goto bad;
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
	timing->u.winsize.cols = (int)ulval;
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
iolog_read_timing_record(struct iolog_file *iol, struct timing_closure *timing)
{
    char line[LINE_MAX];
    const char *errstr;
    debug_decl(iolog_read_timing_record, SUDO_DEBUG_UTIL);

    /* Read next record from timing file. */
    if (iolog_gets(iol, line, sizeof(line), &errstr) == NULL) {
	/* EOF or error reading timing file, we are done. */
	if (iolog_eof(iol))
	    debug_return_int(1);
	sudo_warnx(U_("error reading timing file: %s"), errstr);
	debug_return_int(-1);
    }

    /* Parse timing file record. */
    line[strcspn(line, "\n")] = '\0';
    if (!iolog_parse_timing(line, timing)) {
	sudo_warnx(U_("invalid timing file line: %s"), line);
	debug_return_int(-1);
    }

    debug_return_int(0);
}
