/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1994-1996, 1998-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "log_server.pb-c.h"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */
#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_queue.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "sudo_iolog.h"
#include "logsrvd.h"

#define	LL_HOST_STR	"HOST="
#define	LL_TTY_STR	"TTY="
#define	LL_CWD_STR	"PWD="
#define	LL_USER_STR	"USER="
#define	LL_GROUP_STR	"GROUP="
#define	LL_ENV_STR	"ENV="
#define	LL_CMND_STR	"COMMAND="
#define	LL_TSID_STR	"TSID="

#define IS_SESSID(s) ( \
    isalnum((unsigned char)(s)[0]) && isalnum((unsigned char)(s)[1]) && \
    (s)[2] == '/' && \
    isalnum((unsigned char)(s)[3]) && isalnum((unsigned char)(s)[4]) && \
    (s)[5] == '/' && \
    isalnum((unsigned char)(s)[6]) && isalnum((unsigned char)(s)[7]) && \
    (s)[8] == '\0')

/*
 * Allocate and fill in a new logline.
 */
static char *
new_logline(const char *message, const char *errstr,
    const struct iolog_details *details)
{
    char *line = NULL, *evstr = NULL;
    const char *iolog_file = details->iolog_file;
    char sessid[7];
    const char *tsid = NULL;
    size_t len = 0;
    int i;
    debug_decl(new_logline, SUDO_DEBUG_UTIL);

    /* A TSID may be a sudoers-style session ID or a free-form string. */
    if (iolog_file != NULL) {
	if (IS_SESSID(iolog_file)) {
	    sessid[0] = iolog_file[0];
	    sessid[1] = iolog_file[1];
	    sessid[2] = iolog_file[3];
	    sessid[3] = iolog_file[4];
	    sessid[4] = iolog_file[6];
	    sessid[5] = iolog_file[7];
	    sessid[6] = '\0';
	    tsid = sessid;
	} else {
	    tsid = iolog_file;
	}
    }

    /*
     * Compute line length
     */
    if (message != NULL)
	len += strlen(message) + 3;
    if (errstr != NULL)
	len += strlen(errstr) + 3;
    len += sizeof(LL_HOST_STR) + 2 + strlen(details->submithost);
    len += sizeof(LL_TTY_STR) + 2 + strlen(details->ttyname);
    len += sizeof(LL_CWD_STR) + 2 + strlen(details->cwd);
    if (details->runuser != NULL)
	len += sizeof(LL_USER_STR) + 2 + strlen(details->runuser);
    if (details->rungroup != NULL)
	len += sizeof(LL_GROUP_STR) + 2 + strlen(details->rungroup);
    if (tsid != NULL)
	len += sizeof(LL_TSID_STR) + 2 + strlen(tsid);
    if (details->env_add != NULL) {
	size_t evlen = 0;
	char * const *ep;

	for (ep = details->env_add; *ep != NULL; ep++)
	    evlen += strlen(*ep) + 1;
	if (evlen != 0) {
	    if ((evstr = malloc(evlen)) == NULL)
		goto oom;
	    ep = details->env_add;
	    if (strlcpy(evstr, *ep, evlen) >= evlen)
		goto toobig;
	    while (*++ep != NULL) {
		if (strlcat(evstr, " ", evlen) >= evlen ||
		    strlcat(evstr, *ep, evlen) >= evlen)
		    goto toobig;
	    }
	    len += sizeof(LL_ENV_STR) + 2 + evlen;
	}
    }
    if (details->command != NULL) {
	len += sizeof(LL_CMND_STR) - 1 + strlen(details->command);
	if (details->argc > 1) {
	    for (i = 1; i < details->argc; i++)
		len += strlen(details->argv[i]) + 1;
	}
    }

    /*
     * Allocate and build up the line.
     */
    if ((line = malloc(++len)) == NULL)
	goto oom;
    line[0] = '\0';

    if (message != NULL) {
	if (strlcat(line, message, len) >= len ||
	    strlcat(line, errstr ? " : " : " ; ", len) >= len)
	    goto toobig;
    }
    if (errstr != NULL) {
	if (strlcat(line, errstr, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (strlcat(line, LL_HOST_STR, len) >= len ||
	strlcat(line, details->submithost, len) >= len ||
	strlcat(line, " ; ", len) >= len)
	goto toobig;
    if (strlcat(line, LL_TTY_STR, len) >= len ||
	strlcat(line, details->ttyname, len) >= len ||
	strlcat(line, " ; ", len) >= len)
	goto toobig;
    if (strlcat(line, LL_CWD_STR, len) >= len ||
	strlcat(line, details->cwd, len) >= len ||
	strlcat(line, " ; ", len) >= len)
	goto toobig;
    if (details->runuser != NULL) {
	if (strlcat(line, LL_USER_STR, len) >= len ||
	    strlcat(line, details->runuser, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (details->rungroup != NULL) {
	if (strlcat(line, LL_GROUP_STR, len) >= len ||
	    strlcat(line, details->rungroup, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (tsid != NULL) {
	if (strlcat(line, LL_TSID_STR, len) >= len ||
	    strlcat(line, tsid, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (evstr != NULL) {
	if (strlcat(line, LL_ENV_STR, len) >= len ||
	    strlcat(line, evstr, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
	free(evstr);
	evstr = NULL;
    }
    if (details->command != NULL) {
	if (strlcat(line, LL_CMND_STR, len) >= len)
	    goto toobig;
	if (strlcat(line, details->command, len) >= len)
	    goto toobig;
	if (details->argc > 1) {
	    for (i = 1; i < details->argc; i++) {
		if (strlcat(line, " ", len) >= len ||
		    strlcat(line, details->argv[i], len) >= len)
		    goto toobig;
	    }
	}
    }

    debug_return_str(line);
oom:
    free(evstr);
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    debug_return_str(NULL);
toobig:
    free(evstr);
    free(line);
    sudo_warnx(U_("internal error, %s overflow"), __func__);
    debug_return_str(NULL);
}

/*
 * We do an openlog(3)/closelog(3) for each message because some
 * authentication methods (notably PAM) use syslog(3) for their
 * own nefarious purposes and may call openlog(3) and closelog(3).
 * XXX - no longer need openlog/closelog dance, move openlog call
 */
static void
mysyslog(int pri, const char *fmt, ...)
{
    va_list ap;
    debug_decl(mysyslog, SUDO_DEBUG_UTIL);

    openlog("sudo", 0, logsrvd_conf_syslog_facility());
    va_start(ap, fmt);
    vsyslog(pri, fmt, ap);
    va_end(ap);
    closelog();
    debug_return;
}

/*
 * Log a message to syslog, pre-pending the username and splitting the
 * message into parts if it is longer than syslog_maxlen.
 */
static void
do_syslog(int pri, const struct iolog_details *details, char *msg)
{
    size_t len, maxlen;
    char *p, *tmp, save;
    const char *fmt;
    debug_decl(do_syslog, SUDO_DEBUG_UTIL);

    /* A priority of -1 corresponds to "none". */
    if (pri == -1)
	debug_return;

    /*
     * Log the full line, breaking into multiple syslog(3) calls if necessary
     */
    fmt = _("%8s : %s");
    maxlen = logsrvd_conf_syslog_maxlen() -
	(strlen(fmt) - 5 + strlen(details->submituser));
    for (p = msg; *p != '\0'; ) {
	len = strlen(p);
	if (len > maxlen) {
	    /*
	     * Break up the line into what will fit on one syslog(3) line
	     * Try to avoid breaking words into several lines if possible.
	     */
	    tmp = memrchr(p, ' ', maxlen);
	    if (tmp == NULL)
		tmp = p + maxlen;

	    /* NULL terminate line, but save the char to restore later */
	    save = *tmp;
	    *tmp = '\0';

	    mysyslog(pri, fmt, details->submituser, p);

	    *tmp = save;			/* restore saved character */

	    /* Advance p and eliminate leading whitespace */
	    for (p = tmp; *p == ' '; p++)
		continue;
	} else {
	    mysyslog(pri, fmt, details->submituser, p);
	    p += len;
	}
	fmt = _("%8s : (command continued) %s");
	maxlen = logsrvd_conf_syslog_maxlen() -
	    (strlen(fmt) - 5 + strlen(details->submituser));
    }

    debug_return;
}

static bool
do_logfile(const char *logfile, const struct iolog_details *details,
    const char *msg)
{
    const char *timefmt = logsrvd_conf_logfile_time_format();
    char timebuf[8192], *timestr = NULL;
    struct tm *timeptr;
    bool ret = false;
    mode_t oldmask;
    FILE *fp;
    debug_decl(do_logfile, SUDO_DEBUG_UTIL);

    oldmask = umask(S_IRWXG|S_IRWXO);
    fp = fopen(logfile, "a");
    (void) umask(oldmask);
    if (fp == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to open log file %s", logfile);
	goto done;
    }
    if (!sudo_lock_file(fileno(fp), SUDO_LOCK)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to lock log file %s", logfile);
	goto done;
    }

    if ((timeptr = localtime(&details->submit_time)) != NULL) {
	/* strftime() does not guarantee to NUL-terminate so we must check. */
	timebuf[sizeof(timebuf) - 1] = '\0';
	if (strftime(timebuf, sizeof(timebuf), timefmt, timeptr) != 0 &&
		timebuf[sizeof(timebuf) - 1] == '\0') {
	    timestr = timebuf;
	}
    }
    (void)fprintf(fp, "%s : %s : %s", timestr ? timestr : "invalid date",
	details->submituser, msg);
    (void)fflush(fp);
    if (ferror(fp)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to write log file %s", logfile);
	goto done;
    }
    ret = true;

done:
    if (fp != NULL)
	(void) fclose(fp);
    debug_return_bool(ret);
}

bool
log_accept(const struct iolog_details *details)
{
    const enum logsrvd_eventlog_type log_type = logsrvd_conf_eventlog_type();
    char *logline;
    bool ret = true;
    int pri;
    debug_decl(log_accept, SUDO_DEBUG_UTIL);

    if (log_type == EVLOG_NONE)
	debug_return_bool(true);

    if ((logline = new_logline(NULL, NULL, details)) == NULL)
	debug_return_bool(false);

    switch (log_type) {
    case EVLOG_SYSLOG:
	pri = logsrvd_conf_syslog_acceptpri();
	if (pri != -1)
	    do_syslog(pri, details, logline);
	break;
    case EVLOG_FILE:
	ret = do_logfile(logsrvd_conf_logfile_path(), details, logline);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected eventlog type %d", log_type);
	ret = false;
    }
    free(logline);

    debug_return_bool(ret);
}

bool
log_reject(const struct iolog_details *details, const char *reason)
{
    const enum logsrvd_eventlog_type log_type = logsrvd_conf_eventlog_type();
    char *logline;
    bool ret = true;
    int pri;
    debug_decl(log_reject, SUDO_DEBUG_UTIL);

    if (log_type == EVLOG_NONE)
	debug_return_bool(true);

    if ((logline = new_logline(reason, NULL, details)) == NULL)
	debug_return_bool(false);

    switch (log_type) {
    case EVLOG_SYSLOG:
	pri = logsrvd_conf_syslog_rejectpri();
	if (pri != -1)
	    do_syslog(pri, details, logline);
	break;
    case EVLOG_FILE:
	ret = do_logfile(logsrvd_conf_logfile_path(), details, logline);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected eventlog type %d", log_type);
	ret = false;
    }
    free(logline);

    debug_return_bool(ret);
}

bool
log_alert(const struct iolog_details *details, TimeSpec *alert_time,
    const char *reason)
{
    const enum logsrvd_eventlog_type log_type = logsrvd_conf_eventlog_type();
    char *logline;
    bool ret = true;
    int pri;
    debug_decl(log_alert, SUDO_DEBUG_UTIL);

    if (log_type == EVLOG_NONE)
	debug_return_bool(true);

    if ((logline = new_logline(reason, NULL, details)) == NULL)
	debug_return_bool(false);

    /* TODO: log alert_time */
    switch (log_type) {
    case EVLOG_SYSLOG:
	pri = logsrvd_conf_syslog_alertpri();
	if (pri != -1)
	    do_syslog(pri, details, logline);
	break;
    case EVLOG_FILE:
	ret = do_logfile(logsrvd_conf_logfile_path(), details, logline);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected eventlog type %d", log_type);
	ret = false;
    }
    free(logline);

    debug_return_bool(ret);
}
