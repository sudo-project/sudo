/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1994-1996, 1998-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_iolog.h"
#include "sudo_json.h"
#include "sudo_queue.h"
#include "sudo_util.h"

#include "log_server.pb-c.h"
#include "logsrvd.h"

#define	LL_HOST_STR	"HOST="
#define	LL_TTY_STR	"TTY="
#define	LL_CHROOT_STR	"CHROOT="
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
    if (details->runchroot != NULL)
	len += sizeof(LL_CHROOT_STR) + 2 + strlen(details->runchroot);
    len += sizeof(LL_CWD_STR) + 2 + strlen(details->runcwd);
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
    if (details->runchroot != NULL) {
	if (strlcat(line, LL_CHROOT_STR, len) >= len ||
	    strlcat(line, details->runchroot, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (strlcat(line, LL_CWD_STR, len) >= len ||
	strlcat(line, details->runcwd, len) >= len ||
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

static bool
json_add_timestamp(struct json_container *json, const char *name,
    struct timespec *ts)
{
    const char *timefmt = logsrvd_conf_logfile_time_format();
    struct json_value json_value;
    time_t secs = ts->tv_sec;
    char timebuf[1024];
    struct tm *tm;
    debug_decl(json_add_timestamp, SUDO_DEBUG_PLUGIN);

    if ((tm = gmtime(&secs)) == NULL)
	debug_return_bool(false);

    if (!sudo_json_open_object(json, name))
	goto oom;

    json_value.type = JSON_NUMBER;
    json_value.u.number = ts->tv_sec;
    if (!sudo_json_add_value(json, "seconds", &json_value))
	goto oom;

    json_value.type = JSON_NUMBER;
    json_value.u.number = ts->tv_nsec;
    if (!sudo_json_add_value(json, "nanoseconds", &json_value))
	goto oom;

    strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", tm);
    json_value.type = JSON_STRING;
    json_value.u.string = timebuf;
    if (!sudo_json_add_value(json, "iso8601", &json_value))
	goto oom;

    strftime(timebuf, sizeof(timebuf), timefmt, tm);
    json_value.type = JSON_STRING;
    json_value.u.string = timebuf;
    if (!sudo_json_add_value(json, "localtime", &json_value))
	goto oom;

    if (!sudo_json_close_object(json))
	goto oom;

    debug_return_bool(true);
oom:
    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	"%s: %s", __func__, "unable to allocate memory");
    debug_return_bool(false);
}

static char *
format_json(ClientMessage__TypeCase event_type, const char *reason,
    const struct iolog_details *details, TimeSpec *event_time,
    InfoMessage **info_msgs, size_t infolen, bool compact)
{
    const char *type_str;
    const char *time_str;
    struct json_container json = { 0 };
    struct json_value json_value;
    struct timespec ts;
    size_t idx;
    debug_decl(format_json, SUDO_DEBUG_UTIL);

    if (sudo_gettime_real(&ts) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to read the clock");
	debug_return_str(NULL);
    }

    switch (event_type) {
    case CLIENT_MESSAGE__TYPE_ACCEPT_MSG:
	type_str = "accept";
	time_str = "submit_time";
	break;
    case CLIENT_MESSAGE__TYPE_REJECT_MSG:
	type_str = "reject";
	time_str = "submit_time";
	break;
    case CLIENT_MESSAGE__TYPE_ALERT_MSG:
	type_str = "alert";
	time_str = "alert_time";
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected event type %d", event_type);
	debug_return_str(NULL);
    }

    if (!sudo_json_init(&json, 4, compact, false))
	goto bad;
    if (!sudo_json_open_object(&json, type_str))
	goto bad;

    /* Reject and Alert events include a reason */
    if (reason != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = reason;
	if (!sudo_json_add_value(&json, "reason", &json_value))
	    goto bad;
    }

    /* XXX - create and log uuid? */

    /* Log event time on server (set earlier) */
    if (!json_add_timestamp(&json, "server_time", &ts)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "unable format timestamp");
	goto bad;
    }

    /* Log event time from client */
    ts.tv_sec = event_time->tv_sec;
    ts.tv_nsec = event_time->tv_nsec;
    if (!json_add_timestamp(&json, time_str, &ts)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "unable format timestamp");
	goto bad;
    }

    if (details->iolog_path != NULL) {
	json_value.type = JSON_STRING;
	json_value.u.string = details->iolog_path;
	if (!sudo_json_add_value(&json, "iolog_path", &json_value))
	    goto bad;
    }

    /* Dump details */
    for (idx = 0; idx < infolen; idx++) {
	InfoMessage *info = info_msgs[idx];

	switch (info->value_case) {
	case INFO_MESSAGE__VALUE_NUMVAL:
	    json_value.type = JSON_NUMBER;
	    json_value.u.number = info->u.numval;
	    if (!sudo_json_add_value(&json, info->key, &json_value))
		goto bad;
	    break;
	case INFO_MESSAGE__VALUE_STRVAL:
	    json_value.type = JSON_STRING;
	    json_value.u.string = info->u.strval;
	    if (!sudo_json_add_value(&json, info->key, &json_value))
		goto bad;
	    break;
	case INFO_MESSAGE__VALUE_STRLISTVAL: {
	    InfoMessage__StringList *strlist = info->u.strlistval;
	    size_t n;

	    if (!sudo_json_open_array(&json, info->key))
		goto bad;
	    for (n = 0; n < strlist->n_strings; n++) {
		json_value.type = JSON_STRING;
		json_value.u.string = strlist->strings[n];
		if (!sudo_json_add_value(&json, NULL, &json_value))
		    goto bad;
	    }
	    if (!sudo_json_close_array(&json))
		goto bad;
	    break;
	}
	default:
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unexpected value case %d", info->value_case);
	    goto bad;
	}
    }

    if (!sudo_json_close_object(&json))
	goto bad;

    /* Caller is responsible for freeing the buffer. */
    debug_return_str(sudo_json_get_buf(&json));

bad:
    sudo_json_free(&json);
    debug_return_str(NULL);
}

/*
 * Log a message to syslog, pre-pending the username and splitting the
 * message into parts if it is longer than syslog_maxlen.
 */
static bool
do_syslog_sudo(int pri, const char *reason, const struct iolog_details *details)
{
    size_t len, maxlen;
    char *logline, *p, *tmp, save;
    const char *fmt;
    debug_decl(do_syslog_sudo, SUDO_DEBUG_UTIL);

    /* A priority of -1 corresponds to "none". */
    if (pri == -1)
	debug_return_bool(true);

    if ((logline = new_logline(reason, NULL, details)) == NULL)
	debug_return_bool(false);

    /*
     * Log the full line, breaking into multiple syslog(3) calls if necessary
     */
    fmt = _("%8s : %s");
    maxlen = logsrvd_conf_syslog_maxlen() -
	(strlen(fmt) - 5 + strlen(details->submituser));
    for (p = logline; *p != '\0'; ) {
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

	    syslog(pri, fmt, details->submituser, p);

	    *tmp = save;			/* restore saved character */

	    /* Advance p and eliminate leading whitespace */
	    for (p = tmp; *p == ' '; p++)
		continue;
	} else {
	    syslog(pri, fmt, details->submituser, p);
	    p += len;
	}
	fmt = _("%8s : (command continued) %s");
	maxlen = logsrvd_conf_syslog_maxlen() -
	    (strlen(fmt) - 5 + strlen(details->submituser));
    }
    free(logline);

    debug_return_bool(true);
}

static bool
do_syslog_json(int pri, ClientMessage__TypeCase event_type, const char *reason,
    const struct iolog_details *details, TimeSpec *event_time,
    InfoMessage **info_msgs, size_t infolen)
{
    char *json_str;
    debug_decl(do_syslog_json, SUDO_DEBUG_UTIL);

    /* A priority of -1 corresponds to "none". */
    if (pri == -1)
	debug_return_bool(true);

    /* Format as a compact JSON message (no newlines) */
    json_str = format_json(event_type, reason, details, event_time,
	info_msgs, infolen, true);
    if (json_str == NULL)
	debug_return_bool(false);

    /* Syslog it with a @cee: prefix */
    /* TODO: use logsrvd_conf_syslog_maxlen() to break up long messages. */
    syslog(pri, "@cee:{%s }", json_str);
    free(json_str);
    debug_return_bool(true);
}

/*
 * Log a message to syslog in either sudo or JSON format.
 */
static bool
do_syslog(ClientMessage__TypeCase event_type, const char *reason,
    const struct iolog_details *details, TimeSpec *event_time,
    InfoMessage **info_msgs, size_t infolen)
{
    int pri;
    bool ret = false;
    debug_decl(do_syslog, SUDO_DEBUG_UTIL);

    switch (event_type) {
    case CLIENT_MESSAGE__TYPE_ACCEPT_MSG:
	pri = logsrvd_conf_syslog_acceptpri();
	break;
    case CLIENT_MESSAGE__TYPE_REJECT_MSG:
	pri = logsrvd_conf_syslog_rejectpri();
	break;
    case CLIENT_MESSAGE__TYPE_ALERT_MSG:
	pri = logsrvd_conf_syslog_alertpri();
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected event type %d", event_type);
	pri = -1;
	break;
    }
    if (pri == -1) {
	/* syslog disabled for this message type */
	debug_return_bool(true);
    }

    switch (logsrvd_conf_eventlog_format()) {
    case EVLOG_SUDO:
	ret = do_syslog_sudo(pri, reason, details);
	break;
    case EVLOG_JSON:
	ret = do_syslog_json(pri, event_type, reason, details, event_time,
	    info_msgs, infolen);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected eventlog format %d", logsrvd_conf_eventlog_format());
	break;
    }

    debug_return_bool(ret);
}

static bool
do_logfile_sudo(const char *reason, const struct iolog_details *details)
{
    const char *timefmt = logsrvd_conf_logfile_time_format();
    const char *logfile = logsrvd_conf_logfile_path();
    FILE *fp = logsrvd_conf_logfile_stream();
    char *logline, timebuf[8192], *timestr = NULL;
    struct tm *timeptr;
    bool ret = false;

    debug_decl(do_logfile_sudo, SUDO_DEBUG_UTIL);

    if ((logline = new_logline(reason, NULL, details)) == NULL)
	debug_return_bool(false);

    if (!sudo_lock_file(fileno(fp), SUDO_LOCK)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to lock log file %s", logfile);
	goto done;
    }

    if ((timeptr = localtime(&details->submit_time.tv_sec)) != NULL) {
	/* strftime() does not guarantee to NUL-terminate so we must check. */
	timebuf[sizeof(timebuf) - 1] = '\0';
	if (strftime(timebuf, sizeof(timebuf), timefmt, timeptr) != 0 &&
		timebuf[sizeof(timebuf) - 1] == '\0') {
	    timestr = timebuf;
	}
    }
    (void)fprintf(fp, "%s : %s : %s\n", timestr ? timestr : "invalid date",
	details->submituser, logline);
    (void)fflush(fp);
    if (ferror(fp)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to write log file %s", logfile);
	goto done;
    }
    ret = true;

done:
    free(logline);
    (void)sudo_lock_file(fileno(fp), SUDO_UNLOCK);
    debug_return_bool(ret);
}

static bool
do_logfile_json(ClientMessage__TypeCase event_type, const char *reason,
    const struct iolog_details *details, TimeSpec *event_time,
    InfoMessage **info_msgs, size_t infolen)
{
    const char *logfile = logsrvd_conf_logfile_path();
    FILE *fp = logsrvd_conf_logfile_stream();
    struct stat sb;
    char *json_str;
    int ret = false;
    debug_decl(do_logfile_json, SUDO_DEBUG_UTIL);

    json_str = format_json(event_type, reason, details, event_time,
	info_msgs, infolen, false);
    if (json_str == NULL)
	goto done;

    if (!sudo_lock_file(fileno(fp), SUDO_LOCK)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to lock log file %s", logfile);
	goto done;
    }

    /* Note: assumes file ends in "\n}\n" */
    if (fstat(fileno(fp), &sb) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "unable to stat %s", logfile);
	goto done;
    }
    if (sb.st_size == 0) {
	/* New file */
	putc('{', fp);
    } else if (fseeko(fp, -3, SEEK_END) == 0) {
	/* Continue file, overwrite the final "\n}\n" */
	putc(',', fp);
    } else {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "unable to seek %s", logfile);
	goto done;
    }
    fputs(json_str, fp);
    fputs("\n}\n", fp);			/* close JSON */
    fflush(fp);
    /* XXX - check for file error and recover */

    ret = true;

done:
    free(json_str);
    (void)sudo_lock_file(fileno(fp), SUDO_UNLOCK);
    debug_return_bool(ret);
}

static bool
do_logfile(ClientMessage__TypeCase event_type, const char *reason,
    const struct iolog_details *details, TimeSpec *event_time,
    InfoMessage **info_msgs, size_t infolen)
{
    bool ret = false;
    debug_decl(do_logfile, SUDO_DEBUG_UTIL);

    switch (logsrvd_conf_eventlog_format()) {
    case EVLOG_SUDO:
	ret = do_logfile_sudo(reason, details);
	break;
    case EVLOG_JSON:
	ret = do_logfile_json(event_type, reason, details, event_time,
	    info_msgs, infolen);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected eventlog format %d", logsrvd_conf_eventlog_format());
	break;
    }

    debug_return_bool(ret);
}

bool
log_accept(const struct iolog_details *details, TimeSpec *submit_time,
    InfoMessage **info_msgs, size_t infolen)
{
    const enum logsrvd_eventlog_type log_type = logsrvd_conf_eventlog_type();
    bool ret;
    debug_decl(log_accept, SUDO_DEBUG_UTIL);

    if (log_type == EVLOG_NONE)
	debug_return_bool(true);

    switch (log_type) {
    case EVLOG_SYSLOG:
	ret = do_syslog(CLIENT_MESSAGE__TYPE_ACCEPT_MSG, NULL, details,
	    submit_time, info_msgs, infolen);
	break;
    case EVLOG_FILE:
	ret = do_logfile(CLIENT_MESSAGE__TYPE_ACCEPT_MSG, NULL, details,
	    submit_time, info_msgs, infolen);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected eventlog type %d", log_type);
	ret = false;
    }

    debug_return_bool(ret);
}

bool
log_reject(const struct iolog_details *details, const char *reason,
    TimeSpec *submit_time, InfoMessage **info_msgs, size_t infolen)
{
    const enum logsrvd_eventlog_type log_type = logsrvd_conf_eventlog_type();
    bool ret;
    debug_decl(log_reject, SUDO_DEBUG_UTIL);

    if (log_type == EVLOG_NONE)
	debug_return_bool(true);

    switch (log_type) {
    case EVLOG_SYSLOG:
	ret = do_syslog(CLIENT_MESSAGE__TYPE_REJECT_MSG, NULL, details,
	    submit_time, info_msgs, infolen);
	break;
    case EVLOG_FILE:
	ret = do_logfile(CLIENT_MESSAGE__TYPE_REJECT_MSG, reason, details,
	    submit_time, info_msgs, infolen);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected eventlog type %d", log_type);
	ret = false;
    }

    debug_return_bool(ret);
}

bool
log_alert(const struct iolog_details *details, TimeSpec *alert_time,
    const char *reason)
{
    const enum logsrvd_eventlog_type log_type = logsrvd_conf_eventlog_type();
    bool ret;
    debug_decl(log_alert, SUDO_DEBUG_UTIL);

    if (log_type == EVLOG_NONE)
	debug_return_bool(true);

    /* TODO: log alert_time */
    switch (log_type) {
    case EVLOG_SYSLOG:
	ret = do_syslog(CLIENT_MESSAGE__TYPE_REJECT_MSG, NULL, details,
	    alert_time, NULL, 0);
	break;
    case EVLOG_FILE:
	ret = do_logfile(CLIENT_MESSAGE__TYPE_ALERT_MSG, reason, details,
	    alert_time, NULL, 0);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected eventlog type %d", log_type);
	ret = false;
    }

    debug_return_bool(ret);
}
