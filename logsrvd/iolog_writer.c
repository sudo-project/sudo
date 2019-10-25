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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "log_server.pb-c.h"
#include "sudo_compat.h"
#include "sudo_queue.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "sudo_iolog.h"
#include "logsrvd.h"

static inline bool
has_numval(InfoMessage *info)
{
    return info->value_case == INFO_MESSAGE__VALUE_NUMVAL;
}

static inline bool
has_strval(InfoMessage *info)
{
    return info->value_case == INFO_MESSAGE__VALUE_STRVAL;
}

static inline bool
has_strlistval(InfoMessage *info)
{
    return info->value_case == INFO_MESSAGE__VALUE_STRLISTVAL;
}

/*
 * Copy the specified string list.
 * The input string list need not be NULL-terminated.
 * Returns a NULL-terminated string vector.
 */
static char **
strlist_copy(InfoMessage__StringList *strlist)
{
    char **dst, **src = strlist->strings;
    size_t i, len = strlist->n_strings;
    debug_decl(strlist_copy, SUDO_DEBUG_UTIL)

    dst = reallocarray(NULL, len + 1, sizeof(char *));
    if (dst == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "reallocarray(NULL, %zu, %zu)", len + 1, sizeof(char *));
	goto bad;
    }
    for (i = 0; i < len; i++) {
	if ((dst[i] = strdup(src[i])) == NULL) {
	    sudo_debug_printf(
		SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO, "strdup");
	    goto bad;
	}
    }
    dst[i] = NULL;
    debug_return_ptr(dst);

bad:
    if (dst != NULL) {
	while (i--)
	    free(dst[i]);
	free(dst);
    }
    debug_return_ptr(NULL);
}

/*
 * Free the strings in a struct iolog_details.
 */
void
iolog_details_free(struct iolog_details *details)
{
    int i;
    debug_decl(iolog_details_free, SUDO_DEBUG_UTIL)

    if (details != NULL) {
	free(details->iolog_path);
	free(details->command);
	free(details->cwd);
	free(details->rungroup);
	free(details->runuser);
	free(details->submithost);
	free(details->submituser);
	free(details->submitgroup);
	free(details->ttyname);
	for (i = 0; i < details->argc; i++)
	    free(details->argv[i]);
	free(details->argv);
    }

    debug_return;
}

/*
 * Fill in I/O log details from an AcceptMessage
 * Caller is responsible for freeing strings in struct iolog_details.
 * Returns true on success and false on failure.
 */
bool
iolog_details_fill(struct iolog_details *details, TimeSpec *submit_time,
    InfoMessage **info_msgs, size_t infolen)
{
    size_t idx;
    bool ret = false;
    debug_decl(iolog_details_fill, SUDO_DEBUG_UTIL)

    memset(details, 0, sizeof(*details));

    /* Submit time. */
    details->submit_time = submit_time->tv_sec;

    /* Default values */
    details->lines = 24;
    details->columns = 80;

    /* Pull out values by key from info array. */
    for (idx = 0; idx < infolen; idx++) {
	InfoMessage *info = info_msgs[idx];
	const char *key = info->key;
	switch (key[0]) {
	case 'c':
	    if (strcmp(key, "columns") == 0) {
		if (!has_numval(info)) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"columns specified but not a number");
		} else if (info->numval <= 0 || info->numval > INT_MAX) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"columns (%" PRId64 ") out of range", info->numval);
		} else {
		    details->columns = info->numval;
		}
		continue;
	    }
	    if (strcmp(key, "command") == 0) {
		if (has_strval(info)) {
		    if ((details->command = strdup(info->strval)) == NULL) {
			sudo_debug_printf(
			    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
			    "strdup");
			goto done;
		    }
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"command specified but not a string");
		}
		continue;
	    }
	    if (strcmp(key, "cwd") == 0) {
		if (has_strval(info)) {
		    if ((details->cwd = strdup(info->strval)) == NULL) {
			sudo_debug_printf(
			    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
			    "strdup");
			goto done;
		    }
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"cwd specified but not a string");
		}
		continue;
	    }
	    break;
	case 'l':
	    if (strcmp(key, "lines") == 0) {
		if (!has_numval(info)) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"lines specified but not a number");
		} else if (info->numval <= 0 || info->numval > INT_MAX) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"lines (%" PRId64 ") out of range", info->numval);
		} else {
		    details->lines = info->numval;
		}
		continue;
	    }
	    break;
	case 'r':
	    if (strcmp(key, "runargv") == 0) {
		if (has_strlistval(info)) {
		    details->argv = strlist_copy(info->strlistval);
		    if (details->argv == NULL)
			goto done;
		    details->argc = info->strlistval->n_strings;
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"runargv specified but not a string list");
		}
		continue;
	    }
	    if (strcmp(key, "rungroup") == 0) {
		if (has_strval(info)) {
		    if ((details->rungroup = strdup(info->strval)) == NULL) {
			sudo_debug_printf(
			    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
			    "strdup");
			goto done;
		    }
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"rungroup specified but not a string");
		}
		continue;
	    }
	    if (strcmp(key, "runuser") == 0) {
		if (has_strval(info)) {
		    if ((details->runuser = strdup(info->strval)) == NULL) {
			sudo_debug_printf(
			    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
			    "strdup");
			goto done;
		    }
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"runuser specified but not a string");
		}
		continue;
	    }
	    break;
	case 's':
	    if (strcmp(key, "submithost") == 0) {
		if (has_strval(info)) {
		    if ((details->submithost = strdup(info->strval)) == NULL) {
			sudo_debug_printf(
			    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
			    "strdup");
			goto done;
		    }
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"submithost specified but not a string");
		}
		continue;
	    }
	    if (strcmp(key, "submitgroup") == 0) {
		if (has_strval(info)) {
		    if ((details->submitgroup = strdup(info->strval)) == NULL) {
			sudo_debug_printf(
			    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
			    "strdup");
			goto done;
		    }
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"submitgroup specified but not a string");
		}
		continue;
	    }
	    if (strcmp(key, "submituser") == 0) {
		if (has_strval(info)) {
		    if ((details->submituser = strdup(info->strval)) == NULL) {
			sudo_debug_printf(
			    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
			    "strdup");
			goto done;
		    }
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"submituser specified but not a string");
		}
		continue;
	    }
	    break;
	case 't':
	    if (strcmp(key, "ttyname") == 0) {
		if (has_strval(info)) {
		    if ((details->ttyname = strdup(info->strval)) == NULL) {
			sudo_debug_printf(
			    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
			    "strdup");
			goto done;
		    }
		} else {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"ttyname specified but not a string");
		}
		continue;
	    }
	    break;
	}
    }

    /* TODO: make submitgroup required */
    if (details->submitgroup == NULL) {
	if ((details->submitgroup = strdup("unknown")) == NULL) {
	    sudo_debug_printf(
		SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"strdup");
	    goto done;
	}
    }

    /* Check for required settings */
    if (details->submituser == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "missing user in AcceptMessage");
	goto done;
    }
    if (details->submithost == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "missing host in AcceptMessage");
	goto done;
    }
    if (details->command == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "missing command in AcceptMessage");
	goto done;
    }

    ret = true;

done:
    if (!ret)
	iolog_details_free(details);
    debug_return_bool(ret);
}

static size_t
fill_seq(char *str, size_t strsize, char *logdir, void *closure)
{
    struct iolog_details *details = closure;
    char *sessid = details->sessid;
    int len;
    debug_decl(fill_seq, SUDO_DEBUG_UTIL)

    if (sessid[0] == '\0') {
	if (!iolog_nextid(logdir, sessid))
	    debug_return_size_t((size_t)-1);
    }

    /* Path is of the form /var/log/sudo-io/00/00/01. */
    len = snprintf(str, strsize, "%c%c/%c%c/%c%c", sessid[0],
	sessid[1], sessid[2], sessid[3], sessid[4], sessid[5]);
    if (len < 0 || len >= (ssize_t)strsize) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to format session id");
	debug_return_size_t(strsize); /* handle non-standard snprintf() */
    }
    debug_return_size_t(len);
}

static size_t
fill_user(char *str, size_t strsize, char *unused, void *closure)
{
    const struct iolog_details *details = closure;
    debug_decl(fill_user, SUDO_DEBUG_UTIL)

    if (details->submituser == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "submituser not set");
	debug_return_size_t(strsize);
    }
    debug_return_size_t(strlcpy(str, details->submituser, strsize));
}

static size_t
fill_group(char *str, size_t strsize, char *unused, void *closure)
{
    const struct iolog_details *details = closure;
    debug_decl(fill_group, SUDO_DEBUG_UTIL)

    if (details->submitgroup == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "submitgroup not set");
	debug_return_size_t(strsize);
    }
    debug_return_size_t(strlcpy(str, details->submitgroup, strsize));
}

static size_t
fill_runas_user(char *str, size_t strsize, char *unused, void *closure)
{
    const struct iolog_details *details = closure;
    debug_decl(fill_runas_user, SUDO_DEBUG_UTIL)

    if (details->runuser == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "runuser not set");
	debug_return_size_t(strsize);
    }
    debug_return_size_t(strlcpy(str, details->runuser, strsize));
}

static size_t
fill_runas_group(char *str, size_t strsize, char *unused, void *closure)
{
    const struct iolog_details *details = closure;
    debug_decl(fill_runas_group, SUDO_DEBUG_UTIL)

    /* FIXME: rungroup not guaranteed to be set */
    if (details->rungroup == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "rungroup not set");
	debug_return_size_t(strsize);
    }
    debug_return_size_t(strlcpy(str, details->rungroup, strsize));
}

static size_t
fill_hostname(char *str, size_t strsize, char *unused, void *closure)
{
    const struct iolog_details *details = closure;
    debug_decl(fill_hostname, SUDO_DEBUG_UTIL)

    if (details->submithost == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "submithost not set");
	debug_return_size_t(strsize);
    }
    debug_return_size_t(strlcpy(str, details->submithost, strsize));
}

static size_t
fill_command(char *str, size_t strsize, char *unused, void *closure)
{
    const struct iolog_details *details = closure;
    debug_decl(fill_command, SUDO_DEBUG_UTIL)

    if (details->command == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "command not set");
	debug_return_size_t(strsize);
    }
    debug_return_size_t(strlcpy(str, details->command, strsize));
}

/* Note: "seq" must be first in the list. */
static const struct iolog_path_escape path_escapes[] = {
    { "seq", fill_seq },
    { "user", fill_user },
    { "group", fill_group },
    { "runas_user", fill_runas_user },
    { "runas_group", fill_runas_group },
    { "hostname", fill_hostname },
    { "command", fill_command },
    { NULL, NULL }
};


/*
 * Create I/O log path
 * Sets iolog_path, iolog_file and iolog_dir_fd in the closure
 */
static bool
create_iolog_path(struct connection_closure *closure)
{
    struct iolog_details *details = &closure->details;
    char pathbuf[PATH_MAX];
    size_t len, pathlen;
    debug_decl(create_iolog_path, SUDO_DEBUG_UTIL)

    details->iolog_path = expand_iolog_path(NULL, logsrvd_conf_iolog_dir(),
	logsrvd_conf_iolog_file(), &details->iolog_file, &path_escapes[0],
	details);
    if (details->iolog_path == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to expand iolog path %s/%s",
	    logsrvd_conf_iolog_dir(), logsrvd_conf_iolog_file());
	goto bad;
    }
    pathlen = details->iolog_file - details->iolog_path;

    /*
     * Make local copy of I/O log path and create it, along with any
     * intermediate subdirs.  Calls mkdtemp() if iolog_path ends in XXXXXX.
     */
    len = mkdir_iopath(details->iolog_path, pathbuf, sizeof(pathbuf));
    if (len >= sizeof(pathbuf)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to mkdir iolog path %s", details->iolog_path);
        goto bad;
    }
    free(details->iolog_path);
    if ((details->iolog_path = strdup(pathbuf)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "strdup");
	goto bad;
    }
    details->iolog_file = details->iolog_path + pathlen + 1;

    /* We use iolog_dir_fd in calls to openat(2) */
    closure->iolog_dir_fd =
	iolog_openat(AT_FDCWD, details->iolog_path, O_RDONLY);
    if (closure->iolog_dir_fd == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "%s", details->iolog_path);
	goto bad;
    }

    debug_return_bool(true);
bad:
    free(details->iolog_path);
    details->iolog_path = NULL;
    debug_return_bool(false);
}

/*
 * Write the sudo-style I/O log info file containing user and command info.
 */
static bool
iolog_details_write(struct iolog_details *details,
     struct connection_closure *closure)
{
    struct iolog_info log_info;
    debug_decl(iolog_details_write, SUDO_DEBUG_UTIL)

    /* Convert to iolog_info */
    memset(&log_info, 0, sizeof(log_info));
    log_info.user = details->submituser;
    log_info.runas_user = details->runuser;
    log_info.runas_group = details->rungroup;
    log_info.tty = details->ttyname;
    log_info.cwd = details->cwd;
    log_info.cmd = details->command;
    log_info.lines = details->lines;
    log_info.cols = details->columns;

    debug_return_bool(iolog_write_info_file(closure->iolog_dir_fd,
	 details->iolog_path, &log_info, details->argv));
}

static bool
iolog_create(int iofd, struct connection_closure *closure)
{
    debug_decl(iolog_create, SUDO_DEBUG_UTIL)

    if (iofd < 0 || iofd >= IOFD_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid iofd %d", iofd);
	debug_return_bool(false);
    }

    closure->iolog_files[iofd].enabled = true;
    debug_return_bool(iolog_open(&closure->iolog_files[iofd],
	closure->iolog_dir_fd, iofd, "w"));
}

void
iolog_close_all(struct connection_closure *closure)
{
    const char *errstr;
    int i;
    debug_decl(iolog_close, SUDO_DEBUG_UTIL)

    for (i = 0; i < IOFD_MAX; i++) {
	if (!closure->iolog_files[i].enabled)
	    continue;
	if (!iolog_close(&closure->iolog_files[i], &errstr)) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"error closing iofd %d: %s", i, errstr);
	}
    }
    if (closure->iolog_dir_fd != -1)
	close(closure->iolog_dir_fd);

    debug_return;
}

bool
iolog_init(AcceptMessage *msg, struct connection_closure *closure)
{
    debug_decl(iolog_init, SUDO_DEBUG_UTIL)

    /* Create I/O log path */
    if (!create_iolog_path(closure))
	debug_return_bool(false);

    /* Write sudo I/O log info file */
    if (!iolog_details_write(&closure->details, closure))
	debug_return_bool(false);

    /*
     * Create timing, stdout, stderr and ttyout files for sudoreplay.
     * Others will be created on demand.
     */
    if (!iolog_create(IOFD_TIMING, closure) ||
	!iolog_create(IOFD_STDOUT, closure) ||
	!iolog_create(IOFD_STDERR, closure) ||
	!iolog_create(IOFD_TTYOUT, closure))
	debug_return_bool(false);

    /* Ready to log I/O buffers. */
    debug_return_bool(true);
}

/*
 * Read the next record from the timing file.
 * Return 0 on success, 1 on EOF and -1 on error.
 */
static int
read_timing_record(struct iolog_file *iol, struct timing_closure *timing)
{
    char line[LINE_MAX];
    const char *errstr;
    debug_decl(read_timing_record, SUDO_DEBUG_UTIL)

    /* Read next record from timing file. */
    if (iolog_gets(iol, line, sizeof(line), &errstr) == NULL) {
	/* EOF or error reading timing file, we are done. */
	if (iolog_eof(iol))
	    debug_return_int(1);	/* EOF */
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "error reading timing file: %s", errstr);
	debug_return_int(-1);
    }

    /* Parse timing file record. */
    line[strcspn(line, "\n")] = '\0';
    if (!parse_timing(line, timing)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "invalid timing file line: %s", line);
	debug_return_int(-1);
    }

    debug_return_int(0);
}

/* XXX - compressed I/O logs cannot be restarted, must re-write them */
bool
iolog_restart(RestartMessage *msg, struct connection_closure *closure)
{
    struct timespec target;
    struct timing_closure timing;
    off_t pos;
    int iofd;
    debug_decl(iolog_restart, SUDO_DEBUG_UTIL)

    target.tv_sec = msg->resume_point->tv_sec;
    target.tv_nsec = msg->resume_point->tv_nsec;

    if ((closure->details.iolog_path = strdup(msg->log_id)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "strdup");
	goto bad;
    }

    /* Open existing I/O log files. */
    for (iofd = 0; iofd < IOFD_MAX; iofd++) {
	closure->iolog_files[iofd].enabled = true;
	if (!iolog_open(&closure->iolog_files[iofd], closure->iolog_dir_fd,
		iofd, "r+")) {
	    if (errno != ENOENT) {
		sudo_debug_printf(
		    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		    "unable to open %s/%s", closure->details.iolog_path,
		    iolog_fd_to_name(iofd));
		goto bad;
	    }
	}
    }
    if (!closure->iolog_files[IOFD_TIMING].enabled) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "missing timing file in %s", closure->details.iolog_path);
	goto bad;
    }

    /* Parse timing file until we reach the target point. */
    /* XXX - split up */
    for (;;) {
	if (read_timing_record(&closure->iolog_files[IOFD_TIMING], &timing) != 0)
	    goto bad;
	sudo_timespecadd(&timing.delay, &closure->elapsed_time,
	    &closure->elapsed_time);
	if (timing.event < IOFD_TIMING) {
	    if (!closure->iolog_files[timing.event].enabled) {
		/* Missing log file. */
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "iofd %d referenced but not open", timing.event);
		goto bad;
	    }
	    pos = iolog_seek(&closure->iolog_files[timing.event],
		timing.u.nbytes, SEEK_CUR);
	    if (pos == -1) {
		sudo_debug_printf(
		    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		    "seek(%d, %lld, SEEK_CUR", timing.event,
		    (long long)timing.u.nbytes);
		goto bad;
	    }
	}
	if (sudo_timespeccmp(&closure->elapsed_time, &target, >=)) {
	    if (sudo_timespeccmp(&closure->elapsed_time, &target, ==))
		break;

	    /* Mismatch between resume point and stored log. */
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"resume point mismatch, target [%lld, %ld], have [%lld, %ld]",
		(long long)target.tv_sec, target.tv_nsec,
		(long long)closure->elapsed_time.tv_sec,
		closure->elapsed_time.tv_nsec);
	    goto bad;
	}
    }
    /* Must seek or flush before switching from read -> write. */
    if (iolog_seek(&closure->iolog_files[IOFD_TIMING], 0, SEEK_CUR) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "lseek(IOFD_TIMING, 0, SEEK_CUR)");
	goto bad;
    }

    /* Ready to log I/O buffers. */
    debug_return_bool(true);
bad:
    debug_return_bool(false);
}

/*
 * Add given delta to elapsed time.
 * We cannot use timespecadd here since delta is not struct timespec.
 */
static void
update_elapsed_time(TimeSpec *delta, struct timespec *elapsed)
{
    debug_decl(update_elapsed_time, SUDO_DEBUG_UTIL)

    /* Cannot use timespecadd since msg doesn't use struct timespec. */
    elapsed->tv_sec += delta->tv_sec;
    elapsed->tv_nsec += delta->tv_nsec;
    while (elapsed->tv_nsec >= 1000000000) {
	elapsed->tv_sec++;
	elapsed->tv_nsec -= 1000000000;
    }

    debug_return;
}

int
store_iobuf(int iofd, IoBuffer *msg, struct connection_closure *closure)
{
    const char *errstr;
    char tbuf[1024];
    int len;
    debug_decl(store_iobuf, SUDO_DEBUG_UTIL)

    /* Open log file as needed. */
    if (!closure->iolog_files[iofd].enabled) {
	if (!iolog_create(iofd, closure))
	    debug_return_int(-1);
    }

    /* Format timing data. */
    /* FIXME - assumes IOFD_* matches IO_EVENT_* */
    len = snprintf(tbuf, sizeof(tbuf), "%d %lld.%09d %zu\n",
	iofd, (long long)msg->delay->tv_sec, (int)msg->delay->tv_nsec,
	msg->data.len);
    if (len < 0 || len >= ssizeof(tbuf)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to format timing buffer");
	debug_return_int(-1);
    }

    /* Write to specified I/O log file. */
    if (!iolog_write(&closure->iolog_files[iofd], msg->data.data,
	    msg->data.len, &errstr)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to write to %s/%s: %s", closure->details.iolog_path,
	    iolog_fd_to_name(iofd), errstr);
	debug_return_int(-1);
    }

    /* Write timing data. */
    if (!iolog_write(&closure->iolog_files[IOFD_TIMING], tbuf,
	    len, &errstr)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to write to %s/%s: %s", closure->details.iolog_path,
	    iolog_fd_to_name(IOFD_TIMING), errstr);
	debug_return_int(-1);
    }

    update_elapsed_time(msg->delay, &closure->elapsed_time);

    debug_return_int(0);
}

int
store_suspend(CommandSuspend *msg, struct connection_closure *closure)
{
    const char *errstr;
    char tbuf[1024];
    int len;
    debug_decl(store_suspend, SUDO_DEBUG_UTIL)

    /* Format timing data including suspend signal. */
    len = snprintf(tbuf, sizeof(tbuf), "%d %lld.%09d %s\n", IO_EVENT_SUSPEND,
	(long long)msg->delay->tv_sec, (int)msg->delay->tv_nsec,
	msg->signal);
    if (len < 0 || len >= ssizeof(tbuf)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to format timing buffer");
	debug_return_int(-1);
    }

    /* Write timing data. */
    if (!iolog_write(&closure->iolog_files[IOFD_TIMING], tbuf,
	    len, &errstr)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to write to %s/%s: %s", closure->details.iolog_path,
	    iolog_fd_to_name(IOFD_TIMING), errstr);
	debug_return_int(-1);
    }

    update_elapsed_time(msg->delay, &closure->elapsed_time);

    debug_return_int(0);
}

int
store_winsize(ChangeWindowSize *msg, struct connection_closure *closure)
{
    const char *errstr;
    char tbuf[1024];
    int len;
    debug_decl(store_winsize, SUDO_DEBUG_UTIL)

    /* Format timing data including new window size. */
    len = snprintf(tbuf, sizeof(tbuf), "%d %lld.%09d %d %d\n", IO_EVENT_WINSIZE,
	(long long)msg->delay->tv_sec, (int)msg->delay->tv_nsec,
	msg->rows, msg->cols);
    if (len < 0 || len >= ssizeof(tbuf)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to format timing buffer");
	debug_return_int(-1);
    }

    /* Write timing data. */
    if (!iolog_write(&closure->iolog_files[IOFD_TIMING], tbuf,
	    len, &errstr)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to write to %s/%s: %s", closure->details.iolog_path,
	    iolog_fd_to_name(IOFD_TIMING), errstr);
	debug_return_int(-1);
    }

    update_elapsed_time(msg->delay, &closure->elapsed_time);

    debug_return_int(0);
}
