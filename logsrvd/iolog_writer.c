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
#include "sudo_fatal.h"
#include "iolog.h"
#include "logsrvd.h"

/* I/O log file names relative to iolog_dir. */
static const char *iolog_names[] = {
    "stdin",	/* IOFD_STDIN */
    "stdout",	/* IOFD_STDOUT */
    "stderr",	/* IOFD_STDERR */
    "ttyin",	/* IOFD_TTYIN  */
    "ttyout",	/* IOFD_TTYOUT */
    "timing",	/* IOFD_TIMING */
    NULL	/* IOFD_MAX */
};

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
 * Fill in log info from an ExecMessage
 * Only makes a shallow copy of strings and string lists.
 */
static bool
log_info_fill(struct log_info *log_info, ExecMessage *msg)
{
    size_t idx;
    bool ret = true;
    debug_decl(log_info_fill, SUDO_DEBUG_UTIL)

    memset(log_info, 0, sizeof(*log_info));

    /* Start time. */
    log_info->start_time = msg->start_time->tv_sec;

    /* Default values */
    log_info->lines = 24;
    log_info->columns = 80;

    /* Pull out values by key from info array. */
    for (idx = 0; idx < msg->n_info_msgs; idx++) {
	InfoMessage *info = msg->info_msgs[idx];
	const char *key = info->key;
	switch (key[0]) {
	case 'c':
	    if (strcmp(key, "columns") == 0) {
		if (!has_numval(info)) {
		    sudo_warnx("columns specified but not a number");
		} else if (info->numval <= 0 || info->numval > INT_MAX) {
		    sudo_warnx("columns (%" PRId64 ") out of range", info->numval);
		} else {
		    log_info->columns = info->numval;
		}
		continue;
	    }
	    if (strcmp(key, "command") == 0) {
		if (has_strval(info)) {
		    log_info->command = info->strval;
		} else {
		    sudo_warnx("command specified but not a string");
		}
		continue;
	    }
	    if (strcmp(key, "cwd") == 0) {
		if (has_strval(info)) {
		    log_info->cwd = info->strval;
		} else {
		    sudo_warnx("cwd specified but not a string");
		}
		continue;
	    }
	    break;
	case 'l':
	    if (strcmp(key, "lines") == 0) {
		if (!has_numval(info)) {
		    sudo_warnx("lines specified but not a number");
		} else if (info->numval <= 0 || info->numval > INT_MAX) {
		    sudo_warnx("lines (%" PRId64 ") out of range", info->numval);
		} else {
		    log_info->lines = info->numval;
		}
		continue;
	    }
	    break;
	case 'r':
	    if (strcmp(key, "runargv") == 0) {
		if (has_strlistval(info)) {
		    log_info->argv = info->strlistval->strings;
		    log_info->argc = info->strlistval->n_strings;
		} else {
		    sudo_warnx("runargv specified but not a string list");
		}
		continue;
	    }
	    if (strcmp(key, "rungroup") == 0) {
		if (has_strval(info)) {
		    log_info->rungroup = info->strval;
		} else {
		    sudo_warnx("rungroup specified but not a string");
		}
		continue;
	    }
	    if (strcmp(key, "runuser") == 0) {
		if (has_strval(info)) {
		    log_info->runuser = info->strval;
		} else {
		    sudo_warnx("runuser specified but not a string");
		}
		continue;
	    }
	    break;
	case 's':
	    if (strcmp(key, "submithost") == 0) {
		if (has_strval(info)) {
		    log_info->submithost = info->strval;
		} else {
		    sudo_warnx("submithost specified but not a string");
		}
		continue;
	    }
	    if (strcmp(key, "submituser") == 0) {
		if (has_strval(info)) {
		    log_info->submituser = info->strval;
		} else {
		    sudo_warnx("submituser specified but not a string");
		}
		continue;
	    }
	    break;
	case 't':
	    if (strcmp(key, "ttyname") == 0) {
		if (has_strval(info)) {
		    log_info->ttyname = info->strval;
		} else {
		    sudo_warnx("ttyname specified but not a string");
		}
		continue;
	    }
	    break;
	}
    }

    /* Check for required settings */
    if (log_info->submituser == NULL) {
	sudo_warnx("missing user in ExecMessage");
	ret = false;
    }
    if (log_info->submithost == NULL) {
	sudo_warnx("missing host in ExecMessage");
	ret = false;
    }
    if (log_info->command == NULL) {
	sudo_warnx("missing command in ExecMessage");
	ret = false;
    }

    debug_return_bool(ret);
}

/*
 * Create I/O log path
 * Set iolog_dir and iolog_dir_fd in the closure
 */
static bool
create_iolog_dir(struct log_info *log_info, struct connection_closure *closure)
{
    char path[PATH_MAX];
    int len;
    debug_decl(create_iolog_dir, SUDO_DEBUG_UTIL)

    /* Create IOLOG_DIR/host/user/XXXXXX directory */
    if (mkdir(IOLOG_DIR, 0755) == -1 && errno != EEXIST) {
	sudo_warn("mkdir %s", path);
	goto bad;
    }
    len = snprintf(path, sizeof(path), "%s/%s", IOLOG_DIR,
	log_info->submithost);
    if (len < 0 || len >= ssizeof(path)) {
	sudo_warn("snprintf");
	goto bad;
    }
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
	sudo_warn("mkdir %s", path);
	goto bad;
    }
    len = snprintf(path, sizeof(path), "%s/%s/%s", IOLOG_DIR,
	log_info->submithost, log_info->submituser);
    if (len < 0 || len >= ssizeof(path)) {
	sudo_warn("snprintf");
	goto bad;
    }
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
	sudo_warn("mkdir %s", path);
	goto bad;
    }
    len = snprintf(path, sizeof(path), "%s/%s/%s/XXXXXX", IOLOG_DIR,
	log_info->submithost, log_info->submituser);
    if (len < 0 || len >= ssizeof(path)) {
	sudo_warn("snprintf");
	goto bad;
    }
    if (mkdtemp(path) == NULL) {
	sudo_warn("mkdtemp %s", path);
	goto bad;
    }
    sudo_warnx("I/O log path %s", path); // XXX

    /* Make a copy of iolog_dir for error messages. */
    if ((closure->iolog_dir = strdup(path)) == NULL) {
	sudo_warn("strdup");
	goto bad;
    }

    /* We use iolog_dir_fd in calls to openat(2) */
    closure->iolog_dir_fd = open(closure->iolog_dir, O_RDONLY);
    if (closure->iolog_dir_fd == -1) {
	sudo_warn("%s", path);
	goto bad;
    }

    debug_return_bool(true);
bad:
    free(closure->iolog_dir);
    debug_return_bool(false);
}

/*
 * Write the sudo-style I/O log info file containing user and command info.
 */
static bool
log_info_write(struct log_info *log_info, struct connection_closure *closure)
{
    int fd, i;
    FILE *fp;
    int error;
    debug_decl(log_info_write, SUDO_DEBUG_UTIL)

    fd = openat(closure->iolog_dir_fd, "log", O_CREAT|O_EXCL|O_WRONLY, 0600);
    if (fd == -1 || (fp = fdopen(fd, "w")) == NULL) {
	sudo_warn("unable to open %s", closure->iolog_dir);
	if (fd != -1)
	    close(fd);
	debug_return_bool(false);
    }

    fprintf(fp, "%lld:%s:%s:%s:%s:%d:%d\n%s\n",
	(long long)log_info->start_time, log_info->submituser,
	log_info->runuser ? log_info->runuser : RUNAS_DEFAULT,
	log_info->rungroup ? log_info->rungroup : "",
	log_info->ttyname ? log_info->ttyname : "unknown",
	log_info->lines, log_info->columns,
	log_info->cwd ? log_info->cwd : "unknown");
    fputs(log_info->command, fp);
    for (i = 1; i < log_info->argc; i++) {
	fputc(' ', fp);
	fputs(log_info->argv[i], fp);
    }
    fputc('\n', fp);
    fflush(fp);
    if ((error = ferror(fp)))
	sudo_warn("unable to write to I/O log file %s", closure->iolog_dir);
    fclose(fp);

    debug_return_bool(!error);
}

static bool
iolog_open(int iofd, struct connection_closure *closure)
{
    debug_decl(iolog_open, SUDO_DEBUG_UTIL)

    if (iofd < 0 || iofd >= IOFD_MAX) {
	sudo_warnx("invalid iofd %d", iofd);
	debug_return_bool(false);
    }

    closure->io_fds[iofd] = openat(closure->iolog_dir_fd,
	iolog_names[iofd], O_CREAT|O_EXCL|O_WRONLY, 0600);
    debug_return_bool(closure->io_fds[iofd] != -1);
}

void
iolog_close(struct connection_closure *closure)
{
    int i;
    debug_decl(iolog_close, SUDO_DEBUG_UTIL)

    for (i = 0; i < IOFD_MAX; i++) {
	if (closure->io_fds[i] == -1)
	    continue;
	close(closure->io_fds[i]);
    }
    if (closure->iolog_dir_fd != -1)
	close(closure->iolog_dir_fd);

    debug_return;
}

bool
iolog_init(ExecMessage *msg, struct connection_closure *closure)
{
    struct log_info log_info;
    int i;
    debug_decl(iolog_init, SUDO_DEBUG_UTIL)

    /* Init io_fds in closure. */
    for (i = 0; i < IOFD_MAX; i++)
        closure->io_fds[i] = -1;

    /* Fill in log_info */
    if (!log_info_fill(&log_info, msg))
	debug_return_bool(false);

    /* Create I/O log dir */
    if (!create_iolog_dir(&log_info, closure))
	debug_return_bool(false);

    /* Write sudo I/O log info file */
    if (!log_info_write(&log_info, closure))
	debug_return_bool(false);

    /* Create timing, stdout, stderr and ttyout files for sudoreplay. */
    if (!iolog_open(IOFD_TIMING, closure) ||
	!iolog_open(IOFD_STDOUT, closure) ||
	!iolog_open(IOFD_STDERR, closure) ||
	!iolog_open(IOFD_TTYOUT, closure))
	debug_return_bool(false);

    /* Ready to log I/O buffers. */
    debug_return_bool(true);
}

static bool
iolog_write(int iofd, void *buf, size_t len, struct connection_closure *closure)
{
    debug_decl(iolog_write, SUDO_DEBUG_UTIL)
    size_t nread;

    if (iofd < 0 || iofd >= IOFD_MAX) {
	sudo_warnx("invalid iofd %d", iofd);
	debug_return_bool(false);
    }
    nread = write(closure->io_fds[iofd], buf, len);
    debug_return_bool(nread == len);
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
    char tbuf[1024];
    int len;
    debug_decl(store_iobuf, SUDO_DEBUG_UTIL)

    /* Open log file as needed. */
    if (closure->io_fds[iofd] == -1) {
	if (!iolog_open(iofd, closure))
	    debug_return_int(-1);
    }

    /* Format timing data. */
    /* FIXME - assumes IOFD_* matches IO_EVENT_* */
    len = snprintf(tbuf, sizeof(tbuf), "%d %lld.%09d %zu\n",
	iofd, (long long)msg->delay->tv_sec, (int)msg->delay->tv_nsec,
	msg->data.len);
    if (len < 0 || len >= ssizeof(tbuf)) {
	sudo_warnx("unable to format timing buffer");
	debug_return_int(-1);
    }

    /* Write to specified I/O log file. */
    if (!iolog_write(iofd, msg->data.data, msg->data.len, closure))
	debug_return_int(-1);

    /* Write timing data. */
    if (!iolog_write(IOFD_TIMING, tbuf, len, closure))
	debug_return_int(-1);

    update_elapsed_time(msg->delay, &closure->elapsed_time);

    debug_return_int(0);
}

int
store_suspend(CommandSuspend *msg, struct connection_closure *closure)
{
    char tbuf[1024];
    int len;
    debug_decl(store_suspend, SUDO_DEBUG_UTIL)

    /* Format timing data including suspend signal. */
    len = snprintf(tbuf, sizeof(tbuf), "%d %lld.%09d %s\n", IO_EVENT_SUSPEND,
	(long long)msg->delay->tv_sec, (int)msg->delay->tv_nsec,
	msg->signal);
    if (len < 0 || len >= ssizeof(tbuf)) {
	sudo_warnx("unable to format timing buffer");
	debug_return_int(-1);
    }

    /* Write timing data. */
    if (!iolog_write(IOFD_TIMING, tbuf, len, closure))
	debug_return_int(-1);

    update_elapsed_time(msg->delay, &closure->elapsed_time);

    debug_return_int(0);
}

int
store_winsize(ChangeWindowSize *msg, struct connection_closure *closure)
{
    char tbuf[1024];
    int len;
    debug_decl(store_winsize, SUDO_DEBUG_UTIL)

    /* Format timing data including new window size. */
    len = snprintf(tbuf, sizeof(tbuf), "%d %lld.%09d %d %d\n", IO_EVENT_WINSIZE,
	(long long)msg->delay->tv_sec, (int)msg->delay->tv_nsec,
	msg->rows, msg->cols);
    if (len < 0 || len >= ssizeof(tbuf)) {
	sudo_warnx("unable to format timing buffer");
	debug_return_int(-1);
    }

    /* Write timing data. */
    if (!iolog_write(IOFD_TIMING, tbuf, len, closure))
	debug_return_int(-1);

    update_elapsed_time(msg->delay, &closure->elapsed_time);

    debug_return_int(0);
}
