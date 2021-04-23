/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2021 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_gettext.h"
#include "sudo_eventlog.h"
#include "sudo_iolog.h"
#include "sudo_util.h"

#include "log_server.pb-c.h"
#include "logsrvd.h"

/*
 * Helper function to set closure->journal and closure->journal_path.
 */
static bool
journal_fdopen(int fd, const char *journal_path,
    struct connection_closure *closure)
{
    debug_decl(journal_fdopen, SUDO_DEBUG_UTIL);

    closure->journal_path = strdup(journal_path);
    if (closure->journal_path == NULL) {
	closure->errstr = _("unable to allocate memory");
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to allocate memory");
	debug_return_bool(false);
    }

    /* Defer fdopen() until last--it cannot be undone. */
    if ((closure->journal = fdopen(fd, "r+")) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to fdopen journal file %s", journal_path);
	closure->errstr = _("unable to allocate memory");
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

/*
 * Create a temporary file in the relay dir and store it in the closure.
 */
bool
journal_open(struct connection_closure *closure)
{
    char journal_path[PATH_MAX];
    int fd, len;
    debug_decl(journal_open, SUDO_DEBUG_UTIL);

    len = snprintf(journal_path, sizeof(journal_path), "%s/relay.XXXXXXXX",
	logsrvd_conf_relay_dir());
    if (len >= ssizeof(journal_path)) {
	errno = ENAMETOOLONG;
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "%s/relay.XXXXXXXX", logsrvd_conf_relay_dir());
	debug_return_bool(false);
    }
    /* TODO: use same escapes as iolog_path? */
    if (!sudo_mkdir_parents(journal_path, ROOT_UID, ROOT_GID,
	    S_IRWXU|S_IXGRP|S_IXOTH, false)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to create parent dir for %s", journal_path);
	closure->errstr = _("unable to create journal file");
	debug_return_bool(false);
    }
    if ((fd = mkstemp(journal_path)) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to create journal file %s", journal_path);
	closure->errstr = _("unable to create journal file");
	debug_return_bool(false);
    }
    if (!journal_fdopen(fd, journal_path, closure)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to fdopen journal file %s", journal_path);
	close(fd);
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

/*
 * Flush any buffered data and rewind journal to the beginning.
 * The actual open file is closed in connection_closure_free().
 */
bool
journal_finish(struct connection_closure *closure)
{
    bool ret;
    debug_decl(journal_finish, SUDO_DEBUG_UTIL);

    ret = fflush(closure->journal) == 0;
    if (!ret)
	closure->errstr = _("unable to write journal file");
    rewind(closure->journal);

    debug_return_bool(ret);
}

/*
 * Seek ahead in the journal to the specified target time.
 * Returns true if we reached the target time exactly, else false.
 */
static bool
journal_seek(struct timespec *target, struct connection_closure *closure)
{
    ClientMessage *msg = NULL;
    struct timespec elapsed_time = { 0, 0 };
    size_t nread, bufsize = 0;
    uint8_t *buf = NULL;
    uint32_t msg_len;
    bool ret = false;
    debug_decl(journal_seek, SUDO_DEBUG_UTIL);

    for (;;) {
	TimeSpec *delay = NULL;

	/* Read message size (uint32_t in network byte order). */
	nread = fread(&msg_len, sizeof(msg_len), 1, closure->journal);
	if (nread != 1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to read message length from %s", closure->journal_path);
	    if (feof(closure->journal))
		closure->errstr = _("unexpected EOF reading journal file");
	    else
		closure->errstr = _("error reading journal file");
	    break;
	}
	msg_len = ntohl(msg_len);
	if (msg_len > MESSAGE_SIZE_MAX) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: client message too large %u > %u",
		closure->journal_path, msg_len, MESSAGE_SIZE_MAX);
	    closure->errstr = _("client message too large");
	    break;
	}
	if (msg_len > bufsize) {
	    bufsize = sudo_pow2_roundup(msg_len);
	    free(buf);
	    if ((buf = malloc(bufsize)) == NULL) {
		closure->errstr = _("unable to allocate memory");
		break;
	    }
	}

	/* Read actual message now that we know the size. */
	nread = fread(buf, msg_len, 1, closure->journal);
	if (nread != 1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to read message from %s", closure->journal_path);
	    if (feof(closure->journal))
		closure->errstr = _("unexpected EOF reading journal file");
	    else
		closure->errstr = _("error reading journal file");
	    break;
	}

	client_message__free_unpacked(msg, NULL);
	msg = client_message__unpack(NULL, msg_len, buf);
	if (msg == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to unpack ClientMessage size %u", msg_len);
	    closure->errstr = _("invalid journal file, unable to restart");
	    break;
	}

	switch (msg->type_case) {
	case CLIENT_MESSAGE__TYPE_HELLO_MSG:
	case CLIENT_MESSAGE__TYPE_ACCEPT_MSG:
	case CLIENT_MESSAGE__TYPE_REJECT_MSG:
	case CLIENT_MESSAGE__TYPE_EXIT_MSG:
	case CLIENT_MESSAGE__TYPE_RESTART_MSG:
	case CLIENT_MESSAGE__TYPE_ALERT_MSG:
	    /* No associated delay. */
	    break;
	case CLIENT_MESSAGE__TYPE_TTYIN_BUF:
	    delay = msg->u.ttyin_buf->delay;
	    break;
	case CLIENT_MESSAGE__TYPE_TTYOUT_BUF:
	    delay = msg->u.ttyout_buf->delay;
	    break;
	case CLIENT_MESSAGE__TYPE_STDIN_BUF:
	    delay = msg->u.stdin_buf->delay;
	    break;
	case CLIENT_MESSAGE__TYPE_STDOUT_BUF:
	    delay = msg->u.stdout_buf->delay;
	    break;
	case CLIENT_MESSAGE__TYPE_STDERR_BUF:
	    delay = msg->u.stderr_buf->delay;
	    break;
	case CLIENT_MESSAGE__TYPE_WINSIZE_EVENT:
	    delay = msg->u.winsize_event->delay;
	    break;
	case CLIENT_MESSAGE__TYPE_SUSPEND_EVENT:
	    delay = msg->u.suspend_event->delay;
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unexpected type_case value %d", msg->type_case);
	    break;
	}
	if (delay != NULL) {
	    elapsed_time.tv_sec += delay->tv_sec;
	    elapsed_time.tv_nsec += delay->tv_nsec;
	    if (elapsed_time.tv_nsec >= 1000000000) {
		elapsed_time.tv_sec++;
		elapsed_time.tv_nsec -= 1000000000;
	    }
	}

	if (timespeccmp(&elapsed_time, target, >=)) {
	    if (sudo_timespeccmp(&elapsed_time, target, ==)) {
		ret = true;
		break;
	    }

	    /* Mismatch between resume point and stored log. */
	    closure->errstr = _("invalid journal file, unable to restart");
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to find resume point [%lld, %ld] in %s",
		(long long)target->tv_sec, target->tv_nsec,
		closure->journal_path);
	    break;
	}
    }

    client_message__free_unpacked(msg, NULL);
    free(buf);

    debug_return_bool(ret);
}

/*
 * Restart an existing journal.
 * Seeks to the resume_point in RestartMessage before continuing.
 * Returns true if we reached the target time exactly, else false.
 */
bool
journal_restart(RestartMessage *msg, struct connection_closure *closure)
{
    struct timespec target;
    int fd, len;
    char *cp, journal_path[PATH_MAX];
    debug_decl(journal_restart, SUDO_DEBUG_UTIL);

    /* Strip off leading hostname from log_id. */
    if ((cp = strchr(msg->log_id, '/')) != NULL) {
        if (cp != msg->log_id)
            cp++;
    } else {
    	cp = msg->log_id;
    }
    len = snprintf(journal_path, sizeof(journal_path), "%s/%s",
	logsrvd_conf_relay_dir(), cp);
    if (len >= ssizeof(journal_path)) {
	errno = ENAMETOOLONG;
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "%s/%s", logsrvd_conf_relay_dir(), cp);
	closure->errstr = _("unable to create journal file");
	debug_return_bool(false);
    }
    if ((fd = open(journal_path, O_RDWR)) == -1) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
            "unable to open journal file %s", journal_path);
	closure->errstr = _("unable to create journal file");
        debug_return_bool(false);
    }
    if (!journal_fdopen(fd, journal_path, closure)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to fdopen journal file %s", journal_path);
	close(fd);
	debug_return_bool(false);
    }

    /* Seek forward to resume point. */
    target.tv_sec = msg->resume_point->tv_sec;
    target.tv_nsec = msg->resume_point->tv_nsec;
    if (!journal_seek(&target, closure)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to seek to [%lld, %ld] in journal file %s",
	    (long long)target.tv_sec, target.tv_nsec, journal_path);
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

bool
journal_write(uint8_t *buf, size_t len, struct connection_closure *closure)
{
    uint32_t msg_len;
    debug_decl(journal_write, SUDO_DEBUG_UTIL);

    /* 32-bit message length in network byte order. */
    msg_len = htonl((uint32_t)len);
    if (fwrite(&msg_len, 1, sizeof(msg_len), closure->journal) != sizeof(msg_len)) {
	closure->errstr = _("unable to write journal file");
	debug_return_bool(false);
    }
    /* message payload */
    if (fwrite(buf, 1, len, closure->journal) != len) {
	closure->errstr = _("unable to write journal file");
	debug_return_bool(false);
    }
    debug_return_bool(true);
}
