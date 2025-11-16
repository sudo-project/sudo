/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2021-2022 Todd C. Miller <Todd.Miller@sudo.ws>
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
# include <compat/stdbool.h>
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

#include <sudo_compat.h>
#include <sudo_conf.h>
#include <sudo_debug.h>
#include <sudo_event.h>
#include <sudo_eventlog.h>
#include <sudo_fatal.h>
#include <sudo_gettext.h>
#include <sudo_iolog.h>
#include <sudo_util.h>

#include <logsrvd.h>

/*
 * Helper function to set closure->journal and closure->journal_path.
 */
static bool
journal_fdopen(int fd, const char *journal_path,
    struct connection_closure *closure)
{
    debug_decl(journal_fdopen, SUDO_DEBUG_UTIL);

    free(closure->journal_path);
    closure->journal_path = strdup(journal_path);
    if (closure->journal_path == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_bool(false);
    }

    /* Defer fdopen() until last--it cannot be undone. */
    if (closure->journal != NULL)
	fclose(closure->journal);
    if ((closure->journal = fdopen(fd, "r+")) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to fdopen journal file %s", journal_path);
	free(closure->journal_path);
	closure->journal_path = NULL;
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

static int
journal_mkuuid(const char *parent_dir, char *pathbuf, size_t pathsize)
{
    int len, dfd = -1, fd = -1;
    mode_t dirmode, oldmask;
    unsigned char uuid[16];
    char uuid_str[37];
    debug_decl(journal_mkuuid, SUDO_DEBUG_UTIL);

    /* umask must not be more restrictive than the file modes. */
    dirmode = logsrvd_conf_iolog_mode() | S_IXUSR;
    if (dirmode & (S_IRGRP|S_IWGRP))
        dirmode |= S_IXGRP;
    if (dirmode & (S_IROTH|S_IWOTH))
        dirmode |= S_IXOTH;
    oldmask = umask(ACCESSPERMS & ~dirmode);

    do {
	sudo_uuid_create(uuid);
	if (sudo_uuid_to_string(uuid, uuid_str, sizeof(uuid_str)) == NULL) {
	    sudo_warnx("%s", U_("unable to generate UUID"));
	    goto done;
	}

	len = snprintf(pathbuf, pathsize, "%s/%s/%s",
	    logsrvd_conf_relay_dir(), parent_dir, uuid_str);
	if ((size_t)len >= pathsize) {
	    errno = ENAMETOOLONG;
	    sudo_warn("%s/%s/%s",
		logsrvd_conf_relay_dir(), parent_dir, uuid_str);
	    goto done;
	}
	if (dfd == -1) {
	    dfd = sudo_open_parent_dir(pathbuf, logsrvd_conf_iolog_uid(),
		logsrvd_conf_iolog_gid(), S_IRWXU|S_IXGRP|S_IXOTH, false);
	    if (dfd == -1) {
		sudo_debug_printf(
		    SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		    "unable to create parent dir for %s", pathbuf);
		goto done;
	    }
	}
	fd = openat(dfd, uuid_str, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
    } while (fd == -1 && errno == EEXIST);
    if (fd == -1) {
	sudo_warn(U_("%s: %s"), "openat", pathbuf);
	goto done;
    }

done:
    umask(oldmask);
    if (dfd != -1)
	close(dfd);

    debug_return_int(fd);
}

/*
 * Create a temporary file in the relay dir and store it in the closure.
 */
static bool
journal_create(struct connection_closure *closure)
{
    char journal_path[PATH_MAX];
    int fd;
    debug_decl(journal_create, SUDO_DEBUG_UTIL);

    fd = journal_mkuuid("incoming", journal_path, sizeof(journal_path));
    if (fd == -1) {
	closure->errstr = _("unable to create journal file");
	debug_return_bool(false);
    }
    if (!sudo_lock_file(fd, SUDO_TLOCK)) {
	sudo_warn(U_("unable to lock %s"), journal_path);
	unlink(journal_path);
	close(fd);
	closure->errstr = _("unable to lock journal file");
	debug_return_bool(false);
    }
    if (!journal_fdopen(fd, journal_path, closure)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to fdopen journal file %s", journal_path);
	unlink(journal_path);
	close(fd);
	closure->errstr = _("unable to open journal file");
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

/*
 * Flush any buffered data, rewind journal to the beginning and
 * move to the outgoing directory.
 * The actual open file is closed in connection_closure_free().
 */
static bool
journal_finish(struct connection_closure *closure)
{
    char outgoing_path[PATH_MAX];
    size_t len;
    int fd;
    debug_decl(journal_finish, SUDO_DEBUG_UTIL);

    if (fflush(closure->journal) != 0) {
	closure->errstr = _("unable to write journal file");
	debug_return_bool(false);
    }
    rewind(closure->journal);

    /* Move journal to the outgoing directory. */
    fd = journal_mkuuid("outgoing", outgoing_path, sizeof(outgoing_path));
    if (fd == -1) {
	closure->errstr = _("unable to rename journal file");
	debug_return_bool(false);
    }
    close(fd);
    if (rename(closure->journal_path, outgoing_path) == -1) {
	sudo_warn(U_("unable to rename %s to %s"), closure->journal_path,
	    outgoing_path);
	closure->errstr = _("unable to rename journal file");
	unlink(outgoing_path);
	debug_return_bool(false);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"renamed %s -> %s", closure->journal_path, outgoing_path);
    len = strlen(outgoing_path);
    if (strlen(closure->journal_path) == len) {
	/* This should always be true. */
	memcpy(closure->journal_path, outgoing_path, len);
    } else {
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
	    "length mismatch %zu != %zu", strlen(closure->journal_path), len);
	free(closure->journal_path);
	closure->journal_path = strdup(outgoing_path);
	if (closure->journal_path == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    closure->errstr = _("unable to allocate memory");
	    debug_return_bool(false);
	}
    }

    debug_return_bool(true);
}

/*
 * Seek ahead in the journal to the specified target time.
 * Returns true if we reached the target time exactly, else false.
 */
static bool
journal_seek(const struct timespec *target, struct connection_closure *closure)
{
    ClientMessage *msg = NULL;
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
	    if (feof(closure->journal)) {
		sudo_warnx(U_("%s: %s"), closure->journal_path,
		    U_("unexpected EOF reading journal file"));
		closure->errstr = _("unexpected EOF reading journal file");
	    } else {
		sudo_warn(U_("%s: %s"), closure->journal_path,
		    U_("error reading journal file"));
		closure->errstr = _("error reading journal file");
	    }
	    break;
	}
	msg_len = ntohl(msg_len);
	if (msg_len > MESSAGE_SIZE_MAX) {
	    sudo_warnx(U_("%s: %s"), closure->journal_path,
		U_("client message too large"));
	    closure->errstr = _("client message too large");
	    break;
	}

	/* Read actual message now that we know the size. */
	if (msg_len != 0) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"%s: reading message %u bytes", closure->journal_path, msg_len);

	    if (msg_len > bufsize) {
		bufsize = sudo_pow2_roundup(msg_len);
		if (bufsize < msg_len) {
		    /* overflow */
		    errno = ENOMEM;
		    closure->errstr = _("unable to allocate memory");
		    break;
		}
		free(buf);
		if ((buf = malloc(bufsize)) == NULL) {
		    closure->errstr = _("unable to allocate memory");
		    break;
		}
	    }

	    nread = fread(buf, msg_len, 1, closure->journal);
	    if (nread != 1) {
		if (feof(closure->journal)) {
		    sudo_warnx(U_("%s: %s"), closure->journal_path,
			U_("unexpected EOF reading journal file"));
		    closure->errstr = _("unexpected EOF reading journal file");
		} else {
		    sudo_warn(U_("%s: %s"), closure->journal_path,
			U_("error reading journal file"));
		    closure->errstr = _("error reading journal file");
		}
		break;
	    }
	}

	client_message__free_unpacked(msg, NULL);
	msg = client_message__unpack(NULL, msg_len, buf);
	if (msg == NULL) {
	    sudo_warnx(U_("unable to unpack %s size %zu"), "ClientMessage",
		(size_t)msg_len);
	    closure->errstr = _("invalid journal file, unable to restart");
	    break;
	}

	switch (msg->type_case) {
	case CLIENT_MESSAGE__TYPE_HELLO_MSG:
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"seeking past ClientHello (%d)", msg->type_case);
	    break;
	case CLIENT_MESSAGE__TYPE_ACCEPT_MSG:
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"seeking past AcceptMessage (%d)", msg->type_case);
	    break;
	case CLIENT_MESSAGE__TYPE_REJECT_MSG:
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"seeking past RejectMessage (%d)", msg->type_case);
	    break;
	case CLIENT_MESSAGE__TYPE_EXIT_MSG:
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"seeking past ExitMessage (%d)", msg->type_case);
	    break;
	case CLIENT_MESSAGE__TYPE_RESTART_MSG:
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"seeking past RestartMessage (%d)", msg->type_case);
	    break;
	case CLIENT_MESSAGE__TYPE_ALERT_MSG:
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"seeking past AlertMessage (%d)", msg->type_case);
	    break;
	case CLIENT_MESSAGE__TYPE_TTYIN_BUF:
	    if (msg->u.ttyin_buf == NULL ||
		    !valid_timespec(msg->u.ttyin_buf->delay)) {
		sudo_warnx(U_("%s: %s"), closure->journal_path,
		    U_("invalid IoBuffer"));
		closure->errstr = _("invalid IoBuffer");
		goto done;
	    }
	    delay = msg->u.ttyin_buf->delay;
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"read IoBuffer (%d), delay [%lld, %ld]", msg->type_case,
		(long long)delay->tv_sec, (long)delay->tv_nsec);
	    break;
	case CLIENT_MESSAGE__TYPE_TTYOUT_BUF:
	    if (msg->u.ttyout_buf == NULL ||
		    !valid_timespec(msg->u.ttyout_buf->delay)) {
		sudo_warnx(U_("%s: %s"), closure->journal_path,
		    U_("invalid IoBuffer"));
		closure->errstr = _("invalid IoBuffer");
		goto done;
	    }
	    delay = msg->u.ttyout_buf->delay;
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"read IoBuffer (%d), delay [%lld, %ld]", msg->type_case,
		(long long)delay->tv_sec, (long)delay->tv_nsec);
	    break;
	case CLIENT_MESSAGE__TYPE_STDIN_BUF:
	    if (msg->u.stdin_buf == NULL ||
		    !valid_timespec(msg->u.stdin_buf->delay)) {
		sudo_warnx(U_("%s: %s"), closure->journal_path,
		    U_("invalid IoBuffer"));
		closure->errstr = _("invalid IoBuffer");
		goto done;
	    }
	    delay = msg->u.stdin_buf->delay;
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"read IoBuffer (%d), delay [%lld, %ld]", msg->type_case,
		(long long)delay->tv_sec, (long)delay->tv_nsec);
	    break;
	case CLIENT_MESSAGE__TYPE_STDOUT_BUF:
	    if (msg->u.stdout_buf == NULL ||
		    !valid_timespec(msg->u.stdout_buf->delay)) {
		sudo_warnx(U_("%s: %s"), closure->journal_path,
		    U_("invalid IoBuffer"));
		closure->errstr = _("invalid IoBuffer");
		goto done;
	    }
	    delay = msg->u.stdout_buf->delay;
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"read stdout_buf (%d), delay [%lld, %ld]", msg->type_case,
		(long long)delay->tv_sec, (long)delay->tv_nsec);
	    break;
	case CLIENT_MESSAGE__TYPE_STDERR_BUF:
	    if (msg->u.stderr_buf == NULL ||
		    !valid_timespec(msg->u.stderr_buf->delay)) {
		sudo_warnx(U_("%s: %s"), closure->journal_path,
		    U_("invalid IoBuffer"));
		closure->errstr = _("invalid IoBuffer");
		goto done;
	    }
	    delay = msg->u.stderr_buf->delay;
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"read stderr_buf (%d), delay [%lld, %ld]", msg->type_case,
		(long long)delay->tv_sec, (long)delay->tv_nsec);
	    break;
	case CLIENT_MESSAGE__TYPE_WINSIZE_EVENT:
	    if (msg->u.winsize_event == NULL ||
		    !valid_timespec(msg->u.winsize_event->delay)) {
		sudo_warnx(U_("%s: %s"), closure->journal_path,
		    U_("invalid ChangeWindowSize"));
		closure->errstr = _("invalid ChangeWindowSize");
		goto done;
	    }
	    delay = msg->u.winsize_event->delay;
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"read ChangeWindowSize (%d), delay [%lld, %ld]", msg->type_case,
		(long long)delay->tv_sec, (long)delay->tv_nsec);
	    break;
	case CLIENT_MESSAGE__TYPE_SUSPEND_EVENT:
	    if (msg->u.suspend_event == NULL ||
		    !valid_timespec(msg->u.suspend_event->delay)) {
		sudo_warnx(U_("%s: %s"), closure->journal_path,
		    U_("invalid invalid CommandSuspend"));
		closure->errstr = _("invalid CommandSuspend");
		goto done;
	    }
	    delay = msg->u.suspend_event->delay;
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"read CommandSuspend (%d), delay [%lld, %ld]", msg->type_case,
		(long long)delay->tv_sec, (long)delay->tv_nsec);
	    break;
	default:
	    sudo_warnx(U_("unexpected type_case value %d in %s from %s"),
		msg->type_case, "ClientMessage", closure->journal_path);
	    break;
	}
	if (delay != NULL)
	    update_elapsed_time(delay, &closure->elapsed_time);

	if (sudo_timespeccmp(&closure->elapsed_time, target, >=)) {
	    if (sudo_timespeccmp(&closure->elapsed_time, target, ==)) {
		ret = true;
		break;
	    }

	    /* Mismatch between resume point and stored log. */
	    closure->errstr = _("invalid journal file, unable to restart");
	    sudo_warnx(U_("%s: unable to find resume point [%lld, %ld]"),
		closure->journal_path, (long long)target->tv_sec,
		target->tv_nsec);
	    break;
	}
    }

done:
    client_message__free_unpacked(msg, NULL);
    free(buf);

    debug_return_bool(ret);
}

/*
 * Restart an existing journal.
 * Seeks to the resume_point in RestartMessage before continuing.
 * Returns true if we reached the target time exactly, else false.
 */
static bool
journal_restart(const RestartMessage *msg, const uint8_t *buf, size_t buflen,
    struct connection_closure *closure)
{
    char uuid_str[37], journal_path[PATH_MAX];
    unsigned char uuid[16];
    struct timespec target;
    int fd, len;
    debug_decl(journal_restart, SUDO_DEBUG_UTIL);

    /* A journal log_id must be a base64-encoded UUID. */
    if (strlen(msg->log_id) != ((16 + 2) / 3 * 4))
	goto parse_err;
    if (sudo_base64_decode(msg->log_id, uuid, sizeof(uuid)) != sizeof(uuid))
	goto parse_err;
    if (sudo_uuid_to_string(uuid, uuid_str, sizeof(uuid_str)) == NULL) {
	parse_err:
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to parse log_id"));
	closure->errstr = _("unable to open journal file");
	debug_return_bool(false);
    }

    /* Journal files are stored by UUID. */
    len = snprintf(journal_path, sizeof(journal_path), "%s/incoming/%s",
	logsrvd_conf_relay_dir(), uuid_str);
    if (len >= ssizeof(journal_path)) {
	errno = ENAMETOOLONG;
	sudo_warn("%s/incoming/%s", logsrvd_conf_relay_dir(), uuid_str);
	closure->errstr = _("unable to open journal file");
	debug_return_bool(false);
    }
    if ((fd = open(journal_path, O_RDWR)) == -1) {
	sudo_warn(U_("unable to open %s"), journal_path);
	closure->errstr = _("unable to open journal file");
	debug_return_bool(false);
    }
    if (!sudo_lock_file(fd, SUDO_TLOCK)) {
	sudo_warn(U_("unable to lock %s"), journal_path);
	close(fd);
	closure->errstr = _("unable to lock journal file");
	debug_return_bool(false);
    }
    if (!journal_fdopen(fd, journal_path, closure)) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	close(fd);
	closure->errstr = _("unable to allocate memory");
	debug_return_bool(false);
    }

    /* Seek forward to resume point. */
    target.tv_sec = (time_t)msg->resume_point->tv_sec;
    target.tv_nsec = (long)msg->resume_point->tv_nsec;
    if (!journal_seek(&target, closure)) {
	sudo_warn(U_("unable to seek to [%lld, %ld] in journal file %s"),
	    (long long)target.tv_sec, target.tv_nsec, journal_path);
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

static bool
journal_write(const uint8_t * restrict buf, size_t len,
    struct connection_closure * restrict closure)
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

/*
 * Store an AcceptMessage from the client in the journal.
 */
static bool
journal_accept(const AcceptMessage *msg, const uint8_t *buf, size_t len,
    struct connection_closure *closure)
{
    debug_decl(journal_accept, SUDO_DEBUG_UTIL);

    if (closure->journal_path != NULL) {
	/* Reuse existing journal file. */
	debug_return_bool(journal_write(buf, len, closure));
    }

    /* Store message in a journal for later relaying. */
    if (!journal_create(closure))
	debug_return_bool(false);
    if (!journal_write(buf, len, closure))
	debug_return_bool(false);

    if (msg->expect_iobufs) {
	/* Send log ID to client for restarting connections. */
	unsigned char uuid[16];
	const char *uuid_str;

	/* Journaled I/O log files are files stored by UUID. */
	uuid_str = strrchr(closure->journal_path, '/');
	if (uuid_str == NULL)
	    debug_return_bool(false);
	uuid_str++;

	/* Parse UUID and format as a log ID (base64-encoded). */
	if (sudo_uuid_from_string(uuid_str, uuid) != 0)
	    debug_return_bool(false);
	if (!fmt_log_id_message(uuid, "", closure))
	    debug_return_bool(false);
	if (sudo_ev_add(closure->evbase, closure->write_ev,
		logsrvd_conf_server_timeout(), false) == -1) {
	    sudo_warnx("%s", U_("unable to add event to queue"));
	    debug_return_bool(false);
	}
    }

    debug_return_bool(true);
}

/*
 * Store a RejectMessage from the client in the journal.
 */
static bool
journal_reject(const RejectMessage *msg, const uint8_t * restrict buf,
    size_t len, struct connection_closure * restrict closure)
{
    debug_decl(journal_reject, SUDO_DEBUG_UTIL);

    /* Store message in a journal for later relaying. */
    if (closure->journal_path == NULL) {
	if (!journal_create(closure))
	    debug_return_bool(false);
    }
    if (!journal_write(buf, len, closure))
	debug_return_bool(false);

    debug_return_bool(true);
}

/*
 * Store an ExitMessage from the client in the journal.
 */
static bool
journal_exit(const ExitMessage *msg, const uint8_t * restrict buf, size_t len,
    struct connection_closure * restrict closure)
{
    debug_decl(journal_exit, SUDO_DEBUG_UTIL);

    /* Store exit message in journal. */
    if (!journal_write(buf, len, closure))
	debug_return_bool(false);
    if (!journal_finish(closure))
	debug_return_bool(false);

    debug_return_bool(true);
}

/*
 * Store an AlertMessage from the client in the journal.
 */
static bool
journal_alert(const AlertMessage *msg, const uint8_t * restrict buf, size_t len,
    struct connection_closure * restrict closure)
{
    debug_decl(journal_alert, SUDO_DEBUG_UTIL);

    /* Store message in a journal for later relaying. */
    if (closure->journal_path == NULL) {
	if (!journal_create(closure))
	    debug_return_bool(false);
    }
    if (!journal_write(buf, len, closure))
	debug_return_bool(false);

    debug_return_bool(true);
}

/*
 * Store an IoBuffer from the client in the journal.
 */
static bool
journal_iobuf(int iofd, const IoBuffer *iobuf, const uint8_t * restrict buf,
    size_t len, struct connection_closure * restrict closure)
{
    debug_decl(journal_iobuf, SUDO_DEBUG_UTIL);

    if (!journal_write(buf, len, closure))
	debug_return_bool(false);
    update_elapsed_time(iobuf->delay, &closure->elapsed_time);

    debug_return_bool(true);
}

/*
 * Store a CommandSuspend message from the client in the journal.
 */
static bool
journal_suspend(const CommandSuspend *msg, const uint8_t * restrict buf,
    size_t len, struct connection_closure * restrict closure)
{
    debug_decl(journal_suspend, SUDO_DEBUG_UTIL);

    update_elapsed_time(msg->delay, &closure->elapsed_time);

    debug_return_bool(journal_write(buf, len, closure));
}

/*
 * Store a ChangeWindowSize message from the client in the journal.
 */
static bool
journal_winsize(const ChangeWindowSize *msg, const uint8_t * restrict buf,
    size_t len, struct connection_closure * restrict closure)
{
    debug_decl(journal_winsize, SUDO_DEBUG_UTIL);

    update_elapsed_time(msg->delay, &closure->elapsed_time);

    debug_return_bool(journal_write(buf, len, closure));
}

struct client_message_switch cms_journal = {
    journal_accept,
    journal_reject,
    journal_exit,
    journal_restart,
    journal_alert,
    journal_iobuf,
    journal_suspend,
    journal_winsize
};
