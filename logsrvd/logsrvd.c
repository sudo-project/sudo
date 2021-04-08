/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019-2021 Todd C. Miller <Todd.Miller@sudo.ws>
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
#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

#if defined(HAVE_OPENSSL)
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

#define NEED_INET_NTOP		/* to expose sudo_inet_ntop in sudo_compat.h */

#include "pathnames.h"
#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_event.h"
#include "sudo_eventlog.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_json.h"
#include "sudo_iolog.h"
#include "sudo_queue.h"
#include "sudo_rand.h"
#include "sudo_util.h"

#include "log_server.pb-c.h"
#include "hostcheck.h"
#include "logsrvd.h"

#ifndef O_NOFOLLOW
# define O_NOFOLLOW 0
#endif

/*
 * Sudo I/O audit server.
 */
static int logsrvd_debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;
TAILQ_HEAD(connection_list, connection_closure);
static struct connection_list connections = TAILQ_HEAD_INITIALIZER(connections);
static struct listener_list listeners = TAILQ_HEAD_INITIALIZER(listeners);
static const char server_id[] = "Sudo Audit Server " PACKAGE_VERSION;
static const char *conf_file = _PATH_SUDO_LOGSRVD_CONF;
static double random_drop;

/* Server callback may redirect to client callback for TLS. */
static void client_msg_cb(int fd, int what, void *v);

/*
 * Free a struct connection_closure container and its contents.
 */
void
connection_closure_free(struct connection_closure *closure)
{
    debug_decl(connection_closure_free, SUDO_DEBUG_UTIL);

    if (closure != NULL) {
	bool shutting_down = closure->state == SHUTDOWN;
	struct sudo_event_base *evbase = closure->evbase;
	struct connection_buffer *buf;

	TAILQ_REMOVE(&connections, closure, entries);
	if (closure->relay_closure != NULL)
	    relay_closure_free(closure->relay_closure);
	close(closure->sock);
	iolog_close_all(closure);
	sudo_ev_free(closure->commit_ev);
	sudo_ev_free(closure->read_ev);
	sudo_ev_free(closure->write_ev);
#if defined(HAVE_OPENSSL)
	sudo_ev_free(closure->ssl_accept_ev);
	if (closure->ssl != NULL) {
	    SSL_shutdown(closure->ssl);
	    SSL_free(closure->ssl);
	}
#endif
	eventlog_free(closure->evlog);
	free(closure->read_buf.data);
	while ((buf = TAILQ_FIRST(&closure->write_bufs)) != NULL) {
	    TAILQ_REMOVE(&closure->write_bufs, buf, entries);
	    free(buf->data);
	    free(buf);
	}
	while ((buf = TAILQ_FIRST(&closure->free_bufs)) != NULL) {
	    TAILQ_REMOVE(&closure->free_bufs, buf, entries);
	    free(buf->data);
	    free(buf);
	}
	free(closure);

	if (shutting_down && TAILQ_EMPTY(&connections))
	    sudo_ev_loopbreak(evbase);
    }

    debug_return;
}

struct connection_buffer *
get_free_buf(struct connection_closure *closure)
{
    struct connection_buffer *buf;
    debug_decl(get_free_buf, SUDO_DEBUG_UTIL);

    buf = TAILQ_FIRST(&closure->free_bufs);
    if (buf != NULL)
        TAILQ_REMOVE(&closure->free_bufs, buf, entries);
    else
        buf = calloc(1, sizeof(*buf));

    debug_return_ptr(buf);
}

bool
fmt_server_message(struct connection_closure *closure, ServerMessage *msg)
{
    struct connection_buffer *buf;
    uint32_t msg_len;
    bool ret = false;
    size_t len;
    debug_decl(fmt_server_message, SUDO_DEBUG_UTIL);

    if ((buf = get_free_buf(closure)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate connection_buffer");
        goto done;
    }

    len = server_message__get_packed_size(msg);
    if (len > MESSAGE_SIZE_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "server message too large: %zu", len);
        goto done;
    }

    /* Wire message size is used for length encoding, precedes message. */
    msg_len = htonl((uint32_t)len);
    len += sizeof(msg_len);

    /* Resize buffer as needed. */
    if (len > buf->size) {
	free(buf->data);
	buf->size = sudo_pow2_roundup(len);
	if ((buf->data = malloc(buf->size)) == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to malloc %u", buf->size);
	    buf->size = 0;
	    goto done;
	}
    }
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"size + server message %zu bytes", len);

    memcpy(buf->data, &msg_len, sizeof(msg_len));
    server_message__pack(msg, buf->data + sizeof(msg_len));
    buf->len = len;
    TAILQ_INSERT_TAIL(&closure->write_bufs, buf, entries);
    buf = NULL;

    ret = true;

done:
    if (buf != NULL) {
        free(buf->data);
        free(buf);
    }
    debug_return_bool(ret);
}

static bool
fmt_hello_message(struct connection_closure *closure)
{
    ServerMessage msg = SERVER_MESSAGE__INIT;
    ServerHello hello = SERVER_HELLO__INIT;
    debug_decl(fmt_hello_message, SUDO_DEBUG_UTIL);

    /* TODO: implement redirect and servers array.  */
    hello.server_id = (char *)server_id;
    msg.u.hello = &hello;
    msg.type_case = SERVER_MESSAGE__TYPE_HELLO;

    debug_return_bool(fmt_server_message(closure, &msg));
}

bool
fmt_log_id_message(const char *id, struct connection_closure *closure)
{
    ServerMessage msg = SERVER_MESSAGE__INIT;
    debug_decl(fmt_log_id_message, SUDO_DEBUG_UTIL);

    msg.u.log_id = (char *)id;
    msg.type_case = SERVER_MESSAGE__TYPE_LOG_ID;

    debug_return_bool(fmt_server_message(closure, &msg));
}

bool
fmt_error_message(const char *errstr, struct connection_closure *closure)
{
    ServerMessage msg = SERVER_MESSAGE__INIT;
    debug_decl(fmt_error_message, SUDO_DEBUG_UTIL);

    msg.u.error = (char *)errstr;
    msg.type_case = SERVER_MESSAGE__TYPE_ERROR;

    debug_return_bool(fmt_server_message(closure, &msg));
}

struct logsrvd_info_closure {
    InfoMessage **info_msgs;
    size_t infolen;
};

static bool
logsrvd_json_log_cb(struct json_container *json, void *v)
{
    struct logsrvd_info_closure *closure = v;
    struct json_value json_value;
    size_t idx;
    debug_decl(logsrvd_json_log_cb, SUDO_DEBUG_UTIL);

    for (idx = 0; idx < closure->infolen; idx++) {
	InfoMessage *info = closure->info_msgs[idx];

	switch (info->value_case) {
	case INFO_MESSAGE__VALUE_NUMVAL:
	    json_value.type = JSON_NUMBER;
	    json_value.u.number = info->u.numval;
	    if (!sudo_json_add_value(json, info->key, &json_value))
		goto bad;
	    break;
	case INFO_MESSAGE__VALUE_STRVAL:
	    json_value.type = JSON_STRING;
	    json_value.u.string = info->u.strval;
	    if (!sudo_json_add_value(json, info->key, &json_value))
		goto bad;
	    break;
	case INFO_MESSAGE__VALUE_STRLISTVAL: {
	    InfoMessage__StringList *strlist = info->u.strlistval;
	    size_t n;

	    if (!sudo_json_open_array(json, info->key))
		goto bad;
	    for (n = 0; n < strlist->n_strings; n++) {
		json_value.type = JSON_STRING;
		json_value.u.string = strlist->strings[n];
		if (!sudo_json_add_value(json, NULL, &json_value))
		    goto bad;
	    }
	    if (!sudo_json_close_array(json))
		goto bad;
	    break;
	}
	default:
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unexpected value case %d", info->value_case);
	    goto bad;
	}
    }
    debug_return_bool(true);
bad:
    debug_return_bool(false);
}

/*
 * Parse an AcceptMessage
 */
static bool
handle_accept(AcceptMessage *msg, struct connection_closure *closure)
{
    struct logsrvd_info_closure info = { msg->info_msgs, msg->n_info_msgs };
    debug_decl(handle_accept, SUDO_DEBUG_UTIL);

    if (closure->state != INITIAL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
	debug_return_bool(false);
    }

    /* Check that message is valid. */
    if (msg->submit_time == NULL || msg->n_info_msgs == 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid AcceptMessage, submit_time: %p, n_info_msgs: %zu",
	    msg->submit_time, msg->n_info_msgs);
	closure->errstr = _("invalid AcceptMessage");
	debug_return_bool(false);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received AcceptMessage", __func__);

    if (closure->relay_closure != NULL) {
	/* Forward AcceptMessage to connected relay. */
	debug_return_bool(relay_accept(msg, closure));
    }

    closure->evlog = evlog_new(msg->submit_time, msg->info_msgs,
	msg->n_info_msgs, closure);
    if (closure->evlog == NULL) {
	closure->errstr = _("error parsing AcceptMessage");
	debug_return_bool(false);
    }

    /* Create I/O log info file and parent directories. */
    if (msg->expect_iobufs) {
	if (!iolog_init(msg, closure)) {
	    closure->errstr = _("error creating I/O log");
	    debug_return_bool(false);
	}
	closure->log_io = true;
    }

    if (!eventlog_accept(closure->evlog, 0, logsrvd_json_log_cb, &info)) {
	closure->errstr = _("error logging accept event");
	debug_return_bool(false);
    }

    if (msg->expect_iobufs) {
	/* Send log ID to client for restarting connections. */
	if (!fmt_log_id_message(closure->evlog->iolog_path, closure))
	    debug_return_bool(false);
	if (sudo_ev_add(closure->evbase, closure->write_ev,
		logsrvd_conf_get_sock_timeout(), false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server write event");
	    debug_return_bool(false);
	}
    }

    closure->state = RUNNING;
    debug_return_bool(true);
}

/*
 * Parse a RejectMessage
 */
static bool
handle_reject(RejectMessage *msg, struct connection_closure *closure)
{
    struct logsrvd_info_closure info = { msg->info_msgs, msg->n_info_msgs };
    debug_decl(handle_reject, SUDO_DEBUG_UTIL);

    if (closure->state != INITIAL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
	debug_return_bool(false);
    }

    /* Check that message is valid. */
    if (msg->submit_time == NULL || msg->n_info_msgs == 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid RejectMessage, submit_time: %p, n_info_msgs: %zu",
	    msg->submit_time, msg->n_info_msgs);
	closure->errstr = _("invalid RejectMessage");
	debug_return_bool(false);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received RejectMessage", __func__);

    if (closure->relay_closure != NULL) {
	/* Forward RejectMessage to connected relay. */
	debug_return_bool(relay_reject(msg, closure));
    }

    closure->evlog = evlog_new(msg->submit_time, msg->info_msgs,
	msg->n_info_msgs, closure);
    if (closure->evlog == NULL) {
	closure->errstr = _("error parsing RejectMessage");
	debug_return_bool(false);
    }

    if (!eventlog_reject(closure->evlog, 0, msg->reason,
	    logsrvd_json_log_cb, &info)) {
	closure->errstr = _("error logging reject event");
	debug_return_bool(false);
    }

    closure->state = FINISHED;
    debug_return_bool(true);
}

static bool
handle_exit(ExitMessage *msg, struct connection_closure *closure)
{
    struct timespec tv = { 0, 0 };
    mode_t mode;
    debug_decl(handle_exit, SUDO_DEBUG_UTIL);

    if (closure->state != RUNNING) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received ExitMessage", __func__);

    if (closure->relay_closure != NULL) {
	/* Forward ExitMessage to connected relay. */
	debug_return_bool(relay_exit(msg, closure));
    }

    /* Sudo I/O logs don't store this info. */
    if (msg->signal != NULL && msg->signal[0] != '\0') {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "command was killed by SIG%s%s", msg->signal,
	    msg->dumped_core ? " (core dumped)" : "");
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "command exited with %d", msg->exit_value);
    }

    if (closure->log_io) {
	/* No more data, command exited. */
	closure->state = EXITED;
	sudo_ev_del(closure->evbase, closure->read_ev);

	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: elapsed time: %lld, %ld",
	    __func__, (long long)closure->elapsed_time.tv_sec,
	    closure->elapsed_time.tv_nsec);

	/* Clear write bits from I/O timing file to indicate completion. */
	mode = logsrvd_conf_iolog_mode();
	CLR(mode, S_IWUSR|S_IWGRP|S_IWOTH);
	if (fchmodat(closure->iolog_dir_fd, "timing", mode, 0) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"unable to fchmodat timing file");
	}

	/* Schedule the final commit point event immediately. */
	if (sudo_ev_add(closure->evbase, closure->commit_ev, &tv, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add commit point event");
	    debug_return_bool(false);
	}
    } else {
	/* Command exited, no I/O logs to flush. */
	closure->state = FINISHED;
    }

    debug_return_bool(true);
}

static bool
handle_restart(RestartMessage *msg, struct connection_closure *closure)
{
    debug_decl(handle_restart, SUDO_DEBUG_UTIL);

    if (closure->state != INITIAL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
	debug_return_bool(false);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received RestartMessage for %s",
	__func__, msg->log_id);

    if (closure->relay_closure != NULL) {
	/* Forward RestartMessage to connected relay. */
	debug_return_bool(relay_restart(msg, closure));
    }

    if (!iolog_restart(msg, closure)) {
	sudo_debug_printf(SUDO_DEBUG_WARN, "%s: unable to restart I/O log", __func__);
	/* XXX - structured error message so client can send from beginning */
	if (!fmt_error_message(closure->errstr, closure))
	    debug_return_bool(false);
	sudo_ev_del(closure->evbase, closure->read_ev);
	if (sudo_ev_add(closure->evbase, closure->write_ev,
		logsrvd_conf_get_sock_timeout(), false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server write event");
	    debug_return_bool(false);
	}
	closure->state = ERROR;
	debug_return_bool(true);
    }

    closure->state = RUNNING;
    debug_return_bool(true);
}

static bool
handle_alert(AlertMessage *msg, struct connection_closure *closure)
{
    struct timespec alert_time;
    debug_decl(handle_alert, SUDO_DEBUG_UTIL);

    /* Check that message is valid. */
    if (msg->alert_time == NULL || msg->reason == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid AlertMessage, alert_time: %p, reason: %p",
	    msg->alert_time, msg->reason);
	closure->errstr = _("invalid AlertMessage");
	debug_return_bool(false);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received AlertMessage", __func__);

    if (closure->relay_closure != NULL) {
	/* Forward AlertMessage to connected relay. */
	debug_return_bool(relay_alert(msg, closure));
    }

    if (msg->info_msgs != NULL && msg->n_info_msgs != 0) {
	closure->evlog = evlog_new(NULL, msg->info_msgs,
	    msg->n_info_msgs, closure);
	if (closure->evlog == NULL) {
	    closure->errstr = _("error parsing AlertMessage");
	    debug_return_bool(false);
	}
    }

    alert_time.tv_sec = msg->alert_time->tv_sec;
    alert_time.tv_nsec = msg->alert_time->tv_nsec;
    if (!eventlog_alert(closure->evlog, 0, &alert_time, msg->reason, NULL)) {
	closure->errstr = _("error logging alert event");
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

static bool
handle_iobuf(int iofd, IoBuffer *iobuf, struct connection_closure *closure)
{
    debug_decl(handle_iobuf, SUDO_DEBUG_UTIL);

    if (closure->state != RUNNING) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
	debug_return_bool(false);
    }
    if (!closure->log_io) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "not logging I/O");
	closure->errstr = _("protocol error");
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received IoBuffer", __func__);

    if (closure->relay_closure != NULL) {
	/* Forward IoBuffer to connected relay. */
	debug_return_bool(relay_iobuf(iofd, iobuf, closure));
    }

    /* Store IoBuffer in log. */
    if (store_iobuf(iofd, iobuf, closure) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "failed to store IoBuffer");
	closure->errstr = _("error writing IoBuffer");
	debug_return_bool(false);
    }

    /* Random drop is a debugging tool to test client restart. */
    if (random_drop > 0.0) {
	double randval = arc4random() / (double)UINT32_MAX;
	if (randval < random_drop) {
	    sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
		"randomly dropping connection (%f < %f)", randval, random_drop);
	    debug_return_bool(false);
	}
    }

    /* Schedule a commit point in 10 sec if one is not already pending. */
    if (!ISSET(closure->commit_ev->flags, SUDO_EVQ_INSERTED)) {
	struct timespec tv = { ACK_FREQUENCY, 0 };
	if (sudo_ev_add(closure->evbase, closure->commit_ev, &tv, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add commit point event");
	    debug_return_bool(false);
	}
    }

    debug_return_bool(true);
}

static bool
handle_winsize(ChangeWindowSize *msg, struct connection_closure *closure)
{
    debug_decl(handle_winsize, SUDO_DEBUG_UTIL);

    if (closure->state != RUNNING) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
	debug_return_bool(false);
    }
    if (!closure->log_io) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "not logging I/O");
	closure->errstr = _("protocol error");
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received ChangeWindowSize",
	__func__);

    /* Store new window size in log. */
    if (store_winsize(msg, closure) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "failed to store ChangeWindowSize");
	closure->errstr = _("error writing ChangeWindowSize");
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

static bool
handle_suspend(CommandSuspend *msg, struct connection_closure *closure)
{
    debug_decl(handle_suspend, SUDO_DEBUG_UTIL);

    if (closure->state != RUNNING) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
	debug_return_bool(false);
    }
    if (!closure->log_io) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "not logging I/O");
	closure->errstr = _("protocol error");
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received CommandSuspend",
	__func__);

    /* Store suspend signal in log. */
    if (store_suspend(msg, closure) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "failed to store CommandSuspend");
	closure->errstr = _("error writing CommandSuspend");
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

static bool
handle_client_hello(ClientHello *msg, struct connection_closure *closure)
{
    debug_decl(handle_client_hello, SUDO_DEBUG_UTIL);

    if (closure->state != INITIAL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received ClientHello",
	__func__);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: client ID %s",
	__func__, msg->client_id);

    debug_return_bool(true);
}

static bool
handle_client_message(uint8_t *buf, size_t len,
    struct connection_closure *closure)
{
    ClientMessage *msg;
    bool ret = false;
    debug_decl(handle_client_message, SUDO_DEBUG_UTIL);

    /* TODO: can we extract type_case without unpacking for relay case? */
    msg = client_message__unpack(NULL, len, buf);
    if (msg == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to unpack ClientMessage size %zu", len);
	debug_return_bool(false);
    }

    switch (msg->type_case) {
    case CLIENT_MESSAGE__TYPE_ACCEPT_MSG:
	ret = handle_accept(msg->u.accept_msg, closure);
	break;
    case CLIENT_MESSAGE__TYPE_REJECT_MSG:
	ret = handle_reject(msg->u.reject_msg, closure);
	break;
    case CLIENT_MESSAGE__TYPE_EXIT_MSG:
	ret = handle_exit(msg->u.exit_msg, closure);
	break;
    case CLIENT_MESSAGE__TYPE_RESTART_MSG:
	ret = handle_restart(msg->u.restart_msg, closure);
	break;
    case CLIENT_MESSAGE__TYPE_ALERT_MSG:
	ret = handle_alert(msg->u.alert_msg, closure);
	break;
    case CLIENT_MESSAGE__TYPE_TTYIN_BUF:
	ret = handle_iobuf(IOFD_TTYIN, msg->u.ttyin_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_TTYOUT_BUF:
	ret = handle_iobuf(IOFD_TTYOUT, msg->u.ttyout_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_STDIN_BUF:
	ret = handle_iobuf(IOFD_STDIN, msg->u.stdin_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_STDOUT_BUF:
	ret = handle_iobuf(IOFD_STDOUT, msg->u.stdout_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_STDERR_BUF:
	ret = handle_iobuf(IOFD_STDERR, msg->u.stderr_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_WINSIZE_EVENT:
	ret = handle_winsize(msg->u.winsize_event, closure);
	break;
    case CLIENT_MESSAGE__TYPE_SUSPEND_EVENT:
	ret = handle_suspend(msg->u.suspend_event, closure);
	break;
    case CLIENT_MESSAGE__TYPE_HELLO_MSG:
	ret = handle_client_hello(msg->u.hello_msg, closure);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected type_case value %d", msg->type_case);
	closure->errstr = _("unrecognized ClientMessage type");
	break;
    }
    client_message__free_unpacked(msg, NULL);

    debug_return_bool(ret);
}

static void
shutdown_cb(int unused, int what, void *v)
{
    struct sudo_event_base *base = v;
    debug_decl(shutdown_cb, SUDO_DEBUG_UTIL);

    sudo_ev_loopbreak(base);

    debug_return;
}

/*
 * Shut down active client connections if any, or exit immediately.
 */
static void
server_shutdown(struct sudo_event_base *base)
{
    struct connection_closure *closure, *next;
    struct sudo_event *ev;
    struct timespec tv = { 0, 0 };
    debug_decl(server_shutdown, SUDO_DEBUG_UTIL);

    if (TAILQ_EMPTY(&connections)) {
	sudo_ev_loopbreak(base);
	debug_return;
    }

    TAILQ_FOREACH_SAFE(closure, &connections, entries, next) {
	closure->state = SHUTDOWN;
	sudo_ev_del(base, closure->read_ev);
	if (closure->relay_closure != NULL) {
	    /* Connection being relayed, check for pending I/O. */
	    relay_shutdown(closure);
	} else if (closure->log_io) {
	    /* Schedule final commit point for the connection. */
	    if (sudo_ev_add(base, closure->commit_ev, &tv, false) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "unable to add commit point event");
	    }
	} else {
	    /* No commit point, close connection immediately. */
	    connection_closure_free(closure);
	}
    }

    if (!TAILQ_EMPTY(&connections)) {
	/* We need a timed event to exit even if clients time out. */
	ev = sudo_ev_alloc(-1, SUDO_EV_TIMEOUT, shutdown_cb, base);
	if (ev != NULL) {
	    tv.tv_sec = SHUTDOWN_TIMEO;
	    if (sudo_ev_add(base, ev, &tv, false) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "unable to add shutdown event");
	    }
	}
    }

    debug_return;
}

/*
 * Send a server message to the client.
 */
static void
server_msg_cb(int fd, int what, void *v)
{
    struct connection_closure *closure = v;
    struct connection_buffer *buf;
    ssize_t nwritten;
    debug_decl(server_msg_cb, SUDO_DEBUG_UTIL);

    /* For TLS we may need to write as part of SSL_read(). */
    if (closure->read_instead_of_write) {
	closure->read_instead_of_write = false;
	/* Delete write event if it was only due to SSL_read(). */
	if (closure->temporary_write_event) {
	    closure->temporary_write_event = false;
	    sudo_ev_del(closure->evbase, closure->write_ev);
	}
	client_msg_cb(fd, what, v);
	debug_return;
    }

    if (what == SUDO_EV_TIMEOUT) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "timed out writing to client (%s)", closure->ipaddr);
        goto finished;
    }

    if ((buf = TAILQ_FIRST(&closure->write_bufs)) == NULL) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "missing write buffer");
        goto finished;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: sending %u bytes to client (%s)",
	__func__, buf->len - buf->off, closure->ipaddr);

#if defined(HAVE_OPENSSL)
    if (closure->ssl != NULL) {
        nwritten = SSL_write(closure->ssl, buf->data + buf->off,
	    buf->len - buf->off);
        if (nwritten <= 0) {
            int err = SSL_get_error(closure->ssl, nwritten);
            switch (err) {
                case SSL_ERROR_WANT_READ:
		    /* ssl wants to read, read event always active */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_write returns SSL_ERROR_WANT_READ");
		    /* Redirect persistent read event to finish SSL_write() */
		    closure->write_instead_of_read = true;
                    debug_return;
                case SSL_ERROR_WANT_WRITE:
		    /* ssl wants to write more, write event remains active */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_write returns SSL_ERROR_WANT_WRITE");
                    debug_return;
		case SSL_ERROR_SYSCALL:
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"unexpected error during SSL_write(): %d (%s)",
			err, strerror(errno));
		    goto finished;
                default:
                    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                        "unexpected error during SSL_write(): %d (%s)",
                        err, ERR_error_string(ERR_get_error(), NULL));
                    goto finished;
            }
        }
    } else
#endif
    {
	nwritten = send(fd, buf->data + buf->off, buf->len - buf->off, 0);
    }

    if (nwritten == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to send %u bytes", buf->len - buf->off);
	goto finished;
    }
    buf->off += nwritten;

    if (buf->off == buf->len) {
	/* sent entire message, move buf to free list */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: finished sending %u bytes to client", __func__, buf->len);
	buf->off = 0;
	buf->len = 0;
	TAILQ_REMOVE(&closure->write_bufs, buf, entries);
	TAILQ_INSERT_TAIL(&closure->free_bufs, buf, entries);
	if (TAILQ_EMPTY(&closure->write_bufs)) {
	    /* Write queue empty, check state. */
	    sudo_ev_del(closure->evbase, closure->write_ev);
	    if (closure->state == FINISHED || closure->state == SHUTDOWN ||
		    closure->state == ERROR)
		goto finished;
	}
    }
    debug_return;

finished:
    connection_closure_free(closure);
    debug_return;
}

/*
 * Receive client message(s).
 */
static void
client_msg_cb(int fd, int what, void *v)
{
    struct connection_closure *closure = v;
    struct connection_buffer *buf = &closure->read_buf;
    uint32_t msg_len;
    ssize_t nread;
    debug_decl(client_msg_cb, SUDO_DEBUG_UTIL);

    /* For TLS we may need to read as part of SSL_write(). */
    if (closure->write_instead_of_read) {
	closure->write_instead_of_read = false;
	server_msg_cb(fd, what, v);
	debug_return;
    }

    if (what == SUDO_EV_TIMEOUT) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "timed out reading from client (%s)", closure->ipaddr);
        goto close_connection;
    }

#if defined(HAVE_OPENSSL)
    if (closure->ssl != NULL) {
       nread = SSL_read(closure->ssl, buf->data + buf->len, buf->size);
        if (nread <= 0) {
            int err = SSL_get_error(closure->ssl, nread);
            switch (err) {
		case SSL_ERROR_ZERO_RETURN:
		    /* ssl connection shutdown cleanly */
		    nread = 0;
		    break;
                case SSL_ERROR_WANT_READ:
		    /* ssl wants to read more, read event is always active */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_read returns SSL_ERROR_WANT_READ");
		    /* Read event is always active. */
                    debug_return;
                case SSL_ERROR_WANT_WRITE:
		    /* ssl wants to write, schedule a write if not pending */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_read returns SSL_ERROR_WANT_WRITE");
		    if (!sudo_ev_pending(closure->write_ev, SUDO_EV_WRITE, NULL)) {
			/* Enable a temporary write event. */
			if (sudo_ev_add(closure->evbase, closure->write_ev,
			    logsrvd_conf_get_sock_timeout(), false) == -1) {
			    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
				"unable to add event to queue");
			    closure->errstr = _("unable to allocate memory");
			    goto send_error;
			}
			closure->temporary_write_event = true;
		    }
		    /* Redirect write event to finish SSL_read() */
		    closure->read_instead_of_write = true;
                    debug_return;
		case SSL_ERROR_SYSCALL:
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"unexpected error during SSL_read(): %d (%s)",
			err, strerror(errno));
		    goto close_connection;
                default:
                    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                        "unexpected error during SSL_read(): %d (%s)",
                        err, ERR_error_string(ERR_get_error(), NULL));
                        goto close_connection;
            }
        }
    } else
#endif
    {
        nread = recv(fd, buf->data + buf->len, buf->size - buf->len, 0);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received %zd bytes from client %s",
	__func__, nread, closure->ipaddr);
    switch (nread) {
    case -1:
	if (errno == EAGAIN)
	    debug_return;
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to receive %u bytes", buf->size - buf->len);
	goto close_connection;
    case 0:
        if (closure->state != FINISHED) {
            sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
                "unexpected EOF");
        }
        goto close_connection;
    default:
	break;
    }
    buf->len += nread;

    while (buf->len - buf->off >= sizeof(msg_len)) {
	/* Read wire message size (uint32_t in network byte order). */
	memcpy(&msg_len, buf->data + buf->off, sizeof(msg_len));
	msg_len = ntohl(msg_len);

	if (msg_len > MESSAGE_SIZE_MAX) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"client message too large: %u", msg_len);
	    closure->errstr = _("client message too large");
	    goto send_error;
	}

	if (msg_len + sizeof(msg_len) > buf->len - buf->off) {
	    /* Incomplete message, we'll read the rest next time. */
	    if (!expand_buf(buf, msg_len + sizeof(msg_len))) {
		closure->errstr = _("unable to allocate memory");
		goto send_error;
	    }
	    debug_return;
	}

	/* Parse ClientMessage (could be zero bytes). */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: parsing ClientMessage, size %u", __func__, msg_len);
	buf->off += sizeof(msg_len);
	if (!handle_client_message(buf->data + buf->off, msg_len, closure)) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to parse ClientMessage, size %u", msg_len);
	    closure->errstr = _("invalid ClientMessage");
	    goto send_error;
	}
	buf->off += msg_len;
    }
    buf->len -= buf->off;
    buf->off = 0;

    if (closure->state == FINISHED)
	goto close_connection;

    debug_return;
send_error:
    /*
     * Try to send client an error message before closing connection.
     * If we are already in an error state, just give up.
     */
    if (closure->state == ERROR)
	goto close_connection;
    if (closure->errstr == NULL || !fmt_error_message(closure->errstr, closure))
	goto close_connection;
    sudo_ev_del(closure->evbase, closure->read_ev);
    if (sudo_ev_add(closure->evbase, closure->write_ev,
	    logsrvd_conf_get_sock_timeout(), false) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to add server write event");
	goto close_connection;
    }
    closure->state = ERROR;
    debug_return;
close_connection:
    connection_closure_free(closure);
    debug_return;
}

/*
 * Format and schedule a commit_point message.
 */
bool
schedule_commit_point(TimeSpec *commit_point,
    struct connection_closure *closure)
{
    ServerMessage msg = SERVER_MESSAGE__INIT;
    debug_decl(schedule_commit_point, SUDO_DEBUG_UTIL);

    /* Send the client an acknowledgement of what has been committed to disk. */
    msg.u.commit_point = commit_point;
    msg.type_case = SERVER_MESSAGE__TYPE_COMMIT_POINT;

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: sending commit point [%lld, %ld]",
	__func__, (long long)commit_point->tv_sec, (long)commit_point->tv_nsec);

    if (!fmt_server_message(closure, &msg)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to format ServerMessage (commit point)");
	goto bad;
    }
    if (sudo_ev_add(closure->evbase, closure->write_ev,
        logsrvd_conf_get_sock_timeout(), false) == -1) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "unable to add server write event");
        goto bad;
    }

    if (closure->state == EXITED)
	closure->state = FINISHED;
    debug_return_bool(true);
bad:
    debug_return_bool(false);
}

/*
 * Time-based event that fires periodically to report to the client
 * what has been committed to disk.
 */
static void
server_commit_cb(int unused, int what, void *v)
{
    struct connection_closure *closure = v;
    TimeSpec commit_point = TIME_SPEC__INIT;
    debug_decl(server_commit_cb, SUDO_DEBUG_UTIL);

    commit_point.tv_sec = closure->elapsed_time.tv_sec;
    commit_point.tv_nsec = closure->elapsed_time.tv_nsec;
    if (!schedule_commit_point(&commit_point, closure))
	connection_closure_free(closure);

    debug_return;
}

/*
 * Begin the sudo logserver protocol.
 * When we enter the event loop the ServerHello message will be written
 * and any pending ClientMessage will be read.
 */
bool
start_protocol(struct connection_closure *closure)
{
    const struct timespec *timeout = logsrvd_conf_get_sock_timeout();
    debug_decl(start_protocol, SUDO_DEBUG_UTIL);

    if (closure->relay_closure != NULL && closure->relay_closure->relays != NULL) {
	/* No longer need the stashed relays list. */
	address_list_delref(closure->relay_closure->relays);
	closure->relay_closure->relays = NULL;
	closure->relay_closure->relay_addr = NULL;
    }

    if (!fmt_hello_message(closure))
	debug_return_bool(false);

    if (sudo_ev_add(closure->evbase, closure->write_ev, timeout, false) == -1)
	debug_return_bool(false);

    /* No read timeout, client messages may happen at arbitrary times. */
    if (sudo_ev_add(closure->evbase, closure->read_ev, NULL, false) == -1)
	debug_return_bool(false);

    debug_return_bool(true);
}

#if defined(HAVE_OPENSSL)
static int
verify_peer_identity(int preverify_ok, X509_STORE_CTX *ctx)
{
    HostnameValidationResult result;
    struct connection_closure *closure;
    SSL *ssl;
    X509 *current_cert;
    X509 *peer_cert;
    debug_decl(verify_peer_identity, SUDO_DEBUG_UTIL);

    /* if pre-verification of the cert failed, just propagate that result back */
    if (preverify_ok != 1) {
        debug_return_int(0);
    }

    /* since this callback is called for each cert in the chain,
     * check that current cert is the peer's certificate
     */
    current_cert = X509_STORE_CTX_get_current_cert(ctx);
    peer_cert = X509_STORE_CTX_get0_cert(ctx);

    if (current_cert != peer_cert) {
        debug_return_int(1);
    }

    /* read out the attached object (closure) from the ssl connection object */
    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    closure = (struct connection_closure *)SSL_get_ex_data(ssl, 1);

    result = validate_hostname(peer_cert, closure->ipaddr, closure->ipaddr, 1);

    switch(result)
    {
        case MatchFound:
            debug_return_int(1);
        default:
            sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
                "hostname validation failed");
            debug_return_int(0);
    }
}

/*
 * Set the TLS verify callback to verify_peer_identity().
 */
static void
set_tls_verify_peer(void)
{
    SSL_CTX *ssl_ctx = logsrvd_get_tls_ctx();
    const struct logsrvd_tls_config *tls_config = logsrvd_get_tls_config();
    debug_decl(set_tls_verify_peer, SUDO_DEBUG_UTIL);

    if (ssl_ctx != NULL) {
	if (tls_config->check_peer) {
	    /* Verify server cert during the handshake. */
	    SSL_CTX_set_verify(ssl_ctx,
		SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		verify_peer_identity);
	}
    }

    debug_return;
}

static void
tls_handshake_cb(int fd, int what, void *v)
{
    struct connection_closure *closure = v;
    debug_decl(tls_handshake_cb, SUDO_DEBUG_UTIL);

    if (what == SUDO_EV_TIMEOUT) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "TLS handshake timed out");
        goto bad;
    }

    int handshake_status = SSL_accept(closure->ssl);
    int err = SSL_ERROR_NONE;
    switch (err = SSL_get_error(closure->ssl, handshake_status)) {
        case SSL_ERROR_NONE:
	    /* ssl handshake was successful */
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"TLS handshake successful");
            break;
        case SSL_ERROR_WANT_READ:
	    /* ssl handshake is ongoing, re-schedule the SSL_accept() call */
	    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
		"SSL_accept returns SSL_ERROR_WANT_READ");
	    if (what != SUDO_EV_READ) {
		if (sudo_ev_set(closure->ssl_accept_ev, closure->sock,
			SUDO_EV_READ, tls_handshake_cb, closure) == -1) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"unable to set ssl_accept_ev to SUDO_EV_READ");
		    goto bad;
		}
	    }
            if (sudo_ev_add(closure->evbase, closure->ssl_accept_ev,
                logsrvd_conf_get_sock_timeout(), false) == -1) {
                sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                    "unable to add ssl_accept_ev to queue");
                goto bad;
            }
            debug_return;
        case SSL_ERROR_WANT_WRITE:
	    /* ssl handshake is ongoing, re-schedule the SSL_accept() call */
	    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
		"SSL_accept returns SSL_ERROR_WANT_WRITE");
	    if (what != SUDO_EV_WRITE) {
		if (sudo_ev_set(closure->ssl_accept_ev, closure->sock,
			SUDO_EV_WRITE, tls_handshake_cb, closure) == -1) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
			"unable to set ssl_accept_ev to SUDO_EV_WRITE");
		    goto bad;
		}
	    }
            if (sudo_ev_add(closure->evbase, closure->ssl_accept_ev,
		    logsrvd_conf_get_sock_timeout(), false) == -1) {
                sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                    "unable to add ssl_accept_ev to queue");
                goto bad;
            }
            debug_return;
	case SSL_ERROR_SYSCALL:
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "unexpected error during TLS handshake: %d (%s)",
                err, strerror(errno));
            goto bad;
        default:
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "unexpected error during TLS handshake: %d (%s)",
                err, ERR_error_string(ERR_get_error(), NULL));
            goto bad;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
        "TLS version: %s, negotiated cipher suite: %s",
        SSL_get_version(closure->ssl),
        SSL_get_cipher(closure->ssl));

    /* Start the actual protocol now that the TLS handshake is complete. */
    if (logsrvd_conf_relay() != NULL) {
	if (!connect_relay(closure))
	    goto bad;
    } else {
	if (!start_protocol(closure))
	    goto bad;
    }

    debug_return;
bad:
    connection_closure_free(closure);
    debug_return;
}
#endif /* HAVE_OPENSSL */

/*
 * Allocate a new connection closure.
 */
static struct connection_closure *
connection_closure_alloc(int sock, bool tls, struct sudo_event_base *base)
{
    struct connection_closure *closure;
    debug_decl(connection_closure_alloc, SUDO_DEBUG_UTIL);

    if ((closure = calloc(1, sizeof(*closure))) == NULL)
	debug_return_ptr(NULL);

    closure->iolog_dir_fd = -1;
    closure->sock = sock;
    closure->evbase = base;
    TAILQ_INIT(&closure->write_bufs);
    TAILQ_INIT(&closure->free_bufs);

    TAILQ_INSERT_TAIL(&connections, closure, entries);

    closure->read_buf.size = 64 * 1024;
    closure->read_buf.data = malloc(closure->read_buf.size);
    if (closure->read_buf.data == NULL)
	goto bad;

    closure->commit_ev = sudo_ev_alloc(-1, SUDO_EV_TIMEOUT,
	server_commit_cb, closure);
    if (closure->commit_ev == NULL)
	goto bad;

    closure->read_ev = sudo_ev_alloc(sock, SUDO_EV_READ|SUDO_EV_PERSIST,
	client_msg_cb, closure);
    if (closure->read_ev == NULL)
	goto bad;

    closure->write_ev = sudo_ev_alloc(sock, SUDO_EV_WRITE|SUDO_EV_PERSIST,
	server_msg_cb, closure);
    if (closure->write_ev == NULL)
	goto bad;

#if defined(HAVE_OPENSSL)
    if (tls) {
	closure->ssl_accept_ev = sudo_ev_alloc(sock, SUDO_EV_READ,
	    tls_handshake_cb, closure);
	if (closure->ssl_accept_ev == NULL)
	    goto bad;
    }
#endif

    debug_return_ptr(closure);
bad:
    connection_closure_free(closure);
    debug_return_ptr(NULL);
}

/*
 * New connection.
 * Allocate a connection closure and optionally perform TLS handshake.
 */
static bool
new_connection(int sock, bool tls, const struct sockaddr *sa,
    struct sudo_event_base *evbase)
{
    struct connection_closure *closure;
    debug_decl(new_connection, SUDO_DEBUG_UTIL);

    if ((closure = connection_closure_alloc(sock, tls, evbase)) == NULL)
	goto bad;

    /* store the peer's IP address in the closure object */
    if (sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &sin->sin_addr, closure->ipaddr,
            sizeof(closure->ipaddr));
#if defined(HAVE_STRUCT_IN6_ADDR)
    } else if (sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &sin6->sin6_addr, closure->ipaddr,
            sizeof(closure->ipaddr));
#endif /* HAVE_STRUCT_IN6_ADDR */
    } else {
	errno = EAFNOSUPPORT;
        sudo_warn("%s", U_("unable to get remote IP addr"));
        goto bad;
    }
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"connection from %s", closure->ipaddr);

#if defined(HAVE_OPENSSL)
    /* If TLS is enabled, perform the TLS handshake first. */
    if (tls) {
        /* Create the SSL object for the closure and attach it to the socket */
        if ((closure->ssl = SSL_new(logsrvd_get_tls_ctx())) == NULL) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "unable to create new ssl object: %s",
                ERR_error_string(ERR_get_error(), NULL));
            goto bad;
        }

        if (SSL_set_fd(closure->ssl, closure->sock) != 1) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "unable to set fd for TLS: %s",
                ERR_error_string(ERR_get_error(), NULL));
            goto bad;
        }

        /* attach the closure object to the ssl connection object to make it
        available during hostname matching
        */
        if (SSL_set_ex_data(closure->ssl, 1, closure) <= 0) {
            sudo_warnx(U_("Unable to attach user data to the ssl object: %s"),
                ERR_error_string(ERR_get_error(), NULL));
            goto bad;
        }

        /* Enable SSL_accept to begin handshake with client. */
        if (sudo_ev_add(evbase, closure->ssl_accept_ev,
		logsrvd_conf_get_sock_timeout(), false) == -1) {
            sudo_fatal("%s", U_("unable to add event to queue"));
            goto bad;
        }
    }
#endif
    /* If no TLS handshake, start the protocol immediately. */
    if (!tls) {
	if (logsrvd_conf_relay() != NULL) {
	    if (!connect_relay(closure))
		goto bad;
	} else {
	    if (!start_protocol(closure))
		goto bad;
	}
    }

    debug_return_bool(true);
bad:
    connection_closure_free(closure);
    debug_return_bool(false);
}

static int
create_listener(struct server_address *addr)
{
    int flags, on, sock;
    const char *family = "inet4";
    debug_decl(create_listener, SUDO_DEBUG_UTIL);

    if ((sock = socket(addr->sa_un.sa.sa_family, SOCK_STREAM, 0)) == -1) {
	sudo_warn("socket");
	goto bad;
    }
    on = 1;
#ifdef HAVE_STRUCT_IN6_ADDR
    if (addr->sa_un.sa.sa_family == AF_INET6) {
	family = "inet6";
# ifdef IPV6_V6ONLY
	/* Disable IPv4-mapped IPv6 addresses. */
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1)
	    sudo_warn("IPV6_V6ONLY");
# endif
    }
#endif
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
	sudo_warn("SO_REUSEADDR");
    if (bind(sock, &addr->sa_un.sa, addr->sa_size) == -1) {
	/* TODO: only warn once for IPv4 and IPv6 or disambiguate */
	sudo_warn("%s (%s)", addr->sa_str, family);
	goto bad;
    }
    if (listen(sock, SOMAXCONN) == -1) {
	sudo_warn("listen");
	goto bad;
    }
    flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
	sudo_warn("fcntl(O_NONBLOCK)");
	goto bad;
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "listening on %s (%s)", addr->sa_str,
	family);

    debug_return_int(sock);
bad:
    if (sock != -1)
	close(sock);
    debug_return_int(-1);
}

static void
listener_cb(int fd, int what, void *v)
{
    struct listener *l = v;
    struct sudo_event_base *evbase = sudo_ev_get_base(l->ev);
    union sockaddr_union s_un;
    socklen_t salen = sizeof(s_un);
    int sock;
    debug_decl(listener_cb, SUDO_DEBUG_UTIL);

    sock = accept(fd, &s_un.sa, &salen);
    if (sock != -1) {
	/* set keepalive socket option on socket returned by accept */
	if (logsrvd_conf_tcp_keepalive()) {
	    int keepalive = 1;
	    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
		sizeof(keepalive)) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		    "unable to set SO_KEEPALIVE option");
	    }
	}
	if (!new_connection(sock, l->tls, &s_un.sa, evbase)) {
	    /* TODO: pause accepting on ENOMEM */
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to start new connection");
	}
    } else {
	if (errno != EAGAIN) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"unable to accept new connection");
	}
	/* TODO: pause accepting on ENFILE and EMFILE */
    }

    debug_return;
}

static bool
register_listener(struct server_address *addr, struct sudo_event_base *evbase)
{
    struct listener *l;
    int sock;
    debug_decl(register_listener, SUDO_DEBUG_UTIL);

    sock = create_listener(addr);
    if (sock == -1)
	debug_return_bool(false);

    /* TODO: make non-fatal */
    if ((l = malloc(sizeof(*l))) == NULL)
	sudo_fatal(NULL);
    l->sock = sock;
    l->tls = addr->tls;
    l->ev = sudo_ev_alloc(sock, SUDO_EV_READ|SUDO_EV_PERSIST, listener_cb, l);
    if (l->ev == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(evbase, l->ev, NULL, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));
    TAILQ_INSERT_TAIL(&listeners, l, entries);

    debug_return_bool(true);
}

/*
 * Register listeners and init the TLS context.
 */
static bool
server_setup(struct sudo_event_base *base)
{
    struct server_address *addr;
    struct listener *l;
    int nlisteners = 0;
    bool ret;
    debug_decl(server_setup, SUDO_DEBUG_UTIL);

    /* Free old listeners (if any) and register new ones. */
    while ((l = TAILQ_FIRST(&listeners)) != NULL) {
	TAILQ_REMOVE(&listeners, l, entries);
	sudo_ev_free(l->ev);
	close(l->sock);
	free(l);
    }
    TAILQ_FOREACH(addr, logsrvd_conf_listen_address(), entries) {
	nlisteners += register_listener(addr, base);
    }
    ret = nlisteners > 0;

#if defined(HAVE_OPENSSL)
    if (ret)
	set_tls_verify_peer();
#endif

    debug_return_bool(ret);
}

/*
 * Reload config and re-initialize listeners and TLS context.
 */
static void
server_reload(struct sudo_event_base *base)
{
    debug_decl(server_reload, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO, "reloading server config");
    if (logsrvd_conf_read(conf_file)) {
	/* Re-initialize listeners and TLS context. */
	if (!server_setup(base))
	    sudo_fatalx("%s", U_("unable setup listen socket"));

	/* Re-read sudo.conf and re-initialize debugging. */
	sudo_debug_deregister(logsrvd_debug_instance);
	logsrvd_debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;
	if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) != -1) {
	    logsrvd_debug_instance = sudo_debug_register(getprogname(),
		NULL, NULL, sudo_conf_debug_files(getprogname()));
	}
    }

    debug_return;
}

static void
signal_cb(int signo, int what, void *v)
{
    struct sudo_event_base *base = v;
    debug_decl(signal_cb, SUDO_DEBUG_UTIL);

    switch (signo) {
	case SIGHUP:
	    server_reload(base);
	    break;
	case SIGINT:
	case SIGTERM:
	    /* Shut down active connections. */
	    server_shutdown(base);
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unexpected signal %d", signo);
	    break;
    }

    debug_return;
}

static void
register_signal(int signo, struct sudo_event_base *base)
{
    struct sudo_event *ev;
    debug_decl(register_signal, SUDO_DEBUG_UTIL);

    ev = sudo_ev_alloc(signo, SUDO_EV_SIGNAL, signal_cb, base);
    if (ev == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(base, ev, NULL, false) == -1)
	sudo_fatal("%s", U_("unable to add event to queue"));

    debug_return;
}

static void
logsrvd_cleanup(void)
{
    /* TODO: cleanup like on signal */
    return;
}

/*
 * Write the process ID into a file, typically /var/run/sudo/sudo_logsrvd.pid.
 * If the parent directory doesn't exist, it will be created.
 */
static void
write_pidfile(void)
{
    FILE *fp;
    int fd;
    bool success;
    char *pid_file = (char *)logsrvd_conf_pid_file();
    debug_decl(write_pidfile, SUDO_DEBUG_UTIL);

    if (pid_file == NULL)
	debug_return;

    /* sudo_mkdir_parents() modifies the path but restores it before return. */
    success = sudo_mkdir_parents(pid_file, ROOT_UID, ROOT_GID,
	S_IRWXU|S_IXGRP|S_IXOTH, false);
    if (success) {
	fd = open(pid_file, O_WRONLY|O_CREAT|O_NOFOLLOW, 0644);
	if (fd == -1 || (fp = fdopen(fd, "w")) == NULL) {
	    sudo_warn("%s", pid_file);
	    if (fd != -1)
		close(fd);
	} else {
	    fprintf(fp, "%u\n", (unsigned int)getpid());
	    fflush(fp);
	    if (ferror(fp))
		sudo_warn("%s", pid_file);
	    fclose(fp);
	}
    }
    debug_return;
}

/*
 * Fork, detach from the terminal and write pid file unless nofork set.
 */
static void
daemonize(bool nofork)
{
    int fd;
    debug_decl(daemonize, SUDO_DEBUG_UTIL);

    if (!nofork) {
	switch (fork()) {
	case -1:
	    sudo_fatal("fork");
	case 0:
	    /* child */
	    break;
	default:
	    /* parent, exit */
	    _exit(EXIT_SUCCESS);
	}

	/* detach from terminal and write pid file. */
	if (setsid() == -1)
	    sudo_fatal("setsid");
	write_pidfile();
    }

    if (chdir("/") == -1)
	sudo_warn("chdir(\"/\")");
    if ((fd = open(_PATH_DEVNULL, O_RDWR)) != -1) {
	(void) dup2(fd, STDIN_FILENO);
	(void) dup2(fd, STDOUT_FILENO);
	(void) dup2(fd, STDERR_FILENO);
	if (fd > STDERR_FILENO)
	    (void) close(fd);
    }

    debug_return;
}

static void
usage(bool fatal)
{
    fprintf(stderr, "usage: %s [-n] [-f conf_file] [-R percentage]\n",
	getprogname());
    if (fatal)
	exit(EXIT_FAILURE);
}

static void
help(void)
{
    printf("%s - %s\n\n", getprogname(), _("sudo log server"));
    usage(false);
    printf("\n%s\n", _("Options:"));
    printf("  -f, --file            %s\n",
	_("path to configuration file"));
    printf("  -h, --help            %s\n",
        _("display help message and exit"));
    printf("  -n, --no-fork         %s\n",
	_("do not fork, run in the foreground"));
    printf("  -R, --random-drop     %s\n",
	_("percent chance connections will drop"));
    printf("  -V, --version         %s\n",
	_("display version information and exit"));
    putchar('\n');
    exit(EXIT_SUCCESS);
}

static const char short_opts[] = "f:hnR:V";
static struct option long_opts[] = {
    { "file",		required_argument,	NULL,	'f' },
    { "help",		no_argument,		NULL,	'h' },
    { "no-fork",	no_argument,		NULL,	'n' },
    { "random-drop",	required_argument,	NULL,	'R' },
    { "version",	no_argument,		NULL,	'V' },
    { NULL,		no_argument,		NULL,	0 },
};

sudo_dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    struct sudo_event_base *evbase;
    bool nofork = false;
    char *ep;
    int ch;
    debug_decl_vars(main, SUDO_DEBUG_MAIN);

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    {
	extern char *malloc_options;
	malloc_options = "S";
    }
#endif

    initprogname(argc > 0 ? argv[0] : "sudo_logsrvd");
    setlocale(LC_ALL, "");
    bindtextdomain("sudo", LOCALEDIR); /* XXX - add logsrvd domain */
    textdomain("sudo");

    /* Register fatal/fatalx callback. */
    sudo_fatal_callback_register(logsrvd_cleanup);

    /* Read sudo.conf and initialize the debug subsystem. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
        exit(EXIT_FAILURE);
    logsrvd_debug_instance = sudo_debug_register(getprogname(), NULL, NULL,
        sudo_conf_debug_files(getprogname()));

    if (protobuf_c_version_number() < 1003000)
	sudo_fatalx("%s", U_("Protobuf-C version 1.3 or higher required"));

    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	case 'f':
	    conf_file = optarg;
	    break;
	case 'h':
	    help();
	    break;
	case 'n':
	    nofork = true;
	    break;
	case 'R':
	    /* random connection drop probability as a percentage (debug) */
            errno = 0;
	    random_drop = strtod(optarg, &ep);
            if (*ep != '\0' || errno != 0)
                sudo_fatalx(U_("invalid random drop value: %s"), optarg);
	    random_drop /= 100.0;	/* convert from percentage */
	    break;
	case 'V':
	    (void)printf(_("%s version %s\n"), getprogname(),
		PACKAGE_VERSION);
	    return 0;
	default:
	    usage(true);
	}
    }

    /* Read sudo_logsrvd.conf */
    if (!logsrvd_conf_read(conf_file))
        exit(EXIT_FAILURE);

    if ((evbase = sudo_ev_base_alloc()) == NULL)
	sudo_fatal(NULL);

    /* Initialize listeners and TLS context. */
    if (!server_setup(evbase))
	sudo_fatalx("%s", U_("unable setup listen socket"));

    register_signal(SIGHUP, evbase);
    register_signal(SIGINT, evbase);
    register_signal(SIGTERM, evbase);

    /* Point of no return. */
    daemonize(nofork);
    signal(SIGPIPE, SIG_IGN);

    sudo_ev_dispatch(evbase);
    if (!nofork && logsrvd_conf_pid_file() != NULL)
	unlink(logsrvd_conf_pid_file());
    logsrvd_conf_cleanup();

    debug_return_int(1);
}
