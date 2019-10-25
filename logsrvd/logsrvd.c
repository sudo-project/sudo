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

#include "log_server.pb-c.h"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */
#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_event.h"
#include "sudo_queue.h"
#include "sudo_util.h"
#include "sudo_fatal.h"
#include "logsrvd.h"

TAILQ_HEAD(connection_list, connection_closure);
static struct connection_list connections = TAILQ_HEAD_INITIALIZER(connections);
static const char server_id[] = "Sudo Audit Server 0.1";

/*
 * Proof of concept audit server.
 * Currently only handle a single connection at a time.
 * TODO: use atomic I/O when we know the packed buffer size.
 */

/*
 * Free a struct connection_closure container and its contents.
 */
static void
connection_closure_free(struct connection_closure *closure)
{
    debug_decl(connection_closure_free, SUDO_DEBUG_UTIL)

    if (closure != NULL) {
	bool shutting_down = closure->state == SHUTDOWN;

	TAILQ_REMOVE(&connections, closure, entries);
	close(closure->sock);
	iolog_close(closure);
	sudo_ev_free(closure->commit_ev);
	sudo_ev_free(closure->read_ev);
	sudo_ev_free(closure->write_ev);
	free(closure->read_buf.data);
	free(closure->write_buf.data);
	free(closure->iolog_dir);
	free(closure);

	if (shutting_down && TAILQ_EMPTY(&connections))
	    sudo_ev_loopbreak(NULL);
    }

    debug_return;
}

static bool
fmt_server_message(struct connection_buffer *buf, ServerMessage *msg)
{
    uint16_t msg_len;
    bool ret = false;
    size_t len;
    debug_decl(fmt_server_message, SUDO_DEBUG_UTIL)

    if (buf->len != 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "pending write, unable to format ServerMessage");
	debug_return_bool(false);
    }

    len = server_message__get_packed_size(msg);
    if (len > UINT16_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "server message too large: %zu", len);
        goto done;
    }
    /* Wire message size is used for length encoding, precedes message. */
    msg_len = htons((uint16_t)len);
    len += sizeof(msg_len);

    if (len > buf->size) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "server message too big for buffer, %zu > %u", len, buf->size);
	goto done;
    }

    memcpy(buf->data, &msg_len, sizeof(msg_len));
    server_message__pack(msg, buf->data + sizeof(msg_len));
    buf->len = len;
    ret = true;

done:
    debug_return_bool(ret);
}

static bool
fmt_hello_message(struct connection_buffer *buf)
{
    ServerMessage msg = SERVER_MESSAGE__INIT;
    ServerHello hello = SERVER_HELLO__INIT;
    debug_decl(fmt_hello_message, SUDO_DEBUG_UTIL)

    /* TODO: implement redirect and servers array.  */
    hello.server_id = (char *)server_id;
    msg.hello = &hello;
    msg.type_case = SERVER_MESSAGE__TYPE_HELLO;

    debug_return_bool(fmt_server_message(buf, &msg));
}

static bool
fmt_log_id_message(const char *id, struct connection_buffer *buf)
{
    ServerMessage msg = SERVER_MESSAGE__INIT;
    debug_decl(fmt_log_id_message, SUDO_DEBUG_UTIL)

    msg.log_id = (char *)id;
    msg.type_case = SERVER_MESSAGE__TYPE_LOG_ID;

    debug_return_bool(fmt_server_message(buf, &msg));
}

static bool
fmt_error_message(const char *errstr, struct connection_buffer *buf)
{
    ServerMessage msg = SERVER_MESSAGE__INIT;
    debug_decl(fmt_error_message, SUDO_DEBUG_UTIL)

    msg.error = (char *)errstr;
    msg.type_case = SERVER_MESSAGE__TYPE_ERROR;

    debug_return_bool(fmt_server_message(buf, &msg));
}

/*
 * Parse an ExecMessage
 */
static bool
handle_exec(ExecMessage *msg, struct connection_closure *closure)
{
    debug_decl(handle_exec, SUDO_DEBUG_UTIL)

    if (closure->state != INITIAL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	debug_return_bool(false);
    }

    /* Sanity check message. */
    if (msg->start_time == NULL || msg->n_info_msgs == 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid ExecMessage, start_time: %p, n_info_msgs: %zu",
	    msg->start_time, msg->n_info_msgs);
	debug_return_bool(false);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received ExecMessage", __func__);

    /* Save start time. */
    closure->start_time.tv_sec = msg->start_time->tv_sec;
    closure->start_time.tv_nsec = msg->start_time->tv_nsec;

    /* Create I/O log info file and parent directories. */
    if (!iolog_init(msg, closure))
	debug_return_bool(false);

    /* Send log ID to client for restarting connectoins. */
    if (!fmt_log_id_message(closure->iolog_dir, &closure->write_buf))
	debug_return_bool(false);
    if (sudo_ev_add(NULL, closure->write_ev, NULL, false) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to add server write event");
	debug_return_bool(false);
    }

    closure->state = RUNNING;
    debug_return_bool(true);
}

static bool
handle_exit(ExitMessage *msg, struct connection_closure *closure)
{
    struct timespec tv = { 0, 0 };
    debug_decl(handle_exit, SUDO_DEBUG_UTIL)

    if (closure->state != RUNNING) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	debug_return_bool(false);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received ExitMessage", __func__);

    /* Sudo I/O logs don't store this info. */
    if (msg->signal != NULL && msg->signal[0] != '\0') {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "command was killed by SIG%s%s", msg->signal,
	    msg->dumped_core ? " (core dumped)" : "");
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "command exited with %d", msg->exit_value);
    }

    /* No more data, command exited. */
    closure->state = EXITED;
    sudo_ev_del(NULL, closure->read_ev);

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: elapsed time: %lld, %ld",
	__func__, (long long)closure->elapsed_time.tv_sec,
	closure->elapsed_time.tv_nsec);

    /* Schedule the final commit point event immediately. */
    if (sudo_ev_add(NULL, closure->commit_ev, &tv, false) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to add commit point event");
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

static bool
handle_restart(RestartMessage *msg, struct connection_closure *closure)
{
    debug_decl(handle_restart, SUDO_DEBUG_UTIL)

    if (closure->state != INITIAL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	debug_return_bool(false);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received RestartMessage for %s",
	__func__, msg->log_id);

    if (!iolog_restart(msg, closure)) {
	sudo_debug_printf(SUDO_DEBUG_WARN, "%s: unable to restart I/O log", __func__);
	/* XXX - structured error message so client can send from beginning */
	if (!fmt_error_message("unable to restart log", &closure->write_buf))
	    debug_return_bool(false);
	sudo_ev_del(NULL, closure->read_ev);
	if (sudo_ev_add(NULL, closure->write_ev, NULL, false) == -1) {
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
    debug_decl(handle_alert, SUDO_DEBUG_UTIL)

    /* TODO */
    debug_return_bool(false);
}

static bool
handle_iobuf(int iofd, IoBuffer *msg, struct connection_closure *closure)
{
    debug_decl(handle_iobuf, SUDO_DEBUG_UTIL)

    if (closure->state != RUNNING) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received IoBuffer", __func__);

    /* Store IoBuffer in log. */
    if (store_iobuf(iofd, msg, closure) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "failed to store IoBuffer");
	debug_return_bool(false);
    }

#ifdef SERVER_DEBUG
    if (rand() % 4 == 3)
	kill(getpid(), SIGTERM);
#endif

    /* Schedule a commit point in 10 sec if one is not already pending. */
    if (!ISSET(closure->commit_ev->flags, SUDO_EVQ_INSERTED)) {
	struct timespec tv = { ACK_FREQUENCY, 0 };
	if (sudo_ev_add(NULL, closure->commit_ev, &tv, false) == -1) {
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
    debug_decl(handle_winsize, SUDO_DEBUG_UTIL)

    if (closure->state != RUNNING) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received ChangeWindowSize",
	__func__);

    /* Store new window size in log. */
    if (store_winsize(msg, closure) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "failed to store ChangeWindowSize");
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

static bool
handle_suspend(CommandSuspend *msg, struct connection_closure *closure)
{
    debug_decl(handle_suspend, SUDO_DEBUG_UTIL)

    if (closure->state != RUNNING) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received CommandSuspend",
	__func__);

    /* Store suspend siganl in log. */
    if (store_suspend(msg, closure) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "failed to store CommandSuspend");
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

static bool
handle_client_message(uint8_t *buf, size_t len,
    struct connection_closure *closure)
{
    ClientMessage *msg;
    bool ret = false;
    debug_decl(handle_client_message, SUDO_DEBUG_UTIL)

    msg = client_message__unpack(NULL, len, buf);
    if (msg == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to unpack ClientMessage size %zu", len);
	debug_return_bool(false);
    }

    switch (msg->type_case) {
    case CLIENT_MESSAGE__TYPE_EXEC_MSG:
	ret = handle_exec(msg->exec_msg, closure);
	break;
    case CLIENT_MESSAGE__TYPE_EXIT_MSG:
	ret = handle_exit(msg->exit_msg, closure);
	break;
    case CLIENT_MESSAGE__TYPE_RESTART_MSG:
	ret = handle_restart(msg->restart_msg, closure);
	break;
    case CLIENT_MESSAGE__TYPE_ALERT_MSG:
	ret = handle_alert(msg->alert_msg, closure);
	break;
    case CLIENT_MESSAGE__TYPE_TTYIN_BUF:
	ret = handle_iobuf(IOFD_TTYIN, msg->ttyin_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_TTYOUT_BUF:
	ret = handle_iobuf(IOFD_TTYOUT, msg->ttyout_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_STDIN_BUF:
	ret = handle_iobuf(IOFD_STDIN, msg->stdin_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_STDOUT_BUF:
	ret = handle_iobuf(IOFD_STDOUT, msg->stdout_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_STDERR_BUF:
	ret = handle_iobuf(IOFD_STDERR, msg->stderr_buf, closure);
	break;
    case CLIENT_MESSAGE__TYPE_WINSIZE_EVENT:
	ret = handle_winsize(msg->winsize_event, closure);
	break;
    case CLIENT_MESSAGE__TYPE_SUSPEND_EVENT:
	ret = handle_suspend(msg->suspend_event, closure);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected type_case value %d", msg->type_case);
	break;
    }
    client_message__free_unpacked(msg, NULL);

    debug_return_bool(ret);
}

static void
shutdown_cb(int unused, int what, void *v)
{
    struct sudo_event_base *base = v;
    debug_decl(shutdown_cb, SUDO_DEBUG_UTIL)

    sudo_ev_loopbreak(base);

    debug_return;
}

/*
 * Shut down active client connections if any, or exit immediately.
 */
static void
server_shutdown(struct sudo_event_base *base)
{
    struct connection_closure *closure;
    struct sudo_event *ev;
    struct timespec tv = { 0, 0 };
    debug_decl(server_shutdown, SUDO_DEBUG_UTIL)

    if (TAILQ_EMPTY(&connections)) {
	sudo_ev_loopbreak(base);
	debug_return;
    }

    /* Schedule final commit point for each active connection. */
    TAILQ_FOREACH(closure, &connections, entries) {
	closure->state = SHUTDOWN;
	sudo_ev_del(base, closure->read_ev);
	if (sudo_ev_add(base, closure->commit_ev, &tv, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add commit point event");
	}
    }

    /* We need a timed event to exit even if clients time out. */
    ev = sudo_ev_alloc(-1, SUDO_EV_TIMEOUT, shutdown_cb, base);
    if (ev != NULL) {
	tv.tv_sec = SHUTDOWN_TIMEO;
	if (sudo_ev_add(base, ev, &tv, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add shutdown event");
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
    struct connection_buffer *buf = &closure->write_buf;
    ssize_t nwritten;
    debug_decl(server_msg_cb, SUDO_DEBUG_UTIL)

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: sending %u bytes to client",
	__func__, buf->len - buf->off);

    nwritten = send(fd, buf->data + buf->off, buf->len - buf->off, 0);
    if (nwritten == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to send %u bytes", buf->len - buf->off);
	goto finished;
    }
    buf->off += nwritten;

    if (buf->off == buf->len) {
	/* sent entire message */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: finished sending %u bytes to client", __func__, buf->len);
	buf->off = 0;
	buf->len = 0;
	sudo_ev_del(NULL, closure->write_ev);
	if (closure->state == FLUSHED || closure->state == SHUTDOWN ||
		closure->state == ERROR)
	    goto finished;
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
    uint16_t msg_len;
    ssize_t nread;
    debug_decl(client_msg_cb, SUDO_DEBUG_UTIL)

    nread = recv(fd, buf->data + buf->len, buf->size - buf->len, 0);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received %zd bytes from client",
	__func__, nread);
    switch (nread) {
    case -1:
	if (errno == EAGAIN)
	    debug_return;
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to receive %u bytes", buf->size - buf->len);
	goto finished;
    case 0:
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO, "unexpected EOF");
	goto finished;
    default:
	break;
    }
    buf->len += nread;

    while (buf->len - buf->off >= sizeof(msg_len)) {
	/* Read wire message size (uint16_t in network byte order). */
	memcpy(&msg_len, buf->data + buf->off, sizeof(msg_len));
	msg_len = ntohs(msg_len);

	if (msg_len + sizeof(msg_len) > buf->len - buf->off) {
	    /* Incomplete message, we'll read the rest next time. */
	    /* TODO: realloc if max message size increases */
	    if (buf->off > 0)
		memmove(buf->data, buf->data + buf->off, buf->len - buf->off);
	    break;
	}

	/* Parse ClientMessage, could be zero bytes. */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: parsing ClientMessage, size %hu", __func__, msg_len);
	buf->off += sizeof(msg_len);
	if (!handle_client_message(buf->data + buf->off, msg_len, closure)) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to parse ClientMessage, size %hu", msg_len);
	    goto finished;
	}
	buf->off += msg_len;
    }
    buf->len -= buf->off;
    buf->off = 0;
    debug_return;
finished:
    connection_closure_free(closure);
    debug_return;
}

/*
 * Format and schedule a commit_point message.
 */
static void
server_commit_cb(int unused, int what, void *v)
{
    ServerMessage msg = SERVER_MESSAGE__INIT;
    TimeSpec commit_point = TIME_SPEC__INIT;
    struct connection_closure *closure = v;
    debug_decl(server_commit_cb, SUDO_DEBUG_UTIL)

    /* Send the client an acknowledgement of what has been committed to disk. */
    commit_point.tv_sec = closure->elapsed_time.tv_sec;
    commit_point.tv_nsec = closure->elapsed_time.tv_nsec;
    msg.commit_point = &commit_point;
    msg.type_case = SERVER_MESSAGE__TYPE_COMMIT_POINT;

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: sending commit point [%lld, %ld]",
	__func__, (long long)closure->elapsed_time.tv_sec,
	closure->elapsed_time.tv_nsec);

    /* XXX - assumes no other server message pending, use a queue instead? */
    if (!fmt_server_message(&closure->write_buf, &msg)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to format ServerMessage (commit point)");
	goto bad;
    }
    if (sudo_ev_add(NULL, closure->write_ev, NULL, false) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to add server write event");
	goto bad;
    }

    if (closure->state == EXITED)
	closure->state = FLUSHED;
    debug_return;
bad:
    connection_closure_free(closure);
    debug_return;
}

static void
signal_cb(int signo, int what, void *v)
{
    struct sudo_event_base *base = v;
    debug_decl(signal_cb, SUDO_DEBUG_UTIL)

    switch (signo) {
	case SIGHUP:
	    /* TODO: reload config */
	    sudo_debug_printf(SUDO_DEBUG_INFO, "received SIGHUP");
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

/*
 * Allocate a new connection closure.
 */
static struct connection_closure *
connection_closure_alloc(int sock)
{
    struct connection_closure *closure;
    debug_decl(connection_closure_alloc, SUDO_DEBUG_UTIL)

    if ((closure = calloc(1, sizeof(*closure))) == NULL)
	debug_return_ptr(NULL);

    closure->sock = sock;

    closure->read_buf.size = UINT16_MAX + sizeof(uint16_t);
    closure->read_buf.data = malloc(closure->read_buf.size);
    if (closure->read_buf.data == NULL)
	goto bad;

    closure->write_buf.size = UINT16_MAX + sizeof(uint16_t);
    closure->write_buf.data = malloc(closure->write_buf.size);
    if (closure->write_buf.data == NULL)
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

    TAILQ_INSERT_TAIL(&connections, closure, entries);
    debug_return_ptr(closure);
bad:
    connection_closure_free(closure);
    debug_return_ptr(NULL);
}

/*
 * New connection.
 * Allocate a connection closure and send a server hello message.
 */
static bool
new_connection(int sock, struct sudo_event_base *base)
{
    struct connection_closure *closure;
    debug_decl(new_connection, SUDO_DEBUG_UTIL)

    if ((closure = connection_closure_alloc(sock)) == NULL)
	goto bad;

    /* Format and write ServerHello message. */
    if (!fmt_hello_message(&closure->write_buf))
	goto bad;
    if (sudo_ev_add(base, closure->write_ev, NULL, false) == -1)
	goto bad;

    /* Enable reader for ClientMessage*/
    if (sudo_ev_add(base, closure->read_ev, NULL, false) == -1)
	goto bad;

    debug_return_bool(true);
bad:
    connection_closure_free(closure);
    debug_return_bool(false);
}

static int
create_listener(sa_family_t family, in_port_t port)
{
    union sockaddr_union s_un;
    socklen_t salen;
    int flags, i, sock;
    debug_decl(create_listener, SUDO_DEBUG_UTIL)

    memset(&s_un, 0, sizeof(s_un));
    switch (family) {
    case AF_INET:
	s_un.sin.sin_family = AF_INET;
	s_un.sin.sin_addr.s_addr = INADDR_ANY;
	s_un.sin.sin_port = htons(port);
	salen = sizeof(s_un.sin);
	break;
#ifdef HAVE_STRUCT_IN6_ADDR
    case AF_INET6:
	s_un.sin6.sin6_family = AF_INET6;
	s_un.sin6.sin6_addr = in6addr_any;
	s_un.sin6.sin6_port = htons(port);
	salen = sizeof(s_un.sin6);
	break;
#endif
    default:
	debug_return_int(-1);
    }

    if ((sock = socket(family, SOCK_STREAM, 0)) == -1) {
	sudo_warn("socket");
	goto bad;
    }
    i = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1)
	sudo_warn("SO_REUSEADDR");
    if (bind(sock, &s_un.sa, salen) == -1) {
	sudo_warn("bind");
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

    debug_return_int(sock);
bad:
    if (sock != -1)
	close(sock);
    debug_return_int(-1);
}

static void
listener_cb(int fd, int what, void *v)
{
    struct sudo_event_base *base = v;
    union sockaddr_union s_un;
    socklen_t salen = sizeof(s_un);
    int sock;
    debug_decl(listener_cb, SUDO_DEBUG_UTIL)

    sock = accept(fd, &s_un.sa, &salen);
    if (sock != -1) {
	if (!new_connection(sock, base)) {
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

static void
register_listener(sa_family_t family, in_port_t port, struct sudo_event_base *base)
{
    struct sudo_event *ev;
    int sock;
    debug_decl(register_listener, SUDO_DEBUG_UTIL)

    sock = create_listener(family, port);
    if (sock != -1) {
	ev = sudo_ev_alloc(sock, SUDO_EV_READ|SUDO_EV_PERSIST, listener_cb, base);
	if (ev == NULL)
	    sudo_fatal(NULL);
	if (sudo_ev_add(base, ev, NULL, false) == -1)
	    sudo_fatal("unable to add listener event to queue");
    }

    debug_return;
}

static void
register_signal(int signo, struct sudo_event_base *base)
{
    struct sudo_event *ev;
    debug_decl(register_listener, SUDO_DEBUG_UTIL)

    ev = sudo_ev_alloc(signo, SUDO_EV_SIGNAL, signal_cb, base);
    if (ev == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(base, ev, NULL, false) == -1)
	sudo_fatal("unable to add signal event to queue");

    debug_return;
}

static void
logsrvd_cleanup(void)
{
    /* TODO: cleanup like on signal */
    return;
}

int
main(int argc, char *argv[])
{
    struct sudo_event_base *evbase;
    debug_decl_vars(main, SUDO_DEBUG_MAIN)

    initprogname(argc > 0 ? argv[0] : "sudo_logsrvd");
    setlocale(LC_ALL, "");
    bindtextdomain("sudo", LOCALEDIR); /* XXX - add logsrvd domain */
    textdomain("sudo");

    /* Register fatal/fatalx callback. */
    sudo_fatal_callback_register(logsrvd_cleanup);

    /* Read sudo.conf and initialize the debug subsystem. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
        exit(EXIT_FAILURE);
    sudo_debug_register(getprogname(), NULL, NULL,
        sudo_conf_debug_files(getprogname()));

    /* XXX - getopt_long option handling */

    if (protobuf_c_version_number() < 1003000)
	sudo_fatalx("Protobuf-C version 1.3 or higher required");

    signal(SIGPIPE, SIG_IGN);

    if ((evbase = sudo_ev_base_alloc()) == NULL)
	sudo_fatal(NULL);
    sudo_ev_base_setdef(evbase);

    register_listener(AF_INET, DEFAULT_PORT, evbase);
#ifdef HAVE_STRUCT_IN6_ADDR
    register_listener(AF_INET6, DEFAULT_PORT, evbase);
#endif
    if (TAILQ_EMPTY(&evbase->events))
	debug_return_int(-1);

    register_signal(SIGHUP, evbase);
    register_signal(SIGINT, evbase);
    register_signal(SIGTERM, evbase);

    sudo_ev_dispatch(evbase);

    /* NOTREACHED */
    debug_return_int(1);
}
