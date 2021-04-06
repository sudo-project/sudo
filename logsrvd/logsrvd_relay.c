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

#define NEED_INET_NTOP		/* to expose sudo_inet_ntop in sudo_compat.h */

#include "pathnames.h"
#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_event.h"
#include "sudo_eventlog.h"
#include "sudo_gettext.h"
#include "sudo_json.h"
#include "sudo_iolog.h"
#include "sudo_queue.h"
#include "sudo_util.h"

#include "log_server.pb-c.h"
#include "logsrvd.h"

static void relay_client_msg_cb(int fd, int what, void *v);
static void relay_server_msg_cb(int fd, int what, void *v);
static void connect_cb(int sock, int what, void *v);
static bool start_relay(int sock, struct connection_closure *closure);

/*
 * Free a struct relay_closure container and its contents.
 */
void
relay_closure_free(struct relay_closure *relay_closure)
{
    struct connection_buffer *buf;
    debug_decl(relay_closure_free, SUDO_DEBUG_UTIL);

    if (relay_closure->relays != NULL)
	address_list_delref(relay_closure->relays);
    sudo_ev_free(relay_closure->read_ev);
    sudo_ev_free(relay_closure->write_ev);
    sudo_ev_free(relay_closure->connect_ev);
    free(relay_closure->read_buf.data);
    while ((buf = TAILQ_FIRST(&relay_closure->write_bufs)) != NULL) {
	TAILQ_REMOVE(&relay_closure->write_bufs, buf, entries);
	free(buf->data);
	free(buf);
    }
    if (relay_closure->sock != -1)
	close(relay_closure->sock);
    free(relay_closure);

    debug_return;
}

/*
 * Allocate a relay closure.
 * Note that allocation of the events is deferred until we know the socket.
 */
static struct relay_closure *
relay_closure_alloc(void)
{
    struct relay_closure *relay_closure;
    debug_decl(relay_closure_alloc, SUDO_DEBUG_UTIL);

    if ((relay_closure = calloc(1, sizeof(*relay_closure))) == NULL)
	debug_return_ptr(NULL);

    /* We take a reference to relays so it doesn't change while connecting. */
    relay_closure->sock = -1;
    relay_closure->relays = logsrvd_conf_relay();
    address_list_addref(relay_closure->relays);
    TAILQ_INIT(&relay_closure->write_bufs);

    relay_closure->read_buf.size = 8 * 1024;
    relay_closure->read_buf.data = malloc(relay_closure->read_buf.size);
    if (relay_closure->read_buf.data == NULL)
	goto bad;

    debug_return_ptr(relay_closure);
bad:
    relay_closure_free(relay_closure);
    debug_return_ptr(NULL);
}

/*
 * Format a ClientMessage and store the wire format message in buf.
 * Returns true on success, false on failure.
 */
static bool
fmt_client_message(struct connection_closure *closure, ClientMessage *msg)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    struct connection_buffer *buf;
    uint32_t msg_len;
    bool ret = false;
    size_t len;
    debug_decl(fmt_client_message, SUDO_DEBUG_UTIL);

    if ((buf = get_free_buf(closure)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate connection_buffer");
        goto done;
    }

    len = client_message__get_packed_size(msg);
    if (len > MESSAGE_SIZE_MAX) {
    	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "client message too large: %zu", len);
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
	"size + client message %zu bytes", len);

    memcpy(buf->data, &msg_len, sizeof(msg_len));
    client_message__pack(msg, buf->data + sizeof(msg_len));
    buf->len = len;
    TAILQ_INSERT_TAIL(&relay_closure->write_bufs, buf, entries);
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
fmt_client_hello(struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    ClientHello hello_msg = CLIENT_HELLO__INIT;
    bool ret;
    debug_decl(fmt_client_hello, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: sending ClientHello", __func__);
    hello_msg.client_id = "Sudo Logsrvd " PACKAGE_VERSION;

    client_msg.u.hello_msg = &hello_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_HELLO_MSG;
    ret = fmt_client_message(closure, &client_msg);
    if (ret) {
	if (sudo_ev_add(closure->evbase, relay_closure->read_ev, NULL, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server read event");
	    ret = false;
	}
	if (sudo_ev_add(closure->evbase, relay_closure->write_ev, NULL, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server write event");
	    ret = false;
	}
    }

    debug_return_bool(ret);
}

/*
 * Try to connect to the next relay host.
 * Returns 0 on success, -1 on error, setting errno.
 * If there is no next relay, errno is set to ENOENT.
 */
int
connect_relay_next(struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    struct server_address *relay;
    int ret, sock = -1;
    char *addr;
    debug_decl(connect_relay_next, SUDO_DEBUG_UTIL);

    /* Get next relay or return ENOENT none are left. */
    if (relay_closure->relay_addr != NULL) {
	relay = TAILQ_NEXT(relay_closure->relay_addr, entries);
    } else {
	relay = TAILQ_FIRST(relay_closure->relays);
    }
    if (relay == NULL) {
	errno = ENOENT;
	goto bad;
    }
    relay_closure->relay_addr = relay;

    sock = socket(relay->sa_un.sa.sa_family, SOCK_STREAM, 0);
    if (sock == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to allocate relay socket");
	goto bad;
    }
    ret = fcntl(sock, F_GETFL, 0);
    if (ret == -1 || fcntl(sock, F_SETFL, ret | O_NONBLOCK) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "fcntl(O_NONBLOCK) failed");
	goto bad;
    }

    ret = connect(sock, &relay->sa_un.sa, relay->sa_size);
    if (ret == -1 && errno != EINPROGRESS)
	goto bad;

    switch (relay->sa_un.sa.sa_family) {
    case AF_INET:
	addr = (char *)&relay->sa_un.sin.sin_addr;
	break;
    case AF_INET6:
	addr = (char *)&relay->sa_un.sin6.sin6_addr;
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unsupported address family from connect(): %d",
	    relay->sa_un.sa.sa_family);
	goto bad;
    }
    inet_ntop(relay->sa_un.sa.sa_family, addr, relay_closure->ipaddr,
	sizeof(relay_closure->ipaddr));

    if (ret == 0) {
	/* Connection succeeded without blocking. */
	relay_closure->sock = sock;
	if (!start_relay(sock, closure))
	    goto bad;
    } else {
	/* Connection will be completed in connect_cb(). */
	relay_closure->connect_ev = sudo_ev_alloc(sock, SUDO_EV_WRITE,
	    connect_cb, closure);
	if (relay_closure->connect_ev == NULL)
	    goto bad;
	if (sudo_ev_add(closure->evbase, relay_closure->connect_ev,
		logsrvd_conf_get_connect_timeout(), false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server connect event");
	    goto bad;
	}
	relay_closure->sock = sock;
	closure->state = CONNECTING;
    }
    debug_return_int(ret);

bad:
    /* Connection or system error. */
    if (sock != -1)
	close(sock);
    sudo_ev_free(relay_closure->connect_ev);
    relay_closure->connect_ev = NULL;
    debug_return_int(-1);
}

static void
connect_cb(int sock, int what, void *v)
{
    struct connection_closure *closure = v;
    struct relay_closure *relay_closure = closure->relay_closure;
    int errnum, optval, ret;
    socklen_t optlen = sizeof(optval);
    debug_decl(connect_cb, SUDO_DEBUG_UTIL);

    if (what == SUDO_EV_TIMEOUT) {
	errnum = ETIMEDOUT;
    } else {
	ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
	errnum = ret == 0 ? optval : errno;
    }
    if (errnum == 0) {
	/* Relay connection succeeded, start talking to the client.  */
	closure->state = INITIAL;
	if (!start_relay(sock, closure))
	    connection_closure_free(closure);
    } else {
	/* Connection failed, try next relay (if any). */
	int res;
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
	    "unable to connect to relay %s: %s", relay_closure->ipaddr,
	    strerror(errnum));
	while ((res = connect_relay_next(closure)) == -1) {
	    if (errno == ENOENT || errno == EINPROGRESS) {
		/* Out of relays or connecting asynchronously. */
		break;
	    }
	}
	if (res == -1 && errno != EINPROGRESS) {
	    closure->errstr = _("unable to connect to relay host");
	    closure->state = ERROR;
	}
    }

    debug_return;
}

/* Connect to the first available relay host. */
bool
connect_relay(struct connection_closure *closure)
{
    struct relay_closure *relay_closure;
    int res;
    debug_decl(connect_relay, SUDO_DEBUG_UTIL);

    relay_closure = closure->relay_closure = relay_closure_alloc();
    if (relay_closure == NULL)
	debug_return_bool(false);

    while ((res = connect_relay_next(closure)) == -1) {
	if (errno == ENOENT || errno == EINPROGRESS) {
	    /* Out of relays or connecting asynchronously. */
	    break;
	}
    }

    if (res == -1 && errno != EINPROGRESS)
	debug_return_bool(false);
    debug_return_bool(true);
}

/*
 * Respond to a ServerHello message from the relay.
 * Returns true on success, false on error.
 */
static bool
handle_server_hello(ServerHello *msg, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    debug_decl(handle_server_hello, SUDO_DEBUG_UTIL);

    if (closure->state != INITIAL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
    }

    /* Check that ServerHello is valid. */
    if (msg->server_id == NULL || msg->server_id[0] == '\0') {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid ServerHello, missing server_id");
	closure->errstr = _("invalid ServerHello");
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"relay server (%s) ID %s", relay_closure->ipaddr, msg->server_id);

    /* TODO: handle redirect */

    debug_return_bool(true);
}

/*
 * Respond to a CommitPoint message from the relay.
 * Returns true on success, false on error.
 */
static bool
handle_commit_point(TimeSpec *commit_point, struct connection_closure *closure)
{
    debug_decl(handle_commit_point, SUDO_DEBUG_UTIL);

    if (closure->state < RUNNING) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected state %d", closure->state);
	closure->errstr = _("state machine error");
	debug_return_bool(false);
    }

    /* Pass commit point from relay to client. */
    debug_return_bool(schedule_commit_point(commit_point, closure));
}

/*
 * Respond to a LogId message from the relay.
 * Always returns true.
 */
static bool
handle_log_id(char *id, struct connection_closure *closure)
{
    char *new_id;
    bool ret = false;
    debug_decl(handle_log_id, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"log ID %s from relay (%s)", id, closure->relay_closure->ipaddr);

    /* Generate a new log ID that includes the relay host. */
    if (asprintf(&new_id, "%s/%s", id, closure->relay_closure->ipaddr) != -1) {
	if (fmt_log_id_message(id, closure)) {
	    if (sudo_ev_add(closure->evbase, closure->write_ev,
		    logsrvd_conf_get_sock_timeout(), false) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "unable to add server write event");
	    } else {
		ret = true;
	    }
	}
	free(new_id);
    }

    debug_return_bool(ret);
}

/*
 * Respond to a ServerError message from the relay.
 * Always returns false.
 */
static bool
handle_server_error(char *errmsg, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    debug_decl(handle_server_error, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	"error message received from relay (%s): %s",
	relay_closure->ipaddr, errmsg);

    if (!fmt_error_message(errmsg, closure))
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

/*
 * Respond to a ServerAbort message from the server.
 * Always returns false.
 */
static bool
handle_server_abort(char *errmsg, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    debug_decl(handle_server_abort, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	"abort message received from relay (%s): %s",
	relay_closure->ipaddr, errmsg);

    if (!fmt_error_message(errmsg, closure))
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

/*
 * Respond to a ServerMessage from the relay.
 * Returns true on success, false on error.
 */
static bool
handle_server_message(uint8_t *buf, size_t len, struct connection_closure *closure)
{
    ServerMessage *msg;
    bool ret = false;
    debug_decl(handle_server_message, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: unpacking ServerMessage", __func__);
    msg = server_message__unpack(NULL, len, buf);
    if (msg == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to unpack ServerMessage size %zu", len);
	debug_return_bool(false);
    }

    switch (msg->type_case) {
    case SERVER_MESSAGE__TYPE_HELLO:
	if ((ret = handle_server_hello(msg->u.hello, closure))) {
	    /* Relay server said hello, start talking to client. */
	    ret = start_protocol(closure);
	}
	break;
    case SERVER_MESSAGE__TYPE_COMMIT_POINT:
	ret = handle_commit_point(msg->u.commit_point, closure);
	break;
    case SERVER_MESSAGE__TYPE_LOG_ID:
	ret = handle_log_id(msg->u.log_id, closure);
	break;
    case SERVER_MESSAGE__TYPE_ERROR:
	ret = handle_server_error(msg->u.error, closure);
	break;
    case SERVER_MESSAGE__TYPE_ABORT:
	ret = handle_server_abort(msg->u.abort, closure);
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unexpected type_case value %d", msg->type_case);
	    closure->errstr = _("unrecognized ServerMessage type");
	break;
    }

    server_message__free_unpacked(msg, NULL);
    debug_return_bool(ret);
}

/*
 * Read and unpack a ServerMessage from the relay (read callback).
 */
static void
relay_server_msg_cb(int fd, int what, void *v)
{
    struct connection_closure *closure = v;
    struct relay_closure *relay_closure = closure->relay_closure;
    struct connection_buffer *buf = &relay_closure->read_buf;
    ssize_t nread;
    uint32_t msg_len;
    debug_decl(relay_server_msg_cb, SUDO_DEBUG_UTIL);

    if (what == SUDO_EV_TIMEOUT) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "timed out reading from relay (%s)", relay_closure->ipaddr);
	closure->errstr = _("timeout reading from relay");
        goto send_error;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: ServerMessage from relay %s",
	__func__, relay_closure->ipaddr);

    nread = recv(fd, buf->data + buf->len, buf->size - buf->len, 0);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received %zd bytes from relay %s",
	__func__, nread, relay_closure->ipaddr);
    switch (nread) {
    case -1:
	if (errno == EAGAIN)
	    debug_return;
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "recv from %s", relay_closure->ipaddr);
	closure->errstr = _("unable to read from relay");
	goto send_error;
    case 0:
	/* EOF from relay server, close the socket. */
	close(relay_closure->sock);
	relay_closure->sock = -1;
	sudo_ev_del(closure->evbase, relay_closure->read_ev);
	sudo_ev_del(closure->evbase, relay_closure->write_ev);

	if (closure->state != FINISHED) {
	    sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
		"unexpected EOF from %s (state %d)", relay_closure->ipaddr,
		closure->state);
	    closure->errstr = _("unexpected EOF from relay");
	    goto send_error;
	}
	debug_return;
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
		"server message too large: %u", msg_len);
	    closure->errstr = _("server message too large");
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

	/* Parse ServerMessage (could be zero bytes). */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: parsing ServerMessage, size %u", __func__, msg_len);
	buf->off += sizeof(msg_len);
	if (!handle_server_message(buf->data + buf->off, msg_len, closure))
	    goto send_error;
	buf->off += msg_len;
    }
    buf->len -= buf->off;
    buf->off = 0;
    debug_return;

send_error:
    /*
     * Try to send client an error message before closing connection.
     * If we are already in an error state, just give up.
     */
    if (closure->state == ERROR)
	goto close_connection;
    if (closure->errstr != NULL || !fmt_error_message(closure->errstr, closure))
	goto close_connection;
    sudo_ev_del(closure->evbase, relay_closure->read_ev);
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
 * Forward a ClientMessage to the relay (write callback).
 */
static void
relay_client_msg_cb(int fd, int what, void *v)
{
    struct connection_closure *closure = v;
    struct relay_closure *relay_closure = closure->relay_closure;
    struct connection_buffer *buf;
    ssize_t nwritten;
    debug_decl(relay_client_msg_cb, SUDO_DEBUG_UTIL);

    if (what == SUDO_EV_TIMEOUT) {
	closure->errstr = _("timeout writing to relay");
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "timed out writing to relay (%s)", relay_closure->ipaddr);
        goto send_error;
    }

    if ((buf = TAILQ_FIRST(&relay_closure->write_bufs)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "missing write buffer");
        goto close_connection;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: sending %u bytes to server (%s)",
	__func__, buf->len - buf->off, relay_closure->ipaddr);

    nwritten = send(fd, buf->data + buf->off, buf->len - buf->off, 0);
    if (nwritten == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "send to %s", relay_closure->ipaddr);
	closure->errstr = _("error writing to relay");
	goto send_error;
    }
    buf->off += nwritten;

    if (buf->off == buf->len) {
	/* sent entire message, move buf to free list */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: finished sending %u bytes to server", __func__, buf->len);
	buf->off = 0;
	buf->len = 0;
	TAILQ_REMOVE(&relay_closure->write_bufs, buf, entries);
	TAILQ_INSERT_TAIL(&closure->free_bufs, buf, entries);
	if (TAILQ_EMPTY(&relay_closure->write_bufs))
	    sudo_ev_del(closure->evbase, relay_closure->write_ev);
    }
    debug_return;

send_error:
    /*
     * Try to send client an error message before closing connection.
     * If we are already in an error state, just give up.
     */
    if (closure->state == ERROR)
	goto close_connection;
    if (closure->errstr != NULL || !fmt_error_message(closure->errstr, closure))
	goto close_connection;
    sudo_ev_del(closure->evbase, relay_closure->read_ev);
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

/* Begin the conversation with the relay host. */
static bool
start_relay(int sock, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    debug_decl(start_relay, SUDO_DEBUG_UTIL);

    /* No longer need the connect event. */
    sudo_ev_free(relay_closure->connect_ev);
    relay_closure->connect_ev = NULL;

    /* Allocate relay read/write events now that we know the socket. */
    relay_closure->read_ev = sudo_ev_alloc(sock, SUDO_EV_READ|SUDO_EV_PERSIST,
	relay_server_msg_cb, closure);
    relay_closure->write_ev = sudo_ev_alloc(sock, SUDO_EV_WRITE|SUDO_EV_PERSIST,
	relay_client_msg_cb, closure);
    if (relay_closure->read_ev == NULL || relay_closure->write_ev == NULL)
	debug_return_bool(false);

    /* Start communication with the relay server by saying hello. */
    debug_return_bool(fmt_client_hello(closure));
}

/*
 * Relay an AcceptMessage from the client to the relay server.
 */
bool
relay_accept(AcceptMessage *msg, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    struct sudo_event_base *evbase = closure->evbase;
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    bool ret;
    debug_decl(relay_accept, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: relaying AcceptMessage from %s to %s", __func__,
	closure->ipaddr, relay_closure->ipaddr);

    client_msg.u.accept_msg = msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_ACCEPT_MSG;
    ret = fmt_client_message(closure, &client_msg);
    if (ret) {
	if (sudo_ev_add(evbase, relay_closure->write_ev, NULL, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server write event");
	    ret = false;
	}
    }

    if (ret) {
	/* success */
	if (msg->expect_iobufs)
	    closure->log_io = true;
	closure->state = RUNNING;
    }

    debug_return_bool(ret);
}

/*
 * Relay a RejectMessage from the client to the relay server.
 */
bool
relay_reject(RejectMessage *msg, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    struct sudo_event_base *evbase = closure->evbase;
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    bool ret;
    debug_decl(relay_reject, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: relaying RejectMessage from %s to %s", __func__,
	closure->ipaddr, relay_closure->ipaddr);

    client_msg.u.reject_msg = msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_REJECT_MSG;
    ret = fmt_client_message(closure, &client_msg);
    if (ret) {
	if (sudo_ev_add(evbase, relay_closure->write_ev, NULL, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server write event");
	    ret = false;
	}
    }

    closure->state = FINISHED;

    debug_return_bool(ret);
}

/*
 * Relay an ExitMessage from the client to the relay server.
 */
bool
relay_exit(ExitMessage *msg, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    struct sudo_event_base *evbase = closure->evbase;
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    bool ret;
    debug_decl(relay_exit, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: relaying ExitMessage from %s to %s", __func__,
	closure->ipaddr, relay_closure->ipaddr);

    client_msg.u.exit_msg = msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_EXIT_MSG;
    ret = fmt_client_message(closure, &client_msg);
    if (ret) {
	if (sudo_ev_add(evbase, relay_closure->write_ev, NULL, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server write event");
	    ret = false;
	}
    }

    if (ret) {
	/* Command exited, if I/O logging wait for commit point. */
	closure->state = closure->log_io ? EXITED : FINISHED;
    }

    debug_return_bool(ret);
}

/*
 * Relay a RestartMessage from the client to the relay server.
 */
bool
relay_restart(RestartMessage *msg, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    struct sudo_event_base *evbase = closure->evbase;
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    RestartMessage restart_msg = *msg;
    char *cp;
    bool ret;
    debug_decl(relay_restart, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: relaying RestartMessage from %s to %s", __func__,
	closure->ipaddr, relay_closure->ipaddr);

    /*
     * We prepend "relayhost/" to the log ID before relaying it to
     * the client.  Perform the reverse operation before passing the
     * log ID to the relay host.
     */
    if ((cp = strchr(restart_msg.log_id, '/')) != NULL)
	restart_msg.log_id = cp + 1;

    client_msg.u.restart_msg = &restart_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_RESTART_MSG;
    ret = fmt_client_message(closure, &client_msg);
    if (ret) {
	if (sudo_ev_add(evbase, relay_closure->write_ev, NULL, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server write event");
	    ret = false;
	}
    }

    closure->state = ret ? RUNNING : ERROR;

    debug_return_bool(ret);
}

/*
 * Relay an AlertMessage from the client to the relay server.
 */
bool
relay_alert(AlertMessage *msg, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    struct sudo_event_base *evbase = closure->evbase;
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    bool ret;
    debug_decl(relay_alert, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: relaying AlertMessage from %s to %s", __func__,
	closure->ipaddr, relay_closure->ipaddr);

    client_msg.u.alert_msg = msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_ALERT_MSG;
    ret = fmt_client_message(closure, &client_msg);
    if (ret) {
	if (sudo_ev_add(evbase, relay_closure->write_ev, NULL, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server write event");
	    ret = false;
	}
    }

    debug_return_bool(ret);
}

/*
 * Relay an IoBuffer from the client to the relay server.
 */
bool
relay_iobuf(int iofd, IoBuffer *iobuf, struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    struct sudo_event_base *evbase = closure->evbase;
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    bool ret;
    debug_decl(relay_iobuf, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: relaying IoBuffer from %s to %s", __func__,
	closure->ipaddr, relay_closure->ipaddr);

    switch (iofd) {
    case IOFD_TTYIN:
	client_msg.type_case = CLIENT_MESSAGE__TYPE_TTYIN_BUF;
	client_msg.u.ttyin_buf = iobuf;
	break;
    case IOFD_TTYOUT:
	client_msg.type_case = CLIENT_MESSAGE__TYPE_TTYOUT_BUF;
	client_msg.u.ttyout_buf = iobuf;
	break;
    case IOFD_STDIN:
	client_msg.type_case = CLIENT_MESSAGE__TYPE_STDIN_BUF;
	client_msg.u.stdin_buf = iobuf;
	break;
    case IOFD_STDOUT:
	client_msg.type_case = CLIENT_MESSAGE__TYPE_STDOUT_BUF;
	client_msg.u.stdout_buf = iobuf;
	break;
    case IOFD_STDERR:
	client_msg.type_case = CLIENT_MESSAGE__TYPE_STDERR_BUF;
	client_msg.u.stderr_buf = iobuf;
	break;
    default:
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "unexpected iofd value %d", iofd);
	debug_return_bool(false);
    }
    ret = fmt_client_message(closure, &client_msg);
    if (ret) {
	if (sudo_ev_add(evbase, relay_closure->write_ev, NULL, false) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to add server write event");
	    ret = false;
	}
    }

    debug_return_bool(ret);
}

/*
 * Shutdown relay connection when server is exiting.
 */
bool
relay_shutdown(struct connection_closure *closure)
{
    struct relay_closure *relay_closure = closure->relay_closure;
    debug_decl(relay_shutdown, SUDO_DEBUG_UTIL);

    /* Close connection unless relay events are pending. */
    if (!sudo_ev_pending(relay_closure->read_ev, SUDO_EV_READ, NULL) &&
	    !sudo_ev_pending(relay_closure->write_ev, SUDO_EV_WRITE, NULL) &&
	    TAILQ_EMPTY(&relay_closure->write_bufs)) {
	connection_closure_free(closure);
    }

    debug_return_bool(true);
}
