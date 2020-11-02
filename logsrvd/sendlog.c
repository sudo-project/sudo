/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
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
#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif
#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

#if defined(HAVE_OPENSSL)
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_event.h"
#include "sudo_eventlog.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_iolog.h"
#include "sudo_util.h"

#include "hostcheck.h"
#include "log_server.pb-c.h"
#include "sendlog.h"

#if defined(HAVE_OPENSSL)
# define TLS_HANDSHAKE_TIMEO_SEC 10
#endif

TAILQ_HEAD(connection_list, client_closure);
static struct connection_list connections = TAILQ_HEAD_INITIALIZER(connections);

static const char *server_name = "localhost";
#if defined(HAVE_STRUCT_IN6_ADDR)
static char server_ip[INET6_ADDRSTRLEN];
#else
static char server_ip[INET_ADDRSTRLEN];
#endif
static char *iolog_dir;
static bool testrun = false;
static int nr_of_conns = 1;
static int finished_transmissions = 0;

#if defined(HAVE_OPENSSL)
static SSL_CTX *ssl_ctx = NULL;
static const char *ca_bundle = NULL;
static const char *cert = NULL;
static const char *key = NULL;
static bool verify_server = true;
#endif

/* Server callback may redirect to client callback for TLS. */
static void client_msg_cb(int fd, int what, void *v);
static void server_msg_cb(int fd, int what, void *v);

static void
usage(bool fatal)
{
#if defined(HAVE_OPENSSL)
    fprintf(stderr, "usage: %s [-AnV] [-b ca_bundle] [-c cert_file] [-h host] "
	"[-i iolog-id] [-k key_file] [-p port] "
#else
    fprintf(stderr, "usage: %s [-AnV] [-h host] [-i iolog-id] [-p port] "
#endif
	"[-r restart-point] [-R reject-reason] [-t number] /path/to/iolog\n",
        getprogname());
    if (fatal)
	exit(EXIT_FAILURE);
}

static void
help(void)
{
    (void)printf(_("%s - send sudo I/O log to remote server\n\n"),
	getprogname());
    usage(false);
    (void)puts(_("\nOptions:\n"
	"      --help               display help message and exit\n"
	"  -A, --accept             only send an accept event (no I/O)\n"
	"  -h, --host               host to send logs to\n"
	"  -i, --iolog_id           remote ID of I/O log to be resumed\n"
	"  -p, --port               port to use when connecting to host\n"
	"  -r, --restart            restart previous I/O log transfer\n"
	"  -R, --reject             reject the command with the given reason\n"
#if defined(HAVE_OPENSSL)
	"  -b, --ca-bundle          certificate bundle file to verify server's cert against\n"
	"  -c, --cert               certificate file for TLS handshake\n"
	"  -k, --key                private key file\n"
	"  -n, --no-verify          do not verify server certificate\n"
#endif
	"  -t, --test               test audit server by sending selected I/O log n times in parallel\n"
	"  -V, --version            display version information and exit\n"));
    exit(EXIT_SUCCESS);
}

/*
 * Connect to specified host:port
 * If host has multiple addresses, the first one that connects is used.
 * Returns open socket or -1 on error.
 */
static int
connect_server(const char *host, const char *port)
{
    struct addrinfo hints, *res, *res0;
    const char *addr, *cause = "getaddrinfo";
    int error, sock, save_errno;
    debug_decl(connect_server, SUDO_DEBUG_UTIL);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(host, port, &hints, &res0);
    if (error != 0) {
	sudo_warnx(U_("unable to look up %s:%s: %s"), host, port,
	    gai_strerror(error));
	debug_return_int(-1);
    }

    sock = -1;
    for (res = res0; res; res = res->ai_next) {
	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock == -1) {
	    cause = "socket";
	    continue;
	}
	if (connect(sock, res->ai_addr, res->ai_addrlen) == -1) {
	    cause = "connect";
	    save_errno = errno;
	    close(sock);
	    errno = save_errno;
	    sock = -1;
	    continue;
	}
	if (*server_ip == '\0') {
	    switch (res->ai_family) {
	    case AF_INET:
		addr = (char *)&((struct sockaddr_in *)res->ai_addr)->sin_addr;
		break;
	    case AF_INET6:
		addr = (char *)&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
		break;
	    default:
		cause = "ai_family";
		save_errno = EAFNOSUPPORT;
		close(sock);
		errno = save_errno;
		sock = -1;
		continue;
	    }
	    if (inet_ntop(res->ai_family, addr, server_ip,
		    sizeof(server_ip)) == NULL) {
		sudo_warnx("%s", U_("unable to get server IP addr"));
	    }
	}
	break;	/* success */
    }
    freeaddrinfo(res0);

    if (sock != -1) {
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
	    cause = "fcntl(O_NONBLOCK)";
	    save_errno = errno;
	    close(sock);
	    errno = save_errno;
	    sock = -1;
	}
    }
    if (sock == -1)
	sudo_warn("%s", cause);

    debug_return_int(sock);
}

/*
 * Read the next I/O buffer as described by closure->timing.
 */
static bool
read_io_buf(struct client_closure *closure)
{
    struct timing_closure *timing = &closure->timing;
    const char *errstr = NULL;
    size_t nread;
    debug_decl(read_io_buf, SUDO_DEBUG_UTIL);

    if (!closure->iolog_files[timing->event].enabled) {
	errno = ENOENT;
	sudo_warn("%s/%s", iolog_dir, iolog_fd_to_name(timing->event));
	debug_return_bool(false);
    }

    /* Expand buf as needed. */
    if (timing->u.nbytes > closure->bufsize) {
	free(closure->buf);
	closure->bufsize = sudo_pow2_roundup(timing->u.nbytes);
	if ((closure->buf = malloc(closure->bufsize)) == NULL) {
	    sudo_warn(NULL);
	    timing->u.nbytes = 0;
	    debug_return_bool(false);
	}
    }

    nread = iolog_read(&closure->iolog_files[timing->event], closure->buf,
	timing->u.nbytes, &errstr);
    if (nread != timing->u.nbytes) {
	sudo_warnx(U_("unable to read %s/%s: %s"), iolog_dir,
	    iolog_fd_to_name(timing->event), errstr);
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Format a ClientMessage and store the wire format message in buf.
 * Returns true on success, false on failure.
 */
static bool
fmt_client_message(struct connection_buffer *buf, ClientMessage *msg)
{
    uint32_t msg_len;
    bool ret = false;
    size_t len;
    debug_decl(fmt_client_message, SUDO_DEBUG_UTIL);

    len = client_message__get_packed_size(msg);
    if (len > MESSAGE_SIZE_MAX) {
    	sudo_warnx(U_("client message too large: %zu"), len);
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

    memcpy(buf->data, &msg_len, sizeof(msg_len));
    client_message__pack(msg, buf->data + sizeof(msg_len));
    buf->len = len;
    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Split command + args into an array of strings.
 * Returns an array containing command and args, reusing space in "command".
 * Note that the returned array does not end with a terminating NULL.
 */
static char **
split_command(char *command, size_t *lenp)
{
    char *cp;
    char **args;
    size_t len;
    debug_decl(split_command, SUDO_DEBUG_UTIL);

    for (cp = command, len = 0;;) {
	len++;
	if ((cp = strchr(cp, ' ')) == NULL)
	    break;
	cp++;
    }
    args = reallocarray(NULL, len, sizeof(char *));
    if (args == NULL)
	debug_return_ptr(NULL);

    for (cp = command, len = 0;;) {
	args[len++] = cp;
	if ((cp = strchr(cp, ' ')) == NULL)
	    break;
	*cp++ = '\0';
    }

    *lenp = len;
    debug_return_ptr(args);
}

static bool
fmt_client_hello(struct client_closure *closure)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    ClientHello hello_msg = CLIENT_HELLO__INIT;
    bool ret = false;
    debug_decl(fmt_client_hello, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: sending ClientHello", __func__);
    hello_msg.client_id = "Sudo Sendlog " PACKAGE_VERSION;

    /* Schedule ClientMessage */
    client_msg.u.hello_msg = &hello_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_HELLO_MSG;
    ret = fmt_client_message(&closure->write_buf, &client_msg);
    if (ret) {
	if (sudo_ev_add(closure->evbase, closure->read_ev, NULL, false) == -1)
	    ret = false;
	if (sudo_ev_add(closure->evbase, closure->write_ev, NULL, false) == -1)
	    ret = false;
    }

    debug_return_bool(ret);
}

static void
free_info_messages(InfoMessage **info_msgs, size_t n_info_msgs)
{
    debug_decl(free_info_messages, SUDO_DEBUG_UTIL);

    if (info_msgs != NULL) {
	while (n_info_msgs-- > 0) {
	    if (info_msgs[n_info_msgs]->value_case == INFO_MESSAGE__VALUE_STRLISTVAL) {
		/* Only strlistval was dynamically allocated */
		free(info_msgs[n_info_msgs]->u.strlistval->strings);
		free(info_msgs[n_info_msgs]->u.strlistval);
	    }
	    free(info_msgs[n_info_msgs]);
	}
	free(info_msgs);
    }

    debug_return;
}

static InfoMessage **
fmt_info_messages(const struct eventlog *evlog, char *hostname,
    size_t *n_info_msgs)
{
    InfoMessage **info_msgs = NULL;
    InfoMessage__StringList *runargv = NULL;
    size_t info_msgs_size, n = 0;
    debug_decl(fmt_info_messages, SUDO_DEBUG_UTIL);

    /* Split command into a StringList. */
    runargv = malloc(sizeof(*runargv));
    if (runargv == NULL)
        goto oom;
    info_message__string_list__init(runargv);
    runargv->strings = split_command(evlog->command, &runargv->n_strings);
    if (runargv->strings == NULL)
	goto oom;

    /* The sudo I/O log info file has limited info. */
    info_msgs_size = 10;
    info_msgs = calloc(info_msgs_size, sizeof(InfoMessage *));
    if (info_msgs == NULL)
	goto oom;
    for (n = 0; n < info_msgs_size; n++) {
	info_msgs[n] = malloc(sizeof(InfoMessage));
	if (info_msgs[n] == NULL)
            goto oom;
	info_message__init(info_msgs[n]);
    }

    /* Fill in info_msgs */
    n = 0;
    info_msgs[n]->key = "command";
    info_msgs[n]->u.strval = evlog->command;
    info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    info_msgs[n]->key = "columns";
    info_msgs[n]->u.numval = evlog->columns;
    info_msgs[n]->value_case = INFO_MESSAGE__VALUE_NUMVAL;
    n++;

    info_msgs[n]->key = "lines";
    info_msgs[n]->u.numval = evlog->lines;
    info_msgs[n]->value_case = INFO_MESSAGE__VALUE_NUMVAL;
    n++;

    info_msgs[n]->key = "runargv";
    info_msgs[n]->u.strlistval = runargv;
    info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRLISTVAL;
    runargv = NULL;
    n++;

    if (evlog->rungroup != NULL) {
	info_msgs[n]->key = "rungroup";
	info_msgs[n]->u.strval = evlog->rungroup;
	info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
	n++;
    }

    info_msgs[n]->key = "runuser";
    info_msgs[n]->u.strval = evlog->runuser;
    info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    info_msgs[n]->key = "submitcwd";
    info_msgs[n]->u.strval = evlog->cwd;
    info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    info_msgs[n]->key = "submithost";
    info_msgs[n]->u.strval = hostname;
    info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    info_msgs[n]->key = "submituser";
    info_msgs[n]->u.strval = evlog->submituser;
    info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    info_msgs[n]->key = "ttyname";
    info_msgs[n]->u.strval = evlog->ttyname;
    info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    /* Update n_info_msgs. */
    *n_info_msgs = n;

    /* Avoid leaking unused info_msg structs. */
    while (n < info_msgs_size) {
        free(info_msgs[n++]);
    }

    debug_return_ptr(info_msgs);

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    free_info_messages(info_msgs, n);
    if (runargv != NULL) {
        free(runargv->strings);
        free(runargv);
    }
    *n_info_msgs = 0;
    debug_return_ptr(NULL);
}

/*
 * Build and format a RejectMessage wrapped in a ClientMessage.
 * Stores the wire format message in the closure's write buffer.
 * Returns true on success, false on failure.
 */
static bool
fmt_reject_message(struct client_closure *closure)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    RejectMessage reject_msg = REJECT_MESSAGE__INIT;
    TimeSpec tv = TIME_SPEC__INIT;
    size_t n_info_msgs;
    bool ret = false;
    char *hostname;
    debug_decl(fmt_reject_message, SUDO_DEBUG_UTIL);

    /*
     * Fill in RejectMessage and add it to ClientMessage.
     */
    if ((hostname = sudo_gethostname()) == NULL) {
	sudo_warn("gethostname");
	debug_return_bool(false);
    }

    /* Sudo I/O logs only store start time in seconds. */
    tv.tv_sec = closure->evlog->submit_time.tv_sec;
    tv.tv_nsec = closure->evlog->submit_time.tv_nsec;
    reject_msg.submit_time = &tv;

    /* Why the command was rejected. */
    reject_msg.reason = closure->reject_reason;

    reject_msg.info_msgs = fmt_info_messages(closure->evlog, hostname,
        &n_info_msgs);
    if (reject_msg.info_msgs == NULL)
	goto done;

    /* Update n_info_msgs. */
    reject_msg.n_info_msgs = n_info_msgs;

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending RejectMessage, array length %zu", __func__, n_info_msgs);

    /* Schedule ClientMessage */
    client_msg.u.reject_msg = &reject_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_REJECT_MSG;
    ret = fmt_client_message(&closure->write_buf, &client_msg);
    if (ret) {
	if (sudo_ev_add(closure->evbase, closure->write_ev, NULL, false) == -1)
	    ret = false;
    }

done:
    free_info_messages(reject_msg.info_msgs, n_info_msgs);
    free(hostname);

    debug_return_bool(ret);
}

/*
 * Build and format an AcceptMessage wrapped in a ClientMessage.
 * Stores the wire format message in the closure's write buffer.
 * Returns true on success, false on failure.
 */
static bool
fmt_accept_message(struct client_closure *closure)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    AcceptMessage accept_msg = ACCEPT_MESSAGE__INIT;
    TimeSpec tv = TIME_SPEC__INIT;
    size_t n_info_msgs;
    bool ret = false;
    char *hostname;
    debug_decl(fmt_accept_message, SUDO_DEBUG_UTIL);

    /*
     * Fill in AcceptMessage and add it to ClientMessage.
     */
    if ((hostname = sudo_gethostname()) == NULL) {
	sudo_warn("gethostname");
	debug_return_bool(false);
    }

    /* Sudo I/O logs only store start time in seconds. */
    tv.tv_sec = closure->evlog->submit_time.tv_sec;
    tv.tv_nsec = closure->evlog->submit_time.tv_nsec;
    accept_msg.submit_time = &tv;

    /* Client will send IoBuffer messages. */
    accept_msg.expect_iobufs = !closure->accept_only;

    accept_msg.info_msgs = fmt_info_messages(closure->evlog, hostname,
        &n_info_msgs);
    if (accept_msg.info_msgs == NULL)
	goto done;

    /* Update n_info_msgs. */
    accept_msg.n_info_msgs = n_info_msgs;

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending AcceptMessage, array length %zu", __func__, n_info_msgs);

    /* Schedule ClientMessage */
    client_msg.u.accept_msg = &accept_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_ACCEPT_MSG;
    ret = fmt_client_message(&closure->write_buf, &client_msg);
    if (ret) {
	if (sudo_ev_add(closure->evbase, closure->write_ev, NULL, false) == -1)
	    ret = false;
    }

done:
    free_info_messages(accept_msg.info_msgs, n_info_msgs);
    free(hostname);

    debug_return_bool(ret);
}

/*
 * Build and format a RestartMessage wrapped in a ClientMessage.
 * Stores the wire format message in the closure's write buffer.
 * Returns true on success, false on failure.
 */
static bool
fmt_restart_message(struct client_closure *closure)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    RestartMessage restart_msg = RESTART_MESSAGE__INIT;
    TimeSpec tv = TIME_SPEC__INIT;
    bool ret = false;
    debug_decl(fmt_restart_message, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending RestartMessage, [%lld, %ld]", __func__,
	(long long)closure->restart.tv_sec, closure->restart.tv_nsec);

    tv.tv_sec = closure->restart.tv_sec;
    tv.tv_nsec = closure->restart.tv_nsec;
    restart_msg.resume_point = &tv;
    restart_msg.log_id = (char *)closure->iolog_id;

    /* Schedule ClientMessage */
    client_msg.u.restart_msg = &restart_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_RESTART_MSG;
    ret = fmt_client_message(&closure->write_buf, &client_msg);
    if (ret) {
	if (sudo_ev_add(closure->evbase, closure->write_ev, NULL, false) == -1)
	    ret = false;
    }

    debug_return_bool(ret);
}

/*
 * Build and format an ExitMessage wrapped in a ClientMessage.
 * Stores the wire format message in the closure's write buffer.
 * Returns true on success, false on failure.
 */
static bool
fmt_exit_message(struct client_closure *closure)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    ExitMessage exit_msg = EXIT_MESSAGE__INIT;
    bool ret = false;
    debug_decl(fmt_exit_message, SUDO_DEBUG_UTIL);

    /*
     * We don't have enough data in a sudo I/O log to create a real
     * exit message.  For example, the exit value and run time are
     * not known.  This results in a zero-sized message.
     */
    exit_msg.exit_value = 0;

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending ExitMessage, exit value %d",
	__func__, exit_msg.exit_value);

    /* Send ClientMessage */
    client_msg.u.exit_msg = &exit_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_EXIT_MSG;
    if (!fmt_client_message(&closure->write_buf, &client_msg))
	goto done;

    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Build and format an IoBuffer wrapped in a ClientMessage.
 * Stores the wire format message in buf.
 * Returns true on success, false on failure.
 */
static bool
fmt_io_buf(int type, struct client_closure *closure,
    struct connection_buffer *buf)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    IoBuffer iobuf_msg = IO_BUFFER__INIT;
    TimeSpec delay = TIME_SPEC__INIT;
    bool ret = false;
    debug_decl(fmt_io_buf, SUDO_DEBUG_UTIL);

    if (!read_io_buf(closure))
	goto done;

    /* Fill in IoBuffer. */
    /* TODO: split buffer if it is too large */
    delay.tv_sec = closure->timing.delay.tv_sec;
    delay.tv_nsec = closure->timing.delay.tv_nsec;
    iobuf_msg.delay = &delay;
    iobuf_msg.data.data = (void *)closure->buf;
    iobuf_msg.data.len = closure->timing.u.nbytes;

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending IoBuffer length %zu, type %d, size %zu", __func__,
	iobuf_msg.data.len, type, io_buffer__get_packed_size(&iobuf_msg));

    /* Send ClientMessage, it doesn't matter which IoBuffer we set. */
    client_msg.u.ttyout_buf = &iobuf_msg;
    client_msg.type_case = type;
    if (!fmt_client_message(buf, &client_msg))
        goto done;

    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Build and format a ChangeWindowSize message wrapped in a ClientMessage.
 * Stores the wire format message in buf.
 * Returns true on success, false on failure.
 */
static bool
fmt_winsize(struct client_closure *closure, struct connection_buffer *buf)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    ChangeWindowSize winsize_msg = CHANGE_WINDOW_SIZE__INIT;
    TimeSpec delay = TIME_SPEC__INIT;
    struct timing_closure *timing = &closure->timing;
    bool ret = false;
    debug_decl(fmt_winsize, SUDO_DEBUG_UTIL);

    /* Fill in ChangeWindowSize message. */
    delay.tv_sec = timing->delay.tv_sec;
    delay.tv_nsec = timing->delay.tv_nsec;
    winsize_msg.delay = &delay;
    winsize_msg.rows = timing->u.winsize.lines;
    winsize_msg.cols = timing->u.winsize.cols;

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: sending ChangeWindowSize, %dx%d",
	__func__, winsize_msg.rows, winsize_msg.cols);

    /* Send ClientMessage */
    client_msg.u.winsize_event = &winsize_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_WINSIZE_EVENT;
    if (!fmt_client_message(buf, &client_msg))
        goto done;

    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Build and format a CommandSuspend message wrapped in a ClientMessage.
 * Stores the wire format message in buf.
 * Returns true on success, false on failure.
 */
static bool
fmt_suspend(struct client_closure *closure, struct connection_buffer *buf)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    CommandSuspend suspend_msg = COMMAND_SUSPEND__INIT;
    TimeSpec delay = TIME_SPEC__INIT;
    struct timing_closure *timing = &closure->timing;
    bool ret = false;
    debug_decl(fmt_suspend, SUDO_DEBUG_UTIL);

    /* Fill in CommandSuspend message. */
    delay.tv_sec = timing->delay.tv_sec;
    delay.tv_nsec = timing->delay.tv_nsec;
    suspend_msg.delay = &delay;
    if (sig2str(timing->u.signo, closure->buf) == -1)
	goto done;
    suspend_msg.signal = closure->buf;

    sudo_debug_printf(SUDO_DEBUG_INFO,
    	"%s: sending CommandSuspend, SIG%s", __func__, suspend_msg.signal);

    /* Send ClientMessage */
    client_msg.u.suspend_event = &suspend_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_SUSPEND_EVENT;
    if (!fmt_client_message(buf, &client_msg))
        goto done;

    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Read the next entry for the I/O log timing file and format a ClientMessage.
 * Stores the wire format message in the closure's write buffer.
 * Returns true on success, false on failure.
 */ 
static bool
fmt_next_iolog(struct client_closure *closure)
{
    struct timing_closure *timing = &closure->timing;
    struct connection_buffer *buf = &closure->write_buf;
    bool ret = false;
    debug_decl(fmt_next_iolog, SUDO_DEBUG_UTIL);

    if (buf->len != 0) {
	sudo_warnx(U_("%s: write buffer already in use"), __func__);
	debug_return_bool(false);
    }

    /* TODO: fill write buffer with multiple messages */
again:
    switch (iolog_read_timing_record(&closure->iolog_files[IOFD_TIMING], timing)) {
    case 0:
	/* OK */
	break;
    case 1:
	/* no more IO buffers */
	closure->state = SEND_EXIT;
	debug_return_bool(fmt_exit_message(closure));
    case -1:
    default:
	debug_return_bool(false);
    }

    /* Track elapsed time for comparison with commit points. */
    sudo_timespecadd(&timing->delay, &closure->elapsed, &closure->elapsed);

    /* If we have a restart point, ignore records until we hit it. */
    if (sudo_timespecisset(&closure->restart)) {
	if (sudo_timespeccmp(&closure->restart, &closure->elapsed, >=))
	    goto again;
	sudo_timespecclear(&closure->restart);	/* caught up */
    }

    switch (timing->event) {
    case IO_EVENT_STDIN:
	ret = fmt_io_buf(CLIENT_MESSAGE__TYPE_STDIN_BUF, closure, buf);
	break;
    case IO_EVENT_STDOUT:
	ret = fmt_io_buf(CLIENT_MESSAGE__TYPE_STDOUT_BUF, closure, buf);
	break;
    case IO_EVENT_STDERR:
	ret = fmt_io_buf(CLIENT_MESSAGE__TYPE_STDERR_BUF, closure, buf);
	break;
    case IO_EVENT_TTYIN:
	ret = fmt_io_buf(CLIENT_MESSAGE__TYPE_TTYIN_BUF, closure, buf);
	break;
    case IO_EVENT_TTYOUT:
	ret = fmt_io_buf(CLIENT_MESSAGE__TYPE_TTYOUT_BUF, closure, buf);
	break;
    case IO_EVENT_WINSIZE:
	ret = fmt_winsize(closure, buf);
	break;
    case IO_EVENT_SUSPEND:
	ret = fmt_suspend(closure, buf);
	break;
    default:
	sudo_warnx(U_("unexpected I/O event %d"), timing->event);
	break;
    }

    debug_return_bool(ret);
}

/*
 * Additional work to do after a ClientMessage was sent to the server.
 * Advances state and formats the next ClientMessage (if any).
 */
static bool
client_message_completion(struct client_closure *closure)
{
    debug_decl(client_message_completion, SUDO_DEBUG_UTIL);

    switch (closure->state) {
    case RECV_HELLO:
	/* Wait for ServerHello, nothing to write until then. */
	sudo_ev_del(closure->evbase, closure->write_ev);
	break;
    case SEND_ACCEPT:
	if (closure->accept_only) {
	    closure->state = SEND_EXIT;
	    debug_return_bool(fmt_exit_message(closure));
	}
	FALLTHROUGH;
    case SEND_RESTART:
	closure->state = SEND_IO;
	FALLTHROUGH;
    case SEND_IO:
	/* fmt_next_iolog() will advance state on EOF. */
	if (!fmt_next_iolog(closure))
	    debug_return_bool(false);
	break;
    case SEND_REJECT:
	/* Done writing, wait for server to close connection. */
	sudo_ev_del(closure->evbase, closure->write_ev);
	closure->state = FINISHED;
	break;
    case SEND_EXIT:
	/* Done writing, wait for final commit point if sending I/O. */
	sudo_ev_del(closure->evbase, closure->write_ev);
	closure->state = closure->accept_only ? FINISHED : CLOSING;
	break;
    default:
	sudo_warnx(U_("%s: unexpected state %d"), __func__, closure->state);
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Respond to a ServerHello message from the server.
 * Returns true on success, false on error.
 */
static bool
handle_server_hello(ServerHello *msg, struct client_closure *closure)
{
    size_t n;
    debug_decl(handle_server_hello, SUDO_DEBUG_UTIL);

    if (closure->state != RECV_HELLO) {
	sudo_warnx(U_("%s: unexpected state %d"), __func__, closure->state);
	debug_return_bool(false);
    }

    /* Check that ServerHello is valid. */
    if (msg->server_id == NULL || msg->server_id[0] == '\0') {
	sudo_warnx("%s", U_("invalid ServerHello"));
	debug_return_bool(false);
    }

    if (!testrun) {
        printf("Server ID: %s\n", msg->server_id);
        /* TODO: handle redirect */
        if (msg->redirect != NULL && msg->redirect[0] != '\0')
            printf("Redirect: %s\n", msg->redirect);
        for (n = 0; n < msg->n_servers; n++) {
            printf("Server %zu: %s\n", n + 1, msg->servers[n]);
        }
    }

    debug_return_bool(true);
}

/*
 * Respond to a CommitPoint message from the server.
 * Returns true on success, false on error.
 */
static bool
handle_commit_point(TimeSpec *commit_point, struct client_closure *closure)
{
    debug_decl(handle_commit_point, SUDO_DEBUG_UTIL);

    /* Only valid after we have sent an IO buffer. */
    if (closure->state < SEND_IO) {
	sudo_warnx(U_("%s: unexpected state %d"), __func__, closure->state);
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: commit point: [%lld, %d]",
	__func__, (long long)commit_point->tv_sec, commit_point->tv_nsec);
    closure->committed.tv_sec = commit_point->tv_sec;
    closure->committed.tv_nsec = commit_point->tv_nsec;

    debug_return_bool(true);
}

/*
 * Respond to a LogId message from the server.
 * Always returns true.
 */
static bool
handle_log_id(char *id, struct client_closure *closure)
{
    debug_decl(handle_log_id, SUDO_DEBUG_UTIL);

    if (!testrun)
        printf("Remote log ID: %s\n", id);

    debug_return_bool(true);
}

/*
 * Respond to a ServerError message from the server.
 * Always returns false.
 */
static bool
handle_server_error(char *errmsg, struct client_closure *closure)
{
    debug_decl(handle_server_error, SUDO_DEBUG_UTIL);

    sudo_warnx(U_("error message received from server: %s"), errmsg);
    debug_return_bool(false);
}

/*
 * Respond to a ServerAbort message from the server.
 * Always returns false.
 */
static bool
handle_server_abort(char *errmsg, struct client_closure *closure)
{
    debug_decl(handle_server_abort, SUDO_DEBUG_UTIL);

    sudo_warnx(U_("abort message received from server: %s"), errmsg);
    debug_return_bool(false);
}

/*
 * Respond to a ServerMessage from the server.
 * Returns true on success, false on error.
 */
static bool
handle_server_message(uint8_t *buf, size_t len,
    struct client_closure *closure)
{
    ServerMessage *msg;
    bool ret = false;
    debug_decl(handle_server_message, SUDO_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: unpacking ServerMessage", __func__);
    msg = server_message__unpack(NULL, len, buf);
    if (msg == NULL) {
	sudo_warnx("%s", U_("unable to unpack ServerMessage"));
	debug_return_bool(false);
    }

    switch (msg->type_case) {
    case SERVER_MESSAGE__TYPE_HELLO:
	if ((ret = handle_server_hello(msg->u.hello, closure))) {
	    if (sudo_timespecisset(&closure->restart)) {
		closure->state = SEND_RESTART;
		ret = fmt_restart_message(closure);
	    } else if (closure->reject_reason != NULL) {
		closure->state = SEND_REJECT;
		ret = fmt_reject_message(closure);
            } else {
		closure->state = SEND_ACCEPT;
		ret = fmt_accept_message(closure);
	    }
	}
	break;
    case SERVER_MESSAGE__TYPE_COMMIT_POINT:
	ret = handle_commit_point(msg->u.commit_point, closure);
	if (sudo_timespeccmp(&closure->elapsed, &closure->committed, ==)) {
	    sudo_ev_del(closure->evbase, closure->read_ev);
	    closure->state = FINISHED;
	    if (++finished_transmissions == nr_of_conns)
	        sudo_ev_loopexit(closure->evbase);
	}
	break;
    case SERVER_MESSAGE__TYPE_LOG_ID:
	ret = handle_log_id(msg->u.log_id, closure);
	break;
    case SERVER_MESSAGE__TYPE_ERROR:
	ret = handle_server_error(msg->u.error, closure);
	closure->state = ERROR;
	break;
    case SERVER_MESSAGE__TYPE_ABORT:
	ret = handle_server_abort(msg->u.abort, closure);
	closure->state = ERROR;
	break;
    default:
	sudo_warnx(U_("%s: unexpected type_case value %d"),
	    __func__, msg->type_case);
	break;
    }

    server_message__free_unpacked(msg, NULL);
    debug_return_bool(ret);
}

/*
 * Read and unpack a ServerMessage (read callback).
 */
static void
server_msg_cb(int fd, int what, void *v)
{
    struct client_closure *closure = v;
    struct connection_buffer *buf = &closure->read_buf;
    ssize_t nread;
    uint32_t msg_len;
    debug_decl(server_msg_cb, SUDO_DEBUG_UTIL);

    /* For TLS we may need to read as part of SSL_write(). */
    if (closure->write_instead_of_read) {
	closure->write_instead_of_read = false;
        client_msg_cb(fd, what, v);
        debug_return;
    }

    if (what == SUDO_EV_TIMEOUT) {
        sudo_warnx("%s", U_("timeout reading from server"));
        goto bad;
    }

#if defined(HAVE_OPENSSL)
    if (cert != NULL) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: reading ServerMessage (TLS)", __func__);
        nread = SSL_read(closure->ssl, buf->data + buf->len, buf->size - buf->len);
        if (nread <= 0) {
	    const char *errstr;
	    int err;

            switch (SSL_get_error(closure->ssl, nread)) {
		case SSL_ERROR_ZERO_RETURN:
		    /* ssl connection shutdown cleanly */
		    nread = 0;
		    break;
                case SSL_ERROR_WANT_READ:
                    /* ssl wants to read more, read event is always active */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_read returns SSL_ERROR_WANT_READ");
                    debug_return;
                case SSL_ERROR_WANT_WRITE:
                    /* ssl wants to write, schedule a write if not pending */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_read returns SSL_ERROR_WANT_WRITE");
		    if (!sudo_ev_pending(closure->write_ev, SUDO_EV_WRITE, NULL)) {
			/* Enable a temporary write event. */
			if (sudo_ev_add(closure->evbase, closure->write_ev, NULL, false) == -1) {
			    sudo_warnx("%s", U_("unable to add event to queue"));
			    goto bad;
			}
			closure->temporary_write_event = true;
		    }
		    /* Redirect write event to finish SSL_read() */
		    closure->read_instead_of_write = true;
                    debug_return;
                case SSL_ERROR_SSL:
                    /*
                     * For TLS 1.3, if the cert verify function on the server
                     * returns an error, OpenSSL will send an internal error
                     * alert when we read ServerHello.  Convert to a more useful
                     * message and hope that no actual internal error occurs.
                     */
                    err = ERR_get_error();
                    if (closure->state == RECV_HELLO &&
                        ERR_GET_REASON(err) == SSL_R_TLSV1_ALERT_INTERNAL_ERROR) {
                        errstr = "host name does not match certificate";
                    } else {
                        errstr = ERR_reason_error_string(err);
                    }
                    sudo_warnx("%s", errstr);
                    goto bad;
                case SSL_ERROR_SYSCALL:
                    sudo_warn("recv");
                    goto bad;
                default:
                    errstr = ERR_reason_error_string(ERR_get_error());
                    sudo_warnx("recv: %s", errstr);
                    goto bad;
            }
        }
    } else
#endif
    {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: reading ServerMessage", __func__);
	nread = recv(fd, buf->data + buf->len, buf->size - buf->len, 0);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received %zd bytes from server",
	__func__, nread);
    switch (nread) {
    case -1:
	if (errno == EAGAIN)
	    debug_return;
	sudo_warn("recv");
	goto bad;
    case 0:
	if (closure->state != FINISHED)
	    sudo_warnx("%s", U_("premature EOF"));
	goto bad;
    default:
	break;
    }
    buf->len += nread;

    while (buf->len - buf->off >= sizeof(msg_len)) {
	/* Read wire message size (uint32_t in network byte order). */
	memcpy(&msg_len, buf->data + buf->off, sizeof(msg_len));
	msg_len = ntohl(msg_len);

	if (msg_len > MESSAGE_SIZE_MAX) {
	    sudo_warnx(U_("server message too large: %u"), msg_len);
	    goto bad;
	}

	if (msg_len + sizeof(msg_len) > buf->len - buf->off) {
	    /* Incomplete message, we'll read the rest next time. */
	    if (!expand_buf(buf, msg_len + sizeof(msg_len)))
		    goto bad;
	    debug_return;
	}

	/* Parse ServerMessage, could be zero bytes. */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: parsing ServerMessage, size %u", __func__, msg_len);
	buf->off += sizeof(msg_len);
	if (!handle_server_message(buf->data + buf->off, msg_len, closure))
	    goto bad;
	buf->off += msg_len;
    }
    buf->len -= buf->off;
    buf->off = 0;
    debug_return;
bad:
    sudo_ev_del(closure->evbase, closure->read_ev);
    debug_return;
}

/*
 * Send a ClientMessage to the server (write callback).
 */
static void
client_msg_cb(int fd, int what, void *v)
{
    struct client_closure *closure = v;
    struct connection_buffer *buf = &closure->write_buf;
    ssize_t nwritten;
    debug_decl(client_msg_cb, SUDO_DEBUG_UTIL);

    /* For TLS we may need to write as part of SSL_read(). */
    if (closure->read_instead_of_write) {
	closure->read_instead_of_write = false;
        /* Delete write event if it was only due to SSL_read(). */
        if (closure->temporary_write_event) {
            closure->temporary_write_event = false;
            sudo_ev_del(closure->evbase, closure->write_ev);
        }
        server_msg_cb(fd, what, v);
        debug_return;
    }

    if (what == SUDO_EV_TIMEOUT) {
        sudo_warnx("%s", U_("timeout writing to server"));
        goto bad;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO,
    	"%s: sending %u bytes to server", __func__, buf->len - buf->off);

#if defined(HAVE_OPENSSL)
    if (cert != NULL) {
        nwritten = SSL_write(closure->ssl, buf->data + buf->off, buf->len - buf->off);
        if (nwritten <= 0) {
	    const char *errstr;

            switch (SSL_get_error(closure->ssl, nwritten)) {
		case SSL_ERROR_ZERO_RETURN:
		    /* ssl connection shutdown */
		    goto bad;
                case SSL_ERROR_WANT_READ:
                    /* ssl wants to read, read event always active */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_write returns SSL_ERROR_WANT_READ");
		    /* Redirect read event to finish SSL_write() */
		    closure->write_instead_of_read = true;
                    debug_return;
                case SSL_ERROR_WANT_WRITE:
		    /* ssl wants to write more, write event remains active */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_write returns SSL_ERROR_WANT_WRITE");
                    debug_return;
                case SSL_ERROR_SYSCALL:
                    sudo_warn("recv");
                    goto bad;
                default:
		    errstr = ERR_reason_error_string(ERR_get_error());
		    sudo_warnx("send: %s", errstr);
                    goto bad;
            }
        }
    } else
#endif
    {
	nwritten = send(fd, buf->data + buf->off, buf->len - buf->off, 0);
    }
    if (nwritten == -1) {
	sudo_warn("send");
	goto bad;
    }
    buf->off += nwritten;

    if (buf->off == buf->len) {
	/* sent entire message */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: finished sending %u bytes to server", __func__, buf->len);
	buf->off = 0;
	buf->len = 0;
	if (!client_message_completion(closure))
	    goto bad;
    }
    debug_return;

bad:
    sudo_ev_del(closure->evbase, closure->read_ev);
    sudo_ev_del(closure->evbase, closure->write_ev);
    debug_return;
}

/*
 * Parse a timespec on the command line of the form
 * seconds[,nanoseconds]
 */
static bool
parse_timespec(struct timespec *ts, char *strval)
{
    const char *errstr;
    char *nsecstr;
    debug_decl(parse_timespec, SUDO_DEBUG_UTIL);

    if ((nsecstr = strchr(strval, ',')) != NULL)
	*nsecstr++ = '\0';

    ts->tv_nsec = 0;
    ts->tv_sec = sudo_strtonum(strval, 0, TIME_T_MAX, &errstr);
    if (errstr != NULL) {
	sudo_warnx(U_("%s: %s"), strval, U_(errstr));
	debug_return_bool(false);
    }

    if (nsecstr != NULL) {
	ts->tv_nsec = sudo_strtonum(nsecstr, 0, LONG_MAX, &errstr);
	if (errstr != NULL) {
	    sudo_warnx(U_("%s: %s"), nsecstr, U_(errstr));
	    debug_return_bool(false);
	}
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: parsed timespec [%lld, %ld]",
	__func__, (long long)ts->tv_sec, ts->tv_nsec);
    debug_return_bool(true);
}

#if defined(HAVE_OPENSSL)
/*
 * Check that the server's certificate is valid that it contains the
 * server name or IP address.
 * Returns 0 if the cert is invalid, else 1.
 */
static int
verify_peer_identity(int preverify_ok, X509_STORE_CTX *ctx)
{
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

    if (validate_hostname(peer_cert, server_name, server_ip, 0) == MatchFound) {
        debug_return_int(1);
    }

    debug_return_int(0);
}

static SSL_CTX *
init_tls_client_context(const char *ca_bundle_file, const char *cert_file, const char *key_file)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;
    debug_decl(init_tls_client_context, SUDO_DEBUG_UTIL);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if ((method = TLS_client_method()) == NULL) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "creation of SSL_METHOD failed: %s",
            ERR_error_string(ERR_get_error(), NULL));
        goto bad;
    }
    if ((ctx = SSL_CTX_new(method)) == NULL) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "creation of new SSL_CTX object failed: %s",
            ERR_error_string(ERR_get_error(), NULL));
        goto bad;
    }
#ifdef HAVE_SSL_CTX_SET_MIN_PROTO_VERSION
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "unable to restrict min. protocol version: %s",
            ERR_error_string(ERR_get_error(), NULL));
        goto bad;
    }
#else
    SSL_CTX_set_options(ctx,
        SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1);
#endif

    if (cert_file) {
        if (!SSL_CTX_use_certificate_chain_file(ctx, cert_file)) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "unable to load cert to the ssl context: %s",
                ERR_error_string(ERR_get_error(), NULL));
            goto bad;
        }
        if (!SSL_CTX_use_PrivateKey_file(ctx, key_file, X509_FILETYPE_PEM)) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "unable to load key to the ssl context: %s",
                ERR_error_string(ERR_get_error(), NULL));
            goto bad;
        }
    }

    if (ca_bundle_file != NULL) {
        /* sets the location of the CA bundle file for verification purposes */
        if (SSL_CTX_load_verify_locations(ctx, ca_bundle_file, NULL) <= 0) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "calling SSL_CTX_load_verify_locations() failed: %s",
                ERR_error_string(ERR_get_error(), NULL));
            goto bad;
        }
    }

    if (verify_server) {
        /* verify server cert during the handshake */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_peer_identity);
    }

    goto done;

bad:
    SSL_CTX_free(ctx);

done:
    debug_return_ptr(ctx);
}

static void
tls_connect_cb(int sock, int what, void *v)
{
    struct client_closure *closure = v;
    struct sudo_event_base *evbase = closure->evbase;
    struct timespec timeo = { TLS_HANDSHAKE_TIMEO_SEC, 0 };
    const char *errstr;
    int con_stat;
    debug_decl(tls_connect_cb, SUDO_DEBUG_UTIL);

    if (what == SUDO_EV_TIMEOUT) {
        sudo_warnx("%s", U_("TLS handshake timeout occurred"));
        goto bad;
    }

    con_stat = SSL_connect(closure->ssl);

    if (con_stat == 1) {
	sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	    "SSL_connect successful");
        closure->tls_connect_state = true;
    } else {
        switch (SSL_get_error(closure->ssl, con_stat)) {
            /* TLS handshake is not finished, reschedule event */
            case SSL_ERROR_WANT_READ:
		sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
		    "SSL_connect returns SSL_ERROR_WANT_READ");
		if (what != SUDO_EV_READ) {
		    if (sudo_ev_set(closure->tls_connect_ev, closure->sock,
			    SUDO_EV_READ, tls_connect_cb, closure) == -1) {
			sudo_warnx("%s", U_("unable to set event"));
			goto bad;
		    }
		}
                if (sudo_ev_add(evbase, closure->tls_connect_ev, &timeo, false) == -1) {
                    sudo_warnx("%s", U_("unable to add event to queue"));
		    goto bad;
                }
		break;
            case SSL_ERROR_WANT_WRITE:
		sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
		    "SSL_connect returns SSL_ERROR_WANT_WRITE");
		if (what != SUDO_EV_WRITE) {
		    if (sudo_ev_set(closure->tls_connect_ev, closure->sock,
			    SUDO_EV_WRITE, tls_connect_cb, closure) == -1) {
			sudo_warnx("%s", U_("unable to set event"));
			goto bad;
		    }
		}
                if (sudo_ev_add(evbase, closure->tls_connect_ev, &timeo, false) == -1) {
                    sudo_warnx("%s", U_("unable to add event to queue"));
		    goto bad;
                }
		break;
	    case SSL_ERROR_SYSCALL:
                sudo_warnx(U_("TLS connection failed: %s"), strerror(errno));
		goto bad;
            default:
		errstr = ERR_reason_error_string(ERR_get_error());
                sudo_warnx(U_("TLS connection failed: %s"), errstr);
                goto bad;
        }
    }

    if (closure->tls_connect_state) {
	if (!testrun) {
	    printf("Negotiated protocol version: %s\n", SSL_get_version(closure->ssl));
	    printf("Negotiated ciphersuite: %s\n", SSL_get_cipher(closure->ssl));
	}

	/* Done with TLS connect, send ClientHello */
	sudo_ev_free(closure->tls_connect_ev);
	closure->tls_connect_ev = NULL;
	if (!fmt_client_hello(closure))
	    goto bad;
    }

    debug_return;

bad:
    sudo_ev_loopbreak(evbase);
    debug_return;
}

static bool
tls_setup(struct client_closure *closure)
{
    const char *errstr;
    debug_decl(tls_setup, SUDO_DEBUG_UTIL);

    if ((ssl_ctx = init_tls_client_context(ca_bundle, cert, key)) == NULL) {
	errstr = ERR_reason_error_string(ERR_get_error());
        sudo_warnx(U_("Unable to initialize ssl context: %s"), errstr);
        goto bad;
    }
    if ((closure->ssl = SSL_new(ssl_ctx)) == NULL) {
	errstr = ERR_reason_error_string(ERR_get_error());
        sudo_warnx(U_("Unable to allocate ssl object: %s"), errstr);
        goto bad;
    }
    if (SSL_set_fd(closure->ssl, closure->sock) <= 0) {
	errstr = ERR_reason_error_string(ERR_get_error());
        sudo_warnx(U_("Unable to attach socket to the ssl object: %s"),
	    errstr);
        goto bad;
    }

    if (sudo_ev_add(closure->evbase, closure->tls_connect_ev, NULL, false) == -1) {
	sudo_warnx("%s", U_("unable to add event to queue"));
	goto bad;
    }

    debug_return_bool(true);

bad:
    debug_return_bool(false);
}
#endif /* HAVE_OPENSSL */

/*
 * Free client closure contents.
 */
static void
client_closure_free(struct client_closure *closure)
{
    debug_decl(connection_closure_free, SUDO_DEBUG_UTIL);

    if (closure != NULL) {
	TAILQ_REMOVE(&connections, closure, entries);
#if defined(HAVE_OPENSSL)
        if (closure->ssl != NULL) {
            SSL_shutdown(closure->ssl);
            SSL_free(closure->ssl);
        }
	sudo_ev_free(closure->tls_connect_ev);
#endif
        sudo_ev_free(closure->read_ev);
        sudo_ev_free(closure->write_ev);
        free(closure->read_buf.data);
        free(closure->write_buf.data);
        free(closure->buf);
        close(closure->sock);
        free(closure);
    }

    debug_return;
}

/*
 * Initialize a new client closure
 */
static struct client_closure *
client_closure_alloc(int sock, struct sudo_event_base *base,
    struct timespec *elapsed, struct timespec *restart, const char *iolog_id,
    char *reject_reason, bool accept_only, struct eventlog *evlog)
{
    struct client_closure *closure;
    debug_decl(client_closure_alloc, SUDO_DEBUG_UTIL);

    if ((closure = calloc(1, sizeof(*closure))) == NULL)
	debug_return_ptr(NULL);

    closure->sock = sock;
    closure->evbase = base;

    TAILQ_INSERT_TAIL(&connections, closure, entries);

    closure->state = RECV_HELLO;
    closure->accept_only = accept_only;
    closure->reject_reason = reject_reason;
    closure->evlog = evlog;

    closure->elapsed.tv_sec = elapsed->tv_sec;
    closure->elapsed.tv_nsec = elapsed->tv_nsec;
    closure->restart.tv_sec = restart->tv_sec;
    closure->restart.tv_nsec = restart->tv_nsec;

    closure->iolog_id = iolog_id;

    closure->read_buf.size = 8 * 1024;
    closure->read_buf.data = malloc(closure->read_buf.size);
    if (closure->read_buf.data == NULL)
	goto bad;

    closure->read_ev = sudo_ev_alloc(sock, SUDO_EV_READ|SUDO_EV_PERSIST,
	server_msg_cb, closure);
    if (closure->read_ev == NULL)
	goto bad;

    closure->write_ev = sudo_ev_alloc(sock, SUDO_EV_WRITE|SUDO_EV_PERSIST,
	client_msg_cb, closure);
    if (closure->write_ev == NULL)
	goto bad;

#if defined(HAVE_OPENSSL)
    if (cert != NULL) {
	closure->tls_connect_ev = sudo_ev_alloc(sock, SUDO_EV_WRITE,
	    tls_connect_cb, closure);
	if (closure->tls_connect_ev == NULL)
	    goto bad;
    }
#endif

    debug_return_ptr(closure);
bad:
    client_closure_free(closure);
    debug_return_ptr(NULL);
}

#if defined(HAVE_OPENSSL)
static const char short_opts[] = "Ah:i:np:r:R:t:b:c:k:V";
#else
static const char short_opts[] = "Ah:i:Ip:r:R:t:V";
#endif
static struct option long_opts[] = {
    { "accept",		no_argument,		NULL,	'A' },
    { "help",		no_argument,		NULL,	1 },
    { "host",		required_argument,	NULL,	'h' },
    { "iolog-id",	required_argument,	NULL,	'i' },
    { "port",		required_argument,	NULL,	'p' },
    { "restart",	required_argument,	NULL,	'r' },
    { "reject",		required_argument,	NULL,	'R' },
    { "test",	    	optional_argument,	NULL,	't' },
#if defined(HAVE_OPENSSL)
    { "ca-bundle",	required_argument,	NULL,	'b' },
    { "cert",		required_argument,	NULL,	'c' },
    { "key",		required_argument,	NULL,	'k' },
    { "no-verify",	no_argument,		NULL,	'n' },
#endif
    { "version",	no_argument,		NULL,	'V' },
    { NULL,		no_argument,		NULL,	0 },
};

sudo_dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    struct client_closure *closure = NULL;
    struct sudo_event_base *evbase;
    struct eventlog *evlog;
    const char *port = NULL;
    struct timespec restart = { 0, 0 };
    struct timespec elapsed = { 0, 0 };
    bool accept_only = false;
    char *reject_reason = NULL;
    const char *iolog_id = NULL;
    const char *open_mode = "r";
    const char *errstr;
    int ch, sock, iolog_dir_fd, finished;
    debug_decl_vars(main, SUDO_DEBUG_MAIN);

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    {
	extern char *malloc_options;
	malloc_options = "S";
    }
#endif

    signal(SIGPIPE, SIG_IGN);

    initprogname(argc > 0 ? argv[0] : "sudo_sendlog");
    setlocale(LC_ALL, "");
    bindtextdomain("sudo", LOCALEDIR); /* XXX - add logsrvd domain */
    textdomain("sudo");

    /* Read sudo.conf and initialize the debug subsystem. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
        exit(EXIT_FAILURE);
    sudo_debug_register(getprogname(), NULL, NULL,
        sudo_conf_debug_files(getprogname()));

    if (protobuf_c_version_number() < 1003000)
	sudo_fatalx("%s", U_("Protobuf-C version 1.3 or higher required"));

    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	case 'A':
	    accept_only = true;
	    break;
	case 'h':
	    server_name = optarg;
	    break;
	case 'i':
	    iolog_id = optarg;
	    break;
	case 'R':
	    reject_reason = optarg;
	    break;
	case 'p':
	    port = optarg;
	    break;
	case 'r':
	    if (!parse_timespec(&restart, optarg))
		goto bad;
	    open_mode = "r+";
	    break;
	case 't':
	    nr_of_conns = sudo_strtonum(optarg, 1, INT_MAX, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), optarg, U_(errstr));
		goto bad;
	    }
	    testrun = true;
	    break;
	case 1:
	    help();
	    break;
#if defined(HAVE_OPENSSL)
	case 'b':
	    ca_bundle = optarg;
	    break;
	case 'c':
	    cert = optarg;
	    break;
	case 'k':
	    key = optarg;
	    break;
	case 'n':
	    verify_server = false;
	    break;
#endif
	case 'V':
	    (void)printf(_("%s version %s\n"), getprogname(),
		PACKAGE_VERSION);
	    return 0;
	default:
	    usage(true);
	}
    }
    argc -= optind;
    argv += optind;

#if defined(HAVE_OPENSSL)
    /* if no key file is given explicitly, try to load the key from the cert */
    if (cert != NULL) {
	if (key == NULL)
	    key = cert;
	if (port == NULL)
	    port = DEFAULT_PORT_TLS;
    }
#endif
    if (port == NULL)
	port = DEFAULT_PORT;

    if (sudo_timespecisset(&restart) != (iolog_id != NULL)) {
	sudo_warnx("%s", U_("both restart point and iolog ID must be specified"));
	usage(true);
    }
    if (sudo_timespecisset(&restart) && (accept_only || reject_reason)) {
	sudo_warnx("%s", U_("a restart point may not be set when no I/O is sent"));
	usage(true);
    }

    /* Remaining arg should be to I/O log dir to send. */
    if (argc != 1)
	usage(true);
    iolog_dir = argv[0];
    if ((iolog_dir_fd = open(iolog_dir, O_RDONLY)) == -1) {
	sudo_warn("%s", iolog_dir);
	goto bad;
    }

    /* Parse I/O log info file. */
    if ((evlog = iolog_parse_loginfo(iolog_dir_fd, iolog_dir)) == NULL)
	goto bad;

    if ((evbase = sudo_ev_base_alloc()) == NULL)
	sudo_fatal(NULL);

    if (testrun)
        printf("connecting clients...\n");

    for (int i = 0; i < nr_of_conns; i++) {
        sock = connect_server(server_name, port);
        if (sock == -1)
            goto bad;
        
        if (!testrun)
            printf("Connected to %s:%s\n", server_name, port);

        closure = client_closure_alloc(sock, evbase, &elapsed, &restart,
	    iolog_id, reject_reason, accept_only, evlog);
        if (closure == NULL)
            goto bad;

        /* Open the I/O log files and seek to restart point if there is one. */
        if (!iolog_open_all(iolog_dir_fd, iolog_dir, closure->iolog_files, open_mode))
            goto bad;
        if (sudo_timespecisset(&closure->restart)) {
            if (!iolog_seekto(iolog_dir_fd, iolog_dir, closure->iolog_files,
		    &closure->elapsed, &closure->restart))
                goto bad;
        }

#if defined(HAVE_OPENSSL)
	if (cert != NULL) {
	    if (!tls_setup(closure))
		goto bad;
	} else
#endif
	{
	    /* No TLS, send ClientHello */
	    if (!fmt_client_hello(closure))
		goto bad;
	}
    }  

    if (testrun)
        printf("sending logs...\n");

    struct timespec t_start, t_end, t_result;
    sudo_gettime_real(&t_start);

    sudo_ev_dispatch(evbase);
    sudo_ev_base_free(evbase);

    sudo_gettime_real(&t_end);
    sudo_timespecsub(&t_end, &t_start, &t_result);

    finished = 0;
    while ((closure = TAILQ_FIRST(&connections)) != NULL) {
        if (closure->state == FINISHED) {
	    finished++;
	} else {
            sudo_warnx(U_("exited prematurely with state %d"), closure->state);
            sudo_warnx(U_("elapsed time sent to server [%lld, %ld]"),
                (long long)closure->elapsed.tv_sec, closure->elapsed.tv_nsec);
            sudo_warnx(U_("commit point received from server [%lld, %ld]"),
                (long long)closure->committed.tv_sec, closure->committed.tv_nsec);
        }
        client_closure_free(closure);
    }
    eventlog_free(evlog);
#if defined(HAVE_OPENSSL)
    SSL_CTX_free(ssl_ctx);
#endif

    if (finished != 0) {
        printf("%d I/O log%s transmitted successfully in %lld.%.9ld seconds\n",
	    finished, nr_of_conns > 1 ? "s" : "",
            (long long)t_result.tv_sec, t_result.tv_nsec);
        debug_return_int(EXIT_SUCCESS);
    }

bad:
    debug_return_int(EXIT_FAILURE);
}
