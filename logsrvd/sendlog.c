/*
 * Copyright (c) 2019-2020 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include "log_server.pb-c.h"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */
#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "sudo_event.h"
#include "sudo_fatal.h"
#include "sudo_iolog.h"
#include "sendlog.h"

#if defined(HAVE_OPENSSL)
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif
#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

#if defined(HAVE_OPENSSL)
# define TLS_HANDSHAKE_TIMEO_SEC 10
#endif

TAILQ_HEAD(connection_list, client_closure);
static struct connection_list connections = TAILQ_HEAD_INITIALIZER(connections);

static char *iolog_dir;
static bool testrun = false;
static int nr_of_conns = 1;
static int finished_transmissions = 0;

#if defined(HAVE_OPENSSL)
static bool tls = false;
static bool tls_reqcert = false;
static bool tls_server_auth = false;
static SSL_CTX *ssl_ctx = NULL;
const char *ca_bundle = NULL;
const char *cert = NULL;
const char *key = NULL;
#endif

/* Server callback may redirect to client callback for TLS. */
static void client_msg_cb(int fd, int what, void *v);
static void server_msg_cb(int fd, int what, void *v);

static void
usage(bool fatal)
{
#if defined(HAVE_OPENSSL)
    fprintf(stderr, "usage: %s [-b ca_bundle] [-c cert_file] [-h host] "
	"[-i iolog-id] [-k key_file] [-p port] "
#else
    fprintf(stderr, "usage: %s [-h host] [-i iolog-id] [-p port] "
#endif
	"[-r restart-point] /path/to/iolog\n", getprogname());
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
	"  -h, --host               host to send logs to\n"
	"  -i, --iolog_id           remote ID of I/O log to be resumed\n"
	"  -p, --port               port to use when connecting to host\n"
	"  -r, --restart            restart previous I/O log transfer\n"
	"  -t, --test               test audit server by sending selected I/O log n times in parallel\n"
#if defined(HAVE_OPENSSL)
	"  -b, --ca-bundle          certificate bundle file to verify server's cert against\n"
	"  -c, --cert               certificate file for TLS handshake\n"
	"  -k, --key                private key file\n"
#endif
	"  -V, --version            display version information and exit\n"));
    exit(EXIT_SUCCESS);
}

#if defined(HAVE_OPENSSL)
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

    if (tls_server_auth) {
        /* sets the location of the CA bundle file for verification purposes */
        if (SSL_CTX_load_verify_locations(ctx, ca_bundle_file, NULL) <= 0) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "calling SSL_CTX_load_verify_locations() failed: %s",
                ERR_error_string(ERR_get_error(), NULL));
            goto bad;
        }

        /* set verify server cert during the handshake */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    goto exit;

bad:
    SSL_CTX_free(ctx);

exit:
    return ctx;
}

static void
tls_connect_cb(int sock, int what, void *v)
{
    struct client_closure *closure = v;
    struct sudo_event_base *evbase = closure->tls_connect_ev->base;
    struct timespec timeo = { TLS_HANDSHAKE_TIMEO_SEC, 0 };
    int con_stat, err;

    debug_decl(tls_connect_cb, SUDO_DEBUG_UTIL);

    if (what == SUDO_EV_TIMEOUT) {
        sudo_warnx(U_("TLS handshake timeout occurred"));
        goto bad;
    }

    con_stat = SSL_connect(closure->ssl);

    if (con_stat == 1) {
        closure->tls_connect_state = true;
    } else {
        switch ((err = SSL_get_error(closure->ssl, con_stat))) {
            /* TLS connect successful */
            case SSL_ERROR_NONE:
                closure->tls_connect_state = true;
                break;
            /* TLS handshake is not finished, reschedule event */
            case SSL_ERROR_WANT_READ:
		sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
		    "SSL_connect returns SSL_ERROR_WANT_READ");
		if (what != SUDO_EV_READ) {
		    if (sudo_ev_set(closure->tls_connect_ev, closure->sock,
			    SUDO_EV_READ, tls_connect_cb, closure) == -1) {
			sudo_warnx(U_("unable to set event"));
			goto bad;
		    }
		}
                if (sudo_ev_add(evbase, closure->tls_connect_ev, &timeo, false) == -1) {
                    sudo_warnx(U_("unable to add event to queue"));
		    goto bad;
                }
		break;
            case SSL_ERROR_WANT_WRITE:
		sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
		    "SSL_connect returns SSL_ERROR_WANT_WRITE");
		if (what != SUDO_EV_WRITE) {
		    if (sudo_ev_set(closure->tls_connect_ev, closure->sock,
			    SUDO_EV_WRITE, tls_connect_cb, closure) == -1) {
			sudo_warnx(U_("unable to set event"));
			goto bad;
		    }
		}
                if (sudo_ev_add(evbase, closure->tls_connect_ev, &timeo, false) == -1) {
                    sudo_warnx(U_("unable to add event to queue"));
		    goto bad;
                }
		break;
            default:
                sudo_warnx(U_("SSL_connect failed: ssl_error=%d, stack=%s\n"),
                    err, ERR_error_string(ERR_get_error(), NULL));
                break;
        }
    }

    debug_return;

bad:
    sudo_ev_loopbreak(evbase);
    debug_return;
}

static bool
tls_connect_async(struct client_closure *closure)
{
    struct sudo_event_base *evbase;
    debug_decl(tls_connect_async, SUDO_DEBUG_UTIL);

    closure->tls_connect_state = false;
    evbase = sudo_ev_base_alloc();
    closure->tls_connect_ev = sudo_ev_alloc(closure->sock, SUDO_EV_WRITE,
        tls_connect_cb, closure);
    if (evbase == NULL || closure->tls_connect_ev == NULL) {
	sudo_warnx(U_("unable to allocate memory"));
	goto done;
    }
    if (sudo_ev_add(evbase, closure->tls_connect_ev, NULL, false) == -1) {
	sudo_warnx(U_("unable to add event to queue"));
	goto done;
    }
    if (sudo_ev_dispatch(evbase) == -1 || sudo_ev_got_break(evbase)) {
	sudo_warn(U_("error in event loop"));
	goto done;
    }

done:
    sudo_ev_base_free(evbase);
    sudo_ev_free(closure->tls_connect_ev);

    debug_return_int(closure->tls_connect_state);
}

static bool
do_tls_handshake(struct client_closure *closure)
{
    debug_decl(do_tls_handshake, SUDO_DEBUG_UTIL);

    if (ca_bundle == NULL) {
        sudo_warnx("%s", U_("CA bundle file was not specified"));
        goto bad;
    }
    if (tls_reqcert && (cert == NULL)) {
        sudo_warnx("%s", U_("Client certificate was not specified"));
        goto bad;
    }
    if ((ssl_ctx = init_tls_client_context(ca_bundle, cert, key)) == NULL) {
        sudo_warnx(U_("Unable to initialize ssl context: %s"),
            ERR_error_string(ERR_get_error(), NULL));
        goto bad;
    }
    if ((closure->ssl = SSL_new(ssl_ctx)) == NULL) {
        sudo_warnx(U_("Unable to allocate ssl object: %s\n"),
            ERR_error_string(ERR_get_error(), NULL));
        goto bad;
    }
    if (SSL_set_fd(closure->ssl, closure->sock) <= 0) {
        sudo_warnx(U_("Unable to attach socket to the ssl object: %s\n"),
            ERR_error_string(ERR_get_error(), NULL));
        goto bad;
    }

    if (!tls_connect_async(closure))
        goto bad;

    if (!testrun) {
        printf("Negotiated protocol version: %s\n", SSL_get_version(closure->ssl));
        printf("Negotiated ciphersuite: %s\n", SSL_get_cipher(closure->ssl));
    }

    debug_return_bool(true);

bad:
    debug_return_bool(false);
}
#endif /* HAVE_OPENSSL */

/*
 * Connect to specified host:port
 * If host has multiple addresses, the first one that connects is used.
 * Returns open socket or -1 on error.
 */
static int
connect_server(const char *host, const char *port)
{
    struct addrinfo hints, *res, *res0;
    const char *cause = "getaddrinfo";
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
	break;	/* success */
    }
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
    freeaddrinfo(res0);

    debug_return_int(sock);
}

/*
 * Free client closure contents.
 */
static void
client_closure_free(struct client_closure *closure)
{
    debug_decl(connection_closure_free, SUDO_DEBUG_UTIL);

    if (closure != NULL) {
#if defined(HAVE_OPENSSL)
        SSL_free(closure->ssl);
#endif
        TAILQ_REMOVE(&connections, closure, entries);
        close(closure->sock);
        sudo_ev_free(closure->read_ev);
        sudo_ev_free(closure->write_ev);
#if defined(HAVE_OPENSSL)
        sudo_ev_free(closure->tls_connect_ev);
#endif
        free(closure->read_buf.data);
        free(closure->write_buf.data);
        free(closure);
    }

    debug_return;
}

/*
 * Initialize a new client closure
 */
static struct client_closure *
client_closure_alloc(int sock,
    struct timespec *elapsed, struct timespec *restart, const char *iolog_id,
    struct iolog_info *log_info)
{
    struct client_closure *closure;
    debug_decl(client_closure_alloc, SUDO_DEBUG_UTIL);

    if ((closure = calloc(1, sizeof(*closure))) == NULL)
	debug_return_ptr(NULL);

    closure->sock = sock;

    TAILQ_INSERT_TAIL(&connections, closure, entries);

    closure->state = RECV_HELLO;
    closure->log_info = log_info;

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
    closure->tls_connect_ev = sudo_ev_alloc(sock, SUDO_EV_WRITE,
	tls_connect_cb, closure);
    if (closure->tls_connect_ev == NULL)
	goto bad;
#endif

    debug_return_ptr(closure);
bad:
    client_closure_free(closure);
    debug_return_ptr(NULL);
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
    	sudo_warnx(U_("client message too large: %zu\n"), len);
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
    InfoMessage__StringList runargv = INFO_MESSAGE__STRING_LIST__INIT;
    struct iolog_info *log_info = closure->log_info;
    char *hostname;
    bool ret = false;
    size_t n;
    debug_decl(fmt_accept_message, SUDO_DEBUG_UTIL);

    /*
     * Fill in AcceptMessage and add it to ClientMessage.
     */
    if ((hostname = sudo_gethostname()) == NULL) {
	sudo_warn("gethostname");
	debug_return_bool(false);
    }

    /* Sudo I/O logs only store start time in seconds. */
    tv.tv_sec = log_info->tstamp;
    tv.tv_nsec = 0;
    accept_msg.submit_time = &tv;

    /* Client will send IoBuffer messages. */
    accept_msg.expect_iobufs = true;

    /* Split command into a StringList. */
    runargv.strings = split_command(log_info->cmd, &runargv.n_strings);
    if (runargv.strings == NULL)
	sudo_fatal(NULL);

    /* The sudo I/O log info file has limited info. */
    accept_msg.n_info_msgs = 10;
    accept_msg.info_msgs = calloc(accept_msg.n_info_msgs, sizeof(InfoMessage *));
    if (accept_msg.info_msgs == NULL) {
	accept_msg.n_info_msgs = 0;
	goto done;
    }
    for (n = 0; n < accept_msg.n_info_msgs; n++) {
	accept_msg.info_msgs[n] = malloc(sizeof(InfoMessage));
	if (accept_msg.info_msgs[n] == NULL) {
	    accept_msg.n_info_msgs = n;
	    goto done;
	}
	info_message__init(accept_msg.info_msgs[n]);
    }

    /* Fill in info_msgs */
    n = 0;
    accept_msg.info_msgs[n]->key = "command";
    accept_msg.info_msgs[n]->strval = log_info->cmd;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    accept_msg.info_msgs[n]->key = "columns";
    accept_msg.info_msgs[n]->numval = log_info->cols;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_NUMVAL;
    n++;

    accept_msg.info_msgs[n]->key = "lines";
    accept_msg.info_msgs[n]->numval = log_info->lines;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_NUMVAL;
    n++;

    accept_msg.info_msgs[n]->key = "runargv";
    accept_msg.info_msgs[n]->strlistval = &runargv;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRLISTVAL;
    n++;

    if (log_info->runas_group != NULL) {
	accept_msg.info_msgs[n]->key = "rungroup";
	accept_msg.info_msgs[n]->strval = log_info->runas_group;
	accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
	n++;
    }

    accept_msg.info_msgs[n]->key = "runuser";
    accept_msg.info_msgs[n]->strval = log_info->runas_user;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    accept_msg.info_msgs[n]->key = "submitcwd";
    accept_msg.info_msgs[n]->strval = log_info->cwd;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    accept_msg.info_msgs[n]->key = "submithost";
    accept_msg.info_msgs[n]->strval = hostname;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    accept_msg.info_msgs[n]->key = "submituser";
    accept_msg.info_msgs[n]->strval = log_info->user;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    accept_msg.info_msgs[n]->key = "ttyname";
    accept_msg.info_msgs[n]->strval = log_info->tty;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    /* Update n_info_msgs. */
    accept_msg.n_info_msgs = n;

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending AcceptMessage, array length %zu", __func__, n);

    /* Schedule ClientMessage */
    client_msg.accept_msg = &accept_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_ACCEPT_MSG;
    ret = fmt_client_message(&closure->write_buf, &client_msg);
    if (ret) {
	if (sudo_ev_add(NULL, closure->write_ev, NULL, false) == -1)
	    ret = false;
    }

done:
    for (n = 0; n < accept_msg.n_info_msgs; n++) {
	free(accept_msg.info_msgs[n]);
    }
    free(accept_msg.info_msgs);
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
    client_msg.restart_msg = &restart_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_RESTART_MSG;
    ret = fmt_client_message(&closure->write_buf, &client_msg);
    if (ret) {
	if (sudo_ev_add(NULL, closure->write_ev, NULL, false) == -1)
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
    client_msg.exit_msg = &exit_msg;
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
    client_msg.ttyout_buf = &iobuf_msg;
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
    client_msg.winsize_event = &winsize_msg;
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
    client_msg.suspend_event = &suspend_msg;
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
    case SEND_ACCEPT:
    case SEND_RESTART:
	closure->state = SEND_IO;
	/* FALLTHROUGH */
    case SEND_IO:
	/* fmt_next_iolog() will advance state on EOF. */
	if (!fmt_next_iolog(closure))
	    debug_return_bool(false);
	break;
    case SEND_EXIT:
	/* Done writing, just waiting for final commit point. */
	sudo_ev_del(NULL, closure->write_ev);
	closure->state = CLOSING;
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

    /* Sanity check ServerHello message. */
    if (msg->server_id == NULL || msg->server_id[0] == '\0') {
	sudo_warnx("%s", U_("invalid ServerHello"));
	debug_return_bool(false);
    }

#if defined(HAVE_OPENSSL)
    tls = msg->tls;
    tls_reqcert = msg->tls_reqcert;
    tls_server_auth = msg->tls_server_auth;
#endif

    if (!testrun) {
        printf("server ID: %s\n", msg->server_id);
        /* TODO: handle redirect */
        if (msg->redirect != NULL && msg->redirect[0] != '\0')
            printf("redirect: %s\n", msg->redirect);
        for (n = 0; n < msg->n_servers; n++) {
            printf("server %zu: %s\n", n + 1, msg->servers[n]);
        }

#if defined(HAVE_OPENSSL)
        if (tls) {
            printf("Requested protocol: TLS\n");
            printf("Server authentication: %s\n", tls_server_auth ? "Required":"Not Required");
            printf("Client authentication: %s\n", tls_reqcert ? "Required":"Not Required");
        } else {
            printf("Requested protocol: ClearText\n");
        }
#endif
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
        printf("remote log ID: %s\n", id);

    if ((closure->iolog_id = strdup(id)) == NULL)
	sudo_fatal(NULL);
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
	if ((ret = handle_server_hello(msg->hello, closure))) {
        /* if server wants to communicate over TLS,
         * we have to initialize tls context and do
         * a tls connection to the server
         */
#if defined(HAVE_OPENSSL)
        if (tls && !do_tls_handshake(closure))
            debug_return_bool(false);
#endif
	    if (sudo_timespecisset(&closure->restart)) {
            closure->state = SEND_RESTART;
            ret = fmt_restart_message(closure);
	    } else {
            closure->state = SEND_ACCEPT;
            ret = fmt_accept_message(closure);
	    }
	}
	break;
    case SERVER_MESSAGE__TYPE_COMMIT_POINT:
	ret = handle_commit_point(msg->commit_point, closure);
	if (sudo_timespeccmp(&closure->elapsed, &closure->committed, ==)) {
	    sudo_ev_del(NULL, closure->read_ev);
	    closure->state = FINISHED;
        if (++finished_transmissions == nr_of_conns)
	        sudo_ev_loopexit(NULL);
    }
	break;
    case SERVER_MESSAGE__TYPE_LOG_ID:
	ret = handle_log_id(msg->log_id, closure);
	break;
    case SERVER_MESSAGE__TYPE_ERROR:
	ret = handle_server_error(msg->error, closure);
	closure->state = ERROR;
	break;
    case SERVER_MESSAGE__TYPE_ABORT:
	ret = handle_server_abort(msg->abort, closure);
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
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "Reading from server timed out");
        goto bad;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: reading ServerMessage", __func__);
#if defined(HAVE_OPENSSL)
    if (tls && closure->state != RECV_HELLO) {
        nread = SSL_read(closure->ssl, buf->data + buf->len, buf->size - buf->len);
        if (nread <= 0) {
            int read_status = SSL_get_error(closure->ssl, nread);
            switch (read_status) {
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
			if (sudo_ev_add(NULL, closure->write_ev, NULL, false) == -1) {
			    sudo_warnx(U_("unable to add event to queue"));
			    goto bad;
			}
			closure->temporary_write_event = true;
		    }
		    /* Redirect write event to finish SSL_read() */
		    closure->read_instead_of_write = true;
                    debug_return;
                default:
                    break;
            }
        }
    } else {
        nread = recv(fd, buf->data + buf->len, buf->size - buf->len, 0);
    }
#else
    nread = recv(fd, buf->data + buf->len, buf->size - buf->len, 0);
#endif
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received %zd bytes from server",
	__func__, nread);
    switch (nread) {
    case -1:
	if (errno == EAGAIN)
	    debug_return;
	sudo_warn("recv");
	goto bad;
    case 0:
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
	    sudo_warnx(U_("server message too large: %u\n"), msg_len);
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
    close(fd);
    client_closure_free(closure);
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
            sudo_ev_del(NULL, closure->write_ev);
        }
        server_msg_cb(fd, what, v);
        debug_return;
    }

    if (what == SUDO_EV_TIMEOUT) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "Writing to server timed out");
        goto bad;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO,
    	"%s: sending %u bytes to server", __func__, buf->len - buf->off);

#if defined(HAVE_OPENSSL)
    if (tls) {
        nwritten = SSL_write(closure->ssl, buf->data + buf->off, buf->len - buf->off);
        if (nwritten <= 0) {
            int write_status = SSL_get_error(closure->ssl, nwritten);
            switch (write_status) {
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
                default:
                    break;
            }
        }
    } else {
        nwritten = send(fd, buf->data + buf->off, buf->len - buf->off, 0);
    }
#else
    nwritten = send(fd, buf->data + buf->off, buf->len - buf->off, 0);
#endif
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
    close(fd);
    client_closure_free(closure);
    debug_return;
}

/*
 * Parse a timespec on the command line of the form
 * seconds[,nanoseconds]
 */
static bool
parse_timespec(struct timespec *ts, const char *strval)
{
    long long tv_sec;
    long tv_nsec;
    char *ep;
    debug_decl(parse_timespec, SUDO_DEBUG_UTIL);

    errno = 0;
    tv_sec = strtoll(strval, &ep, 10);
    if (strval == ep || (*ep != ',' && *ep != '\0'))
	debug_return_bool(false);
#if TIME_T_MAX != LLONG_MAX
    if (tv_sec > TIME_T_MAX)
	debug_return_bool(false);
#endif
    if (tv_sec < 0 || (errno == ERANGE && tv_sec == LLONG_MAX))
	debug_return_bool(false);
    strval = ep + 1;

    errno = 0;
    tv_nsec = strtol(strval, &ep, 10);
    if (strval == ep || *ep != '\0')
	debug_return_bool(false);
    if (tv_nsec < 0 || (errno == ERANGE && tv_nsec == LONG_MAX))
	debug_return_bool(false);

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: parsed timespec [%lld, %ld]",
	__func__, tv_sec, tv_nsec);
    ts->tv_sec = (time_t)tv_sec;
    ts->tv_nsec = tv_nsec;
    debug_return_bool(true);
}

#if defined(HAVE_OPENSSL)
static const char short_opts[] = "h:i:p:r:t:b:c:k:V";
#else
static const char short_opts[] = "h:i:p:r:V";
#endif
static struct option long_opts[] = {
    { "help",		no_argument,		NULL,	1 },
    { "host",		required_argument,	NULL,	'h' },
    { "iolog-id",	required_argument,	NULL,	'i' },
    { "port",		required_argument,	NULL,	'p' },
    { "restart",	required_argument,	NULL,	'r' },
    { "test",	    optional_argument,	NULL,	't' },
#if defined(HAVE_OPENSSL)
    { "ca-bundle",	required_argument,	NULL,	'b' },
    { "cert",		required_argument,	NULL,	'c' },
    { "key",		required_argument,	NULL,	'k' },
#endif
    { "version",	no_argument,		NULL,	'V' },
    { NULL,		no_argument,		NULL,	0 },
};

__dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    struct client_closure *closure = NULL;
    struct sudo_event_base *evbase;
    struct iolog_info *log_info;
    const char *host = "localhost";
    const char *port = DEFAULT_PORT_STR;
    struct timespec restart = { 0, 0 };
    struct timespec elapsed = { 0, 0 };
    const char *iolog_id = NULL;
    const char *open_mode = "r";
    int ch, sock, iolog_dir_fd, fd;
    FILE *fp;
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
	case 'h':
	    host = optarg;
	    break;
	case 'i':
	    iolog_id = optarg;
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
        if (sscanf(optarg, "%d", &nr_of_conns) != 1)
            goto bad;
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
    if (cert && !key) {
        key = cert;
    }
#endif

    if (sudo_timespecisset(&restart) != (iolog_id != NULL)) {
	sudo_warnx("%s", U_("both restart point and iolog ID must be specified"));
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
    fd = openat(iolog_dir_fd, "log", O_RDONLY, 0);
    if (fd == -1 || (fp = fdopen(fd, "r")) == NULL) {
	sudo_warn("%s/log", iolog_dir);
	goto bad;
    }
    if ((log_info = iolog_parse_loginfo(fp, iolog_dir)) == NULL)
	goto bad;

    if ((evbase = sudo_ev_base_alloc()) == NULL)
	sudo_fatal(NULL);
    sudo_ev_base_setdef(evbase);

    if (testrun)
        printf("connecting clients...\n");

    for (int i = 0; i < nr_of_conns; i++) {
        sock = connect_server(host, port);
        if (sock == -1)
            goto bad;
        
        if (!testrun)
            printf("Connected to %s:%s\n", host, port);

        closure = client_closure_alloc(sock, &elapsed, &restart, iolog_id, log_info);
        if (!closure)
            goto bad;

        /* Open the I/O log files and seek to restart point if there is one. */
        if (!iolog_open_all(iolog_dir_fd, iolog_dir, closure->iolog_files, open_mode))
            goto bad;
        if (sudo_timespecisset(&closure->restart)) {
            if (!iolog_seekto(iolog_dir_fd, iolog_dir, closure->iolog_files,
		    &closure->elapsed, &closure->restart))
                goto bad;
        }

        if (sudo_ev_add(evbase, closure->read_ev, NULL, false) == -1)
            goto bad;
    }  

    if (testrun)
        printf("sending logs...\n");

    struct timespec t_start, t_end, t_result;
    sudo_gettime_real(&t_start);

    sudo_ev_dispatch(evbase);

    sudo_gettime_real(&t_end);
    sudo_timespecsub(&t_end, &t_start, &t_result);

    TAILQ_FOREACH(closure, &connections, entries) {
        if (closure->state != FINISHED) {
        sudo_warnx(U_("exited prematurely with state %d"), closure->state);
        sudo_warnx(U_("elapsed time sent to server [%lld, %ld]"),
            (long long)closure->elapsed.tv_sec, closure->elapsed.tv_nsec);
        sudo_warnx(U_("commit point received from server [%lld, %ld]"),
            (long long)closure->committed.tv_sec, closure->committed.tv_nsec);
        goto bad;
        }
    }

    printf("I/O log%s transmitted successfully in %lld.%.9ld seconds\n",
        nr_of_conns > 1 ? "s":"",
        (long long)t_result.tv_sec, t_result.tv_nsec);
        
    debug_return_int(EXIT_SUCCESS);
bad:
    debug_return_int(EXIT_FAILURE);
}
