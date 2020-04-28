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

#ifdef SUDOERS_IOLOG_CLIENT

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
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
#include <pwd.h>
#include <grp.h>

#if defined(HAVE_OPENSSL)
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/x509v3.h>
#endif /* HAVE_OPENSSL */

#define NEED_INET_NTOP		/* to expose sudo_inet_ntop in sudo_compat.h */

#include "sudoers.h"
#include "sudo_event.h"
#include "iolog_plugin.h"
#include "hostcheck.h"

#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif

/* Server callback may redirect to client callback for TLS. */
static void client_msg_cb(int fd, int what, void *v);
static void server_msg_cb(int fd, int what, void *v);

static void
connect_cb(int sock, int what, void *v)
{
    int optval, ret, *errnump = v;
    socklen_t optlen = sizeof(optval);
    debug_decl(connect_cb, SUDOERS_DEBUG_UTIL);

    if (what == SUDO_PLUGIN_EV_TIMEOUT) {
	*errnump = ETIMEDOUT;
    } else {
	ret = getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
	*errnump = ret == 0 ? optval : errno;
    }

    debug_return;
}

/*
 * Like connect(2) but with a timeout.
 */
static int
timed_connect(int sock, const struct sockaddr *addr, socklen_t addrlen,
    struct timespec *timo)
{
    struct sudo_event_base *evbase = NULL;
    struct sudo_event *connect_event = NULL;
    int ret, errnum = 0;
    debug_decl(timed_connect, SUDOERS_DEBUG_UTIL);

    ret = connect(sock, addr, addrlen);
    if (ret == -1 && errno == EINPROGRESS) {
	evbase = sudo_ev_base_alloc();
	connect_event = sudo_ev_alloc(sock, SUDO_PLUGIN_EV_WRITE, connect_cb,
	    &errnum);
	if (evbase == NULL || connect_event == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
	if (sudo_ev_add(evbase, connect_event, timo, false) == -1) {
	    sudo_warnx(U_("unable to add event to queue"));
	    goto done;
	}
	if (sudo_ev_dispatch(evbase) == -1) {
	    sudo_warn(U_("error in event loop"));
	    goto done;
	}
	if (errnum == 0)
	    ret = 0;
	else
	    errno = errnum;
    }

done:
    sudo_ev_base_free(evbase);
    sudo_ev_free(connect_event);

    debug_return_int(ret);
}

/*
 * Connect to specified host:port
 * If host has multiple addresses, the first one that connects is used.
 * Returns open socket or -1 on error.
 */
static int
connect_server(const char *host, const char *port, bool tcp_keepalive,
    struct timespec *timo, const char **reason)
{
    struct addrinfo hints, *res, *res0;
    const char *cause = NULL;
    int error, sock = -1;
    debug_decl(connect_server, SUDOERS_DEBUG_UTIL);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(host, port, &hints, &res0);
    if (error != 0) {
	sudo_warnx(U_("unable to look up %s:%s: %s"), host, port,
	    gai_strerror(error));
	debug_return_int(-1);
    }

    for (res = res0; res; res = res->ai_next) {
	int flags, save_errno;

	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock == -1) {
	    cause = "socket";
	    continue;
	}
	flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
	    cause = "fcntl(O_NONBLOCK)";
	    save_errno = errno;
	    close(sock);
	    errno = save_errno;
	    sock = -1;
	    continue;
	}

    if (tcp_keepalive) {
        int keepalive = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
            sizeof(keepalive)) == -1) {
            cause = "setsockopt(SO_KEEPALIVE)";
            save_errno = errno;
            close(sock);
            errno = save_errno;
            sock = -1;
            continue;
        }
    }

	if (timed_connect(sock, res->ai_addr, res->ai_addrlen, timo) == -1) {
	    cause = "connect";
	    save_errno = errno;
	    close(sock);
	    errno = save_errno;
	    sock = -1;
	    continue;
	}
	break;	/* success */
    }
    freeaddrinfo(res0);

    if (sock == -1)
	*reason = cause;

    debug_return_int(sock);
}

/*
 * Connect to the first server in the list.
 * Returns a socket with O_NONBLOCK and close-on-exec flags set.
 */
int
log_server_connect(struct sudoers_str_list *servers, bool tcp_keepalive,
    struct timespec *timo, struct sudoers_string **connected_server)
{
    struct sudoers_string *server;
    char *copy, *host, *port;
    const char *cause = NULL;
    int sock = -1;
    debug_decl(restore_nproc, SUDOERS_DEBUG_UTIL);

    STAILQ_FOREACH(server, servers, entries) {
	copy = strdup(server->str);
	if (!sudo_parse_host_port(copy, &host, &port, DEFAULT_PORT_STR)) {
	    free(copy);
	    continue;
	}
	sock = connect_server(host, port, tcp_keepalive, timo, &cause);
	free(copy);
	if (sock != -1) {
	    int flags = fcntl(sock, F_GETFL, 0);
	    if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1 ||
		    fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) {
		close(sock);
		sock = -1;
	    }
        /* this is the server we successfully connected to */
        *connected_server = server;
	    break;
	}
    }
    if (sock == -1 && cause != NULL)
	sudo_warn("%s", cause);

    debug_return_int(sock);
}

#if defined(HAVE_OPENSSL)
static int
verify_peer_identity(int preverify_ok, X509_STORE_CTX *ctx)
{
    HostnameValidationResult result;
    struct client_closure *closure;
    SSL *ssl;
    X509 *current_cert;
    X509 *peer_cert;
    debug_decl(verify_peer_identity, SUDOERS_DEBUG_UTIL);

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
    closure = (struct client_closure*)SSL_get_ex_data(ssl, 1);

    result = validate_hostname(peer_cert, closure->server_name->str,
	closure->server_ip, 0);

    switch(result)
    {
        case MatchFound:
            debug_return_int(1);
        default:
            debug_return_int(0);
    }
}

static bool
tls_init(struct client_closure *closure, bool verify, bool cert_required)
{
    const char *errstr;
    debug_decl(tls_init, SUDOERS_DEBUG_PLUGIN);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    /* create the ssl context */
    if ((closure->ssl_ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
        errstr = ERR_reason_error_string(ERR_get_error());
        sudo_warnx(U_("Creation of new SSL_CTX object failed: %s"), errstr);
        goto bad;
    }
#ifdef HAVE_SSL_CTX_SET_MIN_PROTO_VERSION
    if (!SSL_CTX_set_min_proto_version(closure->ssl_ctx, TLS1_2_VERSION)) {
        errstr = ERR_reason_error_string(ERR_get_error());
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
            "unable to restrict min. protocol version: %s", errstr);
        goto bad;
    }
#else
    SSL_CTX_set_options(closure->ssl_ctx,
        SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1);
#endif


    /* if server explicitly requests it, turn on server cert verification
       during the handshake. Hostname matching will be done in a custom
       callback (verify_peer_identity).
     */
    if (verify) {
        if (closure->log_details->ca_bundle == NULL) {
            sudo_warnx(U_("CA bundle file is not set in sudoers"));
            goto bad;
        }

        /* sets the location of the CA bundle file for verification purposes */
        if (SSL_CTX_load_verify_locations(closure->ssl_ctx,
            closure->log_details->ca_bundle, NULL) <= 0) {
            errstr = ERR_reason_error_string(ERR_get_error());
            sudo_warnx(U_("Calling SSL_CTX_load_verify_locations() failed: %s"),
                errstr);
            goto bad;
        }

        SSL_CTX_set_verify(closure->ssl_ctx, SSL_VERIFY_PEER, verify_peer_identity);
    }

    /* if the server requests client authentication with signed certificate */
    if (cert_required) {
        /* if no certificate file is set in sudoers */
        if (closure->log_details->cert_file == NULL) {
            sudo_warnx(U_("Signed certificate file is not set in sudoers"));
            goto bad;
        }
        /* load client cert file */
        if (!SSL_CTX_use_certificate_chain_file(closure->ssl_ctx,
            closure->log_details->cert_file)) {
            errstr = ERR_reason_error_string(ERR_get_error());
            sudo_warnx(U_("Unable to load cert into the ssl context: %s"),
                errstr);
            goto bad;
        }
        /* no explicit key file is set, try to use the cert file */
        if (closure->log_details->key_file == NULL) {
            closure->log_details->key_file = closure->log_details->cert_file;
        }
        /* load corresponding private key file */
        if (!SSL_CTX_use_PrivateKey_file(closure->ssl_ctx,
            closure->log_details->key_file, X509_FILETYPE_PEM)) {
            errstr = ERR_reason_error_string(ERR_get_error());
            sudo_warnx(U_("Unable to load private key into the ssl context: %s"),
                errstr);
            goto bad;
        }
    }
    /* create the ssl object for encrypted communication */
    if ((closure->ssl = SSL_new(closure->ssl_ctx)) == NULL) {
        errstr = ERR_reason_error_string(ERR_get_error());
        sudo_warnx(U_("Unable to allocate ssl object: %s"), errstr);
        goto bad;
    }
    /* attach the closure socket to the ssl object */
    if (SSL_set_fd(closure->ssl, closure->sock) <= 0) {
        errstr = ERR_reason_error_string(ERR_get_error());
        sudo_warnx(U_("Unable to attach socket to the ssl object: %s"), errstr);
        goto bad;
    }

    /* attach the closure object to the ssl connection object to make it
       available during hostname matching
     */
    if (SSL_set_ex_data(closure->ssl, 1, closure) <= 0) {
        errstr = ERR_reason_error_string(ERR_get_error());
        sudo_warnx(U_("Unable to attach user data to the ssl object: %s"),
            errstr);
        goto bad;
    }

    closure->tls = true;

    debug_return_bool(true);

bad:
    debug_return_bool(false);
}

struct tls_connect_closure {
    bool tls_conn_status;
    SSL *ssl;
    struct sudo_event_base *evbase;
    struct sudo_event *tls_connect_ev;
};

static void
tls_connect_cb(int sock, int what, void *v)
{
    struct tls_connect_closure *closure = v;
    struct timespec timeo = { 10, 0 };
    const char *errstr;
    int tls_con, err;
    debug_decl(tls_connect_cb, SUDOERS_DEBUG_UTIL);

    if (what == SUDO_PLUGIN_EV_TIMEOUT) {
        sudo_warnx(U_("TLS handshake timeout occurred"));
        goto bad;
    }

    tls_con = SSL_connect(closure->ssl);

    if (tls_con == 1) {
        closure->tls_conn_status = true;
    } else {
        switch ((err = SSL_get_error(closure->ssl, tls_con))) {
            /* TLS connect successful */
            case SSL_ERROR_NONE:
                closure->tls_conn_status = true;
                break;
	    /* TLS handshake is not finished, reschedule event */
            case SSL_ERROR_WANT_READ:
		sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
		    "SSL_connect returns SSL_ERROR_WANT_READ");
		if (what != SUDO_EV_READ) {
		    if (sudo_ev_set(closure->tls_connect_ev, sock,
			    SUDO_EV_READ, tls_connect_cb, closure) == -1) {
			sudo_warnx(U_("unable to set event"));
			goto bad;
		    }
		}
		if (sudo_ev_add(closure->evbase, closure->tls_connect_ev,
			&timeo, false) == -1) {
                    sudo_warnx(U_("unable to add event to queue"));
		    goto bad;
                }
		break;
            case SSL_ERROR_WANT_WRITE:
		sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
		    "SSL_connect returns SSL_ERROR_WANT_WRITE");
		if (what != SUDO_EV_WRITE) {
		    if (sudo_ev_set(closure->tls_connect_ev, sock,
			    SUDO_EV_WRITE, tls_connect_cb, closure) == -1) {
			sudo_warnx(U_("unable to set event"));
			goto bad;
		    }
		}
		if (sudo_ev_add(closure->evbase, closure->tls_connect_ev,
			&timeo, false) == -1) {
                    sudo_warnx(U_("unable to add event to queue"));
		    goto bad;
                }
                break;
            default:
                errstr = ERR_error_string(ERR_get_error(), NULL);
                sudo_warnx(U_("SSL_connect failed: ssl_error=%d, stack=%s"),
                    err, errstr);
                goto bad;
        }
    }

    debug_return;

bad:
    /* Break out of tls connect event loop with an error. */
    sudo_ev_loopbreak(closure->evbase);

    debug_return;
}

static bool
tls_timed_connect(int sock, SSL *ssl, struct timespec *timo)
{
    struct tls_connect_closure closure;
    debug_decl(tls_timed_connect, SUDOERS_DEBUG_UTIL);

    memset(&closure, 0, sizeof(closure));
    closure.ssl = ssl;
    closure.evbase = sudo_ev_base_alloc();
    closure.tls_connect_ev = sudo_ev_alloc(sock, SUDO_PLUGIN_EV_WRITE,
	tls_connect_cb, &closure);

    if (closure.evbase == NULL || closure.tls_connect_ev == NULL) {
        sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto done;
    }

    if (sudo_ev_add(closure.evbase, closure.tls_connect_ev, timo, false) == -1) {
	sudo_warnx(U_("unable to add event to queue"));
	goto done;
    }

    if (sudo_ev_dispatch(closure.evbase) == -1) {
	sudo_warnx(U_("error in event loop"));
	goto done;
    }

done:
    if (closure.tls_connect_ev != NULL)
	sudo_ev_free(closure.tls_connect_ev);
    sudo_ev_base_free(closure.evbase);

    debug_return_bool(closure.tls_conn_status);
}
#endif /* HAVE_OPENSSL */

/*
 * Free client closure and contents and initialize to unused state as
 * per CLIENT_CLOSURE_INITIALIZER.  Log details are not freed.
 */
void
client_closure_free(struct client_closure *closure)
{
    struct connection_buffer *buf;
    debug_decl(client_closure_free, SUDOERS_DEBUG_UTIL);

#if defined(HAVE_OPENSSL)
    if (closure->tls) {
	/* Shut down the TLS connection cleanly and free SSL data. */
	if (closure->ssl != NULL) {
	    SSL_shutdown(closure->ssl);
	    SSL_free(closure->ssl);
	}
	SSL_CTX_free(closure->ssl_ctx);
    }
#endif

    if (closure->sock != -1) {
	close(closure->sock);
	closure->sock = -1;
    }
    closure->state = ERROR;
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
    if (closure->read_ev != NULL) {
	closure->read_ev->free(closure->read_ev);
	closure->read_ev = NULL;
    }
    if (closure->write_ev != NULL) {
	closure->write_ev->free(closure->write_ev);
	closure->write_ev = NULL;
    }
    free(closure->read_buf.data);
    memset(&closure->read_buf, 0, sizeof(closure->read_buf));
    memset(&closure->start_time, 0, sizeof(closure->start_time));
    memset(&closure->elapsed, 0, sizeof(closure->elapsed));
    memset(&closure->committed, 0, sizeof(closure->committed));
    free(closure->iolog_id);
    closure->iolog_id = NULL;

    /* Most of log_details is const. */
    if (closure->log_details != NULL) {
	free(closure->log_details->user_env);
	closure->log_details->user_env = NULL;
	if (closure->log_details->runas_pw)
	    sudo_pw_delref(closure->log_details->runas_pw);
	if (closure->log_details->runas_gr)
	    sudo_gr_delref(closure->log_details->runas_gr);
	closure->log_details = NULL;
    }

    debug_return;
}

static struct connection_buffer *
get_free_buf(struct client_closure *closure)
{
    struct connection_buffer *buf;
    debug_decl(get_free_buf, SUDOERS_DEBUG_UTIL);

    buf = TAILQ_FIRST(&closure->free_bufs);
    if (buf != NULL)
	TAILQ_REMOVE(&closure->free_bufs, buf, entries);
    else
	buf = calloc(1, sizeof(*buf));

    debug_return_ptr(buf);
}

/*
 * Format a ClientMessage.
 * Appends the wire format message to the closure's write queue.
 * Returns true on success, false on failure.
 */
bool
fmt_client_message(struct client_closure *closure, ClientMessage *msg)
{
    struct connection_buffer *buf;
    uint32_t msg_len;
    bool ret = false;
    size_t len;
    debug_decl(fmt_client_message, SUDOERS_DEBUG_UTIL);

    if ((buf = get_free_buf(closure)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto done;
    }

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
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    buf->size = 0;
	    goto done;
	}
    }

    memcpy(buf->data, &msg_len, sizeof(msg_len));
    client_message__pack(msg, buf->data + sizeof(msg_len));
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

/*
 * Build and format an AcceptMessage wrapped in a ClientMessage.
 * Appends the wire format message to the closure's write queue.
 * Returns true on success, false on failure.
 */
bool
fmt_accept_message(struct client_closure *closure)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    AcceptMessage accept_msg = ACCEPT_MESSAGE__INIT;
    TimeSpec ts = TIME_SPEC__INIT;
    InfoMessage__StringList runargv = INFO_MESSAGE__STRING_LIST__INIT;
    InfoMessage__StringList runenv = INFO_MESSAGE__STRING_LIST__INIT;
    struct iolog_details *details = closure->log_details;
    size_t info_msgs_size, n;
    struct timespec now;
    bool ret = false;
    debug_decl(fmt_accept_message, SUDOERS_DEBUG_UTIL);

    /*
     * Fill in AcceptMessage and add it to ClientMessage.
     */
    if (sudo_gettime_real(&now)) {
	sudo_warn("%s", U_("unable to get time of day"));
	debug_return_bool(false);
    }
    ts.tv_sec = now.tv_sec;
    ts.tv_nsec = now.tv_nsec;
    accept_msg.submit_time = &ts;

    /* Client will send IoBuffer messages. */
    accept_msg.expect_iobufs = true;

    /* Convert NULL-terminated vectors to StringList. */
    runargv.strings = (char **)details->argv;
    runargv.n_strings = details->argc;
    runenv.strings = (char **)details->user_env;
    while (runenv.strings[runenv.n_strings] != NULL)
	runenv.n_strings++;

    /* XXX - realloc as needed instead of preallocating */
    info_msgs_size = 22;
    accept_msg.info_msgs = calloc(info_msgs_size, sizeof(InfoMessage *));
    if (accept_msg.info_msgs == NULL) {
	info_msgs_size = 0;
	goto done;
    }
    for (n = 0; n < info_msgs_size; n++) {
	accept_msg.info_msgs[n] = malloc(sizeof(InfoMessage));
	if (accept_msg.info_msgs[n] == NULL) {
	    accept_msg.n_info_msgs = n;
	    goto done;
	}
	info_message__init(accept_msg.info_msgs[n]);
    }

    /* Fill in info_msgs */
    n = 0;

    /* TODO: clientargv (not currently supported by API) */
    /* TODO: clientpid */
    /* TODO: clientppid */
    /* TODO: clientsid */

    accept_msg.info_msgs[n]->key = "columns";
    accept_msg.info_msgs[n]->numval = details->cols;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_NUMVAL;
    n++;

    accept_msg.info_msgs[n]->key = "command";
    accept_msg.info_msgs[n]->strval = (char *)details->command;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    accept_msg.info_msgs[n]->key = "lines";
    accept_msg.info_msgs[n]->numval = details->lines;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_NUMVAL;
    n++;

    accept_msg.info_msgs[n]->key = "runargv";
    accept_msg.info_msgs[n]->strlistval = &runargv;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRLISTVAL;
    n++;

    accept_msg.info_msgs[n]->key = "runenv";
    accept_msg.info_msgs[n]->strlistval = &runenv;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRLISTVAL;
    n++;

    if (details->runas_gr!= NULL) {
	accept_msg.info_msgs[n]->key = "rungid";
	accept_msg.info_msgs[n]->numval = details->runas_gr->gr_gid;
	accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_NUMVAL;
	n++;

	accept_msg.info_msgs[n]->key = "rungroup";
	accept_msg.info_msgs[n]->strval = details->runas_gr->gr_name;
	accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
	n++;
    }

    /* TODO - rungids */
    /* TODO - rungroups */

    accept_msg.info_msgs[n]->key = "runuid";
    accept_msg.info_msgs[n]->numval = details->runas_pw->pw_uid;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_NUMVAL;
    n++;

    accept_msg.info_msgs[n]->key = "runuser";
    accept_msg.info_msgs[n]->strval = details->runas_pw->pw_name;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    if (details->cwd != NULL) {
	accept_msg.info_msgs[n]->key = "submitcwd";
	accept_msg.info_msgs[n]->strval = (char *)details->cwd;
	accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
	n++;
    }

    /* TODO - submitenv */
    /* TODO - submitgid */
    /* TODO - submitgids */
    /* TODO - submitgroup */
    /* TODO - submitgroups */

    accept_msg.info_msgs[n]->key = "submithost";
    accept_msg.info_msgs[n]->strval = (char *)details->host;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    /* TODO - submituid */

    accept_msg.info_msgs[n]->key = "submituser";
    accept_msg.info_msgs[n]->strval = (char *)details->user;
    accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
    n++;

    if (details->tty != NULL) {
	accept_msg.info_msgs[n]->key = "ttyname";
	accept_msg.info_msgs[n]->strval = (char *)details->tty;
	accept_msg.info_msgs[n]->value_case = INFO_MESSAGE__VALUE_STRVAL;
	n++;
    }

    /* Update n_info_msgs. */
    accept_msg.n_info_msgs = n;

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending AcceptMessage, array length %zu", __func__, n);

    /* Schedule ClientMessage */
    client_msg.accept_msg = &accept_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_ACCEPT_MSG;
    ret = fmt_client_message(closure, &client_msg);

done:
    for (n = 0; n < info_msgs_size; n++)
	free(accept_msg.info_msgs[n]);
    free(accept_msg.info_msgs);

    debug_return_bool(ret);
}

#ifdef notyet
/*
 * Build and format a RestartMessage wrapped in a ClientMessage.
 * Appends the wire format message to the closure's write queue.
 * Returns true on success, false on failure.
 */
bool
fmt_restart_message(struct client_closure *closure)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    RestartMessage restart_msg = RESTART_MESSAGE__INIT;
    TimeSpec tv = TIME_SPEC__INIT;
    bool ret = false;
    debug_decl(fmt_restart_message, SUDOERS_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending RestartMessage, [%lld, %ld]", __func__,
	(long long)closure->restart->tv_sec, closure->restart->tv_nsec);

    tv.tv_sec = closure->restart->tv_sec;
    tv.tv_nsec = closure->restart->tv_nsec;
    restart_msg.resume_point = &tv;
    restart_msg.log_id = (char *)closure->iolog_id;

    /* Schedule ClientMessage */
    client_msg.restart_msg = &restart_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_RESTART_MSG;
    ret = fmt_client_message(closure, &client_msg);

    debug_return_bool(ret);
}
#endif

/*
 * Build and format an ExitMessage wrapped in a ClientMessage.
 * Appends the wire format message to the closure's write queue.
 * Returns true on success, false on failure.
 */
bool
fmt_exit_message(struct client_closure *closure, int exit_status, int error)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    ExitMessage exit_msg = EXIT_MESSAGE__INIT;
    TimeSpec ts = TIME_SPEC__INIT;
    char signame[SIG2STR_MAX];
    bool ret = false;
    struct timespec run_time;
    debug_decl(fmt_exit_message, SUDOERS_DEBUG_UTIL);

    if (sudo_gettime_awake(&run_time) == -1) {
	sudo_warn("%s", U_("unable to get time of day"));
	goto done;
    }
    sudo_timespecsub(&run_time, &closure->start_time, &run_time);

    ts.tv_sec = run_time.tv_sec;
    ts.tv_nsec = run_time.tv_nsec;
    exit_msg.run_time = &ts;

    if (error != 0) {
	/* Error executing the command. */
	exit_msg.error = strerror(error);
    } else {
	if (WIFEXITED(exit_status)) {
	    exit_msg.exit_value = WEXITSTATUS(exit_status);
	} else if (WIFSIGNALED(exit_status)) {
	    int signo = WTERMSIG(exit_status);
	    if (signo <= 0 || sig2str(signo, signame) == -1) {
		sudo_warnx(U_("%s: internal error, invalid signal %d"),
		    __func__, signo);
		goto done;
	    }
	    exit_msg.signal = signame;
	    if (WCOREDUMP(exit_status))
		exit_msg.dumped_core = true;
	    exit_msg.exit_value = WTERMSIG(exit_status) | 128;
	} else {
	    sudo_warnx(U_("%s: internal error, invalid exit status %d"),
		__func__, exit_status);
	    goto done;
	}
    }

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending ExitMessage, exitval %d, error %s, signal %s, coredump %s",
	__func__, exit_msg.exit_value, exit_msg.error ? exit_msg.error : "",
	exit_msg.signal ? exit_msg.signal : "",
	exit_msg.dumped_core ? "yes" : "no");

    /* Send ClientMessage */
    client_msg.exit_msg = &exit_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_EXIT_MSG;
    if (!fmt_client_message(closure, &client_msg))
	goto done;

    closure->state = SEND_EXIT;
    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Build and format an IoBuffer wrapped in a ClientMessage.
 * Appends the wire format message to the closure's write queue.
 * Returns true on success, false on failure.
 */
bool
fmt_io_buf(struct client_closure *closure, int type, const char *buf,
    unsigned int len, struct timespec *delay)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    IoBuffer iobuf_msg = IO_BUFFER__INIT;
    TimeSpec ts = TIME_SPEC__INIT;
    bool ret = false;
    debug_decl(fmt_io_buf, SUDOERS_DEBUG_UTIL);

    /* Fill in IoBuffer. */
    ts.tv_sec = delay->tv_sec;
    ts.tv_nsec = delay->tv_nsec;
    iobuf_msg.delay = &ts;
    iobuf_msg.data.data = (void *)buf;
    iobuf_msg.data.len = len;

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: sending IoBuffer length %zu, type %d, size %zu", __func__,
	iobuf_msg.data.len, type, io_buffer__get_packed_size(&iobuf_msg));

    /* Schedule ClientMessage, it doesn't matter which IoBuffer we set. */
    client_msg.ttyout_buf = &iobuf_msg;
    client_msg.type_case = type;
    if (!fmt_client_message(closure, &client_msg))
        goto done;

    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Build and format a ChangeWindowSize message wrapped in a ClientMessage.
 * Appends the wire format message to the closure's write queue.
 * Returns true on success, false on failure.
 */
bool
fmt_winsize(struct client_closure *closure, unsigned int lines,
    unsigned int cols, struct timespec *delay)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    ChangeWindowSize winsize_msg = CHANGE_WINDOW_SIZE__INIT;
    TimeSpec ts = TIME_SPEC__INIT;
    bool ret = false;
    debug_decl(fmt_winsize, SUDOERS_DEBUG_UTIL);

    /* Fill in ChangeWindowSize message. */
    ts.tv_sec = delay->tv_sec;
    ts.tv_nsec = delay->tv_nsec;
    winsize_msg.delay = &ts;
    winsize_msg.rows = lines;
    winsize_msg.cols = cols;

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: sending ChangeWindowSize, %dx%d",
	__func__, winsize_msg.rows, winsize_msg.cols);

    /* Send ClientMessage */
    client_msg.winsize_event = &winsize_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_WINSIZE_EVENT;
    if (!fmt_client_message(closure, &client_msg))
        goto done;

    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Build and format a CommandSuspend message wrapped in a ClientMessage.
 * Appends the wire format message to the closure's write queue.
 * Returns true on success, false on failure.
 */
bool
fmt_suspend(struct client_closure *closure, const char *signame, struct timespec *delay)
{
    ClientMessage client_msg = CLIENT_MESSAGE__INIT;
    CommandSuspend suspend_msg = COMMAND_SUSPEND__INIT;
    TimeSpec ts = TIME_SPEC__INIT;
    bool ret = false;
    debug_decl(fmt_suspend, SUDOERS_DEBUG_UTIL);

    /* Fill in CommandSuspend message. */
    ts.tv_sec = delay->tv_sec;
    ts.tv_nsec = delay->tv_nsec;
    suspend_msg.delay = &ts;
    suspend_msg.signal = (char *)signame;

    sudo_debug_printf(SUDO_DEBUG_INFO,
    	"%s: sending CommandSuspend, SIG%s", __func__, suspend_msg.signal);

    /* Send ClientMessage */
    client_msg.suspend_event = &suspend_msg;
    client_msg.type_case = CLIENT_MESSAGE__TYPE_SUSPEND_EVENT;
    if (!fmt_client_message(closure, &client_msg))
        goto done;

    ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Additional work to do after a ClientMessage was sent to the server.
 * Advances state and formats the next ClientMessage (if any).
 * XXX - better name
 */
static bool
client_message_completion(struct client_closure *closure)
{
    debug_decl(client_message_completion, SUDOERS_DEBUG_UTIL);

    switch (closure->state) {
    case SEND_ACCEPT:
    case SEND_RESTART:
	closure->state = SEND_IO;
	break;
    case SEND_IO:
	/* Arbitrary number of I/O log buffers, no state change. */
	break;
    case SEND_EXIT:
	/* Done writing, just waiting for final commit point. */
	closure->write_ev->del(closure->write_ev);
	closure->state = CLOSING;

	/* Enable timeout while waiting for final commit point. */
	if (closure->read_ev->add(closure->read_ev,
		&closure->log_details->server_timeout) == -1) {
	    sudo_warn(U_("unable to add event to queue"));
	    debug_return_bool(false);
	}
	break;
    default:
	sudo_warnx(U_("%s: unexpected state %d"), __func__, closure->state);
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

bool
read_server_hello(int sock, struct client_closure *closure)
{
    struct sudo_event_base *evbase;
    bool ret = false;
    debug_decl(read_server_hello, SUDOERS_DEBUG_UTIL);

    /* Get new event base so we can read ServerHello syncronously. */
    evbase = sudo_ev_base_alloc();
    if (evbase == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto done;
    }
    closure->read_ev->setbase(closure->read_ev, evbase);

    /* Read ServerHello synchronously and optionally perform TLS handshake. */
    if (closure->read_ev->add(closure->read_ev,
	    &closure->log_details->server_timeout) == -1) {
	sudo_warnx(U_("unable to add event to queue"));
	goto done;
    }
    if (sudo_ev_dispatch(evbase) == -1) {
	sudo_warnx(U_("error in event loop"));
	goto done;
    }

    if (!sudo_ev_got_break(evbase))
	ret = true;

    /* Note: handle_server_hello() reset the event back to sudo's event loop. */

done:
    sudo_ev_base_free(evbase);
    debug_return_bool(ret);
}

/*
 * Respond to a ServerHello message from the server.
 * Returns true on success, false on error.
 */
static bool
handle_server_hello(ServerHello *msg, struct client_closure *closure)
{
    size_t n;
    debug_decl(handle_server_hello, SUDOERS_DEBUG_UTIL);

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
    /* if server requested TLS */
    if (msg->tls) {
        if (!tls_init(closure, msg->tls_server_auth, msg->tls_reqcert)) {
            sudo_warnx(U_("TLS initialization was unsuccessful"));
            debug_return_bool(false);
        }
        if (!tls_timed_connect(closure->sock, closure->ssl,
		&closure->log_details->server_timeout)) {
            sudo_warnx(U_("TLS handshake was unsuccessful"));
            debug_return_bool(false);
        }
    }
#endif /* HAVE_OPENSSL */

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: server ID: %s",
	__func__, msg->server_id);
    /* TODO: handle redirect */
    if (msg->redirect != NULL && msg->redirect[0] != '\0') {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: redirect: %s",
	    __func__, msg->redirect);
    }
    for (n = 0; n < msg->n_servers; n++) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: server %zu: %s",
	    __func__, n + 1, msg->servers[n]);
    }

    /*
     * Move read event back to main sudo event loop.
     * Server messages may occur at any time, so no timeout.
     */
    closure->read_ev->setbase(closure->read_ev, NULL);
    if (closure->read_ev->add(closure->read_ev, NULL) == -1) {
        sudo_warn(U_("unable to add event to queue"));
	debug_return_bool(false);
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
    debug_decl(handle_commit_point, SUDOERS_DEBUG_UTIL);

    /* Only valid after we have sent an IO buffer. */
    if (closure->state < SEND_IO) {
	sudo_warnx(U_("%s: unexpected state %d"), __func__, closure->state);
	debug_return_bool(false);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: commit point: [%lld, %d]",
	__func__, (long long)commit_point->tv_sec, commit_point->tv_nsec);
    closure->committed.tv_sec = commit_point->tv_sec;
    closure->committed.tv_nsec = commit_point->tv_nsec;

    if (closure->state == CLOSING) {
	if (sudo_timespeccmp(&closure->elapsed, &closure->committed, ==)) {
	    /* Last commit point received, exit event loop. */
	    closure->state = FINISHED;
	    closure->read_ev->del(closure->read_ev);
	}
    }

    debug_return_bool(true);
}

/*
 * Respond to a LogId message from the server.
 * Always returns true.
 */
static bool
handle_log_id(char *id, struct client_closure *closure)
{
    debug_decl(handle_log_id, SUDOERS_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: remote log ID: %s", __func__, id);
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
    debug_decl(handle_server_error, SUDOERS_DEBUG_UTIL);

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
    debug_decl(handle_server_abort, SUDOERS_DEBUG_UTIL);

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
    debug_decl(handle_server_message, SUDOERS_DEBUG_UTIL);

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: unpacking ServerMessage", __func__);
    msg = server_message__unpack(NULL, len, buf);
    if (msg == NULL) {
	sudo_warnx("%s", U_("unable to unpack ServerMessage"));
	debug_return_bool(false);
    }

    switch (msg->type_case) {
    case SERVER_MESSAGE__TYPE_HELLO:
	if (handle_server_hello(msg->hello, closure)) {
	    /* Format and schedule accept message. */
	    closure->state = SEND_ACCEPT;
	    if ((ret = fmt_accept_message(closure))) {
		if (closure->write_ev->add(closure->write_ev,
			&closure->log_details->server_timeout) == -1) {
		    sudo_warn(U_("unable to add event to queue"));
		    ret = false;
		}
	    }
	}
	break;
    case SERVER_MESSAGE__TYPE_COMMIT_POINT:
	ret = handle_commit_point(msg->commit_point, closure);
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
 * Expand buf as needed or just reset it.
 * XXX - share with logsrvd/sendlog
 */
static bool
expand_buf(struct connection_buffer *buf, unsigned int needed)
{
    void *newdata;
    debug_decl(expand_buf, SUDOERS_DEBUG_UTIL);

    if (buf->size < needed) {
	/* Expand buffer. */
	needed = sudo_pow2_roundup(needed);
	if ((newdata = malloc(needed)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_bool(false);
	}
	if (buf->off > 0)
	    memcpy(newdata, buf->data + buf->off, buf->len - buf->off);
	free(buf->data);
	buf->data = newdata;
	buf->size = needed;
    } else {
	/* Just reset existing buffer. */
	if (buf->off > 0) {
	    memmove(buf->data, buf->data + buf->off,
		buf->len - buf->off);
	}
    }
    buf->len -= buf->off;
    buf->off = 0;

    debug_return_bool(true);
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
    debug_decl(server_msg_cb, SUDOERS_DEBUG_UTIL);

    /* For TLS we may need to read as part of SSL_write(). */
    if (closure->write_instead_of_read) {
	closure->write_instead_of_read = false;
        client_msg_cb(fd, what, v);
        debug_return;
    }

    if (what == SUDO_PLUGIN_EV_TIMEOUT) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: timed out reading from server",
	    __func__);
	goto bad;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: reading ServerMessage", __func__);
#if defined(HAVE_OPENSSL)
    if (closure->tls && closure->state != RECV_HELLO) {
        nread = SSL_read(closure->ssl, buf->data + buf->len, buf->size - buf->len);
        if (nread <= 0) {
	    const char *errstr;
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
                    debug_return;
                case SSL_ERROR_WANT_WRITE:
                    /* ssl wants to write, so schedule the write handler */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_read returns SSL_ERROR_WANT_WRITE");
		    if (!closure->write_ev->pending(closure->write_ev,
			    SUDO_PLUGIN_EV_WRITE, NULL)) {
			/* Enable a temporary write event. */
			if (closure->write_ev->add(closure->write_ev, NULL) == -1) {
			    sudo_warn(U_("unable to add event to queue"));
			    goto bad;
			}
			closure->temporary_write_event = true;
		    }
		    closure->write_instead_of_read = true;
                    debug_return;
                default:
                    errstr = ERR_error_string(ERR_get_error(), NULL);
                    sudo_warnx(U_("SSL_read failed: ssl_error=%d, stack=%s"),
                        err, errstr);
                    goto bad;
            }
        }
    }
    else {
        nread = recv(fd, buf->data + buf->len, buf->size - buf->len, 0);
    }

#else
    nread = recv(fd, buf->data + buf->len, buf->size - buf->len, 0);
#endif /* HAVE_OPENSSL */
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: received %zd bytes from server",
	__func__, nread);
    switch (nread) {
    case -1:
	if (errno == EAGAIN)
	    debug_return;
	sudo_warn("recv");
	goto bad;
    case 0:
	sudo_warnx("%s", U_("lost connection to log server"));
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
    if (closure->log_details->ignore_iolog_errors) {
	/* Disable plugin, the command continues. */
	closure->disabled = true;
	closure->read_ev->del(closure->read_ev);
    } else {
	/* Break out of sudo event loop and kill the command. */
	closure->read_ev->loopbreak(closure->read_ev);
    }
    debug_return;
}

/*
 * Send a ClientMessage to the server (write callback).
 */
static void
client_msg_cb(int fd, int what, void *v)
{
    struct client_closure *closure = v;
    struct connection_buffer *buf;
    ssize_t nwritten;
    debug_decl(client_msg_cb, SUDOERS_DEBUG_UTIL);

    /* For TLS we may need to write as part of SSL_read(). */
    if (closure->read_instead_of_write) {
	closure->read_instead_of_write = false;
	/* Delete write event if it was only due to SSL_read(). */
	if (closure->temporary_write_event) {
            closure->temporary_write_event = false;
	    closure->write_ev->del(closure->write_ev);
	}
	server_msg_cb(fd, what, v);
	debug_return;
    }

    if (what == SUDO_PLUGIN_EV_TIMEOUT) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: timed out writiing to server",
	    __func__);
	goto bad;
    }

    if ((buf = TAILQ_FIRST(&closure->write_bufs)) == NULL) {
	sudo_warn("%s", U_("missing write buffer"));
	goto bad;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO,
    	"%s: sending %u bytes to server", __func__, buf->len - buf->off);

#if defined(HAVE_OPENSSL)
    if (closure->tls) {
        nwritten = SSL_write(closure->ssl, buf->data + buf->off, buf->len - buf->off);
        if (nwritten <= 0) {
	    const char *errstr;
            int err = SSL_get_error(closure->ssl, nwritten);
            switch (err) {
                case SSL_ERROR_WANT_READ:
		    /* ssl wants to read, read event always active */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_write returns SSL_ERROR_WANT_READ");
		    closure->write_instead_of_read = true;
                    debug_return;
                case SSL_ERROR_WANT_WRITE:
		    /* ssl wants to write more, write event remains active */
		    sudo_debug_printf(SUDO_DEBUG_NOTICE|SUDO_DEBUG_LINENO,
			"SSL_write returns SSL_ERROR_WANT_WRITE");
                    debug_return;
                default:
                    errstr = ERR_error_string(ERR_get_error(), NULL);
                    sudo_warnx(U_("SSL_write failed: ssl_error=%d, stack=%s"),
                        err, errstr);
                    goto bad;
            }
        }
    } else {
        nwritten = send(fd, buf->data + buf->off, buf->len - buf->off, 0);
    }
#else
    nwritten = send(fd, buf->data + buf->off, buf->len - buf->off, 0);
#endif /* HAVE_OPENSSL */

    if (nwritten == -1) {
	sudo_warn("send");
	goto bad;
    }
    buf->off += nwritten;

    if (buf->off == buf->len) {
	/* sent entire message, move buf to free list */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: finished sending %u bytes to server", __func__, buf->len);
	buf->off = 0;
	buf->len = 0;
	TAILQ_REMOVE(&closure->write_bufs, buf, entries);
	TAILQ_INSERT_TAIL(&closure->free_bufs, buf, entries);
	if (TAILQ_EMPTY(&closure->write_bufs)) {
	    /* Write queue empty, check for state change. */
	    closure->write_ev->del(closure->write_ev);
	    if (!client_message_completion(closure))
		goto bad;
	}
    } else {
	/* not done yet */
	TAILQ_INSERT_HEAD(&closure->write_bufs, buf, entries);
    }
    debug_return;

bad:
    if (closure->log_details->ignore_iolog_errors) {
	/* Disable plugin, the command continues. */
	closure->disabled = true;
	closure->write_ev->del(closure->write_ev);
    } else {
	/* Break out of sudo event loop and kill the command. */
	closure->write_ev->loopbreak(closure->write_ev);
    }
    debug_return;
}

/*
 * Allocate and initialize a new client closure
 */
bool
client_closure_fill(struct client_closure *closure, int sock,
    const struct sudoers_string *host, struct timespec *now,
    struct iolog_details *details, struct io_plugin *sudoers_io)
{
    union {
	struct sockaddr sa;
	struct sockaddr_in sin;
#ifdef HAVE_STRUCT_IN6_ADDR
	struct sockaddr_in6 sin6;
#endif
    } addr;
    socklen_t addr_len = sizeof(addr);
    debug_decl(client_closure_alloc, SUDOERS_DEBUG_UTIL);

    closure->sock = -1;
    closure->state = RECV_HELLO;

    closure->start_time.tv_sec = now->tv_sec;
    closure->start_time.tv_nsec = now->tv_nsec;

    closure->read_buf.size = 64 * 1024;
    closure->read_buf.data = malloc(closure->read_buf.size);
    if (closure->read_buf.data == NULL)
	goto oom;

    TAILQ_INIT(&closure->write_bufs);
    TAILQ_INIT(&closure->free_bufs);

    if ((closure->read_ev = sudoers_io->event_alloc()) == NULL)
	goto oom;

    if ((closure->write_ev = sudoers_io->event_alloc()) == NULL)
	goto oom;

    if (closure->read_ev->set(closure->read_ev, sock,
	    SUDO_PLUGIN_EV_READ|SUDO_PLUGIN_EV_PERSIST,
	    server_msg_cb, closure) == -1)
	goto oom;

    if (closure->write_ev->set(closure->write_ev, sock,
	    SUDO_PLUGIN_EV_WRITE|SUDO_PLUGIN_EV_PERSIST,
	    client_msg_cb, closure) == -1)
	goto oom;

    closure->log_details = details;

    /* Save the name and IP of the server we are successfully connected to. */
    closure->server_name = host;
    if (getpeername(sock, (struct sockaddr *)&addr, &addr_len) == -1) {
	sudo_warn("getpeername");
	goto bad;
    }
    switch (addr.sa.sa_family) {
    case AF_INET:
	if (inet_ntop(AF_INET, &addr.sin.sin_addr, closure->server_ip,
		sizeof(closure->server_ip)) == NULL) {
	    sudo_warnx(U_("unable to get remote IP addr"));
	    goto bad;
	}
	break;
#ifdef HAVE_STRUCT_IN6_ADDR
    case AF_INET6:
	if (inet_ntop(AF_INET6, &addr.sin6.sin6_addr, closure->server_ip,
		sizeof(closure->server_ip)) == NULL) {
	    sudo_warnx(U_("unable to get remote IP addr"));
	    goto bad;
	}
	break;
#endif
    default:
	sudo_warnx(U_("unknown address family: %d"), (int)addr.sa.sa_family);
	goto bad;
    }

    /* Store sock last to avoid double-close in parent on error. */
    closure->sock = sock;

    debug_return_bool(true);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
bad:
    client_closure_free(closure);
    debug_return_bool(false);
}

/*
 * Send ExitMessage, wait for final commit message and free closure.
 */
bool
client_close(struct client_closure *closure, int exit_status, int error)
{
    struct sudo_event_base *evbase = NULL;
    bool ret = false;
    debug_decl(client_close, SUDOERS_DEBUG_UTIL);

    if (closure->disabled)
	goto done;

    /* Format and append an ExitMessage to the write queue. */
    if (!fmt_exit_message(closure, exit_status, error))
	goto done;

    /*
     * Create private event base and reparent the read/write events.
     * We cannot use the main sudo event loop as it has already exited.
     */
    if ((evbase = sudo_ev_base_alloc()) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto done;
    }

    /* Enable read event to receive server messages. */
    closure->read_ev->setbase(closure->read_ev, evbase);
    if (closure->read_ev->add(closure->read_ev,
	    &closure->log_details->server_timeout) == -1) {
	sudo_warn(U_("unable to add event to queue"));
	goto done;
    }

    /* Enable the write event to write the ExitMessage. */
    closure->write_ev->setbase(closure->write_ev, evbase);
    if (closure->write_ev->add(closure->write_ev,
	    &closure->log_details->server_timeout) == -1) {
	sudo_warn(U_("unable to add event to queue"));
	goto done;
    }

    /* Loop until queues are flushed and final commit point received. */
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"flushing buffers and waiting for final commit point");
    if (sudo_ev_dispatch(evbase) == -1 || sudo_ev_got_break(evbase)) {
	sudo_warnx(U_("error in event loop"));
	goto done;
    }

    ret = true;

done:
    sudo_ev_base_free(evbase);
    client_closure_free(closure);
    debug_return_bool(ret);
}

#endif /* SUDOERS_IOLOG_CLIENT */
