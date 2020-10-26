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

#ifndef SUDO_LOGSRVD_H
#define SUDO_LOGSRVD_H

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error protobuf-c version 1.30 or higher required
#endif

#include "config.h"

#if defined(HAVE_OPENSSL)
# include <openssl/ssl.h>
#endif

#include "logsrv_util.h"

/* Default timeout value for server socket */
#define DEFAULT_SOCKET_TIMEOUT_SEC 30

/* How often to send an ACK to the client (commit point) in seconds */
#define ACK_FREQUENCY	10

/* Shutdown timeout (in seconds) in case client connections time out. */
#define SHUTDOWN_TIMEO	10

/*
 * Connection status.
 * In the RUNNING state we expect I/O log buffers.
 */
enum connection_status {
    INITIAL,
    RUNNING,
    EXITED,
    SHUTDOWN,
    FINISHED,
    ERROR
};

/*
 * Per-connection state.
 */
struct connection_closure {
    TAILQ_ENTRY(connection_closure) entries;
    struct eventlog *evlog;
    struct timespec elapsed_time;
    struct connection_buffer read_buf;
    struct connection_buffer write_buf;
    struct sudo_event_base *evbase;
    struct sudo_event *commit_ev;
    struct sudo_event *read_ev;
    struct sudo_event *write_ev;
#if defined(HAVE_OPENSSL)
    struct sudo_event *ssl_accept_ev;
    SSL *ssl;
#endif
    const char *errstr;
    struct iolog_file iolog_files[IOFD_MAX];
    bool tls;
    bool log_io;
    bool read_instead_of_write;
    bool write_instead_of_read;
    bool temporary_write_event;
    int iolog_dir_fd;
    int sock;
#ifdef HAVE_STRUCT_IN6_ADDR
    char ipaddr[INET6_ADDRSTRLEN];
#else
    char ipaddr[INET_ADDRSTRLEN];
#endif
    enum connection_status state;
};

union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_in sin;
#ifdef HAVE_STRUCT_IN6_ADDR
    struct sockaddr_in6 sin6;
#endif
};

/*
 * List of listen addresses.
 */
struct listen_address {
    TAILQ_ENTRY(listen_address) entries;
    char *sa_str;
    union sockaddr_union sa_un;
    socklen_t sa_size;
    bool tls;
};
TAILQ_HEAD(listen_address_list, listen_address);

/*
 * List of active network listeners.
 */
struct listener {
    TAILQ_ENTRY(listener) entries;
    struct sudo_event *ev;
    int sock;
    bool tls;
};
TAILQ_HEAD(listener_list, listener);

#if defined(HAVE_OPENSSL)
/* parameters to configure tls */
struct logsrvd_tls_config {
    char *pkey_path;
    char *cert_path;
    char *cacert_path;
    char *dhparams_path;
    char *ciphers_v12;
    char *ciphers_v13;
    bool verify;
    bool check_peer;
};

struct logsrvd_tls_runtime {
    SSL_CTX *ssl_ctx;
};
#endif

/* iolog_writer.c */
struct eventlog *evlog_new(TimeSpec *submit_time, InfoMessage **info_msgs, size_t infolen);
bool iolog_init(AcceptMessage *msg, struct connection_closure *closure);
bool iolog_restart(RestartMessage *msg, struct connection_closure *closure);
int store_iobuf(int iofd, IoBuffer *msg, struct connection_closure *closure);
int store_suspend(CommandSuspend *msg, struct connection_closure *closure);
int store_winsize(ChangeWindowSize *msg, struct connection_closure *closure);
void iolog_close_all(struct connection_closure *closure);

/* logsrvd_conf.c */
bool logsrvd_conf_read(const char *path);
const char *logsrvd_conf_iolog_dir(void);
const char *logsrvd_conf_iolog_file(void);
struct listen_address_list *logsrvd_conf_listen_address(void);
bool logsrvd_conf_tcp_keepalive(void);
const char *logsrvd_conf_pid_file(void);
struct timespec *logsrvd_conf_get_sock_timeout(void);
#if defined(HAVE_OPENSSL)
const struct logsrvd_tls_config *logsrvd_get_tls_config(void);
struct logsrvd_tls_runtime *logsrvd_get_tls_runtime(void);
#endif
mode_t logsrvd_conf_iolog_mode(void);

#endif /* SUDO_LOGSRVD_H */
