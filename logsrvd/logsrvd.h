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

/* Default listen address (port 30344 on all interfaces). */
#define DEFAULT_LISTEN_ADDR	"*:" DEFAULT_PORT_STR

/* Default timeout value for server socket */
#define DEFAULT_SOCKET_TIMEOUT_SEC 30

/* How often to send an ACK to the client (commit point) in seconds */
#define ACK_FREQUENCY	10

/* Shutdown timeout (in seconds) in case client connections time out. */
#define SHUTDOWN_TIMEO	10

/*
 * I/O log details from the AcceptMessage + iolog path and sessid.
 */
struct iolog_details {
    char *iolog_path;
    char *iolog_file;		/* substring of iolog_path, do not free */
    char *command;
    char *cwd;
    char *rungroup;
    char *runuser;
    char *submithost;
    char *submituser;
    char *submitgroup;
    char *ttyname;
    char **argv;
    char **env_add;
    char **envp;
    struct timespec submit_time;
    int argc;
    int lines;
    int columns;
    uid_t runuid;
    gid_t rungid;
    char sessid[7];
};

/*
 * Connection status.
 * In the RUNNING state we expect I/O log buffers.
 */
enum connection_status {
    INITIAL,
    RUNNING,
    EXITED,
    SHUTDOWN,
    FLUSHED,
    ERROR
};

/*
 * Per-connection state.
 */
struct connection_closure {
    TAILQ_ENTRY(connection_closure) entries;
    struct iolog_details details;
    struct timespec submit_time;
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
    union sockaddr_union sa_un;
    socklen_t sa_len;
};
TAILQ_HEAD(listen_address_list, listen_address);

/*
 * List of active network listeners.
 */
struct listener {
    TAILQ_ENTRY(listener) entries;
    struct sudo_event *ev;
    int sock;
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

/* Supported eventlog types */
enum logsrvd_eventlog_type {
    EVLOG_NONE,
    EVLOG_SYSLOG,
    EVLOG_FILE,
};

/* Supported eventlog formats (currently just sudo) */
enum logsrvd_eventlog_format {
    EVLOG_SUDO,
    EVLOG_JSON
};

/* eventlog.c */
bool log_accept(const struct iolog_details *details, TimeSpec *submit_time, InfoMessage **info_msgs, size_t infolen);
bool log_reject(const struct iolog_details *details, const char *reason, TimeSpec *submit_time, InfoMessage **info_msgs, size_t infolen);
bool log_alert(const struct iolog_details *details, TimeSpec *alert_time, const char *reason);

/* iolog_writer.c */
bool iolog_details_fill(struct iolog_details *details, TimeSpec *submit_time, InfoMessage **info_msgs, size_t infolen);
bool iolog_init(AcceptMessage *msg, struct connection_closure *closure);
bool iolog_restart(RestartMessage *msg, struct connection_closure *closure);
int store_iobuf(int iofd, IoBuffer *msg, struct connection_closure *closure);
int store_suspend(CommandSuspend *msg, struct connection_closure *closure);
int store_winsize(ChangeWindowSize *msg, struct connection_closure *closure);
void iolog_close_all(struct connection_closure *closure);
void iolog_details_free(struct iolog_details *details);
char ** strlist_copy(InfoMessage__StringList *strlist);

/* logsrvd_conf.c */
bool logsrvd_conf_read(const char *path);
const char *logsrvd_conf_iolog_dir(void);
const char *logsrvd_conf_iolog_file(void);
struct listen_address_list *logsrvd_conf_listen_address(void);
bool logsrvd_conf_tcp_keepalive(void);
struct timespec *logsrvd_conf_get_sock_timeout(void);
#if defined(HAVE_OPENSSL)
bool logsrvd_conf_get_tls_opt(void);
const struct logsrvd_tls_config *logsrvd_get_tls_config(void);
struct logsrvd_tls_runtime *logsrvd_get_tls_runtime(void);
#endif
enum logsrvd_eventlog_type logsrvd_conf_eventlog_type(void);
enum logsrvd_eventlog_format logsrvd_conf_eventlog_format(void);
unsigned int logsrvd_conf_syslog_maxlen(void);
int logsrvd_conf_syslog_facility(void);
int logsrvd_conf_syslog_acceptpri(void);
int logsrvd_conf_syslog_rejectpri(void);
int logsrvd_conf_syslog_alertpri(void);
mode_t logsrvd_conf_iolog_mode(void);
const char *logsrvd_conf_logfile_path(void);
FILE *logsrvd_conf_logfile_stream(void);
const char *logsrvd_conf_logfile_time_format(void);

#endif /* SUDO_LOGSRVD_H */
