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

#ifndef SUDOERS_IOLOG_CLIENT_H
#define SUDOERS_IOLOG_CLIENT_H

#if defined(HAVE_OPENSSL)
# include <openssl/ssl.h>
#endif /* HAVE_OPENSSL */

#include "log_server.pb-c.h"
#include "strlist.h"

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error protobuf-c version 1.30 or higher required
#endif

/* Default port to listen on */
#define DEFAULT_PORT_STR	"30344"

/* Maximum message size (2Mb) */
#define MESSAGE_SIZE_MAX	(2 * 1024 * 1024)

/* TODO - share with logsrvd/sendlog */
struct connection_buffer {
    TAILQ_ENTRY(connection_buffer) entries;
    uint8_t *data;
    unsigned int size;
    unsigned int len;
    unsigned int off;
};
TAILQ_HEAD(connection_buffer_list, connection_buffer);

/* XXX - remove dependency on sudoers.h? */
#undef runas_pw
#undef runas_gr

struct iolog_details {
    const char *cwd;
    const char *host;
    const char *tty;
    const char *user;
    const char *command;
    const char *iolog_path;
    struct passwd *runas_pw;
    struct group *runas_gr;
    char * const *argv;
    char **user_env;
    struct sudoers_str_list *log_servers;
    struct timespec server_timeout;
    bool tcp_keepalive;
#if defined(HAVE_OPENSSL)
    char *ca_bundle;
    char *cert_file;
    char *key_file;
#endif /* HAVE_OPENSSL */
    int argc;
    int lines;
    int cols;
    bool ignore_iolog_errors;
};

enum client_state {
    ERROR,
    RECV_HELLO,
    SEND_RESTART,	/* TODO: currently unimplemented */
    SEND_ACCEPT,
    SEND_IO,
    SEND_EXIT,
    CLOSING,
    FINISHED
};

/* Remote connection closure, non-zero fields must come first. */
struct client_closure {
    int sock;
    bool read_instead_of_write;
    bool write_instead_of_read;
    bool temporary_write_event;
    const struct sudoers_string *server_name;
#if defined(HAVE_STRUCT_IN6_ADDR)
    char server_ip[INET6_ADDRSTRLEN];
#else
    char server_ip[INET_ADDRSTRLEN];
#endif
#if defined(HAVE_OPENSSL)
    bool tls;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
#endif /* HAVE_OPENSSL */
    enum client_state state;
    bool disabled;
    struct connection_buffer_list write_bufs;
    struct connection_buffer_list free_bufs;
    struct connection_buffer read_buf;
    struct sudo_plugin_event *read_ev;
    struct sudo_plugin_event *write_ev;
    struct iolog_details *log_details;
    struct timespec start_time;
    struct timespec elapsed;
    struct timespec committed;
    char *iolog_id;
};

#if defined(HAVE_OPENSSL)
# define CLIENT_CLOSURE_INITIALIZER(_c)			\
    {							\
	-1,						\
	false,						\
	false,						\
	false,						\
	NULL,					    \
	"", 					    \
    false,                      \
    NULL,						\
    NULL,						\
	ERROR,						\
	false,						\
	TAILQ_HEAD_INITIALIZER((_c).write_bufs),	\
	TAILQ_HEAD_INITIALIZER((_c).free_bufs)		\
    }
#else
# define CLIENT_CLOSURE_INITIALIZER(_c)			\
    {							\
	-1,						\
	false,						\
	false,						\
	false,						\
	NULL,					    \
	"", 					    \
	ERROR,						\
	false,						\
	TAILQ_HEAD_INITIALIZER((_c).write_bufs),	\
	TAILQ_HEAD_INITIALIZER((_c).free_bufs)		\
    }
#endif /* HAVE_OPENSSL */

/* iolog_client.c */
bool client_closure_fill(struct client_closure *closure, int sock, const struct sudoers_string *host, struct iolog_details *details, struct io_plugin *sudoers_io);
bool client_close(struct client_closure *closure, int exit_status, int error);
bool fmt_accept_message(struct client_closure *closure);
bool fmt_client_message(struct client_closure *closure, ClientMessage *msg);
bool fmt_exit_message(struct client_closure *closure, int exit_status, int error);
bool fmt_io_buf(struct client_closure *closure, int type, const char *buf, unsigned int len, struct timespec *delay);
bool fmt_suspend(struct client_closure *closure, const char *signame, struct timespec *delay);
bool fmt_winsize(struct client_closure *closure, unsigned int lines, unsigned int cols, struct timespec *delay);
int log_server_connect(struct sudoers_str_list *servers, bool tcp_keepalive, struct timespec *timo, struct sudoers_string **connected_server);
void client_closure_free(struct client_closure *closure);

#endif /* SUDOERS_IOLOG_CLIENT_H */
