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

#ifndef SUDO_SENDLOG_H
#define SUDO_SENDLOG_H

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error protobuf-c version 1.30 or higher required
#endif

#include "config.h"

#if defined(HAVE_OPENSSL)
# include <openssl/ssl.h>
#endif

#include "logsrv_util.h"

enum client_state {
    ERROR,
    RECV_HELLO,
    SEND_RESTART,
    SEND_ACCEPT,
    SEND_REJECT,
    SEND_IO,
    SEND_EXIT,
    CLOSING,
    FINISHED
};

struct client_closure {
    TAILQ_ENTRY(client_closure) entries;
    int sock;
    bool accept_only;
    bool read_instead_of_write;
    bool write_instead_of_read;
    bool temporary_write_event;
    struct timespec restart;
    struct timespec elapsed;
    struct timespec committed;
    struct timing_closure timing;
    struct sudo_event_base *evbase;
    struct connection_buffer read_buf;
    struct connection_buffer write_buf;
#if defined(HAVE_OPENSSL)
    SSL *ssl;
    struct sudo_event *tls_connect_ev;
    bool tls_connect_state;
#endif
    struct sudo_event *read_ev;
    struct sudo_event *write_ev;
    struct eventlog *evlog;
    struct iolog_file iolog_files[IOFD_MAX];
    const char *iolog_id;
    char *reject_reason;
    char *buf; /* XXX */
    size_t bufsize; /* XXX */
    enum client_state state;
};

#endif /* SUDO_SENDLOG_H */
