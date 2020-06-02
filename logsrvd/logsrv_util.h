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

#ifndef SUDO_LOGSRV_UTIL_H
#define SUDO_LOGSRV_UTIL_H

/* Default ports to listen on */
#define DEFAULT_PORT		"30343"
#define DEFAULT_PORT_TLS	"30344"

/* Maximum message size (2Mb) */
#define MESSAGE_SIZE_MAX	(2 * 1024 * 1024)

struct connection_buffer {
    uint8_t *data;
    unsigned int size;
    unsigned int len;
    unsigned int off;
};

/* logsrv_util.c */
struct iolog_file;
bool expand_buf(struct connection_buffer *buf, unsigned int needed);
bool iolog_open_all(int dfd, const char *iolog_dir, struct iolog_file *iolog_files, const char *mode);
bool iolog_seekto(int iolog_dir_fd, const char *iolog_path, struct iolog_file *iolog_files, struct timespec *elapsed_time, const struct timespec *target);


#endif /* SUDO_LOGSRV_UTIL_H */
