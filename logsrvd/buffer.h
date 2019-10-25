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

#ifndef SUDO_BUFFER_H
#define SUDO_BUFFER_H

/* Maximum message size (2Mb) */
#define MESSAGE_SIZE_MAX	(2 * 1024 * 1024)

struct connection_buffer {
    uint8_t *data;
    unsigned int size;
    unsigned int len;
    unsigned int off;
};

/* buffer.c */
bool expand_buf(struct connection_buffer *buf, unsigned int needed);
unsigned int bufsize_roundup(unsigned int len);

#endif /* SUDO_BUFFER_H */
