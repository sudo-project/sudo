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

#include "config.h"

#include <sys/types.h>

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
#include <unistd.h>

#include "sudo_gettext.h"	/* must be included before sudo_compat.h */
#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "sudo_fatal.h"
#include "buffer.h"

/*
 * Round 32-bit unsigned length to the next highest power of two.
 * Always returns at least 64.
 * Algorithm from bit twiddling hacks.
 */
unsigned int
bufsize_roundup(unsigned int len)
{
    if (len < 64)
	return 64;
    len--;
    len |= len >> 1;
    len |= len >> 2;
    len |= len >> 4;
    len |= len >> 8;
    len |= len >> 16;
    len++;
    return len;
}

/*
 * Expand buf as needed or just reset it.
 */
bool
expand_buf(struct connection_buffer *buf, unsigned int needed)
{
    void *newdata;
    debug_decl(expand_buf, SUDO_DEBUG_UTIL)

    if (buf->size < needed) {
	/* Expand buffer. */
	needed = bufsize_roundup(needed);
	if ((newdata = malloc(needed)) == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to malloc %u", __func__, needed);
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
