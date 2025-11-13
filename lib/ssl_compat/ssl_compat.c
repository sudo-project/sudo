/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2023 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <config.h>

#if defined(HAVE_OPENSSL) && !defined(HAVE_SSL_READ_EX)

# include <sys/types.h>
# if defined(HAVE_WOLFSSL)
#  include <wolfssl/options.h>
# endif
# include <openssl/ssl.h>

# include <sudo_compat.h>
# include <sudo_ssl_compat.h>

/*
 * Emulate SSL_read_ex() using SSL_read().
 */
int
SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)
{
    int nr = SSL_read(ssl, buf, (int)num);
    if (nr < 0)
	nr = 0;
    *readbytes = (size_t)nr;
    return nr > 0;
}

/*
 * Emulate SSL_write_ex() using SSL_write().
 */
int
SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)
{
    int nw = SSL_write(ssl, buf, (int)num);
    if (nw < 0)
	nw = 0;
    *written = (size_t)nw;
    return nw > 0;
}
#endif /* HAVE_OPENSSL && !HAVE_SSL_READ_EX */
