/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2025 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include <sudo_compat.h>
#include <sudo_util.h>

#ifndef LOGIN_NAME_MAX
# ifdef _POSIX_LOGIN_NAME_MAX
#  define LOGIN_NAME_MAX _POSIX_LOGIN_NAME_MAX
# else
#  define LOGIN_NAME_MAX 9
# endif
#endif /* LOGIN_NAME_MAX */

size_t
sudo_login_name_max_v1(void)
{
    static size_t maxval;

    if (maxval == 0) {
	long lval;

#ifdef _SC_LOGIN_NAME_MAX
	lval = sysconf(_SC_LOGIN_NAME_MAX);
	if (lval < 0)
#endif
	    lval = LOGIN_NAME_MAX;
	maxval = (size_t)lval;
    }

    return maxval;
}
