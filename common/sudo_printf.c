/*
 * Copyright (c) 2010-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <sys/types.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#include <stdarg.h>
#include <errno.h>

#include "sudo_plugin.h"
#include "sudo_debug.h"

int
_sudo_printf(int msg_type, const char *fmt, ...)
{
    va_list ap;
    FILE *fp;
    int len;

    switch (msg_type) {
    case SUDO_CONV_INFO_MSG:
	fp = stdout;
	break;
    case SUDO_CONV_ERROR_MSG:
	fp = stderr;
	break;
    case SUDO_CONV_DEBUG_MSG:
    {
	char *buf;
	va_list ap;

	/* XXX - add debug version of vfprintf()? */
	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);
	if (len == -1)
	    return -1;
	sudo_debug_write(buf, len, 0);
	break;
    }
    default:
	errno = EINVAL;
	return -1;
    }

    va_start(ap, fmt);
    len = vfprintf(fp, fmt, ap);
    va_end(ap);

    return len;
}

int (*sudo_printf)(int msg_type, const char *fmt, ...) = _sudo_printf;
