/*
 * Copyright (c) 2004-2005, 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "missing.h"
#include "error.h"

static void _warning(int, const char *, va_list);
       void cleanup(int);

void
error(int eval, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	_warning(1, fmt, ap);
	va_end(ap);
	cleanup(0);
	exit(eval);
}

void
errorx(int eval, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	_warning(0, fmt, ap);
	va_end(ap);
	cleanup(0);
	exit(eval);
}

void
warning(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	_warning(1, fmt, ap);
	va_end(ap);
}

void
warningx(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	_warning(0, fmt, ap);
	va_end(ap);
}

static void
_warning(int use_errno, const char *fmt, va_list ap)
{
	int serrno = errno;

	fputs(getprogname(), stderr);
	if (fmt != NULL) {
		fputs(": ", stderr);
		vfprintf(stderr, fmt, ap);
	}
	if (use_errno) {
	    fputs(": ", stderr);
	    fputs(strerror(serrno), stderr);
	}
	putc('\n', stderr);
}
