/*
 * Copyright (c) 2004-2005, 2010-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <setjmp.h>

#include "missing.h"
#include "alloc.h"
#include "error.h"
#include "sudo_plugin.h"

#define DEFAULT_TEXT_DOMAIN	"sudoers"
#include "gettext.h"

static void _warning(int, const char *, va_list);
       void sudoers_cleanup(int);

sigjmp_buf error_jmp;

extern sudo_conv_t sudo_conv;

void
error2(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _warning(1, fmt, ap);
    va_end(ap);
    sudoers_cleanup(0);
    if (sudo_conv != NULL)
	siglongjmp(error_jmp, eval);
    else
	exit(eval);
}

void
errorx2(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _warning(0, fmt, ap);
    va_end(ap);
    sudoers_cleanup(0);
    if (sudo_conv != NULL)
	siglongjmp(error_jmp, eval);
    else
	exit(eval);
}

void
verror2(int eval, const char *fmt, va_list ap)
{
    _warning(1, fmt, ap);
    sudoers_cleanup(0);
    if (sudo_conv != NULL)
	siglongjmp(error_jmp, eval);
    else
	exit(eval);
}

void
verrorx2(int eval, const char *fmt, va_list ap)
{
    _warning(0, fmt, ap);
    sudoers_cleanup(0);
    if (sudo_conv != NULL)
	siglongjmp(error_jmp, eval);
    else
	exit(eval);
}

void
warning2(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _warning(1, fmt, ap);
    va_end(ap);
}

void
warningx2(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _warning(0, fmt, ap);
    va_end(ap);
}

void
vwarning2(const char *fmt, va_list ap)
{
    _warning(1, fmt, ap);
}

void
vwarningx2(const char *fmt, va_list ap)
{
    _warning(0, fmt, ap);
}

static void
_warning(int use_errno, const char *fmt, va_list ap)
{
    int serrno = errno;

    if (sudo_conv != NULL) {
	struct sudo_conv_message msg[6];
	struct sudo_conv_reply repl[6];
	int nmsgs = 4;
	char *str;

	evasprintf(&str, _(fmt), ap);

	/* Call conversation function */
	memset(&msg, 0, sizeof(msg));
	msg[0].msg_type = SUDO_CONV_ERROR_MSG;
	msg[0].msg = getprogname();
	msg[1].msg_type = SUDO_CONV_ERROR_MSG;
	msg[1].msg = _(": ");
	msg[2].msg_type = SUDO_CONV_ERROR_MSG;
	msg[2].msg = str;
	if (use_errno) {
	    msg[3].msg_type = SUDO_CONV_ERROR_MSG;
	    msg[3].msg = _(": ");
	    msg[4].msg_type = SUDO_CONV_ERROR_MSG;
	    msg[4].msg = strerror(errno);
	    nmsgs = 6;
	}
	msg[nmsgs - 1].msg_type = SUDO_CONV_ERROR_MSG;
	msg[nmsgs - 1].msg = "\n";
	memset(&repl, 0, sizeof(repl));
	sudo_conv(nmsgs, msg, repl);
	efree(str);
    } else {
	fputs(getprogname(), stderr);
	if (fmt != NULL) {
	    fputs(_(": "), stderr);
	    vfprintf(stderr, _(fmt), ap);
	}
	if (use_errno) {
	    fputs(_(": "), stderr);
	    fputs(strerror(serrno), stderr);
	}
	putc('\n', stderr);
    }
}
