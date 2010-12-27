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
#include <setjmp.h>

#include "missing.h"
#include "alloc.h"
#include "error.h"
#include "sudo_plugin.h"

static void _warning(int, const char *, va_list);
       void plugin_cleanup(int);

sigjmp_buf error_jmp;

extern sudo_conv_t sudo_conv;

void
error(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _warning(1, fmt, ap);
    va_end(ap);
    plugin_cleanup(0);
    siglongjmp(error_jmp, eval);
}

void
errorx(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _warning(0, fmt, ap);
    va_end(ap);
    plugin_cleanup(0);
    siglongjmp(error_jmp, eval);
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
    struct sudo_conv_message msg[6];
    struct sudo_conv_reply repl[6];
    char *str;
    int nmsgs = 4;

    evasprintf(&str, fmt, ap);

    /* Call conversation function */
    memset(&msg, 0, sizeof(msg));
    msg[0].msg_type = SUDO_CONV_ERROR_MSG;
    msg[0].msg = getprogname();
    msg[1].msg_type = SUDO_CONV_ERROR_MSG;
    msg[1].msg = ": ";
    msg[2].msg_type = SUDO_CONV_ERROR_MSG;
    msg[2].msg = str;
    if (use_errno) {
	msg[3].msg_type = SUDO_CONV_ERROR_MSG;
	msg[3].msg = ": ";
	msg[4].msg_type = SUDO_CONV_ERROR_MSG;
	msg[4].msg = strerror(errno);
	nmsgs = 6;
    }
    msg[nmsgs - 1].msg_type = SUDO_CONV_ERROR_MSG;
    msg[nmsgs - 1].msg = "\n";
    memset(&repl, 0, sizeof(repl));
    sudo_conv(nmsgs, msg, repl);
    efree(str);
}
