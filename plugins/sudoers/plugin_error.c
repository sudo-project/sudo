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
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#include "missing.h"
#include "alloc.h"
#include "error.h"
#include "logging.h"
#include "sudo_plugin.h"

#define DEFAULT_TEXT_DOMAIN	"sudoers"
#include "gettext.h"

static void _warning(int, const char *, va_list);
       void sudoers_cleanup(int);

static sigjmp_buf error_jmp;
static bool setjmp_enabled = false;

void
error2(int eval, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _warning(1, fmt, ap);
    va_end(ap);
    sudoers_cleanup(0);
    if (setjmp_enabled)
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
    if (setjmp_enabled)
	siglongjmp(error_jmp, eval);
    else
	exit(eval);
}

void
verror2(int eval, const char *fmt, va_list ap)
{
    _warning(1, fmt, ap);
    sudoers_cleanup(0);
    if (setjmp_enabled)
	siglongjmp(error_jmp, eval);
    else
	exit(eval);
}

void
verrorx2(int eval, const char *fmt, va_list ap)
{
    _warning(0, fmt, ap);
    sudoers_cleanup(0);
    if (setjmp_enabled)
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
    char *str;

    evasprintf(&str, fmt, ap);
    if (use_errno) {
	if (fmt != NULL) {
	    sudo_printf(SUDO_CONV_ERROR_MSG,
		_("%s: %s: %s\n"), getprogname(), str, strerror(serrno));
	} else {
	    sudo_printf(SUDO_CONV_ERROR_MSG,
		_("%s: %s\n"), getprogname(), strerror(serrno));
	}
    } else {
	sudo_printf(SUDO_CONV_ERROR_MSG,
	    _("%s: %s\n"), getprogname(), str ? str : "(null)");
    }
    efree(str);
    errno = serrno;
}

static int oldlocale;

void
warning_set_locale(void)
{
    sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);
}

void
warning_restore_locale(void)
{
    sudoers_setlocale(oldlocale, NULL);
}

int
plugin_setjmp(void)
{
    setjmp_enabled = true;
    return sigsetjmp(error_jmp, 1);
}

void
plugin_longjmp(int val)
{
    siglongjmp(error_jmp, val);
}

void
plugin_clearjmp(void)
{
    setjmp_enabled = false;
}
