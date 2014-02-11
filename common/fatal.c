/*
 * Copyright (c) 2004-2005, 2010-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#define DEFAULT_TEXT_DOMAIN	"sudo"
#include "gettext.h"		/* must be included before missing.h */

#include "missing.h"
#include "alloc.h"
#include "fatal.h"
#include "queue.h"
#include "sudo_plugin.h"

struct sudo_fatal_callback {
    SLIST_ENTRY(sudo_fatal_callback) entries;
    void (*func)(void);
};
SLIST_HEAD(sudo_fatal_callback_list, sudo_fatal_callback);

sigjmp_buf fatal_jmp;
static bool setjmp_enabled = false;
static struct sudo_fatal_callback_list callbacks;

static void _warning(int, const char *, va_list);

static void
do_cleanup(void)
{
    struct sudo_fatal_callback *cb;

    /* Run callbacks, removing them from the list as we go. */
    while ((cb = SLIST_FIRST(&callbacks)) != NULL) {
	SLIST_REMOVE_HEAD(&callbacks, entries);
	cb->func();
	free(cb);
    }
}

void
fatal_nodebug(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _warning(1, fmt, ap);
    va_end(ap);
    do_cleanup();
    if (setjmp_enabled)
	siglongjmp(fatal_jmp, 1);
    else
	exit(EXIT_FAILURE);
}

void
fatalx_nodebug(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _warning(0, fmt, ap);
    va_end(ap);
    do_cleanup();
    if (setjmp_enabled)
	siglongjmp(fatal_jmp, 1);
    else
	exit(EXIT_FAILURE);
}

void
vfatal_nodebug(const char *fmt, va_list ap)
{
    _warning(1, fmt, ap);
    do_cleanup();
    if (setjmp_enabled)
	siglongjmp(fatal_jmp, 1);
    else
	exit(EXIT_FAILURE);
}

void
vfatalx_nodebug(const char *fmt, va_list ap)
{
    _warning(0, fmt, ap);
    do_cleanup();
    if (setjmp_enabled)
	siglongjmp(fatal_jmp, 1);
    else
	exit(EXIT_FAILURE);
}

void
warning_nodebug(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    _warning(1, fmt, ap);
    va_end(ap);
}

void
warningx_nodebug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    _warning(0, fmt, ap);
    va_end(ap);
}

void
vwarning_nodebug(const char *fmt, va_list ap)
{
    _warning(1, fmt, ap);
}

void
vwarningx_nodebug(const char *fmt, va_list ap)
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

int
fatal_callback_register(void (*func)(void))
{
    struct sudo_fatal_callback *cb;

    cb = malloc(sizeof(*cb));
    if (cb == NULL)
	return -1;
    cb->func = func;
    SLIST_INSERT_HEAD(&callbacks, cb, entries);

    return 0;
}

void
fatal_disable_setjmp(void)
{
    setjmp_enabled = false;
}

void
fatal_enable_setjmp(void)
{
    setjmp_enabled = true;
}
