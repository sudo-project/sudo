/*
 * Copyright (c) 2009-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <signal.h>

#include "missing.h"

#define DEFAULT_TEXT_DOMAIN	"sudo"
#include "gettext.h"

#if defined(HAVE_DECL_SYS_SIGNAME) && HAVE_DECL_SYS_SIGNAME == 1
# define sudo_sys_signame	sys_signame
#elif defined(HAVE_DECL__SYS_SIGNAME) && HAVE_DECL__SYS_SIGNAME == 1
# define sudo_sys_signame	_sys_signame
#elif defined(HAVE_DECL___SYS_SIGNAME) && HAVE_DECL___SYS_SIGNAME == 1
# define sudo_sys_signame	__sys_signame
#else
extern const char *const sudo_sys_signame[NSIG];
#endif

/*
 * Return signal name
 */
char *
strsigname(int signo)
{
    if (signo > 0 && signo < NSIG)
	return (char *)sudo_sys_signame[signo];
    /* XXX - should be "Unknown signal: %s" */
    return _("Unknown signal");
}
