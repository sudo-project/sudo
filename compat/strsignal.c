/*
 * Copyright (c) 2009 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <stdio.h>
#include <signal.h>

#include <config.h>
#include <compat.h>

#if defined(HAVE_DECL_SYS_SIGLIST)
# define my_sys_siglist	sys_siglist
#elif defined(HAVE_DECL__SYS_SIGLIST)
# define my_sys_siglist	_sys_siglist
#elif defined(HAVE_DECL___SYS_SIGLIST)
# define my_sys_siglist	__sys_siglist
#else
# error one of HAVE_DECL_SYS_SIGLIST, HAVE_DECL__SYS_SIGLIST, HAVE_DECL___SYS_SIGLIST must be defined
#endif

#if !defined(NSIG)
# if defined(_NSIG)
#  define NSIG _NSIG
# elif defined(__NSIG)
#  define NSIG __NSIG
# else
#  error one of NSIG, _NSIG, or __NSIG must be defined
# endif
#endif

/*
 * Get signal description string
 */
char *
strsignal(int signo)
{
    if (signo > 0 && signo < NSIG)
	return((char *)my_sys_siglist[signo]);
    return("Unknown signal");
}
