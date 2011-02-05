/*
 * Copyright (c) 2001-2005 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>

#include <signal.h>
#include <errno.h>

#include "missing.h"

int
sigaction(signo, sa, osa)
    int signo;
    const sigaction_t *sa;
    sigaction_t *osa;
{
    sigaction_t nsa;
    int error;

    /* We must reverse SV_INTERRUPT since it is the opposite of SA_RESTART */
    if (sa) {
	nsa = *sa;
	nsa.sa_flags ^= SV_INTERRUPT;
	sa = &nsa;
    }

    error = sigvec(signo, sa, osa);
    if (!error && osa)
	osa->sa_flags ^= SV_INTERRUPT;		/* flip SV_INTERRUPT as above */

    return error;
}

int
sigemptyset(set)
    sigset_t *set;
{

    *set = 0;
    return 0;
}

int
sigfillset(set)
    sigset_t *set;
{

    *set = ~0;;
    return 0;
}

int
sigaddset(set, signo)
    sigset_t *set;
    int signo;
{

    if (signo <= 0 || signo >= NSIG) {
	errno = EINVAL;
	return -1;
    }

    SET(*set, sigmask(signo));
    return 0;
}

int
sigdelset(set, signo)
    sigset_t *set;
    int signo;
{

    if (signo <= 0 || signo >= NSIG) {
	errno = EINVAL;
	return -1;
    }

    CLR(*set, sigmask(signo));
    return 0;
}

int
sigismember(set, signo)
    sigset_t *set;
    int signo;
{

    return ISSET(*set, sigmask(signo));
}

int
sigprocmask(how, set, oset)
    int how;
    const sigset_t *set;
    sigset_t *oset;
{
    int mask;

    /* If 'set' is NULL the user just wants the current signal mask. */
    if (set == 0)
	mask = sigblock(0);
    else
	switch (how) {
	    case SIG_BLOCK:
		mask = sigblock(*set);
		break;
	    case SIG_UNBLOCK:
		mask = sigsetmask(sigblock(0) & ~(*set));
		break;
	    case SIG_SETMASK:
		mask = sigsetmask(*set);
		break;
	    default:
		return -1;
	}

    if (mask == -1)
	return -1;
    if (oset)
	*oset = mask;
    return 0;
}
