/*
 * Copyright (c) 2001 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * 4. Products derived from this software may not be called "Sudo" nor
 *    may "Sudo" appear in their names without specific prior written
 *    permission from the author.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <signal.h>
#include <errno.h>

#include <compat.h>

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

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

    return(error);
}

int
sigemptyset(set)
    sigset_t *set;
{

    *set = 0;
    return(0);
}

int
sigfillset(set)
    sigset_t *set;
{

    *set = ~0;;
    return(0);
}

int
sigaddset(set, signo)
    sigset_t *set;
    int signo;
{

    if (signo <= 0 || signo >= NSIG) {
	errno = EINVAL;
	return(-1);
    }

    *set |= sigmask(signo);
    return(0);
}

int
sigdelset(set, signo)
    sigset_t *set;
    int signo;
{

    if (signo <= 0 || signo >= NSIG) {
	errno = EINVAL;
	return(-1);
    }

    *set &= ~(sigmask(signo));
    return(0);
}

int
sigismember(set, signo)
    sigset_t *set;
    int signo;
{

    return(*set & sigmask(signo));
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
		mask = sigsetmask(~*set);
		break;
	    case SIG_SETMASK:
		mask = sigsetmask(*set);
		break;
	    default:
		return(-1);
	}

    if (mask == -1)
	return(-1);
    if (oset)
	*oset = mask;
    return(0);
}
