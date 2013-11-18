/*
 * Copyright (c) 2009-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <errno.h>
#include <signal.h>

#include "sudo.h"

int signal_pipe[2];

static struct signal_state {
    int signo;
    int restore;
    sigaction_t sa;
} saved_signals[] = {
    { SIGALRM },	/* SAVED_SIGALRM */
    { SIGCHLD },	/* SAVED_SIGCHLD */
    { SIGCONT },	/* SAVED_SIGCONT */
    { SIGHUP },		/* SAVED_SIGHUP */
    { SIGINT },		/* SAVED_SIGINT */
    { SIGPIPE },	/* SAVED_SIGPIPE */
    { SIGQUIT },	/* SAVED_SIGQUIT */
    { SIGTERM },	/* SAVED_SIGTERM */
    { SIGTSTP },	/* SAVED_SIGTSTP */
    { SIGTTIN },	/* SAVED_SIGTTIN */
    { SIGTTOU },	/* SAVED_SIGTTOU */
    { SIGUSR1 },	/* SAVED_SIGUSR1 */
    { SIGUSR2 },	/* SAVED_SIGUSR2 */
    { -1 }
};

/*
 * Save signal handler state so it can be restored before exec.
 */
void
save_signals(void)
{
    struct signal_state *ss;
    debug_decl(save_signals, SUDO_DEBUG_MAIN)

    for (ss = saved_signals; ss->signo != -1; ss++)
	sigaction(ss->signo, NULL, &ss->sa);

    debug_return;
}

/*
 * Restore signal handlers to initial state for exec.
 */
void
restore_signals(void)
{
    struct signal_state *ss;
    debug_decl(restore_signals, SUDO_DEBUG_MAIN)

    for (ss = saved_signals; ss->signo != -1; ss++) {
	if (ss->restore)
	    sigaction(ss->signo, &ss->sa, NULL);
    }

    debug_return;
}

static void
sudo_handler(int signo)
{
    /*
     * The pipe is non-blocking, if we overflow the kernel's pipe
     * buffer we drop the signal.  This is not a problem in practice.
     */
    ignore_result(write(signal_pipe[1], &signo, sizeof(signo)));
}

/*
 * Trap tty-generated (and other) signals so we can't be killed before
 * calling the policy close function.  The signal pipe will be drained
 * in sudo_execute() before running the command and new handlers will
 * be installed in the parent.
 */
void
init_signals(void)
{
    struct sigaction sa;
    struct signal_state *ss;
    debug_decl(init_signals, SUDO_DEBUG_MAIN)

    /*
     * We use a pipe to atomically handle signal notification within
     * the select() loop without races (we may not have pselect()).
     */
    if (pipe_nonblock(signal_pipe) != 0)
	fatal(U_("unable to create pipe"));

    memset(&sa, 0, sizeof(sa));
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = sudo_handler;

    for (ss = saved_signals; ss->signo > 0; ss++) {
	switch (ss->signo) {
	    case SIGCHLD:
	    case SIGCONT:
	    case SIGPIPE:
	    case SIGTTIN:
	    case SIGTTOU:
		/* Don't install these until exec time. */
		break;
	    default:
		if (ss->sa.sa_handler != SIG_IGN)
		    sigaction(ss->signo, &sa, NULL);
		break;
	}
    }
    debug_return;
}

/*
 * Like sigaction() but sets restore flag in saved_signals[]
 * if needed.
 */
int
sudo_sigaction(int signo, struct sigaction *sa, struct sigaction *osa)
{
    struct signal_state *ss;
    int rval;
    debug_decl(sudo_sigaction, SUDO_DEBUG_MAIN)

    for (ss = saved_signals; ss->signo > 0; ss++) {
	if (ss->signo == signo) {
	    /* If signal was or now is ignored, restore old handler on exec. */
	    if (ss->sa.sa_handler == SIG_IGN || sa->sa_handler == SIG_IGN) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "will restore signal %d on exec", signo);
		ss->restore = true;
	    }
	    break;
	}
    }
    rval = sigaction(signo, sa, osa);

    debug_return_int(rval);
}
