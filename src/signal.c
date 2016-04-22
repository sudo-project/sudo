/*
 * Copyright (c) 2009-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "sudo.h"
#include "sudo_exec.h"

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

    for (ss = saved_signals; ss->signo != -1; ss++) {
	if (sigaction(ss->signo, NULL, &ss->sa) != 0)
	    sudo_warn(U_("unable to save handler for signal %d"), ss->signo);
    }

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
	if (ss->restore) {
	    if (sigaction(ss->signo, &ss->sa, NULL) != 0) {
		sudo_warn(U_("unable to restore handler for signal %d"),
		    ss->signo);
	    }
	}
    }

    debug_return;
}

static void
sudo_handler(int s)
{
    unsigned char signo = (unsigned char)s;

    /*
     * The pipe is non-blocking, if we overflow the kernel's pipe
     * buffer we drop the signal.  This is not a problem in practice.
     */
    while (write(signal_pipe[1], &signo, sizeof(signo)) == -1) {
	if (errno != EINTR)
	    break;
    }
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
	sudo_fatal(U_("unable to create pipe"));

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
		if (ss->sa.sa_handler != SIG_IGN) {
		    if (sigaction(ss->signo, &sa, NULL) != 0) {
			sudo_warn(U_("unable to set handler for signal %d"),
			    ss->signo);
		    }
		}
		break;
	}
    }
    /* Ignore SIGPIPE until exec. */
    if (saved_signals[SAVED_SIGPIPE].sa.sa_handler != SIG_IGN) {
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) != 0)
	    sudo_warn(U_("unable to set handler for signal %d"), SIGPIPE);
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
