/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2022 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "sudo.h"
#include "sudo_exec.h"

void
suspend_sudo_nopty(struct exec_closure *ec, int signo, pid_t my_pid,
    pid_t my_pgrp, pid_t cmnd_pid)
{
    struct sigaction sa, osa;
    pid_t saved_pgrp = -1;
    int fd;
    debug_decl(suspend_sudo_nopty, SUDO_DEBUG_EXEC);

    /*
     * Save the controlling terminal's process group so we can restore
     * it after we resume, if needed.  Most well-behaved shells change
     * the pgrp back to its original value before suspending so we must
     * not try to restore in that case, lest we race with the command
     * upon resume, potentially stopping sudo with SIGTTOU while the
     * command continues to run.
     */
    fd = open(_PATH_TTY, O_RDWR);
    if (fd != -1) {
	saved_pgrp = tcgetpgrp(fd);
	if (saved_pgrp == -1) {
	    close(fd);
	    fd = -1;
	}
    }

    if (saved_pgrp != -1) {
	/*
	 * Command was stopped trying to access the controlling
	 * terminal.  If the command has a different pgrp and we
	 * own the controlling terminal, give it to the command's
	 * pgrp and let it continue.
	 */
	if (signo == SIGTTOU || signo == SIGTTIN) {
	    if (saved_pgrp == my_pgrp) {
		pid_t cmnd_pgrp = getpgid(cmnd_pid);
		if (cmnd_pgrp != my_pgrp) {
		    if (tcsetpgrp_nobg(fd, cmnd_pgrp) == 0) {
			if (killpg(cmnd_pgrp, SIGCONT) != 0)
			    sudo_warn("kill(%d, SIGCONT)", (int)cmnd_pgrp);
			close(fd);
			debug_return;
		    }
		}
	    }
	}
    }

    /* Log the suspend event. */
    log_suspend(ec, signo);

    if (signo == SIGTSTP) {
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;
	if (sudo_sigaction(SIGTSTP, &sa, &osa) != 0)
	    sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);
    }
    if (kill(my_pid, signo) != 0)
	sudo_warn("kill(%d, %d)", (int)my_pid, signo);
    if (signo == SIGTSTP) {
	if (sudo_sigaction(SIGTSTP, &osa, NULL) != 0)
	    sudo_warn(U_("unable to restore handler for signal %d"), SIGTSTP);
    }

    /* Log the resume event. */
    log_suspend(ec, SIGCONT);

    if (saved_pgrp != -1) {
	/*
	 * On resume, restore foreground process group, if different.
	 * Otherwise, we cannot resume some shells (pdksh).
	 *
	 * It is possible that we are no longer the foreground process,
	 * use tcsetpgrp_nobg() to prevent sudo from receiving SIGTTOU.
	 */
	if (saved_pgrp != my_pgrp)
	    tcsetpgrp_nobg(fd, saved_pgrp);
	close(fd);
    }

    debug_return;
}
