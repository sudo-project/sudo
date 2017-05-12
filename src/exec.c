/*
 * Copyright (c) 2009-2017 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <fcntl.h>
#include <signal.h>

#include "sudo.h"
#include "sudo_exec.h"
#include "sudo_event.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

/*
 * Setup the execution environment and execute the command.
 * If SELinux is enabled, run the command via sesh, otherwise
 * execute it directly.
 * If the exec fails, cstat is filled in with the value of errno.
 */
void
exec_cmnd(struct command_details *details, int errfd)
{
    debug_decl(exec_cmnd, SUDO_DEBUG_EXEC)

    restore_signals();
    if (exec_setup(details, NULL, -1) == true) {
	/* headed for execve() */
	if (details->closefrom >= 0) {
	    int fd, maxfd;
	    unsigned char *debug_fds;

	    /* Preserve debug fds and error pipe as needed. */
	    maxfd = sudo_debug_get_fds(&debug_fds);
	    for (fd = 0; fd <= maxfd; fd++) {
		if (sudo_isset(debug_fds, fd))
		    add_preserved_fd(&details->preserved_fds, fd);
	    }
	    if (errfd != -1)
		add_preserved_fd(&details->preserved_fds, errfd);

	    /* Close all fds except those explicitly preserved. */
	    closefrom_except(details->closefrom, &details->preserved_fds);
	}
#ifdef HAVE_SELINUX
	if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	    selinux_execve(details->execfd, details->command, details->argv,
		details->envp, ISSET(details->flags, CD_NOEXEC));
	} else
#endif
	{
	    sudo_execve(details->execfd, details->command, details->argv,
		details->envp, ISSET(details->flags, CD_NOEXEC));
	}
    }
    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to exec %s: %s",
	details->command, strerror(errno));
    debug_return;
}

/*
 * Check for caught signals sent to sudo before command execution.
 * Also suspends the process if SIGTSTP was caught.
 * Returns true if we should terminate, else false.
 */
bool
sudo_terminated(struct command_status *cstat)
{
    int signo;
    bool sigtstp = false;
    debug_decl(sudo_terminated, SUDO_DEBUG_EXEC)

    for (signo = 0; signo < NSIG; signo++) {
	if (signal_pending(signo)) {
	    switch (signo) {
	    case SIGTSTP:
		/* Suspend below if not terminated. */
		sigtstp = true;
		break;
	    default:
		/* Terminal signal, do not exec command. */
		cstat->type = CMD_WSTATUS;
		cstat->val = signo + 128;
		debug_return_bool(true);
		break;
	    }
	}
    }
    if (sigtstp) {
	struct sigaction sa;
	sigset_t set, oset;

	/* Send SIGTSTP to ourselves, unblocking it if needed. */
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;
	if (sudo_sigaction(SIGTSTP, &sa, NULL) != 0)
	    sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);
	sigemptyset(&set);
	sigaddset(&set, SIGTSTP);
	sigprocmask(SIG_UNBLOCK, &set, &oset);
	if (kill(getpid(), SIGTSTP) != 0)
	    sudo_warn("kill(%d, SIGTSTP)", (int)getpid());
	sigprocmask(SIG_SETMASK, &oset, NULL);
	/* No need to restore old SIGTSTP handler. */
    }
    debug_return_bool(false);
}

/*
 * Execute a command, potentially in a pty with I/O loggging, and
 * wait for it to finish.
 * This is a little bit tricky due to how POSIX job control works and
 * we fact that we have two different controlling terminals to deal with.
 */
int
sudo_execute(struct command_details *details, struct command_status *cstat)
{
    debug_decl(sudo_execute, SUDO_DEBUG_EXEC)

    /* If running in background mode, fork and exit. */
    if (ISSET(details->flags, CD_BACKGROUND)) {
	switch (sudo_debug_fork()) {
	    case -1:
		cstat->type = CMD_ERRNO;
		cstat->val = errno;
		debug_return_int(-1);
	    case 0:
		/* child continues without controlling terminal */
		(void)setpgid(0, 0);
		break;
	    default:
		/* parent exits (but does not flush buffers) */
		sudo_debug_exit_int(__func__, __FILE__, __LINE__,
		    sudo_debug_subsys, 0);
		_exit(0);
	}
    }

    /*
     * If we have an I/O plugin or the policy plugin has requested one, we
     * need to allocate a pty.
     */
    if (!TAILQ_EMPTY(&io_plugins) || ISSET(details->flags, CD_USE_PTY)) {
	/*
	 * Run the command in a new pty, wait for it to finish and
	 * send the plugin the exit status.
	 */
	exec_pty(details, cstat);
    } else if (!ISSET(details->flags, CD_SET_TIMEOUT|CD_SUDOEDIT) &&
	policy_plugin.u.policy->close == NULL) {
	/*
	 * If we are not running the command in a pty, we were not invoked
	 * as sudoedit, there is no command timeout and there is no close
	 * function, just exec directly.  Only returns on error.
	 */
	if (!sudo_terminated(cstat)) {
	    exec_cmnd(details, -1);
	    cstat->type = CMD_ERRNO;
	    cstat->val = errno;
	}
    } else {
	/*
	 * No pty but we need to wait for the command to finish to
	 * send the plugin the exit status.
	 */
	exec_nopty(details, cstat);
    }
    debug_return_int(cstat->type == CMD_ERRNO ? -1 : 0);
}

/*
 * Kill command with increasing urgency.
 */
void
terminate_command(pid_t pid, bool use_pgrp)
{
    debug_decl(terminate_command, SUDO_DEBUG_EXEC);

    /* Avoid killing more than a single process or process group. */
    if (pid <= 0)
	debug_return;

    /*
     * Note that SIGCHLD will interrupt the sleep()
     */
    if (use_pgrp) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "killpg %d SIGHUP", (int)pid);
	killpg(pid, SIGHUP);
	sudo_debug_printf(SUDO_DEBUG_INFO, "killpg %d SIGTERM", (int)pid);
	killpg(pid, SIGTERM);
	sleep(2);
	sudo_debug_printf(SUDO_DEBUG_INFO, "killpg %d SIGKILL", (int)pid);
	killpg(pid, SIGKILL);
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill %d SIGHUP", (int)pid);
	kill(pid, SIGHUP);
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill %d SIGTERM", (int)pid);
	kill(pid, SIGTERM);
	sleep(2);
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill %d SIGKILL", (int)pid);
	kill(pid, SIGKILL);
    }

    debug_return;
}
