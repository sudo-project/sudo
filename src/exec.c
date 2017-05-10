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

volatile pid_t cmnd_pid = -1;
volatile pid_t ppgrp = -1;

/*
 * Generic handler for signals received by the sudo front end while the
 * command is running.  The other end is checked in the main event loop.
 */
#ifdef SA_SIGINFO
void
exec_handler(int s, siginfo_t *info, void *context)
{
    unsigned char signo = (unsigned char)s;

    /*
     * Do not forward signals sent by a process in the command's process
     * group, do not forward it as we don't want the child to indirectly
     * kill itself.  For example, this can happen with some versions of
     * reboot that call kill(-1, SIGTERM) to kill all other processes.
     */
    if (s != SIGCHLD && USER_SIGNALED(info) && info->si_pid != 0) {
	pid_t si_pgrp = getpgid(info->si_pid);
	if (si_pgrp != -1) {
	    if (si_pgrp == ppgrp || si_pgrp == cmnd_pid)
		return;
	} else if (info->si_pid == cmnd_pid) {
		return;
	}
    }

    /*
     * The pipe is non-blocking, if we overflow the kernel's pipe
     * buffer we drop the signal.  This is not a problem in practice.
     */
    while (write(signal_pipe[1], &signo, sizeof(signo)) == -1) {
	if (errno != EINTR)
	    break;
    }
}
#else
void
exec_handler(int s)
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
#endif

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
 * Drain pending signals from signal_pipe written by sudo_handler().
 * Handles the case where the signal was sent to us before
 * we have executed the command.
 * Returns 1 if we should terminate, else 0.
 */
static int
dispatch_pending_signals(struct command_status *cstat)
{
    ssize_t nread;
    struct sigaction sa;
    unsigned char signo = 0;
    int ret = 0;
    debug_decl(dispatch_pending_signals, SUDO_DEBUG_EXEC)

    for (;;) {
	nread = read(signal_pipe[0], &signo, sizeof(signo));
	if (nread <= 0) {
	    /* It should not be possible to get EOF but just in case. */
	    if (nread == 0)
		errno = ECONNRESET;
	    /* Restart if interrupted by signal so the pipe doesn't fill. */
	    if (errno == EINTR)
		continue;
	    /* If pipe is empty, we are done. */
	    if (errno == EAGAIN)
		break;
	    sudo_debug_printf(SUDO_DEBUG_ERROR, "error reading signal pipe %s",
		strerror(errno));
	    cstat->type = CMD_ERRNO;
	    cstat->val = errno;
	    ret = 1;
	    break;
	}
	/* Take the first terminal signal. */
	if (signo == SIGINT || signo == SIGQUIT) {
	    cstat->type = CMD_WSTATUS;
	    cstat->val = signo + 128;
	    ret = 1;
	    break;
	}
    }
    /* Only stop if we haven't already been terminated. */
    if (signo == SIGTSTP) {
	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = SIG_DFL;
	if (sudo_sigaction(SIGTSTP, &sa, NULL) != 0)
	    sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);
	if (kill(getpid(), SIGTSTP) != 0)
	    sudo_warn("kill(%d, SIGTSTP)", (int)getpid());
	/* No need to reinstall SIGTSTP handler. */
    }
    debug_return_int(ret);
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

    if (dispatch_pending_signals(cstat) != 0) {
	/* Killed by SIGINT or SIGQUIT */
	debug_return_int(0);
    }

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
	exec_cmnd(details, -1);
	cstat->type = CMD_ERRNO;
	cstat->val = errno;
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
