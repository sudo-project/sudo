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
#include <sys/wait.h>
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

struct exec_closure_nopty {
    pid_t child;
    struct command_status *cstat;
    struct command_details *details;
    struct sudo_event_base *evbase;
    struct sudo_event *signal_event;
    struct sudo_event *errpipe_event;
};

static void signal_pipe_cb(int fd, int what, void *v);
#ifdef SA_SIGINFO
static void exec_handler_user_only(int s, siginfo_t *info, void *context);
#endif

/* Note: this is basically the same as mon_errpipe_cb() in exec_monitor.c */
static void
errpipe_cb(int fd, int what, void *v)
{
    struct exec_closure_nopty *ec = v;
    ssize_t nread;
    int errval;
    debug_decl(errpipe_cb, SUDO_DEBUG_EXEC);

    /*
     * Read errno from child or EOF when command is executed.
     * Note that the error pipe is *blocking*.
     */
    do {
	nread = read(fd, &errval, sizeof(errval));
    } while (nread == -1 && errno == EINTR);

    switch (nread) {
    case -1:
	if (errno != EAGAIN) {
	    if (ec->cstat->val == CMD_INVALID) {
		/* XXX - need a way to distinguish non-exec error. */
		ec->cstat->type = CMD_ERRNO;
		ec->cstat->val = errno;
	    }
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: failed to read error pipe", __func__);
	    sudo_ev_loopbreak(ec->evbase);
	}
	break;
    default:
	if (nread == 0) {
	    /* The error pipe closes when the command is executed. */
	    sudo_debug_printf(SUDO_DEBUG_INFO, "EOF on error pipe");
	} else {
	    /* Errno value when child is unable to execute command. */
	    sudo_debug_printf(SUDO_DEBUG_INFO, "errno from child: %s",
		strerror(errval));
	    ec->cstat->type = CMD_ERRNO;
	    ec->cstat->val = errval;
	}
	sudo_ev_del(ec->evbase, ec->errpipe_event);
	close(fd);
	break;
    }
    debug_return;
}

/*
 * Fill in the exec closure and setup initial exec events.
 * Allocates events for the signal pipe and error pipe.
 */
static void
fill_exec_closure_nopty(struct exec_closure_nopty *ec,
    struct command_status *cstat, struct command_details *details, int errfd)
{
    debug_decl(fill_exec_closure_nopty, SUDO_DEBUG_EXEC)

    /* Fill in the non-event part of the closure. */
    ec->child = cmnd_pid;
    ec->cstat = cstat;
    ec->details = details;

    /* Setup event base and events. */
    ec->evbase = sudo_ev_base_alloc();
    if (ec->evbase == NULL)
	sudo_fatal(NULL);

    /* Event for local signals via signal_pipe. */
    ec->signal_event = sudo_ev_alloc(signal_pipe[0],
	SUDO_EV_READ|SUDO_EV_PERSIST, signal_pipe_cb, ec);
    if (ec->signal_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(ec->evbase, ec->signal_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* Event for command status via errfd. */
    ec->errpipe_event = sudo_ev_alloc(errfd,
	SUDO_EV_READ|SUDO_EV_PERSIST, errpipe_cb, ec);
    if (ec->errpipe_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(ec->evbase, ec->errpipe_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    sudo_debug_printf(SUDO_DEBUG_INFO, "signal pipe fd %d\n", signal_pipe[0]);
    sudo_debug_printf(SUDO_DEBUG_INFO, "error pipe fd %d\n", errfd);

    debug_return;
}

/*
 * Execute a command and wait for it to finish.
 */
int
exec_nopty(struct command_details *details, struct command_status *cstat)
{
    struct exec_closure_nopty ec;
    sigaction_t sa;
    int errpipe[2];
    debug_decl(exec_nopty, SUDO_DEBUG_EXEC)

    /*
     * We use a pipe to get errno if execve(2) fails in the child.
     */
    if (pipe2(errpipe, O_CLOEXEC) == -1)
	sudo_fatal(U_("unable to create pipe"));

    /*
     * Signals to pass to the child process (excluding SIGALRM).
     * We block all other signals while running the signal handler.
     * Note: HP-UX select() will not be interrupted if SA_RESTART set.
     *
     * We also need to handle suspend/restore of sudo and the command.
     * In most cases, the command will be in the same process group as
     * sudo and job control will "just work".  However, if the command
     * changes its process group ID and does not change it back (or is
     * kill by SIGSTOP which is not catchable), we need to resume the
     * command manually.  Also, if SIGTSTP is sent directly to sudo,
     * we need to suspend the command, and then suspend ourself, restoring
     * the default SIGTSTP handler temporarily.
     *
     * XXX - currently we send SIGCONT upon resume in some cases where
     * we don't need to (e.g. command pgrp == parent pgrp).
     */

    memset(&sa, 0, sizeof(sa));
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT; /* do not restart syscalls */
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = exec_handler;
#else
    sa.sa_handler = exec_handler;
#endif
    if (sudo_sigaction(SIGTERM, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTERM);
    if (sudo_sigaction(SIGHUP, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGHUP);
    if (sudo_sigaction(SIGALRM, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGALRM);
    if (sudo_sigaction(SIGPIPE, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGPIPE);
    if (sudo_sigaction(SIGUSR1, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGUSR1);
    if (sudo_sigaction(SIGUSR2, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGUSR2);
    if (sudo_sigaction(SIGCHLD, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGCHLD);
    if (sudo_sigaction(SIGCONT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGCONT);
#ifdef SIGINFO
    if (sudo_sigaction(SIGINFO, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGINFO);
#endif

    /*
     * When not running the command in a pty, we do not want to
     * forward signals generated by the kernel that the child will
     * already have received by virtue of being in the controlling
     * terminals's process group (SIGINT, SIGQUIT, SIGTSTP).
     */
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = exec_handler_user_only;
#endif
    if (sudo_sigaction(SIGINT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGINT);
    if (sudo_sigaction(SIGQUIT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGQUIT);
    if (sudo_sigaction(SIGTSTP, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);

    /*
     * The policy plugin's session init must be run before we fork
     * or certain pam modules won't be able to track their state.
     */
    if (policy_init_session(details) != true)
	sudo_fatalx(U_("policy plugin failed session initialization"));

    ppgrp = getpgrp();	/* parent's process group */

    cmnd_pid = sudo_debug_fork();
    switch (cmnd_pid) {
    case -1:
	sudo_fatal(U_("unable to fork"));
	break;
    case 0:
	/* child */
	close(errpipe[0]);
	close(signal_pipe[0]);
	close(signal_pipe[1]);
	exec_cmnd(details, errpipe[1]);
	while (write(errpipe[1], &errno, sizeof(int)) == -1) {
	    if (errno != EINTR)
		break;
	}
	sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, 1);
	_exit(1);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "executed %s, pid %d", details->command,
	(int)cmnd_pid);
    close(errpipe[1]);

    /* No longer need execfd. */
    if (details->execfd != -1) {
	close(details->execfd);
	details->execfd = -1;
    }

    /* Set command timeout if specified. */
    if (ISSET(details->flags, CD_SET_TIMEOUT))
	alarm(details->timeout);

    /*
     * Fill in exec closure, allocate event base and two persistent events:
     *	the signal pipe and the error pipe.
     */
    fill_exec_closure_nopty(&ec, cstat, details, errpipe[0]);

    /*
     * Non-pty event loop.
     * Wait for command to exit, handles signals and the error pipe.
     */
    if (sudo_ev_loop(ec.evbase, 0) == -1)
	sudo_warn(U_("error in event loop"));
    if (sudo_ev_got_break(ec.evbase)) {
	/* error from callback */
	sudo_debug_printf(SUDO_DEBUG_ERROR, "event loop exited prematurely");
	/* kill command */
	terminate_command(ec.child, true);
    }

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	if (selinux_restore_tty() != 0)
	    sudo_warnx(U_("unable to restore tty label"));
    }
#endif

    /* Free things up. */
    sudo_ev_base_free(ec.evbase);
    sudo_ev_free(ec.signal_event);
    sudo_ev_free(ec.errpipe_event);
    debug_return_int(cstat->type == CMD_ERRNO ? -1 : 0);
}

/*
 * Wait for command status after receiving SIGCHLD.
 * If the command exits, fill in cstat and stop the event loop.
 * If the command stops, save the tty pgrp, suspend sudo, then restore
 * the tty pgrp when sudo resumes.
 */
static void
handle_sigchld_nopty(struct exec_closure_nopty *ec)
{
    pid_t pid;
    int status;
    char signame[SIG2STR_MAX];
    debug_decl(handle_sigchld_nopty, SUDO_DEBUG_EXEC)

    /* Read command status. */
    do {
	pid = waitpid(ec->child, &status, WUNTRACED|WNOHANG);
    } while (pid == -1 && errno == EINTR);
    switch (pid) {
    case 0:
	/* waitpid() will return 0 for SIGCONT, which we don't care about */
	debug_return;
    case -1:
	sudo_warn(U_("%s: %s"), __func__, "waitpid");
	debug_return;
    }

    if (WIFSTOPPED(status)) {
	/*
	 * Save the controlling terminal's process group so we can restore it
	 * after we resume, if needed.  Most well-behaved shells change the
	 * pgrp back to its original value before suspending so we must
	 * not try to restore in that case, lest we race with the child upon
	 * resume, potentially stopping sudo with SIGTTOU while the command
	 * continues to run.
	 */
	sigaction_t sa, osa;
	pid_t saved_pgrp = -1;
	int fd, signo = WSTOPSIG(status);

	if (sig2str(signo, signame) == -1)
	    snprintf(signame, sizeof(signame), "%d", signo);
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) stopped, SIG%s",
	    __func__, (int)ec->child, signame);

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
	     * Child was stopped trying to access the controlling terminal.
	     * If the child has a different pgrp and we own the controlling
	     * terminal, give it to the child's pgrp and let it continue.
	     */
	    if (signo == SIGTTOU || signo == SIGTTIN) {
		if (saved_pgrp == ppgrp) {
		    pid_t child_pgrp = getpgid(ec->child);
		    if (child_pgrp != ppgrp) {
			if (tcsetpgrp_nobg(fd, child_pgrp) == 0) {
			    if (killpg(child_pgrp, SIGCONT) != 0) {
				sudo_warn("kill(%d, SIGCONT)",
				    (int)child_pgrp);
			    }
			    close(fd);
			    goto done;
			}
		    }
		}
	    }
	}
	if (signo == SIGTSTP) {
	    memset(&sa, 0, sizeof(sa));
	    sigemptyset(&sa.sa_mask);
	    sa.sa_flags = SA_RESTART;
	    sa.sa_handler = SIG_DFL;
	    if (sudo_sigaction(SIGTSTP, &sa, &osa) != 0) {
		sudo_warn(U_("unable to set handler for signal %d"),
		    SIGTSTP);
	    }
	}
	if (kill(getpid(), signo) != 0)
	    sudo_warn("kill(%d, SIG%s)", (int)getpid(), signame);
	if (signo == SIGTSTP) {
	    if (sudo_sigaction(SIGTSTP, &osa, NULL) != 0) {
		sudo_warn(U_("unable to restore handler for signal %d"),
		    SIGTSTP);
	    }
	}
	if (saved_pgrp != -1) {
	    /*
	     * On resume, restore foreground process group, if different.
	     * Otherwise, we cannot resume some shells (pdksh).
	     *
	     * It is possible that we are no longer the foreground process so
	     * use tcsetpgrp_nobg() to prevent sudo from receiving SIGTTOU.
	     */
	    if (saved_pgrp != ppgrp)
		tcsetpgrp_nobg(fd, saved_pgrp);
	    close(fd);
	}
    } else {
	/* Child has exited or been killed, we are done. */
	if (WIFSIGNALED(status)) {
	    if (sig2str(WTERMSIG(status), signame) == -1)
		snprintf(signame, sizeof(signame), "%d", WTERMSIG(status));
	    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) killed, SIG%s",
		__func__, (int)ec->child, signame);
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) exited: %d",
		__func__, (int)ec->child, WEXITSTATUS(status));
	}
	/* Don't overwrite execve() failure with child exit status. */
	if (ec->cstat->type != CMD_ERRNO) {
	    ec->cstat->type = CMD_WSTATUS;
	    ec->cstat->val = status;
	}
	ec->child = -1;
    }
done:
    debug_return;
}

/* Signal pipe callback */
static void
signal_pipe_cb(int fd, int what, void *v)
{
    struct exec_closure_nopty *ec = v;
    char signame[SIG2STR_MAX];
    unsigned char signo;
    ssize_t nread;
    debug_decl(signal_pipe_cb, SUDO_DEBUG_EXEC)

    /* Process received signals until the child dies or the pipe is empty. */
    do {
	/* read signal pipe */
	nread = read(fd, &signo, sizeof(signo));
	if (nread <= 0) {
	    /* It should not be possible to get EOF but just in case... */
	    if (nread == 0)
		errno = ECONNRESET;
	    /* Restart if interrupted by signal so the pipe doesn't fill. */
	    if (errno == EINTR)
		continue;
	    /* On error, store errno and break out of the event loop. */
	    if (errno != EAGAIN) {
		ec->cstat->type = CMD_ERRNO;
		ec->cstat->val = errno;
		sudo_warn(U_("error reading from signal pipe"));
		sudo_ev_loopbreak(ec->evbase);
	    }
	    break;
	}
	if (sig2str(signo, signame) == -1)
	    snprintf(signame, sizeof(signame), "%d", signo);
	sudo_debug_printf(SUDO_DEBUG_DIAG,
	    "%s: evbase %p, child: %d, signo %s(%d), cstat %p",
	    __func__, ec->evbase, (int)ec->child, signame, signo, ec->cstat);

	if (signo == SIGCHLD) {
	    handle_sigchld_nopty(ec);
	    if (ec->child == -1) {
		/* Command exited or was killed, exit event loop. */
		sudo_ev_del(ec->evbase, ec->signal_event);
		sudo_ev_loopexit(ec->evbase);
	    }
	} else if (ec->child != -1) {
	    /* Send signal to child. */
	    if (signo == SIGALRM) {
		terminate_command(ec->child, false);
	    } else if (kill(ec->child, signo) != 0) {
		sudo_warn("kill(%d, SIG%s)", (int)ec->child, signame);
	    }
	}
    } while (ec->child != -1);
    debug_return;
}

#ifdef SA_SIGINFO
/*
 * Generic handler for signals passed from parent -> child.
 * The other end of signal_pipe is checked in the main event loop.
 * This version is for the non-pty case and does not forward
 * signals that are generated by the kernel.
 */
static void
exec_handler_user_only(int s, siginfo_t *info, void *context)
{
    unsigned char signo = (unsigned char)s;

    /*
     * Only forward user-generated signals not sent by a process in
     * the command's own process group.  Signals sent by the kernel
     * may include SIGTSTP when the user presses ^Z.  Curses programs
     * often trap ^Z and send SIGTSTP to their own pgrp, so we don't
     * want to send an extra SIGTSTP.
     */
    if (!USER_SIGNALED(info))
	return;
    if (info->si_pid != 0) {
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
#endif /* SA_SIGINFO */
