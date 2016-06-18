/*
 * Copyright (c) 2009-2016 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>

#include "sudo.h"
#include "sudo_exec.h"
#include "sudo_event.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

struct exec_closure {
    pid_t child;
    bool log_io;
    sigset_t omask;
    struct command_status *cstat;
    struct command_details *details;
    struct sudo_event_base *evbase;
};

/* We keep a tailq of signals to forward to child. */
struct sigforward {
    TAILQ_ENTRY(sigforward) entries;
    int signo;
};
TAILQ_HEAD(sigfwd_list, sigforward);
static struct sigfwd_list sigfwd_list = TAILQ_HEAD_INITIALIZER(sigfwd_list);
static struct sudo_event *signal_event;
static struct sudo_event *sigfwd_event;
static struct sudo_event *backchannel_event;
static pid_t ppgrp = -1;

volatile pid_t cmnd_pid = -1;

static void signal_pipe_cb(int fd, int what, void *v);
static int dispatch_pending_signals(struct command_status *cstat);
static void forward_signals(int fd, int what, void *v);
static void schedule_signal(struct sudo_event_base *evbase, int signo);
#ifdef SA_SIGINFO
static void handler_user_only(int s, siginfo_t *info, void *context);
#endif

/*
 * Fork and execute a command, returns the child's pid.
 * Sends errno back on sv[1] if execve() fails.
 */
static int
fork_cmnd(struct command_details *details, int sv[2])
{
    struct command_status cstat;
    sigaction_t sa;
    debug_decl(fork_cmnd, SUDO_DEBUG_EXEC)

    ppgrp = getpgrp();	/* parent's process group */

    /*
     * Handle suspend/restore of sudo and the command.
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
    sa.sa_sigaction = handler;
#else
    sa.sa_handler = handler;
#endif
    if (sudo_sigaction(SIGCHLD, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGCHLD);
    if (sudo_sigaction(SIGCONT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGCONT);
#ifdef SA_SIGINFO
    sa.sa_sigaction = handler_user_only;
#endif
    if (sudo_sigaction(SIGTSTP, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);

    cmnd_pid = sudo_debug_fork();
    switch (cmnd_pid) {
    case -1:
	sudo_fatal(U_("unable to fork"));
	break;
    case 0:
	/* child */
	close(sv[0]);
	close(signal_pipe[0]);
	close(signal_pipe[1]);
	(void)fcntl(sv[1], F_SETFD, FD_CLOEXEC);
	exec_cmnd(details, &cstat, sv[1]);
	ignore_result(send(sv[1], &cstat, sizeof(cstat), 0));
	sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, 1);
	_exit(1);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "executed %s, pid %d", details->command,
	(int)cmnd_pid);
    debug_return_int(cmnd_pid);
}

/*
 * Setup the execution environment and execute the command.
 * If SELinux is enabled, run the command via sesh, otherwise
 * execute it directly.
 * If the exec fails, cstat is filled in with the value of errno.
 */
void
exec_cmnd(struct command_details *details, struct command_status *cstat,
    int errfd)
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
    cstat->type = CMD_ERRNO;
    cstat->val = errno;
    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to exec %s: %s",
	details->command, strerror(errno));
    debug_return;
}

static void
backchannel_cb(int fd, int what, void *v)
{
    struct exec_closure *ec = v;
    ssize_t n;
    debug_decl(backchannel_cb, SUDO_DEBUG_EXEC)

    /* read child status */
    n = recv(fd, ec->cstat, sizeof(struct command_status), MSG_WAITALL);
    if (n != sizeof(struct command_status)) {
	if (n == -1) {
	    switch (errno) {
	    case EINTR:
		/* got a signal, restart loop to service it. */
		sudo_ev_loopcontinue(ec->evbase);
		break;
	    case EAGAIN:
		/* not ready after all... */
		break;
	    default:
		ec->cstat->type = CMD_ERRNO;
		ec->cstat->val = errno;
		sudo_debug_printf(SUDO_DEBUG_ERROR,
		    "failed to read child status: %s", strerror(errno));
		sudo_ev_loopbreak(ec->evbase);
		break;
	    }
	} else {
	    /* Short read or EOF. */
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"failed to read child status: %s", n ? "short read" : "EOF");
	    if (!ec->log_io && n == 0) {
		/*
		 * If not logging I/O we may get EOF when the command is
		 * executed and the other end of the backchannel is closed.
		 * Just remove the event in this case.
		 */
		sudo_ev_del(ec->evbase, backchannel_event);
	    } else {
		/* XXX - need new CMD_ type for monitor errors. */
		errno = n ? EIO : ECONNRESET;
		ec->cstat->type = CMD_ERRNO;
		ec->cstat->val = errno;
		sudo_ev_loopbreak(ec->evbase);
	    }
	}
	debug_return;
    }
    switch (ec->cstat->type) {
    case CMD_PID:
	/*
	 * Once we know the command's pid we can unblock
	 * signals which ere blocked in fork_pty().  This
	 * avoids a race between exec of the command and
	 * receipt of a fatal signal from it.
	 */
	cmnd_pid = ec->cstat->val;
	sudo_debug_printf(SUDO_DEBUG_INFO, "executed %s, pid %d",
	    ec->details->command, (int)cmnd_pid);
	if (ec->log_io)
	    sigprocmask(SIG_SETMASK, &ec->omask, NULL);
	break;
    case CMD_WSTATUS:
	if (WIFSTOPPED(ec->cstat->val)) {
	    /* Suspend parent and tell child how to resume on return. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"child stopped, suspending parent");
	    n = suspend_parent(WSTOPSIG(ec->cstat->val));
	    schedule_signal(ec->evbase, n);
	    /* Re-enable I/O events and restart event loop to service signal. */
	    add_io_events(ec->evbase);
	    sudo_ev_loopcontinue(ec->evbase);
	} else {
	    /* Child exited or was killed, either way we are done. */
	    sudo_debug_printf(SUDO_DEBUG_INFO, "child exited or was killed");
	    sudo_ev_loopexit(ec->evbase);
	}
	break;
    case CMD_ERRNO:
	/* Child was unable to execute command or broken pipe. */
	sudo_debug_printf(SUDO_DEBUG_INFO, "errno from child: %s",
	    strerror(ec->cstat->val));
	sudo_ev_loopbreak(ec->evbase);
	break;
    }
    debug_return;
}

/*
 * Setup initial exec events.
 * Allocates events for the signal pipe and backchannel.
 * Forwarded signals on the backchannel are enabled on demand.
 */
static struct sudo_event_base *
exec_event_setup(int backchannel, struct exec_closure *ec)
{
    struct sudo_event_base *evbase;
    debug_decl(exec_event_setup, SUDO_DEBUG_EXEC)

    evbase = sudo_ev_base_alloc();
    if (evbase == NULL)
	sudo_fatal(NULL);

    /* Event for incoming signals via signal_pipe. */
    signal_event = sudo_ev_alloc(signal_pipe[0],
	SUDO_EV_READ|SUDO_EV_PERSIST, signal_pipe_cb, ec);
    if (signal_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(evbase, signal_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* Event for command status via backchannel. */
    backchannel_event = sudo_ev_alloc(backchannel,
	SUDO_EV_READ|SUDO_EV_PERSIST, backchannel_cb, ec);
    if (backchannel_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(evbase, backchannel_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* The signal forwarding event gets added on demand. */
    sigfwd_event = sudo_ev_alloc(backchannel,
	SUDO_EV_WRITE, forward_signals, NULL);
    if (sigfwd_event == NULL)
	sudo_fatal(NULL);

    sudo_debug_printf(SUDO_DEBUG_INFO, "signal pipe fd %d\n", signal_pipe[0]);
    sudo_debug_printf(SUDO_DEBUG_INFO, "backchannel fd %d\n", backchannel);

    debug_return_ptr(evbase);
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
    struct sigforward *sigfwd, *sigfwd_next;
    const char *utmp_user = NULL;
    struct sudo_event_base *evbase;
    struct exec_closure ec;
    bool log_io = false;
    sigaction_t sa;
    pid_t child;
    int sv[2];
    debug_decl(sudo_execute, SUDO_DEBUG_EXEC)

    dispatch_pending_signals(cstat);

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
     * need to allocate a pty.  It is OK to set log_io in the pty-only case
     * as the io plugin tailqueue will be empty and no I/O logging will occur.
     */
    if (!TAILQ_EMPTY(&io_plugins) || ISSET(details->flags, CD_USE_PTY)) {
	log_io = true;
	if (ISSET(details->flags, CD_SET_UTMP))
	    utmp_user = details->utmp_user ? details->utmp_user : user_details.username;
	sudo_debug_printf(SUDO_DEBUG_INFO, "allocate pty for I/O logging");
	pty_setup(details->euid, user_details.tty, utmp_user);
    } else if (!ISSET(details->flags, CD_SET_TIMEOUT|CD_SUDOEDIT) &&
	policy_plugin.u.policy->close == NULL) {
	/*
	 * If there is no policy close function, no I/O logging or pty,
	 * and we were not invoked as sudoedit, just exec directly.
	 */
	exec_cmnd(details, cstat, -1);
	goto done;
    }

    /*
     * We communicate with the child over a bi-directional pair of sockets.
     * Parent sends signal info to child and child sends back wait status.
     */
    if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) == -1)
	sudo_fatal(U_("unable to create sockets"));

    /*
     * Signals to forward to the child process (excluding SIGALRM).
     * We block all other signals while running the signal handler.
     * Note: HP-UX select() will not be interrupted if SA_RESTART set.
     */
    memset(&sa, 0, sizeof(sa));
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT; /* do not restart syscalls */
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = handler;
#else
    sa.sa_handler = handler;
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
#ifdef SIGINFO
    if (sudo_sigaction(SIGINFO, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGINFO);
#endif

    /*
     * When not running the command in a pty, we do not want to
     * forward signals generated by the kernel that the child will
     * already have received either by virtue of being in the
     * controlling tty's process group (SIGINT, SIGQUIT).
     */
#ifdef SA_SIGINFO
    if (!log_io) {
	sa.sa_flags |= SA_SIGINFO;
	sa.sa_sigaction = handler_user_only;
    }
#endif
    if (sudo_sigaction(SIGINT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGINT);
    if (sudo_sigaction(SIGQUIT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGQUIT);

    /*
     * The policy plugin's session init must be run before we fork
     * or certain pam modules won't be able to track their state.
     */
    if (policy_init_session(details) != true)
	sudo_fatalx(U_("policy plugin failed session initialization"));

    /*
     * Child will run the command in the pty, parent will pass data
     * to and from pty.
     */
    if (log_io)
	child = fork_pty(details, sv, &ec.omask);
    else
	child = fork_cmnd(details, sv);
    close(sv[1]);

    /* Set command timeout if specified. */
    if (ISSET(details->flags, CD_SET_TIMEOUT))
	alarm(details->timeout);

    /*
     * I/O logging must be in the C locale for floating point numbers
     * to be logged consistently.
     */
    setlocale(LC_ALL, "C");

    /*
     * Allocate event base and two persistent events:
     *	the signal pipe and the child process's backchannel.
     */
    evbase = exec_event_setup(sv[0], &ec);

    /*
     * Generic exec closure used for signal_pipe and backchannel callbacks.
     * Note ec.omask is set earlier.
     */
    ec.child = child;
    ec.log_io = log_io;
    ec.cstat = cstat;
    ec.evbase = evbase;
    ec.details = details;

    /*
     * In the event loop we pass input from user tty to master
     * and pass output from master to stdout and IO plugin.
     */
    if (log_io)
	add_io_events(evbase);
    if (sudo_ev_loop(evbase, 0) == -1)
	sudo_warn(U_("error in event loop"));
    if (sudo_ev_got_break(evbase)) {
	/* error from callback */
	sudo_debug_printf(SUDO_DEBUG_ERROR, "event loop exited prematurely");
	/* kill command if still running and not I/O logging */
	if (!log_io && kill(child, 0) == 0)
	    terminate_command(child, true);
    }

    if (log_io) {
	/* Flush any remaining output and free pty-related memory. */
	pty_close(cstat);
   }

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	/* This is probably not needed in log_io mode. */
	if (selinux_restore_tty() != 0)
	    sudo_warnx(U_("unable to restore tty label"));
    }
#endif

    /* Free things up. */
    sudo_ev_base_free(evbase);
    sudo_ev_free(sigfwd_event);
    sudo_ev_free(signal_event);
    sudo_ev_free(backchannel_event);
    TAILQ_FOREACH_SAFE(sigfwd, &sigfwd_list, entries, sigfwd_next) {
	free(sigfwd);
    }
    TAILQ_INIT(&sigfwd_list);
done:
    debug_return_int(cstat->type == CMD_ERRNO ? -1 : 0);
}

/*
 * Forward a signal to the command (non-pty version).
 */
static int
dispatch_signal(struct sudo_event_base *evbase, pid_t child,
    int signo, char *signame, struct command_status *cstat)
{
    int rc = 1;
    debug_decl(dispatch_signal, SUDO_DEBUG_EXEC)

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: evbase %p, child: %d, signo %s(%d), cstat %p",
	__func__, evbase, (int)child, signame, signo, cstat);

    if (signo == SIGCHLD) {
	pid_t pid;
	int status;
	/*
	 * The command stopped or exited.
	 */
	do {
	    pid = waitpid(child, &status, WUNTRACED|WNOHANG);
	} while (pid == -1 && errno == EINTR);
	if (pid == child) {
	    if (WIFSTOPPED(status)) {
		/*
		 * Save the controlling terminal's process group
		 * so we can restore it after we resume, if needed.
		 * Most well-behaved shells change the pgrp back to
		 * its original value before suspending so we must
		 * not try to restore in that case, lest we race with
		 * the child upon resume, potentially stopping sudo
		 * with SIGTTOU while the command continues to run.
		 */
		sigaction_t sa, osa;
		pid_t saved_pgrp = -1;
		int signo = WSTOPSIG(status);
		int fd = open(_PATH_TTY, O_RDWR);
		if (fd != -1) {
		    saved_pgrp = tcgetpgrp(fd);
		    if (saved_pgrp == -1) {
			close(fd);
			fd = -1;
		    }
		}
		if (saved_pgrp != -1) {
		    /*
		     * Child was stopped trying to access controlling
		     * terminal.  If the child has a different pgrp
		     * and we own the controlling terminal, give it
		     * to the child's pgrp and let it continue.
		     */
		    if (signo == SIGTTOU || signo == SIGTTIN) {
			if (saved_pgrp == ppgrp) {
			    pid_t child_pgrp = getpgid(child);
			    if (child_pgrp != ppgrp) {
				if (tcsetpgrp(fd, child_pgrp) == 0) {
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
		     * Restore command's process group if different.
		     * Otherwise, we cannot resume some shells.
		     */
		    if (saved_pgrp != ppgrp)
			(void)tcsetpgrp(fd, saved_pgrp);
		    close(fd);
		}
	    } else {
		/* Child has exited or been killed, we are done. */
		cstat->type = CMD_WSTATUS;
		cstat->val = status;
		sudo_ev_del(evbase, signal_event);
		sudo_ev_loopexit(evbase);
		goto done;
	    }
	}
    } else {
	/* Send signal to child. */
	if (signo == SIGALRM) {
	    terminate_command(child, false);
	} else if (kill(child, signo) != 0) {
	    sudo_warn("kill(%d, SIG%s)", (int)child, signame);
	}
    }
    rc = 0;
done:
    debug_return_int(rc);
}

/*
 * Forward a signal to the monitor (pty version).
 */
static int
dispatch_signal_pty(struct sudo_event_base *evbase, pid_t child,
    int signo, char *signame, struct command_status *cstat)
{
    int rc = 1;
    debug_decl(dispatch_signal_pty, SUDO_DEBUG_EXEC)

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: evbase %p, child: %d, signo %s(%d), cstat %p",
	__func__, evbase, (int)child, signame, signo, cstat);

    if (signo == SIGCHLD) {
	int n, status;
	pid_t pid;
	/*
	 * Monitor process was signaled; wait for it as needed.
	 */
	do {
	    pid = waitpid(child, &status, WUNTRACED|WNOHANG);
	} while (pid == -1 && errno == EINTR);
	if (pid == child) {
	    /*
	     * If the monitor dies we get notified via backchannel_cb().
	     * If it was stopped, we should stop too (the command keeps
	     * running in its pty) and continue it when we come back.
	     */
	    if (WIFSTOPPED(status)) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "monitor stopped, suspending parent");
		n = suspend_parent(WSTOPSIG(status));
		kill(pid, SIGCONT);
		schedule_signal(evbase, n);
		/* Re-enable I/O events and restart event loop. */
		add_io_events(evbase);
		sudo_ev_loopcontinue(evbase);
		goto done;
	    } else if (WIFSIGNALED(status)) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "monitor killed, signal %d", WTERMSIG(status));
	    } else {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "monitor exited, status %d", WEXITSTATUS(status));
	    }
	}
    } else {
	/* Schedule signo to be forwared to the child. */
	schedule_signal(evbase, signo);
	/* Restart event loop to service signal immediately. */
	sudo_ev_loopcontinue(evbase);
    }
    rc = 0;
done:
    debug_return_int(rc);
}

/* Signal pipe callback */
static void
signal_pipe_cb(int fd, int what, void *v)
{
    struct exec_closure *ec = v;
    char signame[SIG2STR_MAX];
    unsigned char signo;
    ssize_t nread;
    int rc = 0;
    debug_decl(signal_pipe_cb, SUDO_DEBUG_EXEC)

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
	sudo_debug_printf(SUDO_DEBUG_DIAG, "received SIG%s", signame);
	if (ec->log_io) {
	    rc = dispatch_signal_pty(ec->evbase, ec->child, signo, signame,
		ec->cstat);
	} else {
	    rc = dispatch_signal(ec->evbase, ec->child, signo, signame,
		ec->cstat);
	}
    } while (rc == 0);
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
    int rval = 0;
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
	    rval = 1;
	    break;
	}
	/* Take the first terminal signal. */
	if (signo == SIGINT || signo == SIGQUIT) {
	    cstat->type = CMD_WSTATUS;
	    cstat->val = signo + 128;
	    rval = 1;
	    break;
	}
    }
    /* Only stop if we haven't already been terminated. */
    if (signo == SIGTSTP)
    {
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
    debug_return_int(rval);
}

/*
 * Forward signals in sigfwd_list to child listening on fd.
 */
static void
forward_signals(int sock, int what, void *v)
{
    char signame[SIG2STR_MAX];
    struct sigforward *sigfwd;
    struct command_status cstat;
    ssize_t nsent;
    debug_decl(forward_signals, SUDO_DEBUG_EXEC)

    while (!TAILQ_EMPTY(&sigfwd_list)) {
	sigfwd = TAILQ_FIRST(&sigfwd_list);
	if (sigfwd->signo == SIGCONT_FG)
	    strlcpy(signame, "CONT_FG", sizeof(signame));
	else if (sigfwd->signo == SIGCONT_BG)
	    strlcpy(signame, "CONT_BG", sizeof(signame));
	else if (sig2str(sigfwd->signo, signame) == -1)
	    snprintf(signame, sizeof(signame), "%d", sigfwd->signo);
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "sending SIG%s to child over backchannel", signame);
	cstat.type = CMD_SIGNO;
	cstat.val = sigfwd->signo;
	do {
	    nsent = send(sock, &cstat, sizeof(cstat), 0);
	} while (nsent == -1 && errno == EINTR);
	TAILQ_REMOVE(&sigfwd_list, sigfwd, entries);
	free(sigfwd);
	if (nsent != sizeof(cstat)) {
	    if (errno == EPIPE) {
		struct sigforward *sigfwd_next;
		sudo_debug_printf(SUDO_DEBUG_ERROR,
		    "broken pipe writing to child over backchannel");
		/* Other end of socket gone, empty out sigfwd_list. */
		TAILQ_FOREACH_SAFE(sigfwd, &sigfwd_list, entries, sigfwd_next) {
		    free(sigfwd);
		}
		TAILQ_INIT(&sigfwd_list);
		/* XXX - child (monitor) is dead, we should exit too? */
	    }
	    break;
	}
    }
}

/*
 * Schedule a signal to be forwarded.
 */
static void
schedule_signal(struct sudo_event_base *evbase, int signo)
{
    struct sigforward *sigfwd;
    char signame[SIG2STR_MAX];
    debug_decl(schedule_signal, SUDO_DEBUG_EXEC)

    if (signo == SIGCONT_FG)
	strlcpy(signame, "CONT_FG", sizeof(signame));
    else if (signo == SIGCONT_BG)
	strlcpy(signame, "CONT_BG", sizeof(signame));
    else if (sig2str(signo, signame) == -1)
	snprintf(signame, sizeof(signame), "%d", signo);
    sudo_debug_printf(SUDO_DEBUG_DIAG, "scheduled SIG%s for child", signame);

    if ((sigfwd = calloc(1, sizeof(*sigfwd))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    sigfwd->signo = signo;
    TAILQ_INSERT_TAIL(&sigfwd_list, sigfwd, entries);

    if (sudo_ev_add(evbase, sigfwd_event, NULL, true) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    debug_return;
}

/*
 * Generic handler for signals passed from parent -> child.
 * The other end of signal_pipe is checked in the main event loop.
 */
#ifdef SA_SIGINFO
void
handler(int s, siginfo_t *info, void *context)
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
handler(int s)
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

#ifdef SA_SIGINFO
/*
 * Generic handler for signals passed from parent -> child.
 * The other end of signal_pipe is checked in the main event loop.
 * This version is for the non-pty case and does not forward
 * signals that are generated by the kernel.
 */
static void
handler_user_only(int s, siginfo_t *info, void *context)
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

/*
 * Open a pipe and make both ends non-blocking.
 * Returns 0 on success and -1 on error.
 */
int
pipe_nonblock(int fds[2])
{
    int flags, rval;
    debug_decl(pipe_nonblock, SUDO_DEBUG_EXEC)

    rval = pipe(fds);
    if (rval != -1) {
	flags = fcntl(fds[0], F_GETFL, 0);
	if (flags != -1 && !ISSET(flags, O_NONBLOCK))
	    rval = fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
	if (rval != -1) {
	    flags = fcntl(fds[1], F_GETFL, 0);
	    if (flags != -1 && !ISSET(flags, O_NONBLOCK))
		rval = fcntl(fds[1], F_SETFL, flags | O_NONBLOCK);
	}
	if (rval == -1) {
	    close(fds[0]);
	    close(fds[1]);
	}
    }

    debug_return_int(rval);
}
