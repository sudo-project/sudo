/*
 * Copyright (c) 2009-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
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
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>

#include "sudo.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

/* Shared with exec_pty.c for use with handler(). */
int signal_pipe[2];

/* We keep a tailq of signals to forward to child. */
struct sigforward {
    struct sigforward *prev, *next;
    int signo;
};
TQ_DECLARE(sigforward)
static struct sigforward_list sigfwd_list;
static pid_t ppgrp = -1;

volatile pid_t cmnd_pid = -1;

static int handle_signals(int sv[2], pid_t child, int log_io,
    struct command_status *cstat);
static void forward_signals(int fd);
static void schedule_signal(int signo);
#ifdef SA_SIGINFO
static void handler_user_only(int s, siginfo_t *info, void *context);
#endif

/*
 * Fork and execute a command, returns the child's pid.
 * Sends errno back on sv[1] if execve() fails.
 */
static int fork_cmnd(struct command_details *details, int sv[2])
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
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT; /* do not restart syscalls */
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = handler;
#else
    sa.sa_handler = handler;
#endif
    sigaction(SIGCONT, &sa, NULL);
#ifdef SA_SIGINFO
    sa.sa_sigaction = handler_user_only;
#endif
    sigaction(SIGTSTP, &sa, NULL);

    /*
     * The policy plugin's session init must be run before we fork
     * or certain pam modules won't be able to track their state.
     */
    if (policy_init_session(details) != true)
	errorx(1, _("policy plugin failed session initialization"));

    cmnd_pid = sudo_debug_fork();
    switch (cmnd_pid) {
    case -1:
	error(1, _("unable to fork"));
	break;
    case 0:
	/* child */
	close(sv[0]);
	close(signal_pipe[0]);
	close(signal_pipe[1]);
	fcntl(sv[1], F_SETFD, FD_CLOEXEC);
	restore_signals();
	if (exec_setup(details, NULL, -1) == true) {
	    /* headed for execve() */
	    sudo_debug_execve(SUDO_DEBUG_INFO, details->command,
		details->argv, details->envp);
	    if (details->closefrom >= 0) {
		int maxfd = details->closefrom;
		dup2(sv[1], maxfd);
		(void)fcntl(maxfd, F_SETFD, FD_CLOEXEC);
		sv[1] = maxfd++;
		if (sudo_debug_fd_set(maxfd) != -1)
		    maxfd++;
		closefrom(maxfd);
	    }
#ifdef HAVE_SELINUX
	    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
		selinux_execve(details->command, details->argv, details->envp,
		    ISSET(details->flags, CD_NOEXEC));
	    } else
#endif
	    {
		sudo_execve(details->command, details->argv, details->envp,
		    ISSET(details->flags, CD_NOEXEC));
	    }
	    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to exec %s: %s",
		details->command, strerror(errno));
	}
	cstat.type = CMD_ERRNO;
	cstat.val = errno;
	send(sv[1], &cstat, sizeof(cstat), 0);
	sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, 1);
	_exit(1);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "executed %s, pid %d", details->command,
	(int)cmnd_pid);
    debug_return_int(cmnd_pid);
}

static struct signal_state {
    int signo;
    sigaction_t sa;
} saved_signals[] = {
    { SIGALRM },
    { SIGCHLD },
    { SIGCONT },
    { SIGHUP },
    { SIGINT },
    { SIGPIPE },
    { SIGQUIT },
    { SIGTERM },
    { SIGTSTP },
    { SIGTTIN },
    { SIGTTOU },
    { SIGUSR1 },
    { SIGUSR2 },
    { -1 }
};

/*
 * Save signal handler state so it can be restored before exec.
 */
void
save_signals(void)
{
    struct signal_state *ss;
    debug_decl(save_signals, SUDO_DEBUG_EXEC)

    for (ss = saved_signals; ss->signo != -1; ss++)
	sigaction(ss->signo, NULL, &ss->sa);

    debug_return;
}

/*
 * Restore signal handlers to initial state.
 */
void
restore_signals(void)
{
    struct signal_state *ss;
    debug_decl(restore_signals, SUDO_DEBUG_EXEC)

    for (ss = saved_signals; ss->signo != -1; ss++)
	sigaction(ss->signo, &ss->sa, NULL);

    debug_return;
}

/*
 * Execute a command, potentially in a pty with I/O loggging.
 * This is a little bit tricky due to how POSIX job control works and
 * we fact that we have two different controlling terminals to deal with.
 */
int
sudo_execute(struct command_details *details, struct command_status *cstat)
{
    int maxfd, n, nready, sv[2];
    const char *utmp_user = NULL;
    bool log_io = false;
    fd_set *fdsr, *fdsw;
    sigaction_t sa;
    sigset_t omask;
    pid_t child;
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
     * need to allocate a pty.  It is OK to set log_io in the pty-only case
     * as the io plugin tailqueue will be empty and no I/O logging will occur.
     */
    if (!tq_empty(&io_plugins) || ISSET(details->flags, CD_USE_PTY)) {
	log_io = true;
	if (ISSET(details->flags, CD_SET_UTMP))
	    utmp_user = details->utmp_user ? details->utmp_user : user_details.username;
	sudo_debug_printf(SUDO_DEBUG_INFO, "allocate pty for I/O logging");
	pty_setup(details->euid, user_details.tty, utmp_user);
    }

    /*
     * We communicate with the child over a bi-directional pair of sockets.
     * Parent sends signal info to child and child sends back wait status.
     */
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sv) == -1)
	error(1, _("unable to create sockets"));

    /*
     * We use a pipe to atomically handle signal notification within
     * the select() loop.
     */
    if (pipe_nonblock(signal_pipe) != 0)
	error(1, _("unable to create pipe"));

    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);

    /*
     * Signals to forward to the child process (excluding SIGALRM and SIGCHLD).
     * Note: HP-UX select() will not be interrupted if SA_RESTART set.
     */
    sa.sa_flags = SA_INTERRUPT; /* do not restart syscalls */
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = handler;
#else
    sa.sa_handler = handler;
#endif
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    /*
     * When not running the command in a pty, we do not want to
     * forward signals generated by the kernel that the child will
     * already have received either by virtue of being in the
     * controlling tty's process group (SIGINT, SIGQUIT) or because
     * the session is terminating (SIGHUP).
     */
#ifdef SA_SIGINFO
    if (!log_io) {
	sa.sa_flags |= SA_SIGINFO;
	sa.sa_sigaction = handler_user_only;
    }
#endif
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    /* Max fd we will be selecting on. */
    maxfd = MAX(sv[0], signal_pipe[0]);

    /*
     * Child will run the command in the pty, parent will pass data
     * to and from pty.  Adjusts maxfd as needed.
     */
    if (log_io)
	child = fork_pty(details, sv, &maxfd, &omask);
    else
	child = fork_cmnd(details, sv);
    close(sv[1]);

    /* Set command timeout if specified. */
    if (ISSET(details->flags, CD_SET_TIMEOUT))
	alarm(details->timeout);

#ifdef HAVE_SETLOCALE
    /*
     * I/O logging must be in the C locale for floating point numbers
     * to be logged consistently.
     */
    setlocale(LC_ALL, "C");
#endif

    /*
     * In the event loop we pass input from user tty to master
     * and pass output from master to stdout and IO plugin.
     */
    fdsr = emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    fdsw = emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    for (;;) {
	memset(fdsw, 0, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));
	memset(fdsr, 0, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));

	FD_SET(signal_pipe[0], fdsr);
	FD_SET(sv[0], fdsr);
	if (!tq_empty(&sigfwd_list))
	    FD_SET(sv[0], fdsw);
	if (log_io)
	    fd_set_iobs(fdsr, fdsw); /* XXX - better name */
	nready = select(maxfd + 1, fdsr, fdsw, NULL, NULL);
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "select returns %d", nready);
	if (nready == -1) {
	    if (errno == EINTR || errno == ENOMEM)
		continue;
	    if (errno == EBADF || errno == EIO) {
		/* One of the ttys must have gone away. */
		goto do_tty_io;
	    }
	    warning(_("select failed"));
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"select failure, terminating child");
	    schedule_signal(SIGKILL);
	    forward_signals(sv[0]);
	    break;
	}
	if (FD_ISSET(sv[0], fdsw)) {
	    forward_signals(sv[0]);
	}
	if (FD_ISSET(signal_pipe[0], fdsr)) {
	    n = handle_signals(sv, child, log_io, cstat);
	    if (n == 0) {
		/* Child has exited, cstat is set, we are done. */
		break;
	    }
	    if (n == -1) {
		/* Error reading signal_pipe[0], should not happen. */
		break;
	    }
	    /* Restart event loop so signals get sent to child immediately. */
	    continue;
	}
	if (FD_ISSET(sv[0], fdsr)) {
	    /* read child status */
	    n = recv(sv[0], cstat, sizeof(*cstat), 0);
	    if (n != sizeof(*cstat)) {
		if (n == -1) {
		    if (errno == EINTR)
			continue;
		    /*
		     * If not logging I/O we may receive ECONNRESET when
		     * the command is executed and sv is closed.
		     * It is safe to ignore this.
		     */
		    if (log_io && errno != EAGAIN) {
			cstat->type = CMD_ERRNO;
			cstat->val = errno;
			break;
		    }
		    sudo_debug_printf(SUDO_DEBUG_ERROR,
			"failed to read child status: %s", strerror(errno));
		} else {
		    /* Short read or EOF. */
		    sudo_debug_printf(SUDO_DEBUG_ERROR,
			"failed to read child status: %s",
			n ? "short read" : "EOF");
		    /* XXX - should set cstat */
		    break;
		}
	    }
	    if (cstat->type == CMD_PID) {
		/*
                 * Once we know the command's pid we can unblock
                 * signals which ere blocked in fork_pty().  This
                 * avoids a race between exec of the command and
                 * receipt of a fatal signal from it.
		 */
		cmnd_pid = cstat->val;
		sudo_debug_printf(SUDO_DEBUG_INFO, "executed %s, pid %d",
		    details->command, (int)cmnd_pid);
		if (log_io)
		    sigprocmask(SIG_SETMASK, &omask, NULL);
	    } else if (cstat->type == CMD_WSTATUS) {
		if (WIFSTOPPED(cstat->val)) {
		    /* Suspend parent and tell child how to resume on return. */
		    sudo_debug_printf(SUDO_DEBUG_INFO,
			"child stopped, suspending parent");
		    n = suspend_parent(WSTOPSIG(cstat->val));
		    schedule_signal(n);
		    continue;
		} else {
		    /* Child exited or was killed, either way we are done. */
		    sudo_debug_printf(SUDO_DEBUG_INFO, "child exited or was killed");
		    break;
		}
	    } else if (cstat->type == CMD_ERRNO) {
		/* Child was unable to execute command or broken pipe. */
		sudo_debug_printf(SUDO_DEBUG_INFO, "errno from child: %s",
		    strerror(cstat->val));
		break;
	    }
	}
do_tty_io:
	if (perform_io(fdsr, fdsw, cstat) != 0) {
	    /* I/O error, kill child if still alive and finish. */
	    sudo_debug_printf(SUDO_DEBUG_ERROR, "I/O error, terminating child");
	    schedule_signal(SIGKILL);
	    forward_signals(sv[0]);
	    break;
	}
    }

    if (log_io) {
	/* Flush any remaining output and free pty-related memory. */
	pty_close(cstat);
   }

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	/* This is probably not needed in log_io mode. */
	if (selinux_restore_tty() != 0)
	    warningx(_("unable to restore tty label"));
    }
#endif

    efree(fdsr);
    efree(fdsw);
    while (!tq_empty(&sigfwd_list)) {
	struct sigforward *sigfwd = tq_first(&sigfwd_list);
	tq_remove(&sigfwd_list, sigfwd);
	efree(sigfwd);
    }

    debug_return_int(cstat->type == CMD_ERRNO ? -1 : 0);
}

/*
 * Read signals on fd written to by handler().
 * Returns -1 on error, 0 on child exit, else 1.
 */
static int
handle_signals(int sv[2], pid_t child, int log_io, struct command_status *cstat)
{
    char signame[SIG2STR_MAX];
    unsigned char signo;
    ssize_t nread;
    int status;
    pid_t pid;
    debug_decl(handle_signals, SUDO_DEBUG_EXEC)

    for (;;) {
	/* read signal pipe */
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
	    debug_return_int(-1);
	}
	if (sig2str(signo, signame) == -1)
	    snprintf(signame, sizeof(signame), "%d", signo);
	sudo_debug_printf(SUDO_DEBUG_DIAG, "received SIG%s", signame);
	if (signo == SIGCHLD) {
	    /*
	     * If logging I/O, child is the intermediate process,
	     * otherwise it is the command itself.
	     */
	    do {
		pid = waitpid(child, &status, WUNTRACED|WNOHANG);
	    } while (pid == -1 && errno == EINTR);
	    if (pid == child) {
		if (log_io) {
		    /*
		     * On BSD we get ECONNRESET on sv[0] if monitor dies
		     * and select() will return with sv[0] readable.
		     * On Linux that doesn't appear to happen so if the
		     * monitor dies, shut down the socketpair to force a
		     * select() notification.
		     */
		    (void) shutdown(sv[0], SHUT_WR);
		} else {
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
			pid_t saved_pgrp = (pid_t)-1;
			int signo = WSTOPSIG(status);
			int fd = open(_PATH_TTY, O_RDWR|O_NOCTTY, 0);
			if (fd != -1) {
			    if ((saved_pgrp = tcgetpgrp(fd)) == ppgrp)
				saved_pgrp = -1;
			}
			if (signo == SIGTSTP) {
			    zero_bytes(&sa, sizeof(sa));
			    sigemptyset(&sa.sa_mask);
			    sa.sa_handler = SIG_DFL;
			    sigaction(SIGTSTP, &sa, &osa);
			}
			if (kill(getpid(), signo) != 0)
			    warning("kill(%d, SIG%s)", (int)getpid(), signame);
			if (signo == SIGTSTP)
			    sigaction(SIGTSTP, &osa, NULL);
			if (fd != -1) {
			    /*
			     * Restore command's process group if different.
			     * Otherwise, we cannot resume some shells.
			     */
			    if (saved_pgrp != (pid_t)-1)
				(void)tcsetpgrp(fd, saved_pgrp);
			    close(fd);
			}
		    } else {
			/* Child has exited, we are done. */
			cstat->type = CMD_WSTATUS;
			cstat->val = status;
			debug_return_int(0);
		    }
		}
	    }
	} else {
	    if (log_io) {
		/* Schedule signo to be forwared to the child. */
		schedule_signal(signo);
	    } else {
		/* Nothing listening on sv[0], send directly. */
		if (signo == SIGALRM)
		    terminate_command(child, false);
		else if (kill(child, signo) != 0)
		    warning("kill(%d, SIG%s)", (int)child, signame);
	    }
	}
    }
    debug_return_int(1);
}

/*
 * Forward signals in sigfwd_list to child listening on fd.
 */
static void
forward_signals(int sock)
{
    char signame[SIG2STR_MAX];
    struct sigforward *sigfwd;
    struct command_status cstat;
    ssize_t nsent;
    debug_decl(forward_signals, SUDO_DEBUG_EXEC)

    while (!tq_empty(&sigfwd_list)) {
	sigfwd = tq_first(&sigfwd_list);
	if (sig2str(sigfwd->signo, signame) == -1)
	    snprintf(signame, sizeof(signame), "%d", sigfwd->signo);
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "sending SIG%s to child over backchannel", signame);
	cstat.type = CMD_SIGNO;
	cstat.val = sigfwd->signo;
	do {
	    nsent = send(sock, &cstat, sizeof(cstat), 0);
	} while (nsent == -1 && errno == EINTR);
	tq_remove(&sigfwd_list, sigfwd);
	efree(sigfwd);
	if (nsent != sizeof(cstat)) {
	    if (errno == EPIPE) {
		sudo_debug_printf(SUDO_DEBUG_ERROR,
		    "broken pipe writing to child over backchannel");
		/* Other end of socket gone, empty out sigfwd_list. */
		while (!tq_empty(&sigfwd_list)) {
		    sigfwd = tq_first(&sigfwd_list);
		    tq_remove(&sigfwd_list, sigfwd);
		    efree(sigfwd);
		}
		/* XXX - child (monitor) is dead, we should exit too? */
	    }
	    break;
	}
    }
    debug_return;
}

/*
 * Schedule a signal to be forwared.
 */
static void
schedule_signal(int signo)
{
    struct sigforward *sigfwd;
    char signame[SIG2STR_MAX];
    debug_decl(schedule_signal, SUDO_DEBUG_EXEC)

    if (sig2str(signo, signame) == -1)
	snprintf(signame, sizeof(signame), "%d", signo);
    sudo_debug_printf(SUDO_DEBUG_DIAG, "forwarding SIG%s to child", signame);

    sigfwd = ecalloc(1, sizeof(*sigfwd));
    sigfwd->prev = sigfwd;
    /* sigfwd->next = NULL; */
    sigfwd->signo = signo;
    tq_append(&sigfwd_list, sigfwd);

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
     * If the signal came from the command we ran, just ignore
     * it since we don't want the child to indirectly kill itself.
     * This can happen with, e.g. BSD-derived versions of reboot
     * that call kill(-1, SIGTERM) to kill all other processes.
     */
    if (info != NULL && info->si_code == SI_USER && info->si_pid == cmnd_pid)
	    return;

    /*
     * The pipe is non-blocking, if we overflow the kernel's pipe
     * buffer we drop the signal.  This is not a problem in practice.
     */
    ignore_result(write(signal_pipe[1], &signo, sizeof(signo)));
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
    ignore_result(write(signal_pipe[1], &signo, sizeof(signo)));
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

    /* Only forward user-generated signals. */
    if (info != NULL && info->si_code == SI_USER) {
	/*
	 * The pipe is non-blocking, if we overflow the kernel's pipe
	 * buffer we drop the signal.  This is not a problem in practice.
	 */
	ignore_result(write(signal_pipe[1], &signo, sizeof(signo)));
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
