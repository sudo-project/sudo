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
#include <sys/socket.h>
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
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "sudo.h"
#include "sudo_event.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

struct monitor_closure {
    struct sudo_event_base *evbase;
    struct sudo_event *errpipe_event;
    struct sudo_event *backchannel_event;
    struct sudo_event *signal_pipe_event;
    struct command_status *cstat;
    int backchannel;
};

static volatile pid_t cmnd_pgrp;
static pid_t mon_pgrp;

extern int io_fds[6]; /* XXX */

/*
 * Generic handler for signals recieved by the monitor process.
 * The other end of signal_pipe is checked in the monitor event loop.
 */
#ifdef SA_SIGINFO
static void
mon_handler(int s, siginfo_t *info, void *context)
{
    unsigned char signo = (unsigned char)s;

    /*
     * If the signal came from the process group of the command we ran,
     * do not forward it as we don't want the child to indirectly kill
     * itself.  This can happen with, e.g., BSD-derived versions of
     * reboot that call kill(-1, SIGTERM) to kill all other processes.
     */
    if (s != SIGCHLD && USER_SIGNALED(info) && info->si_pid != 0) {
	pid_t si_pgrp = getpgid(info->si_pid);
	if (si_pgrp != -1) {
	    if (si_pgrp == cmnd_pgrp)
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
static void
mon_handler(int s)
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
 * Deliver a signal to the running command.
 * The signal was either forwarded to us by the parent sudo process
 * or was received by the monitor itself.
 *
 * There are two "special" signals, SIGCONT_FG and SIGCONT_BG that
 * also specify whether the command should have the controlling tty.
 */
static void
deliver_signal(pid_t pid, int signo, bool from_parent)
{
    char signame[SIG2STR_MAX];
    int status;
    debug_decl(deliver_signal, SUDO_DEBUG_EXEC);

    /* Avoid killing more than a single process or process group. */
    if (pid <= 0)
	debug_return;

    if (signo == SIGCONT_FG)
	strlcpy(signame, "CONT_FG", sizeof(signame));
    else if (signo == SIGCONT_BG)
	strlcpy(signame, "CONT_BG", sizeof(signame));
    else if (sig2str(signo, signame) == -1)
	snprintf(signame, sizeof(signame), "%d", signo);

    /* Handle signal from parent or monitor. */
    sudo_debug_printf(SUDO_DEBUG_INFO, "received SIG%s%s",
	signame, from_parent ? " from parent" : "");
    switch (signo) {
    case SIGALRM:
	terminate_command(pid, true);
	break;
    case SIGCONT_FG:
	/* Continue in foreground, grant it controlling tty. */
	do {
	    status = tcsetpgrp(io_fds[SFD_SLAVE], cmnd_pgrp);
	} while (status == -1 && errno == EINTR);
	killpg(pid, SIGCONT);
	break;
    case SIGCONT_BG:
	/* Continue in background, I take controlling tty. */
	do {
	    status = tcsetpgrp(io_fds[SFD_SLAVE], mon_pgrp);
	} while (status == -1 && errno == EINTR);
	killpg(pid, SIGCONT);
	break;
    case SIGKILL:
	_exit(1); /* XXX */
	/* NOTREACHED */
    default:
	/* Relay signal to command. */
	killpg(pid, signo);
	break;
    }
    debug_return;
}

/*
 * Send status to parent over socketpair.
 * Return value is the same as send(2).
 */
static int
send_status(int fd, struct command_status *cstat)
{
    int n = -1;
    debug_decl(send_status, SUDO_DEBUG_EXEC);

    if (cstat->type != CMD_INVALID) {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "sending status message to parent: [%d, %d]",
	    cstat->type, cstat->val);
	do {
	    n = send(fd, cstat, sizeof(*cstat), 0);
	} while (n == -1 && errno == EINTR);
	if (n != sizeof(*cstat)) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"unable to send status to parent: %s", strerror(errno));
	}
	cstat->type = CMD_INVALID; /* prevent re-sending */
    }
    debug_return_int(n);
}

/*
 * Wait for command status after receiving SIGCHLD.
 * If the command was stopped, the status is send back to the parent.
 * Otherwise, cstat is filled in but not sent.
 */
static void
mon_handle_sigchld(int backchannel, struct command_status *cstat)
{
    char signame[SIG2STR_MAX];
    int status;
    pid_t pid;
    debug_decl(mon_handle_sigchld, SUDO_DEBUG_EXEC);

    /* Read command status. */
    do {
	pid = waitpid(cmnd_pid, &status, WUNTRACED|WCONTINUED|WNOHANG);
    } while (pid == -1 && errno == EINTR);
    switch (pid) {
    case 0:
	errno = ECHILD;
	/* FALLTHROUGH */
    case -1:
	sudo_warn(U_("%s: %s"), __func__, "waitpid");
	debug_return;
    }

    if (WIFCONTINUED(status)) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) resumed",
	    __func__, (int)cmnd_pid);
    } else if (WIFSTOPPED(status)) {
	if (sig2str(WSTOPSIG(status), signame) == -1)
	    snprintf(signame, sizeof(signame), "%d", WSTOPSIG(status));
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) stopped, SIG%s",
	    __func__, (int)cmnd_pid, signame);
    } else if (WIFSIGNALED(status)) {
	if (sig2str(WTERMSIG(status), signame) == -1)
	    snprintf(signame, sizeof(signame), "%d", WTERMSIG(status));
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) killed, SIG%s",
	    __func__, (int)cmnd_pid, signame);
	cmnd_pid = -1;
    } else if (WIFEXITED(status)) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: command (%d) exited: %d",
	    __func__, (int)cmnd_pid, WEXITSTATUS(status));
	cmnd_pid = -1;
    } else {
	sudo_debug_printf(SUDO_DEBUG_WARN,
	    "%s: unexpected wait status %d for command (%d)",
	    __func__, status, (int)cmnd_pid);
    }

    /* Don't overwrite execve() failure with child exit status. */
    if (cstat->type != CMD_ERRNO) {
	/*
	 * Store wait status in cstat and forward to parent if stopped.
	 */
	cstat->type = CMD_WSTATUS;
	cstat->val = status;
	if (WIFSTOPPED(status)) {
	    /* Save the foreground pgid so we can restore it later. */
	    do {
		pid = tcgetpgrp(io_fds[SFD_SLAVE]);
	    } while (pid == -1 && errno == EINTR);
	    if (pid != mon_pgrp)
		cmnd_pgrp = pid;
	    send_status(backchannel, cstat);
	}
    }

    debug_return;
}

static void
mon_signal_pipe_cb(int fd, int what, void *v)
{
    struct monitor_closure *mc = v;
    unsigned char signo;
    ssize_t nread;
    debug_decl(mon_signal_pipe_cb, SUDO_DEBUG_EXEC);

    nread = read(fd, &signo, sizeof(signo));
    if (nread <= 0) {
	/* It should not be possible to get EOF but just in case. */
	if (nread == 0)
	    errno = ECONNRESET;
	if (errno != EINTR && errno != EAGAIN) {
	    sudo_warn(U_("error reading from signal pipe"));
	    sudo_ev_loopbreak(mc->evbase);
	}
    } else {
	/*
	 * Handle SIGCHLD specially and deliver other signals
	 * directly to the command.
	 */
	if (signo == SIGCHLD) {
	    mon_handle_sigchld(mc->backchannel, mc->cstat);
	    if (cmnd_pid == -1) {
		/* Remove all but the errpipe event. */
		sudo_ev_del(mc->evbase, mc->backchannel_event);
		sudo_ev_del(mc->evbase, mc->signal_pipe_event);
	    }
	} else {
	    deliver_signal(cmnd_pid, signo, false);
	}
    }
    debug_return;
}

/* Note: this is basically the same as errpipe_cb() in exec_nopty.c */
static void
mon_errpipe_cb(int fd, int what, void *v)
{
    struct monitor_closure *mc = v;
    ssize_t nread;
    int errval;
    debug_decl(mon_errpipe_cb, SUDO_DEBUG_EXEC);

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
	    if (mc->cstat->val == CMD_INVALID) {
		/* XXX - need a way to distinguish non-exec error. */
		mc->cstat->type = CMD_ERRNO;
		mc->cstat->val = errno;
	    }
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: failed to read error pipe", __func__);
	    sudo_ev_loopbreak(mc->evbase);
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
	    mc->cstat->type = CMD_ERRNO;
	    mc->cstat->val = errval;
	}
	sudo_ev_del(mc->evbase, mc->errpipe_event);
	close(fd);
	break;
    }
    debug_return;
}

static void
mon_backchannel_cb(int fd, int what, void *v)
{
    struct monitor_closure *mc = v;
    struct command_status cstmp;
    ssize_t n;
    debug_decl(mon_backchannel_cb, SUDO_DEBUG_EXEC);

    /* Read command from backchannel, should be a signal. */
    n = recv(fd, &cstmp, sizeof(cstmp), MSG_WAITALL);
    if (n != sizeof(cstmp)) {
	if (n == -1) {
	    if (errno == EINTR || errno == EAGAIN)
		debug_return;
	    sudo_warn(U_("error reading from socketpair"));
	} else {
	    /* short read or EOF, parent process died? */
	}
	sudo_ev_loopbreak(mc->evbase);
    } else {
	if (cstmp.type == CMD_SIGNO) {
	    deliver_signal(cmnd_pid, cstmp.val, true);
	} else {
	    sudo_warnx(U_("unexpected reply type on backchannel: %d"), cstmp.type);
	}
    }
    debug_return;
}

/*
 * Sets up std{in,out,err} and executes the actual command.
 * Returns only if execve() fails.
 */
static void
exec_cmnd_pty(struct command_details *details, bool foreground, int errfd)
{
    volatile pid_t self = getpid();
    debug_decl(exec_cmnd_pty, SUDO_DEBUG_EXEC);

    /* Register cleanup function */
    sudo_fatal_callback_register(pty_cleanup);

    /* Set command process group here too to avoid a race. */
    setpgid(0, self);

    /* Wire up standard fds, note that stdout/stderr may be pipes. */
    if (io_fds[SFD_STDIN] != STDIN_FILENO) {
	if (dup2(io_fds[SFD_STDIN], STDIN_FILENO) == -1)
	    sudo_fatal("dup2");
	if (io_fds[SFD_STDIN] != io_fds[SFD_SLAVE])
	    close(io_fds[SFD_STDIN]);
    }
    if (io_fds[SFD_STDOUT] != STDOUT_FILENO) {
	if (dup2(io_fds[SFD_STDOUT], STDOUT_FILENO) == -1)
	    sudo_fatal("dup2");
	if (io_fds[SFD_STDOUT] != io_fds[SFD_SLAVE])
	    close(io_fds[SFD_STDOUT]);
    }
    if (io_fds[SFD_STDERR] != STDERR_FILENO) {
	if (dup2(io_fds[SFD_STDERR], STDERR_FILENO) == -1)
	    sudo_fatal("dup2");
	if (io_fds[SFD_STDERR] != io_fds[SFD_SLAVE])
	    close(io_fds[SFD_STDERR]);
    }

    /* Wait for parent to grant us the tty if we are foreground. */
    if (foreground && !ISSET(details->flags, CD_EXEC_BG)) {
	struct timespec ts = { 0, 1000 };  /* 1us */
	while (tcgetpgrp(io_fds[SFD_SLAVE]) != self)
	    nanosleep(&ts, NULL);
    }

    /* Done with the pty slave, don't leak it. */
    if (io_fds[SFD_SLAVE] != -1)
	close(io_fds[SFD_SLAVE]);

    /* Execute command; only returns on error. */
    exec_cmnd(details, errfd);

    debug_return;
}

/*
 * Fill in the monitor closure and setup initial events.
 * Allocates read events for the signal pipe, error pipe and backchannel.
 */
static void
fill_exec_closure_monitor(struct monitor_closure *mc,
    struct command_status *cstat, int errfd, int backchannel)
{
    debug_decl(fill_exec_closure_monitor, SUDO_DEBUG_EXEC);
    
    /* Fill in the non-event part of the closure. */
    cstat->type = CMD_INVALID;
    cstat->val = 0;
    mc->cstat = cstat;
    mc->backchannel = backchannel;

    /* Setup event base and events. */
    mc->evbase = sudo_ev_base_alloc();
    if (mc->evbase == NULL)
        sudo_fatal(NULL);

    /* Event for local signals via signal_pipe. */
    mc->signal_pipe_event = sudo_ev_alloc(signal_pipe[0],
	SUDO_EV_READ|SUDO_EV_PERSIST, mon_signal_pipe_cb, mc);
    if (mc->signal_pipe_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(mc->evbase, mc->signal_pipe_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* Event for command status via errfd. */
    mc->errpipe_event = sudo_ev_alloc(errfd,
	SUDO_EV_READ|SUDO_EV_PERSIST, mon_errpipe_cb, mc);
    if (mc->errpipe_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(mc->evbase, mc->errpipe_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* Event for forwarded signals via backchannel. */
    mc->backchannel_event = sudo_ev_alloc(backchannel,
	SUDO_EV_READ|SUDO_EV_PERSIST, mon_backchannel_cb, mc);
    if (mc->backchannel_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(mc->evbase, mc->backchannel_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));
}

/*
 * Monitor process that creates a new session with the controlling tty,
 * resets signal handlers and forks a child to call exec_cmnd_pty().
 * Waits for status changes from the command and relays them to the
 * parent and relays signals from the parent to the command.
 * Returns an error if fork(2) fails, else calls _exit(2).
 */
int
exec_monitor(struct command_details *details, bool foreground, int backchannel)
{
    struct command_status cstat;
    struct monitor_closure mc;
    sigaction_t sa;
    int errpipe[2], n;
    debug_decl(exec_monitor, SUDO_DEBUG_EXEC);

    /* Close unused fds. */
    if (io_fds[SFD_MASTER] != -1)
	close(io_fds[SFD_MASTER]);
    if (io_fds[SFD_USERTTY] != -1)
	close(io_fds[SFD_USERTTY]);

    /*
     * We use a pipe to atomically handle signal notification within
     * the event loop.
     */
    if (pipe2(signal_pipe, O_NONBLOCK) != 0)
	sudo_fatal(U_("unable to create pipe"));

    /* Reset SIGWINCH and SIGALRM. */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    if (sudo_sigaction(SIGWINCH, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGWINCH);
    if (sudo_sigaction(SIGALRM, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGALRM);

    /* Ignore any SIGTTIN or SIGTTOU we get. */
    sa.sa_handler = SIG_IGN;
    if (sudo_sigaction(SIGTTIN, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTIN);
    if (sudo_sigaction(SIGTTOU, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTOU);

    /* Block all signals in mon_handler(). */
    sigfillset(&sa.sa_mask);

    /* Note: HP-UX poll() will not be interrupted if SA_RESTART is set. */
    sa.sa_flags = SA_INTERRUPT;
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = mon_handler;
#else
    sa.sa_handler = mon_handler;
#endif
    if (sudo_sigaction(SIGCHLD, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGCHLD);

    /* Catch common signals so we can cleanup properly. */
    sa.sa_flags = SA_RESTART;
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = mon_handler;
#else
    sa.sa_handler = mon_handler;
#endif
    if (sudo_sigaction(SIGHUP, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGHUP);
    if (sudo_sigaction(SIGINT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGINT);
    if (sudo_sigaction(SIGQUIT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGQUIT);
    if (sudo_sigaction(SIGTERM, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTERM);
    if (sudo_sigaction(SIGTSTP, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);
    if (sudo_sigaction(SIGUSR1, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGUSR1);
    if (sudo_sigaction(SIGUSR2, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGUSR2);

    /*
     * Start a new session with the parent as the session leader
     * and the slave pty as the controlling terminal.
     * This allows us to be notified when the command has been suspended.
     */
    if (setsid() == -1) {
	sudo_warn("setsid");
	goto bad;
    }
    if (pty_make_controlling() == -1) {
	sudo_warn(U_("unable to set controlling tty"));
	goto bad;
    }

    mon_pgrp = getpgrp();	/* save a copy of our process group */

    /* Start command and wait for it to stop or exit */
    if (pipe2(errpipe, O_CLOEXEC) == -1)
	sudo_fatal(U_("unable to create pipe"));
    cmnd_pid = sudo_debug_fork();
    if (cmnd_pid == -1) {
	sudo_warn(U_("unable to fork"));
	goto bad;
    }
    if (cmnd_pid == 0) {
	/* We pass errno back to our parent via pipe on exec failure. */
	close(backchannel);
	close(signal_pipe[0]);
	close(signal_pipe[1]);
	close(errpipe[0]);
	restore_signals();

	/* setup tty and exec command */
	exec_cmnd_pty(details, foreground, errpipe[1]);
	while (write(errpipe[1], &errno, sizeof(int)) == -1) {
	    if (errno != EINTR)
		break;
	}
	_exit(1);
    }
    close(errpipe[1]);

    /* No longer need execfd. */
    if (details->execfd != -1) {
	close(details->execfd);
	details->execfd = -1;
    }

    /* Send the command's pid to main sudo process. */
    cstat.type = CMD_PID;
    cstat.val = cmnd_pid;
    while (send(backchannel, &cstat, sizeof(cstat), 0) == -1) {
	if (errno != EINTR)
	    break;
    }

    /* If any of stdin/stdout/stderr are pipes, close them in parent. */
    if (io_fds[SFD_STDIN] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDIN]);
    if (io_fds[SFD_STDOUT] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDOUT]);
    if (io_fds[SFD_STDERR] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDERR]);

    /* Put command in its own process group. */
    cmnd_pgrp = cmnd_pid;
    setpgid(cmnd_pid, cmnd_pgrp);

    /* Make the command the foreground process for the pty slave. */
    if (foreground && !ISSET(details->flags, CD_EXEC_BG)) {
	do {
	    n = tcsetpgrp(io_fds[SFD_SLAVE], cmnd_pgrp);
	} while (n == -1 && errno == EINTR);
    }

    /*
     * Create new event base and register read events for the
     * signal pipe, error pipe, and backchannel.
     */
    fill_exec_closure_monitor(&mc, &cstat, errpipe[0], backchannel);

    /*
     * Wait for errno on pipe, signal on backchannel or for SIGCHLD.
     * The event loop ends when the child is no longer running and
     * the error pipe is closed.
     */
    (void) sudo_ev_loop(mc.evbase, 0);
    if (cmnd_pid != -1) {
	/* XXX An error occurred, should send a message back. */
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "Command still running after event loop exit, sending SIGKILL");
	kill(cmnd_pid, SIGKILL);
	/* XXX - wait for cmnd_pid to exit */
    } else {
	/* Send parent status. */
	send_status(backchannel, &cstat);
    }

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	if (selinux_restore_tty() != 0)
	    sudo_warnx(U_("unable to restore tty label"));
    }
#endif
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, 1);
    _exit(1);

bad:
    debug_return_int(errno);
}
