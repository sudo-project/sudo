/*
 * Copyright (c) 2009-2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

static int handle_signals(int fd, pid_t child, int log_io,
    struct command_status *cstat);
static void forward_signals(int fd);
static void schedule_signal(int signo);

/*
 * Like execve(2) but falls back to running through /bin/sh
 * ala execvp(3) if we get ENOEXEC.
 */
int
my_execve(const char *path, char *const argv[], char *const envp[])
{
    execve(path, argv, envp);
    if (errno == ENOEXEC) {
	int argc;
	char **nargv;

	for (argc = 0; argv[argc] != NULL; argc++)
	    continue;
	nargv = emalloc2(argc + 2, sizeof(char *));
	nargv[0] = "sh";
	nargv[1] = (char *)path;
	memcpy(nargv + 2, argv + 1, argc * sizeof(char *));
	execve(_PATH_BSHELL, nargv, envp);
	efree(nargv);
    }
    return -1;
}

/*
 * Fork and execute a command, returns the child's pid.
 * Sends errno back on sv[1] if execve() fails.
 */
static int fork_cmnd(struct command_details *details, char *argv[],
    char *envp[], int sv[2])
{
    struct command_status cstat;
    sigaction_t sa;
    pid_t child;

    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT; /* do not restart syscalls */
    sa.sa_handler = handler;
    sigaction(SIGCONT, &sa, NULL);

    child = fork();
    switch (child) {
    case -1:
	error(1, "fork");
	break;
    case 0:
	/* child */
	close(sv[0]);
	close(signal_pipe[0]);
	close(signal_pipe[1]);
	fcntl(sv[1], F_SETFD, FD_CLOEXEC);
	restore_signals();
	if (exec_setup(details, NULL, -1) == TRUE) {
	    /* headed for execve() */
	    if (details->closefrom >= 0)
		closefrom(details->closefrom);
#ifdef HAVE_SELINUX
	    if (ISSET(details->flags, CD_RBAC_ENABLED))
		selinux_execve(details->command, argv, envp);
	    else
#endif
		my_execve(details->command, argv, envp);
	}
	cstat.type = CMD_ERRNO;
	cstat.val = errno;
	send(sv[1], &cstat, sizeof(cstat), 0);
	_exit(1);
    }
    return child;
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

    for (ss = saved_signals; ss->signo != -1; ss++)
	sigaction(ss->signo, NULL, &ss->sa);
}

/*
 * Restore signal handlers to initial state.
 */
void
restore_signals(void)
{
    struct signal_state *ss;

    for (ss = saved_signals; ss->signo != -1; ss++)
	sigaction(ss->signo, &ss->sa, NULL);
}

/*
 * Execute a command, potentially in a pty with I/O loggging.
 * This is a little bit tricky due to how POSIX job control works and
 * we fact that we have two different controlling terminals to deal with.
 */
int
sudo_execve(struct command_details *details, char *argv[], char *envp[],
    struct command_status *cstat)
{
    int maxfd, n, nready, sv[2], log_io = FALSE;
    fd_set *fdsr, *fdsw;
    sigaction_t sa;
    pid_t child;

    /* If running in background mode, fork and exit. */
    if (ISSET(details->flags, CD_BACKGROUND)) {
	switch (fork()) {
	    case -1:
		cstat->type = CMD_ERRNO;
		cstat->val = errno;
		return -1;
	    case 0:
		/* child continues */   
		break;
	    default:
		/* parent exits */
		exit(0);
	}
    }

    /*
     * If we have an I/O plugin or the policy plugin has requested one, we
     * need to allocate a pty.  It is OK to set log_io in the pty-only case
     * as the tailqueue plugin will be empty and no I/O logging will occur.
     */
    if (!tq_empty(&io_plugins) || ISSET(details->flags, CD_USE_PTY)) {
	log_io = TRUE;
	if (!ISSET(details->flags, CD_BACKGROUND)) {
	    sudo_debug(8, "allocate pty for I/O logging");
	    pty_setup(details->euid);
	}
    }

    /*
     * We communicate with the child over a bi-directional pair of sockets.
     * Parent sends signal info to child and child sends back wait status.
     */
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sv) == -1)
	error(1, "cannot create sockets");

    /*
     * We use a pipe to atomically handle signal notification within
     * the select() loop.
     */
    if (pipe_nonblock(signal_pipe) != 0)
	error(1, "cannot create pipe");

    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);

    /*
     * Signals for forward to the child process (excluding SIGALRM and SIGCHLD).
     * Note: HP-UX select() will not be interrupted if SA_RESTART set.
     */
    sa.sa_flags = SA_INTERRUPT; /* do not restart syscalls */
    sa.sa_handler = handler;
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    /* Max fd we will be selecting on. */
    maxfd = MAX(sv[0], signal_pipe[0]);

    /*
     * Child will run the command in the pty, parent will pass data
     * to and from pty.  Adjusts maxfd as needed.
     */
    if (log_io)
	child = fork_pty(details, argv, envp, sv, &maxfd);
    else
	child = fork_cmnd(details, argv, envp, sv);
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
    fdsr = (fd_set *)emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    fdsw = (fd_set *)emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    for (;;) {
	zero_bytes(fdsw, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));
	zero_bytes(fdsr, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));

	FD_SET(signal_pipe[0], fdsr);
	FD_SET(sv[0], fdsr);
	if (!tq_empty(&sigfwd_list))
	    FD_SET(sv[0], fdsw);
	if (log_io)
	    fd_set_iobs(fdsr, fdsw); /* XXX - better name */
	nready = select(maxfd + 1, fdsr, fdsw, NULL, NULL);
	if (nready == -1) {
	    if (errno == EINTR)
		continue;
	    error(1, "select failed");
	}
	if (FD_ISSET(sv[0], fdsw)) {
	    forward_signals(sv[0]);
	}
	if (FD_ISSET(signal_pipe[0], fdsr)) {
	    n = handle_signals(signal_pipe[0], child, log_io, cstat);
	    if (n == 0) {
		/* Child has exited, cstat is set, we are done. */
		goto done;
	    }
	    if (n == -1) {
		if (errno == EAGAIN || errno == EINTR)
		    continue;
		/* Error reading signal_pipe[0], should not happen. */
		break;
	    }
	    /* Restart event loop so signals get sent to child immediately. */
	    continue;
	}
	if (FD_ISSET(sv[0], fdsr)) {
	    /* read child status */
	    n = recv(sv[0], cstat, sizeof(*cstat), 0);
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		/*
		 * If not logging I/O we will receive ECONNRESET when
		 * the command is executed.  It is safe to ignore this.
		 */
		if (log_io && errno != EAGAIN) {
		    cstat->type = CMD_ERRNO;
		    cstat->val = errno;
		    break;
		}
	    }
	    if (cstat->type == CMD_WSTATUS) {
		if (WIFSTOPPED(cstat->val)) {
		    /* Suspend parent and tell child how to resume on return. */
		    sudo_debug(8, "child stopped, suspending parent");
		    n = suspend_parent(WSTOPSIG(cstat->val));
		    schedule_signal(n);
		    continue;
		} else {
		    /* Child exited or was killed, either way we are done. */
		    break;
		}
	    } else if (cstat->type == CMD_ERRNO) {
		/* Child was unable to execute command or broken pipe. */
		break;
	    }
	}

	if (perform_io(fdsr, fdsw, cstat) != 0) {
	    /* I/O error, kill child if still alive and finish. */
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
	    warningx("unable to restore tty label");
    }
#endif

done:
    efree(fdsr);
    efree(fdsw);
    while (!tq_empty(&sigfwd_list)) {
	struct sigforward *sigfwd = tq_first(&sigfwd_list);
	tq_remove(&sigfwd_list, sigfwd);
	efree(sigfwd);
    }

    return cstat->type == CMD_ERRNO ? -1 : 0;
}

/*
 * Read signals on fd written to by handler().
 * Returns -1 on error (possibly non-fatal), 0 on child exit, else 1.
 */
static int
handle_signals(int fd, pid_t child, int log_io, struct command_status *cstat)
{
    unsigned char signo;
    ssize_t nread;
    int status;
    pid_t pid;

    for (;;) {
	/* read signal pipe */
	nread = read(signal_pipe[0], &signo, sizeof(signo));
	if (nread <= 0) {
	    /* It should not be possible to get EOF but just in case. */
	    if (nread == 0)
		errno = ECONNRESET;
	    if (errno != EINTR && errno != EAGAIN) {
		sudo_debug(9, "error reading signal pipe %s", strerror(errno));
		cstat->type = CMD_ERRNO;
		cstat->val = errno;
	    }
	    return -1;
	}
	sudo_debug(9, "received signal %d", signo);
	if (signo == SIGCHLD) {
	    /*
	     * If logging I/O, child is the intermediate process,
	     * otherwise it is the command itself.
	     */
	    do {
		pid = waitpid(child, &status, WUNTRACED|WNOHANG);
	    } while (pid == -1 && errno == EINTR);
	    if (pid == child) {
		/* If not logging I/O and child has exited we are done. */
		if (!log_io) {
		    if (WIFSTOPPED(status)) {
			/* Child may not have privs to suspend us itself. */
			if (kill(getpid(), WSTOPSIG(status)) != 0)
			    warning("kill(%d, %d)", getpid(), WSTOPSIG(status));
		    } else {
			/* Child has exited, we are done. */
			cstat->type = CMD_WSTATUS;
			cstat->val = status;
			return 0;
		    }
		}
		/* Else we get ECONNRESET on sv[0] if child dies. */
	    }
	} else {
	    if (log_io) {
		/* Schedule signo to be forwared to the child. */
		schedule_signal(signo);
	    } else {
		/* Nothing listening on sv[0], send directly. */
		if (signo == SIGALRM) {
		    terminate_child(child, FALSE);
		} else {
		    if (signo == SIGCONT) {
			/*
			 * Before continuing the child, make it the foreground
			 * pgrp if possible.  Fixes resuming a shell.
			 */
			int fd = open(_PATH_TTY, O_RDWR|O_NOCTTY, 0);
			if (fd != -1) {
			    if (tcgetpgrp(fd) == getpgrp())
				(void)tcsetpgrp(fd, child);
			    close(fd);
			}
		    }
		    if (kill(child, signo) != 0)
			warning("kill(%d, %d)", child, signo);
		}
	    }
	}
    }
    return 1;
}

/*
 * Forward signals in sigfwd_list to child listening on fd.
 */
static void
forward_signals(int sock)
{
    struct sigforward *sigfwd;
    struct command_status cstat;
    ssize_t nsent;

    while (!tq_empty(&sigfwd_list)) {
	sigfwd = tq_first(&sigfwd_list);
	sudo_debug(9, "sending signal %d to child over backchannel",
	    sigfwd->signo);
	cstat.type = CMD_SIGNO;
	cstat.val = sigfwd->signo;
	do {
	    nsent = send(sock, &cstat, sizeof(cstat), 0);
	} while (nsent == -1 && errno == EINTR);
	tq_remove(&sigfwd_list, sigfwd);
	efree(sigfwd);
	if (nsent != sizeof(cstat)) {
	    if (errno == EPIPE) {
		/* Other end of socket gone, empty out sigfwd_list. */
		while (!tq_empty(&sigfwd_list)) {
		    sigfwd = tq_first(&sigfwd_list);
		    tq_remove(&sigfwd_list, sigfwd);
		    efree(sigfwd);
		}
	    }
	    break;
	}
    }
}

/*
 * Schedule a signal to be forwared.
 */
static void
schedule_signal(int signo)
{
    struct sigforward *sigfwd;

    sigfwd = emalloc(sizeof(*sigfwd));
    sigfwd->prev = sigfwd;
    sigfwd->next = NULL;
    sigfwd->signo = signo;
    tq_append(&sigfwd_list, sigfwd);
}

/*
 * Generic handler for signals passed from parent -> child.
 * The other end of signal_pipe is checked in the main event loop.
 */
void
handler(int s)
{
    unsigned char signo = (unsigned char)s;

    /*
     * The pipe is non-blocking, if we overflow the kernel's pipe
     * buffer we drop the signal.  This is not a problem in practice.
     */
    if (write(signal_pipe[1], &signo, sizeof(signo)) == -1)
	/* shut up glibc */;
}

/*
 * Open a pipe and make both ends non-blocking.
 * Returns 0 on success and -1 on error.
 */
int
pipe_nonblock(int fds[2])
{
    int flags, rval;

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

    return rval;
}
