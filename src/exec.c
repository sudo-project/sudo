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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#ifdef HAVE_TERMIOS_H
# include <termios.h>
#else
# include <termio.h>
#endif /* HAVE_TERMIOS_H */
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
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#ifdef HAVE_SELINUX
# include <selinux/selinux.h>
#endif

#if !defined(NSIG)
# if defined(_NSIG)
#  define NSIG _NSIG
# elif defined(__NSIG)
#  define NSIG __NSIG
# else
#  define NSIG 64
# endif
#endif

#include "sudo.h" /* XXX? */
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

#define SFD_STDIN	0
#define SFD_STDOUT	1
#define SFD_STDERR	2
#define SFD_MASTER	3
#define SFD_SLAVE	4
#define SFD_USERTTY	5

#define TERM_COOKED	0
#define TERM_RAW	1

/* Compatibility with older tty systems. */
#if !defined(TIOCGSIZE) && defined(TIOCGWINSZ)
# define TIOCGSIZE	TIOCGWINSZ
# define TIOCSSIZE	TIOCSWINSZ
# define ttysize	winsize
# define ts_cols	ws_col
#endif

struct io_buffer {
    struct io_buffer *next;
    int len; /* buffer length (how much produced) */
    int off; /* write position (how much already consumed) */
    int rfd;  /* reader (producer) */
    int wfd; /* writer (consumer) */
    int (*action)(char *buf, unsigned int len);
    char buf[16 * 1024];
};

static int io_fds[6] = { -1, -1, -1, -1, -1, -1};
static int pipeline = FALSE;

static sig_atomic_t recvsig[NSIG];

static sigset_t ttyblock;

static pid_t ppgrp, child;
static int foreground;
static int ttymode = TERM_COOKED;
static int tty_initialized;

static char slavename[PATH_MAX];

static int suspend_parent(int signo, struct io_buffer *iobufs);
static void flush_output(struct io_buffer *iobufs);
static int perform_io(struct io_buffer *iobufs, fd_set *fdsr, fd_set *fdsw);
static void handler(int s);
static int my_execve(const char *path, char *const argv[],
    char *const envp[]);
static int exec_monitor(struct command_details *details, char *argv[],
    char *envp[], int, int);
static void exec_pty(struct command_details *detail, char *argv[],
    char *envp[], int);
static void sigwinch(int s);
static void sync_ttysize(int src, int dst);
static void deliver_signal(pid_t pid, int signo);
static int safe_close(int fd);

extern struct user_details user_details; /* XXX need tty name for SELinux */

static void
pty_setup(uid_t uid)
{
    io_fds[SFD_USERTTY] = open(_PATH_TTY, O_RDWR|O_NOCTTY, 0);
    if (io_fds[SFD_USERTTY] != -1) {
	if (!get_pty(&io_fds[SFD_MASTER], &io_fds[SFD_SLAVE],
	    slavename, sizeof(slavename), uid))
	    error(1, "Can't get pty");
    }
}

/*
 * Cleanup hook for error()/errorx()
 */
void
cleanup(int gotsignal)
{
    if (!tq_empty(&io_plugins))
	term_restore(io_fds[SFD_USERTTY], 0);
}

/* Call I/O plugin tty input log method. */
static int
log_ttyin(char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    int rval = TRUE;

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_ttyin) {
	    if (!plugin->u.io->log_ttyin(buf, n)) {
	    	rval = FALSE;
		break;
	    }
	}
    }

    sigprocmask(SIG_SETMASK, &omask, NULL);
    return rval;
}

/* Call I/O plugin stdin log method. */
static int
log_stdin(char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    int rval = TRUE;

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_stdin) {
	    if (!plugin->u.io->log_stdin(buf, n)) {
	    	rval = FALSE;
		break;
	    }
	}
    }

    sigprocmask(SIG_SETMASK, &omask, NULL);
    return rval;
}

/* Call I/O plugin tty output log method. */
static int
log_ttyout(char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    int rval = TRUE;

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_ttyout) {
	    if (!plugin->u.io->log_ttyout(buf, n)) {
	    	rval = FALSE;
		break;
	    }
	}
    }

    sigprocmask(SIG_SETMASK, &omask, NULL);
    return rval;
}

/* Call I/O plugin stdout log method. */
static int
log_stdout(char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    int rval = TRUE;

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_stdout) {
	    if (!plugin->u.io->log_stdout(buf, n)) {
	    	rval = FALSE;
		break;
	    }
	}
    }

    sigprocmask(SIG_SETMASK, &omask, NULL);
    return rval;
}

/* Call I/O plugin stderr log method. */
static int
log_stderr(char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    int rval = TRUE;

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_stderr) {
	    if (!plugin->u.io->log_stderr(buf, n)) {
	    	rval = FALSE;
		break;
	    }
	}
    }

    sigprocmask(SIG_SETMASK, &omask, NULL);
    return rval;
}

static void
check_foreground(void)
{
    if (io_fds[SFD_USERTTY] != -1) {
	foreground = tcgetpgrp(io_fds[SFD_USERTTY]) == ppgrp;
	if (foreground && !tty_initialized) {
	    if (term_copy(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE])) {
		tty_initialized = 1;
		sync_ttysize(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE]);
	    }
	}
    }
}

/*
 * Suspend sudo if the underlying command is suspended.
 * Returns SIGUSR1 if the child should be resume in foreground else SIGUSR2.
 */
static int
suspend_parent(int signo, struct io_buffer *iobufs)
{
    sigaction_t sa, osa;
    int n, oldmode = ttymode, rval = 0;

    switch (signo) {
    case SIGTTOU:
    case SIGTTIN:
	/*
	 * If we are the foreground process, just resume the child.
	 * Otherwise, re-send the signal with the handler disabled.
	 */
	if (!foreground)
	    check_foreground();
	if (foreground) {
	    if (ttymode != TERM_RAW) {
		do {
		    n = term_raw(io_fds[SFD_USERTTY], 0);
		} while (!n && errno == EINTR);
		ttymode = TERM_RAW;
	    }
	    rval = SIGUSR1; /* resume child in foreground */
	    break;
	}
	ttymode = TERM_RAW;
	/* FALLTHROUGH */
    case SIGSTOP:
    case SIGTSTP:
	/* Flush any remaining output before suspending. */
	flush_output(iobufs);

	/* Restore original tty mode before suspending. */
	if (oldmode != TERM_COOKED) {
	    do {
		n = term_restore(io_fds[SFD_USERTTY], 0);
	    } while (!n && errno == EINTR);
	}

	/* Suspend self and continue child when we resume. */
	sa.sa_handler = SIG_DFL;
	sigaction(signo, &sa, &osa);
	sudo_debug(8, "kill parent %d", signo);
	killpg(ppgrp, signo);

	/* Check foreground/background status on resume. */
	check_foreground();

	/*
	 * Only modify term if we are foreground process and either
	 * the old tty mode was not cooked or child got SIGTT{IN,OU}
	 */
	sudo_debug(8, "parent is in %sground, ttymode %d -> %d",
	    foreground ? "fore" : "back", oldmode, ttymode);

	if (ttymode != TERM_COOKED) {
	    if (foreground) {
		/* Set raw mode. */
		do {
		    n = term_raw(io_fds[SFD_USERTTY], 0);
		} while (!n && errno == EINTR);
	    } else {
		/* Background process, no access to tty. */
		ttymode = TERM_COOKED;
	    }
	}

	sigaction(signo, &osa, NULL);
	rval = ttymode == TERM_RAW ? SIGUSR1 : SIGUSR2;
	break;
    }

    return(rval);
}

/*
 * Like execve(2) but falls back to running through /bin/sh
 * ala execvp(3) if we get ENOEXEC.
 */
static int
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

static void
terminate_child(pid_t pid, int use_pgrp)
{
    /*
     * Kill child with increasing urgency.
     * Note that SIGCHLD will interrupt the sleep()
     */
    if (use_pgrp) {
	killpg(pid, SIGHUP);
	killpg(pid, SIGTERM);
	sleep(2);
	killpg(pid, SIGKILL);
    } else {
	kill(pid, SIGHUP);
	kill(pid, SIGTERM);
	sleep(2);
	kill(pid, SIGKILL);
    }
}

static struct io_buffer *
io_buf_new(int rfd, int wfd, int (*action)(char *, unsigned int),
    struct io_buffer *head)
{
    struct io_buffer *iob;

    iob = emalloc(sizeof(*iob));
    zero_bytes(iob, sizeof(*iob));
    iob->rfd = rfd;
    iob->wfd = wfd;
    iob->action = action;
    iob->next = head;
    return iob;
}

/*
 * Read/write iobufs depending on fdsr and fdsw.
 * Returns the number of errors.
 */
static int
perform_io(struct io_buffer *iobufs, fd_set *fdsr, fd_set *fdsw)
{
    struct io_buffer *iob;
    int n, errors = 0;

    for (iob = iobufs; iob; iob = iob->next) {
	if (iob->rfd != -1 && FD_ISSET(iob->rfd, fdsr)) {
	    do {
		n = read(iob->rfd, iob->buf + iob->len,
		    sizeof(iob->buf) - iob->len);
	    } while (n == -1 && errno == EINTR);
	    if (n == -1) {
		if (errno != EAGAIN)
		    break;
	    } else if (n == 0) {
		/* got EOF */
		safe_close(iob->rfd);
		iob->rfd = -1;
	    } else {
		if (!iob->action(iob->buf + iob->len, n))
		    terminate_child(child, TRUE);
		iob->len += n;
	    }
	}
	if (iob->wfd != -1 && FD_ISSET(iob->wfd, fdsw)) {
	    do {
		n = write(iob->wfd, iob->buf + iob->off,
		    iob->len - iob->off);
	    } while (n == -1 && errno == EINTR);
	    if (n == -1) {
		if (errno == EPIPE) {
		    /* other end of pipe closed */
		    if (iob->rfd != -1) {
			safe_close(iob->rfd);
			iob->rfd = -1;
		    }
		    safe_close(iob->wfd);
		    iob->wfd = -1;
		    continue;
		}
		if (errno != EAGAIN)
		    errors++;
	    } else {
		iob->off += n;
	    }
	}
    }
    return errors;
}

/*
 * This is a little bit tricky due to how POSIX job control works and
 * we fact that we have two different controlling terminals to deal with.
 * There are three processes:
 *  1) parent, which forks a child and does all the I/O passing.
 *     Handles job control signals send by its child to bridge the
 *     two sessions (and ttys).
 *  2) child, creates a new session so it can receive notification of
 *     tty stop signals (SIGTSTP, SIGTTIN, SIGTTOU).  Waits for the
 *     command to stop or die and passes back tty stop signals to parent
 *     so job control works in the user's shell.
 *  3) grandchild, executes the actual command with the pty slave as its
 *     controlling tty, belongs to child's session but has its own pgrp.
 */
int
sudo_execve(struct command_details *details, char *argv[], char *envp[],
    struct command_status *cstat)
{
    sigaction_t sa;
    struct io_buffer *iob, *iobufs = NULL;
    int n, nready;
    int io_pipe[3][2], sv[2];
    fd_set *fdsr, *fdsw;
    int rbac_enabled = 0;
    int log_io, maxfd, status;

    cstat->type = CMD_INVALID;

    log_io = !tq_empty(&io_plugins);
    if (log_io) {
	sudo_debug(8, "allocate pty for I/O logging");
	pty_setup(details->euid);
    }

#ifdef HAVE_SELINUX
    rbac_enabled = is_selinux_enabled() > 0 && details->selinux_role != NULL;
    if (rbac_enabled) {
	/* Must do SELinux setup before changing uid. */
	selinux_setup(details->selinux_role, details->selinux_type,
	    log_io ? slavename : user_details.tty, io_fds[SFD_SLAVE]);
    }
#endif

    ppgrp = getpgrp(); /* parent's pgrp, so child can signal us */

    /*
     * We communicate with the child over a bi-directional pipe.
     * Parent sends signal info to child and child sends back wait status.
     */
    if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sv) != 0)
	error(1, "cannot create sockets");

    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);

    /* Note: HP-UX select() will not be interrupted if SA_RESTART set */
    sa.sa_flags = 0; /* do not restart syscalls */
    sa.sa_handler = handler;
    sigaction(SIGALRM, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if (log_io) {
	if (io_fds[SFD_USERTTY] != -1) {
	    sa.sa_flags = SA_RESTART;
	    sa.sa_handler = sigwinch;
	    sigaction(SIGWINCH, &sa, NULL);
	}

	/* So we can block tty-generated signals */
	sigemptyset(&ttyblock);
	sigaddset(&ttyblock, SIGINT);
	sigaddset(&ttyblock, SIGQUIT);
	sigaddset(&ttyblock, SIGTSTP);
	sigaddset(&ttyblock, SIGTTIN);
	sigaddset(&ttyblock, SIGTTOU);

	/*
	 * Setup stdin/stdout/stderr for child, to be duped after forking.
	 */
	io_fds[SFD_STDIN] = io_fds[SFD_SLAVE];
	io_fds[SFD_STDOUT] = io_fds[SFD_SLAVE];
	io_fds[SFD_STDERR] = io_fds[SFD_SLAVE];

	/* Copy /dev/tty -> pty master */
	if (io_fds[SFD_USERTTY] != -1) {
	    iobufs = io_buf_new(io_fds[SFD_USERTTY], io_fds[SFD_MASTER],
		log_ttyin, iobufs);

	    /* Copy pty master -> /dev/tty */
	    iobufs = io_buf_new(io_fds[SFD_MASTER], io_fds[SFD_USERTTY],
		log_ttyout, iobufs);

	    /* Are we the foreground process? */
	    foreground = tcgetpgrp(io_fds[SFD_USERTTY]) == ppgrp;
	}

	/*
	 * If either stdin, stdout or stderr is not a tty we use a pipe
	 * to interpose ourselves instead of duping the pty fd.
	 */
	memset(io_pipe, 0, sizeof(io_pipe));
	if (!isatty(STDIN_FILENO)) {
	    pipeline = TRUE;
	    if (pipe(io_pipe[STDIN_FILENO]) != 0)
		error(1, "unable to create pipe");
	    iobufs = io_buf_new(STDIN_FILENO, io_pipe[STDIN_FILENO][1],
		log_stdin, iobufs);
	    io_fds[SFD_STDIN] = io_pipe[STDIN_FILENO][0];
	}
	if (!isatty(STDOUT_FILENO)) {
	    pipeline = TRUE;
	    if (pipe(io_pipe[STDOUT_FILENO]) != 0)
		error(1, "unable to create pipe");
	    iobufs = io_buf_new(io_pipe[STDOUT_FILENO][0], STDOUT_FILENO,
		log_stdout, iobufs);
	    io_fds[SFD_STDOUT] = io_pipe[STDOUT_FILENO][1];
	}
	if (!isatty(STDERR_FILENO)) {
	    if (pipe(io_pipe[STDERR_FILENO]) != 0)
		error(1, "unable to create pipe");
	    iobufs = io_buf_new(io_pipe[STDERR_FILENO][0], STDERR_FILENO,
		log_stderr, iobufs);
	    io_fds[SFD_STDERR] = io_pipe[STDERR_FILENO][1];
	}

	/* Job control signals to relay from parent to child. */
	sa.sa_flags = 0; /* do not restart syscalls */
	sa.sa_handler = handler;
	sigaction(SIGTSTP, &sa, NULL);
#if 0 /* XXX - add these? */
	sigaction(SIGTTIN, &sa, NULL);
	sigaction(SIGTTOU, &sa, NULL);
#endif

	if (foreground) {
	    /* Copy terminal attrs from user tty -> pty slave. */
	    if (term_copy(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE])) {
		tty_initialized = 1;
		sync_ttysize(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE]);
	    }

	    /* Start out in raw mode if we are not part of a pipeline. */
	    if (!pipeline) {
		ttymode = TERM_RAW;
		do {
		    n = term_raw(io_fds[SFD_USERTTY], 0);
		} while (!n && errno == EINTR);
		if (!n)
		    error(1, "Can't set terminal to raw mode");
	    }
	}
    }

    /*
     * Child will run the command in the pty, parent will pass data
     * to and from pty.
     */
    child = fork();
    switch (child) {
    case -1:
	error(1, "fork");
	break;
    case 0:
	/* child */
	close(sv[0]);
	fcntl(sv[1], F_SETFD, FD_CLOEXEC);
	if (exec_setup(details) == TRUE) {
	    /* headed for execve() */
	    if (log_io) {
		/* Close the other end of the stdin/stdout/stderr pipes. */
		if (io_pipe[STDIN_FILENO][1])
		    close(io_pipe[STDIN_FILENO][1]);
		if (io_pipe[STDOUT_FILENO][0])
		    close(io_pipe[STDOUT_FILENO][0]);
		if (io_pipe[STDERR_FILENO][0])
		    close(io_pipe[STDERR_FILENO][0]);
		exec_monitor(details, argv, envp, sv[1], rbac_enabled);
	    } else {
		if (details->closefrom >= 0)
		    closefrom(details->closefrom);
#ifdef HAVE_SELINUX
		if (rbac_enabled)
		    selinux_execve(details->command, argv, envp);
		else
#endif
		    my_execve(details->command, argv, envp);
	    }
	}
	cstat->type = CMD_ERRNO;
	cstat->val = errno;
	send(sv[1], cstat, sizeof(*cstat), 0);
	_exit(1);
    }
    close(sv[1]);

    /* Set command timeout if specified. */
    if (ISSET(details->flags, CD_SET_TIMEOUT))
	alarm(details->timeout);

    /* Max fd we will be selecting on. */
    maxfd = sv[0];

    if (log_io) {
	/* Close the other end of the stdin/stdout/stderr pipes. */
	if (io_pipe[STDIN_FILENO][0])
	    close(io_pipe[STDIN_FILENO][0]);
	if (io_pipe[STDOUT_FILENO][1])
	    close(io_pipe[STDOUT_FILENO][1]);
	if (io_pipe[STDERR_FILENO][1])
	    close(io_pipe[STDERR_FILENO][1]);

	for (iob = iobufs; iob; iob = iob->next) {
	    /* Determine maxfd */
	    if (iob->rfd > maxfd)
		maxfd = iob->rfd;
	    if (iob->wfd > maxfd)
		maxfd = iob->wfd;

	    /* Set non-blocking mode. */
	    n = fcntl(iob->rfd, F_GETFL, 0);
	    if (n != -1 && !ISSET(n, O_NONBLOCK))
		(void) fcntl(iob->rfd, F_SETFL, n | O_NONBLOCK);
	    n = fcntl(iob->wfd, F_GETFL, 0);
	    if (n != -1 && !ISSET(n, O_NONBLOCK))
		(void) fcntl(iob->wfd, F_SETFL, n | O_NONBLOCK);
	}
    }

    /*
     * In the event loop we pass input from user tty to master
     * and pass output from master to stdout and IO plugin.
     */
    fdsr = (fd_set *)emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    fdsw = (fd_set *)emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    for (;;) {
	if (recvsig[SIGCHLD]) {
	    pid_t pid;

	    /*
	     * If logging I/O, child is the intermediate process,
	     * otherwise it is the command itself.
	     */
	    recvsig[SIGCHLD] = FALSE;
	    do {
		pid = waitpid(child, &status, WNOHANG);
	    } while (pid == -1 && errno == EINTR);
	    if (pid == child) {
		/* If not logging I/O and child has exited we are done. */
		if (!log_io) {
		    cstat->type = CMD_WSTATUS;
		    cstat->val = status;
		    return 0;
		}
	    }
	}

	zero_bytes(fdsw, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));
	zero_bytes(fdsr, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));

	FD_SET(sv[0], fdsr);
	for (iob = iobufs; iob; iob = iob->next) {
	    if (iob->rfd == -1 && iob->wfd == -1)
	    	continue;
	    if (iob->off == iob->len) {
		iob->off = iob->len = 0;
		/* Forward the EOF from reader to writer. */
		if (iob->rfd == -1) {
		    safe_close(iob->wfd);
		    iob->wfd = -1;
		}
	    }
	    /* Don't read/write /dev/tty if we are not in the foreground. */
	    if (iob->rfd != -1 &&
		(ttymode == TERM_RAW || iob->rfd != io_fds[SFD_USERTTY])) {
		if (iob->len != sizeof(iob->buf))
		    FD_SET(iob->rfd, fdsr);
	    }
	    if (iob->wfd != -1 &&
		(foreground || iob->wfd != io_fds[SFD_USERTTY])) {
		if (iob->len > iob->off)
		    FD_SET(iob->wfd, fdsw);
	    }
	}
	for (n = 0; n < NSIG; n++) {
	    if (recvsig[n] && n != SIGCHLD) {
		if (log_io) {
		    FD_SET(sv[0], fdsw);
		    break;
		} else {
		    /* nothing listening on sv[0], send directly */
		    if (n == SIGALRM) {
			terminate_child(child, FALSE);
		    } else {
			kill(child, n);
		    }
		}
	    }
	}

	if (recvsig[SIGCHLD])
	    continue;
	nready = select(maxfd + 1, fdsr, fdsw, NULL, NULL);
	if (nready == -1) {
	    if (errno == EINTR)
		continue;
	    error(1, "select failed");
	}
	if (FD_ISSET(sv[0], fdsr)) {
	    /* read child status */
	    n = recv(sv[0], cstat, sizeof(*cstat), 0);
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		if (log_io && errno != EAGAIN) {
		    /* Did the other end of the pipe go away? */
		    cstat->type = CMD_ERRNO;
		    cstat->val = errno;
		}
		break;
	    }
	    if (cstat->type == CMD_WSTATUS) {
		if (WIFSTOPPED(cstat->val)) {
		    /* Suspend parent and tell child how to resume on return. */
		    sudo_debug(8, "child stopped, suspending parent");
		    n = suspend_parent(WSTOPSIG(cstat->val), iobufs);
		    recvsig[n] = TRUE;
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

	if (FD_ISSET(sv[0], fdsw)) {
	    for (n = 0; n < NSIG; n++) {
		if (!recvsig[n])
		    continue;
		recvsig[n] = FALSE;
		sudo_debug(9, "sending signal %d to child over backchannel", n);
		cstat->type = CMD_SIGNO;
		cstat->val = n;
		do {
		    n = send(sv[0], cstat, sizeof(*cstat), 0);
		} while (n == -1 && errno == EINTR);
		if (n != sizeof(*cstat)) {
		    recvsig[n] = TRUE;
		    break;
		}
	    }
	}
	if (perform_io(iobufs, fdsr, fdsw) != 0)
	    break;
    }

    if (log_io) {
	/* Flush any remaining output (the plugin already got it) */
	if (io_fds[SFD_USERTTY] != -1) {
	    n = fcntl(io_fds[SFD_USERTTY], F_GETFL, 0);
	    if (n != -1 && ISSET(n, O_NONBLOCK)) {
		CLR(n, O_NONBLOCK);
		(void) fcntl(io_fds[SFD_USERTTY], F_SETFL, n);
	    }
	}
	flush_output(iobufs);

	if (io_fds[SFD_USERTTY] != -1) {
	    do {
		n = term_restore(io_fds[SFD_USERTTY], 0);
	    } while (!n && errno == EINTR);
	}

	if (cstat->type == CMD_WSTATUS && WIFSIGNALED(cstat->val)) {
	    int signo = WTERMSIG(cstat->val);
	    if (signo && signo != SIGINT && signo != SIGPIPE) {
		char *reason = strsignal(signo);
		n = io_fds[SFD_USERTTY] != -1 ?
		    io_fds[SFD_USERTTY] : STDOUT_FILENO;
		write(n, reason, strlen(reason));
		if (WCOREDUMP(cstat->val))
		    write(n, " (core dumped)", 14);
		write(n, "\n", 1);
	    }
	}
    }

#ifdef HAVE_SELINUX
    if (rbac_enabled) {
	/* This is probably not needed in log_io mode. */
	if (selinux_restore_tty() != 0)
	    warningx("unable to restore tty label");
    }
#endif

    efree(fdsr);
    efree(fdsw);
    while ((iob = iobufs) != NULL) {
	iobufs = iobufs->next;
	efree(iob);
    }

    return cstat->type == CMD_ERRNO ? -1 : 0;
}

static void
deliver_signal(pid_t pid, int signo)
{
    int status;

    /* Handle signal from parent. */
    sudo_debug(8, "signal %d from parent", signo);
    switch (signo) {
    case SIGKILL:
	_exit(1); /* XXX */
	/* NOTREACHED */
    case SIGPIPE:
    case SIGHUP:
    case SIGTERM:
    case SIGINT:
    case SIGQUIT:
    case SIGTSTP:
	/* relay signal to child */
	killpg(pid, signo);
	break;
    case SIGALRM:
	terminate_child(pid, TRUE);
	break;
    case SIGUSR1:
	/* foreground process, grant it controlling tty. */
	do {
	    status = tcsetpgrp(io_fds[SFD_SLAVE], pid);
	} while (status == -1 && errno == EINTR);
	killpg(pid, SIGCONT);
	break;
    case SIGUSR2:
	/* background process, I take controlling tty. */
	do {
	    status = tcsetpgrp(io_fds[SFD_SLAVE], getpid());
	} while (status == -1 && errno == EINTR);
	killpg(pid, SIGCONT);
	break;
    default:
	warningx("unexpected signal from child: %d", signo);
	break;
    }
}

/*
 * Send status to parent over socketpair.
 * Return value is the same as send(2).
 */
static int
send_status(int fd, struct command_status *cstat)
{
    int n = -1;

    if (cstat->type != CMD_INVALID) {
	do {
	    n = send(fd, cstat, sizeof(*cstat), 0);
	} while (n == -1 && errno == EINTR);
	if (n != sizeof(*cstat)) {
	    sudo_debug(8, "unable to send status to parent: %s", strerror(errno));
	} else {
	    sudo_debug(8, "sent status to parent");
	}
	cstat->type = CMD_INVALID; /* prevent re-sending */
    }
    return n;
}

/*
 * Wait for child status after receiving SIGCHLD.
 * If the child was stopped, the status is send back to the parent.
 * Otherwise, cstat is filled in but not sent.
 * Returns TRUE if child is still alive, else FALSE.
 */
static int
handle_sigchld(int backchannel, struct command_status *cstat)
{
    int status, alive = TRUE;
    pid_t pid;

    /* read child status */
    do {
	pid = waitpid(child, &status, WUNTRACED|WNOHANG);
    } while (pid == -1 && errno == EINTR);
    if (pid == child) {
	if (cstat->type != CMD_ERRNO) {
	    cstat->type = CMD_WSTATUS;
	    cstat->val = status;
	    if (WIFSTOPPED(status)) {
		sudo_debug(8, "command stopped, signal %d",
		    WSTOPSIG(status));
		if (send_status(backchannel, cstat) == -1)
		    return alive; /* XXX */
	    } else if (WIFSIGNALED(status)) {
		sudo_debug(8, "command killed, signal %d",
		    WTERMSIG(status));
	    } else {
		sudo_debug(8, "command exited: %d",
		    WEXITSTATUS(status));
	    }
	}
	if (!WIFSTOPPED(status))
	    alive = FALSE;
    }
    return alive;
}

/*
 * Monitor process that creates a new session with the controlling tty,
 * resets signal handlers and forks a child to call exec_pty().
 * Waits for status changes from the command and relays them to the
 * parent and relays signals from the parent to the command.
 * Returns an error if fork(2) fails, else calls _exit(2).
 */
int
exec_monitor(struct command_details *details, char *argv[], char *envp[],
    int backchannel, int rbac)
{
    struct command_status cstat;
    struct timeval tv;
    fd_set *fdsr;
    sigaction_t sa;
    int errpipe[2], maxfd, n, status;
    int alive = TRUE;

    /* Close unused fds. */
    if (io_fds[SFD_MASTER] != -1)
	close(io_fds[SFD_MASTER]);
    if (io_fds[SFD_USERTTY] != -1)
	close(io_fds[SFD_USERTTY]);

    /* Reset SIGWINCH and SIGALRM. */
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    sigaction(SIGWINCH, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    /* Ignore any SIGTTIN or SIGTTOU we get. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGTTIN, &sa, NULL);
    sigaction(SIGTTOU, &sa, NULL);

    /* Note: HP-UX select() will not be interrupted if SA_RESTART set */
    sa.sa_flags = 0;
    sa.sa_handler = handler;
    sigaction(SIGCHLD, &sa, NULL);

    /*
     * Start a new session with the parent as the session leader
     * and the slave pty as the controlling terminal.
     * This allows us to be notified when the child has been suspended.
     */
#ifdef HAVE_SETSID
    if (setsid() == -1) {
	warning("setsid");
	goto bad;
    }
#else
# ifdef TIOCNOTTY
    n = open(_PATH_TTY, O_RDWR|O_NOCTTY);
    if (n >= 0) {
	/* Disconnect from old controlling tty. */
	if (ioctl(n, TIOCNOTTY, NULL) == -1)
	    warning("cannot disconnect controlling tty");
	close(n);
    }
# endif
    setpgrp(0, 0);
#endif
    if (io_fds[SFD_SLAVE] != -1) {
#ifdef TIOCSCTTY
	if (ioctl(io_fds[SFD_SLAVE], TIOCSCTTY, NULL) != 0)
	    error(1, "unable to set controlling tty");
#else
	/* Set controlling tty by reopening slave. */
	if ((n = open(slavename, O_RDWR)) >= 0)
	    close(n);
#endif
    }

    /*
     * If stdin/stdout is not a tty, start command in the background
     * since it might be part of a pipeline that reads from /dev/tty.
     * In this case, we rely on the command receiving SIGTTOU or SIGTTIN
     * when it needs access to the controlling tty.
     */
    if (pipeline)
	foreground = 0;

    /* Start command and wait for it to stop or exit */
    if (pipe(errpipe) == -1)
	error(1, "unable to create pipe");
    child = fork();
    if (child == -1) {
	warning("Can't fork");
	goto bad;
    }
    if (child == 0) {
	/* We pass errno back to our parent via pipe on exec failure. */
	close(backchannel);
	close(errpipe[0]);
	fcntl(errpipe[1], F_SETFD, FD_CLOEXEC);

	/* setup tty and exec command */
	exec_pty(details, argv, envp, rbac);
	cstat.type = CMD_ERRNO;
	cstat.val = errno;
	write(errpipe[1], &cstat, sizeof(cstat));
	_exit(1);
    }
    close(errpipe[1]);

    /* If any of stdin/stdout/stderr are pipes, close them in parent. */
    if (io_fds[SFD_STDIN] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDIN]);
    if (io_fds[SFD_STDOUT] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDOUT]);
    if (io_fds[SFD_STDERR] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDERR]);

    /*
     * Put child in its own process group.  If we are starting the command
     * in the foreground, assign its pgrp to the tty.
     */
    setpgid(child, child);
    if (foreground) {
	do {
	    status = tcsetpgrp(io_fds[SFD_SLAVE], child);
	} while (status == -1 && errno == EINTR);
    }

    /* Wait for errno on pipe, signal on backchannel or for SIGCHLD */
    maxfd = MAX(errpipe[0], backchannel);
    fdsr = (fd_set *)emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    zero_bytes(fdsr, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));
    zero_bytes(&cstat, sizeof(cstat));
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    for (;;) {
	/* Read child status. */
	if (recvsig[SIGCHLD]) {
	    recvsig[SIGCHLD] = FALSE;
	    alive = handle_sigchld(backchannel, &cstat);
	}

	/* Check for signal on backchannel or errno on errpipe. */
	FD_SET(backchannel, fdsr);
	if (errpipe[0] != -1)
	    FD_SET(errpipe[0], fdsr);
	maxfd = MAX(errpipe[0], backchannel);

	if (recvsig[SIGCHLD])
	    continue;
	/* If command exited we just poll, there may be data on errpipe. */
	n = select(maxfd + 1, fdsr, NULL, NULL, alive ? NULL : &tv);
	if (n <= 0) {
	    if (n == 0)
		goto done;
	    if (errno == EINTR)
		continue;
	    error(1, "select failed");
	}

	if (errpipe[0] != -1 && FD_ISSET(errpipe[0], fdsr)) {
	    /* read errno or EOF from command pipe */
	    n = read(errpipe[0], &cstat, sizeof(cstat));
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		warning("error reading from pipe");
		goto done;
	    }
	    /* Got errno or EOF, either way we are done with errpipe. */
	    FD_CLR(errpipe[0], fdsr);
	    close(errpipe[0]);
	    errpipe[0] = -1;
	}
	if (FD_ISSET(backchannel, fdsr)) {
	    struct command_status cstmp;

	    /* read command from backchannel, should be a signal */
	    n = recv(backchannel, &cstmp, sizeof(cstmp), 0);
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		warning("error reading from socketpair");
		goto done;
	    }
	    if (cstmp.type != CMD_SIGNO) {
		warningx("unexpected reply type on backchannel: %d", cstmp.type);
		continue;
	    }
	    deliver_signal(child, cstmp.val);
	}
    }

done:
    if (alive) {
	/* XXX An error occurred, should send an error back. */
	kill(child, SIGKILL);
    } else {
	/* Send parent status. */
	send_status(backchannel, &cstat);
    }
    _exit(1);

bad:
    return errno;
}

/*
 * Flush any output buffered in iobufs or readable from the fds.
 * Does not read from /dev/tty.
 */
static void
flush_output(struct io_buffer *iobufs)
{
    struct io_buffer *iob;
    struct timeval tv;
    fd_set *fdsr, *fdsw;
    int nready, nwriters, maxfd = -1;

    /* Determine maxfd */
    for (iob = iobufs; iob; iob = iob->next) {
	if (iob->rfd > maxfd)
	    maxfd = iob->rfd;
	if (iob->wfd > maxfd)
	    maxfd = iob->wfd;
    }
    if (maxfd == -1)
	return;

    fdsr = (fd_set *)emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    fdsw = (fd_set *)emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    for (;;) {
	zero_bytes(fdsw, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));
	zero_bytes(fdsr, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));

	nwriters = 0;
	for (iob = iobufs; iob; iob = iob->next) {
	    /* Don't read from /dev/tty while flushing. */
	    if (io_fds[SFD_USERTTY] != -1 && iob->rfd == io_fds[SFD_USERTTY])
		continue;
	    if (iob->rfd == -1 && iob->wfd == -1)
	    	continue;
	    if (iob->off == iob->len) {
		iob->off = iob->len = 0;
		/* Forward the EOF from reader to writer. */
		if (iob->rfd == -1) {
		    safe_close(iob->wfd);
		    iob->wfd = -1;
		}
	    }
	    if (iob->rfd != -1) {
		if (iob->len != sizeof(iob->buf))
		    FD_SET(iob->rfd, fdsr);
	    }
	    if (iob->wfd != -1) {
		if (iob->len > iob->off) {
		    nwriters++;
		    FD_SET(iob->wfd, fdsw);
		}
	    }
	}

	/* Don't sleep in select if there are no buffers that need writing. */
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	nready = select(maxfd + 1, fdsr, fdsw, NULL, nwriters ? NULL : &tv);
	if (nready <= 0) {
	    if (nready == 0)
		break; /* all I/O flushed */
	    if (errno == EINTR)
		continue;
	    error(1, "select failed");
	}
	if (perform_io(iobufs, fdsr, fdsw) != 0)
	    break;
    }
    efree(fdsr);
    efree(fdsw);
}

/*
 * Sets up std{in,out,err} and executes the actual command.
 * Returns only if execve() fails.
 */
static void
exec_pty(struct command_details *details, char *argv[], char *envp[],
    int rbac_enabled)
{
    sigaction_t sa;
    pid_t self = getpid();

    /* Reset signal handlers. */
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTSTP, &sa, NULL);
    sigaction(SIGTTIN, &sa, NULL);
    sigaction(SIGTTOU, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);

    /* Set child process group here too to avoid a race. */
    setpgid(0, self);

    /* Wire up standard fds, note that stdout/stderr may be pipes. */
    dup2(io_fds[SFD_STDIN], STDIN_FILENO);
    dup2(io_fds[SFD_STDOUT], STDOUT_FILENO);
    dup2(io_fds[SFD_STDERR], STDERR_FILENO);

    /* Wait for parent to grant us the tty if we are foreground. */
    if (foreground) {
	while (tcgetpgrp(io_fds[SFD_SLAVE]) != self)
	    ; /* spin */
    }

    /* We have guaranteed that the slave fd is > 2 */
    if (io_fds[SFD_SLAVE] != -1)
	close(io_fds[SFD_SLAVE]);
    if (io_fds[SFD_STDIN] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDIN]);
    if (io_fds[SFD_STDOUT] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDOUT]);
    if (io_fds[SFD_STDERR] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDERR]);

    if (details->closefrom >= 0)
	closefrom(details->closefrom);
#ifdef HAVE_SELINUX
    if (rbac_enabled)
	selinux_execve(details->command, argv, envp);
    else
#endif
	my_execve(details->command, argv, envp);
}

/*
 * Propagates tty size change signals to pty being used by the command.
 */
static void
sync_ttysize(int src, int dst)
{
#ifdef TIOCGSIZE
    struct ttysize tsize;
    pid_t pgrp;

    if (ioctl(src, TIOCGSIZE, &tsize) == 0) {
	    ioctl(dst, TIOCSSIZE, &tsize);
#ifdef TIOCGPGRP
	    if (ioctl(dst, TIOCGPGRP, &pgrp) == 0)
		    killpg(pgrp, SIGWINCH);
#endif
    }
#endif
}

/*
 * Generic handler for signals passed from parent -> child.
 * The recvsig[] array is checked in the main event loop.
 */
static void
handler(int s)
{
    recvsig[s] = TRUE;
}

/*
 * Handler for SIGWINCH in parent.
 */
static void
sigwinch(int s)
{
    int serrno = errno;

    sync_ttysize(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE]);
    errno = serrno;
}

/*
 * Only close the fd if it is not /dev/tty or std{in,out,err}.
 * Return value is the same as send(2).
 */
static int
safe_close(int fd)
{
    /* Avoid closing /dev/tty or std{in,out,err}. */
    if (fd < 3 || fd == io_fds[SFD_USERTTY]) {
	errno = EINVAL;
	return -1;
    }
    return close(fd);
}
