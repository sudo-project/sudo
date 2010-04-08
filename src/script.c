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

#define SFD_MASTER	0
#define SFD_SLAVE	1
#define SFD_USERTTY	2

#define TERM_COOKED	0
#define TERM_CBREAK	1
#define TERM_RAW	2

#if !defined(TIOCGSIZE) && defined(TIOCGWINSZ)
# define TIOCGSIZE	TIOCGWINSZ
# define TIOCSSIZE	TIOCSWINSZ
# define ttysize	winsize
# define ts_cols	ws_col
#endif

struct script_buf {
    int len; /* buffer length (how much read in) */
    int off; /* write position (how much already consumed) */
    char buf[16 * 1024];
};

static int script_fds[3] = { -1, -1, -1 };
static int ttyout;

static sig_atomic_t recvsig[NSIG];
static sig_atomic_t ttymode = TERM_COOKED;
static sig_atomic_t tty_initialized = 0;

static sigset_t ttyblock;

static pid_t ppgrp, child;
static int child_status;
static int foreground;

static char slavename[PATH_MAX];

static int suspend_parent(int signo, struct script_buf *output);
static void flush_output(struct script_buf *output);
static void handler(int s);
static int script_child(const char *path, char *argv[], char *envp[], int, int);
static void script_run(const char *path, char *argv[], char *envp[], int);
static void sigwinch(int s);
static void sync_ttysize(int src, int dst);
static void deliver_signal(pid_t pid, int signo);

/* sudo.c */
extern struct plugin_container_list io_plugins;

void
script_setup(uid_t uid)
{
    script_fds[SFD_USERTTY] = open(_PATH_TTY, O_RDWR|O_NOCTTY, 0);
    if (script_fds[SFD_USERTTY] == -1)
	errorx(1, "tty required for transcript support");

    if (!get_pty(&script_fds[SFD_MASTER], &script_fds[SFD_SLAVE],
	slavename, sizeof(slavename), uid))
	error(1, "Can't get pty");
}

/* Call I/O plugin input method. */
static void
log_input(char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

    tq_foreach_fwd(&io_plugins, plugin) {
	/* XXX - die if return != TRUE */
	if (plugin->u.io->log_input)
	    plugin->u.io->log_input(buf, n);
    }

    sigprocmask(SIG_SETMASK, &omask, NULL);
}

/* Call I/O plugin output method. */
static void
log_output(char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

    tq_foreach_fwd(&io_plugins, plugin) {
	/* XXX - die if return != TRUE */
	if (plugin->u.io->log_output)
	    plugin->u.io->log_output(buf, n);
    }

    sigprocmask(SIG_SETMASK, &omask, NULL);
}

static void
check_foreground(void)
{
    foreground = tcgetpgrp(script_fds[SFD_USERTTY]) == ppgrp;
    if (foreground && !tty_initialized) {
	if (term_copy(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE], ttyout)) {
	    tty_initialized = 1;
	    sync_ttysize(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE]);
	}
    }
}

/*
 * Suspend sudo if the underlying command is suspended.
 * Returns SIGUSR1 if the child should be resume in foreground else SIGUSR2.
 */
static int
suspend_parent(int signo, struct script_buf *output)
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
		    n = term_raw(script_fds[SFD_USERTTY], !ttyout, 0);
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
	/* Flush any remaining output to master tty. */
	flush_output(output);

	/* Restore original tty mode before suspending. */
	if (oldmode != TERM_COOKED) {
	    do {
		n = term_restore(script_fds[SFD_USERTTY], 0);
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
		/* Set raw/cbreak mode. */
		do {
		    n = term_raw(script_fds[SFD_USERTTY], !ttyout,
			ttymode == TERM_CBREAK);
		} while (!n && errno == EINTR);
	    } else {
		/* background process, no access to tty. */
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
 * like execvp(3) if we get ENOEXEC.
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
script_execve(struct command_details *details, char *argv[], char *envp[],
    struct command_status *cstat)
{
    sigaction_t sa;
    struct script_buf input, output;
    int n, nready;
    int sv[2];
    fd_set *fdsr, *fdsw;
    int rbac_enabled = 0;
    int log_io, maxfd;

    cstat->type = 0; /* XXX */

    log_io = !tq_empty(&io_plugins);

#ifdef HAVE_SELINUX
    rbac_enabled = is_selinux_enabled() > 0 && user_role != NULL;
    if (rbac_enabled) {
	selinux_prefork(user_role, user_type, script_fds[SFD_SLAVE]);
	if (log_io) {
	    /* Re-open slave fd after it has been relabeled */
	    close(script_fds[SFD_SLAVE]);
	    script_fds[SFD_SLAVE] = open(slavename, O_RDWR|O_NOCTTY, 0);
	    if (script_fds[SFD_SLAVE] == -1)
	    error(1, "cannot open %s", slavename);
	}
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
    sa.sa_flags = SA_RESTART;

    /* Catch SIGALRM for command timeout */
    sa.sa_handler = handler;
    sigaction(SIGALRM, &sa, NULL);

    /* Ignore SIGPIPE from other end of socketpair. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* Note: HP-UX select() will not be interrupted if SA_RESTART set */
    sa.sa_flags = 0;
    sa.sa_handler = handler;
    sigaction(SIGCHLD, &sa, NULL);

    if (log_io) {
	sa.sa_handler = sigwinch;
	sigaction(SIGWINCH, &sa, NULL);

	/* So we can block tty-generated signals */
	sigemptyset(&ttyblock);
	sigaddset(&ttyblock, SIGINT);
	sigaddset(&ttyblock, SIGQUIT);
	sigaddset(&ttyblock, SIGTSTP);
	sigaddset(&ttyblock, SIGTTIN);
	sigaddset(&ttyblock, SIGTTOU);

	/* Are we the foreground process? */
	foreground = tcgetpgrp(script_fds[SFD_USERTTY]) == ppgrp;

	/* If stdout is not a tty we handle post-processing differently. */
	ttyout = isatty(STDOUT_FILENO);

	/* Job control signals to relay from parent to child. */
	sa.sa_flags = 0; /* do not restart syscalls */
	sa.sa_handler = handler;
	sigaction(SIGTSTP, &sa, NULL);
#if 0 /* XXX - keep these? */
	sigaction(SIGTTIN, &sa, NULL);
	sigaction(SIGTTOU, &sa, NULL);
#endif

	if (foreground) {
	    /* Copy terminal attrs from user tty -> pty slave. */
	    if (term_copy(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE], ttyout)) {
		tty_initialized = 1;
		sync_ttysize(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE]);
	    }

	    /* Start out in raw mode is stdout is a tty. */
	    ttymode = ttyout ? TERM_RAW : TERM_CBREAK;
	    do {
		n = term_raw(script_fds[SFD_USERTTY], !ttyout,
		    ttymode == TERM_CBREAK);
	    } while (!n && errno == EINTR);
	    if (!n)
		error(1, "Can't set terminal to raw mode");
	}
    }

    /* Non-job control signals to relay from parent to child. */
    sa.sa_flags = 0; /* do not restart syscalls */
    sa.sa_handler = handler;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);

    /* Set command timeout if specified. */
    if (ISSET(details->flags, CD_SET_TIMEOUT))
	    alarm(details->timeout);

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
	if (exec_setup(details) == 0) {
	    /* headed for execve() */
	    if (log_io)
		script_child(details->command, argv, envp, sv[1], rbac_enabled);
	    else {
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

    /* Max fd we will be selecting on. */
    maxfd = sv[0];

    if (log_io) {
	if (maxfd < script_fds[SFD_MASTER])
	    maxfd = script_fds[SFD_MASTER];
	if (maxfd < script_fds[SFD_USERTTY])
	    maxfd = script_fds[SFD_USERTTY];

	n = fcntl(script_fds[SFD_MASTER], F_GETFL, 0);
	if (n != -1) {
	    n |= O_NONBLOCK;
	    (void) fcntl(script_fds[SFD_MASTER], F_SETFL, n);
	}
	n = fcntl(script_fds[SFD_USERTTY], F_GETFL, 0);
	if (n != -1) {
	    n |= O_NONBLOCK;
	    (void) fcntl(script_fds[SFD_USERTTY], F_SETFL, n);
	}
	n = fcntl(STDOUT_FILENO, F_GETFL, 0);
	if (n != -1) {
	    n |= O_NONBLOCK;
	    (void) fcntl(STDOUT_FILENO, F_SETFL, n);
	}
    }

    /*
     * In the event loop we pass input from user tty to master
     * and pass output from master to stdout and IO plugin.
     */
    fdsr = (fd_set *)emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    fdsw = (fd_set *)emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    zero_bytes(&input, sizeof(input));
    zero_bytes(&output, sizeof(output));
    for (;;) {
	/* Wait for children as needed. */
	if (recvsig[SIGCHLD]) {
	    pid_t pid;
	    int flags = WNOHANG;

	    recvsig[SIGCHLD] = FALSE;
	    if (log_io)
		flags |= WUNTRACED;
	    do {
		pid = waitpid(child, &child_status, flags);
	    } while (pid == -1 && errno == EINTR);
	    if (pid == child) {
		/*
		 * If there is no I/O logger we are done.  Otherwise,
		 * we wait for ECONNRESET or EPIPE from the socketpair.
		 */
		if (!log_io)
		    recvsig[SIGCHLD] = TRUE; /* XXX - hacky, see below */
		else if (WIFSTOPPED(child_status))
		    recvsig[WSTOPSIG(child_status)] = TRUE;
	    }
	}

	/* If not logging I/O and child has exited we are done. */
	if (!log_io && recvsig[SIGCHLD]) {
	    cstat->type = CMD_WSTATUS;
	    cstat->val = child_status;
	    break;
	}

	zero_bytes(fdsw, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));
	zero_bytes(fdsr, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));

	if (log_io) {
	    if (input.off == input.len)
		input.off = input.len = 0;
	    if (output.off == output.len)
		output.off = output.len = 0;

	    if (ttymode == TERM_RAW && input.len != sizeof(input.buf))
		FD_SET(script_fds[SFD_USERTTY], fdsr);
	    if (output.len != sizeof(output.buf))
		FD_SET(script_fds[SFD_MASTER], fdsr);
	    if (output.len > output.off)
		FD_SET(STDOUT_FILENO, fdsw);
	    if (input.len > input.off)
		FD_SET(script_fds[SFD_MASTER], fdsw);
	}
	FD_SET(sv[0], fdsr);
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
	    }
	    if (cstat->type == CMD_WSTATUS) {
		if (WIFSTOPPED(cstat->val)) {
		    /* Suspend parent and tell child how to resume on return. */
		    sudo_debug(8, "child stopped, suspending parent");
		    n = suspend_parent(WSTOPSIG(cstat->val), &output);
		    recvsig[n] = TRUE;
		    /* XXX - write sig immediately? */
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
	    /* XXX - we rely on child to be suspended before we suspend ourselves */
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
	if (!log_io)
	    continue;

	if (FD_ISSET(script_fds[SFD_USERTTY], fdsr)) {
	    n = read(script_fds[SFD_USERTTY], input.buf + input.len,
		sizeof(input.buf) - input.len);
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		if (errno != EAGAIN)
		    break;
	    } else {
		if (n == 0)
		    break; /* got EOF */
		log_input(input.buf + input.len, n);
		input.len += n;
	    }
	}
	if (FD_ISSET(script_fds[SFD_MASTER], fdsw)) {
	    n = write(script_fds[SFD_MASTER], input.buf + input.off,
		input.len - input.off);
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		if (errno != EAGAIN)
		    break;
	    } else {
		input.off += n;
	    }
	}
	if (FD_ISSET(script_fds[SFD_MASTER], fdsr)) {
	    n = read(script_fds[SFD_MASTER], output.buf + output.len,
		sizeof(output.buf) - output.len);
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		if (errno != EAGAIN)
		    break;
	    } else {
		if (n == 0)
		    break; /* got EOF */
		log_output(output.buf + output.len, n);
		output.len += n;
	    }
	}
	if (FD_ISSET(STDOUT_FILENO, fdsw)) {
	    n = write(STDOUT_FILENO, output.buf + output.off,
		output.len - output.off);
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		if (errno != EAGAIN)
		    break;
	    } else {
		output.off += n;
	    }
	}
    }

    if (log_io) {
	/* Flush any remaining output to stdout (plugin already got it) */
	n = fcntl(STDOUT_FILENO, F_GETFL, 0);
	if (n != -1) {
	    n &= ~O_NONBLOCK;
	    (void) fcntl(STDOUT_FILENO, F_SETFL, n);
	}
	flush_output(&output);

	if (cstat->type == CMD_WSTATUS && WIFSIGNALED(cstat->val)) {
	    int signo = WTERMSIG(cstat->val);
	    if (signo && signo != SIGINT && signo != SIGPIPE) {
		char *reason = strsignal(signo);
		write(STDOUT_FILENO, reason, strlen(reason));
		if (WCOREDUMP(cstat->val))
		    write(STDOUT_FILENO, " (core dumped)", 14);
		write(STDOUT_FILENO, "\n", 1);
	    }
	}
	do {
	    n = term_restore(script_fds[SFD_USERTTY], 0);
	} while (!n && errno == EINTR);
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
    case SIGHUP:
    case SIGTERM:
    case SIGINT:
    case SIGQUIT:
    case SIGTSTP:
	/* relay signal to child */
	killpg(pid, signo);
	break;
    case SIGALRM:
	terminate_child(child, TRUE);
	break;
    case SIGUSR1:
	/* foreground process, grant it controlling tty. */
	do {
	    status = tcsetpgrp(script_fds[SFD_SLAVE], pid);
	} while (status == -1 && errno == EINTR);
	killpg(pid, SIGCONT);
	break;
    case SIGUSR2:
	/* background process, I take controlling tty. */
	do {
	    status = tcsetpgrp(script_fds[SFD_SLAVE], getpid());
	} while (status == -1 && errno == EINTR);
	killpg(pid, SIGCONT);
	break;
    default:
	warningx("unexpected signal from child: %d", signo);
	break;
    }
}

int
script_child(const char *path, char *argv[], char *envp[], int backchannel, int rbac)
{
    struct command_status cstat;
    fd_set *fdsr;
    sigaction_t sa;
    pid_t pid;
    int n, status;

    /* Close unused fds. */
    close(script_fds[SFD_MASTER]);
    close(script_fds[SFD_USERTTY]);

    /* Reset signal handlers. */
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    sigaction(SIGWINCH, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    /* Ignore any SIGTT{IN,OU} or SIGPIPE we get. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
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
#ifdef TIOCSCTTY
    if (ioctl(script_fds[SFD_SLAVE], TIOCSCTTY, NULL) != 0)
	error(1, "unable to set controlling tty");
#else
    /* Set controlling tty by reopening slave. */
    if ((n = open(slavename, O_RDWR)) >= 0)
	close(n);
#endif

    if (foreground && !ttyout)
	foreground = 0;

    /* Start command and wait for it to stop or exit */
    /* XXX - use details->timeout */
    child = fork();
    if (child == -1) {
	warning("Can't fork");
	goto bad;
    }
    if (child == 0) {
	/* Reset signal handlers. */
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

	/* setup tty and exec command */
	script_run(path, argv, envp, rbac);
	warning("unable to execute %s", path); /* XXX - leave this to plugin? */
	goto bad;
    }

    /*
     * Put child in its own process group.  If we are starting the command
     * in the foreground, assign its pgrp to the tty.
     */
    setpgid(child, child);
    if (foreground) {
	do {
	    status = tcsetpgrp(script_fds[SFD_SLAVE], child);
	} while (status == -1 && errno == EINTR);
    }

    /* Wait for signal on backchannel or for SIGCHLD */
    fdsr = (fd_set *)emalloc2(howmany(backchannel + 1, NFDBITS), sizeof(fd_mask));
    zero_bytes(fdsr, howmany(backchannel + 1, NFDBITS) * sizeof(fd_mask));
    FD_SET(backchannel, fdsr);
    for (;;) {
	/* Read child status */
	while (recvsig[SIGCHLD]) {
	    recvsig[SIGCHLD] = FALSE;
	    /* read child status and relay to parent */
	    do {
		pid = waitpid(child, &status, WUNTRACED|WNOHANG);
	    } while (pid == -1 && errno == EINTR);
	    if (pid == child) {
		if (WIFSTOPPED(status))
		    sudo_debug(8, "command stopped, signal %d", WSTOPSIG(status));
		else if (WIFSIGNALED(status))
		    sudo_debug(8, "command killed, signal %d", WTERMSIG(status));
		else
		    sudo_debug(8, "command exited: %d", WEXITSTATUS(status));
		cstat.type = CMD_WSTATUS;
		cstat.val = status;
		do {
		    n = send(backchannel, &cstat, sizeof(cstat), 0);
		} while (n == -1 && errno == EINTR);
		if (n != sizeof(cstat))
		    break; /* XXX - error, kill child and exit */
		sudo_debug(8, "sent wait status to parent");
		if (!WIFSTOPPED(status)) {
		    /* XXX */
		    _exit(1); /* child dead */
		}
	    }
	}
	n = select(backchannel + 1, fdsr, NULL, NULL, NULL);
	if (n == -1) {
	    if (errno == EINTR)
		continue;
	    error(1, "select failed");
	}

	/* read command from backchannel, should be a signal */
	n = recv(backchannel, &cstat, sizeof(cstat), 0);
	if (n == -1) {
	    if (errno == EINTR)
		continue;
	    warning("error reading command status");
	    break;
	}
	if (cstat.type != CMD_SIGNO) {
	    warningx("unexpected reply type on backchannel: %d", cstat.type);
	    continue;
	}
	deliver_signal(child, cstat.val);
    }

    _exit(1); /* XXX */

bad:
    return errno;
}

static void
flush_output(struct script_buf *output)
{
    int n;

    while (output->len > output->off) {
	n = write(STDOUT_FILENO, output->buf + output->off,
	    output->len - output->off);
	if (n <= 0)
	    break;
	output->off += n;
    }

    /* Make sure there is no output remaining on the master pty. */
    for (;;) {
	n = read(script_fds[SFD_MASTER], output->buf, sizeof(output->buf));
	if (n <= 0)
	    break;
	/* XXX */
	log_output(output->buf, n);
	output->off = 0;
	output->len = n;
	do {
	    n = write(STDOUT_FILENO, output->buf + output->off,
		output->len - output->off);
	    if (n <= 0)
		break;
	    output->off += n;
	} while (output->len > output->off);
    }
}

static void
script_run(const char *path, char *argv[], char *envp[], int rbac_enabled)
{
    pid_t self = getpid();

    /* Set child process group here too to avoid a race. */
    setpgid(0, self);

    /*
     * We have guaranteed that the slave fd > 3
     */
    if (isatty(STDIN_FILENO))
	dup2(script_fds[SFD_SLAVE], STDIN_FILENO);
    dup2(script_fds[SFD_SLAVE], STDOUT_FILENO);
    dup2(script_fds[SFD_SLAVE], STDERR_FILENO);
    close(script_fds[SFD_SLAVE]);

    /* Wait for parent to grant us the tty if we are foreground. */
    if (foreground) {
	while (tcgetpgrp(STDOUT_FILENO) != self)
	    ; /* spin */
    }

#ifdef HAVE_SELINUX
    if (rbac_enabled)
	selinux_execve(path, argv, envp);
    else
#endif
    my_execve(path, argv, envp);
}

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
 * Generic handler for signals passed from parent -> child
 */
static void
handler(int s)
{
    recvsig[s] = TRUE;
}

/*
 * Handler for SIGWINCH in parent
 */
static void
sigwinch(int s)
{
    int serrno = errno;

    sync_ttysize(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE]);
    errno = serrno;
}
