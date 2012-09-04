/*
 * Copyright (c) 2009-2011 Todd C. Miller <Todd.Miller@courtesan.com>
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
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
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
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>

#include "sudo.h"
#include "sudo_exec.h"
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
#if !defined(TIOCGWINSZ) && defined(TIOCGSIZE)
# define TIOCGWINSZ	TIOCGSIZE
# define TIOCSWINSZ	TIOCSSIZE
# define winsize	ttysize
#endif

struct io_buffer {
    struct io_buffer *next;
    int len; /* buffer length (how much produced) */
    int off; /* write position (how much already consumed) */
    int rfd;  /* reader (producer) */
    int wfd; /* writer (consumer) */
    bool (*action)(const char *buf, unsigned int len);
    char buf[16 * 1024];
};

static char slavename[PATH_MAX];
static bool foreground, pipeline, tty_initialized;
static int io_fds[6] = { -1, -1, -1, -1, -1, -1};
static int ttymode = TERM_COOKED;
static pid_t ppgrp, cmnd_pgrp;
static sigset_t ttyblock;
static struct io_buffer *iobufs;

static void flush_output(void);
static int exec_monitor(struct command_details *details, int backchannel);
static void exec_pty(struct command_details *detail, int *errfd);
static void sigwinch(int s);
static void sync_ttysize(int src, int dst);
static void deliver_signal(pid_t pid, int signo, bool from_parent);
static int safe_close(int fd);
static void check_foreground(void);

/*
 * Cleanup hook for error()/errorx()
 */
void
cleanup(int gotsignal)
{
    debug_decl(cleanup, SUDO_DEBUG_EXEC);

    if (!tq_empty(&io_plugins) && io_fds[SFD_USERTTY] != -1) {
	check_foreground();
	if (foreground)
	    term_restore(io_fds[SFD_USERTTY], 0);
    }
#ifdef HAVE_SELINUX
    selinux_restore_tty();
#endif
    utmp_logout(slavename, 0); /* XXX - only if CD_SET_UTMP */

    debug_return;
}

/*
 * Generic handler for signals recieved by the monitor process.
 * The other end of signal_pipe is checked in the monitor event loop.
 */
#ifdef SA_SIGINFO
void
mon_handler(int s, siginfo_t *info, void *context)
{
    unsigned char signo = (unsigned char)s;

    /*
     * If the signal came from the command we ran, just ignore
     * it since we don't want the command to indirectly kill itself.
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
mon_handler(int s)
{
    unsigned char signo = (unsigned char)s;

    /*
     * The pipe is non-blocking, if we overflow the kernel's pipe
     * buffer we drop the signal.  This is not a problem in practice.
     */
    ignore_result(write(signal_pipe[1], &signo, sizeof(signo)));
}
#endif

/*
 * Allocate a pty if /dev/tty is a tty.
 * Fills in io_fds[SFD_USERTTY], io_fds[SFD_MASTER], io_fds[SFD_SLAVE]
 * and slavename globals.
 */
void
pty_setup(uid_t uid, const char *tty, const char *utmp_user)
{
    debug_decl(pty_setup, SUDO_DEBUG_EXEC);

    io_fds[SFD_USERTTY] = open(_PATH_TTY, O_RDWR|O_NOCTTY, 0);
    if (io_fds[SFD_USERTTY] != -1) {
	if (!get_pty(&io_fds[SFD_MASTER], &io_fds[SFD_SLAVE],
	    slavename, sizeof(slavename), uid))
	    error(1, _("unable to allocate pty"));
	/* Add entry to utmp/utmpx? */
	if (utmp_user != NULL)
	    utmp_login(tty, slavename, io_fds[SFD_SLAVE], utmp_user);
    }

    debug_return;
}

/* Call I/O plugin tty input log method. */
static bool
log_ttyin(const char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_ttyin, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_ttyin) {
	    if (!plugin->u.io->log_ttyin(buf, n)) {
	    	rval = false;
		break;
	    }
	}
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(rval);
}

/* Call I/O plugin stdin log method. */
static bool
log_stdin(const char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_stdin, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_stdin) {
	    if (!plugin->u.io->log_stdin(buf, n)) {
	    	rval = false;
		break;
	    }
	}
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(rval);
}

/* Call I/O plugin tty output log method. */
static bool
log_ttyout(const char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_ttyout, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_ttyout) {
	    if (!plugin->u.io->log_ttyout(buf, n)) {
	    	rval = false;
		break;
	    }
	}
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(rval);
}

/* Call I/O plugin stdout log method. */
static bool
log_stdout(const char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_stdout, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_stdout) {
	    if (!plugin->u.io->log_stdout(buf, n)) {
	    	rval = false;
		break;
	    }
	}
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(rval);
}

/* Call I/O plugin stderr log method. */
static bool
log_stderr(const char *buf, unsigned int n)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_stderr, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    tq_foreach_fwd(&io_plugins, plugin) {
	if (plugin->u.io->log_stderr) {
	    if (!plugin->u.io->log_stderr(buf, n)) {
	    	rval = false;
		break;
	    }
	}
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(rval);
}

/*
 * Check whether we are running in the foregroup.
 * Updates the foreground global and does lazy init of the
 * the pty slave as needed.
 */
static void
check_foreground(void)
{
    debug_decl(check_foreground, SUDO_DEBUG_EXEC);

    if (io_fds[SFD_USERTTY] != -1) {
	foreground = tcgetpgrp(io_fds[SFD_USERTTY]) == ppgrp;
	if (foreground && !tty_initialized) {
	    if (term_copy(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE])) {
		tty_initialized = true;
		sync_ttysize(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE]);
	    }
	}
    }

    debug_return;
}

/*
 * Suspend sudo if the underlying command is suspended.
 * Returns SIGCONT_FG if the command should be resumed in the
 * foreground or SIGCONT_BG if it is a background process.
 */
int
suspend_parent(int signo)
{
    char signame[SIG2STR_MAX];
    sigaction_t sa, osa;
    int n, oldmode = ttymode, rval = 0;
    debug_decl(suspend_parent, SUDO_DEBUG_EXEC);

    switch (signo) {
    case SIGTTOU:
    case SIGTTIN:
	/*
	 * If we are the foreground process, just resume the command.
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
	    rval = SIGCONT_FG; /* resume command in foreground */
	    break;
	}
	ttymode = TERM_RAW;
	/* FALLTHROUGH */
    case SIGSTOP:
    case SIGTSTP:
	/* Flush any remaining output before suspending. */
	flush_output();

	/* Restore original tty mode before suspending. */
	if (oldmode != TERM_COOKED) {
	    do {
		n = term_restore(io_fds[SFD_USERTTY], 0);
	    } while (!n && errno == EINTR);
	}

	if (sig2str(signo, signame) == -1)
	    snprintf(signame, sizeof(signame), "%d", signo);

	/* Suspend self and continue command when we resume. */
	zero_bytes(&sa, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_INTERRUPT; /* do not restart syscalls */
	sa.sa_handler = SIG_DFL;
	sigaction(signo, &sa, &osa);
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill parent SIG%s", signame);
	if (killpg(ppgrp, signo) != 0)
	    warning("killpg(%d, SIG%s)", (int)ppgrp, signame);

	/* Check foreground/background status on resume. */
	check_foreground();

	/*
	 * Only modify term if we are foreground process and either
	 * the old tty mode was not cooked or command got SIGTT{IN,OU}
	 */
	sudo_debug_printf(SUDO_DEBUG_INFO, "parent is in %s, ttymode %d -> %d",
	    foreground ? "foreground" : "background", oldmode, ttymode);

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
	rval = ttymode == TERM_RAW ? SIGCONT_FG : SIGCONT_BG;
	break;
    }

    debug_return_int(rval);
}

/*
 * Kill command with increasing urgency.
 */
void
terminate_command(pid_t pid, bool use_pgrp)
{
    debug_decl(terminate_command, SUDO_DEBUG_EXEC);

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

static struct io_buffer *
io_buf_new(int rfd, int wfd, bool (*action)(const char *, unsigned int),
    struct io_buffer *head)
{
    struct io_buffer *iob;
    debug_decl(io_buf_new, SUDO_DEBUG_EXEC);

    iob = ecalloc(1, sizeof(*iob));
    iob->rfd = rfd;
    iob->wfd = wfd;
    iob->action = action;
    iob->next = head;

    debug_return_ptr(iob);
}

/*
 * Read/write iobufs depending on fdsr and fdsw.
 * Returns the number of errors.
 */
int
perform_io(fd_set *fdsr, fd_set *fdsw, struct command_status *cstat)
{
    struct io_buffer *iob;
    int n, errors = 0;
    debug_decl(perform_io, SUDO_DEBUG_EXEC);

    for (iob = iobufs; iob; iob = iob->next) {
	if (iob->rfd != -1 && FD_ISSET(iob->rfd, fdsr)) {
	    do {
		n = read(iob->rfd, iob->buf + iob->len,
		    sizeof(iob->buf) - iob->len);
	    } while (n == -1 && errno == EINTR);
	    switch (n) {
		case -1:
		    if (errno != EAGAIN) {
			/* treat read error as fatal and close the fd */
			sudo_debug_printf(SUDO_DEBUG_ERROR,
			    "error reading fd %d: %s", iob->rfd,
			    strerror(errno));
			safe_close(iob->rfd);
			iob->rfd = -1;
		    }
		    break;
		case 0:
		    /* got EOF or pty has gone away */
		    sudo_debug_printf(SUDO_DEBUG_INFO,
			"read EOF from fd %d", iob->rfd);
		    safe_close(iob->rfd);
		    iob->rfd = -1;
		    break;
		default:
		    sudo_debug_printf(SUDO_DEBUG_INFO,
			"read %d bytes from fd %d", n, iob->rfd);
		    if (!iob->action(iob->buf + iob->len, n))
			terminate_command(cmnd_pid, true);
		    iob->len += n;
		    break;
	    }
	}
	if (iob->wfd != -1 && FD_ISSET(iob->wfd, fdsw)) {
	    do {
		n = write(iob->wfd, iob->buf + iob->off,
		    iob->len - iob->off);
	    } while (n == -1 && errno == EINTR);
	    if (n == -1) {
		if (errno == EPIPE || errno == ENXIO || errno == EIO || errno == EBADF) {
		    sudo_debug_printf(SUDO_DEBUG_INFO,
			"unable to write %d bytes to fd %d",
			    iob->len - iob->off, iob->wfd);
		    /* other end of pipe closed or pty revoked */
		    if (iob->rfd != -1) {
			safe_close(iob->rfd);
			iob->rfd = -1;
		    }
		    safe_close(iob->wfd);
		    iob->wfd = -1;
		    continue;
		}
		if (errno != EAGAIN) {
		    errors++;
		    sudo_debug_printf(SUDO_DEBUG_ERROR,
			"error writing fd %d: %s", iob->wfd, strerror(errno));
		}
	    } else {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "wrote %d bytes to fd %d", n, iob->wfd);
		iob->off += n;
	    }
	}
    }
    if (errors && cstat != NULL) {
	cstat->type = CMD_ERRNO;
	cstat->val = errno;
    }
    debug_return_int(errors);
}

/*
 * Fork a monitor process which runs the actual command as its own child
 * process with std{in,out,err} hooked up to the pty or pipes as appropriate.
 * Returns the child pid.
 */
int
fork_pty(struct command_details *details, int sv[], int *maxfd, sigset_t *omask)
{
    struct command_status cstat;
    struct io_buffer *iob;
    int io_pipe[3][2], n;
    sigaction_t sa;
    sigset_t mask;
    pid_t child;
    debug_decl(fork_pty, SUDO_DEBUG_EXEC);
        
    ppgrp = getpgrp(); /* parent's pgrp, so child can signal us */
     
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
 
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
     * In background mode there is no stdin.
     */
    if (!ISSET(details->flags, CD_BACKGROUND))
	io_fds[SFD_STDIN] = io_fds[SFD_SLAVE];
    io_fds[SFD_STDOUT] = io_fds[SFD_SLAVE];
    io_fds[SFD_STDERR] = io_fds[SFD_SLAVE];

    if (io_fds[SFD_USERTTY] != -1) {
	/* Read from /dev/tty, write to pty master */
	if (!ISSET(details->flags, CD_BACKGROUND)) {
	    iobufs = io_buf_new(io_fds[SFD_USERTTY], io_fds[SFD_MASTER],
		log_ttyin, iobufs);
	}

	/* Read from pty master, write to /dev/tty */
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
    if (io_fds[SFD_STDIN] == -1 || !isatty(STDIN_FILENO)) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "stdin not a tty, creating a pipe");
	pipeline = true;
	if (pipe(io_pipe[STDIN_FILENO]) != 0)
	    error(1, _("unable to create pipe"));
	iobufs = io_buf_new(STDIN_FILENO, io_pipe[STDIN_FILENO][1],
	    log_stdin, iobufs);
	io_fds[SFD_STDIN] = io_pipe[STDIN_FILENO][0];
    }
    if (io_fds[SFD_STDOUT] == -1 || !isatty(STDOUT_FILENO)) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "stdout not a tty, creating a pipe");
	pipeline = true;
	if (pipe(io_pipe[STDOUT_FILENO]) != 0)
	    error(1, _("unable to create pipe"));
	iobufs = io_buf_new(io_pipe[STDOUT_FILENO][0], STDOUT_FILENO,
	    log_stdout, iobufs);
	io_fds[SFD_STDOUT] = io_pipe[STDOUT_FILENO][1];
    }
    if (io_fds[SFD_STDERR] == -1 || !isatty(STDERR_FILENO)) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "stderr not a tty, creating a pipe");
	if (pipe(io_pipe[STDERR_FILENO]) != 0)
	    error(1, _("unable to create pipe"));
	iobufs = io_buf_new(io_pipe[STDERR_FILENO][0], STDERR_FILENO,
	    log_stderr, iobufs);
	io_fds[SFD_STDERR] = io_pipe[STDERR_FILENO][1];
    }

    /* Job control signals to relay from parent to child. */
    sa.sa_flags = SA_INTERRUPT; /* do not restart syscalls */
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = handler;
#else
    sa.sa_handler = handler;
#endif
    sigaction(SIGTSTP, &sa, NULL);

    /* We don't want to receive SIGTTIN/SIGTTOU, getting EIO is preferable. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGTTIN, &sa, NULL);
    sigaction(SIGTTOU, &sa, NULL);

    if (foreground) {
	/* Copy terminal attrs from user tty -> pty slave. */
	if (term_copy(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE])) {
	    tty_initialized = true;
	    sync_ttysize(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE]);
	}

	/* Start out in raw mode if we are not part of a pipeline. */
	if (!pipeline) {
	    ttymode = TERM_RAW;
	    do {
		n = term_raw(io_fds[SFD_USERTTY], 0);
	    } while (!n && errno == EINTR);
	    if (!n)
		error(1, _("unable to set terminal to raw mode"));
	}
    }

    /*
     * The policy plugin's session init must be run before we fork
     * or certain pam modules won't be able to track their state.
     */
    if (policy_init_session(details) != true)
	errorx(1, _("policy plugin failed session initialization"));

    /*
     * Block some signals until cmnd_pid is set in the parent to avoid a
     * race between exec of the command and receipt of a fatal signal from it.
     */
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGQUIT);
    sigprocmask(SIG_BLOCK, &mask, omask);

    child = sudo_debug_fork();
    switch (child) {
    case -1:
	error(1, _("unable to fork"));
	break;
    case 0:
	/* child */
	close(sv[0]);
	close(signal_pipe[0]);
	close(signal_pipe[1]);
	fcntl(sv[1], F_SETFD, FD_CLOEXEC);
	sigprocmask(SIG_SETMASK, omask, NULL);
	if (exec_setup(details, slavename, io_fds[SFD_SLAVE]) == true) {
	    /* Close the other end of the stdin/stdout/stderr pipes and exec. */
	    if (io_pipe[STDIN_FILENO][1])
		close(io_pipe[STDIN_FILENO][1]);
	    if (io_pipe[STDOUT_FILENO][0])
		close(io_pipe[STDOUT_FILENO][0]);
	    if (io_pipe[STDERR_FILENO][0])
		close(io_pipe[STDERR_FILENO][0]);
	    exec_monitor(details, sv[1]);
	}
	cstat.type = CMD_ERRNO;
	cstat.val = errno;
	ignore_result(send(sv[1], &cstat, sizeof(cstat), 0));
	_exit(1);
    }

    /* Close the other end of the stdin/stdout/stderr pipes. */
    if (io_pipe[STDIN_FILENO][0])
	close(io_pipe[STDIN_FILENO][0]);
    if (io_pipe[STDOUT_FILENO][1])
	close(io_pipe[STDOUT_FILENO][1]);
    if (io_pipe[STDERR_FILENO][1]) 
	close(io_pipe[STDERR_FILENO][1]);

    for (iob = iobufs; iob; iob = iob->next) {
	/* Determine maxfd */
	if (iob->rfd > *maxfd)
	    *maxfd = iob->rfd;
	if (iob->wfd > *maxfd)
	    *maxfd = iob->wfd;

	/* Set non-blocking mode. */
	n = fcntl(iob->rfd, F_GETFL, 0);
	if (n != -1 && !ISSET(n, O_NONBLOCK))
	    (void) fcntl(iob->rfd, F_SETFL, n | O_NONBLOCK);
	n = fcntl(iob->wfd, F_GETFL, 0);
	if (n != -1 && !ISSET(n, O_NONBLOCK))
	    (void) fcntl(iob->wfd, F_SETFL, n | O_NONBLOCK);
    }

    debug_return_int(child);
}

void
pty_close(struct command_status *cstat)
{
    int n;
    debug_decl(pty_close, SUDO_DEBUG_EXEC);

    /* Flush any remaining output (the plugin already got it) */
    if (io_fds[SFD_USERTTY] != -1) {
	n = fcntl(io_fds[SFD_USERTTY], F_GETFL, 0);
	if (n != -1 && ISSET(n, O_NONBLOCK)) {
	    CLR(n, O_NONBLOCK);
	    (void) fcntl(io_fds[SFD_USERTTY], F_SETFL, n);
	}
    }
    flush_output();

    if (io_fds[SFD_USERTTY] != -1) {
	check_foreground();
	if (foreground) {
	    do {
		n = term_restore(io_fds[SFD_USERTTY], 0);
	    } while (!n && errno == EINTR);
	}
    }

    /* If child was signalled, write the reason to stdout like the shell. */
    if (cstat->type == CMD_WSTATUS && WIFSIGNALED(cstat->val)) {
	int signo = WTERMSIG(cstat->val);
	if (signo && signo != SIGINT && signo != SIGPIPE) {
	    const char *reason = strsignal(signo);
	    n = io_fds[SFD_USERTTY] != -1 ?
		io_fds[SFD_USERTTY] : STDOUT_FILENO;
	    if (write(n, reason, strlen(reason)) != -1) {
		if (WCOREDUMP(cstat->val)) {
		    ignore_result(write(n, " (core dumped)", 14));
		}
		ignore_result(write(n, "\n", 1));
	    }
	}
    }
    utmp_logout(slavename, cstat->type == CMD_WSTATUS ? cstat->val : 0); /* XXX - only if CD_SET_UTMP */
    debug_return;
}

/*
 * Fill in fdsr and fdsw based on the io buffers list.
 * Called prior to select().
 */
void
fd_set_iobs(fd_set *fdsr, fd_set *fdsw)
{
    struct io_buffer *iob;
    debug_decl(fd_set_iobs, SUDO_DEBUG_EXEC);

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
    debug_return;
}

static void
deliver_signal(pid_t pid, int signo, bool from_parent)
{
    char signame[SIG2STR_MAX];
    int status;
    debug_decl(deliver_signal, SUDO_DEBUG_EXEC);

    if (sig2str(signo, signame) == -1)
	snprintf(signame, sizeof(signame), "%d", signo);

    /* Handle signal from parent. */
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
	    status = tcsetpgrp(io_fds[SFD_SLAVE], getpid());
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
 * Returns true if command is still alive, else false.
 */
static bool
handle_sigchld(int backchannel, struct command_status *cstat)
{
    bool alive = true;
    int status;
    pid_t pid;
    debug_decl(handle_sigchld, SUDO_DEBUG_EXEC);

    /* read command status */
    do {
	pid = waitpid(cmnd_pid, &status, WUNTRACED|WNOHANG);
    } while (pid == -1 && errno == EINTR);
    if (pid == cmnd_pid) {
	if (cstat->type != CMD_ERRNO) {
	    char signame[SIG2STR_MAX];

	    cstat->type = CMD_WSTATUS;
	    cstat->val = status;
	    if (WIFSTOPPED(status)) {
		if (sig2str(WSTOPSIG(status), signame) == -1)
		    snprintf(signame, sizeof(signame), "%d", WSTOPSIG(status));
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "command stopped, SIG%s", signame);
		do {
		    cmnd_pgrp = tcgetpgrp(io_fds[SFD_SLAVE]);
		} while (cmnd_pgrp == -1 && errno == EINTR);
		if (send_status(backchannel, cstat) == -1)
		    return alive; /* XXX */
	    } else if (WIFSIGNALED(status)) {
		if (sig2str(WTERMSIG(status), signame) == -1)
		    snprintf(signame, sizeof(signame), "%d", WTERMSIG(status));
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "command killed, SIG%s", signame);
	    } else {
		sudo_debug_printf(SUDO_DEBUG_INFO, "command exited: %d",
		    WEXITSTATUS(status));
	    }
	}
	if (!WIFSTOPPED(status))
	    alive = false;
    }
    debug_return_bool(alive);
}

/*
 * Monitor process that creates a new session with the controlling tty,
 * resets signal handlers and forks a child to call exec_pty().
 * Waits for status changes from the command and relays them to the
 * parent and relays signals from the parent to the command.
 * Returns an error if fork(2) fails, else calls _exit(2).
 */
static int
exec_monitor(struct command_details *details, int backchannel)
{
    struct command_status cstat;
    struct timeval tv;
    fd_set *fdsr;
    sigaction_t sa;
    int errpipe[2], maxfd, n, status;
    bool alive = true;
    unsigned char signo;
    debug_decl(exec_monitor, SUDO_DEBUG_EXEC);

    /* Close unused fds. */
    if (io_fds[SFD_MASTER] != -1)
	close(io_fds[SFD_MASTER]);
    if (io_fds[SFD_USERTTY] != -1)
	close(io_fds[SFD_USERTTY]);

    /*
     * We use a pipe to atomically handle signal notification within
     * the select() loop.
     */
    if (pipe_nonblock(signal_pipe) != 0)
	error(1, _("unable to create pipe"));

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
    sa.sa_flags = SA_INTERRUPT;
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = mon_handler;
#else
    sa.sa_handler = mon_handler;
#endif
    sigaction(SIGCHLD, &sa, NULL);

    /* Catch common signals so we can cleanup properly. */
    sa.sa_flags = SA_RESTART;
#ifdef SA_SIGINFO
    sa.sa_flags |= SA_SIGINFO;
    sa.sa_sigaction = mon_handler;
#else
    sa.sa_handler = mon_handler;
#endif
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGTSTP, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    /*
     * Start a new session with the parent as the session leader
     * and the slave pty as the controlling terminal.
     * This allows us to be notified when the command has been suspended.
     */
    if (setsid() == -1) {
	warning("setsid");
	goto bad;
    }
    if (io_fds[SFD_SLAVE] != -1) {
#ifdef TIOCSCTTY
	if (ioctl(io_fds[SFD_SLAVE], TIOCSCTTY, NULL) != 0)
	    error(1, _("unable to set controlling tty"));
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
	foreground = false;

    /* Start command and wait for it to stop or exit */
    if (pipe(errpipe) == -1)
	error(1, _("unable to create pipe"));
    cmnd_pid = sudo_debug_fork();
    if (cmnd_pid == -1) {
	warning(_("unable to fork"));
	goto bad;
    }
    if (cmnd_pid == 0) {
	/* We pass errno back to our parent via pipe on exec failure. */
	close(backchannel);
	close(signal_pipe[0]);
	close(signal_pipe[1]);
	close(errpipe[0]);
	fcntl(errpipe[1], F_SETFD, FD_CLOEXEC);
	restore_signals();

	/* setup tty and exec command */
	exec_pty(details, &errpipe[1]);
	cstat.type = CMD_ERRNO;
	cstat.val = errno;
	ignore_result(write(errpipe[1], &cstat, sizeof(cstat)));
	_exit(1);
    }
    close(errpipe[1]);

    /* Send the command's pid to main sudo process. */
    cstat.type = CMD_PID;
    cstat.val = cmnd_pid;
    ignore_result(send(backchannel, &cstat, sizeof(cstat), 0));

    /* If any of stdin/stdout/stderr are pipes, close them in parent. */
    if (io_fds[SFD_STDIN] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDIN]);
    if (io_fds[SFD_STDOUT] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDOUT]);
    if (io_fds[SFD_STDERR] != io_fds[SFD_SLAVE])
	close(io_fds[SFD_STDERR]);

    /*
     * Put command in its own process group.  If we are starting the command
     * in the foreground, assign its pgrp to the tty.
     */
    cmnd_pgrp = cmnd_pid;
    setpgid(cmnd_pid, cmnd_pgrp);
    if (foreground) {
	do {
	    status = tcsetpgrp(io_fds[SFD_SLAVE], cmnd_pgrp);
	} while (status == -1 && errno == EINTR);
    }

    /* Wait for errno on pipe, signal on backchannel or for SIGCHLD */
    maxfd = MAX(MAX(errpipe[0], signal_pipe[0]), backchannel);
    fdsr = ecalloc(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    memset(&cstat, 0, sizeof(cstat));
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    for (;;) {
	/* Check for signal on backchannel or errno on errpipe. */
	FD_SET(backchannel, fdsr);
	FD_SET(signal_pipe[0], fdsr);
	if (errpipe[0] != -1)
	    FD_SET(errpipe[0], fdsr);
	maxfd = MAX(MAX(errpipe[0], signal_pipe[0]), backchannel);

	/* If command exited we just poll, there may be data on errpipe. */
	n = select(maxfd + 1, fdsr, NULL, NULL, alive ? NULL : &tv);
	if (n <= 0) {
	    if (n == 0)
		goto done;
	    if (errno == EINTR || errno == ENOMEM)
		continue;
	    warning("monitor: %s", _("select failed"));
	    break;
	}

	if (FD_ISSET(signal_pipe[0], fdsr)) {
	    n = read(signal_pipe[0], &signo, sizeof(signo));
	    if (n == -1) {
		if (errno == EINTR || errno == EAGAIN)
		    continue;
		warning(_("error reading from signal pipe"));
		goto done;
	    }
	    /*
	     * Handle SIGCHLD specially and deliver other signals
	     * directly to the command.
	     */
	    if (signo == SIGCHLD) {
		if (!handle_sigchld(backchannel, &cstat))
		    alive = false;
	    } else {
		deliver_signal(cmnd_pid, signo, false);
	    }
	    continue;
	}
	if (errpipe[0] != -1 && FD_ISSET(errpipe[0], fdsr)) {
	    /* read errno or EOF from command pipe */
	    n = read(errpipe[0], &cstat, sizeof(cstat));
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		warning(_("error reading from pipe"));
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
		warning(_("error reading from socketpair"));
		goto done;
	    }
	    if (cstmp.type != CMD_SIGNO) {
		warningx(_("unexpected reply type on backchannel: %d"),
		    cstmp.type);
		continue;
	    }
	    deliver_signal(cmnd_pid, cstmp.val, true);
	}
    }

done:
    if (alive) {
	/* XXX An error occurred, should send an error back. */
	kill(cmnd_pid, SIGKILL);
    } else {
	/* Send parent status. */
	send_status(backchannel, &cstat);
    }
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, 1);
    _exit(1);

bad:
    debug_return_int(errno);
}

/*
 * Flush any output buffered in iobufs or readable from the fds.
 * Does not read from /dev/tty.
 */
static void
flush_output(void)
{
    struct io_buffer *iob;
    struct timeval tv;
    fd_set *fdsr, *fdsw;
    int nready, nwriters, maxfd = -1;
    debug_decl(flush_output, SUDO_DEBUG_EXEC);

    /* Determine maxfd */
    for (iob = iobufs; iob; iob = iob->next) {
	if (iob->rfd > maxfd)
	    maxfd = iob->rfd;
	if (iob->wfd > maxfd)
	    maxfd = iob->wfd;
    }
    if (maxfd == -1)
	debug_return;

    fdsr = emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    fdsw = emalloc2(howmany(maxfd + 1, NFDBITS), sizeof(fd_mask));
    for (;;) {
	memset(fdsw, 0, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));
	memset(fdsr, 0, howmany(maxfd + 1, NFDBITS) * sizeof(fd_mask));

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
	    if (errno == EINTR || errno == ENOMEM)
		continue;
	    warning(_("select failed"));
	}
	if (perform_io(fdsr, fdsw, NULL) != 0 || nready == -1)
	    break;
    }
    efree(fdsr);
    efree(fdsw);
    debug_return;
}

/*
 * Sets up std{in,out,err} and executes the actual command.
 * Returns only if execve() fails.
 */
static void
exec_pty(struct command_details *details, int *errfd)
{
    pid_t self = getpid();
    debug_decl(exec_pty, SUDO_DEBUG_EXEC);

    /* Set command process group here too to avoid a race. */
    setpgid(0, self);

    /* Wire up standard fds, note that stdout/stderr may be pipes. */
    if (dup2(io_fds[SFD_STDIN], STDIN_FILENO) == -1 ||
	dup2(io_fds[SFD_STDOUT], STDOUT_FILENO) == -1 ||
	dup2(io_fds[SFD_STDERR], STDERR_FILENO) == -1)
	error(1, "dup2");

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

    sudo_debug_execve(SUDO_DEBUG_INFO, details->command,
	details->argv, details->envp);

    if (details->closefrom >= 0) {
	int maxfd = details->closefrom;
	dup2(*errfd, maxfd);
	(void)fcntl(maxfd, F_SETFD, FD_CLOEXEC);
	*errfd = maxfd++;
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
    debug_return;
}

/*
 * Propagates tty size change signals to pty being used by the command.
 */
static void
sync_ttysize(int src, int dst)
{
#ifdef TIOCGWINSZ
    struct winsize wsize;
    pid_t pgrp;
    debug_decl(sync_ttysize, SUDO_DEBUG_EXEC);

    if (ioctl(src, TIOCGWINSZ, &wsize) == 0) {
	    ioctl(dst, TIOCSWINSZ, &wsize);
	    if ((pgrp = tcgetpgrp(dst)) != -1)
		killpg(pgrp, SIGWINCH);
    }

    debug_return;
#endif
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
    debug_decl(safe_close, SUDO_DEBUG_EXEC);

    /* Avoid closing /dev/tty or std{in,out,err}. */
    if (fd < 3 || fd == io_fds[SFD_USERTTY]) {
	errno = EINVAL;
	debug_return_int(-1);
    }
    debug_return_int(close(fd));
}
