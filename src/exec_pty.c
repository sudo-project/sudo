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
#include "sudo_event.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

#define SFD_STDIN	0
#define SFD_STDOUT	1
#define SFD_STDERR	2
#define SFD_MASTER	3
#define SFD_SLAVE	4
#define SFD_USERTTY	5

/* Evaluates to true if the event has /dev/tty as its fd. */
#define USERTTY_EVENT(_ev)	(sudo_ev_get_fd((_ev)) == io_fds[SFD_USERTTY])

#define TERM_COOKED	0
#define TERM_RAW	1

/* Compatibility with older tty systems. */
#if !defined(TIOCGWINSZ) && defined(TIOCGSIZE)
# define TIOCGWINSZ	TIOCGSIZE
# define TIOCSWINSZ	TIOCSSIZE
# define winsize	ttysize
#endif

/*
 * I/O buffer with associated read/write events and a logging action.
 * Used to, e.g. pass data from the pty to the user's terminal
 * and any I/O logging plugins.
 */
struct io_buffer;
typedef bool (*sudo_io_action_t)(const char *, unsigned int, struct io_buffer *);
struct io_buffer {
    SLIST_ENTRY(io_buffer) entries;
    struct sudo_event *revent;
    struct sudo_event *wevent;
    sudo_io_action_t action;
    int len; /* buffer length (how much produced) */
    int off; /* write position (how much already consumed) */
    char buf[64 * 1024];
};
SLIST_HEAD(io_buffer_list, io_buffer);

static char slavename[PATH_MAX];
static bool foreground, pipeline, tty_initialized;
static int io_fds[6] = { -1, -1, -1, -1, -1, -1};
static int ttymode = TERM_COOKED;
static pid_t ppgrp, cmnd_pgrp, mon_pgrp;
static sigset_t ttyblock;
static struct io_buffer_list iobufs;

static void del_io_events(bool nonblocking);
static int exec_monitor(struct command_details *details, int backchannel);
static void exec_pty(struct command_details *details,
    struct command_status *cstat, int errfd);
static void sigwinch(int s);
static void sync_ttysize(int src, int dst);
static void deliver_signal(pid_t pid, int signo, bool from_parent);
static int safe_close(int fd);
static void ev_free_by_fd(struct sudo_event_base *evbase, int fd);
static void check_foreground(void);

/*
 * Cleanup hook for sudo_fatal()/sudo_fatalx()
 */
static void
pty_cleanup(void)
{
    debug_decl(cleanup, SUDO_DEBUG_EXEC);

    if (!TAILQ_EMPTY(&io_plugins) && io_fds[SFD_USERTTY] != -1)
	sudo_term_restore(io_fds[SFD_USERTTY], 0);
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
 * Allocate a pty if /dev/tty is a tty.
 * Fills in io_fds[SFD_USERTTY], io_fds[SFD_MASTER], io_fds[SFD_SLAVE]
 * and slavename globals.
 */
void
pty_setup(uid_t uid, const char *tty, const char *utmp_user)
{
    debug_decl(pty_setup, SUDO_DEBUG_EXEC);

    io_fds[SFD_USERTTY] = open(_PATH_TTY, O_RDWR);
    if (io_fds[SFD_USERTTY] != -1) {
	if (!get_pty(&io_fds[SFD_MASTER], &io_fds[SFD_SLAVE],
	    slavename, sizeof(slavename), uid))
	    sudo_fatal(U_("unable to allocate pty"));
	/* Add entry to utmp/utmpx? */
	if (utmp_user != NULL)
	    utmp_login(tty, slavename, io_fds[SFD_SLAVE], utmp_user);
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: /dev/tty fd %d, pty master fd %d, pty slave fd %d", __func__,
	    io_fds[SFD_USERTTY], io_fds[SFD_MASTER], io_fds[SFD_SLAVE]);
    }

    debug_return;
}

/* Call I/O plugin tty input log method. */
static bool
log_ttyin(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_ttyin, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_ttyin) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_ttyin(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_ttyin = NULL;
		}
		rval = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(rval);
}

/* Call I/O plugin stdin log method. */
static bool
log_stdin(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_stdin, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_stdin) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_stdin(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_stdin = NULL;
		}
	    	rval = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(rval);
}

/* Call I/O plugin tty output log method. */
static bool
log_ttyout(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_ttyout, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_ttyout) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_ttyout(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_ttyout = NULL;
		}
	    	rval = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    if (!rval) {
	/*
	 * I/O plugin rejected the output, delete the write event
	 * (user's tty) so we do not display the rejected output.
	 */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: deleting and freeing devtty wevent %p", __func__, iob->wevent);
	sudo_ev_del(NULL, iob->wevent);
	sudo_ev_free(iob->wevent);
	iob->wevent = NULL;
	iob->off = iob->len = 0;
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(rval);
}

/* Call I/O plugin stdout log method. */
static bool
log_stdout(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_stdout, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_stdout) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_stdout(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_stdout = NULL;
		}
	    	rval = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    if (!rval) {
	/*
	 * I/O plugin rejected the output, delete the write event
	 * (user's stdout) so we do not display the rejected output.
	 */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: deleting and freeing stdout wevent %p", __func__, iob->wevent);
	sudo_ev_del(NULL, iob->wevent);
	sudo_ev_free(iob->wevent);
	iob->wevent = NULL;
	iob->off = iob->len = 0;
    }
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(rval);
}

/* Call I/O plugin stderr log method. */
static bool
log_stderr(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool rval = true;
    debug_decl(log_stderr, SUDO_DEBUG_EXEC);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_stderr) {
	    int rc;

	    sudo_debug_set_active_instance(plugin->debug_instance);
	    rc = plugin->u.io->log_stderr(buf, n);
	    if (rc <= 0) {
		if (rc < 0) {
		    /* Error: disable plugin's I/O function. */
		    plugin->u.io->log_stderr = NULL;
		}
	    	rval = false;
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    if (!rval) {
	/*
	 * I/O plugin rejected the output, delete the write event
	 * (user's stderr) so we do not display the rejected output.
	 */
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: deleting and freeing stderr wevent %p", __func__, iob->wevent);
	sudo_ev_del(NULL, iob->wevent);
	sudo_ev_free(iob->wevent);
	iob->wevent = NULL;
	iob->off = iob->len = 0;
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
	    if (sudo_term_copy(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE])) {
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
    int rval = 0;
    debug_decl(suspend_parent, SUDO_DEBUG_EXEC);

    switch (signo) {
    case SIGTTOU:
    case SIGTTIN:
	/*
	 * If sudo is already the foreground process, just resume the command
	 * in the foreground.  If not, we'll suspend sudo and resume later.
	 */
	if (!foreground)
	    check_foreground();
	if (foreground) {
	    if (ttymode != TERM_RAW) {
		if (sudo_term_raw(io_fds[SFD_USERTTY], 0))
		    ttymode = TERM_RAW;
	    }
	    rval = SIGCONT_FG; /* resume command in foreground */
	    break;
	}
	/* FALLTHROUGH */
    case SIGSTOP:
    case SIGTSTP:
	/* Flush any remaining output and deschedule I/O events. */
	del_io_events(true);

	/* Restore original tty mode before suspending. */
	if (ttymode != TERM_COOKED)
	    sudo_term_restore(io_fds[SFD_USERTTY], 0);

	if (sig2str(signo, signame) == -1)
	    snprintf(signame, sizeof(signame), "%d", signo);

	/* Suspend self and continue command when we resume. */
	if (signo != SIGSTOP) {
	    memset(&sa, 0, sizeof(sa));
	    sigemptyset(&sa.sa_mask);
	    sa.sa_flags = SA_RESTART;
	    sa.sa_handler = SIG_DFL;
	    if (sudo_sigaction(signo, &sa, &osa) != 0)
		sudo_warn(U_("unable to set handler for signal %d"), signo);
	}
	sudo_debug_printf(SUDO_DEBUG_INFO, "kill parent SIG%s", signame);
	if (killpg(ppgrp, signo) != 0)
	    sudo_warn("killpg(%d, SIG%s)", (int)ppgrp, signame);

	/* Check foreground/background status on resume. */
	check_foreground();

	/*
	 * We always resume the command in the foreground if sudo itself
	 * is the foreground process.  This helps work around poorly behaved
	 * programs that catch SIGTTOU/SIGTTIN but suspend themselves with
	 * SIGSTOP.  At worst, sudo will go into the background but upon
	 * resume the command will be runnable.  Otherwise, we can get into
	 * a situation where the command will immediately suspend itself.
	 */
	sudo_debug_printf(SUDO_DEBUG_INFO, "parent is in %s, ttymode %d -> %d",
	    foreground ? "foreground" : "background", ttymode,
	    foreground ? TERM_RAW : TERM_COOKED);

	if (foreground) {
	    /* Foreground process, set tty to raw mode. */
	    if (sudo_term_raw(io_fds[SFD_USERTTY], 0))
		ttymode = TERM_RAW;
	} else {
	    /* Background process, no access to tty. */
	    ttymode = TERM_COOKED;
	}

	if (signo != SIGSTOP) {
	    if (sudo_sigaction(signo, &osa, NULL) != 0)
		sudo_warn(U_("unable to restore handler for signal %d"), signo);
	}
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

/*
 * Read an iobuf that is ready.
 */
static void
read_callback(int fd, int what, void *v)
{
    struct io_buffer *iob = v;
    struct sudo_event_base *evbase;
    int n;
    debug_decl(read_callback, SUDO_DEBUG_EXEC);

    evbase = sudo_ev_get_base(iob->revent);
    do {
	n = read(fd, iob->buf + iob->len, sizeof(iob->buf) - iob->len);
    } while (n == -1 && errno == EINTR);
    switch (n) {
	case -1:
	    if (errno == EAGAIN)
		break;
	    /* treat read error as fatal and close the fd */
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"error reading fd %d: %s", fd, strerror(errno));
	    /* FALLTHROUGH */
	case 0:
	    /* got EOF or pty has gone away */
	    if (n == 0) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "read EOF from fd %d", fd);
	    }
	    safe_close(fd);
	    ev_free_by_fd(evbase, fd);
	    /* If writer already consumed the buffer, close it too. */
	    if (iob->wevent != NULL && iob->off == iob->len) {
		safe_close(sudo_ev_get_fd(iob->wevent));
		ev_free_by_fd(evbase, sudo_ev_get_fd(iob->wevent));
		iob->off = iob->len = 0;
	    }
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"read %d bytes from fd %d", n, fd);
	    if (!iob->action(iob->buf + iob->len, n, iob))
		terminate_command(cmnd_pid, true);
	    iob->len += n;
	    /* Enable writer if not /dev/tty or we are foreground pgrp. */
	    if (iob->wevent != NULL &&
		(foreground || !USERTTY_EVENT(iob->wevent))) {
		if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	    /* Re-enable reader if buffer is not full. */
	    if (iob->len != sizeof(iob->buf)) {
		if (sudo_ev_add(evbase, iob->revent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	    break;
    }
}

/*
 * Write an iobuf that is ready.
 */
static void
write_callback(int fd, int what, void *v)
{
    struct io_buffer *iob = v;
    struct sudo_event_base *evbase;
    int n;
    debug_decl(write_callback, SUDO_DEBUG_EXEC);

    evbase = sudo_ev_get_base(iob->wevent);
    do {
	n = write(fd, iob->buf + iob->off, iob->len - iob->off);
    } while (n == -1 && errno == EINTR);
    if (n == -1) {
	switch (errno) {
	case EPIPE:
	case ENXIO:
	case EIO:
	case EBADF:
	    /* other end of pipe closed or pty revoked */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"unable to write %d bytes to fd %d",
		iob->len - iob->off, fd);
	    /* Close reader if there is one. */
	    if (iob->revent != NULL) {
		safe_close(sudo_ev_get_fd(iob->revent));
		ev_free_by_fd(evbase, sudo_ev_get_fd(iob->revent));
	    }
	    safe_close(fd);
	    ev_free_by_fd(evbase, fd);
	    break;
	case EAGAIN:
	    /* not an error */
	    break;
	default:
#if 0 /* XXX -- how to set cstat? stash in iobufs instead? */
	    if (cstat != NULL) {
		cstat->type = CMD_ERRNO;
		cstat->val = errno;
	    }
#endif /* XXX */
	    sudo_debug_printf(SUDO_DEBUG_ERROR,
		"error writing fd %d: %s", fd, strerror(errno));
	    sudo_ev_loopbreak(evbase);
	    break;
	}
    } else {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "wrote %d bytes to fd %d", n, fd);
	iob->off += n;
	/* Reset buffer if fully consumed. */
	if (iob->off == iob->len) {
	    iob->off = iob->len = 0;
	    /* Forward the EOF from reader to writer. */
	    if (iob->revent == NULL) {
		safe_close(fd);
		ev_free_by_fd(evbase, fd);
	    }
	}
	/* Re-enable writer if buffer is not empty. */
	if (iob->len > iob->off) {
	    if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
		sudo_fatal(U_("unable to add event to queue"));
	}
	/* Enable reader if buffer is not full. */
	if (iob->revent != NULL &&
	    (ttymode == TERM_RAW || !USERTTY_EVENT(iob->revent))) {
	    if (iob->len != sizeof(iob->buf)) {
		if (sudo_ev_add(evbase, iob->revent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
    }
}

static void
io_buf_new(int rfd, int wfd, bool (*action)(const char *, unsigned int, struct io_buffer *),
    struct io_buffer_list *head)
{
    int n;
    struct io_buffer *iob;
    debug_decl(io_buf_new, SUDO_DEBUG_EXEC);

    /* Set non-blocking mode. */
    n = fcntl(rfd, F_GETFL, 0);
    if (n != -1 && !ISSET(n, O_NONBLOCK))
	(void) fcntl(rfd, F_SETFL, n | O_NONBLOCK);
    n = fcntl(wfd, F_GETFL, 0);
    if (n != -1 && !ISSET(n, O_NONBLOCK))
	(void) fcntl(wfd, F_SETFL, n | O_NONBLOCK);

    /* Allocate and add to head of list. */
    if ((iob = malloc(sizeof(*iob))) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    iob->revent = sudo_ev_alloc(rfd, SUDO_EV_READ, read_callback, iob);
    iob->wevent = sudo_ev_alloc(wfd, SUDO_EV_WRITE, write_callback, iob);
    iob->len = 0;
    iob->off = 0;
    iob->action = action;
    iob->buf[0] = '\0';
    if (iob->revent == NULL || iob->wevent == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    SLIST_INSERT_HEAD(head, iob, entries);

    debug_return;
}

/*
 * Fork a monitor process which runs the actual command as its own child
 * process with std{in,out,err} hooked up to the pty or pipes as appropriate.
 * Returns the child pid.
 */
int
fork_pty(struct command_details *details, int sv[], sigset_t *omask)
{
    struct command_status cstat;
    int io_pipe[3][2];
    sigaction_t sa;
    sigset_t mask;
    pid_t child;
    debug_decl(fork_pty, SUDO_DEBUG_EXEC);

    ppgrp = getpgrp(); /* parent's pgrp, so child can signal us */

    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);

    if (io_fds[SFD_USERTTY] != -1) {
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sigwinch;
	if (sudo_sigaction(SIGWINCH, &sa, NULL) != 0)
	    sudo_warn(U_("unable to set handler for signal %d"), SIGWINCH);
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
	    io_buf_new(io_fds[SFD_USERTTY], io_fds[SFD_MASTER],
		log_ttyin, &iobufs);
	}

	/* Read from pty master, write to /dev/tty */
	io_buf_new(io_fds[SFD_MASTER], io_fds[SFD_USERTTY],
	    log_ttyout, &iobufs);

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
	    sudo_fatal(U_("unable to create pipe"));
	io_buf_new(STDIN_FILENO, io_pipe[STDIN_FILENO][1],
	    log_stdin, &iobufs);
	io_fds[SFD_STDIN] = io_pipe[STDIN_FILENO][0];
    }
    if (io_fds[SFD_STDOUT] == -1 || !isatty(STDOUT_FILENO)) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "stdout not a tty, creating a pipe");
	pipeline = true;
	if (pipe(io_pipe[STDOUT_FILENO]) != 0)
	    sudo_fatal(U_("unable to create pipe"));
	io_buf_new(io_pipe[STDOUT_FILENO][0], STDOUT_FILENO,
	    log_stdout, &iobufs);
	io_fds[SFD_STDOUT] = io_pipe[STDOUT_FILENO][1];
    }
    if (io_fds[SFD_STDERR] == -1 || !isatty(STDERR_FILENO)) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "stderr not a tty, creating a pipe");
	if (pipe(io_pipe[STDERR_FILENO]) != 0)
	    sudo_fatal(U_("unable to create pipe"));
	io_buf_new(io_pipe[STDERR_FILENO][0], STDERR_FILENO,
	    log_stderr, &iobufs);
	io_fds[SFD_STDERR] = io_pipe[STDERR_FILENO][1];
    }

    /* We don't want to receive SIGTTIN/SIGTTOU, getting EIO is preferable. */
    sa.sa_handler = SIG_IGN;
    if (sudo_sigaction(SIGTTIN, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTIN);
    if (sudo_sigaction(SIGTTOU, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTOU);

    /* Job control signals to relay from parent to child. */
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
    if (sudo_sigaction(SIGTSTP, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);

    if (foreground) {
	/* Copy terminal attrs from user tty -> pty slave. */
	if (sudo_term_copy(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE])) {
	    tty_initialized = true;
	    sync_ttysize(io_fds[SFD_USERTTY], io_fds[SFD_SLAVE]);
	}

	/* Start out in raw mode unless part of a pipeline or backgrounded. */
	if (!pipeline && !ISSET(details->flags, CD_EXEC_BG)) {
	    if (sudo_term_raw(io_fds[SFD_USERTTY], 0))
		ttymode = TERM_RAW;
	}
    }

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
	sudo_fatal(U_("unable to fork"));
	break;
    case 0:
	/* child */
	close(sv[0]);
	close(signal_pipe[0]);
	close(signal_pipe[1]);
	(void)fcntl(sv[1], F_SETFD, FD_CLOEXEC);
	sigprocmask(SIG_SETMASK, omask, NULL);
	/* Close the other end of the stdin/stdout/stderr pipes and exec. */
	if (io_pipe[STDIN_FILENO][1])
	    close(io_pipe[STDIN_FILENO][1]);
	if (io_pipe[STDOUT_FILENO][0])
	    close(io_pipe[STDOUT_FILENO][0]);
	if (io_pipe[STDERR_FILENO][0])
	    close(io_pipe[STDERR_FILENO][0]);
	exec_monitor(details, sv[1]);
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

    debug_return_int(child);
}

void
pty_close(struct command_status *cstat)
{
    struct io_buffer *iob;
    int n;
    debug_decl(pty_close, SUDO_DEBUG_EXEC);

    /* Flush any remaining output (the plugin already got it). */
    if (io_fds[SFD_USERTTY] != -1) {
	n = fcntl(io_fds[SFD_USERTTY], F_GETFL, 0);
	if (n != -1 && ISSET(n, O_NONBLOCK)) {
	    CLR(n, O_NONBLOCK);
	    (void) fcntl(io_fds[SFD_USERTTY], F_SETFL, n);
	}
    }
    del_io_events(false);

    /* Free I/O buffers. */
    while ((iob = SLIST_FIRST(&iobufs)) != NULL) {
	SLIST_REMOVE_HEAD(&iobufs, entries);
	if (iob->revent != NULL)
	    sudo_ev_free(iob->revent);
	if (iob->wevent != NULL)
	    sudo_ev_free(iob->wevent);
	free(iob);
    }

    /* Restore terminal settings. */
    if (io_fds[SFD_USERTTY] != -1)
	sudo_term_restore(io_fds[SFD_USERTTY], 0);

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
 * Schedule I/O events before starting the main event loop or
 * resuming from suspend.
 */
void
add_io_events(struct sudo_event_base *evbase)
{
    struct io_buffer *iob;
    debug_decl(add_io_events, SUDO_DEBUG_EXEC);

    /*
     * Schedule all readers as long as the buffer is not full.
     * Schedule writers that contain buffered data.
     * Normally, write buffers are added on demand when data is read.
     */
    SLIST_FOREACH(iob, &iobufs, entries) {
	/* Don't read/write from /dev/tty if we are not in the foreground. */
	if (iob->revent != NULL &&
	    (ttymode == TERM_RAW || !USERTTY_EVENT(iob->revent))) {
	    if (iob->len != sizeof(iob->buf)) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "added I/O revent %p, fd %d, events %d",
		    iob->revent, iob->revent->fd, iob->revent->events);
		if (sudo_ev_add(evbase, iob->revent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
	if (iob->wevent != NULL &&
	    (foreground || !USERTTY_EVENT(iob->wevent))) {
	    if (iob->len > iob->off) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "added I/O wevent %p, fd %d, events %d",
		    iob->wevent, iob->wevent->fd, iob->wevent->events);
		if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
    }
    debug_return;
}

/*
 * Flush any output buffered in iobufs or readable from fds other
 * than /dev/tty.  Removes I/O events from the event base when done.
 */
static void
del_io_events(bool nonblocking)
{
    struct io_buffer *iob;
    struct sudo_event_base *evbase;
    debug_decl(del_io_events, SUDO_DEBUG_EXEC);

    /* Remove iobufs from existing event base. */
    SLIST_FOREACH(iob, &iobufs, entries) {
	if (iob->revent != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"deleted I/O revent %p, fd %d, events %d",
		iob->revent, iob->revent->fd, iob->revent->events);
	    sudo_ev_del(NULL, iob->revent);
	}
	if (iob->wevent != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"deleted I/O wevent %p, fd %d, events %d",
		iob->wevent, iob->wevent->fd, iob->wevent->events);
	    sudo_ev_del(NULL, iob->wevent);
	}
    }

    /* Create temporary event base for flushing. */
    evbase = sudo_ev_base_alloc();
    if (evbase == NULL)
	sudo_fatal(NULL);

    /* Avoid reading from /dev/tty, just flush existing data. */
    SLIST_FOREACH(iob, &iobufs, entries) {
	/* Don't read from /dev/tty while flushing. */
	if (iob->revent != NULL && !USERTTY_EVENT(iob->revent)) {
	    if (iob->len != sizeof(iob->buf)) {
		if (sudo_ev_add(evbase, iob->revent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
	/* Flush any write buffers with data in them. */
	if (iob->wevent != NULL) {
	    if (iob->len > iob->off) {
		if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
		    sudo_fatal(U_("unable to add event to queue"));
	    }
	}
    }
    (void) sudo_ev_loop(evbase, SUDO_EVLOOP_NONBLOCK);

    /*
     * If not in non-blocking mode, make sure we flush write buffers.
     * We don't want to read from the pty or stdin since that might block
     * and the command is no longer running anyway.
     */
    if (!nonblocking) {
	/* Clear out iobufs from event base. */
	SLIST_FOREACH(iob, &iobufs, entries) {
	    if (iob->revent != NULL && !USERTTY_EVENT(iob->revent))
		sudo_ev_del(evbase, iob->revent);
	    if (iob->wevent != NULL)
		sudo_ev_del(evbase, iob->wevent);
	}

	SLIST_FOREACH(iob, &iobufs, entries) {
	    /* Flush any write buffers with data in them. */
	    if (iob->wevent != NULL) {
		if (iob->len > iob->off) {
		    if (sudo_ev_add(evbase, iob->wevent, NULL, false) == -1)
			sudo_fatal(U_("unable to add event to queue"));
		}
	    }
	}
	(void) sudo_ev_loop(evbase, 0);
     
	/* We should now have flushed all write buffers. */
	SLIST_FOREACH(iob, &iobufs, entries) {
	    if (iob->wevent != NULL) {
		if (iob->len > iob->off) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR,
			"unflushed data: wevent %p, fd %d, events %d",
			iob->wevent, iob->wevent->fd, iob->wevent->events);
		}
	    }
	}
    }

    /* Free temporary event base, removing its events. */
    sudo_ev_base_free(evbase);

    debug_return;
}

static void
deliver_signal(pid_t pid, int signo, bool from_parent)
{
    char signame[SIG2STR_MAX];
    int status;
    debug_decl(deliver_signal, SUDO_DEBUG_EXEC);

    if (signo == SIGCONT_FG)
	strlcpy(signame, "CONT_FG", sizeof(signame));
    else if (signo == SIGCONT_BG)
	strlcpy(signame, "CONT_BG", sizeof(signame));
    else if (sig2str(signo, signame) == -1)
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
    if (pid != cmnd_pid) {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "waitpid returned %d, expected pid %d", pid, cmnd_pid);
    } else {
	if (cstat->type != CMD_ERRNO) {
	    char signame[SIG2STR_MAX];

	    cstat->type = CMD_WSTATUS;
	    cstat->val = status;
	    if (WIFSTOPPED(status)) {
		if (sig2str(WSTOPSIG(status), signame) == -1)
		    snprintf(signame, sizeof(signame), "%d", WSTOPSIG(status));
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "command stopped, SIG%s", signame);
		/* Saved the foreground pgid so we can restore it later. */
		do {
		    pid = tcgetpgrp(io_fds[SFD_SLAVE]);
		} while (pid == -1 && errno == EINTR);
		if (pid != mon_pgrp)
		    cmnd_pgrp = pid;
		if (send_status(backchannel, cstat) == -1)
		    debug_return_bool(alive); /* XXX */
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

struct monitor_closure {
    struct sudo_event_base *evbase;
    struct sudo_event *errpipe_event;
    struct sudo_event *backchannel_event;
    struct sudo_event *signal_pipe_event;
    struct command_status *cstat;
    int backchannel;
    bool alive;
};

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
	    mc->alive = handle_sigchld(mc->backchannel, mc->cstat);
	    if (!mc->alive) {
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

static void
mon_errpipe_cb(int fd, int what, void *v)
{
    struct monitor_closure *mc = v;
    ssize_t n;
    debug_decl(mon_errpipe_cb, SUDO_DEBUG_EXEC);

    /* read errno or EOF from command pipe */
    n = read(fd, mc->cstat, sizeof(struct command_status));
    if (n == -1) {
	if (errno != EINTR && errno != EAGAIN) {
	    sudo_warn(U_("error reading from pipe"));
	    sudo_ev_loopbreak(mc->evbase);
	}
    } else {
	/* Got errno or EOF, either way we are done with errpipe. */
	sudo_debug_printf(SUDO_DEBUG_DIAG, "%s: type: %d, val: %d",
	    __func__, mc->cstat->type, mc->cstat->val);
	sudo_ev_del(mc->evbase, mc->errpipe_event);
	close(fd);
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

    /* read command from backchannel, should be a signal */
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
    struct sudo_event_base *evbase;
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
    if (pipe_nonblock(signal_pipe) != 0)
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
    if (io_fds[SFD_SLAVE] != -1) {
#ifdef TIOCSCTTY
	if (ioctl(io_fds[SFD_SLAVE], TIOCSCTTY, NULL) != 0)
	    sudo_fatal(U_("unable to set controlling tty"));
#else
	/* Set controlling tty by reopening slave. */
	if ((n = open(slavename, O_RDWR)) >= 0)
	    close(n);
#endif
    }

    mon_pgrp = getpgrp();	/* save a copy of our process group */

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
	(void)fcntl(errpipe[1], F_SETFD, FD_CLOEXEC);
	restore_signals();

	/* setup tty and exec command */
	exec_pty(details, &cstat, errpipe[1]);
	while (write(errpipe[1], &cstat, sizeof(cstat)) == -1) {
	    if (errno != EINTR)
		break;
	}
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
    evbase = sudo_ev_base_alloc();
    if (evbase == NULL)
	sudo_fatal(NULL);

    memset(&cstat, 0, sizeof(cstat));
    mc.cstat = &cstat;
    mc.evbase = evbase;
    mc.backchannel = backchannel;
    mc.alive = true;

    mc.signal_pipe_event = sudo_ev_alloc(signal_pipe[0],
	SUDO_EV_READ|SUDO_EV_PERSIST, mon_signal_pipe_cb, &mc);
    if (mc.signal_pipe_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(evbase, mc.signal_pipe_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    mc.errpipe_event = sudo_ev_alloc(errpipe[0],
	SUDO_EV_READ|SUDO_EV_PERSIST, mon_errpipe_cb, &mc);
    if (mc.errpipe_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(evbase, mc.errpipe_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    mc.backchannel_event = sudo_ev_alloc(backchannel,
	SUDO_EV_READ|SUDO_EV_PERSIST, mon_backchannel_cb, &mc);
    if (mc.backchannel_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(evbase, mc.backchannel_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /*
     * Wait for errno on pipe, signal on backchannel or for SIGCHLD.
     * The event loop ends when the child is no longer running and
     * the error pipe is closed.
     */
    (void) sudo_ev_loop(evbase, 0);
    if (mc.alive) {
	/* XXX An error occurred, should send a message back. */
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "Command still running after event loop exit, sending SIGKILL");
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
 * Sets up std{in,out,err} and executes the actual command.
 * Returns only if execve() fails.
 */
static void
exec_pty(struct command_details *details,
    struct command_status *cstat, int errfd)
{
    pid_t self = getpid();
    debug_decl(exec_pty, SUDO_DEBUG_EXEC);

    /* Register cleanup function */
    sudo_fatal_callback_register(pty_cleanup);

    /* Set command process group here too to avoid a race. */
    setpgid(0, self);

    /* Wire up standard fds, note that stdout/stderr may be pipes. */
    if (dup2(io_fds[SFD_STDIN], STDIN_FILENO) == -1 ||
	dup2(io_fds[SFD_STDOUT], STDOUT_FILENO) == -1 ||
	dup2(io_fds[SFD_STDERR], STDERR_FILENO) == -1)
	sudo_fatal("dup2");

    /* Wait for parent to grant us the tty if we are foreground. */
    if (foreground && !ISSET(details->flags, CD_EXEC_BG)) {
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

    /* Execute command; only returns on error. */
    exec_cmnd(details, cstat, errfd);

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
 * Remove and free any events associated with the specified
 * file descriptor present in the I/O buffers list.
 */
static void
ev_free_by_fd(struct sudo_event_base *evbase, int fd)
{
    struct io_buffer *iob;
    debug_decl(ev_free_by_fd, SUDO_DEBUG_EXEC);

    /* Deschedule any users of the fd and free up the events. */
    SLIST_FOREACH(iob, &iobufs, entries) {
	if (iob->revent != NULL) {
	    if (sudo_ev_get_fd(iob->revent) == fd) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: deleting and freeing revent %p with fd %d",
		    __func__, iob->revent, fd);
		sudo_ev_del(evbase, iob->revent);
		sudo_ev_free(iob->revent);
		iob->revent = NULL;
	    }
	}
	if (iob->wevent != NULL) {
	    if (sudo_ev_get_fd(iob->wevent) == fd) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: deleting and freeing wevent %p with fd %d",
		    __func__, iob->wevent, fd);
		sudo_ev_del(evbase, iob->wevent);
		sudo_ev_free(iob->wevent);
		iob->wevent = NULL;
	    }
	}
    }
    debug_return;
}

/*
 * Only close the fd if it is not /dev/tty or std{in,out,err}.
 * Return value is the same as close(2).
 */
static int
safe_close(int fd)
{
    debug_decl(safe_close, SUDO_DEBUG_EXEC);

    /* Avoid closing /dev/tty or std{in,out,err}. */
    if (fd < 3 || fd == io_fds[SFD_USERTTY]) {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "%s: not closing fd %d (/dev/tty)", __func__, fd);
	errno = EINVAL;
	debug_return_int(-1);
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: closing fd %d", __func__, fd);
    debug_return_int(close(fd));
}
