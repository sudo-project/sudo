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
#include <errno.h>
#include <fcntl.h>
#include <signal.h>

#include "sudo.h"
#include "sudo_event.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

/* Evaluates to true if the event has /dev/tty as its fd. */
#define USERTTY_EVENT(_ev)	(sudo_ev_get_fd((_ev)) == io_fds[SFD_USERTTY])

#define TERM_COOKED	0
#define TERM_RAW	1

/* We keep a tailq of signals to forward to child. */
struct sigforward {
    TAILQ_ENTRY(sigforward) entries;
    int signo;
};
TAILQ_HEAD(sigfwd_list, sigforward);

struct exec_closure_pty {
    pid_t child;
    sigset_t *omask;
    struct command_status *cstat;
    struct command_details *details;
    struct sudo_event_base *evbase;
    struct sudo_event *signal_event;
    struct sudo_event *sigfwd_event;
    struct sudo_event *backchannel_event;
    struct sigfwd_list sigfwd_list;
};

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
int io_fds[6] = { -1, -1, -1, -1, -1, -1}; /* XXX - sudo_exec.h? */
static bool foreground, pipeline;
static bool tty_initialized;
static int ttymode = TERM_COOKED;
static sigset_t ttyblock;
static struct io_buffer_list iobufs;
static const char *utmp_user;

static int fork_pty(struct command_details *details, int sv[], sigset_t *omask);
static void del_io_events(bool nonblocking);
static void sigwinch(int s);
static void sync_ttysize(int src, int dst);
static int safe_close(int fd);
static void ev_free_by_fd(struct sudo_event_base *evbase, int fd);
static void check_foreground(void);
static void add_io_events(struct sudo_event_base *evbase);

/*
 * Cleanup hook for sudo_fatal()/sudo_fatalx()
 */
void
pty_cleanup(void)
{
    debug_decl(cleanup, SUDO_DEBUG_EXEC);

    if (!TAILQ_EMPTY(&io_plugins) && io_fds[SFD_USERTTY] != -1)
	sudo_term_restore(io_fds[SFD_USERTTY], false);
    if (utmp_user != NULL)
	utmp_logout(slavename, 0);

    debug_return;
}

/*
 * Allocate a pty if /dev/tty is a tty.
 * Fills in io_fds[SFD_USERTTY], io_fds[SFD_MASTER], io_fds[SFD_SLAVE]
 * and slavename globals.
 */
static void
pty_setup(uid_t uid, const char *tty)
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

int
pty_make_controlling(void)
{
    if (io_fds[SFD_USERTTY] != -1) {
#ifdef TIOCSCTTY
	if (ioctl(io_fds[SFD_SLAVE], TIOCSCTTY, NULL) != 0)
	    return -1;
#else
	/* Set controlling tty by reopening slave. */
	int fd = open(slavename, O_RDWR);
	if (fd == -1)
	    return -1;
	close(fd);
#endif
    }
    return 0;
}

/* Call I/O plugin tty input log method. */
static bool
log_ttyin(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
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
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(ret);
}

/* Call I/O plugin stdin log method. */
static bool
log_stdin(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
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
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    sigprocmask(SIG_SETMASK, &omask, NULL);

    debug_return_bool(ret);
}

/* Call I/O plugin tty output log method. */
static bool
log_ttyout(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
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
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    if (!ret) {
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

    debug_return_bool(ret);
}

/* Call I/O plugin stdout log method. */
static bool
log_stdout(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
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
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    if (!ret) {
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

    debug_return_bool(ret);
}

/* Call I/O plugin stderr log method. */
static bool
log_stderr(const char *buf, unsigned int n, struct io_buffer *iob)
{
    struct plugin_container *plugin;
    sigset_t omask;
    bool ret = true;
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
		break;
	    }
	}
    }
    sudo_debug_set_active_instance(sudo_debug_instance);
    if (!ret) {
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

    debug_return_bool(ret);
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
static int
suspend_sudo(int signo)
{
    char signame[SIG2STR_MAX];
    sigaction_t sa, osa;
    int ret = 0;
    debug_decl(suspend_sudo, SUDO_DEBUG_EXEC);

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
	    ret = SIGCONT_FG; /* resume command in foreground */
	    break;
	}
	/* FALLTHROUGH */
    case SIGSTOP:
    case SIGTSTP:
	/* Flush any remaining output and deschedule I/O events. */
	del_io_events(true);

	/* Restore original tty mode before suspending. */
	if (ttymode != TERM_COOKED)
	    sudo_term_restore(io_fds[SFD_USERTTY], false);

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
	ret = ttymode == TERM_RAW ? SIGCONT_FG : SIGCONT_BG;
	break;
    }

    debug_return_int(ret);
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
io_buf_new(int rfd, int wfd,
    bool (*action)(const char *, unsigned int, struct io_buffer *),
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
static int
fork_pty(struct command_details *details, int sv[], sigset_t *omask)
{
    struct plugin_container *plugin;
    struct command_status cstat;
    int io_pipe[3][2] = { { -1, -1 }, { -1, -1 }, { -1, -1 } };
    bool interpose[3] = { false, false, false };
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

    /* Determine whether any of std{in,out,err} should be logged. */
    TAILQ_FOREACH(plugin, &io_plugins, entries) {
	if (plugin->u.io->log_stdin)
	    interpose[STDIN_FILENO] = true;
	if (plugin->u.io->log_stdout)
	    interpose[STDOUT_FILENO] = true;
	if (plugin->u.io->log_stderr)
	    interpose[STDERR_FILENO] = true;
    }

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
     * If stdin, stdout or stderr is not a tty and logging is enabled,
     * use a pipe to interpose ourselves instead of using the pty fd.
     */
    if (io_fds[SFD_STDIN] == -1 || !isatty(STDIN_FILENO)) {
	if (!interpose[STDIN_FILENO]) {
	    /* Not logging stdin, do not interpose. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stdin not a tty, not logging");
	    io_fds[SFD_STDIN] = dup(STDIN_FILENO);
	    if (io_fds[SFD_STDIN] == -1)
		sudo_fatal("dup");
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stdin not a tty, creating a pipe");
	    pipeline = true;
	    if (pipe(io_pipe[STDIN_FILENO]) != 0)
		sudo_fatal(U_("unable to create pipe"));
	    io_buf_new(STDIN_FILENO, io_pipe[STDIN_FILENO][1],
		log_stdin, &iobufs);
	    io_fds[SFD_STDIN] = io_pipe[STDIN_FILENO][0];
	}
    }
    if (io_fds[SFD_STDOUT] == -1 || !isatty(STDOUT_FILENO)) {
	if (!interpose[STDOUT_FILENO]) {
	    /* Not logging stdout, do not interpose. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stdout not a tty, not logging");
	    io_fds[SFD_STDOUT] = dup(STDOUT_FILENO);
	    if (io_fds[SFD_STDOUT] == -1)
		sudo_fatal("dup");
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stdout not a tty, creating a pipe");
	    pipeline = true;
	    if (pipe(io_pipe[STDOUT_FILENO]) != 0)
		sudo_fatal(U_("unable to create pipe"));
	    io_buf_new(io_pipe[STDOUT_FILENO][0], STDOUT_FILENO,
		log_stdout, &iobufs);
	    io_fds[SFD_STDOUT] = io_pipe[STDOUT_FILENO][1];
	}
    }
    if (io_fds[SFD_STDERR] == -1 || !isatty(STDERR_FILENO)) {
	if (!interpose[STDERR_FILENO]) {
	    /* Not logging stderr, do not interpose. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stderr not a tty, not logging");
	    io_fds[SFD_STDERR] = dup(STDERR_FILENO);
	    if (io_fds[SFD_STDERR] == -1)
		sudo_fatal("dup");
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"stderr not a tty, creating a pipe");
	    if (pipe(io_pipe[STDERR_FILENO]) != 0)
		sudo_fatal(U_("unable to create pipe"));
	    io_buf_new(io_pipe[STDERR_FILENO][0], STDERR_FILENO,
		log_stderr, &iobufs);
	    io_fds[SFD_STDERR] = io_pipe[STDERR_FILENO][1];
	}
    }

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
	if (io_pipe[STDIN_FILENO][1] != -1)
	    close(io_pipe[STDIN_FILENO][1]);
	if (io_pipe[STDOUT_FILENO][0] != -1)
	    close(io_pipe[STDOUT_FILENO][0]);
	if (io_pipe[STDERR_FILENO][0] != -1)
	    close(io_pipe[STDERR_FILENO][0]);
	/*                      
	 * If stdin/stdout is not a tty, start command in the background
	 * since it might be part of a pipeline that reads from /dev/tty.
	 * In this case, we rely on the command receiving SIGTTOU or SIGTTIN
	 * when it needs access to the controlling tty.
	 */                                                              
	exec_monitor(details, foreground && !pipeline, sv[1]);
	cstat.type = CMD_ERRNO;
	cstat.val = errno;
	while (send(sv[1], &cstat, sizeof(cstat), 0) == -1) {
	    if (errno != EINTR)
		break;
	}
	_exit(1);
    }

    /* Close the other end of the stdin/stdout/stderr pipes. */
    if (io_pipe[STDIN_FILENO][0] != -1)
	close(io_pipe[STDIN_FILENO][0]);
    if (io_pipe[STDOUT_FILENO][1] != -1)
	close(io_pipe[STDOUT_FILENO][1]);
    if (io_pipe[STDERR_FILENO][1] != -1)
	close(io_pipe[STDERR_FILENO][1]);

    debug_return_int(child);
}

static void
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
	sudo_term_restore(io_fds[SFD_USERTTY], false);

    /* Update utmp */
    if (utmp_user != NULL)
	utmp_logout(slavename, cstat->type == CMD_WSTATUS ? cstat->val : 0);
    debug_return;
}

/*
 * Schedule a signal to be forwarded.
 */
static void
schedule_signal(struct exec_closure_pty *ec, int signo)
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
    TAILQ_INSERT_TAIL(&ec->sigfwd_list, sigfwd, entries);

    if (sudo_ev_add(ec->evbase, ec->sigfwd_event, NULL, true) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    debug_return;
}

static void
backchannel_cb(int fd, int what, void *v)
{
    struct exec_closure_pty *ec = v;
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
	    /* XXX - need new CMD_ type for monitor errors. */
	    errno = n ? EIO : ECONNRESET;
	    ec->cstat->type = CMD_ERRNO;
	    ec->cstat->val = errno;
	    sudo_ev_loopbreak(ec->evbase);
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
	sigprocmask(SIG_SETMASK, ec->omask, NULL);
	break;
    case CMD_WSTATUS:
	if (WIFSTOPPED(ec->cstat->val)) {
	    /* Suspend parent and tell child how to resume on return. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"child stopped, suspending parent");
	    n = suspend_sudo(WSTOPSIG(ec->cstat->val));
	    schedule_signal(ec, n);
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
 * Handle changes to the monitors's status (SIGCHLD).
 */
static void
handle_sigchld_pty(struct exec_closure_pty *ec)
{
    int n, status;
    pid_t pid;
    debug_decl(handle_sigchld_pty, SUDO_DEBUG_EXEC)

    /*
     * Monitor process was signaled; wait for it as needed.
     */
    do {
	pid = waitpid(ec->child, &status, WUNTRACED|WNOHANG);
    } while (pid == -1 && errno == EINTR);
    if (pid == ec->child) {
	/*
	 * If the monitor dies we get notified via backchannel_cb().
	 * If it was stopped, we should stop too (the command keeps
	 * running in its pty) and continue it when we come back.
	 */
	if (WIFSTOPPED(status)) {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"monitor stopped, suspending sudo");
	    n = suspend_sudo(WSTOPSIG(status));
	    kill(pid, SIGCONT);
	    schedule_signal(ec, n);
	    /* Re-enable I/O events and restart event loop. */
	    add_io_events(ec->evbase);
	    sudo_ev_loopcontinue(ec->evbase);
	} else if (WIFSIGNALED(status)) {
	    char signame[SIG2STR_MAX];
	    if (sig2str(WTERMSIG(status), signame) == -1)
		snprintf(signame, sizeof(signame), "%d", WTERMSIG(status));
	    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: monitor (%d) killed, SIG%s",
		__func__, (int)ec->child, signame);
	    ec->child = -1;
	} else {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"%s: monitor exited, status %d", __func__, WEXITSTATUS(status));
	    ec->child = -1;
	}
    }
    debug_return;
}

/* Signal pipe callback */
static void
signal_pipe_cb(int fd, int what, void *v)
{
    struct exec_closure_pty *ec = v;
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
	    handle_sigchld_pty(ec);
	} else if (ec->child != -1) {
	    /* Schedule signo to be forwared to the child. */
	    schedule_signal(ec, signo);
	    /* Restart event loop to service signal immediately. */
	    sudo_ev_loopcontinue(ec->evbase);
	}
    } while (ec->child != -1);
    debug_return;
}

/*
 * Forward signals in sigfwd_list to the monitor so it can
 * deliver them to the command.
 */
static void
sigfwd_cb(int sock, int what, void *v)
{
    struct exec_closure_pty *ec = v;
    char signame[SIG2STR_MAX];
    struct sigforward *sigfwd;
    struct command_status cstat;
    ssize_t nsent;
    debug_decl(sigfwd_cb, SUDO_DEBUG_EXEC)

    while ((sigfwd = TAILQ_FIRST(&ec->sigfwd_list)) != NULL) {
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
	TAILQ_REMOVE(&ec->sigfwd_list, sigfwd, entries);
	free(sigfwd);
	if (nsent != sizeof(cstat)) {
	    if (errno == EPIPE) {
		sudo_debug_printf(SUDO_DEBUG_ERROR,
		    "broken pipe writing to child over backchannel");
		/* Other end of socket gone, empty out sigfwd_list. */
		while ((sigfwd = TAILQ_FIRST(&ec->sigfwd_list)) != NULL) {
		    TAILQ_REMOVE(&ec->sigfwd_list, sigfwd, entries);
		    free(sigfwd);
		}
		/* XXX - child (monitor) is dead, we should exit too? */
	    }
	    break;
	}
    }
}

/*
 * Fill in the exec closure and setup initial exec events.
 * Allocates events for the signal pipe and backchannel.
 * Forwarded signals on the backchannel are enabled on demand.
 */
static void
fill_exec_closure_pty(struct exec_closure_pty *ec, struct command_status *cstat,
    struct command_details *details, pid_t child, sigset_t *omask,
    int backchannel)
{
    debug_decl(fill_exec_closure_pty, SUDO_DEBUG_EXEC)

    /* Fill in the non-event part of the closure. */
    ec->child = child;
    ec->omask = omask;
    ec->cstat = cstat;
    ec->details = details;
    TAILQ_INIT(&ec->sigfwd_list);

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

    /* Event for command status via backchannel. */
    ec->backchannel_event = sudo_ev_alloc(backchannel,
	SUDO_EV_READ|SUDO_EV_PERSIST, backchannel_cb, ec);
    if (ec->backchannel_event == NULL)
	sudo_fatal(NULL);
    if (sudo_ev_add(ec->evbase, ec->backchannel_event, NULL, false) == -1)
	sudo_fatal(U_("unable to add event to queue"));

    /* The signal forwarding event gets added on demand. */
    ec->sigfwd_event = sudo_ev_alloc(backchannel,
	SUDO_EV_WRITE, sigfwd_cb, ec);
    if (ec->sigfwd_event == NULL)
	sudo_fatal(NULL);

    sudo_debug_printf(SUDO_DEBUG_INFO, "signal pipe fd %d\n", signal_pipe[0]);
    sudo_debug_printf(SUDO_DEBUG_INFO, "backchannel fd %d\n", backchannel);
}

/*
 * Execute a command in a pty, potentially with I/O loggging, and
 * wait for it to finish.
 * This is a little bit tricky due to how POSIX job control works and
 * we fact that we have two different controlling terminals to deal with.
 */
int
exec_pty(struct command_details *details, struct command_status *cstat)
{
    struct sigforward *sigfwd, *sigfwd_next;
    struct exec_closure_pty ec;
    sigaction_t sa;
    sigset_t omask;
    pid_t child;
    int sv[2];
    debug_decl(exec_pty, SUDO_DEBUG_EXEC)

    /*
     * Allocate a pty.
     */
    if (ISSET(details->flags, CD_SET_UTMP))
	utmp_user = details->utmp_user ? details->utmp_user : user_details.username;
    sudo_debug_printf(SUDO_DEBUG_INFO, "allocate pty for I/O logging");
    pty_setup(details->euid, user_details.tty);

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
#ifdef SIGINFO
    if (sudo_sigaction(SIGINFO, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGINFO);
#endif

    /*
     * Unlike the non-pty case, we can use our normal signal handler
     * for tty-generated signals triggered by the user.
     */
    if (sudo_sigaction(SIGINT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGINT);
    if (sudo_sigaction(SIGQUIT, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGQUIT);
    if (sudo_sigaction(SIGTSTP, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTSTP);

    /*
     * We don't want to receive SIGTTIN/SIGTTOU, getting EIO is preferable.
     */
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_IGN;
    if (sudo_sigaction(SIGTTIN, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTIN);
    if (sudo_sigaction(SIGTTOU, &sa, NULL) != 0)
	sudo_warn(U_("unable to set handler for signal %d"), SIGTTOU);

    /*
     * The policy plugin's session init must be run before we fork
     * or certain pam modules won't be able to track their state.
     */
    if (policy_init_session(details) != true)
	sudo_fatalx(U_("policy plugin failed session initialization"));

    /*
     * Child will run the command in the pty, parent will pass data
     * to and from pty.
     * XXX - inline fork_pty or refactor differently?
     */
    child = fork_pty(details, sv, &omask);
    close(sv[1]);

    /* No longer need execfd. */
    if (details->execfd != -1) {
	close(details->execfd);
	details->execfd = -1;
    }

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
    fill_exec_closure_pty(&ec, cstat, details, child, &omask, sv[0]);

    /*
     * In the event loop we pass input from user tty to master
     * and pass output from master to stdout and IO plugin.
     */
    add_io_events(ec.evbase);
    if (sudo_ev_loop(ec.evbase, 0) == -1)
	sudo_warn(U_("error in event loop"));
    if (sudo_ev_got_break(ec.evbase)) {
	/* error from callback */
	sudo_debug_printf(SUDO_DEBUG_ERROR, "event loop exited prematurely");
    }

    /* Flush any remaining output and free pty-related memory. */
    pty_close(cstat);

    /* Free things up. */
    sudo_ev_base_free(ec.evbase);
    sudo_ev_free(ec.sigfwd_event);
    sudo_ev_free(ec.signal_event);
    sudo_ev_free(ec.backchannel_event);
    TAILQ_FOREACH_SAFE(sigfwd, &ec.sigfwd_list, entries, sigfwd_next) {
	free(sigfwd);
    }
    debug_return_int(cstat->type == CMD_ERRNO ? -1 : 0);
}

/*
 * Schedule I/O events before starting the main event loop or
 * resuming from suspend.
 */
static void
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
