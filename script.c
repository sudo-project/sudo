/*
 * Copyright (c) 2009 Todd C. Miller <Todd.Miller@courtesan.com>
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
# ifdef HAVE_TERMIO_H
#  include <termio.h>
# else
#  include <sgtty.h>
# endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
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
#ifdef HAVE_ZLIB
# include <zlib.h>
#endif

#include "sudo.h"

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

#define SFD_MASTER	0
#define SFD_SLAVE	1
#define SFD_LOG		2
#define SFD_OUTPUT	3
#define SFD_TIMING	4
#define SFD_USERTTY	5

#define TERM_COOKED	0
#define TERM_CBREAK	1
#define TERM_RAW	2

struct script_buf {
    int len; /* buffer length (how much read in) */
    int off; /* write position (how much already consumed) */
    char buf[16 * 1024];
};

static int script_fds[6];

static sig_atomic_t alive = 1;
static sig_atomic_t recvsig = 0;
static sig_atomic_t ttymode = TERM_COOKED;
static sig_atomic_t foreground = 0;
static sig_atomic_t tty_initialized = 0;

static sigset_t ttyblock;

static pid_t parent, child;
static int child_status;

static char slavename[PATH_MAX];

static int suspend_parent __P((int signo, struct script_buf *output,
    struct timeval *then, struct timeval *now, void *ofile, void *tfile));
static void flush_output __P((struct script_buf *output, struct timeval *then,
    struct timeval *now, void *ofile, void *tfile));
static void handler __P((int s));
static void script_child __P((char *path, char *argv[], int, int));
static void script_run __P((char *path, char *argv[], int));
static void sigchild __P((int s));
static void sigcont __P((int s));
static void sigwinch __P((int s));
static void sync_winsize __P((int src, int dst));

extern int get_pty __P((int *master, int *slave, char *name, size_t namesz));

/*
 * TODO: run monitor as root?
 */

static int
fdcompar(v1, v2)
    const void *v1;
    const void *v2;
{
    int i = *(int *)v1;
    int j = *(int *)v2;

    return(script_fds[i] - script_fds[j]);
}

void
script_nextid()
{
    struct stat sb;
    char buf[32], *ep;
    int fd, i, ch;
    unsigned long id = 0;
    int len;
    ssize_t nread;
    char pathbuf[PATH_MAX];

    /*
     * Create _PATH_SUDO_TRANSCRIPT if it doesn't already exist.
     */
    if (stat(_PATH_SUDO_TRANSCRIPT, &sb) != 0) {
	if (mkdir(_PATH_SUDO_TRANSCRIPT, S_IRWXU) != 0)
	    log_error(USE_ERRNO, "Can't mkdir %s", _PATH_SUDO_TRANSCRIPT);
    } else if (!S_ISDIR(sb.st_mode)) {
	log_error(0, "%s exists but is not a directory (0%o)",
	    _PATH_SUDO_TRANSCRIPT, (unsigned int) sb.st_mode);
    }

    /*
     * Open sequence file
     */
    len = snprintf(pathbuf, sizeof(pathbuf), "%s/seq", _PATH_SUDO_TRANSCRIPT);
    if (len <= 0 || len >= sizeof(pathbuf)) {
	errno = ENAMETOOLONG;
	log_error(USE_ERRNO, "%s/seq", pathbuf);
    }
    fd = open(pathbuf, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
    if (fd == -1)
	log_error(USE_ERRNO, "cannot open %s", pathbuf);
    lock_file(fd, SUDO_LOCK);

    /* Read seq number (base 36). */
    nread = read(fd, buf, sizeof(buf));
    if (nread != 0) {
	if (nread == -1)
	    log_error(USE_ERRNO, "cannot read %s", pathbuf);
	id = strtoul(buf, &ep, 36);
	if (buf == ep || id >= 2176782336U)
	    log_error(0, "invalid sequence number %s", pathbuf);
    }
    id++;

    /*
     * Convert id to a string and stash in sudo_user.sessid.
     * Note that that least significant digits go at the end of the string.
     */
    for (i = 5; i >= 0; i--) {
	ch = id % 36;
	id /= 36;
	buf[i] = ch < 10 ? ch + '0' : ch - 10 + 'A';
    }
    buf[6] = '\n';

    /* Stash id logging purposes */
    memcpy(sudo_user.sessid, buf, 6);
    sudo_user.sessid[6] = '\0';

    /* Rewind and overwrite old seq file. */
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1 || write(fd, buf, 7) != 7)
	log_error(USE_ERRNO, "Can't write to %s", pathbuf);
    close(fd);
}

static int
build_idpath(pathbuf)
    char *pathbuf;
{
    struct stat sb;
    int i, len;

    if (sudo_user.sessid[0] == '\0')
	log_error(0, "tried to build a session id path without a session id");

    /*
     * Path is of the form /var/log/sudo-session/00/00/01.
     */
    len = snprintf(pathbuf, PATH_MAX, "%s/%c%c/%c%c/%c%c", _PATH_SUDO_TRANSCRIPT,
	sudo_user.sessid[0], sudo_user.sessid[1], sudo_user.sessid[2],
	sudo_user.sessid[3], sudo_user.sessid[4], sudo_user.sessid[5]);
    if (len <= 0 && len >= PATH_MAX) {
	errno = ENAMETOOLONG;
	log_error(USE_ERRNO, "%s/%s", _PATH_SUDO_TRANSCRIPT, sudo_user.sessid);
    }

    /*
     * Create the intermediate subdirs as needed.
     */
    for (i = 6; i > 0; i -= 3) {
	pathbuf[len - i] = '\0';
	if (stat(pathbuf, &sb) != 0) {
	    if (mkdir(pathbuf, S_IRWXU) != 0)
		log_error(USE_ERRNO, "Can't mkdir %s", pathbuf);
	} else if (!S_ISDIR(sb.st_mode)) {
	    log_error(0, "%s: %s", pathbuf, strerror(ENOTDIR));
	}
	pathbuf[len - i] = '/';
    }

    return(len);
}

void
script_setup()
{
    char pathbuf[PATH_MAX];
    int len;

    script_fds[SFD_USERTTY] = open(_PATH_TTY, O_RDWR|O_NOCTTY, 0);
    if (script_fds[SFD_USERTTY] == -1)
	log_error(0, "tty required for transcript support"); /* XXX */

    if (!get_pty(&script_fds[SFD_MASTER], &script_fds[SFD_SLAVE],
	slavename, sizeof(slavename)))
	log_error(USE_ERRNO, "Can't get pty");

    /*
     * Build a path containing the session id split into two-digit subdirs,
     * so ID 000001 becomes /var/log/sudo-session/00/00/01.
     */
    len = build_idpath(pathbuf);

    /*
     * We create 3 files: a log file, one for the raw session data,
     * and one for the timing info.
     */
    script_fds[SFD_LOG] = open(pathbuf, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
    if (script_fds[SFD_LOG] == -1)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);

    strlcat(pathbuf, ".scr", sizeof(pathbuf));
    script_fds[SFD_OUTPUT] = open(pathbuf, O_CREAT|O_EXCL|O_WRONLY,
	S_IRUSR|S_IWUSR);
    if (script_fds[SFD_OUTPUT] == -1)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);

    pathbuf[len] = '\0';
    strlcat(pathbuf, ".tim", sizeof(pathbuf));
    script_fds[SFD_TIMING] = open(pathbuf, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
    if (script_fds[SFD_TIMING] == -1)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);
}

int
script_duplow(fd)
    int fd;
{
    int i, j, indices[6];

    /* sort fds so we can dup them safely */
    for (i = 0; i < 6; i++)
	indices[i] = i;
    qsort(indices, 6, sizeof(int), fdcompar);

    /* Move pty master/slave and session fds to low numbered fds. */
    for (i = 0; i < 6; i++) {
	j = indices[i];
	if (script_fds[j] != fd) {
#ifdef HAVE_DUP2
	    dup2(script_fds[j], fd);
#else
	    close(fd);
	    dup(script_fds[j]);
	    close(script_fds[j]);
#endif
	}
	script_fds[j] = fd++;
    }
    return(fd);
}

/* Update output and timing files. */
static void
log_output(buf, n, then, now, ofile, tfile)
    char *buf;
    int n;
    struct timeval *then;
    struct timeval *now;
#ifdef HAVE_ZLIB
    gzFile ofile;
    gzFile tfile;
#else
    FILE *ofile;
    FILE *tfile;
#endif
{
    struct timeval tv;
    sigset_t omask;

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

#ifdef HAVE_ZLIB
    gzwrite(ofile, buf, n);
#else
    fwrite(buf, 1, n, ofile);
#endif
    timersub(now, then, &tv);
#ifdef HAVE_ZLIB
    gzprintf(tfile, "%f %d\n",
	tv.tv_sec + ((double)tv.tv_usec / 1000000), n);
#else
    fprintf(tfile, "%f %d\n",
	tv.tv_sec + ((double)tv.tv_usec / 1000000), n);
#endif
    then->tv_sec = now->tv_sec;
    then->tv_usec = now->tv_usec;

    sigprocmask(SIG_SETMASK, &omask, NULL);
}

/*
 * Suspend sudo if the underlying command is suspended.
 * Returns SIGUSR1 if the child should be resume in foreground else SIGUSR2.
 */
static int
suspend_parent(signo, output, then, now, ofile, tfile)
    int signo;
    struct script_buf *output;
    struct timeval *then;
    struct timeval *now;
    void *ofile;
    void *tfile;
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
	if (foreground) {
	    if (ttymode != TERM_RAW) {
		do {
		    n = term_raw(script_fds[SFD_USERTTY], 1, 0);
		} while (!n && errno == EINTR);
		ttymode = TERM_RAW;
	    }
	    rval = SIGUSR1; /* resume child in foreground */
	    break;
	}
	ttymode = TERM_RAW;
	/* FALLTHROUGH */
    case SIGTSTP:
	/* Flush any remaining output to master tty. */
	flush_output(output, then, now, ofile, tfile);

	/* Restore original tty mode before suspending. */
	if (oldmode != TERM_COOKED) {
	    do {
		n = term_restore(script_fds[SFD_USERTTY], 0);
	    } while (!n && errno == EINTR);
	}

	/* Suspend self and continue child when we resume. */
	sa.sa_handler = SIG_DFL;
	sigaction(signo, &sa, &osa);
#ifdef SCRIPT_DEBUG
	warningx("kill parent %d", signo);
#endif
	kill(parent, signo);

	/*
	 * Only modify term if we are foreground process and either
	 * the old tty mode was not cooked or child got SIGTT{IN,OU}
	 */
#ifdef SCRIPT_DEBUG
	warningx("parent is in %sground, ttymode %d -> %d",
	    foreground ? "fore" : "back", oldmode, ttymode);
#endif

	if (ttymode != TERM_COOKED) {
	    if (foreground) {
		/* Set raw/cbreak mode. */
		do {
		    n = term_raw(script_fds[SFD_USERTTY], 1,
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
script_execv(path, argv)
    char *path;
    char *argv[];
{
    sigaction_t sa;
    struct script_buf input, output;
    struct timeval now, then;
    int n, nready, exitcode = 1;
    int relaysig, sv[2];
    fd_set *fdsr, *fdsw;
    FILE *idfile;
#ifdef HAVE_ZLIB
    gzFile ofile, tfile;
#else
    FILE *ofile, *tfile;
#endif
    int rbac_enabled = 0;

#ifdef HAVE_SELINUX
    rbac_enabled = is_selinux_enabled() > 0 && user_role != NULL;
    if (rbac_enabled) {
	selinux_prefork(user_role, user_type, script_fds[SFD_SLAVE]);
	/* Re-open slave fd after it has been relabeled */
	close(script_fds[SFD_SLAVE]);
	script_fds[SFD_SLAVE] = open(slavename, O_RDWR|O_NOCTTY, 0);
	if (script_fds[SFD_SLAVE] == -1)
	    log_error(USE_ERRNO, "cannot open %s", slavename);
    }
#endif

    /* Are we the foreground process? */
    parent = getpid(); /* so child can pass signals back to us */
    foreground = tcgetpgrp(script_fds[SFD_USERTTY]) == parent;

    /* So we can block tty-generated signals */
    sigemptyset(&ttyblock);
    sigaddset(&ttyblock, SIGINT);
    sigaddset(&ttyblock, SIGQUIT);
    sigaddset(&ttyblock, SIGTSTP);
    sigaddset(&ttyblock, SIGTTIN);
    sigaddset(&ttyblock, SIGTTOU);

    /* Setup signal handlers window size changes and child stop/exit */
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = sigwinch;
    sigaction(SIGWINCH, &sa, NULL);

    /* XXX - now get command status via sv (still need to detect child death) */
    sa.sa_handler = sigchild;
    sigaction(SIGCHLD, &sa, NULL);

    /* Ignore SIGPIPE from other end of socketpair. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    /* To update foreground/background state. */
    sa.sa_handler = sigcont;
    sigaction(SIGCONT, &sa, NULL);

    /* Signals to relay from parent to child. */
    sa.sa_flags = 0; /* do not restart syscalls for these */
    sa.sa_handler = handler;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTSTP, &sa, NULL);
#if 0 /* XXX - keep? */
    sigaction(SIGTTIN, &sa, NULL);
    sigaction(SIGTTOU, &sa, NULL);
#endif

    /*
     * We communicate with the child over a bi-directional pipe.
     * Parent sends signal info to child and child sends back wait status.
     */
    if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) != 0)
	log_error(USE_ERRNO, "cannot create sockets");

    if (foreground) {
	/* Copy terminal attrs from user tty -> pty slave. */
	if (term_copy(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE], 0)) {
	    tty_initialized = 1;
	    sync_winsize(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE]);
	}

	/* Start out in cbreak mode. */
	do {
	    n = term_raw(script_fds[SFD_USERTTY], 1, 1);
	} while (!n && errno == EINTR);
	if (!n)
	    log_error(USE_ERRNO, "Can't set terminal to raw mode");
	ttymode = TERM_CBREAK;
    }

    /*
     * Child will run the command in the pty, parent will pass data
     * to and from pty.
     */
    child = fork();
    switch (child) {
    case -1:
	log_error(USE_ERRNO, "fork");
	break;
    case 0:
	close(sv[0]);
	script_child(path, argv, sv[1], rbac_enabled);
	/* NOTREACHED */
	break;
    }
    close(sv[1]);

    if ((idfile = fdopen(script_fds[SFD_LOG], "w")) == NULL)
	log_error(USE_ERRNO, "fdopen");
#ifdef HAVE_ZLIB
    if ((ofile = gzdopen(script_fds[SFD_OUTPUT], "w")) == NULL)
	log_error(USE_ERRNO, "gzdopen");
    if ((tfile = gzdopen(script_fds[SFD_TIMING], "w")) == NULL)
	log_error(USE_ERRNO, "gzdopen");
#else
    if ((ofile = fdopen(script_fds[SFD_OUTPUT], "w")) == NULL)
	log_error(USE_ERRNO, "fdopen");
    if ((tfile = fdopen(script_fds[SFD_TIMING], "w")) == NULL)
	log_error(USE_ERRNO, "fdopen");
#endif

    gettimeofday(&then, NULL);

    /* XXX - log more stuff?  window size? environment? */
    fprintf(idfile, "%ld:%s:%s:%s:%s\n", then.tv_sec, user_name,
	runas_pw->pw_name, runas_gr ? runas_gr->gr_name : "", user_tty);
    fprintf(idfile, "%s\n", user_cwd);
    fprintf(idfile, "%s%s%s\n", user_cmnd, user_args ? " " : "",
	user_args ? user_args : "");
    fclose(idfile);

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

    /*
     * In the event loop we pass input from user tty to master
     * and pass output from master to stdout and ofile.  Note that
     * we've set things up such that master is > 3 (see sudo.c).
     */
    fdsr = (fd_set *)emalloc2(howmany(sv[0] + 1, NFDBITS), sizeof(fd_mask));
    fdsw = (fd_set *)emalloc2(howmany(sv[0] + 1, NFDBITS), sizeof(fd_mask));
    zero_bytes(&input, sizeof(input));
    zero_bytes(&output, sizeof(output));
    while (alive) {
       /* XXX */
	if (!relaysig && recvsig != SIGCHLD) {
	    relaysig = recvsig;
	    recvsig = 0;
	}

	if (input.off == input.len)
	    input.off = input.len = 0;
	if (output.off == output.len)
	    output.off = output.len = 0;

	zero_bytes(fdsw, howmany(sv[0] + 1, NFDBITS) * sizeof(fd_mask));
	zero_bytes(fdsr, howmany(sv[0] + 1, NFDBITS) * sizeof(fd_mask));

	if (ttymode == TERM_RAW && input.len != sizeof(input.buf))
	    FD_SET(script_fds[SFD_USERTTY], fdsr);
	if (output.len != sizeof(output.buf))
	    FD_SET(script_fds[SFD_MASTER], fdsr);
	if (output.len > output.off)
	    FD_SET(STDOUT_FILENO, fdsw);
	if (input.len > input.off)
	    FD_SET(script_fds[SFD_MASTER], fdsw);
	FD_SET(sv[0], fdsr);
	if (relaysig)
	    FD_SET(sv[0], fdsw);

	nready = select(sv[0] + 1, fdsr, fdsw, NULL, NULL);
	if (nready == -1) {
	    if (errno == EINTR)
		continue;
	    log_error(USE_ERRNO, "select failed");
	}
	if (FD_ISSET(sv[0], fdsr)) {
	    /* read child status */
	    n = read(sv[0], &child_status, sizeof(child_status));
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		if (errno != EAGAIN)
		    break;
	    } else if (n != sizeof(child_status)) {
		break; /* EOF? */
	    }
	    if (WIFSTOPPED(child_status)) {
		/* Suspend parent and tell child how to resume on return. */
#ifdef SCRIPT_DEBUG
		warningx("child stopped, suspending parent");
#endif
		relaysig = suspend_parent(WSTOPSIG(child_status),
		    &output, &then, &now, ofile, tfile);
		/* XXX - write relaysig immediately? */
		continue;
	    } else {
		/* Child exited or was killed, either way we are done. */
		if (WIFEXITED(child_status))
		    exitcode = WEXITSTATUS(child_status);
		else if (WIFSIGNALED(child_status))
		    exitcode = WTERMSIG(child_status) | 128;
		break;
	    }
	}
	if (FD_ISSET(sv[0], fdsw)) {
	    /* XXX - we rely on child to be suspended before we suspend us */
	    n = write(sv[0], &relaysig, sizeof(relaysig));
	    relaysig = 0;
	    if (n == -1) {
		if (errno == EINTR)
		    continue;
		if (errno != EAGAIN)
		    break;
	    } else if (n != sizeof(relaysig)) {
		break; /* should not happen */
	    }
	}
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
	    gettimeofday(&now, NULL);
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

		/* Update output and timing files. */
		log_output(output.buf + output.len, n, &then, &now, ofile, tfile);
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

    /* Flush any remaining output to stdout (already updated output file). */
    n = fcntl(STDOUT_FILENO, F_GETFL, 0);
    if (n != -1) {
	n &= ~O_NONBLOCK;
	(void) fcntl(STDOUT_FILENO, F_SETFL, n);
    }
    flush_output(&output, &then, &now, ofile, tfile);

#ifdef HAVE_ZLIB
    gzclose(ofile);
    gzclose(tfile);
#else
    fclose(ofile);
    fclose(tfile);
#endif

#ifdef HAVE_STRSIGNAL
    if (WIFSIGNALED(child_status)) {
	int signo = WTERMSIG(child_status);
	if (signo && signo != SIGINT && signo != SIGPIPE) {
	    char *reason = strsignal(signo);
	    write(STDOUT_FILENO, reason, strlen(reason));
	    if (WCOREDUMP(child_status))
		write(STDOUT_FILENO, " (core dumped)", 14);
	    write(STDOUT_FILENO, "\n", 1);
	}
    }
#endif

    do {
	n = term_restore(script_fds[SFD_USERTTY], 0);
    } while (!n && errno == EINTR);

    exit(exitcode);
}

void
script_child(path, argv, backchannel, rbac_enabled)
    char *path;
    char *argv[];
    int backchannel;
    int rbac_enabled;
{
    sigaction_t sa;
    pid_t pid, self = getpid();
    int nread, signo, status;
#ifndef TIOCSCTTY
    int n;
#endif

    recvsig = 0;

    /* Close unused fds. */
    close(script_fds[SFD_MASTER]);
    close(script_fds[SFD_LOG]);
    close(script_fds[SFD_OUTPUT]);
    close(script_fds[SFD_TIMING]);
    close(script_fds[SFD_USERTTY]);

    /* Reset signal handlers. */
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    sigaction(SIGCONT, &sa, NULL);
    sigaction(SIGWINCH, &sa, NULL);

    /* Ignore any SIGTT{IN,OU} or SIGPIPE we get. */
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGTTIN, &sa, NULL);
    sigaction(SIGTTOU, &sa, NULL);

    /* We want SIGCHLD to interrupt us. */
    sa.sa_flags = 0; /* do not restart syscalls for these signals. */
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
	_exit(1);
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
	log_error(USE_ERRNO, "unable to set controlling tty");
#else
    /* Set controlling tty by reopening slave. */
    if ((n = open(slavename, O_RDWR)) >= 0)
	close(n);
#endif

    /* Start command and wait for it to stop or exit */
    child = fork();
    if (child == -1) {
	warning("Can't fork");
	_exit(1);
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

	/* setup tty and exec command */
	script_run(path, argv, rbac_enabled);
	warning("unable to execute %s", path);
	_exit(127);
    }

    /*
     * Put child in its own process group.  We always start the command
     * in the background until it needs to be the foreground process.
     */
    setpgid(child, child);

    /* Wait for signal on backchannel or for SIGCHLD */
    for (;;) {
	/* Read child status, assumes recvsig can only be SIGCHLD */
	while (recvsig) {
	    recvsig = 0;
	    /* read child status and relay to parent */
	    do {
		pid = waitpid(child, &status, WUNTRACED|WNOHANG);
	    } while (pid == -1 && errno == EINTR);
	    if (pid == child) {
#ifdef SCRIPT_DEBUG
		if (WIFSTOPPED(status))
		    warningx("command stopped, signal %d", WSTOPSIG(status));
		else if (WIFSIGNALED(status))
		    warningx("command killed, signal %d", WTERMSIG(status));
		else
		    warningx("command exited?");
#endif
		if (write(backchannel, &status, sizeof(status)) != sizeof(status))
		    break; /* XXX - error, kill child and exit */
#ifdef SCRIPT_DEBUG
		warningx("sent signo to parent");
#endif
		if (!WIFSTOPPED(status)) {
		    _exit(1); /* child dead */
		}
	    }
	}
	nread = read(backchannel, &signo, sizeof(signo));
	if (nread == -1) {
	    if (errno != EINTR)
		break; /* XXX - error, kill child and exit */
	    continue;
	}
	if (nread != sizeof(signo)) {
	    /* EOF? */
	    break;
	}

	/* Handle signal from parent. */
#ifdef SCRIPT_DEBUG
	warningx("signal %d from parent", signo);
#endif
	switch (signo) {
	case SIGKILL:
	    _exit(1);
	    /* NOTREACHED */
	case SIGHUP:
	case SIGTERM:
	case SIGINT:
	case SIGQUIT:
	case SIGTSTP:
	    /* relay signal to child */
	    killpg(child, signo);
	    break;
	case SIGUSR1:
	    /* foreground process, grant it controlling tty. */
	    do {
		status = tcsetpgrp(script_fds[SFD_SLAVE], child);
	    } while (status == -1 && errno == EINTR);
	    killpg(child, SIGCONT);
	    break;
	case SIGUSR2:
	    /* background process, I take controlling tty. */
	    do {
		status = tcsetpgrp(script_fds[SFD_SLAVE], self);
	    } while (status == -1 && errno == EINTR);
	    killpg(child, SIGCONT);
	    break;
	default:
	    /* XXX - warn? */
	    break;
	}
    }

    _exit(1);
}

static void
flush_output(output, then, now, ofile, tfile)
    struct script_buf *output;
    struct timeval *then;
    struct timeval *now;
    void *ofile;
    void *tfile;
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
	log_output(output->buf, n, &then, &now, ofile, tfile);
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
script_run(path, argv, rbac_enabled)
    char *path;
    char *argv[];
    int rbac_enabled;
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

#ifdef HAVE_SELINUX
    if (rbac_enabled)
	selinux_execv(path, argv);
    else
#endif
    execv(path, argv);
}

static void
sync_winsize(src, dst)
    int src;
    int dst;
{
#ifdef TIOCGWINSZ
    struct winsize win;
    pid_t pgrp;

    if (ioctl(src, TIOCGWINSZ, &win) == 0) {
	    ioctl(dst, TIOCSWINSZ, &win);
#ifdef TIOCGPGRP
	    if (ioctl(dst, TIOCGPGRP, &pgrp) == 0)
		    killpg(pgrp, SIGWINCH);
#endif
    }
#endif
}

/*
 * Handler for SIGCONT in parent
 */
static void
sigcont(s)
    int s;
{
    int serrno = errno;

    /* Did we get continued in the foreground or background? */
    foreground = tcgetpgrp(script_fds[SFD_USERTTY]) == parent;

    if (foreground && !tty_initialized) {
	if (term_copy(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE], 0)) {
	    tty_initialized = 1;
	    sync_winsize(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE]);
	}
    }

    errno = serrno;
}

/*
 * Handler for SIGCHLD in parent
 */
static void
sigchild(s)
    int s;
{
    pid_t pid;
    int serrno = errno;

    do {
	pid = waitpid(child, &child_status, WNOHANG | WUNTRACED);
    } while (pid == -1 && errno == EINTR);
    if (pid == child) {
	if (WIFSTOPPED(child_status))
	    recvsig = WSTOPSIG(child_status);
	else
	    alive = 0;
    }

    errno = serrno;
}

/*
 * Generic handler for signals passed from parent -> child
 */
static void
handler(s)
    int s;
{
    recvsig = s;
}

/*
 * Handler for SIGWINCH in parent
 */
static void
sigwinch(s)
    int s;
{
    int serrno = errno;

    sync_winsize(script_fds[SFD_USERTTY], script_fds[SFD_SLAVE]);
    errno = serrno;
}
