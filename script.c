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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
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

#ifdef HAVE_UTIL_H
# include <util.h>
#endif
#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#include "sudo.h"

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

#define SFD_MASTER 0
#define SFD_SLAVE 1
#define SFD_LOG 2
#define SFD_OUTPUT 3
#define SFD_TIMING 4

int script_fds[5];

static sig_atomic_t alive = 1;

static void script_child __P((const char *path, char *const argv[]));
static void sync_winsize __P((int src, int dst));
static void sigchild __P((int signo));
static void sigwinch __P((int signo));
static int get_pty __P((int *master, int *slave));

/*
 * TODO: run monitor as root?
 *       get_pty for unix98 pty
 *       if stdin not tty, just use sane defaults
 *	 fix sigchild
 */

static int fdcompar(v1, v2)
    const void *v1;
    const void *v2;
{
    return(*(int *)v1 - *(int *)v2);
}

void
script_setup()
{
    struct stat sb;
    unsigned int len;
    char pathbuf[PATH_MAX];

    /* XXX - bail early if stdin is not a tty */

    if (!get_pty(&script_fds[SFD_MASTER], &script_fds[SFD_SLAVE]))
	log_error(USE_ERRNO, "Can't get pty");

    /* Copy terminal attrs from stdin -> pty slave. */
    if (!term_copy(STDIN_FILENO, script_fds[SFD_SLAVE]))
	log_error(USE_ERRNO, "Can't copy terminal attributes");
    sync_winsize(STDIN_FILENO, script_fds[SFD_SLAVE]);

    if (!term_raw(STDIN_FILENO))
	log_error(USE_ERRNO, "Can't set terminal to raw mode");

#if 0
    if (openpty(&script_fds[SFD_MASTER], &script_fds[SFD_SLAVE], ttypath, oterm, &win) == -1)
	log_error(USE_ERRNO, "Can't get pty");

    /* Get current terminal attrs, set stdin to raw, no echo, then open pty. */
    if (tcgetattr(STDIN_FILENO, &oterm_buf) != 0)
	log_error(USE_ERRNO, "Can't get terminal attributes");
    oterm = &oterm_buf;
    memcpy(&term, oterm, sizeof(term));
    cfmakeraw(&term);
    term.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) != 0)
	log_error(USE_ERRNO, "Can't set terminal attributes");
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &win) != 0)
	log_error(USE_ERRNO, "Can't get window size");
    if (openpty(&script_fds[SFD_MASTER], &script_fds[SFD_SLAVE], ttypath, oterm, &win) == -1)
	log_error(USE_ERRNO, "Can't open pty");
    (void) chown(ttypath, runas_pw->pw_uid, -1);
#endif

    /*
     * Log files live in a per-user subdir of _PATH_SUDO_SESSDIR.
     * Create these if they don't already exist.
     */
    if (stat(_PATH_SUDO_SESSDIR, &sb) != 0) {
	if (mkdir(_PATH_SUDO_SESSDIR, S_IRWXU) != 0)
	    log_error(USE_ERRNO, "Can't mkdir %s", _PATH_SUDO_SESSDIR);
    } else if (!S_ISDIR(sb.st_mode)) {
	log_error(0, "%s exists but is not a directory (0%o)",
	    _PATH_SUDO_SESSDIR, (unsigned int) sb.st_mode);
    }
    snprintf(pathbuf, sizeof(pathbuf), "%s/%s", _PATH_SUDO_SESSDIR, user_name);
    if (stat(pathbuf, &sb) != 0) {
	if (mkdir(pathbuf, S_IRWXU) != 0)
	    log_error(USE_ERRNO, "Can't mkdir %s", pathbuf);
    } else if (!S_ISDIR(sb.st_mode)) {
	log_error(0, "%s exists but is not a directory (0%o)",
	    pathbuf, (unsigned int) sb.st_mode);
    }

    /*
     * We create 3 files: one for the command + args and timestamp,
     * one for the raw session data, and another for the timing info.
     */
    strlcat(pathbuf, "/XXXXXXXXXX", sizeof(pathbuf));
    script_fds[SFD_LOG] = mkstemp(pathbuf);
    if (script_fds[SFD_LOG] == -1)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);
    len = strlen(pathbuf);

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

    /* sort fds so we can dup them safely */
    qsort(script_fds, 5, sizeof(int), fdcompar);
}

struct script_buf {
    int len; /* buffer length (how much read in) */
    int off; /* write position (how much already consumed) */
    char buf[16 * 1024];
};

int
script_execv(path, argv)
    const char *path;
    char *const argv[];
{
    pid_t child, pid;
    int n, nready;
    fd_set *fdsr, *fdsw;
    struct script_buf input, output;
    struct timeval now, prevtime, tv;
    sigaction_t sa;
    FILE *idfile, *ofile, *tfile;

    if ((idfile = fdopen(script_fds[SFD_LOG], "w")) == NULL)
	log_error(USE_ERRNO, "fdopen");
    if ((ofile = fdopen(script_fds[SFD_OUTPUT], "w")) == NULL)
	log_error(USE_ERRNO, "fdopen");
    if ((tfile = fdopen(script_fds[SFD_TIMING], "w")) == NULL)
	log_error(USE_ERRNO, "fdopen");

    child = fork();
    if (child == -1)
	log_error(USE_ERRNO, "Can't fork");
    if (child == 0) {
	/* fork child, setup tty and exec command */
	script_child(path, argv);
	return(-1); /* execv failure */
    }

    /* Setup signal handlers for child exit and window size changes. */
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigchild;
    sa.sa_flags = SA_RESTART|SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);
    sa.sa_handler = sigwinch;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa, NULL);

    gettimeofday(&prevtime, NULL);

    /* XXX - log more stuff to idfile (like normal log line?) */
    fprintf(idfile, "%ld %s\n", prevtime.tv_sec, user_tty);
    fprintf(idfile, "%s%s%s\n", user_cmnd, user_args ? " " : "",
	user_args ? user_args : "");

    n = fcntl(script_fds[SFD_MASTER], F_GETFL, 0);
    if (n != -1) {
	n |= O_NONBLOCK;
	(void) fcntl(script_fds[SFD_MASTER], F_SETFL, n);
    }
    n = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (n != -1) {
	n |= O_NONBLOCK;
	(void) fcntl(STDIN_FILENO, F_SETFL, n);
    }
    n = fcntl(STDOUT_FILENO, F_GETFL, 0);
    if (n != -1) {
	n |= O_NONBLOCK;
	(void) fcntl(STDOUT_FILENO, F_SETFL, n);
    }

    /*
     * In the event loop we pass input from stdin to master
     * and pass output from master to stdout and ofile.
     * Note that we've set things up such that master is above
     * stdin and stdout (see sudo.c).
     */
    fdsr = (fd_set *)emalloc2(howmany(script_fds[SFD_MASTER] + 1, NFDBITS),
	sizeof(fd_mask));
    fdsw = (fd_set *)emalloc2(howmany(script_fds[SFD_MASTER] + 1, NFDBITS),
	sizeof(fd_mask));
    zero_bytes(&input, sizeof(input));
    zero_bytes(&output, sizeof(output));
    while (alive) {
	if (input.off == input.len)
	    input.off = input.len = 0;
	if (output.off == output.len)
	    output.off = output.len = 0;

	zero_bytes(fdsw, howmany(script_fds[SFD_MASTER] + 1, NFDBITS) * sizeof(fd_mask));
	zero_bytes(fdsr, howmany(script_fds[SFD_MASTER] + 1, NFDBITS) * sizeof(fd_mask));
	if (input.len != sizeof(input.buf))
	    FD_SET(STDIN_FILENO, fdsr);
	if (output.len != sizeof(output.buf))
	    FD_SET(script_fds[SFD_MASTER], fdsr);
	if (output.len > output.off)
	    FD_SET(STDOUT_FILENO, fdsw);
	if (input.len > input.off)
	    FD_SET(script_fds[SFD_MASTER], fdsw);

	nready = select(script_fds[SFD_MASTER] + 1, fdsr, fdsw, NULL, NULL);
	if (nready == -1) {
	    if (errno == EINTR)
		continue;
	    log_error(USE_ERRNO, "select failed");
	}
	if (FD_ISSET(STDIN_FILENO, fdsr)) {
	    n = read(STDIN_FILENO, input.buf + input.len,
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
		output.len += n;

		/* Update output and timing files. */
		fwrite(output.buf + output.off, 1, n, ofile);
		timersub(&now, &prevtime, &tv);
		fprintf(tfile, "%f %d\n",
		    tv.tv_sec + ((double)tv.tv_usec / 1000000), n);
		prevtime.tv_sec = now.tv_sec;
		prevtime.tv_usec = now.tv_usec;
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

    /* Flush any remaining output. */
    n = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (n != -1) {
	n &= ~O_NONBLOCK;
	(void) fcntl(STDIN_FILENO, F_SETFL, n);
    }
    /* XXX - no check for short writes */
    if (output.len > output.off) {
	write(STDOUT_FILENO, output.buf + output.off, output.len - output.off);
	fwrite(output.buf + output.off, 1, output.len - output.off, ofile);
    }
    for (;;) {
	n = read(script_fds[SFD_MASTER], output.buf, sizeof(output.buf));
	if (n <= 0)
	    break;
	write(STDOUT_FILENO, output.buf, n);
	fwrite(output.buf, 1, n, ofile);
    }
    term_restore(STDIN_FILENO);

    do {
#ifdef sudo_waitpid
        pid = sudo_waitpid(child, &n, 0);
#else
        pid = wait(&n);
#endif
    } while (pid != -1 || errno == EINTR);
#ifdef HAVE_VHANGUP
    signal(SIGHUP, SIG_IGN);
    vhangup();
#endif
    if (WIFEXITED(n))
	exit(WEXITSTATUS(n));
    if (WIFSIGNALED(n))
	exit(128 | WSTOPSIG(n));
    exit(1);
}

static void
script_child(path, argv)
    const char *path;
    char *const argv[];
{
    /*
     * Create new session, make slave controlling terminal and
     * point std{in,out,err} to it.
     */
#ifdef HAVE_SETSID
    setsid();
#else
    setpgrp(0, 0);
#endif
#ifdef TIOCSCTTY
    if (ioctl(script_fds[SFD_SLAVE], TIOCSCTTY, NULL) != 0) {
	warning("unable to set controlling tty");
	return;
    }
#endif
    dup2(script_fds[SFD_SLAVE], STDIN_FILENO);
    dup2(script_fds[SFD_SLAVE], STDOUT_FILENO);
    dup2(script_fds[SFD_SLAVE], STDERR_FILENO);

    /*
     * Close old fds and exec command.
     */
    close(script_fds[SFD_MASTER]);
    close(script_fds[SFD_SLAVE]);
    close(script_fds[SFD_LOG]);
    close(script_fds[SFD_OUTPUT]);
    close(script_fds[SFD_TIMING]);
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

static void
sigchild(signo)
    int signo;
{
    /* XXX - might not be right pid, must wait for it to find out */
    alive = 0;
}

static void
sigwinch(signo)
    int signo;
{
    int serrno = errno;

    sync_winsize(STDIN_FILENO, script_fds[SFD_SLAVE]);
    errno = serrno;
}

#ifdef HAVE_OPENPTY
static int get_pty(master, slave)
    int *master;
    int *slave;
{
    char line[PATH_MAX];
    struct group *gr;
    gid_t ttygid = -1;

    if ((gr = sudo_getgrnam("tty")) != NULL)
	ttygid = gr->gr_gid;

    if (openpty(master, slave, line, NULL, NULL) != 0)
	return(0);
    (void) chown(line, runas_pw->pw_uid, ttygid);
    return(1);
}

#else

static char line[] = "/dev/ptyXX";
static int get_pty(master, slave)
    int *master;
    int *slave;
{
    char *bank, *cp;
    struct group *gr;
    gid_t ttygid = -1;

    if ((gr = sudo_getgrnam("tty")) != NULL)
	ttygid = gr->gr_gid;

    for (bank = "pqrs"; *bank != '\0'; bank++) {
	line[sizeof("/dev/ptyX") - 2] = *bank;
	for (cp = "0123456789abcdef"; *cp != '\0'; cp++) {
	    line[sizeof("/dev/ptyXX") - 2] = *cp;
	    *master = open(line, O_RDWR, 0);
	    if (*master == -1) {
		if (errno == ENOENT)
		    return(0); /* out of ptys */
		continue; /* already in use */
	    }
	    line[sizeof("/dev/p") - 2] = 't';
	    (void)chown(line, runas_pw->pw_uid, ttygid);
	    (void)chmod(line, S_IRUSR|S_IWUSR|S_IWGRP);
#ifdef HAVE_REVOKE
	    (void)revoke(line);
#endif
	    *slave = open(line, O_RDWR, 0);
	    if (*slave != -1)
		    return(1); /* success */
	    (void)close(*master);
	}
    }
    return(0);
}

#endif
