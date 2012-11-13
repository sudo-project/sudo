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
#include <sys/stat.h>
#include <sys/time.h>
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
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_ZLIB_H
# include <zlib.h>
#endif

#include "sudo.h"

union io_fd {
    FILE *f;
#ifdef HAVE_ZLIB_H
    gzFile g;
#endif
    void *v;
};

struct script_buf {
    int len; /* buffer length (how much read in) */
    int off; /* write position (how much already consumed) */
    char buf[16 * 1024];
};

#define IOFD_STDIN	0
#define IOFD_STDOUT	1
#define IOFD_STDERR	2
#define IOFD_TTYIN	3
#define IOFD_TTYOUT	4
#define IOFD_TIMING	5
#define IOFD_MAX	6

#ifdef __STDC__
# define SESSID_MAX	2176782336U
#else
# define SESSID_MAX	(unsigned long)2176782336
#endif

static sigset_t ttyblock;
static struct timeval last_time;
static union io_fd io_fds[IOFD_MAX];

void
io_nextid()
{
    struct stat sb;
    char buf[32], *ep;
    int fd, i;
    unsigned long id = 0;
    int len;
    ssize_t nread;
    char pathbuf[PATH_MAX];
    static const char b36char[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /*
     * Create I/O log directory if it doesn't already exist.
     */
    if (stat(def_iolog_dir, &sb) != 0) {
	if (mkdir(def_iolog_dir, S_IRWXU) != 0)
	    log_fatal(USE_ERRNO, "Can't mkdir %s", def_iolog_dir);
	(void) chown(def_iolog_dir, (uid_t)-1, ROOT_GID);
    } else if (!S_ISDIR(sb.st_mode)) {
	log_fatal(0, "%s exists but is not a directory (0%o)",
	    def_iolog_dir, (unsigned int) sb.st_mode);
    }

    /*
     * Open sequence file
     */
    len = snprintf(pathbuf, sizeof(pathbuf), "%s/seq", def_iolog_dir);
    if (len <= 0 || len >= sizeof(pathbuf)) {
	errno = ENAMETOOLONG;
	log_fatal(USE_ERRNO, "%s/seq", pathbuf);
    }
    fd = open(pathbuf, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
    if (fd == -1)
	log_fatal(USE_ERRNO, "cannot open %s", pathbuf);
    lock_file(fd, SUDO_LOCK);

    /* Read seq number (base 36). */
    nread = read(fd, buf, sizeof(buf));
    if (nread != 0) {
	if (nread == -1)
	    log_fatal(USE_ERRNO, "cannot read %s", pathbuf);
	id = strtoul(buf, &ep, 36);
	if (buf == ep || id >= SESSID_MAX)
	    log_fatal(0, "invalid sequence number %s", pathbuf);
    }
    id++;

    /*
     * Convert id to a string and stash in sudo_user.sessid.
     * Note that that least significant digits go at the end of the string.
     */
    for (i = 5; i >= 0; i--) {
	buf[i] = b36char[id % 36];
	id /= 36;
    }
    buf[6] = '\n';

    /* Stash id for logging purposes. */
    memcpy(sudo_user.sessid, buf, 6);
    sudo_user.sessid[6] = '\0';

    /* Rewind and overwrite old seq file. */
    if (lseek(fd, (off_t)0, SEEK_SET) == (off_t)-1 || write(fd, buf, 7) != 7)
	log_fatal(USE_ERRNO, "Can't write to %s", pathbuf);
    close(fd);
}

static int
build_idpath(pathbuf, pathsize)
    char *pathbuf;
    size_t pathsize;
{
    struct stat sb;
    int i, len;

    if (sudo_user.sessid[0] == '\0')
	log_fatal(0, "tried to build a session id path without a session id");

    /*
     * Path is of the form /var/log/sudo-io/00/00/01.
     */
    len = snprintf(pathbuf, pathsize, "%s/%c%c/%c%c/%c%c", def_iolog_dir,
	sudo_user.sessid[0], sudo_user.sessid[1], sudo_user.sessid[2],
	sudo_user.sessid[3], sudo_user.sessid[4], sudo_user.sessid[5]);
    if (len <= 0 && len >= pathsize) {
	errno = ENAMETOOLONG;
	log_fatal(USE_ERRNO, "%s/%s", def_iolog_dir, sudo_user.sessid);
    }

    /*
     * Create the intermediate subdirs as needed.
     */
    for (i = 6; i > 0; i -= 3) {
	pathbuf[len - i] = '\0';
	if (stat(pathbuf, &sb) != 0) {
	    if (mkdir(pathbuf, S_IRWXU) != 0)
		log_fatal(USE_ERRNO, "Can't mkdir %s", pathbuf);
	    (void) chown(pathbuf, (uid_t)-1, ROOT_GID);
	} else if (!S_ISDIR(sb.st_mode)) {
	    log_fatal(0, "%s: %s", pathbuf, strerror(ENOTDIR));
	}
	pathbuf[len - i] = '/';
    }

    return len;
}

static void *
open_io_fd(pathbuf, len, suffix, docompress)
    char *pathbuf;
    int len;
    const char *suffix;
    int docompress;
{
    void *vfd = NULL;
    int fd;

    pathbuf[len] = '\0';
    strlcat(pathbuf, suffix, PATH_MAX);
    fd = open(pathbuf, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
    if (fd != -1) {
	fcntl(fd, F_SETFD, FD_CLOEXEC);
#ifdef HAVE_ZLIB_H
	if (docompress)
	    vfd = gzdopen(fd, "w");
	else
#endif
	    vfd = fdopen(fd, "w");
    }
    return vfd;
}

int
io_log_open()
{
    char pathbuf[PATH_MAX];
    FILE *io_logfile;
    int len;

    if (!def_log_input && !def_log_output)
	return FALSE;

    /*
     * Build a path containing the session id split into two-digit subdirs,
     * so ID 000001 becomes /var/log/sudo-io/00/00/01.
     */
    len = build_idpath(pathbuf, sizeof(pathbuf));
    if (len == -1)
	return -1;

    if (mkdir(pathbuf, S_IRUSR|S_IWUSR|S_IXUSR) != 0)
	log_fatal(USE_ERRNO, "Can't mkdir %s", pathbuf);
    (void) chown(pathbuf, (uid_t)-1, ROOT_GID);

    /*
     * We create 7 files: a log file, a timing file and 5 for input/output.
     */
    io_logfile = open_io_fd(pathbuf, len, "/log", FALSE);
    if (io_logfile == NULL)
	log_fatal(USE_ERRNO, "Can't create %s", pathbuf);

    io_fds[IOFD_TIMING].v = open_io_fd(pathbuf, len, "/timing", def_compress_io);
    if (io_fds[IOFD_TIMING].v == NULL)
	log_fatal(USE_ERRNO, "Can't create %s", pathbuf);

    if (def_log_input) {
	io_fds[IOFD_TTYIN].v = open_io_fd(pathbuf, len, "/ttyin", def_compress_io);
	if (io_fds[IOFD_TTYIN].v == NULL)
	    log_fatal(USE_ERRNO, "Can't create %s", pathbuf);
    }

    if (def_log_output) {
	io_fds[IOFD_TTYOUT].v = open_io_fd(pathbuf, len, "/ttyout", def_compress_io);
	if (io_fds[IOFD_TTYOUT].v == NULL)
	    log_fatal(USE_ERRNO, "Can't create %s", pathbuf);
    }

    if (def_log_input) {
	io_fds[IOFD_STDIN].v = open_io_fd(pathbuf, len, "/stdin", def_compress_io);
	if (io_fds[IOFD_STDIN].v == NULL)
	    log_fatal(USE_ERRNO, "Can't create %s", pathbuf);
    }

    if (def_log_output) {
	io_fds[IOFD_STDOUT].v = open_io_fd(pathbuf, len, "/stdout", def_compress_io);
	if (io_fds[IOFD_STDOUT].v == NULL)
	    log_fatal(USE_ERRNO, "Can't create %s", pathbuf);
    }

    if (def_log_output) {
	io_fds[IOFD_STDERR].v = open_io_fd(pathbuf, len, "/stderr", def_compress_io);
	if (io_fds[IOFD_STDERR].v == NULL)
	    log_fatal(USE_ERRNO, "Can't create %s", pathbuf);
    }

    /* So we can block tty-generated signals */
    sigemptyset(&ttyblock);
    sigaddset(&ttyblock, SIGINT);
    sigaddset(&ttyblock, SIGQUIT);
    sigaddset(&ttyblock, SIGTSTP);
    sigaddset(&ttyblock, SIGTTIN);
    sigaddset(&ttyblock, SIGTTOU);

    gettimeofday(&last_time, NULL);

    /* XXX - log more stuff?  window size? environment? */
    fprintf(io_logfile, "%ld:%s:%s:%s:%s\n", (long)last_time.tv_sec, user_name,
        runas_pw->pw_name, runas_gr ? runas_gr->gr_name : "", user_tty);
    fprintf(io_logfile, "%s\n", user_cwd);
    fprintf(io_logfile, "%s%s%s\n", user_cmnd, user_args ? " " : "",
        user_args ? user_args : "");
    fclose(io_logfile);

    return TRUE;
}

void
io_log_close()
{
    int i;

    for (i = 0; i < IOFD_MAX; i++) {
	if (io_fds[i].v == NULL)
	    continue;
#ifdef HAVE_ZLIB_H
	if (def_compress_io)
	    gzclose(io_fds[i].g);
	else
#endif
	    fclose(io_fds[i].f);
    }
}

static int
log_io(buf, len, idx)
    const char *buf;
    unsigned int len;
    int idx;
{
    struct timeval now, delay;
    sigset_t omask;

    gettimeofday(&now, NULL);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

#ifdef HAVE_ZLIB_H
    if (def_compress_io)
	ignore_result(gzwrite(io_fds[idx].g, (const voidp)buf, len));
    else
#endif
	ignore_result(fwrite(buf, 1, len, io_fds[idx].f));
    delay.tv_sec = now.tv_sec;
    delay.tv_usec = now.tv_usec;
    timevalsub(&delay, &last_time);
#ifdef HAVE_ZLIB_H
    if (def_compress_io)
	gzprintf(io_fds[IOFD_TIMING].g, "%d %f %d\n", idx,
	    delay.tv_sec + ((double)delay.tv_usec / 1000000), len);
    else
#endif
	fprintf(io_fds[IOFD_TIMING].f, "%d %f %d\n", idx,
	    delay.tv_sec + ((double)delay.tv_usec / 1000000), len);
    last_time.tv_sec = now.tv_sec;
    last_time.tv_usec = now.tv_usec;

    sigprocmask(SIG_SETMASK, &omask, NULL);

    return TRUE;
}

int
log_ttyin(buf, len)
    const char *buf;
    unsigned int len;
{
    if (!io_fds[IOFD_TTYIN].v)
	return TRUE;
    return log_io(buf, len, IOFD_TTYIN);
}

int
log_ttyout(buf, len)
    const char *buf;
    unsigned int len;
{
    if (!io_fds[IOFD_TTYOUT].v)
	return TRUE;
    return log_io(buf, len, IOFD_TTYOUT);
}

int
log_stdin(buf, len)
    const char *buf;
    unsigned int len;
{
    if (!io_fds[IOFD_STDIN].v)
	return TRUE;
    return log_io(buf, len, IOFD_STDIN);
}

int
log_stdout(buf, len)
    const char *buf;
    unsigned int len;
{
    if (!io_fds[IOFD_STDOUT].v)
	return TRUE;
    return log_io(buf, len, IOFD_STDOUT);
}

int
log_stderr(buf, len)
    const char *buf;
    unsigned int len;
{
    if (!io_fds[IOFD_STDOUT].v)
	return TRUE;
    return log_io(buf, len, IOFD_STDERR);
}
