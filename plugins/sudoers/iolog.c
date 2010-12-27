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
#include <setjmp.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_ZLIB_H
# include <zlib.h>
#endif

#include "sudoers.h"

/* plugin_error.c */
extern sigjmp_buf error_jmp;

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

#define SESSID_MAX	2176782336U

static struct timeval last_time;
static union io_fd io_fds[IOFD_MAX];
extern struct io_plugin sudoers_io;

static void
mkdir_parents(char *path)
{
    struct stat sb;
    char *slash = path;

    for (;;) {
	if ((slash = strchr(slash + 1, '/')) == NULL)
	    break;
	*slash = '\0';
	if (stat(path, &sb) != 0) {
	    if (mkdir(path, S_IRWXU) != 0)
		log_error(USE_ERRNO, "Can't mkdir %s", path);
	} else if (!S_ISDIR(sb.st_mode)) {
	    log_error(0, "%s: %s", path, strerror(ENOTDIR));
	}
	*slash = '/';
    }
}

void
io_nextid(void)
{
    struct stat sb;
    char buf[32], *ep;
    int fd, i, ch;
    unsigned long id = 0;
    int len;
    ssize_t nread;
    char pathbuf[PATH_MAX];

    /*
     * Create I/O log directory if it doesn't already exist.
     */
    mkdir_parents(def_iolog_dir);
    if (stat(def_iolog_dir, &sb) != 0) {
	if (mkdir(def_iolog_dir, S_IRWXU) != 0)
	    log_error(USE_ERRNO, "Can't mkdir %s", def_iolog_dir);
    } else if (!S_ISDIR(sb.st_mode)) {
	log_error(0, "%s exists but is not a directory (0%o)",
	    def_iolog_dir, (unsigned int) sb.st_mode);
    }

    /*
     * Open sequence file
     */
    len = snprintf(pathbuf, sizeof(pathbuf), "%s/seq", def_iolog_dir);
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
	if (buf == ep || id >= SESSID_MAX)
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
build_iopath(const char *iolog_dir, const char *iolog_file, char *pathbuf,
    size_t pathsize)
{
    int dirlen, filelen, len;

    /* Trim extraneous slashes. */
    dirlen = strlen(iolog_dir);
    while (dirlen > 1 && iolog_dir[dirlen - 1] == '/')
	dirlen--;
    while (*iolog_file == '/')
	iolog_file++;
    filelen = strlen(iolog_file);
    while (filelen > 1 && iolog_file[filelen - 1] == '/')
	filelen--;

    if (*iolog_dir != '/' || *iolog_file == '\0')
	log_error(0, "invalid I/O log path: %s/%s", iolog_dir, iolog_file);

    len = snprintf(pathbuf, pathsize, "%.*s/%.*s", dirlen, iolog_dir,
	filelen, iolog_file);
    if (len <= 0 && len >= pathsize) {
	errno = ENAMETOOLONG;
	log_error(USE_ERRNO, "%.*s/%.*s", dirlen, iolog_dir,
	    filelen, iolog_file);
    }

    /*
     * Create path and intermediate subdirs as needed.
     * If path ends in at least 6 Xs (ala POSIX mktemp), use mkdtemp().
     */
    mkdir_parents(pathbuf);
    if (len >= 6 && strcmp(&pathbuf[len - 6], "XXXXXX") == 0) {
	if (mkdtemp(pathbuf) == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	if (mkdir(pathbuf, S_IRWXU) != 0)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    }

    return(len);
}

static void *
open_io_fd(char *pathbuf, int len, const char *suffix, int docompress)
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

static int
sudoers_io_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], char * const command_info[],
    int argc, char * const argv[], char * const user_env[])
{
    char pathbuf[PATH_MAX];
    const char *iolog_dir, *iolog_file;
    char * const *cur;
    FILE *io_logfile;
    int len, iolog_stdin, iolog_stdout, iolog_stderr, iolog_ttyin, iolog_ttyout;

    if (!sudo_conv)
	sudo_conv = conversation;
    if (!sudo_printf)
	sudo_printf = plugin_printf;

    /* If we have no command (because -V was specified) just return. */
    if (argc == 0)
	return TRUE;

    if (sigsetjmp(error_jmp, 1)) {
	/* called via error(), errorx() or log_error() */
	return -1;
    }

    /*
     * Pull iolog settings out of command_info, if any.
     */
    iolog_dir = _PATH_SUDO_IO_LOGDIR; /* XXX */
    iolog_file = sudo_user.sessid; /* XXX */
    iolog_stdin = iolog_ttyin = def_log_input;
    iolog_stdout = iolog_stderr = iolog_ttyout = def_log_output;
    for (cur = command_info; *cur != NULL; cur++) {
	if (**cur != 'i')
	    continue;
	if (strncmp(*cur, "iolog_file=", sizeof("iolog_file=") - 1) == 0) {
	    iolog_file = *cur + sizeof("iolog_file=") - 1;
	    continue;
	}
	if (strncmp(*cur, "iolog_dir=", sizeof("iolog_dir=") - 1) == 0) {
	    iolog_dir = *cur + sizeof("iolog_dir=") - 1;
	    continue;
	}
	if (strncmp(*cur, "iolog_stdin=", sizeof("iolog_stdin=") - 1) == 0) {
	    if (atobool(*cur + sizeof("iolog_stdin=") - 1) == TRUE)
		iolog_stdin = TRUE;
	    continue;
	}
	if (strncmp(*cur, "iolog_stdout=", sizeof("iolog_stdout=") - 1) == 0) {
	    if (atobool(*cur + sizeof("iolog_stdout=") - 1) == TRUE)
		iolog_stdout = TRUE;
	    continue;
	}
	if (strncmp(*cur, "iolog_stderr=", sizeof("iolog_stderr=") - 1) == 0) {
	    if (atobool(*cur + sizeof("iolog_stderr=") - 1) == TRUE)
		iolog_stderr = TRUE;
	    continue;
	}
	if (strncmp(*cur, "iolog_ttyin=", sizeof("iolog_ttyin=") - 1) == 0) {
	    if (atobool(*cur + sizeof("iolog_ttyin=") - 1) == TRUE)
		iolog_ttyin = TRUE;
	    continue;
	}
	if (strncmp(*cur, "iolog_ttyout=", sizeof("iolog_ttyout=") - 1) == 0) {
	    if (atobool(*cur + sizeof("iolog_ttyout=") - 1) == TRUE)
		iolog_ttyout = TRUE;
	    continue;
	}
    }
    /* Did policy module disable I/O logging? */
    if (!iolog_stdin && !iolog_ttyin && !iolog_stdout && !iolog_stderr &&
	!iolog_ttyout)
	return FALSE;

    /* If no I/O log file defined there is nothing to do. */
    if (iolog_file == NULL || iolog_dir == NULL)
	return FALSE;

    /* Build a path from I/O file and dir, creating intermediate subdirs. */
    len = build_iopath(iolog_dir, iolog_file, pathbuf, sizeof(pathbuf));
    if (len < 0 || len >= sizeof(pathbuf))
	return -1;

    /*
     * We create 7 files: a log file, a timing file and 5 for input/output.
     */
    io_logfile = open_io_fd(pathbuf, len, "/log", FALSE);
    if (io_logfile == NULL)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);

    io_fds[IOFD_TIMING].v = open_io_fd(pathbuf, len, "/timing", def_compress_io);
    if (io_fds[IOFD_TIMING].v == NULL)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);

    if (iolog_ttyin) {
	io_fds[IOFD_TTYIN].v = open_io_fd(pathbuf, len, "/ttyin", def_compress_io);
	if (io_fds[IOFD_TTYIN].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_ttyin = NULL;
    }
    if (iolog_stdin) {
	io_fds[IOFD_STDIN].v = open_io_fd(pathbuf, len, "/stdin", def_compress_io);
	if (io_fds[IOFD_STDIN].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_stdin = NULL;
    }
    if (iolog_ttyout) {
	io_fds[IOFD_TTYOUT].v = open_io_fd(pathbuf, len, "/ttyout", def_compress_io);
	if (io_fds[IOFD_TTYOUT].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_ttyout = NULL;
    }
    if (iolog_stdout) {
	io_fds[IOFD_STDOUT].v = open_io_fd(pathbuf, len, "/stdout", def_compress_io);
	if (io_fds[IOFD_STDOUT].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_stdout = NULL;
    }
    if (iolog_stderr) {
	io_fds[IOFD_STDERR].v = open_io_fd(pathbuf, len, "/stderr", def_compress_io);
	if (io_fds[IOFD_STDERR].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_stderr = NULL;
    }

    gettimeofday(&last_time, NULL);

    /* XXX - log more stuff?  window size? environment? */
    /* XXX - don't rely on policy module globals */
    fprintf(io_logfile, "%ld:%s:%s:%s:%s\n", (long)last_time.tv_sec, user_name,
        runas_pw->pw_name, runas_gr ? runas_gr->gr_name : "", user_tty);
    fprintf(io_logfile, "%s\n", user_cwd);
    fprintf(io_logfile, "%s%s%s\n", user_cmnd, user_args ? " " : "",
        user_args ? user_args : "");
    fclose(io_logfile);

    return TRUE;
}

static void
sudoers_io_close(int exit_status, int error)
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
sudoers_io_version(int verbose)
{
    sudo_printf(SUDO_CONV_INFO_MSG, "Sudoers I/O plugin version %s\n",
	PACKAGE_VERSION);

    return TRUE;
}

static int
sudoers_io_log(const char *buf, unsigned int len, int idx)
{
    struct timeval now, delay;

    gettimeofday(&now, NULL);

#ifdef HAVE_ZLIB_H
    if (def_compress_io)
	gzwrite(io_fds[idx].g, buf, len);
    else
#endif
	fwrite(buf, 1, len, io_fds[idx].f);
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

    return TRUE;
}

static int
sudoers_io_log_ttyin(const char *buf, unsigned int len)
{
    return sudoers_io_log(buf, len, IOFD_TTYIN);
}

static int
sudoers_io_log_ttyout(const char *buf, unsigned int len)
{
    return sudoers_io_log(buf, len, IOFD_TTYOUT);
}

static int
sudoers_io_log_stdin(const char *buf, unsigned int len)
{
    return sudoers_io_log(buf, len, IOFD_STDIN);
}

static int
sudoers_io_log_stdout(const char *buf, unsigned int len)
{
    return sudoers_io_log(buf, len, IOFD_STDOUT);
}

static int
sudoers_io_log_stderr(const char *buf, unsigned int len)
{
    return sudoers_io_log(buf, len, IOFD_STDERR);
}

struct io_plugin sudoers_io = {
    SUDO_IO_PLUGIN,
    SUDO_API_VERSION,
    sudoers_io_open,
    sudoers_io_close,
    sudoers_io_version,
    sudoers_io_log_ttyin,
    sudoers_io_log_ttyout,
    sudoers_io_log_stdin,
    sudoers_io_log_stdout,
    sudoers_io_log_stderr
};
