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
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_ZLIB
# include <zlib.h>
#endif

#include "sudoers.h"

union script_fd {
    FILE *f;
#ifdef HAVE_ZLIB
    gzFile g;
#endif
    void *v;
};

struct script_buf {
    int len; /* buffer length (how much read in) */
    int off; /* write position (how much already consumed) */
    char buf[16 * 1024];
};

static void
io_nextid()
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
build_idpath(char *pathbuf, size_t pathsize)
{
    struct stat sb;
    int i, len;

    if (sudo_user.sessid[0] == '\0')
	log_error(0, "tried to build a session id path without a session id");

    /*
     * Path is of the form /var/log/sudo-session/00/00/01.
     */
    len = snprintf(pathbuf, pathsize, "%s/%c%c/%c%c/%c%c", _PATH_SUDO_TRANSCRIPT,
	sudo_user.sessid[0], sudo_user.sessid[1], sudo_user.sessid[2],
	sudo_user.sessid[3], sudo_user.sessid[4], sudo_user.sessid[5]);
    if (len <= 0 && len >= pathsize) {
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

/* XXX */
static sudo_conv_t io_conv;
static sigset_t ttyblock;
static struct timeval last_time;
static union script_fd io_outfile, io_timfile;

/* XXX - need to defer this until after the policy check succeeds */
int
sudoers_io_open(unsigned int version, sudo_conv_t conversation,
    char * const settings[], char * const user_info[], char * const user_env[])
{
    char pathbuf[PATH_MAX];
    FILE *io_logfile;
    int fd, len;

    io_conv = conversation;

    /* XXX - def_transcript may not be set yet */
    if (!def_transcript)
	return FALSE;

    /*
     * Build a path containing the session id split into two-digit subdirs,
     * so ID 000001 becomes /var/log/sudo-session/00/00/01.
     */
    io_nextid();
    len = build_idpath(pathbuf, sizeof(pathbuf));
    if (len == -1)
	return -1;

    /*
     * We create 3 files: a log file, one for the raw session data,
     * and one for the timing info.
     */
    fd = open(pathbuf, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
    if (fd == -1)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);
    io_logfile = fdopen(fd, "w");
    if (io_logfile == NULL)
        log_error(USE_ERRNO, "fdopen");

    strlcat(pathbuf, ".scr", sizeof(pathbuf));
    fd = open(pathbuf, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
    if (fd == -1)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);
#ifdef HAVE_ZLIB
    if (def_compress_transcript)
        io_outfile.g = gzdopen(fd, "w");
    else
#endif
	io_outfile.f = fdopen(fd, "w");
    if (io_outfile.v == NULL)
	log_error(USE_ERRNO, "Can't open %s", pathbuf);

    pathbuf[len] = '\0';
    strlcat(pathbuf, ".tim", sizeof(pathbuf));
    fd = open(pathbuf, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR|S_IWUSR);
    if (fd == -1)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);
#ifdef HAVE_ZLIB
    if (def_compress_transcript)
        io_timfile.g = gzdopen(fd, "w");
    else
#endif
	io_timfile.f = fdopen(fd, "w");
    if (io_timfile.v == NULL)
	log_error(USE_ERRNO, "Can't open %s", pathbuf);

    /* So we can block tty-generated signals */
    sigemptyset(&ttyblock);
    sigaddset(&ttyblock, SIGINT);
    sigaddset(&ttyblock, SIGQUIT);
    sigaddset(&ttyblock, SIGTSTP);
    sigaddset(&ttyblock, SIGTTIN);
    sigaddset(&ttyblock, SIGTTOU);

    gettimeofday(&last_time, NULL);

    /* XXX - too early, don't even have user_cmnd yet */
    /* XXX - log more stuff?  window size? environment? */
    fprintf(io_logfile, "%ld:%s:%s:%s:%s\n", last_time.tv_sec, user_name,
        runas_pw->pw_name, runas_gr ? runas_gr->gr_name : "", user_tty);
    fprintf(io_logfile, "%s\n", user_cwd);
    fprintf(io_logfile, "%s%s%s\n", user_cmnd, user_args ? " " : "",
        user_args ? user_args : "");
    fclose(io_logfile);

    return TRUE;
}

void
sudoers_io_close(int exit_status, int error)
{
#ifdef HAVE_ZLIB
    if (def_compress_transcript) {
	gzclose(io_outfile.g);
	gzclose(io_timfile.g);
    } else
#endif
    {
	fclose(io_outfile.f);
	fclose(io_timfile.f);
    }
}

int
sudoers_io_version(int verbose)
{
    struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    char *str;

    easprintf(&str, "Sudoers I/O plugin version %s\n", PACKAGE_VERSION);

    /* Call conversation function */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = SUDO_CONV_INFO_MSG;
    msg.msg = str;
    memset(&repl, 0, sizeof(repl));
    sudo_conv(1, &msg, &repl);
    free(str);

    return TRUE;
}

int
sudoers_io_log_output(const char *buf, unsigned int len)
{
    struct timeval now, tv;
    sigset_t omask;

    gettimeofday(&now, NULL);

    sigprocmask(SIG_BLOCK, &ttyblock, &omask);

#ifdef HAVE_ZLIB
    if (def_compress_transcript)
	gzwrite(io_outfile.g, buf, len);
    else
#endif
	fwrite(buf, 1, len, io_outfile.f);
    timersub(&now, &last_time, &tv);
#ifdef HAVE_ZLIB
    if (def_compress_transcript)
	gzprintf(io_timfile.g, "%f %d\n",
	    tv.tv_sec + ((double)tv.tv_usec / 1000000), len);
    else
#endif
	fprintf(io_timfile.f, "%f %d\n",
	    tv.tv_sec + ((double)tv.tv_usec / 1000000), len);
    last_time.tv_sec = now.tv_sec;
    last_time.tv_usec = now.tv_usec;

    sigprocmask(SIG_SETMASK, &omask, NULL);

    return TRUE;
}
