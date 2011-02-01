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

/* XXX - separate sudoers.h and iolog.h? */
#undef runas_pw
#undef runas_gr

struct iolog_details {
    const char *cwd;
    const char *tty;
    const char *user;
    const char *command;
    const char *iolog_path;
    struct passwd *runas_pw;
    struct group *runas_gr;
    int iolog_stdin;
    int iolog_stdout;
    int iolog_stderr;
    int iolog_ttyin;
    int iolog_ttyout;
};

#define IOFD_STDIN	0
#define IOFD_STDOUT	1
#define IOFD_STDERR	2
#define IOFD_TTYIN	3
#define IOFD_TTYOUT	4
#define IOFD_TIMING	5
#define IOFD_MAX	6

#define SESSID_MAX	2176782336U

static int iolog_compress;
static struct timeval last_time;
static union io_fd io_fds[IOFD_MAX];
extern struct io_plugin sudoers_io;

/*
 * Create parent directories for path as needed, but not path itself.
 */
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

/*
 * Read the on-disk sequence number, set sudo_user.sessid to the next
 * number, and update the on-disk copy.
 * Uses file locking to avoid sequence number collisions.
 */
void
io_nextid(char *iolog_dir, char sessid[7])
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
    mkdir_parents(iolog_dir);
    if (stat(iolog_dir, &sb) != 0) {
	if (mkdir(iolog_dir, S_IRWXU) != 0)
	    log_error(USE_ERRNO, "Can't mkdir %s", iolog_dir);
    } else if (!S_ISDIR(sb.st_mode)) {
	log_error(0, "%s exists but is not a directory (0%o)",
	    iolog_dir, (unsigned int) sb.st_mode);
    }

    /*
     * Open sequence file
     */
    len = snprintf(pathbuf, sizeof(pathbuf), "%s/seq", iolog_dir);
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
     * Convert id to a string and stash in sessid.
     * Note that that least significant digits go at the end of the string.
     */
    for (i = 5; i >= 0; i--) {
	buf[i] = b36char[id % 36];
	id /= 36;
    }
    buf[6] = '\n';

    /* Stash id logging purposes */
    memcpy(sessid, buf, 6);
    sessid[6] = '\0';

    /* Rewind and overwrite old seq file. */
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1 || write(fd, buf, 7) != 7)
	log_error(USE_ERRNO, "Can't write to %s", pathbuf);
    close(fd);
}

/*
 * Copy iolog_path to pathbuf and create the directory and any intermediate
 * directories.  If iolog_path ends in 'XXXXXX', use mkdtemp().
 */
static size_t
mkdir_iopath(const char *iolog_path, char *pathbuf, size_t pathsize)
{
    size_t len;

    len = strlcpy(pathbuf, iolog_path, pathsize);
    if (len >= pathsize) {
	errno = ENAMETOOLONG;
	log_error(USE_ERRNO, "%s", iolog_path);
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

    return len;
}

/*
 * Append suffix to pathbuf after len chars and open the resulting file.
 * Note that the size of pathbuf is assumed to be PATH_MAX.
 * Uses zlib if docompress is TRUE.
 * Returns the open file handle which has the close-on-exec flag set.
 */
static void *
open_io_fd(char *pathbuf, size_t len, const char *suffix, int docompress)
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

/*
 * Pull out I/O log related data from user_info and command_info arrays.
 */
static void
iolog_deserialize_info(struct iolog_details *details, char * const user_info[],
    char * const command_info[])
{
    const char *runas_uid_str = "0", *runas_euid_str = NULL;
    const char *runas_gid_str = "0", *runas_egid_str = NULL;
    char id[MAX_UID_T_LEN + 2], *ep;
    char * const *cur;
    unsigned long ulval;
    uid_t runas_uid = 0;
    gid_t runas_gid = 0;

    memset(details, 0, sizeof(*details));

    for (cur = user_info; *cur != NULL; cur++) {
	switch (**cur) {
	case 'c':
	    if (strncmp(*cur, "cwd=", sizeof("cwd=") - 1) == 0) {
		details->cwd = *cur + sizeof("cwd=") - 1;
		continue;
	    }
	    break;
	case 't':
	    if (strncmp(*cur, "tty=", sizeof("tty=") - 1) == 0) {
		details->tty = *cur + sizeof("tty=") - 1;
		continue;
	    }
	    break;
	case 'u':
	    if (strncmp(*cur, "user=", sizeof("user=") - 1) == 0) {
		details->user = *cur + sizeof("user=") - 1;
		continue;
	    }
	    break;
	}
    }

    for (cur = command_info; *cur != NULL; cur++) {
	switch (**cur) {
	case 'c':
	    if (strncmp(*cur, "command=", sizeof("command=") - 1) == 0) {
		details->command = *cur + sizeof("command=") - 1;
		continue;
	    }
	    break;
	case 'i':
	    if (strncmp(*cur, "iolog_path=", sizeof("iolog_path=") - 1) == 0) {
		details->iolog_path = *cur + sizeof("iolog_path=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "iolog_stdin=", sizeof("iolog_stdin=") - 1) == 0) {
		if (atobool(*cur + sizeof("iolog_stdin=") - 1) == TRUE)
		    details->iolog_stdin = TRUE;
		continue;
	    }
	    if (strncmp(*cur, "iolog_stdout=", sizeof("iolog_stdout=") - 1) == 0) {
		if (atobool(*cur + sizeof("iolog_stdout=") - 1) == TRUE)
		    details->iolog_stdout = TRUE;
		continue;
	    }
	    if (strncmp(*cur, "iolog_stderr=", sizeof("iolog_stderr=") - 1) == 0) {
		if (atobool(*cur + sizeof("iolog_stderr=") - 1) == TRUE)
		    details->iolog_stderr = TRUE;
		continue;
	    }
	    if (strncmp(*cur, "iolog_ttyin=", sizeof("iolog_ttyin=") - 1) == 0) {
		if (atobool(*cur + sizeof("iolog_ttyin=") - 1) == TRUE)
		    details->iolog_ttyin = TRUE;
		continue;
	    }
	    if (strncmp(*cur, "iolog_ttyout=", sizeof("iolog_ttyout=") - 1) == 0) {
		if (atobool(*cur + sizeof("iolog_ttyout=") - 1) == TRUE)
		    details->iolog_ttyout = TRUE;
		continue;
	    }
	    if (strncmp(*cur, "iolog_compress=", sizeof("iolog_compress=") - 1) == 0) {
		if (atobool(*cur + sizeof("iolog_compress=") - 1) == TRUE)
		    iolog_compress = TRUE; /* must be global */
		continue;
	    }
	    break;
	case 'r':
	    if (strncmp(*cur, "runas_gid=", sizeof("runas_gid=") - 1) == 0) {
		runas_gid_str = *cur + sizeof("runas_gid=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "runas_egid=", sizeof("runas_egid=") - 1) == 0) {
		runas_egid_str = *cur + sizeof("runas_egid=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "runas_uid=", sizeof("runas_uid=") - 1) == 0) {
		runas_uid_str = *cur + sizeof("runas_uid=") - 1;
		continue;
	    }
	    if (strncmp(*cur, "runas_euid=", sizeof("runas_euid=") - 1) == 0) {
		runas_euid_str = *cur + sizeof("runas_euid=") - 1;
		continue;
	    }
	    break;
	}
    }

    /*
     * Lookup runas user and group, preferring effective over real uid/gid.
     */
    if (runas_euid_str != NULL)
	runas_uid_str = runas_euid_str;
    if (runas_uid_str != NULL) {
	errno = 0;
	ulval = strtoul(runas_uid_str, &ep, 0);
	if (*runas_uid_str != '\0' && *ep == '\0' &&
	    (errno != ERANGE || ulval != ULONG_MAX)) {
	    runas_uid = (uid_t)ulval;
	}
    }
    if (runas_egid_str != NULL)
	runas_gid_str = runas_egid_str;
    if (runas_gid_str != NULL) {
	errno = 0;
	ulval = strtoul(runas_gid_str, &ep, 0);
	if (*runas_gid_str != '\0' && *ep == '\0' &&
	    (errno != ERANGE || ulval != ULONG_MAX)) {
	    runas_gid = (gid_t)ulval;
	}
    }

    details->runas_pw = sudo_getpwuid(runas_uid);
    if (details->runas_pw == NULL) {
	id[0] = '#';
	strlcpy(&id[1], runas_uid_str, sizeof(id) - 1);
	details->runas_pw = sudo_fakepwnam(id, runas_gid);
    }

    if (runas_gid != details->runas_pw->pw_gid) {
	details->runas_gr = sudo_getgrgid(runas_gid);
	if (details->runas_gr == NULL) {
	    id[0] = '#';
	    strlcpy(&id[1], runas_gid_str, sizeof(id) - 1);
	    details->runas_gr = sudo_fakegrnam(id);
	}
    }
}

static int
sudoers_io_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], char * const command_info[],
    int argc, char * const argv[], char * const user_env[])
{
    struct iolog_details details;
    char pathbuf[PATH_MAX], sessid[7];
    char *tofree = NULL;
    char * const *cur;
    FILE *io_logfile;
    size_t len;
    int rval = -1;

    if (!sudo_conv)
	sudo_conv = conversation;
    if (!sudo_printf)
	sudo_printf = plugin_printf;

    /* If we have no command (because -V was specified) just return. */
    if (argc == 0)
	return TRUE;

    if (sigsetjmp(error_jmp, 1)) {
	/* called via error(), errorx() or log_error() */
	rval = -1;
	goto done;
    }

    sudo_setpwent();
    sudo_setgrent();

    /*
     * Pull iolog settings out of command_info, if any.
     */
    iolog_deserialize_info(&details, user_info, command_info);
    /* Did policy module disable I/O logging? */
    if (!details.iolog_stdin && !details.iolog_ttyin &&
	!details.iolog_stdout && !details.iolog_stderr &&
	!details.iolog_ttyout) {
	rval = FALSE;
	goto done;
    }

    /* If no I/O log path defined we need to figure it out ourselves. */
    if (details.iolog_path == NULL) {
	/* Get next session ID and convert it into a path. */
	tofree = emalloc(sizeof(_PATH_SUDO_IO_LOGDIR) + sizeof(sessid) + 2);
	memcpy(tofree, _PATH_SUDO_IO_LOGDIR, sizeof(_PATH_SUDO_IO_LOGDIR));
	io_nextid(tofree, sessid);
	snprintf(tofree + sizeof(_PATH_SUDO_IO_LOGDIR), sizeof(sessid) + 2,
	    "%c%c/%c%c/%c%c", sessid[0], sessid[1], sessid[2], sessid[3],
	    sessid[4], sessid[5]);
	details.iolog_path = tofree;
    }

    /*
     * Make local copy of I/O log path and create it, along with any
     * intermediate subdirs.  Calls mkdtemp() if iolog_path ends in XXXXXX.
     */
    len = mkdir_iopath(details.iolog_path, pathbuf, sizeof(pathbuf));
    if (len >= sizeof(pathbuf))
	goto done;

    /*
     * We create 7 files: a log file, a timing file and 5 for input/output.
     */
    io_logfile = open_io_fd(pathbuf, len, "/log", FALSE);
    if (io_logfile == NULL)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);

    io_fds[IOFD_TIMING].v = open_io_fd(pathbuf, len, "/timing",
	iolog_compress);
    if (io_fds[IOFD_TIMING].v == NULL)
	log_error(USE_ERRNO, "Can't create %s", pathbuf);

    if (details.iolog_ttyin) {
	io_fds[IOFD_TTYIN].v = open_io_fd(pathbuf, len, "/ttyin",
	    iolog_compress);
	if (io_fds[IOFD_TTYIN].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_ttyin = NULL;
    }
    if (details.iolog_stdin) {
	io_fds[IOFD_STDIN].v = open_io_fd(pathbuf, len, "/stdin",
	    iolog_compress);
	if (io_fds[IOFD_STDIN].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_stdin = NULL;
    }
    if (details.iolog_ttyout) {
	io_fds[IOFD_TTYOUT].v = open_io_fd(pathbuf, len, "/ttyout",
	    iolog_compress);
	if (io_fds[IOFD_TTYOUT].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_ttyout = NULL;
    }
    if (details.iolog_stdout) {
	io_fds[IOFD_STDOUT].v = open_io_fd(pathbuf, len, "/stdout",
	    iolog_compress);
	if (io_fds[IOFD_STDOUT].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_stdout = NULL;
    }
    if (details.iolog_stderr) {
	io_fds[IOFD_STDERR].v = open_io_fd(pathbuf, len, "/stderr",
	    iolog_compress);
	if (io_fds[IOFD_STDERR].v == NULL)
	    log_error(USE_ERRNO, "Can't create %s", pathbuf);
    } else {
	sudoers_io.log_stderr = NULL;
    }

    gettimeofday(&last_time, NULL);

    fprintf(io_logfile, "%ld:%s:%s:%s:%s\n", (long)last_time.tv_sec,
	details.user ? details.user : "unknown", details.runas_pw->pw_name,
	details.runas_gr ? details.runas_gr->gr_name : "",
	details.tty ? details.tty : "unknown");
    fputs(details.cwd ? details.cwd : "unknown", io_logfile);
    fputc('\n', io_logfile);
    fputs(details.command ? details.command : "unknown", io_logfile);
    for (cur = &argv[1]; *cur != NULL; cur++) {
	if (cur != &argv[1])
	    fputc(' ', io_logfile);
	fputs(*cur, io_logfile);
    }
    fputc('\n', io_logfile);
    fclose(io_logfile);

    rval = TRUE;

done:
    efree(tofree);
    if (details.runas_pw)
	pw_delref(details.runas_pw);
    sudo_endpwent();
    if (details.runas_gr)
	gr_delref(details.runas_gr);
    sudo_endgrent();

    return rval;
}

static void
sudoers_io_close(int exit_status, int error)
{
    int i;

    if (sigsetjmp(error_jmp, 1)) {
	/* called via error(), errorx() or log_error() */
	return;
    }

    for (i = 0; i < IOFD_MAX; i++) {
	if (io_fds[i].v == NULL)
	    continue;
#ifdef HAVE_ZLIB_H
	if (iolog_compress)
	    gzclose(io_fds[i].g);
	else
#endif
	    fclose(io_fds[i].f);
    }
}

static int
sudoers_io_version(int verbose)
{
    if (sigsetjmp(error_jmp, 1)) {
	/* called via error(), errorx() or log_error() */
	return -1;
    }

    sudo_printf(SUDO_CONV_INFO_MSG, "Sudoers I/O plugin version %s\n",
	PACKAGE_VERSION);

    return TRUE;
}

/*
 * Generic I/O logging function.  Called by the I/O logging entry points.
 */
static int
sudoers_io_log(const char *buf, unsigned int len, int idx)
{
    struct timeval now, delay;

    gettimeofday(&now, NULL);

    if (sigsetjmp(error_jmp, 1)) {
	/* called via error(), errorx() or log_error() */
	return -1;
    }

#ifdef HAVE_ZLIB_H
    if (iolog_compress)
	gzwrite(io_fds[idx].g, buf, len);
    else
#endif
	fwrite(buf, 1, len, io_fds[idx].f);
    delay.tv_sec = now.tv_sec;
    delay.tv_usec = now.tv_usec;
    timevalsub(&delay, &last_time);
#ifdef HAVE_ZLIB_H
    if (iolog_compress)
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
