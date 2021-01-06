/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>

#include "pathnames.h"
#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_eventlog.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_iolog.h"
#include "sudo_json.h"
#include "sudo_queue.h"
#include "sudo_util.h"

static unsigned char const gzip_magic[2] = {0x1f, 0x8b};
static unsigned int sessid_max = SESSID_MAX;
static mode_t iolog_filemode = S_IRUSR|S_IWUSR;
static mode_t iolog_dirmode = S_IRWXU;
static uid_t iolog_uid = ROOT_UID;
static gid_t iolog_gid = ROOT_GID;
static bool iolog_gid_set;
static bool iolog_compress;
static bool iolog_flush;

/*
 * Set effective user and group-IDs to iolog_uid and iolog_gid.
 * If restore flag is set, swap them back.
 */
static bool
io_swapids(bool restore)
{
#ifdef HAVE_SETEUID
    static uid_t user_euid = (uid_t)-1;
    static gid_t user_egid = (gid_t)-1;
    debug_decl(io_swapids, SUDO_DEBUG_UTIL);

    if (user_euid == (uid_t)-1)
	user_euid = geteuid();
    if (user_egid == (gid_t)-1)
	user_egid = getegid();

    if (restore) {
	if (seteuid(user_euid) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to restore effective uid to %d", __func__,
		(int)user_euid);
	    sudo_warn("seteuid() %d -> %d", (int)iolog_uid, (int)user_euid);
	    debug_return_bool(false);
	}
	if (setegid(user_egid) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to restore effective gid to %d", __func__,
		(int)user_egid);
	    sudo_warn("setegid() %d -> %d", (int)iolog_gid, (int)user_egid);
	    debug_return_bool(false);
	}
    } else {
	/* Fail silently if the user has insufficient privileges. */
	if (setegid(iolog_gid) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to set effective gid to %d", __func__,
		(int)iolog_gid);
	    debug_return_bool(false);
	}
	if (seteuid(iolog_uid) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to set effective uid to %d", __func__,
		(int)iolog_uid);
	    debug_return_bool(false);
	}
    }
    debug_return_bool(true);
#else
    return false;
#endif
}

/*
 * Create directory and any parent directories as needed.
 */
static bool
iolog_mkdirs(char *path)
{
    mode_t omask;
    struct stat sb;
    int dfd;
    bool ok = true, uid_changed = false;
    debug_decl(iolog_mkdirs, SUDO_DEBUG_UTIL);

    dfd = open(path, O_RDONLY|O_NONBLOCK);
    if (dfd == -1 && errno == EACCES) {
	/* Try again as the I/O log owner (for NFS). */
	if (io_swapids(false)) {
	    dfd = open(path, O_RDONLY|O_NONBLOCK);
	    if (!io_swapids(true)) {
		ok = false;
		goto done;
	    }
	}
    }
    if (dfd != -1 && fstat(dfd, &sb) != -1) {
	if (S_ISDIR(sb.st_mode)) {
	    if (sb.st_uid != iolog_uid || sb.st_gid != iolog_gid) {
		if (fchown(dfd, iolog_uid, iolog_gid) != 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: unable to chown %d:%d %s", __func__,
			(int)iolog_uid, (int)iolog_gid, path);
		}
	    }
	    if ((sb.st_mode & ALLPERMS) != iolog_dirmode) {
		if (fchmod(dfd, iolog_dirmode) != 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: unable to chmod 0%o %s", __func__,
			(int)iolog_dirmode, path);
		}
	    }
	} else {
	    sudo_warnx(U_("%s exists but is not a directory (0%o)"),
		path, (unsigned int) sb.st_mode);
	    ok = false;
	}
	goto done;
    }

    /* umask must not be more restrictive than the file modes. */
    omask = umask(ACCESSPERMS & ~(iolog_filemode|iolog_dirmode));

    ok = sudo_mkdir_parents(path, iolog_uid, iolog_gid, iolog_dirmode, true);
    if (!ok && errno == EACCES) {
	/* Try again as the I/O log owner (for NFS). */
	uid_changed = io_swapids(false);
	if (uid_changed)
	    ok = sudo_mkdir_parents(path, -1, -1, iolog_dirmode, false);
    }
    if (ok) {
	/* Create final path component. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "mkdir %s, mode 0%o", path, (unsigned int) iolog_dirmode);
	ok = mkdir(path, iolog_dirmode) == 0 || errno == EEXIST;
	if (!ok) {
	    if (errno == EACCES && !uid_changed) {
		/* Try again as the I/O log owner (for NFS). */
		uid_changed = io_swapids(false);
		if (uid_changed)
		    ok = mkdir(path, iolog_dirmode) == 0 || errno == EEXIST;
	    }
	    if (!ok)
		sudo_warn(U_("unable to mkdir %s"), path);
	} else {
	    if (chown(path, iolog_uid, iolog_gid) != 0) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		    "%s: unable to chown %d:%d %s", __func__,
		    (int)iolog_uid, (int)iolog_gid, path);
	    }
	}
    }
    if (uid_changed) {
	if (!io_swapids(true))
	    ok = false;
    }

    umask(omask);

done:
    if (dfd != -1)
	close(dfd);
    debug_return_bool(ok);
}

/*
 * Create temporary directory and any parent directories as needed.
 */
bool
iolog_mkdtemp(char *path)
{
    bool ok, uid_changed = false;
    debug_decl(iolog_mkdtemp, SUDO_DEBUG_UTIL);

    ok = sudo_mkdir_parents(path, iolog_uid, iolog_gid, iolog_dirmode, true);
    if (!ok && errno == EACCES) {
	/* Try again as the I/O log owner (for NFS). */
	uid_changed = io_swapids(false);
	if (uid_changed)
	    ok = sudo_mkdir_parents(path, -1, -1, iolog_dirmode, false);
    }
    if (ok) {
	/* Create final path component. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "mkdtemp %s", path);
	/* We cannot retry mkdtemp() so always open as iolog user */
	if (!uid_changed)
	    uid_changed = io_swapids(false);
	if (mkdtemp(path) == NULL) {
	    sudo_warn(U_("unable to mkdir %s"), path);
	    ok = false;
	} else {
	    if (chmod(path, iolog_dirmode) != 0) {
		sudo_warn(U_("unable to change mode of %s to 0%o"),
		    path, (unsigned int)iolog_dirmode);
	    }
	}
    }

    if (uid_changed) {
	if (!io_swapids(true))
	    ok = false;
    }
    debug_return_bool(ok);
}

/*
 * Like rename(2) but changes UID as needed.
 */
bool
iolog_rename(const char *from, const char *to)
{
    bool ok, uid_changed = false;
    debug_decl(iolog_rename, SUDO_DEBUG_UTIL);

    ok = rename(from, to) == 0;
    if (!ok && errno == EACCES) {
	uid_changed = io_swapids(false);
	if (uid_changed)
	    ok = rename(from, to) == 0;
    }

    if (uid_changed) {
	if (!io_swapids(true))
	    ok = false;
    }
    debug_return_bool(ok);
}

/*
 * Reset I/O log settings to default values.
 */
void
iolog_set_defaults(void)
{
    sessid_max = SESSID_MAX;
    iolog_filemode = S_IRUSR|S_IWUSR;
    iolog_dirmode = S_IRWXU;
    iolog_uid = ROOT_UID;
    iolog_gid = ROOT_GID;
    iolog_gid_set = false;
    iolog_compress = false;
    iolog_flush = false;
}

/*
 * Set max sequence number (aka session ID)
 */
void
iolog_set_maxseq(unsigned int newval)
{
    debug_decl(iolog_set_maxseq, SUDO_DEBUG_UTIL);

    /* Clamp to SESSID_MAX as documented. */
    if (newval > SESSID_MAX)
	newval = SESSID_MAX;
    sessid_max = newval;

    debug_return;
}

/*
 * Set iolog_uid (and iolog_gid if gid not explicitly set).
 */
void
iolog_set_owner(uid_t uid, gid_t gid)
{
    debug_decl(iolog_set_owner, SUDO_DEBUG_UTIL);

    iolog_uid = uid;
    if (!iolog_gid_set)
	iolog_gid = gid;

    debug_return;
}

/*
 * Set iolog_gid.
 */
void
iolog_set_gid(gid_t gid)
{
    debug_decl(iolog_set_gid, SUDO_DEBUG_UTIL);

    iolog_gid = gid;
    iolog_gid_set = true;

    debug_return;
}

/*
 * Set iolog_filemode and iolog_dirmode.
 */
void
iolog_set_mode(mode_t mode)
{
    debug_decl(iolog_set_mode, SUDO_DEBUG_UTIL);

    /* I/O log files must be readable and writable by owner. */
    iolog_filemode = S_IRUSR|S_IWUSR;

    /* Add in group and other read/write if specified. */
    iolog_filemode |= mode & (S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

    /* For directory mode, add execute bits as needed. */
    iolog_dirmode = iolog_filemode | S_IXUSR;
    if (iolog_dirmode & (S_IRGRP|S_IWGRP))
	iolog_dirmode |= S_IXGRP;
    if (iolog_dirmode & (S_IROTH|S_IWOTH))
	iolog_dirmode |= S_IXOTH;

    debug_return;
}

/*
 * Set iolog_compress
 */
void
iolog_set_compress(bool newval)
{
    debug_decl(iolog_set_compress, SUDO_DEBUG_UTIL);
    iolog_compress = newval;
    debug_return;
}

/*
 * Set iolog_flush
 */
void
iolog_set_flush(bool newval)
{
    debug_decl(iolog_set_flush, SUDO_DEBUG_UTIL);
    iolog_flush = newval;
    debug_return;
}

/*
 * Wrapper for openat(2) that sets umask and retries as iolog_uid/iolog_gid
 * if openat(2) returns EACCES.
 */
int
iolog_openat(int dfd, const char *path, int flags)
{
    int fd;
    mode_t omask = S_IRWXG|S_IRWXO;
    debug_decl(iolog_openat, SUDO_DEBUG_UTIL);

    if (ISSET(flags, O_CREAT)) {
	/* umask must not be more restrictive than the file modes. */
	omask = umask(ACCESSPERMS & ~(iolog_filemode|iolog_dirmode));
    }
    fd = openat(dfd, path, flags, iolog_filemode);
    if (fd == -1 && errno == EACCES) {
	/* Enable write bit if it is missing. */
	struct stat sb;
	if (fstatat(dfd, path, &sb, 0) == 0) {
	    mode_t write_bits = iolog_filemode & (S_IWUSR|S_IWGRP|S_IWOTH);
	    if ((sb.st_mode & write_bits) != write_bits) {
		if (fchmodat(dfd, path, iolog_filemode, 0) == 0)
		    fd = openat(dfd, path, flags, iolog_filemode);
	    }
	}
    }
    if (fd == -1 && errno == EACCES) {
	/* Try again as the I/O log owner (for NFS). */
	if (io_swapids(false)) {
	    fd = openat(dfd, path, flags, iolog_filemode);
	    if (!io_swapids(true)) {
		/* io_swapids() warns on error. */
		if (fd != -1) {
		    close(fd);
		    fd = -1;
		}
	    }
	}
    }
    if (ISSET(flags, O_CREAT))
	umask(omask);
    debug_return_int(fd);
}

/*
 * Read the on-disk sequence number, set sessid to the next
 * number, and update the on-disk copy.
 * Uses file locking to avoid sequence number collisions.
 */
bool
iolog_nextid(char *iolog_dir, char sessid[7])
{
    char buf[32], *ep;
    int i, len, fd = -1;
    unsigned long id = 0;
    ssize_t nread;
    bool ret = false;
    char pathbuf[PATH_MAX];
    static const char b36char[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    debug_decl(iolog_nextid, SUDO_DEBUG_UTIL);

    /*
     * Create I/O log directory if it doesn't already exist.
     */
    if (!iolog_mkdirs(iolog_dir))
	goto done;

    /*
     * Open sequence file
     */
    len = snprintf(pathbuf, sizeof(pathbuf), "%s/seq", iolog_dir);
    if (len < 0 || len >= ssizeof(pathbuf)) {
	errno = ENAMETOOLONG;
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: %s/seq", __func__, iolog_dir);
	goto done;
    }
    fd = iolog_openat(AT_FDCWD, pathbuf, O_RDWR|O_CREAT);
    if (fd == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to open %s", __func__, pathbuf);
	goto done;
    }
    if (!sudo_lock_file(fd, SUDO_LOCK)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to lock %s", pathbuf);
	goto done;
    }
    if (fchown(fd, iolog_uid, iolog_gid) != 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to fchown %d:%d %s", __func__,
	    (int)iolog_uid, (int)iolog_gid, pathbuf);
    }

    /* Read current seq number (base 36). */
    nread = read(fd, buf, sizeof(buf) - 1);
    if (nread != 0) {
	if (nread == -1) {
	    goto done;
	}
	if (buf[nread - 1] == '\n')
	    nread--;
	buf[nread] = '\0';
	id = strtoul(buf, &ep, 36);
	if (ep == buf || *ep != '\0' || id >= sessid_max) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: bad sequence number: %s", pathbuf, buf);
	    id = 0;
	}
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

    /* Stash id for logging purposes. */
    memcpy(sessid, buf, 6);
    sessid[6] = '\0';

    /* Rewind and overwrite old seq file, including the NUL byte. */
#ifdef HAVE_PWRITE
    if (pwrite(fd, buf, 7, 0) != 7) {
#else
    if (lseek(fd, 0, SEEK_SET) == -1 || write(fd, buf, 7) != 7) {
#endif
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to write %s", __func__, pathbuf);
	goto done;
    }
    ret = true;

done:
    if (fd != -1)
	close(fd);
    debug_return_bool(ret);
}

/*
 * Create path and any intermediate directories.
 * If path ends in 'XXXXXX', use mkdtemp().
 */
bool
iolog_mkpath(char *path)
{
    size_t len;
    bool ret;
    debug_decl(iolog_mkpath, SUDO_DEBUG_UTIL);

    /*
     * Create path and intermediate subdirs as needed.
     * If path ends in at least 6 Xs (ala POSIX mktemp), use mkdtemp().
     * Sets iolog_gid (if it is not already set) as a side effect.
     */
    len = strlen(path);
    if (len >= 6 && strcmp(&path[len - 6], "XXXXXX") == 0)
	ret = iolog_mkdtemp(path);
    else
	ret = iolog_mkdirs(path);

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO, "iolog path %s", path);

    debug_return_bool(ret);
}

/*
 * Append suffix to pathbuf after len chars and open the resulting file.
 * Note that the size of pathbuf is assumed to be PATH_MAX.
 * Stores the open file handle which has the close-on-exec flag set.
 * XXX - move enabled logic into caller?
 */
bool
iolog_open(struct iolog_file *iol, int dfd, int iofd, const char *mode)
{
    int flags;
    const char *file;
    unsigned char magic[2];
    debug_decl(iolog_open, SUDO_DEBUG_UTIL);

    if (mode[0] == 'r') {
	flags = mode[1] == '+' ? O_RDWR : O_RDONLY;
    } else if (mode[0] == 'w') {
	flags = O_CREAT|O_TRUNC;
	flags |= mode[1] == '+' ? O_RDWR : O_WRONLY;
    } else {
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "%s: invalid I/O mode %s", __func__, mode);
	debug_return_bool(false);
    }
    if ((file = iolog_fd_to_name(iofd)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR,
	    "%s: invalid iofd %d", __func__, iofd);
	debug_return_bool(false);
    }

    iol->writable = false;
    iol->compressed = false;
    if (iol->enabled) {
	int fd = iolog_openat(dfd, file, flags);
	if (fd != -1) {
	    if (*mode == 'w') {
		if (fchown(fd, iolog_uid, iolog_gid) != 0) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"%s: unable to fchown %d:%d %s", __func__,
			(int)iolog_uid, (int)iolog_gid, file);
		}
		iol->compressed = iolog_compress;
	    } else {
		/* check for gzip magic number */
		if (pread(fd, magic, sizeof(magic), 0) == ssizeof(magic)) {
		    if (magic[0] == gzip_magic[0] && magic[1] == gzip_magic[1])
			iol->compressed = true;
		}
	    }
	    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != -1) {
#ifdef HAVE_ZLIB_H
		if (iol->compressed)
		    iol->fd.g = gzdopen(fd, mode);
		else
#endif
		    iol->fd.f = fdopen(fd, mode);
	    }
	    if (iol->fd.v != NULL) {
		switch ((flags & O_ACCMODE)) {
		case O_WRONLY:
		case O_RDWR:
		    iol->writable = true;
		    break;
		}
	    } else {
		int save_errno = errno;
		close(fd);
		errno = save_errno;
		fd = -1;
	    }
	}
	if (fd == -1) {
	    iol->enabled = false;
	    debug_return_bool(false);
	}
    } else {
	if (*mode == 'w') {
	    /* Remove old log file in case we recycled sequence numbers. */
	    (void)unlinkat(dfd, file, 0);
	}
    }
    debug_return_bool(true);
}

#ifdef HAVE_ZLIB_H
static const char *
gzstrerror(gzFile file)
{
    const char *errstr;
    int errnum;

    errstr = gzerror(file, &errnum);
    if (errnum == Z_ERRNO)
	errstr = strerror(errno);

    return errstr;
}
#endif /* HAVE_ZLIB_H */

/*
 * Close an I/O log.
 */
bool
iolog_close(struct iolog_file *iol, const char **errstr)
{
    bool ret = true;
    debug_decl(iolog_close, SUDO_DEBUG_UTIL);

#ifdef HAVE_ZLIB_H
    if (iol->compressed) {
	int errnum;

	/* Must check error indicator before closing. */
	if (iol->writable) {
	    if (gzflush(iol->fd.g, Z_SYNC_FLUSH) != Z_OK) {
		ret = false;
		if (errstr != NULL)
		    *errstr = gzstrerror(iol->fd.g);
	    }
	}
	errnum = gzclose(iol->fd.g);
	if (ret && errnum != Z_OK) {
	    ret = false;
	    if (errstr != NULL)
		*errstr = errnum == Z_ERRNO ? strerror(errno) : "unknown error";
	}
    } else
#endif
    if (fclose(iol->fd.f) != 0) {
	ret = false;
	if (errstr != NULL)
	    *errstr = strerror(errno);
    }

    debug_return_bool(ret);
}

/*
 * I/O log wrapper for fseek/gzseek.
 */
off_t
iolog_seek(struct iolog_file *iol, off_t offset, int whence)
{
    off_t ret;
    //debug_decl(iolog_seek, SUDO_DEBUG_UTIL);

#ifdef HAVE_ZLIB_H
    if (iol->compressed)
	ret = gzseek(iol->fd.g, offset, whence);
    else
#endif
	ret = fseeko(iol->fd.f, offset, whence);

    //debug_return_off_t(ret);
    return ret;
}

/*
 * I/O log wrapper for rewind/gzrewind.
 */
void
iolog_rewind(struct iolog_file *iol)
{
    debug_decl(iolog_rewind, SUDO_DEBUG_UTIL);

#ifdef HAVE_ZLIB_H
    if (iol->compressed)
	(void)gzrewind(iol->fd.g);
    else
#endif
	rewind(iol->fd.f);

    debug_return;
}

/*
 * Read from a (possibly compressed) I/O log file.
 */
ssize_t
iolog_read(struct iolog_file *iol, void *buf, size_t nbytes,
    const char **errstr)
{
    ssize_t nread;
    debug_decl(iolog_read, SUDO_DEBUG_UTIL);

    if (nbytes > UINT_MAX) {
	errno = EINVAL;
	if (errstr != NULL)
	    *errstr = strerror(errno);
	debug_return_ssize_t(-1);
    }

#ifdef HAVE_ZLIB_H
    if (iol->compressed) {
	if ((nread = gzread(iol->fd.g, buf, nbytes)) == -1) {
	    if (errstr != NULL)
		*errstr = gzstrerror(iol->fd.g);
	}
    } else
#endif
    {
	nread = (ssize_t)fread(buf, 1, nbytes, iol->fd.f);
	if (nread == 0 && ferror(iol->fd.f)) {
	    nread = -1;
	    if (errstr != NULL)
		*errstr = strerror(errno);
	}
    }
    debug_return_ssize_t(nread);
}

/*
 * Write to an I/O log, optionally compressing.
 */
ssize_t
iolog_write(struct iolog_file *iol, const void *buf, size_t len,
    const char **errstr)
{
    ssize_t ret;
    debug_decl(iolog_write, SUDO_DEBUG_UTIL);

    if (len > UINT_MAX) {
	errno = EINVAL;
	if (errstr != NULL)
	    *errstr = strerror(errno);
	debug_return_ssize_t(-1);
    }

#ifdef HAVE_ZLIB_H
    if (iol->compressed) {
	ret = gzwrite(iol->fd.g, (const voidp)buf, len);
	if (ret == 0) {
	    ret = -1;
	    if (errstr != NULL)
		*errstr = gzstrerror(iol->fd.g);
	    goto done;
	}
	if (iolog_flush) {
	    if (gzflush(iol->fd.g, Z_SYNC_FLUSH) != Z_OK) {
		ret = -1;
		if (errstr != NULL)
		    *errstr = gzstrerror(iol->fd.g);
		goto done;
	    }
	}
    } else
#endif
    {
	ret = fwrite(buf, 1, len, iol->fd.f);
	if (ret == 0) {
	    ret = -1;
	    if (errstr != NULL)
		*errstr = strerror(errno);
	    goto done;
	}
	if (iolog_flush) {
	    if (fflush(iol->fd.f) != 0) {
		ret = -1;
		if (errstr != NULL)
		    *errstr = strerror(errno);
		goto done;
	    }
	}
    }

done:
    debug_return_ssize_t(ret);
}

/*
 * Returns true if at end of I/O log file, else false.
 */
bool
iolog_eof(struct iolog_file *iol)
{
    bool ret;
    debug_decl(iolog_eof, SUDO_DEBUG_UTIL);

#ifdef HAVE_ZLIB_H
    if (iol->compressed)
	ret = gzeof(iol->fd.g) == 1;
    else
#endif
	ret = feof(iol->fd.f) == 1;
    debug_return_int(ret);
}

void
iolog_clearerr(struct iolog_file *iol)
{
    debug_decl(iolog_eof, SUDO_DEBUG_UTIL);

#ifdef HAVE_ZLIB_H
    if (iol->compressed)
	gzclearerr(iol->fd.g);
    else
#endif
	clearerr(iol->fd.f);
    debug_return;
}

/*
 * Like gets() but for struct iolog_file.
 */
char *
iolog_gets(struct iolog_file *iol, char *buf, size_t nbytes,
    const char **errstr)
{
    char *str;
    debug_decl(iolog_gets, SUDO_DEBUG_UTIL);

    if (nbytes > UINT_MAX) {
	errno = EINVAL;
	if (errstr != NULL)
	    *errstr = strerror(errno);
	debug_return_str(NULL);
    }

#ifdef HAVE_ZLIB_H
    if (iol->compressed) {
	if ((str = gzgets(iol->fd.g, buf, nbytes)) == NULL) {
	    if (errstr != NULL)
		*errstr = gzstrerror(iol->fd.g);
	}
    } else
#endif
    {
	if ((str = fgets(buf, nbytes, iol->fd.f)) == NULL) {
	    if (errstr != NULL)
		*errstr = strerror(errno);
	}
    }
    debug_return_str(str);
}

/*
 * Write the legacy I/O log file that contains the user and command info.
 * This file is not compressed.
 */
static bool
iolog_write_info_file_legacy(int dfd, struct eventlog *evlog)
{
    char * const *av;
    FILE *fp;
    int error, fd;
    debug_decl(iolog_info_write_log, SUDO_DEBUG_UTIL);

    fd = iolog_openat(dfd, "log", O_CREAT|O_TRUNC|O_WRONLY);
    if (fd == -1 || (fp = fdopen(fd, "w")) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to open %s/log", evlog->iolog_path);
	if (fd != -1)
	    close(fd);
	debug_return_bool(false);
    }
    if (fchown(fd, iolog_uid, iolog_gid) != 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to fchown %d:%d %s/log", __func__,
	    (int)iolog_uid, (int)iolog_gid, evlog->iolog_path);
    }

    fprintf(fp, "%lld:%s:%s:%s:%s:%d:%d\n%s\n",
	(long long)evlog->submit_time.tv_sec,
	evlog->submituser ? evlog->submituser : "unknown",
	evlog->runuser ? evlog->runuser : RUNAS_DEFAULT,
	evlog->rungroup ? evlog->rungroup : "",
	evlog->ttyname ? evlog->ttyname : "unknown",
	evlog->lines, evlog->columns,
	evlog->cwd ? evlog->cwd : "unknown");
    fputs(evlog->command ? evlog->command : "unknown", fp);
    for (av = evlog->argv + 1; *av != NULL; av++) {
	fputc(' ', fp);
	fputs(*av, fp);
    }
    fputc('\n', fp);
    fflush(fp);
    if ((error = ferror(fp))) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to write to I/O log file %s/log", evlog->iolog_path);
    }
    fclose(fp);

    debug_return_bool(!error);
}

/*
 * Write the "log.json" file that contains the user and command info.
 * This file is not compressed.
 */
static bool
iolog_write_info_file_json(int dfd, struct eventlog *evlog)
{
    struct json_container json;
    struct json_value json_value;
    bool ret = false;
    FILE *fp = NULL;
    int fd = -1;
    debug_decl(iolog_write_info_file_json, SUDO_DEBUG_UTIL);

    if (!sudo_json_init(&json, 4, false, false))
	debug_return_bool(false);

    /* Timestamp */
    if (!sudo_json_open_object(&json, "timestamp"))
	goto oom;

    json_value.type = JSON_NUMBER;
    json_value.u.number = evlog->submit_time.tv_sec;
    if (!sudo_json_add_value(&json, "seconds", &json_value))
        goto oom;

    json_value.type = JSON_NUMBER;
    json_value.u.number = evlog->submit_time.tv_nsec;
    if (!sudo_json_add_value(&json, "nanoseconds", &json_value))
        goto oom;

    if (!sudo_json_close_object(&json))
	goto oom;

    if (!eventlog_store_json(&json, evlog))
	goto done;

    fd = iolog_openat(dfd, "log.json", O_CREAT|O_TRUNC|O_WRONLY);
    if (fd == -1 || (fp = fdopen(fd, "w")) == NULL) {
        sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
            "unable to open %s/log.json", evlog->iolog_path);
        goto done;
    }

    if (fchown(fd, iolog_uid, iolog_gid) != 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "%s: unable to fchown %d:%d %s/log", __func__,
	    (int)iolog_uid, (int)iolog_gid, evlog->iolog_path);
    }
    fd = -1;

    fprintf(fp, "{%s\n}\n", sudo_json_get_buf(&json));
    fflush(fp);
    if (ferror(fp)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
            "unable to write to I/O log file %s/log.json", evlog->iolog_path);
	goto done;
    }

    ret = true;
    goto done;

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
done:
    sudo_json_free(&json);
    if (fp != NULL)
	fclose(fp);
    if (fd != -1)
	close(fd);

    debug_return_bool(ret);
}

/*
 * Write the I/O log and log.json files that contain user and command info.
 * These files are not compressed.
 */
bool
iolog_write_info_file(int dfd, struct eventlog *evlog)
{
    debug_decl(iolog_write_info_file, SUDO_DEBUG_UTIL);

    if (!iolog_write_info_file_legacy(dfd, evlog))
	debug_return_bool(false);
    if (!iolog_write_info_file_json(dfd, evlog))
	debug_return_bool(false);

    debug_return_bool(true);
}

/*
 * Map IOFD_* -> name.
 */
const char *
iolog_fd_to_name(int iofd)
{
    const char *ret;
    debug_decl(iolog_fd_to_name, SUDO_DEBUG_UTIL);

    switch (iofd) {
    case IOFD_STDIN:
	ret = "stdin";
	break;
    case IOFD_STDOUT:
	ret = "stdout";
	break;
    case IOFD_STDERR:
	ret = "stderr";
	break;
    case IOFD_TTYIN:
	ret = "ttyin";
	break;
    case IOFD_TTYOUT:
	ret = "ttyout";
	break;
    case IOFD_TIMING:
	ret = "timing";
	break;
    default:
	ret = "unknown";
	sudo_debug_printf(SUDO_DEBUG_ERROR, "%s: unexpected iofd %d",
	    __func__, iofd);
	break;
    }
    debug_return_const_str(ret);
}
