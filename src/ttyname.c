/*
 * Copyright (c) 2012-2017 Todd C. Miller <Todd.Miller@courtesan.com>
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

/* Large files not supported by procfs.h on Solaris. */
#if defined(HAVE_STRUCT_PSINFO_PR_TTYDEV)
# undef _FILE_OFFSET_BITS
# undef _LARGE_FILES
#endif

#include <sys/types.h>
#include <sys/stat.h>
#if defined(MAJOR_IN_MKDEV)
# include <sys/mkdev.h>
#elif defined(MAJOR_IN_SYSMACROS)
# include <sys/sysmacros.h>
#endif
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
#include <limits.h>
#include <dirent.h>
#if defined(HAVE_STRUCT_KINFO_PROC_P_TDEV) || defined (HAVE_STRUCT_KINFO_PROC_KP_EPROC_E_TDEV) || defined(HAVE_STRUCT_KINFO_PROC2_P_TDEV)
# include <sys/param.h>		/* for makedev/major/minor */
# include <sys/sysctl.h>
#elif defined(HAVE_STRUCT_KINFO_PROC_KI_TDEV)
# include <sys/param.h>		/* for makedev/major/minor */
# include <sys/sysctl.h>
# include <sys/user.h>
#endif
#if defined(HAVE_PROCFS_H)
# include <procfs.h>
#elif defined(HAVE_SYS_PROCFS_H)
# include <sys/procfs.h>
#endif
#ifdef HAVE_PSTAT_GETPROC
# include <sys/param.h>		/* for makedev/major/minor */
# include <sys/pstat.h>
#endif

#include "sudo.h"

#if defined(HAVE_STRUCT_DIRENT_D_NAMLEN) && HAVE_STRUCT_DIRENT_D_NAMLEN
# define NAMLEN(dirent)	(dirent)->d_namlen
#else
# define NAMLEN(dirent)	strlen((dirent)->d_name)
#endif

/*
 * How to access the tty device number in struct kinfo_proc.
 */
#if defined(HAVE_STRUCT_KINFO_PROC2_P_TDEV)
# define SUDO_KERN_PROC		KERN_PROC2
# define sudo_kinfo_proc	kinfo_proc2
# define sudo_kp_tdev		p_tdev
# define sudo_kp_namelen	6
#elif defined(HAVE_STRUCT_KINFO_PROC_P_TDEV)
# define SUDO_KERN_PROC		KERN_PROC
# define sudo_kinfo_proc	kinfo_proc
# define sudo_kp_tdev		p_tdev
# define sudo_kp_namelen	6
#elif defined(HAVE_STRUCT_KINFO_PROC_KI_TDEV)
# define SUDO_KERN_PROC		KERN_PROC
# define sudo_kinfo_proc	kinfo_proc
# define sudo_kp_tdev		ki_tdev
# define sudo_kp_namelen	4
#elif defined(HAVE_STRUCT_KINFO_PROC_KP_EPROC_E_TDEV)
# define SUDO_KERN_PROC		KERN_PROC
# define sudo_kinfo_proc	kinfo_proc
# define sudo_kp_tdev		kp_eproc.e_tdev
# define sudo_kp_namelen	4
#endif

#if defined(sudo_kp_tdev)
/*
 * Like ttyname() but uses a dev_t instead of an open fd.
 * Returns name on success and NULL on failure, setting errno.
 * The BSD version uses devname().
 */
static char *
sudo_ttyname_dev(dev_t tdev, char *name, size_t namelen)
{
    char *dev;
    debug_decl(sudo_ttyname_dev, SUDO_DEBUG_UTIL)

    /* Some versions of devname() return NULL on failure, others do not. */
    dev = devname(tdev, S_IFCHR);
    if (dev != NULL && *dev != '?' && *dev != '#') {
	if (strlcpy(name, _PATH_DEV, namelen) < namelen &&
	    strlcat(name, dev, namelen) < namelen)
	    debug_return_str(name);
	errno = ERANGE;
    } else {
	/* Not all versions of devname() set errno. */
	errno = ENOENT;
    }
    debug_return_str(NULL);
}
#elif defined(HAVE__TTYNAME_DEV)
extern char *_ttyname_dev(dev_t rdev, char *buffer, size_t buflen);

/*
 * Like ttyname() but uses a dev_t instead of an open fd.
 * Returns name on success and NULL on failure, setting errno.
 * This version is just a wrapper around _ttyname_dev().
 */
static char *
sudo_ttyname_dev(dev_t tdev, char *name, size_t namelen)
{
    int serrno = errno;
    debug_decl(sudo_ttyname_dev, SUDO_DEBUG_UTIL)

    /*
     * _ttyname_dev() sets errno to ERANGE if namelen is too small
     * but does not modify it if tdev is not found.
     */
    errno = ENOENT;
    if (_ttyname_dev(tdev, name, namelen) == NULL)
	debug_return_str(NULL);
    errno = serrno;

    debug_return_str(name);
}
#elif defined(HAVE_STRUCT_PSINFO_PR_TTYDEV) || defined(HAVE_PSTAT_GETPROC) || defined(__linux__)
/*
 * Device nodes and directories to search before searching all of /dev
 */
static char *search_devs[] = {
    "/dev/console",
    "/dev/pts/",	/* POSIX pty */
    "/dev/vt/",		/* Solaris virtual console */
    "/dev/term/",	/* Solaris serial ports */
    "/dev/zcons/",	/* Solaris zone console */
    "/dev/pty/",	/* HP-UX old-style pty */
    NULL
};

/*
 * Device nodes to ignore when searching all of /dev
 */
static char *ignore_devs[] = {
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    NULL
};

/*
 * Do a scan of a directory looking for the specified device.
 * Does not descend into subdirectories.
 * Returns name on success and NULL on failure, setting errno.
 */
static char *
sudo_ttyname_scan(const char *dir, dev_t rdev, char *name, size_t namelen)
{
    size_t sdlen;
    char pathbuf[PATH_MAX];
    char *ret = NULL;
    struct dirent *dp;
    struct stat sb;
    unsigned int i;
    DIR *d = NULL;
    debug_decl(sudo_ttyname_scan, SUDO_DEBUG_UTIL)

    if (dir[0] == '\0') {
	errno = ENOENT;
	goto done;
    }
    if ((d = opendir(dir)) == NULL)
	goto done;

    if (fstat(dirfd(d), &sb) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to fstat %s", dir);
	goto done;
    }
    if ((sb.st_mode & S_IWOTH) != 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "ignoring world-writable directory %s", dir);
	errno = ENOENT;
	goto done;
    }

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"scanning for dev %u in %s", (unsigned int)rdev, dir);

    sdlen = strlen(dir);
    if (dir[sdlen - 1] == '/')
	sdlen--;
    if (sdlen + 1 >= sizeof(pathbuf)) {
	errno = ERANGE;
	goto done;
    }
    memcpy(pathbuf, dir, sdlen);
    pathbuf[sdlen++] = '/';
    pathbuf[sdlen] = '\0';

    while ((dp = readdir(d)) != NULL) {
	struct stat sb;
	size_t d_len, len;

	/* Skip anything starting with "." */
	if (dp->d_name[0] == '.')
	    continue;

	d_len = NAMLEN(dp);
	if (sdlen + d_len >= sizeof(pathbuf))
	    continue;
	memcpy(&pathbuf[sdlen], dp->d_name, d_len + 1); /* copy NUL too */
	d_len += sdlen;

	for (i = 0; ignore_devs[i] != NULL; i++) {
	    len = strlen(ignore_devs[i]);
	    if (ignore_devs[i][len - 1] == '/')
		len--;
	    if (d_len == len && strncmp(pathbuf, ignore_devs[i], len) == 0)
		break;
	}
	if (ignore_devs[i] != NULL)
	    continue;
# if defined(HAVE_STRUCT_DIRENT_D_TYPE) && defined(DTTOIF)
	/*
	 * Avoid excessive stat() calls by checking dp->d_type.
	 */
	switch (dp->d_type) {
	    case DT_CHR:
	    case DT_LNK:
	    case DT_UNKNOWN:
		/* Could be a character device, stat() it. */
		if (stat(pathbuf, &sb) == -1)
		    continue;
		break;
	    default:
		/* Not a character device or link, skip it. */
		continue;
	}
# else
	if (stat(pathbuf, &sb) == -1)
	    continue;
# endif
	if (S_ISCHR(sb.st_mode) && sb.st_rdev == rdev) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"resolved dev %u as %s", (unsigned int)rdev, pathbuf);
	    if (strlcpy(name, pathbuf, namelen) < namelen) {
		ret = name;
	    } else {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "unable to store %s, have %zu, need %zu",
		    pathbuf, namelen, strlen(pathbuf) + 1);
		errno = ERANGE;
	    }
	    goto done;
	}
    }

done:
    if (d != NULL)
	closedir(d);
    debug_return_str(ret);
}

/*
 * Like ttyname() but uses a dev_t instead of an open fd.
 * Returns name on success and NULL on failure, setting errno.
 * Generic version.
 */
static char *
sudo_ttyname_dev(dev_t rdev, char *name, size_t namelen)
{
    char buf[PATH_MAX], **sd, *devname;
    char *ret = NULL;
    struct stat sb;
    size_t len;
    debug_decl(sudo_ttyname_dev, SUDO_DEBUG_UTIL)

    /*
     * First check search_devs[] for common tty devices.
     */
    for (sd = search_devs; (devname = *sd) != NULL; sd++) {
	len = strlen(devname);
	if (devname[len - 1] == '/') {
	    if (strcmp(devname, "/dev/pts/") == 0) {
		/* Special case /dev/pts */
		(void)snprintf(buf, sizeof(buf), "%spts/%u", _PATH_DEV,
		    (unsigned int)minor(rdev));
		if (stat(buf, &sb) == 0) {
		    if (S_ISCHR(sb.st_mode) && sb.st_rdev == rdev) {
			sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
			    "comparing dev %u to %s: match!",
			    (unsigned int)rdev, buf);
			if (strlcpy(name, buf, namelen) < namelen)
			    ret = name;
			else
			    errno = ERANGE;
			goto done;
		    }
		}
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "comparing dev %u to %s: no", (unsigned int)rdev, buf);
	    } else {
		/* Traverse directory */
		ret = sudo_ttyname_scan(devname, rdev, name, namelen);
		if (ret != NULL || errno == ENOMEM)
		    goto done;
	    }
	} else {
	    if (stat(devname, &sb) == 0) {
		if (S_ISCHR(sb.st_mode) && sb.st_rdev == rdev) {
		    if (strlcpy(name, devname, namelen) < namelen)
			ret = name;
		    else
			errno = ERANGE;
		    goto done;
		}
	    }
	}
    }

    /*
     * Not found?  Check all device nodes in /dev.
     */
    ret = sudo_ttyname_scan(_PATH_DEV, rdev, name, namelen);

done:
    debug_return_str(ret);
}
#endif

#if defined(sudo_kp_tdev)
/*
 * Store the name of the tty to which the process is attached in name.
 * Returns name on success and NULL on failure, setting errno.
 */
char *
get_process_ttyname(char *name, size_t namelen)
{
    struct sudo_kinfo_proc *ki_proc = NULL;
    size_t size = sizeof(*ki_proc);
    int mib[6], rc, serrno = errno;
    char *ret = NULL;
    debug_decl(get_process_ttyname, SUDO_DEBUG_UTIL)

    /*
     * Lookup controlling tty for this process via sysctl.
     * This will work even if std{in,out,err} are redirected.
     */
    mib[0] = CTL_KERN;
    mib[1] = SUDO_KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = (int)getpid();
    mib[4] = sizeof(*ki_proc);
    mib[5] = 1;
    do {
	struct sudo_kinfo_proc *kp;

	size += size / 10;
	if ((kp = realloc(ki_proc, size)) == NULL) {
	    rc = -1;
	    break;		/* really out of memory. */
	}
	ki_proc = kp;
	rc = sysctl(mib, sudo_kp_namelen, ki_proc, &size, NULL, 0);
    } while (rc == -1 && errno == ENOMEM);
    errno = ENOENT;
    if (rc != -1) {
	if ((dev_t)ki_proc->sudo_kp_tdev != (dev_t)-1) {
	    errno = serrno;
	    ret = sudo_ttyname_dev(ki_proc->sudo_kp_tdev, name, namelen);
	    if (ret == NULL) {
		sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		    "unable to map device number %u to name",
		    ki_proc->sudo_kp_tdev);
	    }
	}
    } else {
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to resolve tty via KERN_PROC");
    }
    free(ki_proc);

    debug_return_str(ret);
}
#elif defined(HAVE_STRUCT_PSINFO_PR_TTYDEV)
/*
 * Store the name of the tty to which the process is attached in name.
 * Returns name on success and NULL on failure, setting errno.
 */
char *
get_process_ttyname(char *name, size_t namelen)
{
    char path[PATH_MAX], *ret = NULL;
    struct psinfo psinfo;
    ssize_t nread;
    int fd, serrno = errno;
    debug_decl(get_process_ttyname, SUDO_DEBUG_UTIL)

    /* Try to determine the tty from pr_ttydev in /proc/pid/psinfo. */
    snprintf(path, sizeof(path), "/proc/%u/psinfo", (unsigned int)getpid());
    if ((fd = open(path, O_RDONLY, 0)) != -1) {
	nread = read(fd, &psinfo, sizeof(psinfo));
	close(fd);
	if (nread == (ssize_t)sizeof(psinfo)) {
	    dev_t rdev = (dev_t)psinfo.pr_ttydev;
#if defined(_AIX) && defined(DEVNO64)
	    if ((psinfo.pr_ttydev & DEVNO64) && sizeof(dev_t) == 4)
		rdev = makedev(major64(psinfo.pr_ttydev), minor64(psinfo.pr_ttydev));
#endif
	    if (rdev != (dev_t)-1) {
		errno = serrno;
		ret = sudo_ttyname_dev(rdev, name, namelen);
		goto done;
	    }
	}
    }
    errno = ENOENT;

done:
    if (ret == NULL)
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to resolve tty via %s", path);

    debug_return_str(ret);
}
#elif defined(__linux__)
/*
 * Store the name of the tty to which the process is attached in name.
 * Returns name on success and NULL on failure, setting errno.
 */
char *
get_process_ttyname(char *name, size_t namelen)
{
    const char path[] = "/proc/self/stat";
    char *cp, buf[1024];
    char *ret = NULL;
    int serrno = errno;
    ssize_t nread;
    int fd;
    debug_decl(get_process_ttyname, SUDO_DEBUG_UTIL)

    /*
     * Try to determine the tty from tty_nr in /proc/self/stat.
     * Ignore /proc/self/stat if it contains embedded NUL bytes.
     */
    if ((fd = open(path, O_RDONLY | O_NOFOLLOW)) != -1) {
	cp = buf;
	while ((nread = read(fd, cp, buf + sizeof(buf) - cp)) != 0) {
	    if (nread == -1) {
		if (errno == EAGAIN || errno == EINTR)
		    continue;
		break;
	    }
	    cp += nread;
	    if (cp >= buf + sizeof(buf))
		break;
	}
	if (nread == 0 && memchr(buf, '\0', cp - buf) == NULL) {
	    /*
	     * Field 7 is the tty dev (0 if no tty).
	     * Since the process name at field 2 "(comm)" may include
	     * whitespace (including newlines), start at the last ')' found.
	     */
	    *cp = '\0';
	    cp = strrchr(buf, ')');
	    if (cp != NULL) {
		char *ep = cp;
		const char *errstr;
		int field = 1;

		while (*++ep != '\0') {
		    if (*ep == ' ') {
			*ep = '\0';
			if (++field == 7) {
			    dev_t tdev = strtonum(cp, INT_MIN, INT_MAX, &errstr);
			    if (errstr) {
				sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
				    "%s: tty device %s: %s", path, cp, errstr);
			    }
			    if (tdev > 0) {
				errno = serrno;
				ret = sudo_ttyname_dev(tdev, name, namelen);
				goto done;
			    }
			    break;
			}
			cp = ep + 1;
		    }
		}
	    }
	}
    }
    errno = ENOENT;

done:
    if (fd != -1)
	close(fd);
    if (ret == NULL)
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to resolve tty via %s", path);

    debug_return_str(ret);
}
#elif defined(HAVE_PSTAT_GETPROC)
/*
 * Store the name of the tty to which the process is attached in name.
 * Returns name on success and NULL on failure, setting errno.
 */
char *
get_process_ttyname(char *name, size_t namelen)
{
    struct pst_status pstat;
    char *ret = NULL;
    int rc, serrno = errno;
    debug_decl(get_process_ttyname, SUDO_DEBUG_UTIL)

    /*
     * Determine the tty from psdev in struct pst_status.
     * We may get EOVERFLOW if the whole thing doesn't fit but that is OK.
     */
    rc = pstat_getproc(&pstat, sizeof(pstat), (size_t)0, (int)getpid());
    if (rc != -1 || errno == EOVERFLOW) {
	if (pstat.pst_term.psd_major != -1 && pstat.pst_term.psd_minor != -1) {
	    errno = serrno;
	    ret = sudo_ttyname_dev(makedev(pstat.pst_term.psd_major,
		pstat.pst_term.psd_minor), name, namelen);
	    goto done;
	}
    }
    errno = ENOENT;

done:
    if (ret == NULL)
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to resolve tty via pstat");

    debug_return_str(ret);
}
#else
/*
 * Store the name of the tty to which the process is attached in name.
 * Returns name on success and NULL on failure, setting errno.
 */
char *
get_process_ttyname(char *name, size_t namelen)
{
    char *tty;
    debug_decl(get_process_ttyname, SUDO_DEBUG_UTIL)

    if ((tty = ttyname(STDIN_FILENO)) == NULL) {
	if ((tty = ttyname(STDOUT_FILENO)) == NULL)
	    tty = ttyname(STDERR_FILENO);
    }
    if (tty != NULL) {
	if (strlcpy(name, tty, namelen) < namelen)
	    debug_return_str(name);
	errno = ERANGE;
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to store tty from ttyname");
    } else {
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to resolve tty via ttyname");
	errno = ENOENT;
    }

    debug_return_str(NULL);
}
#endif
