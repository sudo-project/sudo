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
 * Device nodes to ignore.
 */
static const char *ignore_devs[] = {
    _PATH_DEV "stdin",
    _PATH_DEV "stdout",
    _PATH_DEV "stderr",
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
    while (sdlen > 0 && dir[sdlen - 1] == '/')
	sdlen--;
    if (sdlen + 1 >= sizeof(pathbuf)) {
	errno = ERANGE;
	goto done;
    }
    memcpy(pathbuf, dir, sdlen);
    pathbuf[sdlen++] = '/';

    while ((dp = readdir(d)) != NULL) {
	struct stat sb;

	/* Skip anything starting with "." */
	if (dp->d_name[0] == '.')
	    continue;

	pathbuf[sdlen] = '\0';
	if (strlcat(pathbuf, dp->d_name, sizeof(pathbuf)) >= sizeof(pathbuf)) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s%s is too big to fit in pathbuf", pathbuf, dp->d_name);
	    continue;
	}

	/* Ignore device nodes listed in ignore_devs[]. */
	for (i = 0; ignore_devs[i] != NULL; i++) {
	    if (strcmp(pathbuf, ignore_devs[i]) == 0)
		break;
	}
	if (ignore_devs[i] != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"ignoring %s", pathbuf);
	    continue;
	}

# if defined(HAVE_STRUCT_DIRENT_D_TYPE)
	/*
	 * Avoid excessive stat() calls by checking dp->d_type.
	 */
	switch (dp->d_type) {
	    case DT_CHR:
	    case DT_LNK:
	    case DT_UNKNOWN:
		break;
	    default:
		/* Not a character device or link, skip it. */
		sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		    "skipping non-device %s", pathbuf);
		continue;
	}
# endif
	if (stat(pathbuf, &sb) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"unable to stat %s", pathbuf);
	    continue;
	}
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

static char *
sudo_dev_check(dev_t rdev, const char *devname, char *buf, size_t buflen)
{
    struct stat sb;
    debug_decl(sudo_dev_check, SUDO_DEBUG_UTIL)

    if (stat(devname, &sb) == 0) {
	if (S_ISCHR(sb.st_mode) && sb.st_rdev == rdev) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"comparing dev %u to %s: match!",
		(unsigned int)rdev, devname);
	    if (strlcpy(buf, devname, buflen) < buflen)
		debug_return_str(buf);
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to store %s, have %zu, need %zu",
		devname, buflen, strlen(devname) + 1);
	    errno = ERANGE;
	}
    }
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"comparing dev %u to %s: no", (unsigned int)rdev, devname);
    debug_return_str(NULL);
}

/*
 * Like ttyname() but uses a dev_t instead of an open fd.
 * Returns name on success and NULL on failure, setting errno.
 * Generic version.
 */
static char *
sudo_ttyname_dev(dev_t rdev, char *buf, size_t buflen)
{
    const char *devsearch, *devsearch_end;
    char path[PATH_MAX], *ret;
    const char *cp, *ep;
    size_t len;
    debug_decl(sudo_ttyname_dev, SUDO_DEBUG_UTIL)

    /*
     * First, check /dev/console.
     */
    ret = sudo_dev_check(rdev, _PATH_DEV "console", buf, buflen);
    if (ret != NULL)
	goto done;

    /*
     * Then check the device search path.
     */
    devsearch = sudo_conf_devsearch_path();
    devsearch_end = devsearch + strlen(devsearch);
    for (cp = sudo_strsplit(devsearch, devsearch_end, ":", &ep);
	cp != NULL; cp = sudo_strsplit(NULL, devsearch_end, ":", &ep)) {

	len = (size_t)(ep - cp);
	if (len >= sizeof(path)) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"devsearch entry %.*s too long", (int)len, cp);
	    continue;
	}
	memcpy(path, cp, len);
	path[len] = '\0';

	if (strcmp(path, _PATH_DEV "pts") == 0) {
	    /* Special case /dev/pts */
	    len = (size_t)snprintf(path, sizeof(path), "%spts/%u",
		_PATH_DEV, (unsigned int)minor(rdev));
	    if (len >= sizeof(path)) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "devsearch entry %spts/%u too long",
		    _PATH_DEV, (unsigned int)minor(rdev));
		continue;
	    }
	    ret = sudo_dev_check(rdev, path, buf, buflen);
	    if (ret != NULL)
		goto done;
	} else {
	    /* Scan path, looking for rdev. */
	    ret = sudo_ttyname_scan(path, rdev, buf, buflen);
	    if (ret != NULL || errno == ENOMEM)
		goto done;
	}
    }

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
			    int tty_nr = strtonum(cp, INT_MIN, INT_MAX, &errstr);
			    if (errstr) {
				sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
				    "%s: tty device %s: %s", path, cp, errstr);
			    }
			    if (tty_nr != 0) {
				/*
				 * Avoid sign extension when assigning tdev.
				 * tty_nr in /proc/self/stat is printed as a
				 * signed int but the actual device number is an
				 * unsigned int and dev_t is unsigned long long.
				 */
				dev_t tdev = (unsigned int)tty_nr;
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
