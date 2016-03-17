/*
 * Copyright (c) 2012-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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

/* Large files not supported by procfs.h */
#if defined(HAVE_PROCFS_H) || defined(HAVE_SYS_PROCFS_H)
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
 * Devices to search before doing a breadth-first scan.
 */
static char *search_devs[] = {
    "/dev/console",
    "/dev/wscons",
    "/dev/pts/",
    "/dev/vt/",
    "/dev/term/",
    "/dev/zcons/",
    NULL
};

static char *ignore_devs[] = {
    "/dev/fd/",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    NULL
};

/*
 * Do a breadth-first scan of dir looking for the specified device.
 * Returns name on success and NULL on failure, setting errno.
 */
static char *
sudo_ttyname_scan(const char *dir, dev_t rdev, bool builtin, char *name, size_t namelen)
{
    size_t sdlen, num_subdirs = 0, max_subdirs = 0;
    char pathbuf[PATH_MAX], **subdirs = NULL;
    char *rval = NULL;
    struct dirent *dp;
    unsigned int i;
    DIR *d = NULL;
    debug_decl(sudo_ttyname_scan, SUDO_DEBUG_UTIL)

    if (dir[0] == '\0' || (d = opendir(dir)) == NULL)
	goto done;

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
	if (!builtin) {
	    /* Skip entries in search_devs; we already checked them. */
	    for (i = 0; search_devs[i] != NULL; i++) {
		len = strlen(search_devs[i]);
		if (search_devs[i][len - 1] == '/')
		    len--;
		if (d_len == len && strncmp(pathbuf, search_devs[i], len) == 0)
		    break;
	    }
	    if (search_devs[i] != NULL)
		continue;
	}
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
	    case DT_DIR:
		/* Directory, no need to stat() it. */
		sb.st_mode = DTTOIF(dp->d_type);
		sb.st_rdev = 0;		/* quiet ccc-analyzer false positive */
		break;
	    default:
		/* Not a character device, link or directory, skip it. */
		continue;
	}
# else
	if (stat(pathbuf, &sb) == -1)
	    continue;
# endif
	if (S_ISDIR(sb.st_mode)) {
	    if (!builtin) {
		/* Add to list of subdirs to search. */
		if (num_subdirs + 1 > max_subdirs) {
		    char **new_subdirs;

		    new_subdirs = reallocarray(subdirs, max_subdirs + 64,
			sizeof(char *));
		    if (new_subdirs == NULL)
			goto done;
		    subdirs = new_subdirs;
		    max_subdirs += 64;
		}
		subdirs[num_subdirs] = strdup(pathbuf);
		if (subdirs[num_subdirs] == NULL)
		    goto done;
		num_subdirs++;
	    }
	    continue;
	}
	if (S_ISCHR(sb.st_mode) && sb.st_rdev == rdev) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"resolved dev %u as %s", (unsigned int)rdev, pathbuf);
	    if (strlcpy(name, pathbuf, namelen) < namelen) {
		rval = name;
	    } else {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "unable to store %s, have %zu, need %zu",
		    pathbuf, namelen, strlen(pathbuf) + 1);
		errno = ERANGE;
	    }
	    goto done;
	}
    }

    /* Search subdirs if we didn't find it in the root level. */
    for (i = 0; rval == NULL && i < num_subdirs; i++)
	rval = sudo_ttyname_scan(subdirs[i], rdev, false, name, namelen);

done:
    if (d != NULL)
	closedir(d);
    for (i = 0; i < num_subdirs; i++)
	free(subdirs[i]);
    free(subdirs);
    debug_return_str(rval);
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
    char *rval = NULL;
    struct stat sb;
    size_t len;
    debug_decl(sudo_ttyname_dev, SUDO_DEBUG_UTIL)

    /*
     * First check search_devs for common tty devices.
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
			    rval = name;
			else
			    errno = ERANGE;
			goto done;
		    }
		}
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "comparing dev %u to %s: no", (unsigned int)rdev, buf);
	    } else {
		/* Traverse directory */
		rval = sudo_ttyname_scan(devname, rdev, true, name, namelen);
		if (rval != NULL || errno == ENOMEM)
		    goto done;
	    }
	} else {
	    if (stat(devname, &sb) == 0) {
		if (S_ISCHR(sb.st_mode) && sb.st_rdev == rdev) {
		    if (strlcpy(name, devname, namelen) < namelen)
			rval = name;
		    else
			errno = ERANGE;
		    goto done;
		}
	    }
	}
    }

    /*
     * Not found?  Do a breadth-first traversal of /dev/.
     */
    rval = sudo_ttyname_scan(_PATH_DEV, rdev, false, name, namelen);

done:
    debug_return_str(rval);
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
    char *rval = NULL;
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
	    rval = sudo_ttyname_dev(ki_proc->sudo_kp_tdev, name, namelen);
	    if (rval == NULL) {
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

    debug_return_str(rval);
}
#elif defined(HAVE_STRUCT_PSINFO_PR_TTYDEV)
/*
 * Store the name of the tty to which the process is attached in name.
 * Returns name on success and NULL on failure, setting errno.
 */
char *
get_process_ttyname(char *name, size_t namelen)
{
    char path[PATH_MAX], *rval = NULL;
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
		rval = sudo_ttyname_dev(rdev, name, namelen);
		goto done;
	    }
	}
    }
    errno = ENOENT;

done:
    if (rval == NULL)
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to resolve tty via %s", path);

    debug_return_str(rval);
}
#elif defined(__linux__)
/*
 * Store the name of the tty to which the process is attached in name.
 * Returns name on success and NULL on failure, setting errno.
 */
char *
get_process_ttyname(char *name, size_t namelen)
{
    char path[PATH_MAX], *line = NULL;
    char *rval = NULL;
    size_t linesize = 0;
    int serrno = errno;
    ssize_t len;
    FILE *fp;
    debug_decl(get_process_ttyname, SUDO_DEBUG_UTIL)

    /* Try to determine the tty from tty_nr in /proc/pid/stat. */
    snprintf(path, sizeof(path), "/proc/%u/stat", (unsigned int)getpid());
    if ((fp = fopen(path, "r")) != NULL) {
	len = getline(&line, &linesize, fp);
	fclose(fp);
	if (len != -1) {
	    /* Field 7 is the tty dev (0 if no tty) */
	    char *cp = line;
	    char *ep = line;
	    const char *errstr;
	    int field = 0;
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
			    rval = sudo_ttyname_dev(tdev, name, namelen);
			    goto done;
			}
			break;
		    }
		    cp = ep + 1;
		}
	    }
	}
    }
    errno = ENOENT;

done:
    free(line);
    if (rval == NULL)
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to resolve tty via %s", path);

    debug_return_str(rval);
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
    char *rval = NULL;
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
	    rval = sudo_ttyname_dev(makedev(pstat.pst_term.psd_major,
		pstat.pst_term.psd_minor), name, namelen);
	    goto done;
	}
    }
    errno = ENOENT;

done:
    if (rval == NULL)
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "unable to resolve tty via pstat");

    debug_return_str(rval);
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
