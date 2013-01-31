/*
 * Copyright (c) 2012-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
#include <sys/stat.h>
#if defined(MAJOR_IN_MKDEV)
# include <sys/mkdev.h>
#elif defined(MAJOR_IN_SYSMACROS)
# include <sys/sysmacros.h>
#endif
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
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
#if defined(HAVE_STRUCT_KINFO_PROC_P_TDEV) || defined (HAVE_STRUCT_KINFO_PROC_KP_EPROC_E_TDEV) || defined(HAVE_STRUCT_KINFO_PROC2_P_TDEV)
# include <sys/sysctl.h>
#elif defined(HAVE_STRUCT_KINFO_PROC_KI_TDEV)
# include <sys/sysctl.h>
# include <sys/user.h>
#endif
#if defined(HAVE_PROCFS_H)
# include <procfs.h>
#elif defined(HAVE_SYS_PROCFS_H)
# include <sys/procfs.h>
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
 * Caller is responsible for freeing the returned string.
 * The BSD version uses devname()
 */
static char *
sudo_ttyname_dev(dev_t tdev)
{
    char *dev, *tty = NULL;

    /* Some versions of devname() return NULL on failure, others do not. */
    dev = devname(tdev, S_IFCHR);
    if (dev != NULL && *dev != '?' && *dev != '#') {
	if (*dev != '/') {
	    /* devname() doesn't use the /dev/ prefix, add one... */
	    size_t len = sizeof(_PATH_DEV) + strlen(dev);
	    tty = emalloc(len);
	    strlcpy(tty, _PATH_DEV, len);
	    strlcat(tty, dev, len);
	} else {
	    /* Should not happen but just in case... */
	    tty = estrdup(dev);
	}
    }
    return tty;
}
#elif defined(HAVE__TTYNAME_DEV)
extern char *_ttyname_dev(dev_t rdev, char *buffer, size_t buflen);

/*
 * Like ttyname() but uses a dev_t instead of an open fd.
 * Caller is responsible for freeing the returned string.
 * This version is just a wrapper around _ttyname_dev().
 */
static char *
sudo_ttyname_dev(dev_t tdev)
{
    char buf[TTYNAME_MAX], *tty;

    tty = _ttyname_dev(tdev, buf, sizeof(buf));

    return estrdup(tty);
}
#else
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
 */
static
char *sudo_ttyname_scan(dir, rdev, builtin)
    const char *dir;
    dev_t rdev;
    int builtin;
{
    DIR *d;
    char pathbuf[PATH_MAX], **subdirs = NULL, *devname = NULL;
    size_t sdlen, d_len, len, num_subdirs = 0, max_subdirs = 0;
    struct dirent *dp;
    struct stat sb;
    int i;

    if (dir[0] == '\0' || (d = opendir(dir)) == NULL)
	goto done;

    sdlen = strlen(dir);
    if (dir[sdlen - 1] == '/')
	sdlen--;
    if (sdlen + 1 >= sizeof(pathbuf)) {
	errno = ENAMETOOLONG;
	warning("%.*s/", (int)sdlen, dir);
	goto done;
    }
    memcpy(pathbuf, dir, sdlen);
    pathbuf[sdlen++] = '/';
    pathbuf[sdlen] = '\0';

    while ((dp = readdir(d)) != NULL) {
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
	/* Use d_type to avoid a stat() if possible. */
	/* Convert d_type to stat-style type bits but follow links. */
	if (dp->d_type != DT_LNK && dp->d_type != DT_CHR)
	    sb.st_mode = DTTOIF(dp->d_type);
	else
# endif
	if (stat(pathbuf, &sb) == -1)
	    continue;
	if (S_ISDIR(sb.st_mode)) {
	    if (!builtin) {
		/* Add to list of subdirs to search. */
		if (num_subdirs + 1 > max_subdirs) {
		    max_subdirs += 64;
		    subdirs = erealloc3(subdirs, max_subdirs, sizeof(char *));
		}
		subdirs[num_subdirs++] = estrdup(pathbuf);
	    }
	    continue;
	}
	if (S_ISCHR(sb.st_mode) && sb.st_rdev == rdev) {
	    devname = estrdup(pathbuf);
	    break;
	}
    }
    closedir(d);

    /* Search subdirs if we didn't find it in the root level. */
    for (i = 0; devname == NULL && i < num_subdirs; i++)
	devname = sudo_ttyname_scan(subdirs[i], rdev, FALSE);

done:
    for (i = 0; i < num_subdirs; i++)
	efree(subdirs[i]);
    efree(subdirs);
    return devname;
}

/*
 * Like ttyname() but uses a dev_t instead of an open fd.
 * Caller is responsible for freeing the returned string.
 * Generic version.
 */
static char *
sudo_ttyname_dev(rdev)
    dev_t rdev;
{
    struct stat sb;
    size_t len;
    char buf[PATH_MAX], **sd, *devname, *tty = NULL;

    /*
     * First check search_devs.
     */
    for (sd = search_devs; (devname = *sd) != NULL; sd++) {
	len = strlen(devname);
	if (devname[len - 1] == '/') {
	    /* Special case /dev/pts */
	    if (strcmp(devname, "/dev/pts/") == 0) {
		(void)snprintf(buf, sizeof(buf), "%spts/%u", _PATH_DEV,
		    (unsigned int)minor(rdev));
		if (stat(buf, &sb) == 0) {
		    if (S_ISCHR(sb.st_mode) && sb.st_rdev == rdev) {
			tty = estrdup(buf);
			break;
		    }
		}
		continue;
	    }
	    /* Traverse directory */
	    tty = sudo_ttyname_scan(devname, rdev, TRUE);
	} else {
	    if (stat(devname, &sb) == 0) {
		if (S_ISCHR(sb.st_mode) && sb.st_rdev == rdev) {
		    tty = estrdup(devname);
		    break;
		}
	    }
	}
    }

    /*
     * Not found?  Do a breadth-first traversal of /dev/.
     */
    if (tty == NULL)
	tty = sudo_ttyname_scan(_PATH_DEV, rdev, FALSE);

    return tty;
}
#endif

#if defined(sudo_kp_tdev)
/*
 * Return a string from ttyname() containing the tty to which the process is
 * attached or NULL if there is no tty associated with the process (or its
 * parent).  First tries sysctl using the current pid, then the parent's pid.
 * Falls back on ttyname of std{in,out,err} if that fails.
 */
char *
get_process_ttyname()
{
    char *tty = NULL;
    struct sudo_kinfo_proc *ki_proc = NULL;
    size_t size = sizeof(*ki_proc);
    int i, mib[6], rc;

    /*
     * Lookup tty for this process and, failing that, our parent.
     * Even if we redirect std{in,out,err} the kernel should still know.
     */
    for (i = 0; tty == NULL && i < 2; i++) {
	mib[0] = CTL_KERN;
	mib[1] = SUDO_KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = i ? (int)getppid() : (int)getpid();
	mib[4] = sizeof(*ki_proc);
	mib[5] = 1;
	do {
	    size += size / 10;
	    ki_proc = erealloc(ki_proc, size);
	    rc = sysctl(mib, sudo_kp_namelen, ki_proc, &size, NULL, 0);
	} while (rc == -1 && errno == ENOMEM);
	if (rc != -1) {
	    if (ki_proc->sudo_kp_tdev != (dev_t)-1) {
		tty = sudo_ttyname_dev(ki_proc->sudo_kp_tdev);
	    }
	}
    }
    efree(ki_proc);

    return tty;
}
#elif defined(HAVE_STRUCT_PSINFO_PR_TTYDEV)
/*
 * Return a string from ttyname() containing the tty to which the process is
 * attached or NULL if there is no tty associated with the process (or its
 * parent).  First tries /proc/pid/psinfo, then /proc/ppid/psinfo.
 * Falls back on ttyname of std{in,out,err} if that fails.
 */
char *
get_process_ttyname()
{
    char path[PATH_MAX], *tty = NULL;
    struct stat sb;
    struct psinfo psinfo;
    ssize_t nread;
    int i, fd;

    /* Try to determine the tty from pr_ttydev in /proc/pid/psinfo. */
    for (i = 0; tty == NULL && i < 2; i++) {
	(void)snprintf(path, sizeof(path), "/proc/%u/psinfo",
	    i ? (unsigned int)getppid() : (unsigned int)getpid());
	if ((fd = open(path, O_RDONLY, 0)) == -1)
	    continue;
	nread = read(fd, &psinfo, sizeof(psinfo));
	close(fd);
	if (nread == (ssize_t)sizeof(psinfo) && psinfo.pr_ttydev != (dev_t)-1) {
	    tty = sudo_ttyname_dev(psinfo.pr_ttydev);
	}
    }

    return tty;
}
#elif defined(__linux__)
/*
 * Return a string from ttyname() containing the tty to which the process is
 * attached or NULL if there is no tty associated with the process (or its
 * parent).  First tries field 7 in /proc/pid/stat, then /proc/ppid/stat.
 * Falls back on ttyname of std{in,out,err} if that fails.
 */
char *
get_process_ttyname()
{
    char *line = NULL, *tty = NULL;
    size_t linesize = 0;
    ssize_t len;
    int i;

    /* Try to determine the tty from tty_nr in /proc/pid/stat. */
    for (i = 0; tty == NULL && i < 2; i++) {
	FILE *fp;
	char path[PATH_MAX];
	(void)snprintf(path, sizeof(path), "/proc/%u/stat",
	    i ? (unsigned int)getppid() : (unsigned int)getpid());
	if ((fp = fopen(path, "r")) == NULL)
	    continue;
	len = getline(&line, &linesize, fp);
	fclose(fp);
	if (len != -1) {
	    /* Field 7 is the tty dev (0 if no tty) */
	    char *cp = line;
	    int field = 1;
	    while (*cp != '\0') {
		if (*cp++ == ' ') {
		    if (++field == 7) {
			dev_t tdev = (dev_t)atoi(cp);
			if (tdev > 0)
			    tty = sudo_ttyname_dev(tdev);
			break;
		    }
		}
	    }
	}
    }
    efree(line);

    return tty;
}
#else
/*
 * Return a string from ttyname() containing the tty to which the process is
 * attached or NULL if there is no tty associated with the process.
 * parent).
 */
char *
get_process_ttyname()
{
    char *tty;

    if ((tty = ttyname(STDIN_FILENO)) == NULL) {
	if ((tty = ttyname(STDOUT_FILENO)) == NULL)
	    tty = ttyname(STDERR_FILENO);
    }

    return estrdup(tty);
}
#endif
