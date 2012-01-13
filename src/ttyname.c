/*
 * Copyright (c) 2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#if defined(HAVE_STRUCT_KINFO_PROC_P_TDEV) || defined (HAVE_STRUCT_KINFO_PROC_KP_EPROC_E_TDEV)
# include <sys/sysctl.h>
#elif defined(HAVE_STRUCT_KINFO_PROC_KI_TDEV)
# include <sys/sysctl.h>
# include <sys/user.h>
#endif

#include "sudo.h"

/*
 * How to access the tty device number in struct kinfo_proc.
 */
#if defined(HAVE_STRUCT_KINFO_PROC_KP_EPROC_E_TDEV)
# define sudo_kp_tdev		kp_eproc.e_tdev
# define sudo_kp_namelen	4
#elif defined(HAVE_STRUCT_KINFO_PROC_KI_TDEV)
# define sudo_kp_tdev		ki_tdev
# define sudo_kp_namelen	4
#elif defined(HAVE_STRUCT_KINFO_PROC_P_TDEV)
# define sudo_kp_tdev		p_tdev
# define sudo_kp_namelen	6
#endif

#ifdef sudo_kp_tdev
/*
 * Return a string from ttyname() containing the tty to which the process is
 * attached or NULL if there is no tty associated with the process (or its
 * parent).  First tries sysctl using the current pid, then the parent's pid.
 * Falls back on ttyname of std{in,out,err} if that fails.
 */
char *
get_process_ttyname(void)
{
    char *tty = NULL;
    struct kinfo_proc *ki_proc = NULL;
    size_t size = sizeof(*ki_proc);
    int i, mib[6], rc;
    debug_decl(get_process_ttyname, SUDO_DEBUG_UTIL)

    /*
     * Lookup tty for this process and, failing that, our parent.
     * Even if we redirect std{in,out,err} the kernel should still know.
     */
    for (i = 0; tty == NULL && i < 2; i++) {
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
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
	    char *dev = devname(ki_proc->sudo_kp_tdev, S_IFCHR);
	    /* Some versions of devname() return NULL, others do not. */
	    if (dev == NULL || *dev == '?' || *dev == '#') {
		sudo_debug_printf(SUDO_DEBUG_WARN,
		    "unable to map device number %u to name",
		    ki_proc->sudo_kp_tdev);
	    } else if (*dev != '/') {
		/* devname() doesn't use the /dev/ prefix, add one... */
		size_t len = sizeof(_PATH_DEV) + strlen(dev);
		tty = emalloc(len);
		strlcpy(tty, _PATH_DEV, len);
		strlcat(tty, dev, len);
	    } else {
		/* Should not happen but just in case... */
		tty = estrdup(dev);
	    }
	} else {
	    sudo_debug_printf(SUDO_DEBUG_WARN,
		"unable to resolve tty via KERN_PROC: %s", strerror(errno));
	}
	efree(ki_proc);
    }

    /* If all else fails, fall back on ttyname(). */
    if (tty == NULL) {
	if ((tty = ttyname(STDIN_FILENO)) != NULL ||
	    (tty = ttyname(STDOUT_FILENO)) != NULL ||
	    (tty = ttyname(STDERR_FILENO)) != NULL)
	    tty = estrdup(tty);
    }

    debug_return_str(tty);
}
#else
/*
 * Return a string from ttyname() containing the tty to which the process is
 * attached or NULL if there is no tty associated with the process (or its
 * parent).  First tries std{in,out,err} then falls back to the parent's /proc
 * entry.  We could try following the parent all the way to pid 1 but
 * /proc/%d/status is system-specific (text on Linux, a struct on Solaris).
 */
char *
get_process_ttyname(void)
{
    char path[PATH_MAX], *tty = NULL;
    pid_t ppid;
    int i, fd;
    debug_decl(get_process_ttyname, SUDO_DEBUG_UTIL)

    if ((tty = ttyname(STDIN_FILENO)) == NULL &&
	(tty = ttyname(STDOUT_FILENO)) == NULL &&
	(tty = ttyname(STDERR_FILENO)) == NULL) {
	/* No tty for child, check the parent via /proc. */
	ppid = getppid();
	for (i = STDIN_FILENO; i < STDERR_FILENO && tty == NULL; i++) {
	    snprintf(path, sizeof(path), "/proc/%d/fd/%d", ppid, i);
	    fd = open(path, O_RDONLY|O_NOCTTY, 0);
	    if (fd != -1) {
		tty = ttyname(fd);
		close(fd);
	    }
	}
    }

    debug_return_str(estrdup(tty));
}
#endif /* sudo_kp_tdev */
