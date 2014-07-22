/*
 * Copyright (c) 2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef HAVE_PSTAT_GETPROC
# include <sys/param.h>
# include <sys/pstat.h>
#endif
#if defined(HAVE_PROCFS_H)
# include <procfs.h>
#elif defined(HAVE_SYS_PROCFS_H)
# include <sys/procfs.h>
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
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <errno.h>
#include <fcntl.h>

#include "sudo_compat.h"
#include "sudo_util.h"

#if defined(HAVE_GETPROGNAME)

void
initprogname(const char *name)
{
# ifdef HAVE_SETPROGNAME
    /* Check for libtool prefix and strip it if present. */
    name = getprogname();
    if (name[0] == 'l' && name[1] == 't' && name[2] == '-' && name[3] != '\0')
	setprogname(name + 3);
# endif
    return;
}

#elif defined(HAVE___PROGNAME)

extern const char *__progname;
static const char *progname = "";

void
initprogname(const char *name)
{
    /* Check for libtool prefix and strip it if present. */
    if (__progname[0] == 'l' && __progname[1] == 't' && __progname[2] == '-' &&
	__progname[3] != '\0')
	progname = __progname + 3;
    else
	progname = __progname;
    return;
}

#else

static const char *progname = "";

void
initprogname(const char *name)
{
    const char *base;
#ifdef HAVE_PSTAT_GETPROC
    static char ucomm[PST_UCOMMLEN];
    struct pst_status pstat;
    int rc;

    /*
     * Determine the progname from pst_ucomm in struct pst_status.
     * We may get EOVERFLOW if the whole thing doesn't fit but that is OK.
     */
    rc = pstat_getproc(&pstat, sizeof(pstat), (size_t)0, (int)getpid());
    if (rc != -1 || errno == EOVERFLOW) {
        strlcpy(ucomm, pstat.pst_ucomm, sizeof(ucomm));
	progname = ucomm;
	goto done;
    }
#elif defined(HAVE_PROCFS_H) || defined(HAVE_SYS_PROCFS_H)
    /* XXX - configure check for psinfo.pr_fname */
    static char ucomm[PRFNSZ];
    struct psinfo psinfo;
    char path[PATH_MAX];
    ssize_t nread;
    int fd;

    /* Try to determine the tty from pr_ttydev in /proc/pid/psinfo. */
    snprintf(path, sizeof(path), "/proc/%u/psinfo", (unsigned int)getpid());
    if ((fd = open(path, O_RDONLY, 0)) != -1) {
	nread = read(fd, &psinfo, sizeof(psinfo));
	close(fd);
	if (nread == (ssize_t)sizeof(psinfo)) {
	    strlcpy(ucomm, psinfo.pr_fname, sizeof(ucomm));
	    progname = ucomm;
	    goto done;
	}
    }
#endif /* HAVE_PSTAT_GETPROC */

    if ((base = strrchr(name, '/')) != NULL) {
	base++;
    } else {
	base = name;
    }
    progname = base;

done:
    if (progname[0] == 'l' && progname[1] == 't' && progname[2] == '-' &&
	progname[3] != '\0')
	progname += 3;
}
#endif /* !HAVE_GETPROGNAME && !HAVE___PROGNAME */

#if !defined(HAVE_GETPROGNAME)
const char *
sudo_getprogname(void)
{
    return progname;
}
#endif /* !HAVE_GETPROGNAME */
