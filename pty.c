/*
 * Copyright (c) 2009 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/ioctl.h>
#ifdef HAVE_SYS_STROPTS_H
#include <sys/stropts.h>
#endif /* HAVE_SYS_STROPTS_H */
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
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>

#ifdef HAVE_UTIL_H
# include <util.h>
#endif
#ifdef HAVE_PTY_H
# include <pty.h>
#endif

#include "sudo.h"

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

#ifdef HAVE_OPENPTY
int
get_pty(master, slave, name, namesz)
    int *master;
    int *slave;
    char *name;
    size_t namesz;
{
    struct group *gr;
    gid_t ttygid = -1;

    if ((gr = sudo_getgrnam("tty")) != NULL)
	ttygid = gr->gr_gid;

    if (openpty(master, slave, name, NULL, NULL) != 0)
	return(0);
    (void) chown(name, runas_pw->pw_uid, ttygid);
    return(1);
}

#else
# ifdef HAVE_GRANTPT
#  ifndef HAVE_POSIX_OPENPT
static int
posix_openpt(oflag)
    int oflag;
{
    int fd;

#   ifdef _AIX
    fd = open("/dev/ptc", oflag);
#   else
    fd = open("/dev/ptmx", oflag);
#   endif
    return(fd);
}
#  endif /* HAVE_POSIX_OPENPT */

int
get_pty(master, slave, name, namesz)
    int *master;
    int *slave;
    char *name;
    size_t namesz;
{
    char *line;

    *master = posix_openpt(O_RDWR|O_NOCTTY);
    if (*master == -1)
	return(0);

    (void) grantpt(*master);
    if (unlockpt(*master) != 0) {
	close(*master);
	return(0);
    }
    line = ptsname(*master);
    if (line == NULL) {
	close(*master);
	return(0);
    }
    *slave = open(line, O_RDWR|O_NOCTTY, 0);
    if (*slave == -1) {
	close(*master);
	return(0);
    }
#ifdef I_PUSH
    ioctl(*slave, I_PUSH, "ptem");	/* pseudo tty emulation module */
    ioctl(*slave, I_PUSH, "ldterm");	/* line discipline module */
#endif
    (void) chown(line, runas_pw->pw_uid, -1);
    strlcpy(name, line, namesz);
    return(1);
}

# else /* !HAVE_GRANTPT */

static char line[] = "/dev/ptyXX";

int
get_pty(master, slave, name, namesz)
    int *master;
    int *slave;
    char *name;
    size_t namesz;
{
    char *bank, *cp;
    struct group *gr;
    gid_t ttygid = -1;

    if ((gr = sudo_getgrnam("tty")) != NULL)
	ttygid = gr->gr_gid;

    for (bank = "pqrs"; *bank != '\0'; bank++) {
	line[sizeof("/dev/ptyX") - 2] = *bank;
	for (cp = "0123456789abcdef"; *cp != '\0'; cp++) {
	    line[sizeof("/dev/ptyXX") - 2] = *cp;
	    *master = open(line, O_RDWR|O_NOCTTY, 0);
	    if (*master == -1) {
		if (errno == ENOENT)
		    return(0); /* out of ptys */
		continue; /* already in use */
	    }
	    line[sizeof("/dev/p") - 2] = 't';
	    (void) chown(line, runas_pw->pw_uid, ttygid);
	    (void) chmod(line, S_IRUSR|S_IWUSR|S_IWGRP);
#  ifdef HAVE_REVOKE
	    (void) revoke(line);
#  endif
	    *slave = open(line, O_RDWR|O_NOCTTY, 0);
	    if (*slave != -1) {
		    strlcpy(name, line, namesz);
		    return(1); /* success */
	    }
	    (void) close(*master);
	}
    }
    return(0);
}

# endif /* HAVE_GRANTPT */
#endif /* HAVE_OPENPTY */
