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

#include <sys/param.h>          /* for howmany() on Linux */
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>     /* for howmany() on Solaris */
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>	/* for FD_* macros */
#endif /* HAVE_SYS_SELECT_H */
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

#include "sudo.h"

/*
 * Add an fd to preserve.
 */
void
add_preserved_fd(struct preserved_fds *pfds, int fd)
{
    debug_decl(add_preserved_fd, SUDO_DEBUG_UTIL)

    /* Reallocate as needed before adding. */
    if (fd > pfds->maxfd) {
	int osize = howmany(pfds->maxfd + 1, NFDBITS);
	int nsize = howmany(fd + 1, NFDBITS);
	if (nsize > osize)
	    pfds->fds = erecalloc(pfds->fds, osize, nsize, sizeof(fd_mask));
	pfds->maxfd = fd;
    }
    FD_SET(fd, pfds->fds);

    debug_return;
}

/*
 * Close all descriptors, startfd and higher except those listed
 * in pfds.
 */
void
closefrom_except(int startfd, struct preserved_fds *pfds)
{
    int fd;
    debug_decl(closefrom_except, SUDO_DEBUG_UTIL)

    /* First handle the preserved fds. */
    if (startfd <= pfds->maxfd) {
	for (fd = startfd; fd <= pfds->maxfd; fd++) {
	    if (!FD_ISSET(fd, pfds->fds)) {
#ifdef __APPLE__
		/* Avoid potential libdispatch crash when we close its fds. */
		(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
#else
		(void) close(fd);
#endif
	    }
	}
	startfd = pfds->maxfd + 1;
    }
    closefrom(startfd);

    debug_return;
}

/*
 * Parse a comma-separated list of fds and add them to preserved_fds.
 */
void
parse_preserved_fds(struct preserved_fds *pfds, const char *fdstr)
{
    const char *cp = fdstr;
    long lval;
    char *ep;
    debug_decl(parse_preserved_fds, SUDO_DEBUG_UTIL)

    do {
	errno = 0;
	lval = strtol(cp, &ep, 10);
	if (ep == cp || (*ep != ',' && *ep != '\0')) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to parse fd string %s", cp);
	    break;
	}
	if ((errno == ERANGE && lval == LONG_MAX) || lval < 0 || lval > INT_MAX) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"range error parsing fd string %s", cp);
	} else {
	    add_preserved_fd(pfds, (int)lval);
	}
	cp = ep + 1;
    } while (*ep != '\0');

    debug_return;
}
