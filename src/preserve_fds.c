/*
 * Copyright (c) 2013-2014 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <sys/param.h>		/* for howmany() on Linux */
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>	/* for howmany() on Solaris */
#endif /* HAVE_SYS_SYSMACROS_H */
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
int
add_preserved_fd(struct preserved_fd_list *pfds, int fd)
{
    struct preserved_fd *pfd, *pfd_new;
    debug_decl(add_preserved_fd, SUDO_DEBUG_UTIL)

    pfd_new = emalloc(sizeof(*pfd));
    pfd_new->lowfd = fd;
    pfd_new->highfd = fd;
    pfd_new->flags = fcntl(fd, F_GETFD);
    if (pfd_new->flags == -1) {
	efree(pfd_new);
	debug_return_int(-1);
    }

    TAILQ_FOREACH(pfd, pfds, entries) {
	if (fd == pfd->highfd) {
	    /* already preserved */
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"fd %d already preserved", fd);
	    efree(pfd_new);
	    break;
	}
	if (fd < pfd->highfd) {
	    TAILQ_INSERT_BEFORE(pfd, pfd_new, entries);
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"preserving fd %d", fd);
	    break;
	}
    }
    if (pfd == NULL) {
	TAILQ_INSERT_TAIL(pfds, pfd_new, entries);
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "preserving fd %d", fd);
    }

    debug_return_int(0);
}

/*
 * Close all descriptors, startfd and higher except those listed
 * in pfds.
 */
void
closefrom_except(int startfd, struct preserved_fd_list *pfds)
{
    int debug_fd, fd, lastfd = -1;
    struct preserved_fd *pfd, *pfd_next;
    fd_set *fdsp;
    debug_decl(closefrom_except, SUDO_DEBUG_UTIL)

    debug_fd = sudo_debug_fd_get();

    /* First, relocate preserved fds to be as contiguous as possible.  */
    TAILQ_FOREACH_REVERSE_SAFE(pfd, pfds, preserved_fd_list, entries, pfd_next) {
	if (pfd->highfd < startfd)
	    continue;
	fd = dup(pfd->highfd);
	if (fd == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"dup %d", pfd->highfd);
	    if (errno == EBADF) {
		TAILQ_REMOVE(pfds, pfd, entries);
		continue;
	    }
	    /* NOTE: still need to adjust lastfd below with unchanged lowfd. */
	} else if (fd < pfd->highfd) {
	    pfd->lowfd = fd;
	    fd = pfd->highfd;
	    if (fd == debug_fd)
		debug_fd = sudo_debug_fd_set(pfd->lowfd);
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"dup %d -> %d", pfd->highfd, pfd->lowfd);
	}
	if (fd != -1)
	    (void) close(fd);

	if (pfd->lowfd > lastfd)
	    lastfd = pfd->lowfd;	/* highest (relocated) preserved fd */
    }

    if (lastfd == -1) {
	/* No fds to preserve. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "closefrom(%d)", startfd);
	closefrom(startfd);
	debug_return;
    }

    /* Create bitmap of preserved (relocated) fds.  */
    fdsp = ecalloc(howmany(lastfd + 1, NFDBITS), sizeof(fd_mask));
    TAILQ_FOREACH(pfd, pfds, entries) {
	FD_SET(pfd->lowfd, fdsp);
    }

    /*
     * Close any unpreserved fds [startfd,lastfd]
     */
    for (fd = startfd; fd <= lastfd; fd++) {
	if (!FD_ISSET(fd, fdsp)) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"closing fd %d", fd);
#ifdef __APPLE__
	    /* Avoid potential libdispatch crash when we close its fds. */
	    (void) fcntl(fd, F_SETFD, FD_CLOEXEC);
#else
	    (void) close(fd);
#endif
	}
    }
    free(fdsp);

    /* Let closefrom() do the rest for us. */
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"closefrom(%d)", lastfd + 1);
    closefrom(lastfd + 1);

    /* Restore preserved fds and set flags. */
    TAILQ_FOREACH_REVERSE(pfd, pfds, preserved_fd_list, entries) {
	if (pfd->lowfd != pfd->highfd) {
	    if (dup2(pfd->lowfd, pfd->highfd) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "dup2(%d, %d): %s", pfd->lowfd, pfd->highfd,
		    strerror(errno));
	    } else {
		sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		    "dup2(%d, %d)", pfd->lowfd, pfd->highfd);
	    }
	    if (fcntl(pfd->highfd, F_SETFD, pfd->flags) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "fcntl(%d, F_SETFD, %d): %s", pfd->highfd,
		    pfd->flags, strerror(errno));
	    } else {
		sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		    "fcntl(%d, F_SETFD, %d)", pfd->highfd, pfd->flags);
	    }
	    if (pfd->lowfd == debug_fd)
		debug_fd = sudo_debug_fd_set(pfd->highfd);
	    (void) close(pfd->lowfd);
	    pfd->lowfd = pfd->highfd;
	}
    }
    debug_return;
}

/*
 * Parse a comma-separated list of fds and add them to preserved_fds.
 */
void
parse_preserved_fds(struct preserved_fd_list *pfds, const char *fdstr)
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
