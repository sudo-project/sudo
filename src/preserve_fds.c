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

#include <sys/types.h>
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
 * Close fds in the range [from,to]
 */
static void
closefrom_range(int from, int to)
{
    debug_decl(closefrom_range, SUDO_DEBUG_UTIL)

    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"closing fds [%d, %d]", from, to);
    while (from <= to) {
#ifdef __APPLE__
	/* Avoid potential libdispatch crash when we close its fds. */
	(void) fcntl(from, F_SETFD, FD_CLOEXEC);
#else
	(void) close(from);
#endif
	from++;
    }
    debug_return;
}

/*
 * Close all descriptors, startfd and higher except those listed
 * in pfds.
 */
void
closefrom_except(int startfd, struct preserved_fd_list *pfds)
{
    int tmpfd;
    struct preserved_fd *pfd, *pfd_next;
    debug_decl(closefrom_except, SUDO_DEBUG_UTIL)

    /*
     * First, relocate preserved fds to be as contiguous as possible.
     */
    TAILQ_FOREACH_SAFE(pfd, pfds, entries, pfd_next) {
	if (pfd->highfd < startfd)
	    continue;
	tmpfd = dup(pfd->highfd);
	if (tmpfd < pfd->highfd) {
	    if (tmpfd == -1) {
		if (errno == EBADF)
		    TAILQ_REMOVE(pfds, pfd, entries);
		continue;
	    }
	    pfd->lowfd = tmpfd;
	    tmpfd = pfd->highfd;
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"dup %d -> %d", pfd->highfd, pfd->lowfd);
	}
	(void) close(tmpfd);
    }

    if (TAILQ_EMPTY(pfds)) {
	/* No fds to preserve. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "closefrom(%d)", startfd);
	closefrom(startfd);
	debug_return;
    }

    /* Close any fds [startfd,TAILQ_FIRST(pfds)->lowfd) */
    closefrom_range(startfd, TAILQ_FIRST(pfds)->lowfd - 1);

    /* Close any unpreserved fds (TAILQ_LAST(pfds)->lowfd,startfd) */
    TAILQ_FOREACH_SAFE(pfd, pfds, entries, pfd_next) {
	if (pfd->lowfd < startfd)
	    continue;
	if (pfd_next != NULL && pfd->lowfd + 1 != pfd_next->lowfd)
	    closefrom_range(pfd->lowfd + 1, pfd_next->lowfd);
    }

    /* Let closefrom() do the rest for us. */
    pfd = TAILQ_LAST(pfds, preserved_fd_list);
    if (pfd != NULL && pfd->lowfd + 1 > startfd)
	startfd = pfd->lowfd + 1;
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"closefrom(%d)", startfd);
    closefrom(startfd);

    /* Restore preserved fds and set flags. */
    TAILQ_FOREACH(pfd, pfds, entries) {
	if (pfd->lowfd != pfd->highfd) {
	    if (dup2(pfd->lowfd, pfd->highfd) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "dup2(%d, %d): %s", pfd->lowfd, pfd->highfd,
		    strerror(errno));
	    } else {
		sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		    "dup2(%d, %d)", pfd->lowfd, pfd->highfd);
	    }
	    if (fcntl(pfd->highfd, F_SETFL, pfd->flags) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "fcntl(%d, F_SETFL, %d): %s", pfd->highfd,
		    pfd->flags, strerror(errno));
	    } else {
		sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		    "fcntl(%d, F_SETFL, %d)", pfd->highfd, pfd->flags);
	    }
	    (void) close(pfd->lowfd);
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
