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

#include <sys/param.h>		/* for howmany() on Linux */
#include <sys/time.h>
#ifdef HAVE_SYS_SYSMACROS_H
# include <sys/sysmacros.h>	/* for howmany() on Solaris */
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
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
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <errno.h>

#include "missing.h"
#include "alloc.h"
#include "fatal.h"
#include "sudo_debug.h"
#include "sudo_event.h"
#include "sudo_util.h"

/* XXX - use non-exiting allocators? */

int
sudo_ev_base_alloc_impl(struct sudo_event_base *base)
{
    debug_decl(sudo_ev_base_alloc_impl, SUDO_DEBUG_EVENT)

    base->maxfd = NFDBITS - 1;
    base->readfds_in = ecalloc(1, sizeof(fd_mask));
    base->writefds_in = ecalloc(1, sizeof(fd_mask));
    base->readfds_out = ecalloc(1, sizeof(fd_mask));
    base->writefds_out = ecalloc(1, sizeof(fd_mask));

    debug_return_int(0);
}

void
sudo_ev_base_free_impl(struct sudo_event_base *base)
{
    debug_decl(sudo_ev_base_free_impl, SUDO_DEBUG_EVENT)
    efree(base->readfds_in);
    efree(base->writefds_in);
    efree(base->readfds_out);
    efree(base->writefds_out);
    debug_return;
}

int
sudo_ev_add_impl(struct sudo_event_base *base, struct sudo_event *ev)
{
    debug_decl(sudo_ev_add_impl, SUDO_DEBUG_EVENT)

    /* If out of space in fd sets, realloc. */
    if (ev->fd > base->maxfd) {
	const int o = (base->maxfd + 1) / NFDBITS;
	const int n = howmany(ev->fd + 1, NFDBITS);
	base->readfds_in = erecalloc(base->readfds_in, o, n, sizeof(fd_mask));
	base->writefds_in = erecalloc(base->writefds_in, o, n, sizeof(fd_mask));
	base->readfds_out = erecalloc(base->readfds_out, o, n, sizeof(fd_mask));
	base->writefds_out = erecalloc(base->writefds_out, o, n, sizeof(fd_mask));
	base->maxfd = (n * NFDBITS) - 1;
    }

    /* Set events and adjust high fd as needed. */
    if (ISSET(ev->events, SUDO_EV_READ)) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "%s: added fd %d to readfs",
	    __func__, ev->fd);
	FD_SET(ev->fd, base->readfds_in);
    }
    if (ISSET(ev->events, SUDO_EV_WRITE)) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "%s: added fd %d to writefds",
	    __func__, ev->fd);
	FD_SET(ev->fd, base->writefds_in);
    }
    if (ev->fd > base->highfd)
	base->highfd = ev->fd;

    debug_return_int(0);
}

int
sudo_ev_del_impl(struct sudo_event_base *base, struct sudo_event *ev)
{
    debug_decl(sudo_ev_del_impl, SUDO_DEBUG_EVENT)

    /* Remove from readfds and writefds and adjust high fd. */
    if (ISSET(ev->events, SUDO_EV_READ)) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "%s: removed fd %d from readfds",
	    __func__, ev->fd);
	FD_CLR(ev->fd, base->readfds_in);
    }
    if (ISSET(ev->events, SUDO_EV_WRITE)) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "%s: removed fd %d from writefds",
	    __func__, ev->fd);
	FD_CLR(ev->fd, base->writefds_in);
    }
    if (base->highfd == ev->fd) {
	for (;;) {
	    if (FD_ISSET(base->highfd, base->readfds_in) ||
		FD_ISSET(base->highfd, base->writefds_in))
		break;
	    if (--base->highfd < 0)
		break;
	}
    }

    debug_return_int(0);
}

int
sudo_ev_scan_impl(struct sudo_event_base *base, int flags)
{
    struct timeval now, tv, *timeout;
    struct sudo_event *ev;
    size_t setsize;
    int nready;
    debug_decl(sudo_ev_loop, SUDO_DEBUG_EVENT)

    if ((ev = TAILQ_FIRST(&base->timeouts)) != NULL) {
	gettimeofday(&now, NULL);
	sudo_timevalsub(&ev->timeout, &now, &tv);
	if (tv.tv_sec < 0 || (tv.tv_sec == 0 && tv.tv_usec < 0))
	    sudo_timevalclear(&tv);
	timeout = &tv;
    } else {
	if (ISSET(flags, SUDO_EVLOOP_NONBLOCK)) {
	    sudo_timevalclear(&tv);
	    timeout = &tv;
	} else {
	    timeout = NULL;
	}
    }

    /* select() overwrites readfds/writefds so make a copy. */
    setsize = howmany(base->highfd + 1, NFDBITS) * sizeof(fd_mask);
    memcpy(base->readfds_out, base->readfds_in, setsize);
    memcpy(base->writefds_out, base->writefds_in, setsize);

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "%s: select high fd %d",
	__func__, base->highfd);
    nready = select(base->highfd + 1, base->readfds_out, base->writefds_out,
	NULL, timeout);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: %d fds ready", __func__, nready);
    switch (nready) {
    case -1:
	/* Error or interrupted by signal. */
	debug_return_int(-1);
    case 0:
	/* Front end will activate timeout events. */
	break;
    default:
	/* Activate each I/O event that fired. */
	TAILQ_FOREACH(ev, &base->events, entries) {
	    if (ev->fd >= 0) {
		int what = 0;
		if (FD_ISSET(ev->fd, base->readfds_out))
		    what |= (ev->events & SUDO_EV_READ);
		if (FD_ISSET(ev->fd, base->writefds_out))
		    what |= (ev->events & SUDO_EV_WRITE);
		if (what != 0) {
		    /* Make event active. */
		    sudo_debug_printf(SUDO_DEBUG_DEBUG,
			"%s: selected fd %d, events %d, activating %p",
			__func__, ev->fd, what, ev);
		    ev->revents = what;
		    TAILQ_INSERT_TAIL(&base->active, ev, active_entries);
		    SET(ev->flags, SUDO_EVQ_ACTIVE);
		}
	    }
	}
	break;
    }
    debug_return_int(nready);
}
