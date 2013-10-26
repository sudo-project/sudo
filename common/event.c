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

/* XXX - use non-exiting allocators? */

struct sudo_event_base *
sudo_ev_base_alloc(void)
{
    struct sudo_event_base *base;
    debug_decl(sudo_ev_base_alloc, SUDO_DEBUG_EVENT)

    base = ecalloc(1, sizeof(*base));
    TAILQ_INIT(&base->events);
    if (sudo_ev_base_alloc_impl(base) != 0) {
	efree(base);
	base = NULL;
    }

    debug_return_ptr(base);
}

void
sudo_ev_base_free(struct sudo_event_base *base)
{
    struct sudo_event *next;
    debug_decl(sudo_ev_base_free, SUDO_DEBUG_EVENT)

    /* Remove any existing events before freeing the base. */
    TAILQ_FOREACH_SAFE(base->cur, &base->events, entries, next) {
	sudo_ev_del(base, base->cur);
    }
    sudo_ev_base_free_impl(base);
    efree(base);

    debug_return;
}

struct sudo_event *
sudo_ev_alloc(int fd, short events, sudo_ev_callback_t callback, void *closure)
{
    struct sudo_event *ev;
    debug_decl(sudo_ev_alloc, SUDO_DEBUG_EVENT)

    ev = ecalloc(1, sizeof(*ev));
    ev->fd = fd;
    ev->events = events;
    ev->pfd_idx = -1;
    ev->callback = callback;
    ev->closure = closure;

    debug_return_ptr(ev);
}

void
sudo_ev_free(struct sudo_event *ev)
{
    debug_decl(sudo_ev_free, SUDO_DEBUG_EVENT)

    /* Make sure ev is not in use before freeing it. */
    if (ev->base != NULL)
	(void)sudo_ev_del(NULL, ev);
    free(ev);
    debug_return;
}

int
sudo_ev_add(struct sudo_event_base *base, struct sudo_event *ev, bool tohead)
{
    debug_decl(sudo_ev_add, SUDO_DEBUG_EVENT)

    /* Don't add an event twice; revisit if we want to support timeouts. */
    if (ev->base == NULL) {
	if (sudo_ev_add_impl(base, ev) != 0)
	    debug_return_int(-1);
	ev->base = base;
	if (tohead) {
	    TAILQ_INSERT_HEAD(&base->events, ev, entries);
	} else {
	    TAILQ_INSERT_TAIL(&base->events, ev, entries);
	}
    }
    /* Clear pending delete so adding from callback works properly. */
    CLR(ev->flags, SUDO_EV_DELETE);
    debug_return_int(0);
}

int
sudo_ev_del(struct sudo_event_base *base, struct sudo_event *ev)
{
    debug_decl(sudo_ev_del, SUDO_DEBUG_EVENT)

    /* Make sure event is really in the queue. */
    if (ev->base == NULL) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: event %p not in queue",
	    __func__, ev);
	debug_return_int(0);
    }

    /* Check for event base mismatch, if one is specified. */
    if (base == NULL) {
	base = ev->base;
    } else if (base != ev->base) {
	sudo_debug_printf(SUDO_DEBUG_ERROR, "%s: mismatch base %p, ev->base %p",
	    __func__, base, ev->base);
	debug_return_int(-1);
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: removing event %p from base %p",
	__func__, ev, base);

    /* Call backend. */
    if (sudo_ev_del_impl(base, ev) != 0)
	debug_return_int(-1);

    /* Unlink from event list. */
    TAILQ_REMOVE(&base->events, ev, entries);

    /* Unlink from active list and update base pointers as needed. */
    if (ISSET(ev->flags, SUDO_EV_ACTIVE)) {
	TAILQ_REMOVE(&base->active, ev, active_entries);
	if (ev == base->pending)
	    base->pending = TAILQ_NEXT(ev, active_entries);
	if (ev == base->cur)
	    base->cur = NULL;
    }

    /* Mark event unused. */
    ev->base = NULL;
    ev->flags = 0;
    ev->pfd_idx = -1;

    debug_return_int(0);
}

/*
 * Run main event loop.
 * Returns 0 on success, 1 if no events registered  and -1 on error 
 */
int
sudo_ev_loop(struct sudo_event_base *base, int flags)
{
    int rc;
    debug_decl(sudo_ev_loop, SUDO_DEBUG_EVENT)

    /*
     * If sudo_ev_loopexit() was called when events were not running
     * the next invocation of sudo_ev_loop() only runs once.
     * All other base flags are ignored unless we are running events.
     */
    if (ISSET(base->flags, SUDO_EVBASE_LOOPEXIT))
	flags |= SUDO_EVLOOP_ONCE;
    base->flags = 0;

    for (;;) {
rescan:
	/* Make sure we have some events. */
	if (TAILQ_EMPTY(&base->events)) {
	    rc = 1;
	    break;
	}

	/* Call backend to setup the active queue. */
	TAILQ_INIT(&base->active);
	rc = sudo_ev_loop_impl(base, flags);
	if (rc == -1) {
	    if (errno == EINTR || errno == ENOMEM)
		continue;
	    break;
	}

	/*
	 * Service each event in the active queue.
	 * We store the current event pointer in the base so that
	 * it can be cleared by sudo_ev_del().  This prevents a use
	 * after free if the callback frees its own event.
	 */
	TAILQ_FOREACH_SAFE(base->cur, &base->active, active_entries, base->pending) {
	    if (!ISSET(base->cur->events, SUDO_EV_PERSIST))
		SET(base->cur->flags, SUDO_EV_DELETE);
	    base->cur->callback(base->cur->fd, base->cur->revents,
		base->cur->closure);
	    if (base->cur != NULL) {
		CLR(base->cur->flags, SUDO_EV_ACTIVE);
		if (ISSET(base->cur->flags, SUDO_EV_DELETE))
		    sudo_ev_del(base, base->cur);
	    }
	    if (ISSET(base->flags, SUDO_EVBASE_LOOPBREAK)) {
		/* stop processing events immediately */
		base->flags |= SUDO_EVBASE_GOT_BREAK;
		base->pending = NULL;
		goto done;
	    }
	    if (ISSET(base->flags, SUDO_EVBASE_LOOPCONT)) {
		/* rescan events and start polling again */
		CLR(base->flags, SUDO_EVBASE_LOOPCONT);
		base->pending = NULL;
		goto rescan;
	    }
	}
	base->pending = NULL;
	if (ISSET(base->flags, SUDO_EVBASE_LOOPEXIT)) {
	    /* exit loop after once through */
	    base->flags |= SUDO_EVBASE_GOT_EXIT;
	    goto done;
	}
	if (flags & (SUDO_EVLOOP_ONCE | SUDO_EVLOOP_NONBLOCK))
	    break;
    }
done:
    base->flags &= SUDO_EVBASE_GOT_MASK;
    debug_return_int(rc);
}

void
sudo_ev_loopexit(struct sudo_event_base *base)
{
    debug_decl(sudo_ev_loopexit, SUDO_DEBUG_EVENT)
    base->flags |= SUDO_EVBASE_LOOPEXIT;
    debug_return;
}

void
sudo_ev_loopbreak(struct sudo_event_base *base)
{
    debug_decl(sudo_ev_loopbreak, SUDO_DEBUG_EVENT)
    base->flags |= SUDO_EVBASE_LOOPBREAK;
    debug_return;
}

void
sudo_ev_loopcontinue(struct sudo_event_base *base)
{
    debug_decl(sudo_ev_loopcontinue, SUDO_DEBUG_EVENT)
    base->flags |= SUDO_EVBASE_LOOPCONT;
    debug_return;
}

bool
sudo_ev_got_exit(struct sudo_event_base *base)
{
    debug_decl(sudo_ev_got_exit, SUDO_DEBUG_EVENT)
    debug_return_bool(ISSET(base->flags, SUDO_EVBASE_GOT_EXIT));
}

bool
sudo_ev_got_break(struct sudo_event_base *base)
{
    debug_decl(sudo_ev_got_break, SUDO_DEBUG_EVENT)
    debug_return_bool(ISSET(base->flags, SUDO_EVBASE_GOT_BREAK));
}
