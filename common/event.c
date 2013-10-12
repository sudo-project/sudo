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
#include "list.h"
#include "sudo_debug.h"
#include "sudo_event.h"

/* XXX - use non-exiting allocators? */

struct sudo_event_base *
sudo_ev_base_alloc(void)
{
    struct sudo_event_base *base;
    debug_decl(sudo_ev_base_alloc, SUDO_DEBUG_EVENT)

    base = ecalloc(1, sizeof(*base));
    if (sudo_ev_base_alloc_impl(base) != 0) {
	efree(base);
	base = NULL;
    }

    debug_return_ptr(base);
}

void
sudo_ev_base_free(struct sudo_event_base *base)
{
    debug_decl(sudo_ev_base_free, SUDO_DEBUG_EVENT)
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
	    tq_insert_head(base, ev);
	} else {
	    tq_insert_tail(base, ev);
	}
    }
    /* Clear pending delete so adding from callback works properly. */
    CLR(ev->events, SUDO_EV_DELETE);
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

    /* Unlink from list. */
    tq_remove(base, ev);

    /* If we removed the pending event, replace it with the next one. */
    if (base->pending == ev)
	base->pending = ev->next;

    /* Mark event unused. */
    ev->pfd_idx = -1;
    ev->base = NULL;
    ev->prev = NULL;
    ev->next = NULL;

    debug_return_int(0);
}

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

    /* Most work is done by the backend. */
    rc = sudo_ev_loop_impl(base, flags);
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
