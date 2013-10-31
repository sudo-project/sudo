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

#ifndef _SUDO_EVENT_H
#define _SUDO_EVENT_H

#include "queue.h"

/* Event types */
#define SUDO_EV_TIMEOUT		0x01	/* fire after timeout */
#define SUDO_EV_READ		0x02	/* fire when readable */
#define SUDO_EV_WRITE		0x04	/* fire when writable */
#define SUDO_EV_PERSIST		0x08	/* persist until deleted */

/* Event flags (internal) */
#define SUDO_EVQ_INSERTED	0x01	/* event is on the event queue */
#define SUDO_EVQ_ACTIVE		0x02	/* event is on the active queue */
#define SUDO_EVQ_TIMEOUTS	0x04	/* event is on the timeouts queue */

/* Event loop flags */
#define SUDO_EVLOOP_ONCE	0x01	/* Only run once through the loop */
#define SUDO_EVLOOP_NONBLOCK	0x02	/* Do not block in event loop */

/* Event base flags (internal) */
#define SUDO_EVBASE_LOOPEXIT	0x01
#define SUDO_EVBASE_LOOPBREAK	0x02
#define SUDO_EVBASE_LOOPCONT	0x04
#define SUDO_EVBASE_GOT_EXIT	0x10
#define SUDO_EVBASE_GOT_BREAK	0x20
#define SUDO_EVBASE_GOT_MASK	0xf0

typedef void (*sudo_ev_callback_t)(int fd, int what, void *closure);

/* Member of struct sudo_event_base. */
struct sudo_event {
    TAILQ_ENTRY(sudo_event) entries;
    TAILQ_ENTRY(sudo_event) active_entries;
    TAILQ_ENTRY(sudo_event) timeouts_entries;
    struct sudo_event_base *base; /* base this event belongs to */
    int fd;			/* fd we are interested in */
    short events;		/* SUDO_EV_* flags (in) */
    short revents;		/* SUDO_EV_* flags (out) */
    short flags;		/* internal event flags */
    short pfd_idx;		/* index into pfds array (XXX) */
    sudo_ev_callback_t callback;/* user-provided callback */
    struct timeval timeout;	/* for SUDO_EV_TIMEOUT */
    void *closure;		/* user-provided data pointer */
};

TAILQ_HEAD(sudo_event_list, sudo_event);

struct sudo_event_base {
    struct sudo_event_list events; /* tail queue of all events */
    struct sudo_event_list active; /* tail queue of active events */
    struct sudo_event_list timeouts; /* tail queue of timeout events */
#ifdef HAVE_POLL
    struct pollfd *pfds;	/* array of struct pollfd */
    int pfd_max;		/* size of the pfds array */
    int pfd_high;		/* highest slot used */
    int pfd_free;		/* idx of next free entry or pfd_max if full */
#else
    fd_set *readfds_in;		/* read I/O descriptor set (in) */
    fd_set *writefds_in;	/* write I/O descriptor set (in) */
    fd_set *readfds_out;	/* read I/O descriptor set (out) */
    fd_set *writefds_out;	/* write I/O descriptor set (out) */
    int maxfd;			/* max fd we can store in readfds/writefds */
    int highfd;			/* highest fd to pass as 1st arg to select */
#endif /* HAVE_POLL */
    unsigned int flags;		/* SUDO_EVBASE_* */
};

/* Allocate a new event base. */
struct sudo_event_base *sudo_ev_base_alloc(void);

/* Free an event base. */
void sudo_ev_base_free(struct sudo_event_base *base);

/* Allocate a new event. */
struct sudo_event *sudo_ev_alloc(int fd, short events, sudo_ev_callback_t callback, void *closure);

/* Free an event. */
void sudo_ev_free(struct sudo_event *ev);

/* Add an event, returns 0 on success, -1 on error */
int sudo_ev_add(struct sudo_event_base *head, struct sudo_event *ev, struct timeval *timo, bool tohead);

/* Delete an event, returns 0 on success, -1 on error */
int sudo_ev_del(struct sudo_event_base *head, struct sudo_event *ev);

/* Main event loop, returns SUDO_CB_SUCCESS, SUDO_CB_BREAK or SUDO_CB_ERROR */
int sudo_ev_loop(struct sudo_event_base *head, int flags);

/* Return the remaining timeout associated with an event. */
int sudo_ev_get_timeleft(struct sudo_event *ev, struct timeval *tv);

/* Cause the event loop to exit after one run through. */
void sudo_ev_loopexit(struct sudo_event_base *base);

/* Break out of the event loop right now. */
void sudo_ev_loopbreak(struct sudo_event_base *base);

/* Rescan for events and restart the event loop. */
void sudo_ev_loopcontinue(struct sudo_event_base *base);

/* Returns true if event loop stopped due to sudo_ev_loopexit(). */
bool sudo_ev_got_exit(struct sudo_event_base *base);

/* Returns true if event loop stopped due to sudo_ev_loopbreak(). */
bool sudo_ev_got_break(struct sudo_event_base *base);

/* Return the fd associated with an event. */
#define sudo_ev_get_fd(_ev) ((_ev) ? (_ev)->fd : -1)

/* Return the (absolute) timeout associated with an event or NULL. */
#define sudo_ev_get_timeout(_ev) \
    (ISSET((_ev)->flags, SUDO_EVQ_TIMEOUTS) ? &(_ev)->timeout : NULL)

/* Return the base an event is associated with or NULL. */
#define sudo_ev_get_base(_ev) ((_ev) ? (_ev)->base : NULL)

/* Magic pointer value to use self pointer as callback arg. */
#define sudo_ev_self_cbarg() ((void *)-1)

/*
 * Backend implementation.
 */
int sudo_ev_base_alloc_impl(struct sudo_event_base *base);
void sudo_ev_base_free_impl(struct sudo_event_base *base);
int sudo_ev_add_impl(struct sudo_event_base *base, struct sudo_event *ev);
int sudo_ev_del_impl(struct sudo_event_base *base, struct sudo_event *ev);
int sudo_ev_scan_impl(struct sudo_event_base *base, int flags);

#endif /* _SUDO_EVENT_H */
