/*
 * Copyright (c) 2007 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * $Sudo$
 */

#ifndef _SUDO_LIST_H
#define _SUDO_LIST_H

/*
 * Convenience macro for declaring a list head.
 */
#ifdef __STDC__
#define LH_DECLARE(n)					\
struct n##_list {					\
    struct n *first;					\
    struct n *last;					\
};
#else
#define LH_DECLARE(n)					\
struct n/**/_list {					\
    struct n *first;					\
    struct n *last;					\
};
#endif

/*
 * Foreach loops: forward and reverse
 */
#undef lh_foreach_fwd
#define lh_foreach_fwd(h, v)				\
    for ((v) = (h)->first; (v) != NULL; (v) = (v)->next)

#undef lh_foreach_rev
#define lh_foreach_rev(h, v)				\
    for ((v) = (h)->last; (v) != NULL; (v) = (v)->prev)

/*
 * Init a list head.
 */
#undef lh_init
#define lh_init(h) do {					\
    (h)->first = NULL;					\
    (h)->last = NULL;					\
} while (0)

/*
 * Simple macros to avoid exposing first/last and prev/next.
 */
#undef lh_empty
#define lh_empty(h)	((h)->first == NULL)

#undef lh_first
#define lh_first(h)	((h)->first)

#undef lh_last
#define lh_last(h)	((h)->last)

#undef list_next
#define list_next(e)	((e)->next)

#undef list_prev
#define list_prev(e)	((e)->prev)

/*
 * Prototypes for list.c
 */
void *lh_pop		__P((void *));
void lh_append		__P((void *, void *));
void list_append	__P((void *, void *));
void list2head		__P((void *, void *));

#endif /* _SUDO_LIST_H */
