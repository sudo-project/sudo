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
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif
#include <errno.h>
#include <limits.h>

#define DEFAULT_TEXT_DOMAIN	"sudo"
#include "gettext.h"

#include "missing.h"
#include "sudo_debug.h"

id_t
atoid(const char *p, const char *sep, char **endp, const char **errstr)
{
    char *ep;
    id_t rval = 0;
    bool valid = false;
    debug_decl(atoid, SUDO_DEBUG_UTIL)

    if (sep == NULL)
	sep = "";
    errno = 0;
    if (*p == '-') {
	long lval = strtol(p, &ep, 10);
	if (ep != p) {
	    /* check for valid separator (including '\0') */
	    do {
		if (*ep == *sep)
		    valid = true;
	    } while (*sep++ != '\0');
	}
	if (!valid) {
	    *errstr = N_("invalid value");
	    errno = EINVAL;
	    goto done;
	}
	if ((errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) ||
	    (lval > INT_MAX || lval < INT_MIN)) {
	    errno = ERANGE;
	    *errstr = N_("value out of range");
	    goto done;
	}
	rval = (id_t)lval;
	*errstr = NULL;
    } else {
	unsigned long ulval = strtoul(p, &ep, 10);
	if (ep != p) {
	    /* check for valid separator (including '\0') */
	    do {
		if (*ep == *sep)
		    valid = true;
	    } while (*sep++ != '\0');
	}
	if (!valid) {
	    *errstr = N_("invalid value");
	    errno = EINVAL;
	    goto done;
	}
	if ((errno == ERANGE && ulval == ULONG_MAX) || ulval > UINT_MAX) {
	    errno = ERANGE;
	    *errstr = N_("value too large");
	    goto done;
	}
	rval = (id_t)ulval;
	*errstr = NULL;
    }
    if (endp != NULL)
	*endp = ep;
done:
    debug_return_int(rval);
}
