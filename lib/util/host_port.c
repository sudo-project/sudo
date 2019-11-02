/*
 * Copyright (c) 2019 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include "config.h"

#include <sys/types.h>

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sudo_gettext.h"	/* must be included before sudo_compat.h */
#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"

/*
 * Parse a string in the form host[:port] where host can also be
 * an IPv4 address or an IPv6 address in square brackets.
 * Modifies str.
 */
bool
sudo_parse_host_port_v1(char *str, char **hostp, char **portp, char *defport)
{
    char *port, *host = str;
    bool ret = false;
    debug_decl(sudo_parse_host_port, SUDO_DEBUG_UTIL)

    /* Check for IPv6 address like [::0] followed by optional port */
    if (*host == '[') {
	host++;
	port = strchr(host, ']');
	if (port == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"invalid IPv6 address %s", str);
	    goto done;
	}
	*port++ = '\0';
	if (*port == ':') {
	    port++;
	} else if (*port == '\0') {
	    port = NULL;		/* no port specified */
	} else {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"invalid IPv6 address %s", str);
	    goto done;
	}
    } else {
	port = strrchr(host, ':');
	if (port != NULL)
	    *port++ = '\0';
    }

    if (port == NULL)
	port = defport;

    ret = true;

done:
    debug_return_bool(ret);
}
