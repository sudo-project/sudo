/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/socket.h>
#include <sys/param.h>
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
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include "sudoers.h"
#include "interfaces.h"

#ifndef INADDR_NONE
# define INADDR_NONE ((unsigned int)-1)
#endif

/*
 * Parse a space-delimited list of IP address/netmask pairs and
 * store in a list of interface structures.
 */
void
set_interfaces(const char *ai)
{
    char *addrinfo, *addr, *mask;
    struct interface *ifp;

    addrinfo = estrdup(ai);
    for (addr = strtok(addrinfo, " \t"); addr != NULL; addr = strtok(NULL, " \t")) {
	/* Separate addr and mask. */
	if ((mask = strchr(addr, '/')) == NULL)
	    continue;
	*mask++ = '\0';

	/* Parse addr and store in list. */
	ifp = emalloc(sizeof(*ifp));
	if (strchr(addr, ':')) {
	    /* IPv6 */
#ifdef HAVE_IN6_ADDR
	    ifp->family = AF_INET6;
	    if (inet_pton(AF_INET6, addr, &ifp->addr.ip6) != 1 ||
		inet_pton(AF_INET6, mask, &ifp->netmask.ip6) != 1)
#endif
	    {
		efree(ifp);
		continue;
	    }
	} else {
	    /* IPv4 */
	    ifp->family = AF_INET;
	    ifp->addr.ip4.s_addr = inet_addr(addr);
	    ifp->netmask.ip4.s_addr = inet_addr(mask);
	    if (ifp->addr.ip4.s_addr == INADDR_NONE ||
		ifp->netmask.ip4.s_addr == INADDR_NONE) {
		efree(ifp);
		continue;
	    }
	}
	ifp->next = interfaces;
	interfaces = ifp;
    }
    efree(addrinfo);
}

void
dump_interfaces(const char *ai)
{
    char *cp, *addrinfo;

    addrinfo = estrdup(ai);

    sudo_printf(SUDO_CONV_INFO_MSG, "Local IP address and netmask pairs:\n");
    for (cp = strtok(addrinfo, " \t"); cp != NULL; cp = strtok(NULL, " \t"))
	sudo_printf(SUDO_CONV_INFO_MSG, "\t%s\n", cp);

    efree(addrinfo);
}
