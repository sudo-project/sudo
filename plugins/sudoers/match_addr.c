/*
 * Copyright (c) 1996, 1998-2005, 2007-2011
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
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

#include "sudoers.h"
#include "interfaces.h"

static int
addr_matches_if(char *n)
{
    union sudo_in_addr_un addr;
    struct interface *ifp;
#ifdef HAVE_IN6_ADDR
    int j;
#endif
    int family;
    debug_decl(addr_matches_if, SUDO_DEBUG_MATCH)

#ifdef HAVE_IN6_ADDR
    if (inet_pton(AF_INET6, n, &addr.ip6) > 0) {
	family = AF_INET6;
    } else
#endif
    {
	family = AF_INET;
	addr.ip4.s_addr = inet_addr(n);
    }

    for (ifp = interfaces; ifp != NULL; ifp = ifp->next) {
	if (ifp->family != family)
	    continue;
	switch(family) {
	    case AF_INET:
		if (ifp->addr.ip4.s_addr == addr.ip4.s_addr ||
		    (ifp->addr.ip4.s_addr & ifp->netmask.ip4.s_addr)
		    == addr.ip4.s_addr)
		    debug_return_bool(TRUE);
		break;
#ifdef HAVE_IN6_ADDR
	    case AF_INET6:
		if (memcmp(ifp->addr.ip6.s6_addr, addr.ip6.s6_addr,
		    sizeof(addr.ip6.s6_addr)) == 0)
		    debug_return_bool(TRUE);
		for (j = 0; j < sizeof(addr.ip6.s6_addr); j++) {
		    if ((ifp->addr.ip6.s6_addr[j] & ifp->netmask.ip6.s6_addr[j]) != addr.ip6.s6_addr[j])
			break;
		}
		if (j == sizeof(addr.ip6.s6_addr))
		    debug_return_bool(TRUE);
#endif
	}
    }

    debug_return_bool(FALSE);
}

static int
addr_matches_if_netmask(char *n, char *m)
{
    int i;
    union sudo_in_addr_un addr, mask;
    struct interface *ifp;
#ifdef HAVE_IN6_ADDR
    int j;
#endif
    int family;
    debug_decl(addr_matches_if, SUDO_DEBUG_MATCH)

#ifdef HAVE_IN6_ADDR
    if (inet_pton(AF_INET6, n, &addr.ip6) > 0)
	family = AF_INET6;
    else
#endif
    {
	family = AF_INET;
	addr.ip4.s_addr = inet_addr(n);
    }

    if (family == AF_INET) {
	if (strchr(m, '.')) {
	    mask.ip4.s_addr = inet_addr(m);
	} else {
	    i = atoi(m);
	    if (i == 0)
		mask.ip4.s_addr = 0;
	    else if (i == 32)
		mask.ip4.s_addr = 0xffffffff;
	    else
		mask.ip4.s_addr = 0xffffffff - (1 << (32 - i)) + 1;
	    mask.ip4.s_addr = htonl(mask.ip4.s_addr);
	}
	addr.ip4.s_addr &= mask.ip4.s_addr;
    }
#ifdef HAVE_IN6_ADDR
    else {
	if (inet_pton(AF_INET6, m, &mask.ip6) <= 0) {
	    j = atoi(m);
	    for (i = 0; i < sizeof(addr.ip6.s6_addr); i++) {
		if (j < i * 8)
		    mask.ip6.s6_addr[i] = 0;
		else if (i * 8 + 8 <= j)
		    mask.ip6.s6_addr[i] = 0xff;
		else
		    mask.ip6.s6_addr[i] = 0xff00 >> (j - i * 8);
		addr.ip6.s6_addr[i] &= mask.ip6.s6_addr[i];
	    }
	}
    }
#endif /* HAVE_IN6_ADDR */

    for (ifp = interfaces; ifp != NULL; ifp = ifp->next) {
	if (ifp->family != family)
	    continue;
	switch(family) {
	    case AF_INET:
		if ((ifp->addr.ip4.s_addr & mask.ip4.s_addr) == addr.ip4.s_addr)
		    debug_return_bool(TRUE);
#ifdef HAVE_IN6_ADDR
	    case AF_INET6:
		for (j = 0; j < sizeof(addr.ip6.s6_addr); j++) {
		    if ((ifp->addr.ip6.s6_addr[j] & mask.ip6.s6_addr[j]) != addr.ip6.s6_addr[j])
			break;
		}
		if (j == sizeof(addr.ip6.s6_addr))
		    debug_return_bool(TRUE);
#endif /* HAVE_IN6_ADDR */
	}
    }

    debug_return_bool(FALSE);
}

/*
 * Returns TRUE if "n" is one of our ip addresses or if
 * "n" is a network that we are on, else returns FALSE.
 */
int
addr_matches(char *n)
{
    char *m;
    int retval;
    debug_decl(addr_matches, SUDO_DEBUG_MATCH)

    /* If there's an explicit netmask, use it. */
    if ((m = strchr(n, '/'))) {
	*m++ = '\0';
	retval = addr_matches_if_netmask(n, m);
	*(m - 1) = '/';
    } else
	retval = addr_matches_if(n);

    debug_return_bool(retval);
}
