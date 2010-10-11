/*
 * Copyright (c) 1996, 1998-2005, 2007-2010
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

/*
 * Suppress a warning w/ gcc on Digital UN*X.
 * The system headers should really do this....
 */
#if defined(__osf__) && !defined(__cplusplus)
struct mbuf;
struct rtentry;
#endif

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#if defined(HAVE_SYS_SOCKIO_H) && !defined(SIOCGIFCONF)
# include <sys/sockio.h>
#endif
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
#include <netdb.h>
#include <errno.h>
#ifdef _ISC
# include <sys/stream.h>
# include <sys/sioctl.h>
# include <sys/stropts.h>
# define STRSET(cmd, param, len) {strioctl.ic_cmd=(cmd);\
				 strioctl.ic_dp=(param);\
				 strioctl.ic_timout=0;\
				 strioctl.ic_len=(len);}
#endif /* _ISC */
#ifdef _MIPS
# include <net/soioctl.h>
#endif /* _MIPS */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#ifdef HAVE_GETIFADDRS
# include <ifaddrs.h>
#endif

#include "missing.h"
#include "alloc.h"
#include "error.h"

/* Minix apparently lacks IFF_LOOPBACK */
#ifndef IFF_LOOPBACK
# define IFF_LOOPBACK	0
#endif

#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN 46
#endif

#ifdef HAVE_GETIFADDRS

/*
 * Fill in the interfaces string with the machine's ip addresses and netmasks
 * and return the number of interfaces found.
 */
int
get_net_ifs(char **addrinfo)
{
    struct ifaddrs *ifa, *ifaddrs;
    struct sockaddr_in *sin;
#ifdef HAVE_IN6_ADDR
    struct sockaddr_in6 *sin6;
    char addrbuf[INET6_ADDRSTRLEN];
#endif
    int ailen, i, len, num_interfaces = 0;
    char *cp;

    if (getifaddrs(&ifaddrs))
	return 0;

    /* Allocate space for the interfaces info string. */
    for (ifa = ifaddrs; ifa != NULL; ifa = ifa -> ifa_next) {
	/* Skip interfaces marked "down" and "loopback". */
	if (ifa->ifa_addr == NULL || ifa->ifa_netmask == NULL ||
	    !ISSET(ifa->ifa_flags, IFF_UP) || ISSET(ifa->ifa_flags, IFF_LOOPBACK))
	    continue;

	switch(ifa->ifa_addr->sa_family) {
	    case AF_INET:
#ifdef HAVE_IN6_ADDR
	    case AF_INET6:
#endif
		num_interfaces++;
		break;
	}
    }
    if (num_interfaces == 0)
	return 0;
    ailen = num_interfaces * 2 * INET6_ADDRSTRLEN;
    *addrinfo = cp = emalloc(ailen);

    /* Store the IP addr/netmask pairs. */
    for (ifa = ifaddrs, i = 0; ifa != NULL; ifa = ifa -> ifa_next) {
	/* Skip interfaces marked "down" and "loopback". */
	if (ifa->ifa_addr == NULL || ifa->ifa_netmask == NULL ||
	    !ISSET(ifa->ifa_flags, IFF_UP) || ISSET(ifa->ifa_flags, IFF_LOOPBACK))
		continue;

	switch(ifa->ifa_addr->sa_family) {
	    case AF_INET:
		sin = (struct sockaddr_in *)ifa->ifa_addr;
		len = snprintf(cp, ailen - (*addrinfo - cp),
		    "%s%s/", cp == *addrinfo ? "" : " ",
		    inet_ntoa(sin->sin_addr));
		if (len <= 0 || len >= ailen - (*addrinfo - cp)) {
		    warningx("load_interfaces: overflow detected");
		    goto done;
		}
		cp += len;

		sin = (struct sockaddr_in *)ifa->ifa_netmask;
		len = snprintf(cp, ailen - (*addrinfo - cp),
		    "%s", inet_ntoa(sin->sin_addr));
		if (len <= 0 || len >= ailen - (*addrinfo - cp)) {
		    warningx("load_interfaces: overflow detected");
		    goto done;
		}
		cp += len;
		break;
#ifdef HAVE_IN6_ADDR
	    case AF_INET6:
		sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, addrbuf, sizeof(addrbuf));
		len = snprintf(cp, ailen - (*addrinfo - cp),
		    "%s%s/", cp == *addrinfo ? "" : " ", addrbuf);
		if (len <= 0 || len >= ailen - (*addrinfo - cp)) {
		    warningx("load_interfaces: overflow detected");
		    goto done;
		}
		cp += len;

		sin6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
		inet_ntop(AF_INET6, &sin6->sin6_addr, addrbuf, sizeof(addrbuf));
		len = snprintf(cp, ailen - (*addrinfo - cp), "%s", addrbuf);
		if (len <= 0 || len >= ailen - (*addrinfo - cp)) {
		    warningx("load_interfaces: overflow detected");
		    goto done;
		}
		cp += len;
		break;
#endif /* HAVE_IN6_ADDR */
	}
    }

done:
#ifdef HAVE_FREEIFADDRS
    freeifaddrs(ifaddrs);
#else
    efree(ifaddrs);
#endif
    return num_interfaces;
}

#elif defined(SIOCGIFCONF) && !defined(STUB_LOAD_INTERFACES)

/*
 * Allocate and fill in the interfaces global variable with the
 * machine's ip addresses and netmasks.
 */
int
get_net_ifs(char **addrinfo)
{
    struct ifconf *ifconf;
    struct ifreq *ifr, ifr_tmp;
    struct sockaddr_in *sin;
    int ailen, i, len, n, sock, num_interfaces = 0;
    size_t buflen = sizeof(struct ifconf) + BUFSIZ;
    char *cp, *previfname = "", *ifconf_buf = NULL;
#ifdef _ISC
    struct strioctl strioctl;
#endif /* _ISC */

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
	error(1, "cannot open socket");

    /*
     * Get interface configuration or return.
     */
    for (;;) {
	ifconf_buf = erealloc(ifconf_buf, buflen);
	ifconf = (struct ifconf *) ifconf_buf;
	ifconf->ifc_len = buflen - sizeof(struct ifconf);
	ifconf->ifc_buf = (caddr_t) (ifconf_buf + sizeof(struct ifconf));

#ifdef _ISC
	STRSET(SIOCGIFCONF, (caddr_t) ifconf, buflen);
	if (ioctl(sock, I_STR, (caddr_t) &strioctl) < 0) {
#else
	/* Note that some kernels return EINVAL if the buffer is too small */
	if (ioctl(sock, SIOCGIFCONF, (caddr_t) ifconf) < 0 && errno != EINVAL) {
#endif /* _ISC */
	    efree(ifconf_buf);
	    (void) close(sock);
	    return 0;
	}

	/* Break out of loop if we have a big enough buffer. */
	if (ifconf->ifc_len + sizeof(struct ifreq) < buflen)
	    break;
	buflen += BUFSIZ;
    }

    /* Allocate space for the maximum number of interfaces that could exist. */
    if ((n = ifconf->ifc_len / sizeof(struct ifreq)) == 0)
	return 0;
    ailen = n * 2 * INET6_ADDRSTRLEN;
    *addrinfo = cp = emalloc(ailen);

    /* For each interface, store the ip address and netmask. */
    for (i = 0; i < ifconf->ifc_len; ) {
	/* Get a pointer to the current interface. */
	ifr = (struct ifreq *) &ifconf->ifc_buf[i];

	/* Set i to the subscript of the next interface. */
	i += sizeof(struct ifreq);
#ifdef HAVE_SA_LEN
	if (ifr->ifr_addr.sa_len > sizeof(ifr->ifr_addr))
	    i += ifr->ifr_addr.sa_len - sizeof(struct sockaddr);
#endif /* HAVE_SA_LEN */

	/* Skip duplicates and interfaces with NULL addresses. */
	sin = (struct sockaddr_in *) &ifr->ifr_addr;
	if (sin->sin_addr.s_addr == 0 ||
	    strncmp(previfname, ifr->ifr_name, sizeof(ifr->ifr_name) - 1) == 0)
	    continue;

	if (ifr->ifr_addr.sa_family != AF_INET)
		continue;

#ifdef SIOCGIFFLAGS
	memset(&ifr_tmp, 0, sizeof(ifr_tmp));
	strncpy(ifr_tmp.ifr_name, ifr->ifr_name, sizeof(ifr_tmp.ifr_name) - 1);
	if (ioctl(sock, SIOCGIFFLAGS, (caddr_t) &ifr_tmp) < 0)
#endif
	    ifr_tmp = *ifr;
	
	/* Skip interfaces marked "down" and "loopback". */
	if (!ISSET(ifr_tmp.ifr_flags, IFF_UP) ||
	    ISSET(ifr_tmp.ifr_flags, IFF_LOOPBACK))
		continue;

	sin = (struct sockaddr_in *) &ifr->ifr_addr;
	len = snprintf(cp, ailen - (*addrinfo - cp),
	    "%s%s/", cp == *addrinfo ? "" : " ",
	    inet_ntoa(sin->sin_addr));
	if (len <= 0 || len >= ailen - (*addrinfo - cp)) {
	    warningx("load_interfaces: overflow detected");
	    goto done;
	}
	cp += len;

	/* Stash the name of the interface we saved. */
	previfname = ifr->ifr_name;

	/* Get the netmask. */
	memset(&ifr_tmp, 0, sizeof(ifr_tmp));
	strncpy(ifr_tmp.ifr_name, ifr->ifr_name, sizeof(ifr_tmp.ifr_name) - 1);
#ifdef _ISC
	STRSET(SIOCGIFNETMASK, (caddr_t) &ifr_tmp, sizeof(ifr_tmp));
	if (ioctl(sock, I_STR, (caddr_t) &strioctl) < 0) {
#else
	if (ioctl(sock, SIOCGIFNETMASK, (caddr_t) &ifr_tmp) < 0) {
#endif /* _ISC */
	    sin = (struct sockaddr_in *) &ifr_tmp.ifr_addr;
	    sin->sin_addr.s_addr = htonl(IN_CLASSC_NET);
	}
	sin = (struct sockaddr_in *) &ifr_tmp.ifr_addr;
	len = snprintf(cp, ailen - (*addrinfo - cp),
	    "%s", inet_ntoa(sin->sin_addr));
	if (len <= 0 || len >= ailen - (*addrinfo - cp)) {
	    warningx("load_interfaces: overflow detected");
	    goto done;
	}
	cp += len;
	num_interfaces++;
    }

done:
    efree(ifconf_buf);
    (void) close(sock);

    return num_interfaces;
}

#else /* !SIOCGIFCONF || STUB_LOAD_INTERFACES */

/*
 * Stub function for those without SIOCGIFCONF or getifaddrs()
 */
int
get_net_ifs(char **addrinfo)
{
    return 0;
}

#endif /* SIOCGIFCONF && !STUB_LOAD_INTERFACES */
