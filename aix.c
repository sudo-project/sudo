/*
 * Copyright (c) 2008 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/resource.h>

#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#include <usersec.h>

#include <compat.h>

#ifdef HAVE_GETUSERATTR

#ifndef RLIM_SAVED_MAX
# define RLIM_SAVED_MAX	RLIM_INFINITY
#endif

struct aix_limit {
    int resource;
    char *soft;
    char *hard;
    int factor;
};

static struct aix_limit aix_limits[] = {
    { RLIMIT_FSIZE, S_UFSIZE, S_UFSIZE_HARD, 512 },
    { RLIMIT_CPU, S_UCPU, S_UCPU_HARD, 1 },
    { RLIMIT_DATA, S_UDATA, S_UDATA_HARD, 512 },
    { RLIMIT_STACK, S_USTACK, S_USTACK_HARD, 512 },
    { RLIMIT_RSS, S_URSS, S_URSS_HARD, 512 },
    { RLIMIT_CORE, S_UCORE, S_UCORE_HARD, 512 },
    { RLIMIT_NOFILE, S_UNOFILE, S_UNOFILE_HARD, 1 }
};

static int
aix_getlimit(user, lim, valp)
    char *user;
    char *lim;
    int *valp;
{
    if (getuserattr(user, lim, valp, SEC_INT) != 0)
	return getuserattr("default", lim, valp, SEC_INT);
    return(0);
}

void
aix_setlimits(user)
    char *user;
{
    struct rlimit rlim;
    int i, n;

    /*
     * For each resource limit, get the soft/hard values for the user
     * and set those values via setrlimit().  Must be run as euid 0.
     */
    for (n = 0; n < sizeof(aix_limits) / sizeof(aix_limits[0]); n++) {
	/*
	 * We have two strategies, depending on whether or not the
	 * hard limit has been defined.
	 */
	if (aix_getlimit(user, aix_limits[n].hard, &i) == 0) {
	    rlim.rlim_max = i == -1 ? RLIM_INFINITY : i * aix_limits[n].factor;
	    if (aix_getlimit(user, aix_limits[n].soft, &i) == 0)
		rlim.rlim_cur = i == -1 ? RLIM_INFINITY : i * aix_limits[n].factor;
	    else
		rlim.rlim_cur = rlim.rlim_max;	/* soft not specd, use hard */
	} else {
	    /* No hard limit set, try soft limit. */
	    if (aix_getlimit(user, aix_limits[n].soft, &i) == 0)
		rlim.rlim_cur = i == -1 ? RLIM_INFINITY : i * aix_limits[n].factor;

	    /* Set hard limit per AIX /etc/security/limits documentation. */
	    switch (aix_limits[n].resource) {
		case RLIMIT_CPU:
		case RLIMIT_FSIZE:
		    rlim.rlim_max = rlim.rlim_cur;
		    break;
		case RLIMIT_STACK:
		    rlim.rlim_max = RLIM_SAVED_MAX;
		    break;
		default:
		    rlim.rlim_max = RLIM_INFINITY;
		    break;
	    }
	}
	(void)setrlimit(aix_limits[n].resource, &rlim);
    }
}

#endif /* HAVE_GETUSERATTR */
