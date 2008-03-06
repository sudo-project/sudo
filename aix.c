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

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

#ifdef HAVE_GETUSERATTR

struct aix_limit {
    int resource;
    const char *soft;
    const char *hard;
};

static struct aix_limit aix_limits[] = {
    { RLIMIT_FSIZE, S_UFSIZE, S_UFSIZE_HARD },
    { RLIMIT_CPU, S_UCPU, S_UCPU_HARD },
    { RLIMIT_DATA, S_UDATA, S_UDATA_HARD },
    { RLIMIT_STACK, S_USTACK, S_USTACK_HARD },
    { RLIMIT_RSS, S_URSS, S_URSS_HARD },
    { RLIMIT_CORE, S_UCORE, S_UCORE_HARD },
    { RLIMIT_NOFILE, S_UNOFILE, S_UNOFILE_HARD }
};

void
aix_setlimits(user)
    const char *user;
{
    struct rlimit rlim;
    int i, n;

    /*
     * For each resource limit, get the soft/hard values for the user
     * and set those values via setrlimit().  Must be run as euid 0.
     */
    for (n = 0; n < sizeof(aix_limits) / sizeof(aix_limits[0])) {
	if (getuserattr(user, aix_limits[n].soft, &i, SEC_INT) != 0)
	    continue;
	rlim.rlim_cur = i;
	if (getuserattr(user, aix_limits[n].hard, &i, SEC_INT) != 0)
	    continue;
	rlim.rlim_max = i;
	(void)setrlimit(aix_limits[n].resource, &rlim);
    }
}

#endif /* HAVE_GETUSERATTR */
