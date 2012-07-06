/*
 * Copyright (c) 2008, 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <uinfo.h>

#include "missing.h"
#include "alloc.h"
#include "error.h"

#ifdef HAVE_GETUSERATTR

#ifndef HAVE_SETRLIMIT64
# define setrlimit64(a, b) setrlimit(a, b)
# define rlimit64 rlimit
# define rlim64_t rlim_t
# define RLIM64_INFINITY RLIM_INFINITY
#endif /* HAVE_SETRLIMIT64 */

#ifndef RLIM_SAVED_MAX
# define RLIM_SAVED_MAX	RLIM64_INFINITY
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
    rlim64_t *valp;
{
    int val;

    if (getuserattr(user, lim, &val, SEC_INT) != 0)
	return -1;
    *valp = val;
    return 0;
}

static void
aix_setlimits(user)
    char *user;
{
    struct rlimit64 rlim;
    rlim64_t val;
    int n;

    if (setuserdb(S_READ) != 0)
	error(1, "unable to open userdb");

    /*
     * For each resource limit, get the soft/hard values for the user
     * and set those values via setrlimit64().  Must be run as euid 0.
     */
    for (n = 0; n < sizeof(aix_limits) / sizeof(aix_limits[0]); n++) {
	/*
	 * We have two strategies, depending on whether or not the
	 * hard limit has been defined.
	 */
	if (aix_getlimit(user, aix_limits[n].hard, &val) == 0) {
	    rlim.rlim_max = val == -1 ? RLIM64_INFINITY : val * aix_limits[n].factor;
	    if (aix_getlimit(user, aix_limits[n].soft, &val) == 0)
		rlim.rlim_cur = val == -1 ? RLIM64_INFINITY : val * aix_limits[n].factor;
	    else
		rlim.rlim_cur = rlim.rlim_max;	/* soft not specd, use hard */
	} else {
	    /* No hard limit set, try soft limit, if it exists. */
	    if (aix_getlimit(user, aix_limits[n].soft, &val) == -1)
		continue;
	    rlim.rlim_cur = val == -1 ? RLIM64_INFINITY : val * aix_limits[n].factor;

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
		    rlim.rlim_max = RLIM64_INFINITY;
		    break;
	    }
	}
	(void)setrlimit64(aix_limits[n].resource, &rlim);
    }
    enduserdb();
}

#ifdef HAVE_SETAUTHDB
/*
 * Look up administrative domain for user (SYSTEM in /etc/security/user) and
 * set it as the default for the process.  This ensures that password and
 * group lookups are made against the correct source (files, NIS, LDAP, etc).
 */
void
aix_setauthdb(user)
    char *user;
{
    char *registry;

    if (user != NULL) {
	if (setuserdb(S_READ) != 0)
	    error(1, "unable to open userdb");
	if (getuserattr(user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
	    if (setauthdb(registry, NULL) != 0)
		error(1, "unable to switch to registry \"%s\" for %s",
		    registry, user);
	}
	enduserdb();
    }
}

/*
 * Restore the saved administrative domain, if any.
 */
void
aix_restoreauthdb()
{
    if (setauthdb(NULL, NULL) != 0)
	error(1, "unable to restore registry");
}
#endif

void
aix_prep_user(user, tty)
    char *user;
    char *tty;
{
    char *info;
    int len;

    /* set usrinfo, like login(1) does */
    len = easprintf(&info, "NAME=%s%cLOGIN=%s%cLOGNAME=%s%cTTY=%s%c",
	user, '\0', user, '\0', user, '\0', tty ? tty : "", '\0');
    (void)usrinfo(SETUINFO, info, len);
    efree(info);

#ifdef HAVE_SETAUTHDB
    /* set administrative domain */
    aix_setauthdb(user);
#endif

    /* set resource limits */
    aix_setlimits(user);
}
#endif /* HAVE_GETUSERATTR */
