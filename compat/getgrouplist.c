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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#include <grp.h>

#include <compat.h>

/*
 * BSD-compatible getgrouplist(3) using getgrent(3)
 */
int
getgrouplist(const char *name, gid_t basegid, gid_t *groups, int *ngroupsp)
{
    int i, ngroups = 1;
    int grpsize = *ngroupsp;
    int rval = -1;
    struct group *grp;

    /* We support BSD semantics where the first element is the base gid */
    if (grpsize <= 0)
	return -1;
    groups[0] = basegid;

    setgrent();
    while ((grp = getgrent()) != NULL) {
	if (grp->gr_gid == basegid)
	    continue;

	for (i = 0; grp->gr_mem[i] != NULL; i++) {
	    if (strcmp(name, grp->gr_mem[i]) == 0)
		break;
	}
	if (grp->gr_mem[i] == NULL)
	    continue; /* user not found */

	/* Only add if it is not the same as an existing gid */
	for (i = 0; i < ngroups; i++) {
	    if (grp->gr_gid == groups[i])
		break;
	}
	if (i == ngroups) {
	    if (ngroups == grpsize)
		goto done;
	    groups[ngroups++] = grp->gr_gid;
	}
    }
    rval = 0;

done:
    endgrent();
    *ngroupsp = ngroups;

    return rval;
}
