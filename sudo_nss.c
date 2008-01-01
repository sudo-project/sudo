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
 */

#include <config.h>

#include <sys/types.h>
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
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */

#include "sudo.h"

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

extern struct sudo_nss sudo_nss_file;
#ifdef HAVE_LDAP
extern struct sudo_nss sudo_nss_ldap;
#endif

#if defined(HAVE_LDAP) && defined(_PATH_NSSWITCH_CONF)
/*
 * Read in /etc/nsswitch.conf
 * Returns a tail queue of matches.
 */
struct sudo_nss_list *
sudo_read_nss()
{
    FILE *fp;
    char *cp;
    int saw_files = FALSE;
    int saw_ldap = FALSE;
    int got_match = FALSE;
    static struct sudo_nss_list snl;

    if ((fp = fopen(_PATH_NSSWITCH_CONF, "r")) == NULL)
	goto nomatch;

    while ((cp = sudo_parseln(fp)) != NULL) {
	/* Skip blank or comment lines */
	if (*cp == '\0')
	    continue;

	/* Look for a line starting with "sudoers:" */
	if (strncasecmp(cp, "sudoers:", 8) != 0)
	    continue;

	/* Parse line */
	for ((cp = strtok(cp + 8, " \t")); cp != NULL; (cp = strtok(NULL, " \t"))) {
	    if (strcasecmp(cp, "files") == 0 && !saw_files) {
		tq_append(&snl, &sudo_nss_file);
		got_match = TRUE;
	    } else if (strcasecmp(cp, "ldap") == 0 && !saw_ldap) {
		tq_append(&snl, &sudo_nss_ldap);
		got_match = TRUE;
	    } else if (strcasecmp(cp, "[NOTFOUND=return]") == 0 && got_match) {
		/* NOTFOUND affects the most recent entry */
		tq_last(&snl)->ret_notfound = TRUE;
		got_match = FALSE;
	    } else
		got_match = FALSE;
	}
	/* Only parse the first "sudoers:" line */
	break;
    }
    fclose(fp);

nomatch:
    /* Default to files only if no matches */
    if (tq_empty(&snl))
	tq_append(&snl, &sudo_nss_file);

    return(&snl);
}

#else /* HAVE_LDAP && _PATH_NSSWITCH_CONF */

/*
 * Non-nsswitch.conf version with hard-coded order.
 */
struct sudo_nss_list *
sudo_read_nss()
{
    static struct sudo_nss_list snl;

# ifdef HAVE_LDAP
    tq_append(&snl, &sudo_nss_ldap);
# endif
    tq_append(&snl, &sudo_nss_file);

    return(&snl);
}

#endif /* HAVE_LDAP && _PATH_NSSWITCH_CONF */
