/*
 *  CU sudo version 1.6
 *  Copyright (c) 1999 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  Please send bugs, changes, problems to sudo-bugs@courtesan.com
 */

#include "config.h"

#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <sys/param.h>
#include <sys/types.h>
#include <pwd.h>
#include <krb.h>

#include "sudo.h"
#include "sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

int
kerb4_setup(pw, promptp, data)
    struct passwd *pw;
    char **promptp;
    void **data;
{
    static char realm[REALM_SZ];

    if (*data)
	return(AUTH_SUCCESS);		/* Already initialized */

    /* Don't try to verify root */
    if (pw->pw_uid == 0)
	return(AUTH_FAILURE);

    /* Get the local realm, or retrun failure (no krb.conf) */
    if (krb_get_lrealm(realm, 1) != KSUCCESS)
	return(AUTH_FAILURE);

    /* Stash a pointer to the realm (used in kerb4_verify) */
    *data = realm;

    return(AUTH_SUCCESS);
}

int
kerb4_verify(pw, pass, data)
    struct passwd *pw;
    char *pass;
    void **data;
{
    char tkfile[sizeof(_PATH_SUDO_TIMEDIR) + 4 + MAX_UID_T_LEN];
    char *realm = *data;
    int error;

    /*
     * Set the ticket file to be in sudo sudo timedir so we don't
     * wipe out other (real) kerberos tickets.
     */
    (void) sprintf(tkfile, "%s/tkt%ld", _PATH_SUDO_TIMEDIR, (long) pw->pw_uid);
    (void) krb_set_tkt_string(tkfile);

    /* Convert the password to a ticket given. */
    error = krb_get_pw_in_tkt(pw->pw_name, "", realm, "krbtgt", realm,
	DEFAULT_TKT_LIFE, pass);

    switch (error) {
	case INTK_OK:
	    dest_tkt();			/* we are done with the temp ticket */
	    return(AUTH_SUCCESS);
	    break;
	case INTK_BADPW:
	case KDC_PR_UNKNOWN:
	    break;
	default:
	    (void) fprintf(stderr, "Warning: Kerberos error: %s\n",
		krb_err_txt[error]);
    }

    return(AUTH_FAILURE);
}
