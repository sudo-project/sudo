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

#include <afs/stds.h>
#include <afs/kautils.h>

#include "sudo.h"
#include "sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

int
afs_verify(pw, pass, data)
    struct passwd *pw;
    char *pass;
    void **data;
{
    struct ktc_encryptionKey afs_key;
    struct ktc_token afs_token;

    /* Try to just check the password */
    ka_StringToKey(pass, NULL, &afs_key);
    if (ka_GetAdminToken(pw->pw_name,		/* name */
			 NULL,			/* instance */
			 NULL,			/* realm */
			 &afs_key,		/* key (contains password) */
			 0,			/* lifetime */
			 &afs_token,		/* token */
			 0) == 0)		/* new */
	return(AUTH_SUCCESS);

    /* Fall back on old method XXX - needed? */
    setpag();
    if (ka_UserAuthenticateGeneral(KA_USERAUTH_VERSION+KA_USERAUTH_DOSETPAG,
				   pw->pw_name,	/* name */
				   NULL,	/* instance */
				   NULL,	/* realm */
				   pass,	/* password */
				   0,		/* lifetime */
				   NULL,	/* expiration ptr (unused) */
				   0,		/* spare */
				   NULL) == 0)	/* reason */
	return(AUTH_SUCCESS);

    return(AUTH_FAILURE);
}
