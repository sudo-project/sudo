/*
 *  CU sudo version 1.6
 *  Copyright (c) 1998, 1999 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef __hpux
#  include <hpsecurity.h>
#else
#  include <sys/security.h>
#endif /* __hpux */
#include <prot.h>

#include "sudo.h"
#include "sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

int
secureware_setup(pw, promptp, data)
    struct passwd *pw;
    char **promptp;
    void **data;
{
#ifdef __alpha
    extern int crypt_type;

    if (crypt_type == INT_MAX)
	return(AUTH_FAILURE);			/* no shadow */
#endif
    return(AUTH_SUCCESS);
}

int
secureware_verify(pw, pass, data)
    struct passwd *pw;
    char *pass;
    void **data;
{
#ifdef __alpha
    extern int crypt_type;

#  ifdef HAVE_DISPCRYPT
    if (strcmp(user_passwd, dispcrypt(pass, user_passwd, crypt_type)) == 0)
	return(AUTH_SUCCESS);
#  else
    if (crypt_type == AUTH_CRYPT_BIGCRYPT) {
	if (strcmp(user_passwd, bigcrypt(pass, user_passwd)) == 0)
	    return(AUTH_SUCCESS);
    } else if (crypt_type == AUTH_CRYPT_CRYPT16) {
	if (strcmp(user_passwd, crypt(pass, user_passwd)) == 0)
	    return(AUTH_SUCCESS);
    }
#  endif /* HAVE_DISPCRYPT */
#elif defined(HAVE_BIGCRYPT)
    if (strcmp(user_passwd, bigcrypt(pass, user_passwd)) == 0)
	return(AUTH_SUCCESS);
#endif /* __alpha */

	return(AUTH_FAILURE);
}
