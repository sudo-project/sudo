/*
 *  CU sudo version 1.5.8
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
 *
 *******************************************************************
 *
 *  secureware.c -- check a user's password when using SecureWare C2
 *
 *  Todd C. Miller (millert@colorado.edu) Sat Oct 17 14:42:44 MDT 1998
 */

#include "config.h"

#ifdef HAVE_GETPRPWNAM

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
#include <netinet/in.h>
#include <pwd.h>
#ifdef __hpux
#  include <hpsecurity.h>
#else
#  include <sys/security.h>
#endif /* __hpux */
#include <prot.h>

#include "sudo.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */


/********************************************************************
 *
 *  check_secureware()
 *
 *  This function checks a password against the user's encrypted one
 *  using the SecureWare crypt functions. Returns 1 on a match, else 0.
 */

int check_secureware(pass)
    char *pass;
{
#ifdef __alpha
    extern int crypt_type;

    if (crypt_type == INT_MAX)
	return(0);			/* no shadow */

#  ifdef HAVE_DISPCRYPT
    if (strcmp(user_passwd, dispcrypt(pass, user_passwd, crypt_type)) == 0)
	return(1);
#  else
    if (crypt_type == AUTH_CRYPT_BIGCRYPT) {
	if (strcmp(user_passwd, bigcrypt(pass, user_passwd)) == 0)
	    return(1);
    } else if (crypt_type == AUTH_CRYPT_CRYPT16) {
	if (strcmp(user_passwd, crypt(pass, user_passwd)) == 0)
	    return(1);
    }
#  endif /* HAVE_DISPCRYPT */
#elif defined(HAVE_BIGCRYPT)
    if (strcmp(user_passwd, bigcrypt(pass, user_passwd)) == 0)
	return(1);
#endif /* __alpha */

	return(0);
}

#endif /* HAVE_GETPRPWNAM */
