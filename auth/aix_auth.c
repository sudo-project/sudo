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

#include "sudo.h"
#include "sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

int
aixauth_verify(pw, prompt, data)
    struct passwd *pw;
    char *prompt;
    void **data;
{
    char *message, *pass;
    int reenter = 1;

    pass = GETPASS(prompt, PASSWORD_TIMEOUT * 60, 1);
    if (authenticate(pw->pw_name, pass, &reenter, &message) == 0)
	return(AUTH_SUCCESS);
    else
	return(AUTH_FAILURE);
}
