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

#include <sdi_athd.h>
#include <sdconf.h>
#include <sdacmvls.h>

#include "sudo.h"
#include "sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

union config_record configure;

int
securid_setup(pw, promptp, data)
    struct passwd *pw;
    char **promptp;
    void **data;
{
    static SD_CLIENT sd_dat;			/* SecurID data block */

    if (!*data)
	creadcfg();				/* Only read config file once */

    /* Initialize SecurID every time. */
    *data = &sd_dat;
    if (sd_init(sd) == 0)
	return(AUTH_SUCCESS);
    else {
	(void) fprintf(stderr, "%s: Cannot contact SecurID server\n", Argv[0]);
	return(AUTH_FATAL);
    }
}

int
securid_verify(pw, pass, data)
    struct passwd *pw;
    char *pass;
    void **data;
{
    struct SD_CLIENT *sd = (struct SD_CLIENT *)(*data);

    if (sd_auth(sd) == ACM_OK)
	return(AUTH_SUCCESS);
    else
	return(AUTH_FAILURE);
}
