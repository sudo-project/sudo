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

#include <firewall.h>

#include "sudo.h"
#include "sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

int
fwtk_setup(pw, promptp, data)
    struct passwd *pw;
    char **promptp;
    void **data;
{
    static Cfg *confp;			/* Configuration entry struct */
    char resp[128];			/* Response from the server */

    if (confp)
	return(AUTH_SUCCESS);		/* Already initialized */

    if ((confp = cfg_read("sudo")) == (Cfg *)-1) {
	fprintf(stderr, "%s: cannot read fwtk config.\n", Argv[0]);
	return(AUTH_FATAL);
    }

    if (auth_open(confp)) {
	fprintf(stderr, "%s: cannot connect to authentication server.\n",
	    Argv[0]);
	return(AUTH_FATAL);
    }

    /* Get welcome message from auth server */
    if (auth_recv(resp, sizeof(resp))) {
	fprintf(stderr, "%s: lost connection to authentication server.\n",
	    Argv[0]);
	return(AUTH_FATAL);
    }
    if (strncmp(resp, "Authsrv ready", 13) != 0) {
	fprintf(stderr, "%s: authentication server error.\n%s\n", Argv[0], resp);
	return(AUTH_FATAL);
    }

    return(AUTH_SUCCESS);
}

int
fwtk_verify(pw, prompt, data)
    struct passwd *pw;
    char *prompt;
    void **data;
{
    char *pass;				/* Password from the user */
    char buf[SUDO_PASS_MAX + 12];	/* General prupose buffer */
    char resp[128];			/* Response from the server */
    extern int nil_pw;

    /* Send username to authentication server. */
    (void) sprintf(buf,"authorize %s 'sudo'", pw->pw_name);
    if (auth_send(buf) || auth_recv(resp, sizeof(resp))) {
	fprintf(stderr, "%s: lost connection to authentication server.\n",
	    Argv[0]);
	return(AUTH_FATAL);
    }

    /* Get the password/response from the user. */
    if (strncmp(resp, "challenge ", 10) == 0) {
	sprintf(buf, "%s\nResponse: ", &resp[10]);
	pass = tgetpass(buf, PASSWORD_TIMEOUT * 60, 0);
    } else if (strncmp(resp, "password", 8) == 0) {
	pass = tgetpass(prompt, PASSWORD_TIMEOUT * 60, 1);
    } else {
	fprintf(stderr, "%s: %s\n", Argv[0], resp);
	return(AUTH_FATAL);
    }
    if (!pass || *pass == '\0')
	nil_pw = 1;			/* empty password */

    /* Send the user's response to the server */
    sprintf(buf, "response '%s'", pass);
    if (auth_send(buf) || auth_recv(resp, sizeof(resp))) {
	fprintf(stderr, "%s: lost connection to authentication server.\n",
	    Argv[0]);
	return(AUTH_FATAL);
    }

    if (strncmp(resp, "ok", 2) == 0)
	return(AUTH_SUCCESS);

    /* Main loop prints "Permission Denied" or insult. */
    if (strcmp(resp, "Permission Denied.") != 0)
	fprintf(stderr, "%s: %s\n", Argv[0], resp);
    return(AUTH_FAILURE);
}

int
fwtk_cleanup(pw, status, data)
    struct passwd *pw;
    int status;
    void **data;
{

    auth_close();
}
