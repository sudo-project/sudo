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
#include "insults.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

sudo_auth auth_switch[] = {
#ifdef AUTH_STANDALONE
    AUTH_STANDALONE
#else
    AUTH_ENTRY(0, "passwd", NULL, passwd_verify, NULL)
#  ifdef HAVE_SECUREWARE
    AUTH_ENTRY(0, "secureware", secureware_setup, secureware_verify, NULL)
#  endif
#  ifdef HAVE_SKEY
    AUTH_ENTRY(1, "skey", skey_setup, skey_verify, NULL)
#  endif
#  ifdef HAVE_OPIE
    AUTH_ENTRY(1, "opie", opie_setup, opie_verify, NULL)
#  endif
#  ifdef HAVE_AFS
    AUTH_ENTRY(1, "afs", NULL, afs_verify, NULL)
#  endif
#  ifdef HAVE_KERB4
    AUTH_ENTRY(1, "kerb4", kerb4_setup, kerb4_verify, NULL)
#  endif
#  ifdef HAVE_KERB5
    AUTH_ENTRY(1, "kerb5", kerb5_setup, kerb5_verify, NULL)
#  endif
#endif /* AUTH_STANDALONE */
    AUTH_ENTRY(0, NULL, NULL, NULL, NULL)
};

int nil_pw; /* bad global, bad (oh well) */

void
/* verify_user() */
check_passwd()
{
    int counter = TRIES_FOR_PASSWORD + 1;
    int status, success = AUTH_FAILURE;
    char *p;
    sudo_auth *auth;

    while (--counter) {
	/* Do any per-method setup and unconfigure the method if needed */
	for (auth = auth_switch; auth->name; auth++) {
	    if (auth->setup && auth->configured) {
		if (auth->need_root)
		    set_perms(PERM_ROOT, 0);

		status = (auth->setup)(user_pw_ent, &prompt, &auth->data);
		if (status == AUTH_FAILURE)
		    auth->configured = 0;
		else if (status == AUTH_FATAL)	/* XXX log */
		    exit(1);		/* assume error msg already printed */

		if (auth->need_root)
		    set_perms(PERM_USER, 0);
	    }
	}

	/* Get the password unless the auth function will do it for us */
	nil_pw = 0;
#if defined(AUTH_STANDALONE) && !defined(AUTH_STANDALONE_GETPASS)
	p = prompt;
#else
	p = (char *) tgetpass(prompt, PASSWORD_TIMEOUT * 60, 1);
	if (!p || *p == '\0')
	    nil_pw = 1;
#endif /* AUTH_STANDALONE */

	/* Call authentication functions. */
	for (auth = auth_switch; auth->name; auth++) {
	    if (!auth->configured)
		continue;

	    if (auth->need_root)
		set_perms(PERM_ROOT, 0);

	    success = auth->status = (auth->verify)(user_pw_ent, p, &auth->data);

	    if (auth->need_root)
		set_perms(PERM_USER, 0);

	    if (auth->status != AUTH_FAILURE)
		goto cleanup;
	}

	/* Exit loop on nil password, but give it a chance to match first. */
	if (nil_pw) {
	    if (counter == TRIES_FOR_PASSWORD)
		exit(1);
	    else
		break;
	}

	pass_warn(stderr);
    }

cleanup:
    /* Call cleanup routines. */
    for (auth = auth_switch; auth->name; auth++) {
	if (auth->cleanup && auth->configured) {
	    if (auth->need_root)
		set_perms(PERM_ROOT, 0);

	    status = (auth->cleanup)(user_pw_ent, auth->status, &auth->data);
	    if (status == AUTH_FATAL)	/* XXX log */
		exit(1);		/* assume error msg already printed */

	    if (auth->need_root)
		set_perms(PERM_USER, 0);
	}
    }

    switch (success) {
	case AUTH_SUCCESS:
	    return;
	case AUTH_FAILURE:
	    log_error(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
	    inform_user(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
	case AUTH_FATAL:
	    exit(1);
    }
}

void
pass_warn(fp)
    FILE *fp;
{

#ifdef USE_INSULTS
    (void) fprintf(fp, "%s\n", INSULT);
#else
    (void) fprintf(fp, "%s\n", INCORRECT_PASSWORD);
#endif /* USE_INSULTS */
}
