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

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

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
#include <opie.h>

#include "sudo.h"
#include "sudo_auth.h"

int
opie_setup(pw, promptp, data)
    struct passwd *pw;
    char **promptp;
    void **data;
{
    char challenge[OPIE_CHALLENGE_MAX];
    static char *orig_prompt = NULL, *new_prompt = NULL;
    static int op_len, np_size;
    static struct opie opie;

    /* Stash a pointer to the opie struct if we have not initialized */
    if (!*data)
	*data = &opie;

    /* Save the original prompt */
    if (orig_prompt == NULL) {
	orig_prompt = *promptp;
	op_len = strlen(orig_prompt);

	/* Ignore trailing colon (we will add our own) */
	if (orig_prompt[op_len - 1] == ':')
	    op_len--;
    }

    /* Get the opie part of the prompt */
    if (opiechallenge(&opie, user_name, challenge) != 0) {
#ifdef OTP_ONLY
	(void) fprintf(stderr,
		       "%s: You do not exist in the s/key database.\n",
		       Argv[0]);
	return(AUTH_FATAL);
#else
	return(AUTH_FAILURE);
#endif /* OTP_ONLY */
    }

    /* Get space for new prompt with embedded S/Key challenge */
    if (np_size < op_len + strlen(challenge) + 7) {
	np_size = op_len + strlen(challenge) + 7;
	new_prompt = (char *) erealloc(new_prompt, np_size);
    }

#ifdef LONG_OTP_PROMPT
    (void) sprintf(new_prompt, "%s\n%s", challenge, orig_prompt);
#else
    (void) sprintf(new_prompt, "%.*s [ %s ]:", op_len, orig_prompt, challenge);
#endif /* LONG_OTP_PROMPT */

    *promptp = new_prompt;
    return(AUTH_SUCCESS);
}

int
opie_verify(pw, pass, data)
    struct passwd *pw;
    char *pass;
    void **data;
{
    struct opie *opiep = (struct opie *) (*data);

    if (opieverify(opiep, pass) == 0)  
	return(AUTH_SUCCESS);
    else
	return(AUTH_FAILURE);
}
