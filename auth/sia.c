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
 *
 *******************************************************************
 *
 *  sia.c -- check a user's password using Digital UN*X's
 *	     Security Integration Architecture (SIA)
 *
 * This code is derived from software contributed by Spider Boardman
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
#include <siad.h>

#include "sudo.h"
#include "sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

static int sudo_collect	__P((int, int, uchar_t *, int, prompt_t *));

static char *def_prompt;

/*
 * Collection routine (callback) for limiting the timeouts in SIA
 * prompts and (possibly) setting a custom prompt.
 */
static int
sudo_collect(timeout, rendition, title, nprompts, prompts)
    int timeout;
    int rendition;
    uchar_t *title;
    int nprompts;
    prompt_t *prompts;
{
    switch (rendition) {
	case SIAFORM:
	case SIAONELINER:
	    if (timeout <= 0 || timeout > PASSWORD_TIMEOUT * 60)
		timeout = PASSWORD_TIMEOUT * 60;
	    /*
	     * Substitute custom prompt if a) the sudo prompt is not "Password:"
	     * and b) the SIA prompt is "Password:" (so we know it is safe).
	     * This keeps us from overwriting things like S/Key challenges.
	     */
	    if (strcmp((char *)prompts[0].prompt, "Password:") == 0 &&
		strcmp(def_prompt, "Password:") != 0)
		prompts[0].prompt = (unsigned char *)def_prompt;
	    break;
	default:
	    break;
    }

    return sia_collect_trm(timeout, rendition, title, nprompts, prompts);
}

int
sia_setup(pw, promptp, data)
    struct passwd *pw;
    char **promptp;
    void **data;
{
    SIAENTITY *siah = NULL;

    if (sia_ses_init(&siah, Argc, Argv, NULL, pw->pw_name, ttyname(0), 1, NULL)
	!= SIASUCCESS) {

	set_perms(PERM_USER, 0);
	log_error(BAD_AUTH_INIT);
	inform_user(BAD_AUTH_INIT);
	return(AUTH_FATAL);
    }

    *data = siah;
    return(AUTH_SUCCESS);
}

int
sia_verify(pw, prompt, data)
    struct passwd *pw;
    char *prompt;
    void **data;
{
    SIAENTITY *siah = (SIAENTITY *)(*data);

    def_prompt = prompt;		/* for sudo_collect */

    /* XXX - need a way to detect user hitting return or EOF at prompt */
    if (sia_ses_reauthent(sudo_collect, siah) == SIASUCCESS)
	return(AUTH_SUCCESS);
    else
	return(AUTH_FAILURE);
}

int
sia_cleanup(pw, status, data)
    struct passwd *pw;
    int status;
    void **data;
{
    SIAENTITY *siah = (SIAENTITY *)(*data);

    (void) sia_ses_release(&siah);
}
