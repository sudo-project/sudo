/*
 *  CU sudo version 1.5.7
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
 *  check_sia.c -- check a user's password using Digital UNIX's
 *		   Security Integration Architecture
 *
 *  Spider Boardman Sep 26, 1998
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"

#ifdef HAVE_SIA

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
#include <siad.h>

#include "sudo.h"

/*
 * Prototypes for local functions
 */
static int tcollect	__P((int, int, uchar_t *, int, prompt_t *));

/********************************************************************
 *  tcollect()
 *
 *  Collection routine (callback) for limiting the timeouts in SIA
 *  prompts.
 */
static int tcollect(timeout, rendition, title, nprompts, prompts)
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
	    break;
	default:
	    break;
    }
    return sia_collect_trm(timeout, rendition, title, nprompts, prompts);
}

/********************************************************************
 *  sia_attempt_auth()
 *
 *  Try to authenticate the user using Security Integration Architecture
 *  (SIA). Added 9/26/98 by Spider Boardman
 */
void sia_attempt_auth()
{
    SIAENTITY *siah = NULL;
    int retval;
    int counter = TRIES_FOR_PASSWORD;

    set_perms(PERM_ROOT, 0);
    while (counter > 0) {
	retval = sia_ses_init(&siah, Argc, Argv, NULL, user_name, ttyname(0),
			      1, NULL);
	if (retval != SIASUCCESS) {
	    set_perms(PERM_USER, 0);
	    log_error(BAD_ALLOCATION);
	    inform_user(BAD_ALLOCATION);
	    exit(1);
	}
	retval = sia_ses_reauthent(tcollect, siah);
	(void) sia_ses_release(&siah);
	if (retval == SIASUCCESS) {
	    set_perms(PERM_USER, 0);
	    return;
	}

	--counter;
#ifdef USE_INSULTS
	(void) fprintf(stderr, "%s\n", INSULT);
#else
	(void) fprintf(stderr, "%s\n", INCORRECT_PASSWORD);
#endif /* USE_INSULTS */
    }
    set_perms(PERM_USER, 0);

    if (counter > 0) {
	log_error(PASSWORD_NOT_CORRECT);
	inform_user(PASSWORD_NOT_CORRECT);
    } else {
	log_error(PASSWORDS_NOT_CORRECT);
	inform_user(PASSWORDS_NOT_CORRECT);
    }
    exit(1);
}

#endif /* HAVE_SIA */
