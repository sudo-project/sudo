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

#include <security/pam_appl.h>

#include "sudo.h"
#include "sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

static int sudo_conv __P((int, PAM_CONST struct pam_message **,
			  struct pam_response **, void *));
static char *def_prompt;

int
pam_setup(pw, promptp, data)
    struct passwd *pw;
    char **promptp;
    void **data;
{
    static struct pam_conv pam_conv;
    pam_handle_t *pamh;

    if (*data)
	return(AUTH_SUCCESS);		/* Already initialized */

    /* Initial PAM setup */
    pam_conv.conv = sudo_conv;
    if (pam_start("sudo", pw->pw_name, &pam_conv, &pamh) != PAM_SUCCESS) {
	set_perms(PERM_USER, 0);
	log_error(BAD_AUTH_INIT);
	inform_user(BAD_AUTH_INIT);
	return(AUTH_FATAL);
    }
    *data = pamh;
    return(AUTH_SUCCESS);
}

int
pam_verify(pw, prompt, data)
    struct passwd *pw;
    char *prompt;
    void **data;
{
    pam_handle_t *pamh = (pam_handle_t *)(*data);

    def_prompt = prompt;	/* for sudo_conv */

    /* PAM_SILENT prevents error messages from going to syslog(3) */
    if (pam_authenticate(pamh, PAM_SILENT) == PAM_SUCCESS)
	return(AUTH_SUCCESS);
    else
	return(AUTH_FAILURE);
}

int
pam_cleanup(pw, status, data)
    struct passwd *pw;
    int status;
    void **data;
{
    pam_handle_t *pamh = (pam_handle_t *)(*data);

    if (pam_end(pamh, (status == AUTH_SUCCESS)) == PAM_SUCCESS)
	return(AUTH_SUCCESS);
    else
	return(AUTH_FAILURE);
}

/*
 * sudo_conv()
 *
 * ``Conversation function'' for PAM.
 */
static int
sudo_conv(num_msg, msg, response, appdata_ptr)
    int num_msg;
    PAM_CONST struct pam_message **msg;
    struct pam_response **response;
    void *appdata_ptr;
{
    struct pam_response *pr;
    struct pam_message *pm;
    char *p = def_prompt;
    int echo = 0;
    extern int nil_pw;

    if ((*response = malloc(num_msg * sizeof(struct pam_response))) == NULL)
	return(PAM_CONV_ERR);
    (void) memset((VOID *)*response, 0, num_msg * sizeof(struct pam_response));

    for (pr = *response, pm = *msg; num_msg--; pr++, pm++) {
	switch (pm->msg_style) {
	    case PAM_PROMPT_ECHO_ON:
		echo = 1;
	    case PAM_PROMPT_ECHO_OFF:
		/* Override default prompt for unix auth */
		if (strcmp(p, "Password: ") && strcmp(p, "Password:"))
		    p = (char *) pm->msg;
		pr->resp = estrdup((char *) tgetpass(p,
		    PASSWORD_TIMEOUT * 60, !echo));
		if (*pr->resp == '\0')
		    nil_pw = 1;		/* empty password */
		break;
	    case PAM_TEXT_INFO:
		if (pm->msg)
		    (void) puts(pm->msg);
		break;
	    case PAM_ERROR_MSG:
		if (pm->msg) {
		    (void) fputs(pm->msg, stderr);
		    (void) fputc('\n', stderr);
		}
		break;
	    default:
		/* Something odd happened */
		/* XXX - should free non-NULL response members */
		free(*response);
		*response = NULL;
		return(PAM_CONV_ERR);
		break;
	}
    }

    return(PAM_SUCCESS);
}
