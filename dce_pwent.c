/*
 *  CU sudo version 1.5.8
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
 *  Contributed by Jeff Earickson, Colby College, Waterville, ME
 *  (jaearick@colby.edu)
 *
 *  The code below basically comes from the examples supplied on
 *  the OSF DCE 1.0.3 manpages for the sec_login routines, with
 *  enough additional polishing to make the routine work with the
 *  rest of sudo.
 *
 *  This code is known to work on HP 700 and 800 series systems
 *  running HP-UX 9.X and 10.X, with either HP's version 1.2.1 of DCE.
 *  (aka, OSF DCE 1.0.3) or with HP's version 1.4 of DCE (aka, OSF
 *  DCE 1.1).
 *
 *  Use at your own risk!!!  (But I would like to hear about bugs.)
 *
 *  $Id$
 */

#include "config.h"

#ifdef HAVE_DCE

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <dce/rpc.h>
#include <dce/sec_login.h>
#include <dce/dce_error.h> /* required to call dce_error_inq_text routine   */

#include "compat.h"

/*
 * Prototypes
 */
static int check_dce_status __P((error_status_t, char *));

/*
 * Globals
 */
static int      error_stat;
static unsigned char    error_string[dce_c_error_string_len];


/* returns 1 ("true") if user is a valid DCE principal, 0 otherwise */
int dce_pwent(username, plain_pw)
char *username;
char *plain_pw;
{
	struct passwd		*pwd;
	sec_passwd_rec_t	password_rec;
	sec_login_handle_t	login_context;
	boolean32			reset_passwd;
	sec_login_auth_src_t	auth_src;
	error_status_t		status;
	unsigned32			nbytes;

	/* create the local context of the DCE principal necessary   */
	/* to perform authenticated network operations. The network  */
	/* identity set up by this operation cannot be used until it */
	/* is validated via sec_login_validate_identity(). */
	if(sec_login_setup_identity((unsigned_char_p_t) username,
		sec_login_no_flags,&login_context,&status))
	{
		if(check_dce_status(status,"sec_login_setup_identity(1):"))
			return(0);

		password_rec.key.key_type = sec_passwd_plain;
		password_rec.key.tagged_union.plain = (idl_char *) plain_pw;
		password_rec.pepper = NULL;
		password_rec.version_number = sec_passwd_c_version_none;

		/* validate the login context with the password */
		if(sec_login_validate_identity(login_context,&password_rec,
			&reset_passwd,&auth_src,&status))
		{
			if(check_dce_status(status,"sec_login_validate_identity(1):"))
				return(0);

			/* Certify that the DCE Security Server used to set      */
			/* up and validate a login context is legitimate.  Makes */
			/* sure that we didn't get spoofed by another DCE server.*/
			if(!sec_login_certify_identity(login_context,&status))
			{
				fprintf(stderr,"Whoa! Bogus authentication server!\n");
				(void) check_dce_status(status,"sec_login_certify_identity(1):");
				return(0);
			}
			if(check_dce_status(status,"sec_login_certify_identity(2):"))
				return(0);

			/* sets the network credentials to those specified */
			/* by the now validated login context. */
			sec_login_set_context(login_context,&status);
			if(check_dce_status(status,"sec_login_set_context:"))
				return(0);

			/* oops, your credentials were no good. Possibly   */
			/* caused by clock times out of adjustment between */
			/* DCE client and DCE security server...           */
			if(auth_src != sec_login_auth_src_network)
			{
				fprintf(stderr,"You have no network credentials\n");
				return(0);
			}
			/* check if the password has aged and is no good */
			if(reset_passwd)
			{
				fprintf(stderr,"Your DCE password needs resetting\n");
				return(0);
			}

			/* malloc space for passwd structure */
			nbytes = sizeof(struct passwd);
			if((pwd = (struct passwd *) malloc(nbytes)) == NULL)
			{
				fprintf(stderr,"malloc for passwd struct failed\n");
				return(0);
			}
			/* we should be a valid user by this point.  Pull the */
			/* user's password structure from the DCE security    */
			/* server just to make sure.  If we get it with no    */
			/* problems, then we really are legitimate...         */
			sec_login_get_pwent(login_context,(sec_login_passwd_t) pwd,&status);
			free(pwd);
			if(check_dce_status(status,"sec_login_get_pwent:"))
				return(0);

			/************************************************************/
			/* if we get to here, then the pwent above properly fetched */
			/* the password structure from the DCE registry, so the user*/
			/*  must be valid.  We don't really care what the user's    */
			/* registry password is, just that the user could be        */
			/* validated.  In fact, if we tried to compare the local    */
			/* password to the DCE entry at this point, the operation   */
			/* would fail if the hidden password feature is turned on,  */
			/* because the password field would contain an asterisk.    */
			/*   Also go ahead and destroy the user's DCE login context */
			/* before we leave here (and don't bother checking the      */
			/* status), in order to clean up credentials files in       */
			/* /opt/dcelocal/var/security/creds.  By doing this, we are */
			/* assuming that the user will not need DCE authentication  */
			/* later in the program, only local authentication.  If this*/
			/* is not true, then the login_context will have to be      */
			/* returned to the calling program, and the context purged  */
			/* somewhere later in the program.                          */
			/************************************************************/
			sec_login_purge_context(&login_context,&status);
			return(1);
		}
		else
		{
			if(check_dce_status(status,"sec_login_validate_identity(2):"))
				return(0);
			sec_login_purge_context(&login_context,&status);
			if(check_dce_status(status,"sec_login_purge_context:"))
				return(0);
		}
	}
	if(check_dce_status(status,"sec_login_setup_identity(2):")) return(0);
	return(0);
}

/* returns 0 for DCE "ok" status, 1 otherwise */
static int check_dce_status(input_status, comment)
error_status_t input_status;
char *comment;
{
	if(input_status == rpc_s_ok) return(0);
	dce_error_inq_text(input_status, error_string, &error_stat);
	fprintf(stderr, "%s %s\n", comment, error_string);
	return(1);
}
#endif /* HAVE_DCE */
