/*
 * supplied by Jeff Earickson, Colby College, Waterville, ME
 * (jaearick@colby.edu)
 *    The code below basically comes from the examples supplied on
 * the OSF DCE 1.0.3 manpages for the sec_login routines, with 
 * enough additional polishing to make the routine work with the
 * reset of sudo.  
 *   This code is known to work on HP 700 and 800 series systems
 * running HP-UX 10.0, with HP's version 1.2.1 of DCE.
 *
 * Use at your own risk!!!  (But I would like to hear about bugs.)
 */

#include "config.h"

#ifdef HAVE_DCE

#include <stdio.h>
#include <pwd.h>
#include <sys/time.h>
#include <dce/rpc.h>
#include <dce/sec_login.h>
#include <dce/dce_error.h> /* required to call dce_error_inq_text routine   */

static int            error_stat;
static unsigned char  error_string[dce_c_error_string_len];
int check(error_status_t input_status, char *comment);
void exit();

int dce_pwent(char *username, char *plain_pw)
/* returns 1 ("true") if user is a valid DCE principal, 0 otherwise */
{
	struct passwd		*pwd;
	sec_passwd_rec_t	password_rec;
	sec_login_handle_t	login_context;
	boolean32			reset_passwd;
	sec_login_auth_src_t	auth_src;
	error_status_t		status;
	unsigned32			nbytes;

	if(sec_login_setup_identity((unsigned_char_p_t) username,
		sec_login_no_flags,&login_context,&status))
	{
		if(check(status,"sec_login_setup_identity(1):")) return(0);

		password_rec.key.key_type = sec_passwd_plain;
		password_rec.key.tagged_union.plain = (idl_char *) plain_pw;

		if(sec_login_validate_identity(login_context,&password_rec,
			&reset_passwd,&auth_src,&status))
		{
			if(check(status,"sec_login_validate_identity(1):")) return(0);

			if(!sec_login_certify_identity(login_context,&status))
			{
				fprintf(stderr,"Whoa! Bogus authentication server!\n");
				(void) check(status,"sec_login_certify_identity(1):"); 
				return(0);
			}
			if(check(status,"sec_login_certify_identity(2):")) return(0);

			sec_login_set_context(login_context,&status);
			if(check(status,"sec_login_set_context:")) return(0);

			if(auth_src != sec_login_auth_src_network)
			{
				fprintf(stderr,"You have no network credentials\n");
				return(0);
			}
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
				return(0);;
			}
			sec_login_get_pwent(login_context,&pwd,&status);
			free(pwd);
			if(check(status,"sec_login_get_pwent:")) return(0);

			/* if we get to here, then the pwent above */
			/* properly fetched the password structure */
			/* from the DCE registry, so the user must */
			/* be valid.  We don't really care what    */
			/* the user's registry password is, just   */
			/* that the user could be validated....    */
			return(1);
		}
		else
		{
			if(check(status,"sec_login_validate_identity(2):")) return(0);
			sec_login_purge_context(&login_context,&status);
			if(check(status,"sec_login_purge_context:")) return(0);
		}
	}
	if(check(status,"sec_login_setup_identity(2):")) return(0);
	return(0);
}

int check(error_status_t input_status, char *comment) 
/* returns 1 (aka, true) for DCE "ok" status, 0 otherwise */
{ 
	if(input_status == rpc_s_ok) return(0);
	dce_error_inq_text(input_status, error_string, &error_stat); 
	fprintf(stderr, "%s %s\n", comment, error_string); 
	return(1);
}

#endif	/* HAVE_DCE */
