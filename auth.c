/*
 *  CU sudo version 1.6
 *  Copyright (c) 1994,1996,1998,1999 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *  This module contains routines to authenticate a user.
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
#include <fcntl.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_KERB4
#  include <krb.h>
#endif /* HAVE_KERB4 */
#ifdef HAVE_KERB5
#  include <krb5.h>
#endif /* HAVE_KERB5 */
#ifdef HAVE_PAM
#  include <security/pam_appl.h>
#endif /* HAVE_PAM */
#ifdef HAVE_AFS
#  include <afs/stds.h>
#  include <afs/kautils.h>
#endif /* HAVE_AFS */
#ifdef HAVE_SECURID
#  include <sdi_athd.h>
#  include <sdconf.h>
#  include <sdacmvls.h>
#endif /* HAVE_SECURID */
#ifdef HAVE_SKEY
#  include <skey.h>
#endif /* HAVE_SKEY */
#ifdef HAVE_OPIE
#  include <opie.h>
#endif /* HAVE_OPIE */
#ifdef HAVE_AUTHSRV
#  include <firewall.h>
#endif

#include "sudo.h"
#include "insults.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Prototypes for local functions
 */
#ifdef HAVE_KERB4
static int   sudo_krb_validate_user	__P((struct passwd *, char *));
#endif /* HAVE_KERB4 */
#ifdef HAVE_KERB5
static int   sudo_krb5_validate_user	__P((struct passwd *, char *));
static int   verify_krb_v5_tgt		__P((krb5_ccache));
#endif /* HAVE_KERB5 */
#ifdef HAVE_PAM
static int sudo_conv			__P((int,
					     PAM_CONST struct pam_message **,
					     struct pam_response **, void *));
#endif /* HAVE_PAM */
#ifdef HAVE_SKEY
static char *sudo_skeyprompt		__P((struct skey *, char *));
#endif /* HAVE_SKEY */
#ifdef HAVE_OPIE
static char *sudo_opieprompt		__P((struct opie *, char *));
#endif /* HAVE_OPIE */
int   user_is_exempt			__P((void));

/*
 * Globals
 */
#ifdef HAVE_SECURID
union config_record configure;
#endif /* HAVE_SECURID */
#ifdef HAVE_SKEY
struct skey skey;
#endif
#ifdef HAVE_OPIE
struct opie opie;
#endif
#ifdef HAVE_KERB5
extern krb5_context sudo_context;
extern char *realm;
extern int xrealm;
#endif /* HAVE_KERB5 */


/********************************************************************
 *
 *  check_passwd()
 *
 *  This function grabs the user's password and checks with the password
 *  in /etc/passwd (or uses other specified authentication method).
 */

#ifdef HAVE_SECURID
void
check_passwd()
{
    struct SD_CLIENT sd_dat, *sd;		/* SecurID data block */
    register int counter = TRIES_FOR_PASSWORD;

    (void) memset((VOID *)&sd_dat, 0, sizeof(sd_dat));
    sd = &sd_dat;

    /* Initialize SecurID. */
    set_perms(PERM_ROOT, 0);
    creadcfg();
    if (sd_init(sd) != 0) {
	(void) fprintf(stderr, "%s: Cannot contact SecurID server\n", Argv[0]);
	exit(1);
    }

    /* You get TRIES_FOR_PASSWORD times to guess your password */
    while (counter > 0) {
	if (sd_auth(sd) == ACM_OK) {
	    set_perms(PERM_USER, 0);
	    return;
	}

	--counter;		/* otherwise, try again  */
	pass_warn(stderr);
    }
    set_perms(PERM_USER, 0);

    log_error(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
    inform_user(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
    exit(1);
}
#else /* !HAVE_SECURID */
#ifdef HAVE_AUTHSRV
void
check_passwd()
{
    char *pass;			/* this is what gets entered */
    Cfg *confp;

    char        cbuf[128];
    char        ubuf[128], buf[128];
    register int counter = TRIES_FOR_PASSWORD;

    if ((confp = cfg_read("sudo")) == (Cfg *)-1) {
	fprintf(stderr, "Cannot read config.\n");
	exit(1);
    }

    /* Initialize Auth Client */
    auth_open(confp);

    /* get welcome message from auth server */
    if (auth_recv(buf, sizeof(buf))) {
	sprintf(buf, "Lost connection to server");
	fprintf(stderr, "%s\n", buf);
	exit(1);
    }

    if (strncmp(buf, "Authsrv ready", 13)) {
	fprintf(stderr, "Auth server error %s\n", buf);
	auth_close();
	exit(1);
    }

    /* You get TRIES_FOR_PASSWORD times to guess your password */
    while (counter > 0) {

	sprintf(cbuf,"authorize	%s	sudo",user_name);

	auth_send(cbuf);
	auth_recv(cbuf,sizeof(cbuf));

	if (!strncmp(cbuf, "challenge ", 10)) {
	    sprintf(buf, "Challenge \"%s\": ", &cbuf[10]);
	    pass = GETPASS(buf, PASSWORD_TIMEOUT * 60, 1);
	} else if (!strncmp(cbuf, "password", 8)) {
	    pass = GETPASS(buf, PASSWORD_TIMEOUT * 60, 1);
	} else {
	    fprintf(stderr, "Server sent %s\n", cbuf);
	    auth_close();
	    exit(1);
	}

	sprintf(cbuf, "response '%s'", pass);
	auth_send(cbuf);
	auth_recv(cbuf, sizeof(cbuf));

	if (!strncmp(cbuf, "ok", 2)) {
	    /* Success */
	    /*inform_user(cbuf);*/
	    set_perms(PERM_USER, 0);
	    auth_close();
	    return;
	} else {
	    fprintf(stderr, "Server returned %s\n", cbuf);
	}
	pass_warn(stderr);
	--counter;		/* otherwise, try again  */
    }

    set_perms(PERM_USER, 0);

    auth_close();

    log_error(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
    inform_user(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
    exit(1);
}

#else /* !HAVE_AUTHSRV */

void
check_passwd()
{
    char *pass;			/* this is what gets entered */
    int counter = TRIES_FOR_PASSWORD;
#if defined(HAVE_KERB4) && defined(USE_GETPASS)
    char kpass[SUDO_PASS_MAX + 1];
#endif /* HAVE_KERB4 && USE_GETPASS */
#ifdef HAVE_AUTHENTICATE
    char *message;
    int reenter;
#endif /* HAVE_AUTHENTICATE */

#ifdef HAVE_SKEY
    (void) memset((VOID *)&skey, 0, sizeof(skey));
#endif /* HAVE_SKEY */
#ifdef HAVE_OPIE
    (void) memset((VOID *)&opie, 0, sizeof(opie));
#endif /* HAVE_OPIE */

    /* You get TRIES_FOR_PASSWORD times to guess your password */
    while (counter > 0) {

#ifdef HAVE_AUTHENTICATE
	/* use AIX authenticate() function */
	pass = GETPASS(prompt, PASSWORD_TIMEOUT * 60, 1);
	reenter = 1;
	if (authenticate(user_name, pass, &reenter, &message) == 0)
	    return;		/* valid password */
#else /* HAVE_AUTHENTICATE */
#  ifdef HAVE_SKEY
	/* rewrite the prompt if using s/key since the challenge can change */
	set_perms(PERM_ROOT, 0);
	prompt = sudo_skeyprompt(&skey, prompt);
	set_perms(PERM_USER, 0);
#  endif /* HAVE_SKEY */
#  ifdef HAVE_OPIE
	/* rewrite the prompt if using OPIE since the challenge can change */
	set_perms(PERM_ROOT, 0);
	prompt = sudo_opieprompt(&opie, prompt);
	set_perms(PERM_USER, 0);
#  endif /* HAVE_OPIE */

	/* get a password from the user */
#  if defined(HAVE_KERB4) && defined(USE_GETPASS)
	(void) des_read_pw_string(kpass, sizeof(kpass) - 1, prompt, 0);
	pass = kpass;
#  else
	pass = (char *) GETPASS(prompt, PASSWORD_TIMEOUT * 60, 1);
#  endif /* HAVE_KERB4 */

#  ifdef HAVE_SKEY
	/* Only check s/key db if the user exists there */
	if (skey.keyfile) {
	    set_perms(PERM_ROOT, 0);
	    if (skeyverify(&skey, pass) == 0) {
		set_perms(PERM_USER, 0);
		return;             /* if the key is correct return() */
	    }
	    set_perms(PERM_USER, 0);
	}
#  endif /* HAVE_SKEY */
#  ifdef HAVE_OPIE
	/* Only check OPIE db if the user exists there */
	if (opie.opie_flags) {
	    set_perms(PERM_ROOT, 0);
	    if (opieverify(&opie, pass) == 0) {
		set_perms(PERM_USER, 0);
		return;             /* if the key is correct return() */
	    }
	    set_perms(PERM_USER, 0);
	}
#  endif /* HAVE_OPIE */
#  if !defined(OTP_ONLY) || (!defined(HAVE_SKEY) && !defined(HAVE_OPIE))
	/*
	 * If we use shadow passwords with a different crypt(3)
	 * check that here, else use standard crypt(3).
	 */
#    ifdef HAVE_GETAUTHUID
	if (!strcmp(user_passwd, (char *) crypt16(pass, user_passwd)))
	    return;		/* if the passwd is correct return() */
#    endif /* HAVE_GETAUTHUID */

#    ifdef HAVE_GETPRPWNAM
	if (check_secureware(pass))
	    return;		/* if the passwd is correct return() */
#    endif /* HAVE_HAVE_GETPRPWNAM */

	/* Normal UN*X password check */
	if (!strcmp(user_passwd, (char *) crypt(pass, user_passwd)))
	    return;		/* if the passwd is correct return() */

#    ifdef HAVE_KERB4
	if (user_uid && sudo_krb_validate_user(user_pw_ent, pass) == 0)
	    return;
#    endif /* HAVE_KERB4 */

#    ifdef HAVE_KERB5
	if (sudo_krb5_validate_user(user_pw_ent, pass) == 0)
	    return;
#    endif /* HAVE_KERB5 */

#    ifdef HAVE_AFS
	if (ka_UserAuthenticateGeneral(KA_USERAUTH_VERSION,
                                       user_name,	/* name */
                                       NULL,		/* instance */
                                       NULL,		/* realm */
                                       pass,		/* password */
                                       0,		/* lifetime */
                                       0, 0,		/* spare */
                                       NULL) == 0)	/* reason */
	    return;
#    endif /* HAVE_AFS */
#    ifdef HAVE_DCE
	/* 
	 * consult the DCE registry for password validation
	 * note that dce_pwent trashes pass upon return...
	 */
	if (dce_pwent(user_name, pass))
	    return;
#    endif /* HAVE_DCE */
#  endif /* !OTP_ONLY || (!HAVE_SKEY && !HAVE_OPIE) */
#endif /* HAVE_AUTHENTICATE */

	/* Exit loop on nil password, but give it a chance to match first. */
	if (!pass || *pass == '\0') {
	    if (counter == TRIES_FOR_PASSWORD)
		exit(1);
	    else
		break;
	}

	--counter;		/* otherwise, try again  */
	pass_warn(stderr);
    }

    log_error(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
    inform_user(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
    exit(1);
}
#endif /* HAVE_AUTHSRV */
#endif /* HAVE_SECURID */


#ifdef HAVE_KERB4
/********************************************************************
 *
 *  sudo_krb_validate_user()
 *
 *  Validate a user via kerberos.
 */
static int
sudo_krb_validate_user(pw, pass)
    struct passwd *pw;
    char *pass;
{
    char realm[REALM_SZ];
    char tkfile[sizeof(_PATH_SUDO_TIMEDIR) + 4 + MAX_UID_T_LEN];
    int k_errno;

    /* Get the local realm, or retrun failure (no krb.conf) */
    if (krb_get_lrealm(realm, 1) != KSUCCESS)
	return(-1);

    /*
     * Set the ticket file to be in sudo sudo timedir so we don't
     * wipe out other kerberos tickets.
     */
    (void) sprintf(tkfile, "%s/tkt%ld", _PATH_SUDO_TIMEDIR,
		   (long) pw->pw_uid);
    (void) krb_set_tkt_string(tkfile);

    /*
     * Update the ticket if password is ok.  Kerb4 expects
     * the ruid and euid to be the same here so we setuid to root.
     */
    set_perms(PERM_ROOT, 0);
    k_errno = krb_get_pw_in_tkt(pw->pw_name, "", realm, "krbtgt", realm,
	DEFAULT_TKT_LIFE, pass);

    /*
     * If we authenticated, destroy the ticket now that we are done with it.
     * If not, warn on a "real" error.
     */
    if (k_errno == INTK_OK)
	dest_tkt();
    else if (k_errno != INTK_BADPW && k_errno != KDC_PR_UNKNOWN)
	(void) fprintf(stderr, "Warning: Kerberos error: %s\n",
		       krb_err_txt[k_errno]);

    /* done with rootly stuff */
    set_perms(PERM_USER, 0);

    return(!(k_errno == INTK_OK));
}
#endif /* HAVE_KERB4 */


#ifdef HAVE_KERB5
/********************************************************************
 *
 *  sudo_krb5_validate_user()
 *
 *  Validate a user via Kerberos 5. We may lose a bit of memory, but it's
 *  OK since we're a short lived program. I'd rather do that than contort
 *  the code to handle the cleanup.
 */
static int
sudo_krb5_validate_user(pw, pass)
    struct passwd *pw;
    char *pass;
{
    krb5_error_code	retval;
    krb5_principal	princ;
    krb5_creds		creds;
    krb5_ccache		ccache;
    char		cache_name[64];
    char		*princ_name;
    krb5_get_init_creds_opt opts;

    /* Initialize */
    if (!sudo_context)
	return -1;
    krb5_get_init_creds_opt_init(&opts);

    princ_name = emalloc(strlen(pw->pw_name) + strlen(realm) + 2);

    (void) sprintf(princ_name, "%s@%s", pw->pw_name, realm);
    if (retval = krb5_parse_name(sudo_context, princ_name, &princ))
	return retval;

    /* Set the ticket file to be in /tmp so we don't need to change perms. */
    (void) sprintf(cache_name, "FILE:/tmp/sudocc_%ld", getpid());
    if (retval = krb5_cc_resolve(sudo_context, cache_name, &ccache))
	return retval;

    if (retval = krb5_get_init_creds_password(sudo_context, &creds, princ,
					      pass, krb5_prompter_posix, NULL,	
					      0, NULL, &opts))
	return retval;

    /* Stash the TGT so we can verify it. */
    if (retval = krb5_cc_initialize(sudo_context, ccache, princ))
	return retval;
    if (retval = krb5_cc_store_cred(sudo_context, ccache, &creds)) {
	(void) krb5_cc_destroy(sudo_context, ccache);
	return retval;
    }

    retval = verify_krb_v5_tgt(ccache);
    (void) krb5_cc_destroy(sudo_context, ccache);
    return (retval == -1);
}


/*
 * This routine with some modification is from the MIT V5B6 appl/bsd/login.c
 *
 * Verify the Kerberos ticket-granting ticket just retrieved for the
 * user.  If the Kerberos server doesn't respond, assume the user is
 * trying to fake us out (since we DID just get a TGT from what is
 * supposedly our KDC).  If the host/<host> service is unknown (i.e.,
 * the local keytab doesn't have it), let her in.
 *
 * Returns 1 for confirmation, -1 for failure, 0 for uncertainty.
 */
static int
verify_krb_v5_tgt(ccache)
    krb5_ccache		ccache;
{
    char		phost[BUFSIZ];
    krb5_error_code	retval;
    krb5_principal	princ;
    krb5_keyblock *	keyblock = 0;
    krb5_data		packet;
    krb5_auth_context	auth_context = NULL;

    packet.data = 0;

    /*
     * Get the server principal for the local host.
     * (Use defaults of "host" and canonicalized local name.)
     */
    if (krb5_sname_to_principal(sudo_context, NULL, NULL,
				KRB5_NT_SRV_HST, &princ))
	return -1;

    /* Extract the name directly. */
    strncpy(phost, krb5_princ_component(c, princ, 1)->data, BUFSIZ);
    phost[BUFSIZ - 1] = '\0';

    /*
     * Do we have host/<host> keys?
     * (use default keytab, kvno IGNORE_VNO to get the first match,
     * and enctype is currently ignored anyhow.)
     */
    if (retval = krb5_kt_read_service_key(sudo_context, NULL, princ, 0,
					  ENCTYPE_DES_CBC_MD5, &keyblock)) {
	/* Keytab or service key does not exist */
	if (xrealm)
	    retval = -1;
	else
	    retval = 0;
	goto cleanup;
    }
    if (keyblock)
	krb5_free_keyblock(sudo_context, keyblock);

    /* Talk to the kdc and construct the ticket. */
    retval = krb5_mk_req(sudo_context, &auth_context, 0, "host", phost,
			 NULL, ccache, &packet);
    if (auth_context) {
	krb5_auth_con_free(sudo_context, auth_context);
	auth_context = NULL; /* setup for rd_req */
    }
    if (retval) {
	retval = -1;
	goto cleanup;
    }

    /* Try to use the ticket. */
    retval = krb5_rd_req(sudo_context, &auth_context, &packet, princ,
			 NULL, NULL, NULL);
    if (retval) {
	retval = -1;
    } else {
	retval = 1;
    }

cleanup:
    if (packet.data)
	krb5_free_data_contents(sudo_context, &packet);
    krb5_free_principal(sudo_context, princ);
    return retval;

}
#endif /* HAVE_KERB5 */


#ifdef HAVE_PAM
/********************************************************************
 *  pam_attempt_auth()
 *
 *  Try to authenticate the user using Pluggable Authentication
 *  Modules (PAM).
 */
void
pam_attempt_auth()
{
    int counter = TRIES_FOR_PASSWORD;
    int null_pw = 0;
    static struct pam_conv pam_conv;
    static pam_handle_t *pamh;

    set_perms(PERM_ROOT, 0);

    /* Initial PAM setup + use our default prompt */
    pam_conv.conv = sudo_conv;
    pam_conv.appdata_ptr = &null_pw;
    if (pam_start("sudo", user_name, &pam_conv, &pamh) != PAM_SUCCESS ||
	pam_set_item(pamh, PAM_USER_PROMPT, (void *) prompt) != PAM_SUCCESS) {
	set_perms(PERM_USER, 0);
	log_error(BAD_AUTH_INIT);
	inform_user(BAD_AUTH_INIT);
	exit(1);
    }

    /* You get TRIES_FOR_PASSWORD times to guess your password */
    while (counter > 0) {

	/* PAM_SILENT prevents error messages from going to syslog(3) */
	if (pam_authenticate(pamh, PAM_SILENT) == PAM_SUCCESS) {
	    pam_end(pamh, PAM_SUCCESS);
            set_perms(PERM_USER, 0);
            return;
        }
	if (null_pw)
	    break;

	--counter;		/* otherwise, try again  */
        pass_warn(stderr);
    }
    pam_end(pamh, 0);
    set_perms(PERM_USER, 0);

    log_error(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
    inform_user(counter ? PASSWORD_NOT_CORRECT : PASSWORDS_NOT_CORRECT);
    exit(1);
}


/********************************************************************
 *  sudo_conv()
 *
 *  ``Conversation function'' for PAM.
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
    int echo = 0;

    if ((*response = malloc(num_msg * sizeof(struct pam_response))) == NULL)
	return(PAM_CONV_ERR);
    (void) memset((VOID *)*response, 0, num_msg * sizeof(struct pam_response));

    for (pr = *response, pm = *msg; num_msg--; pr++, pm++) {
	switch (pm->msg_style) {
	    case PAM_PROMPT_ECHO_ON:
		echo = 1;
	    case PAM_PROMPT_ECHO_OFF:
		pr->resp = estrdup((char *) GETPASS(pm->msg,
		    PASSWORD_TIMEOUT * 60, !echo));
		/* Solaris PAM does not pass through appdata_ptr! */
		if (pr->resp[0] == '\0' && appdata_ptr != NULL)
		    *((int *) appdata_ptr) = 1;	/* indicate an empty password */
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
#endif /* HAVE_PAM */


#ifdef HAVE_SKEY
/********************************************************************
 *
 *  sudo_skeyprompt()
 *
 *  This function rewrites and return the prompt based the
 *  s/key challenge *  and fills in the user's skey structure.
 */

static char *
sudo_skeyprompt(user_skey, p)
    struct skey *user_skey;
    char *p;
{
    char challenge[256];
    int rval;
    static char *orig_prompt = NULL, *new_prompt = NULL;
    static int op_len, np_size;

    /* save the original prompt */
    if (orig_prompt == NULL) {
	orig_prompt = p;
	op_len = strlen(p);

	/* ignore trailing colon */
	if (p[op_len - 1] == ':')
	    op_len--;
    }

    /* close old stream */
    if (user_skey->keyfile)
	(void) fclose(user_skey->keyfile);

    /* get the skey part of the prompt */
    if ((rval = skeychallenge(user_skey, user_name, challenge)) != 0) {
#ifdef OTP_ONLY
	(void) fprintf(stderr,
		       "%s: You do not exist in the s/key database.\n",
		       Argv[0]);
	exit(1);
#else
	/* return the original prompt if we cannot get s/key info */
	return(orig_prompt);
#endif /* OTP_ONLY */
    }

    /* get space for new prompt with embedded s/key challenge */
    if (new_prompt == NULL) {
	/* allocate space for new prompt */
	np_size = op_len + strlen(challenge) + 7;
	new_prompt = (char *) emalloc(np_size);
    } else {
	/* already have space allocated, is it enough? */
	if (np_size < op_len + strlen(challenge) + 7) {
	    np_size = op_len + strlen(challenge) + 7;
	    new_prompt = (char *) erealloc(new_prompt, np_size);
	}
    }

    /* embed the s/key challenge into the new password prompt */
#ifdef LONG_OTP_PROMPT
    (void) sprintf(new_prompt, "%s\n%s", challenge, orig_prompt);
#else
    (void) sprintf(new_prompt, "%.*s [ %s ]:", op_len, orig_prompt, challenge);
#endif /* LONG_OTP_PROMPT */

    return(new_prompt);
}
#endif /* HAVE_SKEY */


#ifdef HAVE_OPIE
/********************************************************************
 *
 *  sudo_opieprompt()
 *
 *  This function rewrites and return the prompt based the
 *  OPIE challenge *  and fills in the user's opie structure.
 */

static char *
sudo_opieprompt(user_opie, p)
    struct opie *user_opie;
    char *p;
{
    char challenge[OPIE_CHALLENGE_MAX];
    int rval;
    static char *orig_prompt = NULL, *new_prompt = NULL;
    static int op_len, np_size;

    /* save the original prompt */
    if (orig_prompt == NULL) {
	orig_prompt = p;
	op_len = strlen(p);

	/* ignore trailing colon */
	if (p[op_len - 1] == ':')
	    op_len--;
    }

    /* get the opie part of the prompt */
    if ((rval = opiechallenge(user_opie, user_name, challenge)) != 0) {
#ifdef OTP_ONLY
	(void) fprintf(stderr,
		       "%s: You do not exist in the opie database.\n",
		       Argv[0]);
	exit(1);
#else
	/* return the original prompt if we cannot get opie info */
	return(orig_prompt);
#endif /* OTP_ONLY */
    }

    /* get space for new prompt with embedded opie challenge */
    if (new_prompt == NULL) {
	/* allocate space for new prompt */
	np_size = op_len + strlen(challenge) + 7;
	new_prompt = (char *) emalloc(np_size);
    } else {
	/* already have space allocated, is it enough? */
	if (np_size < op_len + strlen(challenge) + 7) {
	    np_size = op_len + strlen(challenge) + 7;
	    new_prompt = (char *) erealloc(new_prompt, np_size);
	}
    }

    /* embed the s/key challenge into the new password prompt */
#ifdef LONG_OTP_PROMPT
    (void) sprintf(new_prompt, "%s\n%s", challenge, orig_prompt);
#else
    (void) sprintf(new_prompt, "%.*s [ %s ]:", op_len, orig_prompt, challenge);
#endif /* LONG_OTP_PROMPT */

    return(new_prompt);
}
#endif /* HAVE_OPIE */


/********************************************************************
 *
 *  pass_warn()
 *
 *  warn the user that the password was incorrect
 *  (and insult them if insults are configured).
 */

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
