/*
 * Copyright (c) 1999-2005, 2007-2013 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <errno.h>

#ifdef HAVE_PAM_PAM_APPL_H
# include <pam/pam_appl.h>
#else
# include <security/pam_appl.h>
#endif

#ifdef HAVE_LIBINTL_H
# if defined(__LINUX_PAM__)
#  define PAM_TEXT_DOMAIN	"Linux-PAM"
# elif defined(__sun__)
#  define PAM_TEXT_DOMAIN	"SUNW_OST_SYSOSPAM"
# endif
#endif

/* We don't want to translate the strings in the calls to dgt(). */
#ifdef PAM_TEXT_DOMAIN
# define dgt(d, t)	dgettext(d, t)
#endif

#include "sudoers.h"
#include "sudo_auth.h"

/* Only OpenPAM and Linux PAM use const qualifiers. */
#if defined(_OPENPAM) || defined(OPENPAM_VERSION) || \
    defined(__LIBPAM_VERSION) || defined(__LINUX_PAM__)
# define PAM_CONST	const
#else
# define PAM_CONST
#endif

#ifndef PAM_DATA_SILENT
#define PAM_DATA_SILENT	0
#endif

static int converse(int, PAM_CONST struct pam_message **,
		    struct pam_response **, void *);
static char *def_prompt = "Password:";
static int getpass_error;
static pam_handle_t *pamh;

int
sudo_pam_init(struct passwd *pw, sudo_auth *auth)
{
    static struct pam_conv pam_conv;
    static int pam_status;
    debug_decl(sudo_pam_init, SUDO_DEBUG_AUTH)

    /* Initial PAM setup */
    auth->data = (void *) &pam_status;
    pam_conv.conv = converse;
    pam_status = pam_start(ISSET(sudo_mode, MODE_LOGIN_SHELL) ?
	def_pam_login_service : def_pam_service, pw->pw_name, &pam_conv, &pamh);
    if (pam_status != PAM_SUCCESS) {
	log_warning(USE_ERRNO|NO_MAIL, N_("unable to initialize PAM"));
	debug_return_int(AUTH_FATAL);
    }

    /*
     * Set PAM_RUSER to the invoking user (the "from" user).
     * We set PAM_RHOST to avoid a bug in Solaris 7 and below.
     */
    (void) pam_set_item(pamh, PAM_RUSER, user_name);
#ifdef __sun__
    (void) pam_set_item(pamh, PAM_RHOST, user_host);
#endif

    /*
     * Some versions of pam_lastlog have a bug that
     * will cause a crash if PAM_TTY is not set so if
     * there is no tty, set PAM_TTY to the empty string.
     */
    if (user_ttypath == NULL)
	(void) pam_set_item(pamh, PAM_TTY, "");
    else
	(void) pam_set_item(pamh, PAM_TTY, user_ttypath);

    /*
     * If PAM session and setcred support is disabled we don't
     * need to keep a sudo process around to close the session.
     */
    if (!def_pam_session && !def_pam_setcred)
	auth->end_session = NULL;

    debug_return_int(AUTH_SUCCESS);
}

int
sudo_pam_verify(struct passwd *pw, char *prompt, sudo_auth *auth)
{
    const char *s;
    int *pam_status = (int *) auth->data;
    debug_decl(sudo_pam_verify, SUDO_DEBUG_AUTH)

    def_prompt = prompt;	/* for converse */

    /* PAM_SILENT prevents the authentication service from generating output. */
    *pam_status = pam_authenticate(pamh, PAM_SILENT);
    switch (*pam_status) {
	case PAM_SUCCESS:
	    *pam_status = pam_acct_mgmt(pamh, PAM_SILENT);
	    switch (*pam_status) {
		case PAM_SUCCESS:
		    debug_return_int(AUTH_SUCCESS);
		case PAM_AUTH_ERR:
		    log_warning(NO_MAIL, N_("account validation failure, "
			"is your account locked?"));
		    debug_return_int(AUTH_FATAL);
		case PAM_NEW_AUTHTOK_REQD:
		    log_warning(NO_MAIL, N_("Account or password is "
			"expired, reset your password and try again"));
		    *pam_status = pam_chauthtok(pamh,
			PAM_CHANGE_EXPIRED_AUTHTOK);
		    if (*pam_status == PAM_SUCCESS)
			debug_return_int(AUTH_SUCCESS);
		    if ((s = pam_strerror(pamh, *pam_status)) != NULL) {
			log_warning(NO_MAIL,
			    N_("unable to change expired password: %s"), s);
		    }
		    debug_return_int(AUTH_FAILURE);
		case PAM_AUTHTOK_EXPIRED:
		    log_warning(NO_MAIL,
			N_("Password expired, contact your system administrator"));
		    debug_return_int(AUTH_FATAL);
		case PAM_ACCT_EXPIRED:
		    log_warning(NO_MAIL,
			N_("Account expired or PAM config lacks an \"account\" "
			"section for sudo, contact your system administrator"));
		    debug_return_int(AUTH_FATAL);
	    }
	    /* FALLTHROUGH */
	case PAM_AUTH_ERR:
	case PAM_AUTHINFO_UNAVAIL:
	    if (getpass_error) {
		/* error or ^C from tgetpass() */
		debug_return_int(AUTH_INTR);
	    }
	    /* FALLTHROUGH */
	case PAM_MAXTRIES:
	case PAM_PERM_DENIED:
	    debug_return_int(AUTH_FAILURE);
	default:
	    if ((s = pam_strerror(pamh, *pam_status)) != NULL)
		log_warning(NO_MAIL, N_("PAM authentication error: %s"), s);
	    debug_return_int(AUTH_FATAL);
    }
}

int
sudo_pam_cleanup(struct passwd *pw, sudo_auth *auth)
{
    int *pam_status = (int *) auth->data;
    debug_decl(sudo_pam_cleanup, SUDO_DEBUG_AUTH)

    /* If successful, we can't close the session until sudo_pam_end_session() */
    if (*pam_status != PAM_SUCCESS || auth->end_session == NULL) {
	*pam_status = pam_end(pamh, *pam_status | PAM_DATA_SILENT);
	pamh = NULL;
    }
    debug_return_int(*pam_status == PAM_SUCCESS ? AUTH_SUCCESS : AUTH_FAILURE);
}

int
sudo_pam_begin_session(struct passwd *pw, char **user_envp[], sudo_auth *auth)
{
    int status = AUTH_SUCCESS;
    int *pam_status = (int *) auth->data;
    debug_decl(sudo_pam_begin_session, SUDO_DEBUG_AUTH)

    /*
     * If there is no valid user we cannot open a PAM session.
     * This is not an error as sudo can run commands with arbitrary
     * uids, it just means we are done from a session management standpoint.
     */
    if (pw == NULL) {
	if (pamh != NULL) {
	    (void) pam_end(pamh, PAM_SUCCESS | PAM_DATA_SILENT);
	    pamh = NULL;
	}
	goto done;
    }

    /*
     * Update PAM_USER to reference the user we are running the command
     * as, as opposed to the user we authenticated as.
     */
    (void) pam_set_item(pamh, PAM_USER, pw->pw_name);

    /*
     * Reinitialize credentials when changing the user.
     * We don't worry about a failure from pam_setcred() since with
     * stacked PAM auth modules a failure from one module may override
     * PAM_SUCCESS from another.  For example, given a non-local user,
     * pam_unix will fail but pam_ldap or pam_sss may succeed, but if
     * pam_unix is first in the stack, pam_setcred() will fail.
     */
    if (def_pam_setcred)
	(void) pam_setcred(pamh, PAM_REINITIALIZE_CRED);

    if (def_pam_session) {
	*pam_status = pam_open_session(pamh, 0);
	if (*pam_status != PAM_SUCCESS) {
	    (void) pam_end(pamh, *pam_status | PAM_DATA_SILENT);
	    pamh = NULL;
	    status = AUTH_FAILURE;
	    goto done;
	}
    }

#ifdef HAVE_PAM_GETENVLIST
    /*
     * Update environment based on what is stored in pamh.
     * If no authentication is done we will only have environment
     * variables if pam_env is called via session.
     */
    if (user_envp != NULL) {
	char **pam_envp = pam_getenvlist(pamh);
	if (pam_envp != NULL) {
	    /* Merge pam env with user env. */
	    env_init(*user_envp);
	    env_merge(pam_envp);
	    *user_envp = env_get();
	    env_init(NULL);
	    efree(pam_envp);
	    /* XXX - we leak any duplicates that were in pam_envp */
	}
    }
#endif /* HAVE_PAM_GETENVLIST */

done:
    debug_return_int(status);
}

int
sudo_pam_end_session(struct passwd *pw, sudo_auth *auth)
{
    int status = AUTH_SUCCESS;
    debug_decl(sudo_pam_end_session, SUDO_DEBUG_AUTH)

    if (pamh != NULL) {
	/*
	 * Update PAM_USER to reference the user we are running the command
	 * as, as opposed to the user we authenticated as.
	 * XXX - still needed now that session init is in parent?
	 */
	(void) pam_set_item(pamh, PAM_USER, pw->pw_name);
	if (def_pam_session)
	    (void) pam_close_session(pamh, PAM_SILENT);
	if (def_pam_setcred)
	    (void) pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);
	if (pam_end(pamh, PAM_SUCCESS | PAM_DATA_SILENT) != PAM_SUCCESS)
	    status = AUTH_FAILURE;
	pamh = NULL;
    }

    debug_return_int(status);
}

/*
 * ``Conversation function'' for PAM.
 * XXX - does not handle PAM_BINARY_PROMPT
 */
static int
converse(int num_msg, PAM_CONST struct pam_message **msg,
    struct pam_response **response, void *appdata_ptr)
{
    struct pam_response *pr;
    PAM_CONST struct pam_message *pm;
    const char *prompt;
    char *pass;
    int n, type, std_prompt;
    int ret = PAM_AUTH_ERR;
    debug_decl(converse, SUDO_DEBUG_AUTH)

    if ((*response = malloc(num_msg * sizeof(struct pam_response))) == NULL)
	debug_return_int(PAM_SYSTEM_ERR);
    memset(*response, 0, num_msg * sizeof(struct pam_response));

    for (pr = *response, pm = *msg, n = num_msg; n--; pr++, pm++) {
	type = SUDO_CONV_PROMPT_ECHO_OFF;
	switch (pm->msg_style) {
	    case PAM_PROMPT_ECHO_ON:
		type = SUDO_CONV_PROMPT_ECHO_ON;
		/* FALLTHROUGH */
	    case PAM_PROMPT_ECHO_OFF:
		prompt = def_prompt;

		/* Error out if the last password read was interrupted. */
		if (getpass_error)
		    goto done;

		/* Is the sudo prompt standard? (If so, we'll just use PAM's) */
		std_prompt =  strncmp(def_prompt, "Password:", 9) == 0 &&
		    (def_prompt[9] == '\0' ||
		    (def_prompt[9] == ' ' && def_prompt[10] == '\0'));

		/* Only override PAM prompt if it matches /^Password: ?/ */
#if defined(PAM_TEXT_DOMAIN) && defined(HAVE_LIBINTL_H)
		if (!def_passprompt_override && (std_prompt ||
		    (strcmp(pm->msg, dgt(PAM_TEXT_DOMAIN, "Password: ")) &&
		    strcmp(pm->msg, dgt(PAM_TEXT_DOMAIN, "Password:")))))
		    prompt = pm->msg;
#else
		if (!def_passprompt_override && (std_prompt ||
		    strncmp(pm->msg, "Password:", 9) || (pm->msg[9] != '\0'
		    && (pm->msg[9] != ' ' || pm->msg[10] != '\0'))))
		    prompt = pm->msg;
#endif
		/* Read the password unless interrupted. */
		pass = auth_getpass(prompt, def_passwd_timeout * 60, type);
		if (pass == NULL) {
		    /* Error (or ^C) reading password, don't try again. */
		    getpass_error = 1;
#if (defined(__darwin__) || defined(__APPLE__)) && !defined(OPENPAM_VERSION)
		    pass = "";
#else
		    goto done;
#endif
		}
		pr->resp = estrdup(pass);
		memset_s(pass, SUDO_CONV_REPL_MAX, 0, strlen(pass));
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
		ret = PAM_CONV_ERR;
		goto done;
	}
    }
    ret = PAM_SUCCESS;

done:
    if (ret != PAM_SUCCESS) {
	/* Zero and free allocated memory and return an error. */
	for (pr = *response, n = num_msg; n--; pr++) {
	    if (pr->resp != NULL) {
		memset_s(pr->resp, SUDO_CONV_REPL_MAX, 0, strlen(pr->resp));
		free(pr->resp);
		pr->resp = NULL;
	    }
	}
	free(*response);
	*response = NULL;
    }
    debug_return_int(ret);
}
