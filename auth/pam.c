/*
 * Copyright (c) 1999-2005, 2007-2011 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
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

#ifdef HAVE_DGETTEXT
# include <libintl.h>
# if defined(__LINUX_PAM__)
#  define PAM_TEXT_DOMAIN	"Linux-PAM"
# elif defined(__sun__)
#  define PAM_TEXT_DOMAIN	"SUNW_OST_SYSOSPAM"
# endif
#endif

#include "sudo.h"
#include "sudo_auth.h"

/* Only OpenPAM and Linux PAM use const qualifiers. */
#if defined(_OPENPAM) || defined(OPENPAM_VERSION) || \
    defined(__LIBPAM_VERSION) || defined(__LINUX_PAM__)
# define PAM_CONST	const
#else
# define PAM_CONST
#endif

static int sudo_conv __P((int, PAM_CONST struct pam_message **,
			  struct pam_response **, void *));
static char *def_prompt = "Password:";
static int getpass_error;

#ifndef PAM_DATA_SILENT
#define PAM_DATA_SILENT	0
#endif

static pam_handle_t *pamh;

int
pam_init(pw, auth)
    struct passwd *pw;
    sudo_auth *auth;
{
    static struct pam_conv pam_conv;
    static int pam_status;

    /* Initial PAM setup */
    if (auth != NULL)
	auth->data = (void *) &pam_status;
    pam_conv.conv = sudo_conv;
#ifdef HAVE_PAM_LOGIN
    if (ISSET(sudo_mode, MODE_LOGIN_SHELL))
	pam_status = pam_start("sudo-i", pw->pw_name, &pam_conv, &pamh);
    else
#endif
	pam_status = pam_start("sudo", pw->pw_name, &pam_conv, &pamh);

    if (pam_status != PAM_SUCCESS) {
	log_error(USE_ERRNO|NO_MAIL, "unable to initialize PAM");
	return AUTH_FATAL;
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

    return AUTH_SUCCESS;
}

int
pam_verify(pw, prompt, auth)
    struct passwd *pw;
    char *prompt;
    sudo_auth *auth;
{
    const char *s;
    int *pam_status = (int *) auth->data;

    def_prompt = prompt;	/* for sudo_conv */

    /* PAM_SILENT prevents the authentication service from generating output. */
    *pam_status = pam_authenticate(pamh, PAM_SILENT);
    switch (*pam_status) {
	case PAM_SUCCESS:
	    *pam_status = pam_acct_mgmt(pamh, PAM_SILENT);
	    switch (*pam_status) {
		case PAM_SUCCESS:
		    return AUTH_SUCCESS;
		case PAM_AUTH_ERR:
		    log_error(NO_MAIL,
			"account validation failure, is your account locked?");
		    return AUTH_FATAL;
		case PAM_NEW_AUTHTOK_REQD:
		    log_error(NO_MAIL, "%s, %s",
			"Account or password is expired",
			"reset your password and try again");
		    *pam_status = pam_chauthtok(pamh,
			PAM_CHANGE_EXPIRED_AUTHTOK);
		    if (*pam_status == PAM_SUCCESS)
			return AUTH_SUCCESS;
		    if ((s = pam_strerror(pamh, *pam_status)))
			log_error(NO_MAIL, "pam_chauthtok: %s", s);
		    return AUTH_FAILURE;
		case PAM_AUTHTOK_EXPIRED:
		    log_error(NO_MAIL,
			"Password expired, contact your system administrator");
		    return AUTH_FATAL;
		case PAM_ACCT_EXPIRED:
		    log_error(NO_MAIL, "%s %s",
			"Account expired or PAM config lacks an \"account\"",
			"section for sudo, contact your system administrator");
		    return AUTH_FATAL;
	    }
	    /* FALLTHROUGH */
	case PAM_AUTH_ERR:
	case PAM_AUTHINFO_UNAVAIL:
	    if (getpass_error) {
		/* error or ^C from tgetpass() */
		return AUTH_INTR;
	    }
	    /* FALLTHROUGH */
	case PAM_MAXTRIES:
	case PAM_PERM_DENIED:
	    return AUTH_FAILURE;
	default:
	    if ((s = pam_strerror(pamh, *pam_status)))
		log_error(NO_MAIL, "pam_authenticate: %s", s);
	    return AUTH_FATAL;
    }
}

int
pam_cleanup(pw, auth)
    struct passwd *pw;
    sudo_auth *auth;
{
    int *pam_status = (int *) auth->data;

    /* If successful, we can't close the session until pam_end_session() */
    if (*pam_status == AUTH_SUCCESS)
	return AUTH_SUCCESS;

    *pam_status = pam_end(pamh, *pam_status | PAM_DATA_SILENT);
    pamh = NULL;
    return *pam_status == PAM_SUCCESS ? AUTH_SUCCESS : AUTH_FAILURE;
}

int
pam_begin_session(pw)
    struct passwd *pw;
{
#ifdef HAVE_PAM_GETENVLIST
    char **pam_envp;
#endif
    int status = PAM_SUCCESS;

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
     * Set credentials (may include resource limits, device ownership, etc).
     * We don't check the return value here because in Linux-PAM 0.75
     * it returns the last saved return code, not the return code
     * for the setcred module.  Because we haven't called pam_authenticate(),
     * this is not set and so pam_setcred() returns PAM_PERM_DENIED.
     * We can't call pam_acct_mgmt() with Linux-PAM for a similar reason.
     */
    (void) pam_setcred(pamh, PAM_ESTABLISH_CRED);

#ifdef HAVE_PAM_GETENVLIST
    /*
     * Update environment based on what is stored in pamh.
     * If no authentication is done we will only have environment
     * variables if pam_env is called via session.
     */
    if ((pam_envp = pam_getenvlist(pamh)) != NULL) {
	/* Merge pam env with user env but do not overwrite. */
	env_merge(pam_envp, FALSE);
	efree(pam_envp);
	/* XXX - we leak any duplicates that were in pam_envp */
    }
#endif /* HAVE_PAM_GETENVLIST */

#ifndef NO_PAM_SESSION
    status = pam_open_session(pamh, 0);
    if (status != PAM_SUCCESS) {
	(void) pam_end(pamh, status | PAM_DATA_SILENT);
	pamh = NULL;
    }
#endif

done:
    return status == PAM_SUCCESS ? AUTH_SUCCESS : AUTH_FAILURE;
}

int
pam_end_session(pw)
    struct passwd *pw;
{
    int status = PAM_SUCCESS;

    if (pamh != NULL) {
	/*
	 * Update PAM_USER to reference the user we are running the command
	 * as, as opposed to the user we authenticated as.
	 */
	(void) pam_set_item(pamh, PAM_USER, pw->pw_name);
#ifndef NO_PAM_SESSION
	(void) pam_close_session(pamh, PAM_SILENT);
#endif
	(void) pam_setcred(pamh, PAM_DELETE_CRED | PAM_SILENT);
	status = pam_end(pamh, PAM_SUCCESS | PAM_DATA_SILENT);
	pamh = NULL;
    }

    return status == PAM_SUCCESS ? AUTH_SUCCESS : AUTH_FAILURE;
}

/*
 * ``Conversation function'' for PAM.
 * XXX - does not handle PAM_BINARY_PROMPT
 */
static int
sudo_conv(num_msg, msg, response, appdata_ptr)
    int num_msg;
    PAM_CONST struct pam_message **msg;
    struct pam_response **response;
    void *appdata_ptr;
{
    struct pam_response *pr;
    PAM_CONST struct pam_message *pm;
    const char *prompt;
    char *pass;
    int n, flags, std_prompt;
    int ret = PAM_AUTH_ERR;

    if ((*response = malloc(num_msg * sizeof(struct pam_response))) == NULL)
	return PAM_SYSTEM_ERR;
    zero_bytes(*response, num_msg * sizeof(struct pam_response));

    for (pr = *response, pm = *msg, n = num_msg; n--; pr++, pm++) {
	flags = tgetpass_flags;
	switch (pm->msg_style) {
	    case PAM_PROMPT_ECHO_ON:
		SET(flags, TGP_ECHO);
		/* FALLTHROUGH */
	    case PAM_PROMPT_ECHO_OFF:
		prompt = def_prompt;

		/* Error out if the last password read was interrupted. */
		if (getpass_error)
		    goto done;

		/* Is the sudo prompt standard? (If so, we'l just use PAM's) */
		std_prompt =  strncmp(def_prompt, "Password:", 9) == 0 &&
		    (def_prompt[9] == '\0' ||
		    (def_prompt[9] == ' ' && def_prompt[10] == '\0'));

		/* Only override PAM prompt if it matches /^Password: ?/ */
#if defined(PAM_TEXT_DOMAIN) && defined(HAVE_DGETTEXT)
		if (!def_passprompt_override && (std_prompt ||
		    (strcmp(pm->msg, dgettext(PAM_TEXT_DOMAIN, "Password: ")) &&
		    strcmp(pm->msg, dgettext(PAM_TEXT_DOMAIN, "Password:")))))
		    prompt = pm->msg;
#else
		if (!def_passprompt_override && (std_prompt ||
		    strncmp(pm->msg, "Password:", 9) || (pm->msg[9] != '\0'
		    && (pm->msg[9] != ' ' || pm->msg[10] != '\0'))))
		    prompt = pm->msg;
#endif
		/* Read the password unless interrupted. */
		pass = tgetpass(prompt, def_passwd_timeout * 60, flags);
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
		zero_bytes(pass, strlen(pass));
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
		zero_bytes(pr->resp, strlen(pr->resp));
		free(pr->resp);
		pr->resp = NULL;
	    }
	}
	zero_bytes(*response, num_msg * sizeof(struct pam_response));
	free(*response);
	*response = NULL;
    }
    return ret;
}
