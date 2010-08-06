/*
 * Copyright (c) 1999-2005, 2008-2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <time.h>
#include <signal.h>

#include "sudoers.h"
#include "sudo_auth.h"
#include "insults.h"

static sudo_auth auth_switch[] = {
/* Standalone entries first */
#ifdef HAVE_PAM
    AUTH_ENTRY("pam", FLAG_STANDALONE, pam_init, NULL, pam_verify, pam_cleanup, pam_begin_session, pam_end_session)
#endif
#ifdef HAVE_SECURID
    AUTH_ENTRY("SecurId", FLAG_STANDALONE, securid_init, securid_setup, securid_verify, NULL, NULL, NULL)
#endif
#ifdef HAVE_SIA_SES_INIT
    AUTH_ENTRY("sia", FLAG_STANDALONE, NULL, sia_setup, sia_verify, sia_cleanup, NULL, NULL)
#endif
#ifdef HAVE_AIXAUTH
    AUTH_ENTRY("aixauth", FLAG_STANDALONE, NULL, NULL, aixauth_verify, aixauth_cleanup, NULL, NULL)
#endif
#ifdef HAVE_FWTK
    AUTH_ENTRY("fwtk", FLAG_STANDALONE, fwtk_init, NULL, fwtk_verify, fwtk_cleanup, NULL, NULL)
#endif
#ifdef HAVE_BSD_AUTH_H
    AUTH_ENTRY("bsdauth", FLAG_STANDALONE, bsdauth_init, NULL, bsdauth_verify, bsdauth_cleanup, NULL, NULL)
#endif

/* Non-standalone entries */
#ifndef WITHOUT_PASSWD
    AUTH_ENTRY("passwd", 0, passwd_init, NULL, passwd_verify, passwd_cleanup, NULL, NULL)
#endif
#if defined(HAVE_GETPRPWNAM) && !defined(WITHOUT_PASSWD)
    AUTH_ENTRY("secureware", 0, secureware_init, NULL, secureware_verify, secureware_cleanup, NULL, NULL)
#endif
#ifdef HAVE_AFS
    AUTH_ENTRY("afs", 0, NULL, NULL, afs_verify, NULL, NULL, NULL)
#endif
#ifdef HAVE_DCE
    AUTH_ENTRY("dce", 0, NULL, NULL, dce_verify, NULL, NULL, NULL)
#endif
#ifdef HAVE_KERB4
    AUTH_ENTRY("kerb4", 0, kerb4_init, NULL, kerb4_verify, NULL, NULL, NULL)
#endif
#ifdef HAVE_KERB5
    AUTH_ENTRY("kerb5", 0, kerb5_init, NULL, kerb5_verify, kerb5_cleanup, NULL, NULL)
#endif
#ifdef HAVE_SKEY
    AUTH_ENTRY("S/Key", 0, NULL, rfc1938_setup, rfc1938_verify, NULL, NULL, NULL)
#endif
#ifdef HAVE_OPIE
    AUTH_ENTRY("OPIE", 0, NULL, rfc1938_setup, rfc1938_verify, NULL, NULL, NULL)
#endif
    AUTH_ENTRY(NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL)
};

extern char **NewArgv; /* XXX - for auditing */

static void pass_warn(void);

int
verify_user(struct passwd *pw, char *prompt)
{
    int counter = def_passwd_tries + 1;
    int success = AUTH_FAILURE;
    int flags, status, standalone, rval;
    char *p;
    sudo_auth *auth;
    sigaction_t sa, osa;

    /* Enable suspend during password entry. */
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    (void) sigaction(SIGTSTP, &sa, &osa);

    /* Make sure we have at least one auth method. */
    if (auth_switch[0].name == NULL) {
	audit_failure(NewArgv, "no authentication methods");
    	log_error(0, "%s  %s %s",
	    "There are no authentication methods compiled into sudo!",
	    "If you want to turn off authentication, use the",
	    "--disable-authentication configure option.");
	return -1;
    }

    /* Make sure we haven't mixed standalone and shared auth methods. */
    standalone = IS_STANDALONE(&auth_switch[0]);
    if (standalone && auth_switch[1].name != NULL) {
	audit_failure(NewArgv, "invalid authentication methods");
    	log_error(0, "Invalid authentication methods compiled into sudo!  "
	    "You cannot mix standalone and non-standalone authentication.");
	return -1;
    }

    /* Set FLAG_ONEANDONLY if there is only one auth method. */
    if (auth_switch[1].name == NULL)
	SET(auth_switch[0].flags, FLAG_ONEANDONLY);

    /* Initialize auth methods and unconfigure the method if necessary. */
    for (auth = auth_switch; auth->name; auth++) {
	if (auth->init && !IS_DISABLED(auth)) {
	    if (NEEDS_USER(auth))
		set_perms(PERM_USER);

	    status = (auth->init)(pw, &prompt, auth);
	    if (status == AUTH_FAILURE)
		SET(auth->flags, FLAG_DISABLED);
	    else if (status == AUTH_FATAL) {	/* XXX log */
		audit_failure(NewArgv, "authentication failure");
		return -1;		/* assume error msg already printed */
	    }

	    if (NEEDS_USER(auth))
		restore_perms();
	}
    }

    while (--counter) {
	/* Do any per-method setup and unconfigure the method if needed */
	for (auth = auth_switch; auth->name; auth++) {
	    if (auth->setup && !IS_DISABLED(auth)) {
		if (NEEDS_USER(auth))
		    set_perms(PERM_USER);

		status = (auth->setup)(pw, &prompt, auth);
		if (status == AUTH_FAILURE)
		    SET(auth->flags, FLAG_DISABLED);
		else if (status == AUTH_FATAL) {/* XXX log */
		    audit_failure(NewArgv, "authentication failure");
		    return -1;		/* assume error msg already printed */
		}

		if (NEEDS_USER(auth))
		    restore_perms();
	    }
	}

	/* Get the password unless the auth function will do it for us */
	if (standalone) {
	    p = prompt;
	} else {
	    p = auth_getpass(prompt, def_passwd_timeout * 60,
		SUDO_CONV_PROMPT_ECHO_OFF);
	    if (p == NULL)
		break;
	}

	/* Call authentication functions. */
	for (auth = auth_switch; auth->name; auth++) {
	    if (IS_DISABLED(auth))
		continue;

	    if (NEEDS_USER(auth))
		set_perms(PERM_USER);

	    success = auth->status = (auth->verify)(pw, p, auth);

	    if (NEEDS_USER(auth))
		restore_perms();

	    if (auth->status != AUTH_FAILURE)
		goto cleanup;
	}
	if (!standalone)
	    zero_bytes(p, strlen(p));
	pass_warn();
    }

cleanup:
    /* Call cleanup routines. */
    for (auth = auth_switch; auth->name; auth++) {
	if (auth->cleanup && !IS_DISABLED(auth)) {
	    if (NEEDS_USER(auth))
		set_perms(PERM_USER);

	    status = (auth->cleanup)(pw, auth);
	    if (status == AUTH_FATAL) {	/* XXX log */
		audit_failure(NewArgv, "authentication failure");
		return -1;		/* assume error msg already printed */
	    }

	    if (NEEDS_USER(auth))
		restore_perms();
	}
    }

    switch (success) {
	case AUTH_SUCCESS:
	    (void) sigaction(SIGTSTP, &osa, NULL);
	    rval = TRUE;
	    break;
	case AUTH_INTR:
	case AUTH_FAILURE:
	    if (counter != def_passwd_tries) {
		if (def_mail_badpass || def_mail_always)
		    flags = 0;
		else
		    flags = NO_MAIL;
		log_error(flags, "%d incorrect password attempt%s",
		    def_passwd_tries - counter,
		    (def_passwd_tries - counter == 1) ? "" : "s");
	    }
	    audit_failure(NewArgv, "authentication failure");
	    rval = FALSE;
	    break;
	case AUTH_FATAL:
	default:
	    audit_failure(NewArgv, "authentication failure");
	    rval = -1;
	    break;
    }

    return rval;
}

int auth_begin_session(struct passwd *pw)
{
    sudo_auth *auth;
    int status;

    for (auth = auth_switch; auth->name; auth++) {
	if (auth->begin_session && !IS_DISABLED(auth)) {
	    status = (auth->begin_session)(pw, auth);
	    if (status == AUTH_FATAL) {	/* XXX log */
		audit_failure(NewArgv, "authentication failure");
		return -1;		/* assume error msg already printed */
	    }
	}
    }
    return TRUE;
}

int auth_end_session(void)
{
    sudo_auth *auth;
    int status;

    for (auth = auth_switch; auth->name; auth++) {
	if (auth->end_session && !IS_DISABLED(auth)) {
	    status = (auth->end_session)(auth);
	    if (status == AUTH_FATAL) {	/* XXX log */
		return -1;		/* assume error msg already printed */
	    }
	}
    }
    return TRUE;
}

static void
pass_warn(void)
{
    const char *warning = def_badpass_message;

#ifdef INSULT
    if (def_insults)
	warning = INSULT;
#endif
    sudo_printf(SUDO_CONV_ERROR_MSG, "%s\n", warning);
}

char *
auth_getpass(const char *prompt, int timeout, int type)
{
    struct sudo_conv_message msg;
    struct sudo_conv_reply repl;

    /* Mask user input if pwfeedback set and echo is off. */
    if (type == SUDO_CONV_PROMPT_ECHO_OFF && def_pwfeedback)
	type = SUDO_CONV_PROMPT_MASK;

    /* If visiblepw set, do not error out if there is no tty. */
    if (def_visiblepw)
	type |= SUDO_CONV_PROMPT_ECHO_OK;

    /* Call conversation function */
    memset(&msg, 0, sizeof(msg));
    msg.msg_type = type;
    msg.timeout = def_passwd_timeout * 60;
    msg.msg = prompt;
    memset(&repl, 0, sizeof(repl));
    sudo_conv(1, &msg, &repl);
    /* XXX - check for ENOTTY? */
    return repl.reply;
}

void
dump_auth_methods(void)
{
    sudo_auth *auth;

    sudo_printf(SUDO_CONV_INFO_MSG, "Authentication methods:");
    for (auth = auth_switch; auth->name; auth++)
	sudo_printf(SUDO_CONV_INFO_MSG, " '%s'", auth->name);
    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
}
