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

#include "sudo.h"
#include "sudo_auth.h"
#include "insults.h"

extern char **NewArgv; /* XXX */

sudo_auth auth_switch[] = {
#ifdef AUTH_STANDALONE
    AUTH_STANDALONE
#else
#  ifndef WITHOUT_PASSWD
    AUTH_ENTRY(0, "passwd", passwd_init, NULL, passwd_verify, passwd_cleanup)
#  endif
#  if defined(HAVE_GETPRPWNAM) && !defined(WITHOUT_PASSWD)
    AUTH_ENTRY(0, "secureware", secureware_init, NULL, secureware_verify, secureware_cleanup)
#  endif
#  ifdef HAVE_AFS
    AUTH_ENTRY(0, "afs", NULL, NULL, afs_verify, NULL)
#  endif
#  ifdef HAVE_DCE
    AUTH_ENTRY(0, "dce", NULL, NULL, dce_verify, NULL)
#  endif
#  ifdef HAVE_KERB4
    AUTH_ENTRY(0, "kerb4", kerb4_init, NULL, kerb4_verify, NULL)
#  endif
#  ifdef HAVE_KERB5
    AUTH_ENTRY(0, "kerb5", kerb5_init, kerb5_setup, kerb5_verify, kerb5_cleanup)
#  endif
#  ifdef HAVE_SKEY
    AUTH_ENTRY(0, "S/Key", NULL, rfc1938_setup, rfc1938_verify, NULL)
#  endif
#  ifdef HAVE_OPIE
    AUTH_ENTRY(0, "OPIE", NULL, rfc1938_setup, rfc1938_verify, NULL)
#  endif
#endif /* AUTH_STANDALONE */
    AUTH_ENTRY(0, NULL, NULL, NULL, NULL, NULL)
};

/*
 * Initialize sudoers authentication method(s).
 * Returns 0 on success and -1 on error.
 */
int
sudo_auth_init(pw)
    struct passwd *pw;
{
    sudo_auth *auth;
    int status = AUTH_SUCCESS;

    if (auth_switch[0].name == NULL)
	return 0;

    /* Set FLAG_ONEANDONLY if there is only one auth method. */
    if (auth_switch[1].name == NULL)
	SET(auth_switch[0].flags, FLAG_ONEANDONLY);

    /* Initialize auth methods and unconfigure the method if necessary. */
    for (auth = auth_switch; auth->name; auth++) {
	if (auth->init && IS_CONFIGURED(auth)) {
	    if (NEEDS_USER(auth))
		set_perms(PERM_USER);

	    status = (auth->init)(pw, auth);

	    if (NEEDS_USER(auth))
		set_perms(PERM_ROOT);

	    /* Disable if it failed to init unless there was a fatal error. */
	    if (status == AUTH_FAILURE)
		CLR(auth->flags, FLAG_CONFIGURED);
	    else if (status == AUTH_FATAL)
		break;		/* assume error msg already printed */
	}
    }
    return status == AUTH_FATAL ? -1 : 0;
}

/*
 * Cleanup all authentication methods.
 * Returns 0 on success and -1 on error.
 */
int
sudo_auth_cleanup(pw)
    struct passwd *pw;
{
    sudo_auth *auth;
    int status = AUTH_SUCCESS;

    /* Call cleanup routines. */
    for (auth = auth_switch; auth->name; auth++) {
	if (auth->cleanup && IS_CONFIGURED(auth)) {
	    if (NEEDS_USER(auth))
		set_perms(PERM_USER);

	    status = (auth->cleanup)(pw, auth);

	    if (NEEDS_USER(auth))
		set_perms(PERM_ROOT);

	    if (status == AUTH_FATAL)
		break;		/* assume error msg already printed */
	}
    }
    return status == AUTH_FATAL ? -1 : 0;
}

/*
 * Verify the specified user.
 * Returns TRUE if verified, FALSE if not or -1 on error.
 */
int
verify_user(pw, prompt, validated)
    struct passwd *pw;
    char *prompt;
    int validated;
{
    int counter = def_passwd_tries + 1;
    int success = AUTH_FAILURE;
    int status, rval;
    char *p;
    sudo_auth *auth;
    sigaction_t sa, osa;

    /* Enable suspend during password entry. */
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_DFL;
    (void) sigaction(SIGTSTP, &sa, &osa);

    /* Make sure we have at least one auth method. */
    /* XXX - check FLAG_DISABLED too */
    if (auth_switch[0].name == NULL) {
	audit_failure(NewArgv, "no authentication methods");
    	log_error(0, "%s  %s %s",
	    "There are no authentication methods compiled into sudo!",
	    "If you want to turn off authentication, use the",
	    "--disable-authentication configure option.");
	return -1;
    }

    while (--counter) {
	/* Do any per-method setup and unconfigure the method if needed */
	for (auth = auth_switch; auth->name; auth++) {
	    if (auth->setup && IS_CONFIGURED(auth)) {
		if (NEEDS_USER(auth))
		    set_perms(PERM_USER);

		status = (auth->setup)(pw, &prompt, auth);

		if (NEEDS_USER(auth))
		    set_perms(PERM_ROOT);

		if (status == AUTH_FAILURE)
		    CLR(auth->flags, FLAG_CONFIGURED);
		else if (status == AUTH_FATAL) {
		    goto done;		/* assume error msg already printed */
		}
	    }
	}

	/* Get the password unless the auth function will do it for us */
#ifdef AUTH_STANDALONE
	p = prompt;
#else
	p = (char *) tgetpass(prompt, def_passwd_timeout * 60,
	    tgetpass_flags);
#endif /* AUTH_STANDALONE */

	/* Call authentication functions. */
	for (auth = auth_switch; p && auth->name; auth++) {
	    if (!IS_CONFIGURED(auth))
		continue;

	    if (NEEDS_USER(auth))
		set_perms(PERM_USER);

	    success = auth->status = (auth->verify)(pw, (char *)p, auth);

	    if (NEEDS_USER(auth))
		set_perms(PERM_ROOT);

	    if (auth->status != AUTH_FAILURE)
		goto done;
	}
#ifndef AUTH_STANDALONE
	if (p == NULL)
	    break;
	zero_bytes(p, strlen(p));
#endif
	if (!ISSET(tgetpass_flags, TGP_ASKPASS))
	    pass_warn(stderr);
    }

done:
    switch (success) {
	case AUTH_SUCCESS:
	    (void) sigaction(SIGTSTP, &osa, NULL);
	    rval = TRUE;
	    break;
	case AUTH_INTR:
	case AUTH_FAILURE:
	    if (counter != def_passwd_tries)
		validated |= FLAG_BAD_PASSWORD;
	    log_auth_failure(validated, def_passwd_tries - counter);
	    rval = FALSE;
	    break;
	case AUTH_FATAL:
	default:
	    log_auth_failure(validated | FLAG_AUTH_ERROR, 0);
	    rval = -1;
	    break;
    }
    return rval;
}

void
pass_warn(fp)
    FILE *fp;
{

#ifdef INSULT
    if (def_insults)
	(void) fprintf(fp, "%s\n", INSULT);
    else
#endif
	(void) fprintf(fp, "%s\n", def_badpass_message);
}

void
dump_auth_methods()
{
    sudo_auth *auth;

    (void) fputs("Authentication methods:", stdout);
    for (auth = auth_switch; auth->name; auth++)
        (void) printf(" '%s'", auth->name);
    (void) putchar('\n');
}
