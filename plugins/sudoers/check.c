/*
 * Copyright (c) 1993-1996,1998-2005, 2007-2012
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "timestamp.h"

static char *expand_prompt(char *, char *, char *);
static bool  display_lecture(int);
static struct passwd *get_authpw(void);

/*
 * Returns true if the user successfully authenticates, false if not
 * or -1 on error.
 */
int
check_user(int validated, int mode)
{
    struct passwd *auth_pw;
    char *prompt;
    int status, rval = true;
    debug_decl(check_user, SUDO_DEBUG_AUTH)

    /*
     * Init authentication system regardless of whether we need a password.
     * Required for proper PAM session support.
     */
    auth_pw = get_authpw();
    if (sudo_auth_init(auth_pw) == -1) {
	rval = -1;
	goto done;
    }

    /*
     * Don't prompt for the root passwd or if the user is exempt.
     * If the user is not changing uid/gid, no need for a password.
     */
    if (!def_authenticate || user_uid == 0 || user_is_exempt())
	goto done;
    if (user_uid == runas_pw->pw_uid &&
	(!runas_gr || user_in_group(sudo_user.pw, runas_gr->gr_name))) {
#ifdef HAVE_SELINUX
	if (user_role == NULL && user_type == NULL)
#endif
#ifdef HAVE_PRIV_SET
	if (runas_privs == NULL && runas_limitprivs == NULL)
#endif
	    goto done;
    }

    /* Always need a password when -k was specified with the command. */
    if (ISSET(mode, MODE_IGNORE_TICKET))
	SET(validated, FLAG_CHECK_USER);

    if (build_timestamp() == -1) {
	rval = -1;
	goto done;
    }

    status = timestamp_status(TS_MAKE_DIRS);

    if (status != TS_CURRENT || ISSET(validated, FLAG_CHECK_USER)) {
	/* Bail out if we are non-interactive and a password is required */
	if (ISSET(mode, MODE_NONINTERACTIVE)) {
	    validated |= FLAG_NON_INTERACTIVE;
	    log_auth_failure(validated, 0);
	    rval = -1;
	    goto done;
	}

	/* XXX - should not lecture if askpass helper is being used. */
	display_lecture(status);

	/* Expand any escapes in the prompt. */
	prompt = expand_prompt(user_prompt ? user_prompt : def_passprompt,
	    user_name, user_shost);

	rval = verify_user(auth_pw, prompt, validated);
    }
    /* Only update timestamp if user was validated. */
    if (rval == true && ISSET(validated, VALIDATE_OK) &&
	!ISSET(mode, MODE_IGNORE_TICKET) && status != TS_ERROR)
	update_timestamp();

done:
    sudo_auth_cleanup(auth_pw);
    sudo_pw_delref(auth_pw);

    debug_return_bool(rval);
}

#define DEFAULT_LECTURE "\n" \
    "We trust you have received the usual lecture from the local System\n" \
    "Administrator. It usually boils down to these three things:\n\n" \
    "    #1) Respect the privacy of others.\n" \
    "    #2) Think before you type.\n" \
    "    #3) With great power comes great responsibility.\n\n"

/*
 * Display sudo lecture (standard or custom).
 * Returns true if the user was lectured, else false.
 */
static bool
display_lecture(int status)
{
    FILE *fp;
    char buf[BUFSIZ];
    ssize_t nread;
    struct sudo_conv_message msg;
    struct sudo_conv_reply repl;
    debug_decl(lecture, SUDO_DEBUG_AUTH)

    if (def_lecture == never ||
	(def_lecture == once && status != TS_MISSING && status != TS_ERROR))
	debug_return_int(false);

    memset(&msg, 0, sizeof(msg));
    memset(&repl, 0, sizeof(repl));

    if (def_lecture_file && (fp = fopen(def_lecture_file, "r")) != NULL) {
	while ((nread = fread(buf, sizeof(char), sizeof(buf) - 1, fp)) != 0) {
	    buf[nread] = '\0';
	    msg.msg_type = SUDO_CONV_ERROR_MSG;
	    msg.msg = buf;
	    sudo_conv(1, &msg, &repl);
	}
	fclose(fp);
    } else {
	msg.msg_type = SUDO_CONV_ERROR_MSG;
	msg.msg = _(DEFAULT_LECTURE);
	sudo_conv(1, &msg, &repl);
    }
    debug_return_int(true);
}

/*
 * Expand %h and %u escapes in the prompt and pass back the dynamically
 * allocated result.  Returns the same string if there are no escapes.
 */
static char *
expand_prompt(char *old_prompt, char *user, char *host)
{
    size_t len, n;
    int subst;
    char *p, *np, *new_prompt, *endp;
    debug_decl(expand_prompt, SUDO_DEBUG_AUTH)

    /* How much space do we need to malloc for the prompt? */
    subst = 0;
    for (p = old_prompt, len = strlen(old_prompt); *p; p++) {
	if (p[0] =='%') {
	    switch (p[1]) {
		case 'h':
		    p++;
		    len += strlen(user_shost) - 2;
		    subst = 1;
		    break;
		case 'H':
		    p++;
		    len += strlen(user_host) - 2;
		    subst = 1;
		    break;
		case 'p':
		    p++;
		    if (def_rootpw)
			    len += 2;
		    else if (def_targetpw || def_runaspw)
			    len += strlen(runas_pw->pw_name) - 2;
		    else
			    len += strlen(user_name) - 2;
		    subst = 1;
		    break;
		case 'u':
		    p++;
		    len += strlen(user_name) - 2;
		    subst = 1;
		    break;
		case 'U':
		    p++;
		    len += strlen(runas_pw->pw_name) - 2;
		    subst = 1;
		    break;
		case '%':
		    p++;
		    len--;
		    subst = 1;
		    break;
		default:
		    break;
	    }
	}
    }

    if (subst) {
	new_prompt = emalloc(++len);
	endp = new_prompt + len;
	for (p = old_prompt, np = new_prompt; *p; p++) {
	    if (p[0] =='%') {
		switch (p[1]) {
		    case 'h':
			p++;
			n = strlcpy(np, user_shost, np - endp);
			if (n >= np - endp)
			    goto oflow;
			np += n;
			continue;
		    case 'H':
			p++;
			n = strlcpy(np, user_host, np - endp);
			if (n >= np - endp)
			    goto oflow;
			np += n;
			continue;
		    case 'p':
			p++;
			if (def_rootpw)
				n = strlcpy(np, "root", np - endp);
			else if (def_targetpw || def_runaspw)
				n = strlcpy(np, runas_pw->pw_name, np - endp);
			else
				n = strlcpy(np, user_name, np - endp);
			if (n >= np - endp)
				goto oflow;
			np += n;
			continue;
		    case 'u':
			p++;
			n = strlcpy(np, user_name, np - endp);
			if (n >= np - endp)
			    goto oflow;
			np += n;
			continue;
		    case 'U':
			p++;
			n = strlcpy(np,  runas_pw->pw_name, np - endp);
			if (n >= np - endp)
			    goto oflow;
			np += n;
			continue;
		    case '%':
			/* convert %% -> % */
			p++;
			break;
		    default:
			/* no conversion */
			break;
		}
	    }
	    *np++ = *p;
	    if (np >= endp)
		goto oflow;
	}
	*np = '\0';
    } else
	new_prompt = old_prompt;

    debug_return_str(new_prompt);

oflow:
    /* We pre-allocate enough space, so this should never happen. */
    errorx(1, _("internal error, %s overflow"), "expand_prompt()");
}

/*
 * Checks if the user is exempt from supplying a password.
 */
bool
user_is_exempt(void)
{
    bool rval = false;
    debug_decl(user_is_exempt, SUDO_DEBUG_AUTH)

    if (def_exempt_group)
	rval = user_in_group(sudo_user.pw, def_exempt_group);
    debug_return_bool(rval);
}

/*
 * Get passwd entry for the user we are going to authenticate as.
 * By default, this is the user invoking sudo.  In the most common
 * case, this matches sudo_user.pw or runas_pw.
 */
static struct passwd *
get_authpw(void)
{
    struct passwd *pw;
    debug_decl(get_authpw, SUDO_DEBUG_AUTH)

    if (def_rootpw) {
	if ((pw = sudo_getpwuid(ROOT_UID)) == NULL)
	    log_fatal(0, _("unknown uid: %u"), ROOT_UID);
    } else if (def_runaspw) {
	if ((pw = sudo_getpwnam(def_runas_default)) == NULL)
	    log_fatal(0, _("unknown user: %s"), def_runas_default);
    } else if (def_targetpw) {
	if (runas_pw->pw_name == NULL)
	    log_fatal(NO_MAIL|MSG_ONLY, _("unknown uid: %u"),
		(unsigned int) runas_pw->pw_uid);
	sudo_pw_addref(runas_pw);
	pw = runas_pw;
    } else {
	sudo_pw_addref(sudo_user.pw);
	pw = sudo_user.pw;
    }

    debug_return_ptr(pw);
}
