/*
 * Copyright (c) 1996, 1998-2004 Todd C. Miller <Todd.Miller@courtesan.com>
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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include "config.h"

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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <ctype.h>
#include <pwd.h>

#include "sudo.h"
#include "parse.h"
#include "gram.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Parsed sudoers info.
 */
extern struct userspec *userspecs;

/*
 * Parse the specified sudoers file.
 */
int
parse_sudoers(path)
    const char *path;
{
    extern FILE *yyin;

    yyin = open_sudoers(_PATH_SUDOERS, NULL);
    init_parser(_PATH_SUDOERS, 0);
    return(yyparse());
}

/*
 * Look up the user in the parsed sudoers file and check to see if they are
 * allowed to run the specified command on this host as the target user.
 */
int
sudoers_lookup(pwflag)
    int pwflag;
{
    int rval, validated, matched;
    enum def_tupple pwcheck = 0;
    struct cmndspec *cs;
    struct cmndtag *tags = NULL;
    struct privilege *priv;
    struct userspec *us;

    /*
     * We use pwflag to tell us when a password should be required
     * for pseudo-commands.  XXX - pass in pwcheck, not pwflag
     */
    if (pwflag)
	pwcheck = (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;

    /* Assume the worst.  */
    validated = VALIDATE_NOT_OK | FLAG_NO_HOST | FLAG_NO_USER;
    if (pwflag && list_pw == NULL)
	SET(validated, FLAG_NO_CHECK);
    else if (!def_authenticate)
	validated |= FLAG_NOPASS;

    /*
     * Only check the actual command if pwflag is not set.
     * It is set for the "validate", "list" and "kill" pseudo-commands.
     * Always check the host and user.
     */
    if (pwflag) {
	int nopass = UNSPEC;

	CLR(validated, FLAG_NO_USER);
	CLR(validated, FLAG_NO_HOST);
	matched = FALSE;
	for (us = userspecs; us != NULL; us = us->next) {
	    if (user_matches(sudo_user.pw, us->user) == TRUE) {
		priv = us->privileges;
		if (host_matches(user_shost, user_host, priv->hostlist) == TRUE) {
		    for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
			/* Only check the command when listing another user. */
			if (user_uid == 0 || list_pw == NULL ||
			    user_uid == list_pw->pw_uid ||
			    cmnd_matches(user_cmnd, user_args, cs->cmnd) == TRUE)
				matched = TRUE;
			if ((pwcheck == any && nopass != TRUE) ||
			    (pwcheck == all && nopass == TRUE))
			    nopass = cs->tags.nopasswd;
		    }
		}
	    }
	}
	if (matched == TRUE) {
	    /* User has an entry for this host. */
	    CLR(validated, VALIDATE_NOT_OK);
	    SET(validated, VALIDATE_OK);
	    if (pwcheck == always && def_authenticate)
		SET(validated, FLAG_CHECK_USER);
	    else if (pwcheck == never || !def_authenticate || nopass == TRUE)
		SET(validated, FLAG_NOPASS);
	}
	return(validated);
    }

    /* Need to be runas user while stat'ing things. */
    set_perms(PERM_RUNAS);

    matched = UNSPEC;
    for (us = userspecs; us != NULL; us = us->next) {
	if (user_matches(sudo_user.pw, us->user) == TRUE) {
	    CLR(validated, FLAG_NO_USER);
	    priv = us->privileges;
	    if (host_matches(user_shost, user_host, priv->hostlist) == TRUE) {
		CLR(validated, FLAG_NO_HOST);
		for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
		    if (runas_matches(runas_pw, cs->runaslist) == TRUE) {
			rval = cmnd_matches(user_cmnd, user_args, cs->cmnd);
			if (rval != UNSPEC) {
			    matched = rval;
			    tags = &cs->tags;
			}
		    }
		}
	    }
	}
    }
    if (matched == TRUE) {
	CLR(validated, VALIDATE_NOT_OK);
	SET(validated, VALIDATE_OK);
	if (tags != NULL) {
	    if (tags->nopasswd == TRUE)
		SET(validated, FLAG_NOPASS);
	    if (tags->noexec == TRUE)
		SET(validated, FLAG_NOEXEC);
	    if (tags->monitor == TRUE)
		SET(validated, FLAG_MONITOR);
	}
    }
    set_perms(PERM_ROOT);
    return(validated);
}

/*
 * Print out privileges for the specified user.
 */
void
display_privs(pw)
    struct passwd *pw;
{
    struct cmndspec *cs;
    struct member *m, *runas;
    struct privilege *priv;
    struct userspec *us;

    printf("User %s may run the following commands on this host:\n",
	pw->pw_name);

    for (us = userspecs; us != NULL; us = us->next) {
	if (user_matches(pw, us->user) != TRUE ||
	  host_matches(user_shost, user_host, us->privileges->hostlist) != TRUE)
	    continue;

	priv = us->privileges;
	runas = NULL;
	for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
	    fputs("    ", stdout);
	    if (cs->runaslist != NULL)
		runas = cs->runaslist;
	    if (runas != NULL) {
		fputs("(", stdout);
		for (m = runas; m != NULL; m = m->next) {
		    if (m != runas)
			fputs(", ", stdout);
		    print_member(m);
		}
		fputs(") ", stdout);
	    }
	    if (cs->tags.monitor != UNSPEC && cs->tags.monitor != def_monitor)
		printf("%sMONITOR: ", cs->tags.monitor ? "" : "NO");
	    if (cs->tags.noexec != UNSPEC && cs->tags.noexec != def_noexec)
		printf("%sEXEC: ", cs->tags.noexec ? "NO" : "");
	    if (cs->tags.nopasswd != UNSPEC && cs->tags.nopasswd != !def_authenticate)
		printf("%sPASSWD: ", cs->tags.nopasswd ? "NO" : "");
	    print_member(cs->cmnd);
	    putchar('\n');
	}
    }
}

/*
 * Print the contents of a struct member to stdout
 */
void
print_member(m)
    struct member *m;
{
    struct sudo_command *c;

    if (m->negated)
	printf("!");
    if (m->name == NULL)
	printf("ALL");
    else if (m->type != COMMAND)
	printf("%s", m->name);
    else {
	c = (struct sudo_command *) m->name;
	printf("%s%s%s", c->cmnd, c->args ? " " : "",
	    c->args ? c->args : "");
    }
}
