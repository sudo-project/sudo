/*
 * Copyright (c) 2004-2005, 2007 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <grp.h>

#include "sudo.h"
#include "parse.h"
#include "lbuf.h"
#include <gram.h>

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

/* Characters that must be quoted in sudoers */
#define SUDOERS_QUOTED	":\\,=#\""

/*
 * Local prototypes.
 */
static void print_member	__P((struct lbuf *, char *, int, int, int));
static void display_defaults	__P((struct passwd *));
static void display_bound_defaults __P((int));

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
    int validated, match, host_match, runas_match, cmnd_match;
    struct cmndspec *cs;
    struct cmndtag *tags = NULL;
    struct privilege *priv;
    struct userspec *us;

    /* Assume the worst.  */
    validated = VALIDATE_NOT_OK | FLAG_NO_HOST | FLAG_NO_USER;

    /*
     * Only check the actual command if pwflag is not set.
     * It is set for the "validate", "list" and "kill" pseudo-commands.
     * Always check the host and user.
     */
    if (pwflag) {
	int nopass = UNSPEC;
	enum def_tupple pwcheck;

	pwcheck = (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;

	if (list_pw == NULL)
	    SET(validated, FLAG_NO_CHECK);
	CLR(validated, FLAG_NO_USER);
	CLR(validated, FLAG_NO_HOST);
	match = DENY;
	tq_foreach_rev(&userspecs, us) {
	    if (userlist_matches(sudo_user.pw, &us->users) != ALLOW)
		continue;
	    tq_foreach_rev(&us->privileges, priv) {
		if (hostlist_matches(&priv->hostlist) != ALLOW)
		    continue;
		tq_foreach_rev(&priv->cmndlist, cs) {
		    /* Only check the command when listing another user. */
		    if (user_uid == 0 || list_pw == NULL ||
			user_uid == list_pw->pw_uid ||
			cmnd_matches(cs->cmnd) == ALLOW)
			    match = ALLOW;
		    if ((pwcheck == any && nopass != TRUE) ||
			(pwcheck == all && nopass == TRUE))
			nopass = cs->tags.nopasswd;
		    if (match == ALLOW)
			goto matched_pseudo;
		}
	    }
	}
	matched_pseudo:
	if (match == ALLOW || user_uid == 0) {
	    /* User has an entry for this host. */
	    CLR(validated, VALIDATE_NOT_OK);
	    SET(validated, VALIDATE_OK);
	}
	if (pwcheck == always && def_authenticate)
	    SET(validated, FLAG_CHECK_USER);
	else if (pwcheck == never || nopass == TRUE)
	    def_authenticate = FALSE;
	return(validated);
    }

    /* Need to be runas user while stat'ing things. */
    set_perms(PERM_RUNAS);

    match = UNSPEC;
    tq_foreach_rev(&userspecs, us) {
	if (userlist_matches(sudo_user.pw, &us->users) != ALLOW)
	    continue;
	CLR(validated, FLAG_NO_USER);
	tq_foreach_rev(&us->privileges, priv) {
	    host_match = hostlist_matches(&priv->hostlist);
	    if (host_match == ALLOW)
		CLR(validated, FLAG_NO_HOST);
	    else
		continue;
	    tq_foreach_rev(&priv->cmndlist, cs) {
		runas_match = runaslist_matches(&cs->runasuserlist,
		    &cs->runasgrouplist);
		if (runas_match == ALLOW) {
		    cmnd_match = cmnd_matches(cs->cmnd);
		    if (cmnd_match != UNSPEC) {
			match = cmnd_match;
			tags = &cs->tags;
			goto matched2;
		    }
		}
	    }
	}
    }
    matched2:
    if (match == ALLOW) {
	CLR(validated, VALIDATE_NOT_OK);
	SET(validated, VALIDATE_OK);
	if (tags != NULL) {
	    if (tags->nopasswd != UNSPEC)
		def_authenticate = !tags->nopasswd;
	    if (tags->noexec != UNSPEC)
		def_noexec = tags->noexec;
	    if (tags->setenv != UNSPEC)
		def_setenv = tags->setenv;
	}
    }
    set_perms(PERM_ROOT);
    return(validated);
}

#define	TAG_CHANGED(t) \
	(cs->tags.t != UNSPEC && cs->tags.t != IMPLIED && cs->tags.t != tags.t)

/*
 * Print out privileges for the specified user.
 */
void
display_privs(v, pw)
    void *v;
    struct passwd *pw;
{
    struct lbuf lbuf;
    struct cmndspec *cs;
    struct member *m;
    struct privilege *priv;
    struct userspec *us;
    struct cmndtag tags;

#if defined(HAVE_INITGROUPS) && defined(HAVE_GETGROUPS)
    /* Set group vector so group matching works correctly. */
    if (pw != sudo_user.pw) {
	(void) initgroups(pw->pw_name, pw->pw_gid);
	if ((user_ngroups = getgroups(0, NULL)) > 0) {
	    user_groups = erealloc3(user_groups, user_ngroups,
		MAX(sizeof(gid_t), sizeof(int)));
	    if (getgroups(user_ngroups, user_groups) < 0)
		log_error(USE_ERRNO|MSG_ONLY, "can't get group vector");
	} else
	    user_ngroups = 0;
    }
#endif

    if (!def_ignore_local_sudoers) {
	display_defaults(pw);

	lbuf_init(&lbuf, NULL, 8, '\\');
	printf("User %s may run the following commands on this host:\n",
	    pw->pw_name);

	tq_foreach_fwd(&userspecs, us) {
	    /* XXX - why only check the first privilege here? */
	    if (userlist_matches(pw, &us->users) != ALLOW ||
		hostlist_matches(&us->privileges.first->hostlist) != ALLOW)
		continue;

	    tq_foreach_fwd(&us->privileges, priv) {
		tags.noexec = def_noexec;
		tags.setenv = def_setenv;
		tags.nopasswd = !def_authenticate;
		lbuf_append(&lbuf, "    ", NULL);
		tq_foreach_fwd(&priv->cmndlist, cs) {
		    if (cs != tq_first(&priv->cmndlist))
			lbuf_append(&lbuf, ", ", NULL);
		    lbuf_append(&lbuf, "(", NULL);
		    if (!tq_empty(&cs->runasuserlist)) {
			tq_foreach_fwd(&cs->runasuserlist, m) {
			    if (m != tq_first(&cs->runasuserlist))
				lbuf_append(&lbuf, ", ", NULL);
			    print_member(&lbuf, m->name, m->type, m->negated,
				RUNASALIAS);
			}
		    } else {
			lbuf_append(&lbuf, def_runas_default, NULL);
		    }
		    if (!tq_empty(&cs->runasgrouplist)) {
			lbuf_append(&lbuf, " : ", NULL);
			tq_foreach_fwd(&cs->runasgrouplist, m) {
			    if (m != tq_first(&cs->runasgrouplist))
				lbuf_append(&lbuf, ", ", NULL);
			    print_member(&lbuf, m->name, m->type, m->negated,
				RUNASALIAS);
			}
		    }
		    lbuf_append(&lbuf, ") ", NULL);
		    if (TAG_CHANGED(setenv)) {
			lbuf_append(&lbuf, cs->tags.setenv ? "SETENV: " :
			    "NOSETENV: ", NULL);
			tags.setenv = cs->tags.setenv;
		    }
		    if (TAG_CHANGED(noexec)) {
			lbuf_append(&lbuf, cs->tags.noexec ? "NOEXEC: " :
			    "EXEC: ", NULL);
			tags.noexec = cs->tags.noexec;
		    }
		    if (TAG_CHANGED(nopasswd)) {
			lbuf_append(&lbuf, cs->tags.nopasswd ? "NOPASSWD: " :
			    "PASSWD: ", NULL);
			tags.nopasswd = cs->tags.nopasswd;
		    }
		    m = cs->cmnd;
		    print_member(&lbuf, m->name, m->type, m->negated,
			CMNDALIAS);
		}
		lbuf_print(&lbuf);
	    }
	}
	lbuf_destroy(&lbuf);
    }
#ifdef HAVE_LDAP
    if (v != NULL)
	sudo_ldap_display_privs(v, pw);
#endif
}

/*
 * Display matching Defaults entries for the given user on this host.
 */
static void
display_defaults(pw)
    struct passwd *pw;
{
    struct defaults *d;
    struct lbuf lbuf;
    char *prefix = NULL;
    int per_runas = 0, per_cmnd = 0;

    lbuf_init(&lbuf, NULL, 4, 0);

    tq_foreach_fwd(&defaults, d) {
	switch (d->type) {
	    case DEFAULTS_HOST:
		if (hostlist_matches(&d->binding) != ALLOW)
		    continue;
		break;
	    case DEFAULTS_USER:
		if (userlist_matches(pw, &d->binding) != ALLOW)
		    continue;
		break;
	    case DEFAULTS_RUNAS:
		per_runas = 1;
		continue;
	    case DEFAULTS_CMND:
		per_cmnd = 1;
		continue;
	}
	if (prefix == NULL) {
	    printf("Matching Defaults entries for %s on this host:\n",
		pw->pw_name);
	    prefix = "    ";
	}
	lbuf_append(&lbuf, prefix, NULL);
	if (d->val != NULL) {
	    lbuf_append(&lbuf, d->var, d->op == '+' ? " += " :
		d->op == '-' ? " -= " : " = ", NULL);
	    if (strpbrk(d->val, " \t") != NULL) {
		lbuf_append(&lbuf, "\"", NULL);
		lbuf_append_quoted(&lbuf, "\"", d->val, NULL);
		lbuf_append(&lbuf, "\"", NULL);
	    } else
		lbuf_append_quoted(&lbuf, SUDOERS_QUOTED, d->val, NULL);
	} else
	    lbuf_append(&lbuf, d->op == FALSE ? "!" : "", d->var, NULL);
	prefix = ", ";
    }
    if (prefix) {
	lbuf_print(&lbuf);
	putchar('\n');
    }
    lbuf_destroy(&lbuf);

    if (per_runas)
	display_bound_defaults(DEFAULTS_RUNAS);
    if (per_cmnd)
	display_bound_defaults(DEFAULTS_CMND);
}

/*
 * Display Defaults entries of the given type.
 */
static void
display_bound_defaults(dtype)
    int dtype;
{
    struct lbuf lbuf;
    struct defaults *d;
    struct member *m, *binding = NULL;
    char *dname, *dsep;
    int atype;

    switch (dtype) {
	case DEFAULTS_HOST:
	    atype = HOSTALIAS;
	    dname = "host";
	    dsep = "@";
	    break;
	case DEFAULTS_USER:
	    atype = USERALIAS;
	    dname = "user";
	    dsep = ":";
	    break;
	case DEFAULTS_RUNAS:
	    atype = RUNASALIAS;
	    dname = "runas";
	    dsep = ">";
	    break;
	case DEFAULTS_CMND:
	    atype = CMNDALIAS;
	    dname = "cmnd";
	    dsep = "!";
	    break;
	default:
	    return;
    }
    lbuf_init(&lbuf, NULL, 4, 0);
    printf("Per-%s Defaults entries:\n", dname);
    tq_foreach_fwd(&defaults, d) {
	if (d->type != dtype)
	    continue;

	if (binding != tq_first(&d->binding)) {
	    binding = tq_first(&d->binding);
	    lbuf_append(&lbuf, "    Defaults", dsep, NULL);
	    for (m = binding; m != NULL; m = m->next) {
		if (m != binding)
		    lbuf_append(&lbuf, ",", NULL);
		print_member(&lbuf, m->name, m->type, m->negated, atype);
		lbuf_append(&lbuf, " ", NULL);
	    }
	} else
	    lbuf_append(&lbuf, ", ", NULL);
	if (d->val != NULL) {
	    lbuf_append(&lbuf, d->var, d->op == '+' ? "+=" :
		d->op == '-' ? "-=" : "=", d->val, NULL);
	} else
	    lbuf_append(&lbuf, d->op == FALSE ? "!" : "", d->var, NULL);
    }
    lbuf_print(&lbuf);
    lbuf_destroy(&lbuf);
    putchar('\n');
}

/*
 * Check user_cmnd against sudoers and print the matching entry if the
 * command is allowed.
 */
int
display_cmnd(v, pw)
    void *v;
    struct passwd *pw;
{
    struct cmndspec *cs;
    struct member *match;
    struct privilege *priv;
    struct userspec *us;
    int rval = 1;
    int host_match, runas_match, cmnd_match;

#ifdef HAVE_LDAP
    if (v != NULL)
	rval = sudo_ldap_display_cmnd(v, pw);
#endif
    if (rval != 0 && !def_ignore_local_sudoers) {
	match = NULL;
	tq_foreach_rev(&userspecs, us) {
	    if (userlist_matches(pw, &us->users) != ALLOW)
		continue;

	    tq_foreach_rev(&us->privileges, priv) {
		host_match = hostlist_matches(&priv->hostlist);
		if (host_match != ALLOW)
		    continue;
		tq_foreach_rev(&priv->cmndlist, cs) {
		    runas_match = runaslist_matches(&cs->runasuserlist,
			&cs->runasgrouplist);
		    if (runas_match == ALLOW) {
			cmnd_match = cmnd_matches(cs->cmnd);
			if (cmnd_match != UNSPEC) {
			    match = host_match && runas_match ?
				cs->cmnd : NULL;
			    goto matched;
			}
		    }
		}
	    }
	}
	matched:
	if (match != NULL && !match->negated) {
	    printf("%s%s%s\n", safe_cmnd, user_args ? " " : "",
		user_args ? user_args : "");
	    rval = 0;
	}
    }
    return(rval);
}

/*
 * Print the contents of a struct member to stdout
 */
static void
_print_member(lbuf, name, type, negated, alias_type)
    struct lbuf *lbuf;
    char *name;
    int type, negated, alias_type;
{
    struct alias *a;
    struct member *m;
    struct sudo_command *c;

    switch (type) {
	case ALL:
	    lbuf_append(lbuf, negated ? "!ALL" : "ALL", NULL);
	    break;
	case COMMAND:
	    c = (struct sudo_command *) name;
	    if (negated)
		lbuf_append(lbuf, "!", NULL);
	    lbuf_append_quoted(lbuf, SUDOERS_QUOTED, c->cmnd, NULL);
	    if (c->args) {
		lbuf_append(lbuf, " ", NULL);
		lbuf_append_quoted(lbuf, SUDOERS_QUOTED, c->args, NULL);
	    }
	    break;
	case ALIAS:
	    if ((a = find_alias(name, alias_type)) != NULL) {
		tq_foreach_fwd(&a->members, m) {
		    if (m != tq_first(&a->members))
			lbuf_append(lbuf, ", ", NULL);
		    _print_member(lbuf, m->name, m->type,
			negated ? !m->negated : m->negated, alias_type);
		}
		break;
	    }
	    /* FALLTHROUGH */
	default:
	    lbuf_append(lbuf, negated ? "!" : "", name, NULL);
	    break;
    }
}

static void
print_member(lbuf, name, type, negated, alias_type)
    struct lbuf *lbuf;
    char *name;
    int type, negated, alias_type;
{
    alias_seqno++;
    _print_member(lbuf, name, type, negated, alias_type);
}
