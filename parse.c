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
#include <sys/ioctl.h>
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
#include <gram.h>

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Parsed sudoers info.
 */
extern struct userspec *userspecs;
extern struct defaults *defaults;

/*
 * Local prototypes.
 */
static void print_member	__P((char *, int, int, int));
static void display_defaults	__P((struct passwd *));
static void display_bound_defaults __P((int));
static int  get_ttycols		__P((void));
static void print_wrap		__P((int, int, int, ...));

#define	print_def(a)		print_wrap(4, 0, 1, a);
#define	print_def2(a, b)	print_wrap(4, 0, 2, a, b);
#define	print_def3(a, b, c)	print_wrap(4, 0, 3, a, b, c);
#define	print_def4(a, b, c, d)	print_wrap(4, 0, 4, a, b, c, d);
#define	print_priv(a)		print_wrap(8, '\\', 1, a);
#define	print_priv2(a, b)	print_wrap(8, '\\', 2, a, b);
#define	print_priv3(a, b, c)	print_wrap(8, '\\', 3, a, b, c);
#define	print_priv4(a, b, c, d)	print_wrap(8, '\\', 4, a, b, c, d);

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
    struct member *runas;
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
	for (us = userspecs; us != NULL; us = us->next) {
	    if (user_matches(sudo_user.pw, us->user) != ALLOW)
		continue;
	    for (priv = us->privileges; priv != NULL; priv = priv->next) {
		if (host_matches(priv->hostlist) != ALLOW)
		    continue;
		for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
		    /* Only check the command when listing another user. */
		    if (user_uid == 0 || list_pw == NULL ||
			user_uid == list_pw->pw_uid ||
			cmnd_matches(cs->cmnd) == ALLOW)
			    match = ALLOW;
		    if ((pwcheck == any && nopass != TRUE) ||
			(pwcheck == all && nopass == TRUE))
			nopass = cs->tags.nopasswd;
		}
	    }
	}
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
    for (us = userspecs; us != NULL; us = us->next) {
	if (user_matches(sudo_user.pw, us->user) != ALLOW)
	    continue;
	CLR(validated, FLAG_NO_USER);
	for (priv = us->privileges; priv != NULL; priv = priv->next) {
	    host_match = host_matches(priv->hostlist);
	    if (host_match == UNSPEC)
		continue;
	    if (host_match == ALLOW)
		CLR(validated, FLAG_NO_HOST);
	    runas = NULL;
	    for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
		if (cs->runaslist != NULL)
		    runas = cs->runaslist;
		runas_match = runas_matches(runas);
		if (runas_match != UNSPEC) {
		    cmnd_match = cmnd_matches(cs->cmnd);
		    if (cmnd_match != UNSPEC)
			match = host_match && runas_match && cmnd_match;
		    if (match == ALLOW)
			tags = &cs->tags;
		}
	    }
	}
    }
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

#define	TAG_CHANGED(t)	(cs->tags.t != UNSPEC && cs->tags.t != tags.t)

/*
 * Print out privileges for the specified user.
 */
void
display_privs(v, pw)
    VOID *v;
    struct passwd *pw;
{
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

	print_priv3("User ", pw->pw_name,
	    " may run the following commands on this host:\n");

	for (us = userspecs; us != NULL; us = us->next) {
	    if (user_matches(pw, us->user) != ALLOW ||
	      host_matches(us->privileges->hostlist) != ALLOW)
		continue;

	    for (priv = us->privileges; priv != NULL; priv = priv->next) {
		tags.noexec = def_noexec;
		tags.setenv = def_setenv;
		tags.nopasswd = !def_authenticate;
		for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
		    if (cs != priv->cmndlist)
			print_priv(", ");
		    print_priv("    (");
		    if (cs->runaslist != NULL) {
			for (m = cs->runaslist; m != NULL; m = m->next) {
			    if (m != cs->runaslist)
				print_priv(", ");
			    print_member(m->name, m->type, m->negated, RUNASALIAS);
			}
		    } else {
			print_priv(def_runas_default);
		    }
		    print_priv(") ");
		    if (TAG_CHANGED(setenv)) {
			print_priv(cs->tags.setenv ? "SETENV: " : "NOSETENV: ");
			tags.setenv = cs->tags.setenv;
		    }
		    if (TAG_CHANGED(noexec)) {
			print_priv(cs->tags.noexec ? "NOEXEC: " : "EXEC: ");
			tags.noexec = cs->tags.noexec;
		    }
		    if (TAG_CHANGED(nopasswd)) {
			print_priv(cs->tags.nopasswd ? "NOPASSWD: " : "PASSWD: ");
			tags.nopasswd = cs->tags.nopasswd;
		    }
		    m = cs->cmnd;
		    print_member(m->name, m->type, m->negated, CMNDALIAS);
		}
		print_priv("\n");
	    }
	}
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
    char *prefix;
    int per_runas = 0, per_cmnd = 0;

    for (d = defaults, prefix = NULL; d != NULL; d = d->next) {
	switch (d->type) {
	    case DEFAULTS_HOST:
		if (host_matches(d->binding) != ALLOW)
		    continue;
		break;
	    case DEFAULTS_USER:
		if (user_matches(pw, d->binding) != ALLOW)
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
	    print_def4("Matching Defaults entries for ", pw->pw_name,
		" on this host:\n", "    ");
	} else {
	    print_def(prefix);
	}
	if (d->val != NULL) {
	    print_def3(d->var, d->op == '+' ? "+=" : d->op == '-' ? "-=" : "=",
		d->val);
	} else
	    print_def2(d->op == FALSE ? "!" : "", d->var);
	prefix = ", ";
    }
    if (prefix)
	print_priv("\n\n");

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
    struct defaults *d;
    struct member *m, *binding;
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
    print_def3("Per-", dname, " Defaults entries:");
    for (d = defaults, binding = NULL; d != NULL; d = d->next) {
	if (d->type != dtype)
	    continue;

	if (d->binding != binding) {
	    binding = d->binding;
	    print_def3("\n", "    Defaults", dsep);
	    for (m = binding; m != NULL; m = m->next) {
		if (m != binding)
		    print_def(",");
		print_member(m->name, m->type, m->negated, atype);
		print_def(" ");
	    }
	} else
	    print_def(", ");
	if (d->val != NULL) {
	    print_def3(d->var, d->op == '+' ? "+=" : d->op == '-' ? "-=" : "=",
		d->val);
	} else
	    print_def2(d->op == FALSE ? "!" : "", d->var);
    }
    print_priv("\n\n");
}

/*
 * Check user_cmnd against sudoers and print the matching entry if the
 * command is allowed.
 */
int
display_cmnd(v, pw)
    VOID *v;
    struct passwd *pw;
{
    struct cmndspec *cs;
    struct member *match, *runas;
    struct privilege *priv;
    struct userspec *us;
    int rval = 1;
    int host_match, runas_match, cmnd_match;

#ifdef HAVE_LDAP
    if (v != NULL)
	rval = sudo_ldap_display_cmnd(v, pw);
#endif
    if (rval != 0 && !def_ignore_local_sudoers) {
	for (match = NULL, us = userspecs; us != NULL; us = us->next) {
	    if (user_matches(pw, us->user) != ALLOW)
		continue;

	    for (priv = us->privileges; priv != NULL; priv = priv->next) {
		host_match = host_matches(priv->hostlist);
		if (host_match == UNSPEC)
		    continue;
		runas = NULL;
		for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
		    if (cs->runaslist != NULL)
			runas = cs->runaslist;
		    runas_match = runas_matches(runas);
		    if (runas_match != UNSPEC) {
			cmnd_match = cmnd_matches(cs->cmnd);
			if (cmnd_match != UNSPEC)
			    match = host_match && runas_match ?
				cs->cmnd : NULL;
		    }
		}
	    }
	}
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
print_member(name, type, negated, alias_type)
    char *name;
    int type, negated, alias_type;
{
    struct alias *a;
    struct member *m;
    struct sudo_command *c;

    switch (type) {
	case ALL:
	    print_priv(negated ? "!ALL" : "ALL");
	    break;
	case COMMAND:
	    c = (struct sudo_command *) name;
	    print_priv4(negated ? "!" : "", c->cmnd, c->args ? " " : "",
		c->args ? c->args : "");
	    break;
	case ALIAS:
	    if ((a = find_alias(name, alias_type)) != NULL) {
		for (m = a->first_member; m != NULL; m = m->next) {
		    if (m != a->first_member)
			print_priv(", ");
		    print_member(m->name, m->type,
			negated ? !m->negated : m->negated, alias_type);
		}
		break;
	    }
	    /* FALLTHROUGH */
	default:
	    print_priv2(negated ? "!" : "", name);
	    break;
    }
}

#if !defined(TIOCGSIZE) && defined(TIOCGWINSZ)
# define TIOCGSIZE	TIOCGWINSZ
# define ttysize	winsize
# define ts_cols	ws_col
#endif

static int
get_ttycols()
{
    char *p;
    int cols;
#ifdef TIOCGSIZE
    struct ttysize win;

    if (ioctl(STDERR_FILENO, TIOCGSIZE, &win) == 0 && win.ts_cols != 0)
	return((int)win.ts_cols);
#endif

    /* Fall back on $COLUMNS. */
    if ((p = getenv("COLUMNS")) == NULL || (cols = atoi(p)) <= 0)
	cols = 80;
    return(cols);
}

/*
 * Simplistic print function with line wrap.
 * XXX - does not expand tabs, etc and only checks for newlines
 *       at the end of an arg.
 */
static void
#ifdef __STDC__
print_wrap(int indent, int lc, int nargs, ...)
#else
print_wrap(indent, lc, nargs, va_alist)
	int indent;
	int lc;
	int nargs;
	va_dcl
#endif
{
    static int left, cols = -1;
    int i, n, len;
    va_list ap;
    char *s = NULL;

    if (cols == -1)
	left = cols = get_ttycols();

#ifdef __STDC__
    va_start(ap, nargs);
#else
    va_start(ap);
#endif
    for (len = 0, i = 1; i <= nargs; i++) {
	s = va_arg(ap, char *);
	if ((n = strlen(s)) > 0)
	    len += s[n - 1] == '\n' ? n - 1 : n;
    }
    va_end(ap);

    if (len > left && cols > indent && len < cols - indent) {
	if (lc)
	    putchar(lc);
	putchar('\n');
	for (i = 0; i < indent; i++)
	    putchar(' ');
	left = cols - indent;
    }
#ifdef __STDC__
    va_start(ap, nargs);
#else
    va_start(ap);
#endif
    for (i = 1; i <= nargs; i++) {
	s = va_arg(ap, char *);
	if ((len = strlen(s)) > 0) {
	    fwrite(s, len, 1, stdout);
	    if (s[len - 1] == '\n')
		left = cols;
	    else if (len > left)
		left = 0;
	    else
		left -= len;
	}
    }
    va_end(ap);
}
