/*
 * Copyright (c) 2004-2005, 2007-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "parse.h"
#include "lbuf.h"
#include <gram.h>

/* Characters that must be quoted in sudoers */
#define	SUDOERS_QUOTED	":\\,=#\""

/* sudoers nsswitch routines */
struct sudo_nss sudo_nss_file = {
    { NULL, NULL },
    sudo_file_open,
    sudo_file_close,
    sudo_file_parse,
    sudo_file_setdefs,
    sudo_file_lookup,
    sudo_file_display_cmnd,
    sudo_file_display_defaults,
    sudo_file_display_bound_defaults,
    sudo_file_display_privs
};

/*
 * Local prototypes.
 */
static int display_bound_defaults(int dtype, struct lbuf *lbuf);
static void print_member(struct lbuf *lbuf, struct member *m, int alias_type);
static void print_member2(struct lbuf *lbuf, struct member *m,
    const char *separator, int alias_type);

int
sudo_file_open(struct sudo_nss *nss)
{
    debug_decl(sudo_file_open, SUDO_DEBUG_NSS)

    if (def_ignore_local_sudoers)
	debug_return_int(-1);
    nss->handle = open_sudoers(sudoers_file, false, NULL);
    debug_return_int(nss->handle ? 0 : -1);
}

int
sudo_file_close(struct sudo_nss *nss)
{
    debug_decl(sudo_file_close, SUDO_DEBUG_NSS)

    /* Free parser data structures and close sudoers file. */
    init_parser(NULL, false);
    if (nss->handle != NULL) {
	fclose(nss->handle);
	nss->handle = NULL;
	sudoersin = NULL;
    }
    debug_return_int(0);
}

/*
 * Parse the specified sudoers file.
 */
int
sudo_file_parse(struct sudo_nss *nss)
{
    debug_decl(sudo_file_close, SUDO_DEBUG_NSS)

    if (nss->handle == NULL)
	debug_return_int(-1);

    init_parser(sudoers_file, false);
    sudoersin = nss->handle;
    if (sudoersparse() != 0 || parse_error) {
	if (errorlineno != -1) {
	    log_warning(0, N_("parse error in %s near line %d"),
		errorfile, errorlineno);
	} else {
	    log_warning(0, N_("parse error in %s"), errorfile);
	}
	debug_return_int(-1);
    }
    debug_return_int(0);
}

/*
 * Wrapper around update_defaults() for nsswitch code.
 */
int
sudo_file_setdefs(struct sudo_nss *nss)
{
    debug_decl(sudo_file_setdefs, SUDO_DEBUG_NSS)

    if (nss->handle == NULL)
	debug_return_int(-1);

    if (!update_defaults(SETDEF_GENERIC|SETDEF_HOST|SETDEF_USER))
	debug_return_int(-1);
    debug_return_int(0);
}

/*
 * Look up the user in the parsed sudoers file and check to see if they are
 * allowed to run the specified command on this host as the target user.
 */
int
sudo_file_lookup(struct sudo_nss *nss, int validated, int pwflag)
{
    int match, host_match, runas_match, cmnd_match;
    struct cmndspec *cs;
    struct cmndtag *tags = NULL;
    struct privilege *priv;
    struct userspec *us;
    struct member *matching_user;
    debug_decl(sudo_file_lookup, SUDO_DEBUG_NSS)

    if (nss->handle == NULL)
	debug_return_int(validated);

    /*
     * Only check the actual command if pwflag is not set.
     * It is set for the "validate", "list" and "kill" pseudo-commands.
     * Always check the host and user.
     */
    if (pwflag) {
	int nopass;
	enum def_tuple pwcheck;

	pwcheck = (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;
	nopass = (pwcheck == all) ? true : false;

	if (list_pw == NULL)
	    SET(validated, FLAG_NO_CHECK);
	CLR(validated, FLAG_NO_USER);
	CLR(validated, FLAG_NO_HOST);
	match = DENY;
	TAILQ_FOREACH(us, &userspecs, entries) {
	    if (userlist_matches(sudo_user.pw, &us->users) != ALLOW)
		continue;
	    TAILQ_FOREACH(priv, &us->privileges, entries) {
		if (hostlist_matches(&priv->hostlist) != ALLOW)
		    continue;
		TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		    /* Only check the command when listing another user. */
		    if (user_uid == 0 || list_pw == NULL ||
			user_uid == list_pw->pw_uid ||
			cmnd_matches(cs->cmnd) == ALLOW)
			    match = ALLOW;
		    if ((pwcheck == any && cs->tags.nopasswd == true) ||
			(pwcheck == all && cs->tags.nopasswd != true))
			nopass = cs->tags.nopasswd;
		}
	    }
	}
	if (match == ALLOW || user_uid == 0) {
	    /* User has an entry for this host. */
	    SET(validated, VALIDATE_OK);
	} else if (match == DENY)
	    SET(validated, VALIDATE_NOT_OK);
	if (pwcheck == always && def_authenticate)
	    SET(validated, FLAG_CHECK_USER);
	else if (pwcheck == never || nopass == true)
	    def_authenticate = false;
	debug_return_int(validated);
    }

    /* Need to be runas user while stat'ing things. */
    set_perms(PERM_RUNAS);

    match = UNSPEC;
    TAILQ_FOREACH_REVERSE(us, &userspecs, userspec_list, entries) {
	if (userlist_matches(sudo_user.pw, &us->users) != ALLOW)
	    continue;
	CLR(validated, FLAG_NO_USER);
	TAILQ_FOREACH_REVERSE(priv, &us->privileges, privilege_list, entries) {
	    host_match = hostlist_matches(&priv->hostlist);
	    if (host_match == ALLOW)
		CLR(validated, FLAG_NO_HOST);
	    else
		continue;
	    TAILQ_FOREACH_REVERSE(cs, &priv->cmndlist, cmndspec_list, entries) {
		matching_user = NULL;
		runas_match = runaslist_matches(cs->runasuserlist,
		    cs->runasgrouplist, &matching_user, NULL);
		if (runas_match == ALLOW) {
		    cmnd_match = cmnd_matches(cs->cmnd);
		    if (cmnd_match != UNSPEC) {
			match = cmnd_match;
			tags = &cs->tags;
#ifdef HAVE_SELINUX
			/* Set role and type if not specified on command line. */
			if (user_role == NULL)
			    user_role = cs->role ? estrdup(cs->role) : def_role;
			if (user_type == NULL)
			    user_type = cs->type ? estrdup(cs->type) : def_type;
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
			/* Set Solaris privilege sets */
			if (runas_privs == NULL)
			    runas_privs = cs->privs ? estrdup(cs->privs) : def_privs;
			if (runas_limitprivs == NULL)
			    runas_limitprivs = cs->limitprivs ? estrdup(cs->limitprivs) : def_limitprivs;
#endif /* HAVE_PRIV_SET */
			/*
			 * If user is running command as himself,
			 * set runas_pw = sudo_user.pw.
			 * XXX - hack, want more general solution
			 */
			if (matching_user && matching_user->type == MYSELF) {
			    sudo_pw_delref(runas_pw);
			    sudo_pw_addref(sudo_user.pw);
			    runas_pw = sudo_user.pw;
			}
			goto matched2;
		    }
		}
	    }
	}
    }
    matched2:
    if (match == ALLOW) {
	SET(validated, VALIDATE_OK);
	CLR(validated, VALIDATE_NOT_OK);
	if (tags != NULL) {
	    if (tags->nopasswd != UNSPEC)
		def_authenticate = !tags->nopasswd;
	    if (tags->noexec != UNSPEC)
		def_noexec = tags->noexec;
	    if (tags->setenv != UNSPEC)
		def_setenv = tags->setenv;
	    if (tags->log_input != UNSPEC)
		def_log_input = tags->log_input;
	    if (tags->log_output != UNSPEC)
		def_log_output = tags->log_output;
	}
    } else if (match == DENY) {
	SET(validated, VALIDATE_NOT_OK);
	CLR(validated, VALIDATE_OK);
	if (tags != NULL && tags->nopasswd != UNSPEC)
	    def_authenticate = !tags->nopasswd;
    }
    restore_perms();
    debug_return_int(validated);
}

#define	TAG_SET(tt) \
	((tt) != UNSPEC && (tt) != IMPLIED)

#define	TAG_CHANGED(t) \
	(TAG_SET(cs->tags.t) && cs->tags.t != tags->t)

static void
sudo_file_append_cmnd(struct cmndspec *cs, struct cmndtag *tags,
    struct lbuf *lbuf)
{
    debug_decl(sudo_file_append_cmnd, SUDO_DEBUG_NSS)

#ifdef HAVE_PRIV_SET
    if (cs->privs)
	lbuf_append(lbuf, "PRIVS=\"%s\" ", cs->privs);
    if (cs->limitprivs)
	lbuf_append(lbuf, "LIMITPRIVS=\"%s\" ", cs->limitprivs);
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
    if (cs->role)
	lbuf_append(lbuf, "ROLE=%s ", cs->role);
    if (cs->type)
	lbuf_append(lbuf, "TYPE=%s ", cs->type);
#endif /* HAVE_SELINUX */
    if (TAG_CHANGED(setenv)) {
	lbuf_append(lbuf, cs->tags.setenv ? "SETENV: " : "NOSETENV: ");
	tags->setenv = cs->tags.setenv;
    }
    if (TAG_CHANGED(noexec)) {
	lbuf_append(lbuf, cs->tags.noexec ? "NOEXEC: " : "EXEC: ");
	tags->noexec = cs->tags.noexec;
    }
    if (TAG_CHANGED(nopasswd)) {
	lbuf_append(lbuf, cs->tags.nopasswd ? "NOPASSWD: " : "PASSWD: ");
	tags->nopasswd = cs->tags.nopasswd;
    }
    if (TAG_CHANGED(log_input)) {
	lbuf_append(lbuf, cs->tags.log_input ? "LOG_INPUT: " : "NOLOG_INPUT: ");
	tags->log_input = cs->tags.log_input;
    }
    if (TAG_CHANGED(log_output)) {
	lbuf_append(lbuf, cs->tags.log_output ? "LOG_OUTPUT: " : "NOLOG_OUTPUT: ");
	tags->log_output = cs->tags.log_output;
    }
    print_member(lbuf, cs->cmnd, CMNDALIAS);
    debug_return;
}

#define	RUNAS_CHANGED(cs1, cs2) \
	(cs1 == NULL || cs2 == NULL || \
	 cs1->runasuserlist != cs2->runasuserlist || \
	 cs1->runasgrouplist != cs2->runasgrouplist)

static int
sudo_file_display_priv_short(struct passwd *pw, struct userspec *us,
    struct lbuf *lbuf)
{
    struct cmndspec *cs, *prev_cs;
    struct member *m;
    struct privilege *priv;
    struct cmndtag tags;
    int nfound = 0;
    debug_decl(sudo_file_display_priv_short, SUDO_DEBUG_NSS)

    /* gcc -Wuninitialized false positive */
    tags.noexec = UNSPEC;
    tags.setenv = UNSPEC;
    tags.nopasswd = UNSPEC;
    tags.log_input = UNSPEC;
    tags.log_output = UNSPEC;
    TAILQ_FOREACH(priv, &us->privileges, entries) {
	if (hostlist_matches(&priv->hostlist) != ALLOW)
	    continue;
	prev_cs = NULL;
	TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	    if (RUNAS_CHANGED(cs, prev_cs)) {
		if (cs != TAILQ_FIRST(&priv->cmndlist))
		    lbuf_append(lbuf, "\n");
		lbuf_append(lbuf, "    (");
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m != TAILQ_FIRST(cs->runasuserlist))
			    lbuf_append(lbuf, ", ");
			print_member(lbuf, m, RUNASALIAS);
		    }
		} else if (cs->runasgrouplist == NULL) {
		    lbuf_append(lbuf, "%s", def_runas_default);
		} else {
		    lbuf_append(lbuf, "%s", pw->pw_name);
		}
		if (cs->runasgrouplist != NULL) {
		    lbuf_append(lbuf, " : ");
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m != TAILQ_FIRST(cs->runasgrouplist))
			    lbuf_append(lbuf, ", ");
			print_member(lbuf, m, RUNASALIAS);
		    }
		}
		lbuf_append(lbuf, ") ");
		tags.noexec = UNSPEC;
		tags.setenv = UNSPEC;
		tags.nopasswd = UNSPEC;
		tags.log_input = UNSPEC;
		tags.log_output = UNSPEC;
	    } else if (cs != TAILQ_FIRST(&priv->cmndlist)) {
		lbuf_append(lbuf, ", ");
	    }
	    sudo_file_append_cmnd(cs, &tags, lbuf);
	    prev_cs = cs;
	    nfound++;
	}
	lbuf_append(lbuf, "\n");
    }
    debug_return_int(nfound);
}

#define	TAGS_CHANGED(ot, nt) \
	((TAG_SET((nt).setenv) && (nt).setenv != (ot).setenv) || \
	 (TAG_SET((nt).noexec) && (nt).noexec != (ot).noexec) || \
	 (TAG_SET((nt).nopasswd) && (nt).nopasswd != (ot).nopasswd) || \
	 (TAG_SET((nt).log_input) && (nt).log_input != (ot).log_input) || \
	 (TAG_SET((nt).log_output) && (nt).log_output != (ot).log_output))

/*
 * Compare the current cmndspec with the previous one to determine
 * whether we need to start a new long entry for "sudo -ll".
 * Returns true if we should start a new long entry, else false.
 */
static bool
new_long_entry(struct cmndspec *cs, struct cmndspec *prev_cs)
{
    if (prev_cs == NULL)
	return true;
    if (RUNAS_CHANGED(cs, prev_cs) || TAGS_CHANGED(cs->tags, prev_cs->tags))
	return true;
#ifdef HAVE_PRIV_SET
    if (cs->privs && (!prev_cs->privs || strcmp(cs->privs, prev_cs->privs) != 0))
	return true;
    if (cs->limitprivs && (!prev_cs->limitprivs || strcmp(cs->limitprivs, prev_cs->limitprivs) != 0))
	return true;
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
    if (cs->role && (!prev_cs->role || strcmp(cs->role, prev_cs->role) != 0))
	return true;
    if (cs->type && (!prev_cs->type || strcmp(cs->type, prev_cs->type) != 0))
	return true;
#endif /* HAVE_SELINUX */
    return false;
}

static int
sudo_file_display_priv_long(struct passwd *pw, struct userspec *us,
    struct lbuf *lbuf)
{
    struct cmndspec *cs, *prev_cs;
    struct member *m;
    struct privilege *priv;
    int nfound = 0, olen;
    debug_decl(sudo_file_display_priv_long, SUDO_DEBUG_NSS)

    TAILQ_FOREACH(priv, &us->privileges, entries) {
	if (hostlist_matches(&priv->hostlist) != ALLOW)
	    continue;
	prev_cs = NULL;
	TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	    if (new_long_entry(cs, prev_cs)) {
		lbuf_append(lbuf, _("\nSudoers entry:\n"));
		lbuf_append(lbuf, _("    RunAsUsers: "));
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m != TAILQ_FIRST(cs->runasuserlist))
			    lbuf_append(lbuf, ", ");
			print_member(lbuf, m, RUNASALIAS);
		    }
		} else if (cs->runasgrouplist == NULL) {
		    lbuf_append(lbuf, "%s", def_runas_default);
		} else {
		    lbuf_append(lbuf, "%s", pw->pw_name);
		}
		lbuf_append(lbuf, "\n");
		if (cs->runasgrouplist != NULL) {
		    lbuf_append(lbuf, _("    RunAsGroups: "));
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m != TAILQ_FIRST(cs->runasgrouplist))
			    lbuf_append(lbuf, ", ");
			print_member(lbuf, m, RUNASALIAS);
		    }
		    lbuf_append(lbuf, "\n");
		}
		olen = lbuf->len;
		lbuf_append(lbuf, _("    Options: "));
		if (TAG_SET(cs->tags.setenv))
		    lbuf_append(lbuf, "%ssetenv, ", cs->tags.setenv ? "" : "!");
		if (TAG_SET(cs->tags.noexec))
		    lbuf_append(lbuf, "%snoexec, ", cs->tags.noexec ? "" : "!");
		if (TAG_SET(cs->tags.nopasswd))
		    lbuf_append(lbuf, "%sauthenticate, ", cs->tags.nopasswd ? "!" : "");
		if (TAG_SET(cs->tags.log_input))
		    lbuf_append(lbuf, "%slog_input, ", cs->tags.log_input ? "" : "!");
		if (TAG_SET(cs->tags.log_output))
		    lbuf_append(lbuf, "%slog_output, ", cs->tags.log_output ? "" : "!");
		if (lbuf->buf[lbuf->len - 2] == ',') {
		    lbuf->len -= 2;	/* remove trailing ", " */
		    lbuf_append(lbuf, "\n");
		} else {
		    lbuf->len = olen;	/* no options */
		}
#ifdef HAVE_PRIV_SET
		if (cs->privs)
		    lbuf_append(lbuf, "    Privs: %s\n", cs->privs);
		if (cs->limitprivs)
		    lbuf_append(lbuf, "    Limitprivs: %s\n", cs->limitprivs);
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
		if (cs->role)
		    lbuf_append(lbuf, "    Role: %s\n", cs->role);
		if (cs->type)
		    lbuf_append(lbuf, "    Type: %s\n", cs->type);
#endif /* HAVE_SELINUX */
		lbuf_append(lbuf, _("    Commands:\n"));
	    }
	    lbuf_append(lbuf, "\t");
	    print_member2(lbuf, cs->cmnd, "\n\t", CMNDALIAS);
	    lbuf_append(lbuf, "\n");
	    prev_cs = cs;
	    nfound++;
	}
    }
    debug_return_int(nfound);
}

int
sudo_file_display_privs(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf)
{
    struct userspec *us;
    int nfound = 0;
    debug_decl(sudo_file_display_priv, SUDO_DEBUG_NSS)

    if (nss->handle == NULL)
	goto done;

    TAILQ_FOREACH(us, &userspecs, entries) {
	if (userlist_matches(pw, &us->users) != ALLOW)
	    continue;

	if (long_list)
	    nfound += sudo_file_display_priv_long(pw, us, lbuf);
	else
	    nfound += sudo_file_display_priv_short(pw, us, lbuf);
    }
done:
    debug_return_int(nfound);
}

/*
 * Display matching Defaults entries for the given user on this host.
 */
int
sudo_file_display_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf)
{
    struct defaults *d;
    char *prefix;
    int nfound = 0;
    debug_decl(sudo_file_display_defaults, SUDO_DEBUG_NSS)

    if (nss->handle == NULL)
	goto done;

    if (lbuf->len == 0 || isspace((unsigned char)lbuf->buf[lbuf->len - 1]))
	prefix = "    ";
    else
	prefix = ", ";

    TAILQ_FOREACH(d, &defaults, entries) {
	switch (d->type) {
	    case DEFAULTS_HOST:
		if (hostlist_matches(d->binding) != ALLOW)
		    continue;
		break;
	    case DEFAULTS_USER:
		if (userlist_matches(pw, d->binding) != ALLOW)
		    continue;
		break;
	    case DEFAULTS_RUNAS:
	    case DEFAULTS_CMND:
		continue;
	}
	if (d->val != NULL) {
	    lbuf_append(lbuf, "%s%s%s", prefix, d->var,
		d->op == '+' ? "+=" : d->op == '-' ? "-=" : "=");
	    if (strpbrk(d->val, " \t") != NULL) {
		lbuf_append(lbuf, "\"");
		lbuf_append_quoted(lbuf, "\"", "%s", d->val);
		lbuf_append(lbuf, "\"");
	    } else
		lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", d->val);
	} else
	    lbuf_append(lbuf, "%s%s%s", prefix,
		d->op == false ? "!" : "", d->var);
	prefix = ", ";
	nfound++;
    }
done:
    debug_return_int(nfound);
}

/*
 * Display Defaults entries that are per-runas or per-command
 */
int
sudo_file_display_bound_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf)
{
    int nfound = 0;
    debug_decl(sudo_file_display_bound_defaults, SUDO_DEBUG_NSS)

    /* XXX - should only print ones that match what the user can do. */
    nfound += display_bound_defaults(DEFAULTS_RUNAS, lbuf);
    nfound += display_bound_defaults(DEFAULTS_CMND, lbuf);

    debug_return_int(nfound);
}

/*
 * Display Defaults entries of the given type.
 */
static int
display_bound_defaults(int dtype, struct lbuf *lbuf)
{
    struct defaults *d;
    struct member_list *binding = NULL;
    struct member *m;
    char *dsep;
    int atype, nfound = 0;
    debug_decl(display_bound_defaults, SUDO_DEBUG_NSS)

    switch (dtype) {
	case DEFAULTS_HOST:
	    atype = HOSTALIAS;
	    dsep = "@";
	    break;
	case DEFAULTS_USER:
	    atype = USERALIAS;
	    dsep = ":";
	    break;
	case DEFAULTS_RUNAS:
	    atype = RUNASALIAS;
	    dsep = ">";
	    break;
	case DEFAULTS_CMND:
	    atype = CMNDALIAS;
	    dsep = "!";
	    break;
	default:
	    debug_return_int(-1);
    }
    TAILQ_FOREACH(d, &defaults, entries) {
	if (d->type != dtype)
	    continue;

	nfound++;
	if (binding != d->binding) {
	    binding = d->binding;
	    if (nfound != 1)
		lbuf_append(lbuf, "\n");
	    lbuf_append(lbuf, "    Defaults%s", dsep);
	    TAILQ_FOREACH(m, binding, entries) {
		if (m != TAILQ_FIRST(binding))
		    lbuf_append(lbuf, ",");
		print_member(lbuf, m, atype);
		lbuf_append(lbuf, " ");
	    }
	} else
	    lbuf_append(lbuf, ", ");
	if (d->val != NULL) {
	    lbuf_append(lbuf, "%s%s%s", d->var, d->op == '+' ? "+=" :
		d->op == '-' ? "-=" : "=", d->val);
	} else
	    lbuf_append(lbuf, "%s%s", d->op == false ? "!" : "", d->var);
    }

    debug_return_int(nfound);
}

int
sudo_file_display_cmnd(struct sudo_nss *nss, struct passwd *pw)
{
    struct cmndspec *cs;
    struct member *match;
    struct privilege *priv;
    struct userspec *us;
    int rval = 1;
    int host_match, runas_match, cmnd_match;
    debug_decl(sudo_file_display_cmnd, SUDO_DEBUG_NSS)

    if (nss->handle == NULL)
	goto done;

    match = NULL;
    TAILQ_FOREACH_REVERSE(us, &userspecs, userspec_list, entries) {
	if (userlist_matches(pw, &us->users) != ALLOW)
	    continue;

	TAILQ_FOREACH_REVERSE(priv, &us->privileges, privilege_list, entries) {
	    host_match = hostlist_matches(&priv->hostlist);
	    if (host_match != ALLOW)
		continue;
	    TAILQ_FOREACH_REVERSE(cs, &priv->cmndlist, cmndspec_list, entries) {
		runas_match = runaslist_matches(cs->runasuserlist,
		    cs->runasgrouplist, NULL, NULL);
		if (runas_match == ALLOW) {
		    cmnd_match = cmnd_matches(cs->cmnd);
		    if (cmnd_match != UNSPEC) {
			if (cmnd_match == ALLOW)
			    match = cs->cmnd;
			goto matched;
		    }
		}
	    }
	}
    }
    matched:
    if (match != NULL && !match->negated) {
	sudo_printf(SUDO_CONV_INFO_MSG, "%s%s%s\n",
	    safe_cmnd, user_args ? " " : "", user_args ? user_args : "");
	rval = 0;
    }
done:
    debug_return_int(rval);
}

/*
 * Print the contents of a struct member to stdout
 */
static void
_print_member(struct lbuf *lbuf, char *name, int type, int negated,
    const char *separator, int alias_type)
{
    struct alias *a;
    struct member *m;
    struct sudo_command *c;
    debug_decl(_print_member, SUDO_DEBUG_NSS)

    switch (type) {
	case ALL:
	    lbuf_append(lbuf, "%sALL", negated ? "!" : "");
	    break;
	case MYSELF:
	    lbuf_append(lbuf, "%s%s", negated ? "!" : "", user_name);
	    break;
	case COMMAND:
	    c = (struct sudo_command *) name;
	    if (negated)
		lbuf_append(lbuf, "!");
	    lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", c->cmnd);
	    if (c->args) {
		lbuf_append(lbuf, " ");
		lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", c->args);
	    }
	    break;
	case ALIAS:
	    if ((a = alias_get(name, alias_type)) != NULL) {
		TAILQ_FOREACH(m, &a->members, entries) {
		    if (m != TAILQ_FIRST(&a->members))
			lbuf_append(lbuf, "%s", separator);
		    _print_member(lbuf, m->name, m->type,
			negated ? !m->negated : m->negated, separator,
			alias_type);
		}
		alias_put(a);
		break;
	    }
	    /* FALLTHROUGH */
	default:
	    lbuf_append(lbuf, "%s%s", negated ? "!" : "", name);
	    break;
    }
    debug_return;
}

static void
print_member(struct lbuf *lbuf, struct member *m, int alias_type)
{
    _print_member(lbuf, m->name, m->type, m->negated, ", ", alias_type);
}

static void
print_member2(struct lbuf *lbuf, struct member *m, const char *separator,
    int alias_type)
{
    _print_member(lbuf, m->name, m->type, m->negated, separator, alias_type);
}
