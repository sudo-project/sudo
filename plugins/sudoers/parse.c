/*
 * Copyright (c) 2004-2005, 2007-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "parse.h"
#include "sudo_lbuf.h"
#include <gram.h>

/* Characters that must be quoted in sudoers */
#define	SUDOERS_QUOTED	":\\,=#\""

/*
 * Local prototypes.
 */
static int display_bound_defaults(int dtype, struct sudo_lbuf *lbuf);
static int sudo_file_close(struct sudo_nss *);
static int sudo_file_display_bound_defaults(struct sudo_nss *, struct passwd *, struct sudo_lbuf *);
static int sudo_file_display_cmnd(struct sudo_nss *, struct passwd *);
static int sudo_file_display_defaults(struct sudo_nss *, struct passwd *, struct sudo_lbuf *);
static int sudo_file_display_privs(struct sudo_nss *, struct passwd *, struct sudo_lbuf *);
static int sudo_file_lookup(struct sudo_nss *, int, int);
static int sudo_file_open(struct sudo_nss *);
static int sudo_file_parse(struct sudo_nss *);
static int sudo_file_setdefs(struct sudo_nss *);
static void print_member(struct sudo_lbuf *lbuf, struct member *m, int alias_type);
static void print_member_sep(struct sudo_lbuf *lbuf, struct member *m, const char *separator, int alias_type);

/* sudo_nss implementation */
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

int
sudo_file_open(struct sudo_nss *nss)
{
    debug_decl(sudo_file_open, SUDOERS_DEBUG_NSS)

    if (def_ignore_local_sudoers)
	debug_return_int(-1);
    nss->handle = open_sudoers(sudoers_file, false, NULL);
    debug_return_int(nss->handle ? 0 : -1);
}

int
sudo_file_close(struct sudo_nss *nss)
{
    debug_decl(sudo_file_close, SUDOERS_DEBUG_NSS)

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
    debug_decl(sudo_file_close, SUDOERS_DEBUG_NSS)

    if (nss->handle == NULL)
	debug_return_int(-1);

    init_parser(sudoers_file, false);
    sudoersin = nss->handle;
    if (sudoersparse() != 0 || parse_error) {
	if (errorlineno != -1) {
	    log_warningx(SLOG_SEND_MAIL, N_("parse error in %s near line %d"),
		errorfile, errorlineno);
	} else {
	    log_warningx(SLOG_SEND_MAIL, N_("parse error in %s"), errorfile);
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
    debug_decl(sudo_file_setdefs, SUDOERS_DEBUG_NSS)

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
    debug_decl(sudo_file_lookup, SUDOERS_DEBUG_NSS)

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
		if (hostlist_matches(sudo_user.pw, &priv->hostlist) != ALLOW)
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
	    SET(validated, VALIDATE_SUCCESS);
	} else if (match == DENY)
	    SET(validated, VALIDATE_FAILURE);
	if (pwcheck == always && def_authenticate)
	    SET(validated, FLAG_CHECK_USER);
	else if (nopass == true)
	    SET(validated, FLAG_NOPASSWD);
	debug_return_int(validated);
    }

    /* Need to be runas user while stat'ing things. */
    if (!set_perms(PERM_RUNAS))
	debug_return_int(validated);

    match = UNSPEC;
    TAILQ_FOREACH_REVERSE(us, &userspecs, userspec_list, entries) {
	if (userlist_matches(sudo_user.pw, &us->users) != ALLOW)
	    continue;
	CLR(validated, FLAG_NO_USER);
	TAILQ_FOREACH_REVERSE(priv, &us->privileges, privilege_list, entries) {
	    host_match = hostlist_matches(sudo_user.pw, &priv->hostlist);
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
			if (user_role == NULL) {
			    if (cs->role != NULL) {
				user_role = strdup(cs->role);
				if (user_role == NULL) {
				    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
				    SET(validated, VALIDATE_ERROR);
				    goto done;
				}
			    } else {
				user_role = def_role;
			    }
			}
			if (user_type == NULL) {
			    if (cs->type != NULL) {
				user_type = strdup(cs->type);
				if (user_type == NULL) {
				    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
				    SET(validated, VALIDATE_ERROR);
				    goto done;
				}
			    } else {
				user_type = def_type;
			    }
			}
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
			/* Set Solaris privilege sets */
			if (runas_privs == NULL) {
			    if (cs->privs != NULL) {
				runas_privs = strdup(cs->privs);
				if (runas_privs == NULL) {
				    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
				    SET(validated, VALIDATE_ERROR);
				    goto done;
				}
			    } else {
				runas_privs = def_privs;
			    }
			}
			if (runas_limitprivs == NULL) {
			    if (cs->limitprivs != NULL) {
				runas_limitprivs = strdup(cs->limitprivs);
				if (runas_limitprivs == NULL) {
				    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
				    SET(validated, VALIDATE_ERROR);
				    goto done;
				}
			    } else {
				runas_limitprivs = def_limitprivs;
			    }
			}
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
	SET(validated, VALIDATE_SUCCESS);
	CLR(validated, VALIDATE_FAILURE);
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
	    if (tags->send_mail != UNSPEC) {
		if (tags->send_mail) {
		    def_mail_all_cmnds = true;
		} else {
		    def_mail_all_cmnds = false;
		    def_mail_always = false;
		    def_mail_no_perms = false;
		}
	    }
	    if (tags->follow != UNSPEC)
		def_sudoedit_follow = tags->follow;
	}
    } else if (match == DENY) {
	SET(validated, VALIDATE_FAILURE);
	CLR(validated, VALIDATE_SUCCESS);
	if (tags != NULL) {
	    if (tags->nopasswd != UNSPEC)
		def_authenticate = !tags->nopasswd;
	    if (tags->send_mail != UNSPEC) {
		if (tags->send_mail) {
		    def_mail_all_cmnds = true;
		} else {
		    def_mail_all_cmnds = false;
		    def_mail_always = false;
		    def_mail_no_perms = false;
		}
	    }
	}
    }
#if defined(HAVE_SELINUX) || defined(HAVE_PRIV_SET)
done:
#endif
    if (!restore_perms())
	SET(validated, VALIDATE_ERROR);
    debug_return_int(validated);
}

#define	TAG_CHANGED(t) \
	(TAG_SET(cs->tags.t) && cs->tags.t != tags->t)

static bool
sudo_file_append_cmnd(struct cmndspec *cs, struct cmndtag *tags,
    struct sudo_lbuf *lbuf)
{
    debug_decl(sudo_file_append_cmnd, SUDOERS_DEBUG_NSS)

#ifdef HAVE_PRIV_SET
    if (cs->privs)
	sudo_lbuf_append(lbuf, "PRIVS=\"%s\" ", cs->privs);
    if (cs->limitprivs)
	sudo_lbuf_append(lbuf, "LIMITPRIVS=\"%s\" ", cs->limitprivs);
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
    if (cs->role)
	sudo_lbuf_append(lbuf, "ROLE=%s ", cs->role);
    if (cs->type)
	sudo_lbuf_append(lbuf, "TYPE=%s ", cs->type);
#endif /* HAVE_SELINUX */
    if (TAG_CHANGED(setenv)) {
	tags->setenv = cs->tags.setenv;
	sudo_lbuf_append(lbuf, tags->setenv ? "SETENV: " : "NOSETENV: ");
    }
    if (TAG_CHANGED(noexec)) {
	tags->noexec = cs->tags.noexec;
	sudo_lbuf_append(lbuf, tags->noexec ? "NOEXEC: " : "EXEC: ");
    }
    if (TAG_CHANGED(nopasswd)) {
	tags->nopasswd = cs->tags.nopasswd;
	sudo_lbuf_append(lbuf, tags->nopasswd ? "NOPASSWD: " : "PASSWD: ");
    }
    if (TAG_CHANGED(log_input)) {
	tags->log_input = cs->tags.log_input;
	sudo_lbuf_append(lbuf, tags->log_input ? "LOG_INPUT: " : "NOLOG_INPUT: ");
    }
    if (TAG_CHANGED(log_output)) {
	tags->log_output = cs->tags.log_output;
	sudo_lbuf_append(lbuf, tags->log_output ? "LOG_OUTPUT: " : "NOLOG_OUTPUT: ");
    }
    if (TAG_CHANGED(send_mail)) {
	tags->send_mail = cs->tags.send_mail;
	sudo_lbuf_append(lbuf, tags->send_mail ? "MAIL: " : "NOMAIL: ");
    }
    if (TAG_CHANGED(follow)) {
	tags->follow = cs->tags.follow;
	sudo_lbuf_append(lbuf, tags->follow ? "FOLLOW: " : "NOFOLLOW: ");
    }
    print_member(lbuf, cs->cmnd, CMNDALIAS);
    debug_return_bool(!sudo_lbuf_error(lbuf));
}

static int
sudo_file_display_priv_short(struct passwd *pw, struct userspec *us,
    struct sudo_lbuf *lbuf)
{
    struct cmndspec *cs, *prev_cs;
    struct member *m;
    struct privilege *priv;
    struct cmndtag tags;
    int nfound = 0;
    debug_decl(sudo_file_display_priv_short, SUDOERS_DEBUG_NSS)

    /* gcc -Wuninitialized false positive */
    TAGS_INIT(tags);
    TAILQ_FOREACH(priv, &us->privileges, entries) {
	if (hostlist_matches(pw, &priv->hostlist) != ALLOW)
	    continue;
	prev_cs = NULL;
	TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	    if (prev_cs == NULL || RUNAS_CHANGED(cs, prev_cs)) {
		if (cs != TAILQ_FIRST(&priv->cmndlist))
		    sudo_lbuf_append(lbuf, "\n");
		sudo_lbuf_append(lbuf, "    (");
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m != TAILQ_FIRST(cs->runasuserlist))
			    sudo_lbuf_append(lbuf, ", ");
			print_member(lbuf, m, RUNASALIAS);
		    }
		} else if (cs->runasgrouplist == NULL) {
		    sudo_lbuf_append(lbuf, "%s", def_runas_default);
		} else {
		    sudo_lbuf_append(lbuf, "%s", pw->pw_name);
		}
		if (cs->runasgrouplist != NULL) {
		    sudo_lbuf_append(lbuf, " : ");
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m != TAILQ_FIRST(cs->runasgrouplist))
			    sudo_lbuf_append(lbuf, ", ");
			print_member(lbuf, m, RUNASALIAS);
		    }
		}
		sudo_lbuf_append(lbuf, ") ");
		TAGS_INIT(tags);
	    } else if (cs != TAILQ_FIRST(&priv->cmndlist)) {
		sudo_lbuf_append(lbuf, ", ");
	    }
	    sudo_file_append_cmnd(cs, &tags, lbuf);
	    prev_cs = cs;
	    nfound++;
	}
	sudo_lbuf_append(lbuf, "\n");
    }
    debug_return_int(nfound);
}

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
    struct sudo_lbuf *lbuf)
{
    struct cmndspec *cs, *prev_cs;
    struct member *m;
    struct privilege *priv;
    int nfound = 0, olen;
    debug_decl(sudo_file_display_priv_long, SUDOERS_DEBUG_NSS)

    TAILQ_FOREACH(priv, &us->privileges, entries) {
	if (hostlist_matches(pw, &priv->hostlist) != ALLOW)
	    continue;
	prev_cs = NULL;
	TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	    if (new_long_entry(cs, prev_cs)) {
		sudo_lbuf_append(lbuf, _("\nSudoers entry:\n"));
		sudo_lbuf_append(lbuf, _("    RunAsUsers: "));
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m != TAILQ_FIRST(cs->runasuserlist))
			    sudo_lbuf_append(lbuf, ", ");
			print_member(lbuf, m, RUNASALIAS);
		    }
		} else if (cs->runasgrouplist == NULL) {
		    sudo_lbuf_append(lbuf, "%s", def_runas_default);
		} else {
		    sudo_lbuf_append(lbuf, "%s", pw->pw_name);
		}
		sudo_lbuf_append(lbuf, "\n");
		if (cs->runasgrouplist != NULL) {
		    sudo_lbuf_append(lbuf, _("    RunAsGroups: "));
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m != TAILQ_FIRST(cs->runasgrouplist))
			    sudo_lbuf_append(lbuf, ", ");
			print_member(lbuf, m, RUNASALIAS);
		    }
		    sudo_lbuf_append(lbuf, "\n");
		}
		olen = lbuf->len;
		sudo_lbuf_append(lbuf, _("    Options: "));
		if (TAG_SET(cs->tags.setenv))
		    sudo_lbuf_append(lbuf, "%ssetenv, ", cs->tags.setenv ? "" : "!");
		if (TAG_SET(cs->tags.noexec))
		    sudo_lbuf_append(lbuf, "%snoexec, ", cs->tags.noexec ? "" : "!");
		if (TAG_SET(cs->tags.nopasswd))
		    sudo_lbuf_append(lbuf, "%sauthenticate, ", cs->tags.nopasswd ? "!" : "");
		if (TAG_SET(cs->tags.log_input))
		    sudo_lbuf_append(lbuf, "%slog_input, ", cs->tags.log_input ? "" : "!");
		if (TAG_SET(cs->tags.log_output))
		    sudo_lbuf_append(lbuf, "%slog_output, ", cs->tags.log_output ? "" : "!");
		if (lbuf->buf[lbuf->len - 2] == ',') {
		    lbuf->len -= 2;	/* remove trailing ", " */
		    sudo_lbuf_append(lbuf, "\n");
		} else {
		    lbuf->len = olen;	/* no options */
		}
#ifdef HAVE_PRIV_SET
		if (cs->privs)
		    sudo_lbuf_append(lbuf, "    Privs: %s\n", cs->privs);
		if (cs->limitprivs)
		    sudo_lbuf_append(lbuf, "    Limitprivs: %s\n", cs->limitprivs);
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
		if (cs->role)
		    sudo_lbuf_append(lbuf, "    Role: %s\n", cs->role);
		if (cs->type)
		    sudo_lbuf_append(lbuf, "    Type: %s\n", cs->type);
#endif /* HAVE_SELINUX */
		sudo_lbuf_append(lbuf, _("    Commands:\n"));
	    }
	    sudo_lbuf_append(lbuf, "\t");
	    print_member_sep(lbuf, cs->cmnd, "\n\t", CMNDALIAS);
	    sudo_lbuf_append(lbuf, "\n");
	    prev_cs = cs;
	    nfound++;
	}
    }
    debug_return_int(nfound);
}

/*
 * Returns the number of matching privileges or -1 on error.
 */
int
sudo_file_display_privs(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf)
{
    struct userspec *us;
    int nfound = 0;
    debug_decl(sudo_file_display_priv, SUDOERS_DEBUG_NSS)

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
    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
done:
    debug_return_int(nfound);
}

/*
 * Display matching Defaults entries for the given user on this host.
 */
int
sudo_file_display_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf)
{
    struct defaults *d;
    char *prefix;
    int nfound = 0;
    debug_decl(sudo_file_display_defaults, SUDOERS_DEBUG_NSS)

    if (nss->handle == NULL)
	goto done;

    if (lbuf->len == 0 || isspace((unsigned char)lbuf->buf[lbuf->len - 1]))
	prefix = "    ";
    else
	prefix = ", ";

    TAILQ_FOREACH(d, &defaults, entries) {
	switch (d->type) {
	    case DEFAULTS_HOST:
		if (hostlist_matches(pw, d->binding) != ALLOW)
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
	    sudo_lbuf_append(lbuf, "%s%s%s", prefix, d->var,
		d->op == '+' ? "+=" : d->op == '-' ? "-=" : "=");
	    if (strpbrk(d->val, " \t") != NULL) {
		sudo_lbuf_append(lbuf, "\"");
		sudo_lbuf_append_quoted(lbuf, "\"", "%s", d->val);
		sudo_lbuf_append(lbuf, "\"");
	    } else
		sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", d->val);
	} else
	    sudo_lbuf_append(lbuf, "%s%s%s", prefix,
		d->op == false ? "!" : "", d->var);
	prefix = ", ";
	nfound++;
    }
    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
done:
    debug_return_int(nfound);
}

/*
 * Display Defaults entries that are per-runas or per-command
 */
int
sudo_file_display_bound_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf)
{
    int nfound = 0;
    debug_decl(sudo_file_display_bound_defaults, SUDOERS_DEBUG_NSS)

    /* XXX - should only print ones that match what the user can do. */
    nfound += display_bound_defaults(DEFAULTS_RUNAS, lbuf);
    nfound += display_bound_defaults(DEFAULTS_CMND, lbuf);

    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(nfound);
}

/*
 * Display Defaults entries of the given type.
 */
static int
display_bound_defaults(int dtype, struct sudo_lbuf *lbuf)
{
    struct defaults *d;
    struct member_list *binding = NULL;
    struct member *m;
    char *dsep;
    int atype, nfound = 0;
    debug_decl(display_bound_defaults, SUDOERS_DEBUG_NSS)

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
		sudo_lbuf_append(lbuf, "\n");
	    sudo_lbuf_append(lbuf, "    Defaults%s", dsep);
	    TAILQ_FOREACH(m, binding, entries) {
		if (m != TAILQ_FIRST(binding))
		    sudo_lbuf_append(lbuf, ",");
		print_member(lbuf, m, atype);
		sudo_lbuf_append(lbuf, " ");
	    }
	} else
	    sudo_lbuf_append(lbuf, ", ");
	if (d->val != NULL) {
	    sudo_lbuf_append(lbuf, "%s%s%s", d->var, d->op == '+' ? "+=" :
		d->op == '-' ? "-=" : "=", d->val);
	} else
	    sudo_lbuf_append(lbuf, "%s%s", d->op == false ? "!" : "", d->var);
    }

    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(nfound);
}

/*
 * Returns 0 if the command is allowed, 1 if not or -1 on error.
 */
int
sudo_file_display_cmnd(struct sudo_nss *nss, struct passwd *pw)
{
    struct cmndspec *cs;
    struct member *match;
    struct privilege *priv;
    struct userspec *us;
    int rval = 1;
    int host_match, runas_match, cmnd_match;
    debug_decl(sudo_file_display_cmnd, SUDOERS_DEBUG_NSS)

    if (nss->handle == NULL)
	goto done;

    match = NULL;
    TAILQ_FOREACH_REVERSE(us, &userspecs, userspec_list, entries) {
	if (userlist_matches(pw, &us->users) != ALLOW)
	    continue;

	TAILQ_FOREACH_REVERSE(priv, &us->privileges, privilege_list, entries) {
	    host_match = hostlist_matches(pw, &priv->hostlist);
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
	const int len = sudo_printf(SUDO_CONV_INFO_MSG, "%s%s%s\n",
	    safe_cmnd, user_args ? " " : "", user_args ? user_args : "");
	rval = len < 0 ? -1 : 0;
    }
done:
    debug_return_int(rval);
}

/*
 * Print the contents of a struct member to stdout
 */
static void
print_member_int(struct sudo_lbuf *lbuf, char *name, int type, int negated,
    const char *separator, int alias_type)
{
    struct alias *a;
    struct member *m;
    struct sudo_command *c;
    debug_decl(print_member_int, SUDOERS_DEBUG_NSS)

    switch (type) {
	case ALL:
	    sudo_lbuf_append(lbuf, "%sALL", negated ? "!" : "");
	    break;
	case MYSELF:
	    sudo_lbuf_append(lbuf, "%s%s", negated ? "!" : "", user_name);
	    break;
	case COMMAND:
	    c = (struct sudo_command *) name;
	    if (negated)
		sudo_lbuf_append(lbuf, "!");
	    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", c->cmnd);
	    if (c->args) {
		sudo_lbuf_append(lbuf, " ");
		sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", c->args);
	    }
	    break;
	case ALIAS:
	    if ((a = alias_get(name, alias_type)) != NULL) {
		TAILQ_FOREACH(m, &a->members, entries) {
		    if (m != TAILQ_FIRST(&a->members))
			sudo_lbuf_append(lbuf, "%s", separator);
		    print_member_int(lbuf, m->name, m->type,
			negated ? !m->negated : m->negated, separator,
			alias_type);
		}
		alias_put(a);
		break;
	    }
	    /* FALLTHROUGH */
	default:
	    sudo_lbuf_append(lbuf, "%s%s", negated ? "!" : "", name);
	    break;
    }
    debug_return;
}

static void
print_member(struct sudo_lbuf *lbuf, struct member *m, int alias_type)
{
    print_member_int(lbuf, m->name, m->type, m->negated, ", ", alias_type);
}

static void
print_member_sep(struct sudo_lbuf *lbuf, struct member *m,
    const char *separator, int alias_type)
{
    print_member_int(lbuf, m->name, m->type, m->negated, separator, alias_type);
}
