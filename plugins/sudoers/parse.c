/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2004-2005, 2007-2023 Todd C. Miller <Todd.Miller@sudo.ws>
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
 */

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "sudoers.h"
#include <gram.h>

static int
runas_matches_pw(struct sudoers_parse_tree *parse_tree,
    const struct cmndspec *cs, const struct passwd *pw)
{
    debug_decl(runas_matches_pw, SUDOERS_DEBUG_PARSER);

    if (cs->runasuserlist != NULL)
	debug_return_int(userlist_matches(parse_tree, pw, cs->runasuserlist));

    if (cs->runasgrouplist == NULL) {
	/* No explicit runas user or group, use default. */
	if (userpw_matches(def_runas_default, pw->pw_name, pw))
	    debug_return_int(ALLOW);
    }
    debug_return_int(UNSPEC);
}

/*
 * Look up the user in the sudoers parse tree for pseudo-commands like
 * list, verify and kill.
 */
static int
sudoers_lookup_pseudo(struct sudo_nss_list *snl, struct passwd *pw, int pwflag)
{
    char *saved_runchroot;
    struct passwd *root_pw = NULL;
    struct sudo_nss *nss;
    struct cmndspec *cs;
    struct privilege *priv;
    struct userspec *us;
    struct defaults *def;
    int cmnd_match, nopass, match = DENY;
    int validated = 0;
    enum def_tuple pwcheck;
    debug_decl(sudoers_lookup_pseudo, SUDOERS_DEBUG_PARSER);

    pwcheck = (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;
    nopass = (pwcheck == never || pwcheck == all) ? true : false;

    if (list_pw != NULL) {
	root_pw = sudo_getpwuid(ROOT_UID);
	if (root_pw == NULL)
	    log_warningx(SLOG_SEND_MAIL, N_("unknown uid %u"), ROOT_UID);
    } else {
	SET(validated, FLAG_NO_CHECK);
    }

    /* Don't use chroot setting for pseudo-commands. */
    saved_runchroot = def_runchroot;
    def_runchroot = NULL;

    TAILQ_FOREACH(nss, snl, entries) {
	if (nss->query(nss, pw) == -1) {
	    /* The query function should have printed an error message. */
	    SET(validated, VALIDATE_ERROR);
	    break;
	}
	TAILQ_FOREACH(us, &nss->parse_tree->userspecs, entries) {
	    if (userlist_matches(nss->parse_tree, pw, &us->users) != ALLOW)
		continue;
	    TAILQ_FOREACH(priv, &us->privileges, entries) {
		int priv_nopass = UNSPEC;

		if (hostlist_matches(nss->parse_tree, pw, &priv->hostlist) != ALLOW)
		    continue;
		TAILQ_FOREACH(def, &priv->defaults, entries) {
		    if (strcmp(def->var, "authenticate") == 0)
			priv_nopass = !def->op;
		}
		TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		    if (pwcheck == any) {
			if (cs->tags.nopasswd == true || priv_nopass == true)
			    nopass = true;
		    } else if (pwcheck == all) {
			if (cs->tags.nopasswd != true && priv_nopass != true)
			    nopass = false;
		    }
		    if (match == ALLOW)
			continue;

		    /*
		     * Root can list any user's privileges.
		     * A user may always list their own privileges.
		     */
		    if (user_uid == 0 || list_pw == NULL ||
			    user_uid == list_pw->pw_uid) {
			match = ALLOW;
			continue;
		    }

		    /*
		     * To list another user's prilileges, the runas
		     * user must match the list user or root.
		     */
		    switch (runas_matches_pw(nss->parse_tree, cs, list_pw)) {
		    case DENY:
			break;
		    case ALLOW:
			/*
			 * RunAs user matches list user.
			 * Match on command "list" or ALL.
			 */
			cmnd_match = cmnd_matches(nss->parse_tree,
			    cs->cmnd, cs->runchroot, NULL);
			if (cmnd_match != UNSPEC) {
			    match = cmnd_match;
			    goto done;
			}
			break;
		    default:
			/*
			 * RunAs user doesn't match list user.  Only allow
			 * listing if the user has "sudo ALL" for root.
			 */
			if (root_pw != NULL && runas_matches_pw(nss->parse_tree,
				cs, root_pw) == ALLOW) {
			    cmnd_match = cmnd_matches_all(nss->parse_tree,
				cs->cmnd, cs->runchroot, NULL);
			    if (cmnd_match != UNSPEC) {
				match = cmnd_match;
				goto done;
			    }
			}
			break;
		    }
		}
	    }
	}
    }
done:
    if (root_pw != NULL)
	sudo_pw_delref(root_pw);
    if (match == ALLOW || user_uid == 0) {
	/* User has an entry for this host. */
	SET(validated, VALIDATE_SUCCESS);
    } else if (match == DENY)
	SET(validated, VALIDATE_FAILURE);
    if (pwcheck == always && def_authenticate)
	SET(validated, FLAG_CHECK_USER);
    else if (nopass == true)
	def_authenticate = false;

    /* Restore original def_runchroot. */
    def_runchroot = saved_runchroot;

    debug_return_int(validated);
}

static void
init_cmnd_info(struct cmnd_info *info)
{
    memset(info, 0, sizeof(*info));
    if (def_intercept || ISSET(sudo_mode, MODE_POLICY_INTERCEPTED))
	info->intercepted = true;
}

static int
sudoers_lookup_check(struct sudo_nss *nss, struct passwd *pw,
    int *validated, struct cmnd_info *info, struct cmndspec **matching_cs,
    struct defaults_list **defs, time_t now)
{
    int host_match, runas_match, cmnd_match;
    struct cmndspec *cs;
    struct privilege *priv;
    struct userspec *us;
    struct member *matching_user;
    debug_decl(sudoers_lookup_check, SUDOERS_DEBUG_PARSER);

    init_cmnd_info(info);

    TAILQ_FOREACH_REVERSE(us, &nss->parse_tree->userspecs, userspec_list, entries) {
	if (userlist_matches(nss->parse_tree, pw, &us->users) != ALLOW)
	    continue;
	CLR(*validated, FLAG_NO_USER);
	TAILQ_FOREACH_REVERSE(priv, &us->privileges, privilege_list, entries) {
	    host_match = hostlist_matches(nss->parse_tree, pw, &priv->hostlist);
	    if (host_match == ALLOW)
		CLR(*validated, FLAG_NO_HOST);
	    else
		continue;
	    TAILQ_FOREACH_REVERSE(cs, &priv->cmndlist, cmndspec_list, entries) {
		if (cs->notbefore != UNSPEC) {
		    if (now < cs->notbefore)
			continue;
		}
		if (cs->notafter != UNSPEC) {
		    if (now > cs->notafter)
			continue;
		}
		matching_user = NULL;
		runas_match = runaslist_matches(nss->parse_tree,
		    cs->runasuserlist, cs->runasgrouplist, &matching_user,
		    NULL);
		if (runas_match == ALLOW) {
		    cmnd_match = cmnd_matches(nss->parse_tree, cs->cmnd,
			cs->runchroot, info);
		    if (cmnd_match != UNSPEC) {
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
			*matching_cs = cs;
			*defs = &priv->defaults;
			sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
			    "userspec matched @ %s:%d:%d: %s",
			    us->file ? us->file : "???", us->line, us->column,
			    cmnd_match ? "allowed" : "denied");
			debug_return_int(cmnd_match);
		    }
		    free(info->cmnd_path);
		    init_cmnd_info(info);
		}
	    }
	}
    }
    debug_return_int(UNSPEC);
}

/*
 * Apply cmndspec-specific settings including SELinux role/type,
 * Solaris privs, and command tags.
 */
static bool
apply_cmndspec(struct cmndspec *cs)
{
    debug_decl(apply_cmndspec, SUDOERS_DEBUG_PARSER);

    if (cs != NULL) {
#ifdef HAVE_SELINUX
	/* Set role and type if not specified on command line. */
	if (user_role == NULL) {
	    if (cs->role != NULL) {
		user_role = strdup(cs->role);
		if (user_role == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    debug_return_bool(false);
		}
	    } else {
		user_role = def_role;
		def_role = NULL;
	    }
	    if (user_role != NULL) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "user_role -> %s", user_role);
	    }
	}
	if (user_type == NULL) {
	    if (cs->type != NULL) {
		user_type = strdup(cs->type);
		if (user_type == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    debug_return_bool(false);
		}
	    } else {
		user_type = def_type;
		def_type = NULL;
	    }
	    if (user_type != NULL) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "user_type -> %s", user_type);
	    }
	}
#endif /* HAVE_SELINUX */
#ifdef HAVE_APPARMOR
	/* Set AppArmor profile, if specified */
	if (cs->apparmor_profile != NULL) {
	    user_apparmor_profile = strdup(cs->apparmor_profile);
	    if (user_apparmor_profile == NULL) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		debug_return_bool(false);
	    }
	} else {
	    user_apparmor_profile = def_apparmor_profile;
	    def_apparmor_profile = NULL;
	}
	if (user_apparmor_profile != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"user_apparmor_profile -> %s", user_apparmor_profile);
	}
#endif
#ifdef HAVE_PRIV_SET
	/* Set Solaris privilege sets */
	if (runas_privs == NULL) {
	    if (cs->privs != NULL) {
		runas_privs = strdup(cs->privs);
		if (runas_privs == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    debug_return_bool(false);
		}
	    } else {
		runas_privs = def_privs;
		def_privs = NULL;
	    }
	    if (runas_privs != NULL) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "runas_privs -> %s", runas_privs);
	    }
	}
	if (runas_limitprivs == NULL) {
	    if (cs->limitprivs != NULL) {
		runas_limitprivs = strdup(cs->limitprivs);
		if (runas_limitprivs == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    debug_return_bool(false);
		}
	    } else {
		runas_limitprivs = def_limitprivs;
		def_limitprivs = NULL;
	    }
	    if (runas_limitprivs != NULL) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "runas_limitprivs -> %s", runas_limitprivs);
	    }
	}
#endif /* HAVE_PRIV_SET */
	if (cs->timeout > 0) {
	    def_command_timeout = cs->timeout;
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_command_timeout -> %d", def_command_timeout);
	}
	if (cs->runcwd != NULL) {
	    free(def_runcwd);
	    def_runcwd = strdup(cs->runcwd);
	    if (def_runcwd == NULL) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		debug_return_bool(false);
	    }
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_runcwd -> %s", def_runcwd);
	}
	if (cs->runchroot != NULL) {
	    free(def_runchroot);
	    def_runchroot = strdup(cs->runchroot);
	    if (def_runchroot == NULL) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		debug_return_bool(false);
	    }
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_runchroot -> %s", def_runchroot);
	}
	if (cs->tags.nopasswd != UNSPEC) {
	    def_authenticate = !cs->tags.nopasswd;
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_authenticate -> %s", def_authenticate ? "true" : "false");
	}
	if (cs->tags.noexec != UNSPEC) {
	    def_noexec = cs->tags.noexec;
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_noexec -> %s", def_noexec ? "true" : "false");
	}
	if (cs->tags.intercept != UNSPEC) {
	    def_intercept = cs->tags.intercept;
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_intercept -> %s", def_intercept ? "true" : "false");
	}
	if (cs->tags.setenv != UNSPEC) {
	    def_setenv = cs->tags.setenv;
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_setenv -> %s", def_setenv ? "true" : "false");
	}
	if (cs->tags.log_input != UNSPEC) {
	    def_log_input = cs->tags.log_input;
	    cb_log_input(NULL, 0, 0, NULL, cs->tags.log_input);
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_log_input -> %s", def_log_input ? "true" : "false");
	}
	if (cs->tags.log_output != UNSPEC) {
	    def_log_output = cs->tags.log_output;
	    cb_log_output(NULL, 0, 0, NULL, cs->tags.log_output);
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_log_output -> %s", def_log_output ? "true" : "false");
	}
	if (cs->tags.send_mail != UNSPEC) {
	    if (cs->tags.send_mail) {
		def_mail_all_cmnds = true;
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "def_mail_all_cmnds -> true");
	    } else {
		def_mail_all_cmnds = false;
		def_mail_always = false;
		def_mail_no_perms = false;
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "def_mail_all_cmnds -> false, def_mail_always -> false, "
		    "def_mail_no_perms -> false");
	    }
	}
	if (cs->tags.follow != UNSPEC) {
	    def_sudoedit_follow = cs->tags.follow;
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"def_sudoedit_follow -> %s", def_sudoedit_follow ? "true" : "false");
	}
    }

    debug_return_bool(true);
}

/*
 * Look up the user in the sudoers parse tree and check to see if they are
 * allowed to run the specified command on this host as the target user.
 */
int
sudoers_lookup(struct sudo_nss_list *snl, struct passwd *pw, int *cmnd_status,
    int pwflag)
{
    struct defaults_list *defs = NULL;
    struct sudoers_parse_tree *parse_tree = NULL;
    struct cmndspec *cs = NULL;
    struct sudo_nss *nss;
    struct cmnd_info info;
    int validated = FLAG_NO_USER | FLAG_NO_HOST;
    int m, match = UNSPEC;
    time_t now;
    debug_decl(sudoers_lookup, SUDOERS_DEBUG_PARSER);

    /*
     * Special case checking the "validate", "list" and "kill" pseudo-commands.
     */
    if (pwflag)
	debug_return_int(sudoers_lookup_pseudo(snl, pw, pwflag));

    /* Need to be runas user while stat'ing things. */
    if (!set_perms(PERM_RUNAS))
	debug_return_int(validated);

    /* Query each sudoers source and check the user. */
    time(&now);
    TAILQ_FOREACH(nss, snl, entries) {
	if (nss->query(nss, pw) == -1) {
	    /* The query function should have printed an error message. */
	    SET(validated, VALIDATE_ERROR);
	    break;
	}

	m = sudoers_lookup_check(nss, pw, &validated, &info, &cs, &defs, now);
	if (m != UNSPEC) {
	    match = m;
	    parse_tree = nss->parse_tree;
	}

	if (!sudo_nss_can_continue(nss, m))
	    break;
    }
    if (match != UNSPEC) {
	if (info.cmnd_path != NULL) {
	    /* Update user_cmnd, user_stat, cmnd_status from matching entry. */
	    free(user_cmnd);
	    user_cmnd = info.cmnd_path;
	    if (user_stat != NULL)
		*user_stat = info.cmnd_stat;
	    *cmnd_status = info.status;
	}
	if (defs != NULL)
	    (void)update_defaults(parse_tree, defs, SETDEF_GENERIC, false);
	if (!apply_cmndspec(cs))
	    SET(validated, VALIDATE_ERROR);
	else if (match == ALLOW)
	    SET(validated, VALIDATE_SUCCESS);
	else
	    SET(validated, VALIDATE_FAILURE);
    }
    if (!restore_perms())
	SET(validated, VALIDATE_ERROR);
    debug_return_int(validated);
}
