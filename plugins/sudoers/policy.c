/*
 * Copyright (c) 2010-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
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
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <errno.h>
#include <grp.h>
#include <pwd.h>

#include "sudoers.h"
#include "sudoers_version.h"
#include "interfaces.h"

/*
 * Info passed in from the sudo front-end.
 */
struct sudoers_policy_open_info {
    char * const *settings;
    char * const *user_info;
    char * const *plugin_args;
};

/*
 * Command execution args to be filled in: argv, envp and command info.
 */
struct sudoers_exec_args {
    char ***argv;
    char ***envp;
    char ***info;
};

static int sudo_version;
static const char *interfaces_string;
sudo_conv_t sudo_conv;
sudo_printf_t sudo_printf;
const char *path_ldap_conf = _PATH_LDAP_CONF;
const char *path_ldap_secret = _PATH_LDAP_SECRET;

extern __dso_public struct policy_plugin sudoers_policy;

#ifdef HAVE_BSD_AUTH_H
extern char *login_style;
#endif /* HAVE_BSD_AUTH_H */

/*
 * Deserialize args, settings and user_info arrays.
 * Fills in struct sudo_user and other common sudoers state.
 */
int
sudoers_policy_deserialize_info(void *v, char **runas_user, char **runas_group)
{
    struct sudoers_policy_open_info *info = v;
    char * const *cur;
    const char *p, *errstr, *groups = NULL;
    const char *remhost = NULL;
    int flags = 0;
    debug_decl(sudoers_policy_deserialize_info, SUDOERS_DEBUG_PLUGIN)

#define MATCHES(s, v) (strncmp(s, v, sizeof(v) - 1) == 0)

    /* Parse sudo.conf plugin args. */
    if (info->plugin_args != NULL) {
	for (cur = info->plugin_args; *cur != NULL; cur++) {
	    if (MATCHES(*cur, "sudoers_file=")) {
		sudoers_file = *cur + sizeof("sudoers_file=") - 1;
		continue;
	    }
	    if (MATCHES(*cur, "sudoers_uid=")) {
		p = *cur + sizeof("sudoers_uid=") - 1;
		sudoers_uid = (uid_t) sudo_strtoid(p, NULL, NULL, &errstr);
		if (errstr != NULL) {
		    sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		    goto bad;
		}
		continue;
	    }
	    if (MATCHES(*cur, "sudoers_gid=")) {
		p = *cur + sizeof("sudoers_gid=") - 1;
		sudoers_gid = (gid_t) sudo_strtoid(p, NULL, NULL, &errstr);
		if (errstr != NULL) {
		    sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		    goto bad;
		}
		continue;
	    }
	    if (MATCHES(*cur, "sudoers_mode=")) {
		p = *cur + sizeof("sudoers_mode=") - 1;
		sudoers_mode = sudo_strtomode(p, &errstr);
		if (errstr != NULL) {
		    sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		    goto bad;
		}
		continue;
	    }
	    if (MATCHES(*cur, "ldap_conf=")) {
		path_ldap_conf = *cur + sizeof("ldap_conf=") - 1;
		continue;
	    }
	    if (MATCHES(*cur, "ldap_secret=")) {
		path_ldap_secret = *cur + sizeof("ldap_secret=") - 1;
		continue;
	    }
	}
    }

    /* Parse command line settings. */
    user_closefrom = -1;
    for (cur = info->settings; *cur != NULL; cur++) {
	if (MATCHES(*cur, "closefrom=")) {
	    errno = 0;
	    p = *cur + sizeof("closefrom=") - 1;
	    user_closefrom = strtonum(p, 4, INT_MAX, &errstr);
	    if (user_closefrom == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "runas_user=")) {
	    *runas_user = *cur + sizeof("runas_user=") - 1;
	    sudo_user.flags |= RUNAS_USER_SPECIFIED;
	    continue;
	}
	if (MATCHES(*cur, "runas_group=")) {
	    *runas_group = *cur + sizeof("runas_group=") - 1;
	    sudo_user.flags |= RUNAS_GROUP_SPECIFIED;
	    continue;
	}
	if (MATCHES(*cur, "prompt=")) {
	    user_prompt = *cur + sizeof("prompt=") - 1;
	    def_passprompt_override = true;
	    continue;
	}
	if (MATCHES(*cur, "set_home=")) {
	    if (sudo_strtobool(*cur + sizeof("set_home=") - 1) == true)
		SET(flags, MODE_RESET_HOME);
	    continue;
	}
	if (MATCHES(*cur, "preserve_environment=")) {
	    if (sudo_strtobool(*cur + sizeof("preserve_environment=") - 1) == true)
		SET(flags, MODE_PRESERVE_ENV);
	    continue;
	}
	if (MATCHES(*cur, "run_shell=")) {
	    if (sudo_strtobool(*cur + sizeof("run_shell=") - 1) == true)
		SET(flags, MODE_SHELL);
	    continue;
	}
	if (MATCHES(*cur, "login_shell=")) {
	    if (sudo_strtobool(*cur + sizeof("login_shell=") - 1) == true) {
		SET(flags, MODE_LOGIN_SHELL);
		def_env_reset = true;
	    }
	    continue;
	}
	if (MATCHES(*cur, "implied_shell=")) {
	    if (sudo_strtobool(*cur + sizeof("implied_shell=") - 1) == true)
		SET(flags, MODE_IMPLIED_SHELL);
	    continue;
	}
	if (MATCHES(*cur, "preserve_groups=")) {
	    if (sudo_strtobool(*cur + sizeof("preserve_groups=") - 1) == true)
		SET(flags, MODE_PRESERVE_GROUPS);
	    continue;
	}
	if (MATCHES(*cur, "ignore_ticket=")) {
	    if (sudo_strtobool(*cur + sizeof("ignore_ticket=") - 1) == true)
		SET(flags, MODE_IGNORE_TICKET);
	    continue;
	}
	if (MATCHES(*cur, "noninteractive=")) {
	    if (sudo_strtobool(*cur + sizeof("noninteractive=") - 1) == true)
		SET(flags, MODE_NONINTERACTIVE);
	    continue;
	}
	if (MATCHES(*cur, "sudoedit=")) {
	    if (sudo_strtobool(*cur + sizeof("sudoedit=") - 1) == true)
		SET(flags, MODE_EDIT);
	    continue;
	}
	if (MATCHES(*cur, "login_class=")) {
	    login_class = *cur + sizeof("login_class=") - 1;
	    def_use_loginclass = true;
	    continue;
	}
#ifdef HAVE_PRIV_SET
	if (MATCHES(*cur, "runas_privs=")) {
	    def_privs = *cur + sizeof("runas_privs=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "runas_limitprivs=")) {
	    def_limitprivs = *cur + sizeof("runas_limitprivs=") - 1;
	    continue;
	}
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
	if (MATCHES(*cur, "selinux_role=")) {
	    user_role = *cur + sizeof("selinux_role=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "selinux_type=")) {
	    user_type = *cur + sizeof("selinux_type=") - 1;
	    continue;
	}
#endif /* HAVE_SELINUX */
#ifdef HAVE_BSD_AUTH_H
	if (MATCHES(*cur, "bsdauth_type=")) {
	    login_style = *cur + sizeof("bsdauth_type=") - 1;
	    continue;
	}
#endif /* HAVE_BSD_AUTH_H */
	if (MATCHES(*cur, "network_addrs=")) {
	    interfaces_string = *cur + sizeof("network_addrs=") - 1;
	    set_interfaces(interfaces_string);
	    continue;
	}
	if (MATCHES(*cur, "max_groups=")) {
	    errno = 0;
	    p = *cur + sizeof("max_groups=") - 1;
	    sudo_user.max_groups = strtonum(p, 1, INT_MAX, &errstr);
	    if (sudo_user.max_groups == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "remote_host=")) {
	    remhost = *cur + sizeof("remote_host=") - 1;
	    continue;
	}
    }

    for (cur = info->user_info; *cur != NULL; cur++) {
	if (MATCHES(*cur, "user=")) {
	    user_name = sudo_estrdup(*cur + sizeof("user=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "uid=")) {
	    p = *cur + sizeof("uid=") - 1;
	    user_uid = (uid_t) sudo_strtoid(p, NULL, NULL, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "gid=")) {
	    p = *cur + sizeof("gid=") - 1;
	    user_gid = (gid_t) sudo_strtoid(p, NULL, NULL, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "groups=")) {
	    groups = *cur + sizeof("groups=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "cwd=")) {
	    user_cwd = sudo_estrdup(*cur + sizeof("cwd=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "tty=")) {
	    user_tty = user_ttypath = sudo_estrdup(*cur + sizeof("tty=") - 1);
	    if (strncmp(user_tty, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
		user_tty += sizeof(_PATH_DEV) - 1;
	    continue;
	}
	if (MATCHES(*cur, "host=")) {
	    user_host = user_shost = sudo_estrdup(*cur + sizeof("host=") - 1);
	    if ((p = strchr(user_host, '.')))
		user_shost = sudo_estrndup(user_host, (size_t)(p - user_host));
	    continue;
	}
	if (MATCHES(*cur, "lines=")) {
	    errno = 0;
	    p = *cur + sizeof("lines=") - 1;
	    sudo_user.lines = strtonum(p, 1, INT_MAX, &errstr);
	    if (sudo_user.lines == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "cols=")) {
	    errno = 0;
	    p = *cur + sizeof("cols=") - 1;
	    sudo_user.cols = strtonum(p, 1, INT_MAX, &errstr);
	    if (sudo_user.lines == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "sid=")) {
	    p = *cur + sizeof("sid=") - 1;
	    sudo_user.sid = (pid_t) sudo_strtoid(p, NULL, NULL, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
    }
    user_runhost = user_srunhost = sudo_estrdup(remhost ? remhost : user_host);
    if ((p = strchr(user_runhost, '.')))
	user_srunhost = sudo_estrndup(user_runhost, (size_t)(p - user_runhost));
    if (user_cwd == NULL)
	user_cwd = sudo_estrdup("unknown");
    if (user_tty == NULL)
	user_tty = sudo_estrdup("unknown"); /* user_ttypath remains NULL */

    if (groups != NULL && groups[0] != '\0') {
	/* sudo_parse_gids() will print a warning on error. */
	user_ngids = sudo_parse_gids(groups, &user_gid, &user_gids);
	if (user_ngids == -1)
	    goto bad;
    }

    /* Stash initial umask for later use. */
    user_umask = umask(SUDO_UMASK);
    umask(user_umask);

    /* Dump settings and user info (XXX - plugin args) */
    for (cur = info->settings; *cur != NULL; cur++)
	sudo_debug_printf(SUDO_DEBUG_INFO, "settings: %s", *cur);
    for (cur = info->user_info; *cur != NULL; cur++)
	sudo_debug_printf(SUDO_DEBUG_INFO, "user_info: %s", *cur);

#undef MATCHES
    debug_return_int(flags);

bad:
    debug_return_int(MODE_ERROR);
}

/*
 * Setup the execution environment.
 * Builds up the command_info list and sets argv and envp.
 * Returns 1 on success and -1 on error.
 */
int
sudoers_policy_exec_setup(char *argv[], char *envp[], mode_t cmnd_umask,
    char *iolog_path, void *v)
{
    struct sudoers_exec_args *exec_args = v;
    char **command_info;
    int info_len = 0;
    int rval = -1;
    debug_decl(sudoers_policy_exec_setup, SUDOERS_DEBUG_PLUGIN)

    /* Increase the length of command_info as needed, it is *not* checked. */
    command_info = sudo_ecalloc(32, sizeof(char **));

    command_info[info_len++] = sudo_new_key_val("command", safe_cmnd);
    if (def_log_input || def_log_output) {
	if (iolog_path)
	    command_info[info_len++] = iolog_path;
	if (def_log_input) {
	    command_info[info_len++] = sudo_estrdup("iolog_stdin=true");
	    command_info[info_len++] = sudo_estrdup("iolog_ttyin=true");
	}
	if (def_log_output) {
	    command_info[info_len++] = sudo_estrdup("iolog_stdout=true");
	    command_info[info_len++] = sudo_estrdup("iolog_stderr=true");
	    command_info[info_len++] = sudo_estrdup("iolog_ttyout=true");
	}
	if (def_compress_io) {
	    command_info[info_len++] = sudo_estrdup("iolog_compress=true");
	}
	if (def_maxseq) {
	    sudo_easprintf(&command_info[info_len++], "maxseq=%u", def_maxseq);
	}
    }
    if (ISSET(sudo_mode, MODE_EDIT))
	command_info[info_len++] = sudo_estrdup("sudoedit=true");
    if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
	/* Set cwd to run user's homedir. */
	command_info[info_len++] = sudo_new_key_val("cwd", runas_pw->pw_dir);
    }
    if (def_stay_setuid) {
	sudo_easprintf(&command_info[info_len++], "runas_uid=%u",
	    (unsigned int)user_uid);
	sudo_easprintf(&command_info[info_len++], "runas_gid=%u",
	    (unsigned int)user_gid);
	sudo_easprintf(&command_info[info_len++], "runas_euid=%u",
	    (unsigned int)runas_pw->pw_uid);
	sudo_easprintf(&command_info[info_len++], "runas_egid=%u",
	    runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid);
    } else {
	sudo_easprintf(&command_info[info_len++], "runas_uid=%u",
	    (unsigned int)runas_pw->pw_uid);
	sudo_easprintf(&command_info[info_len++], "runas_gid=%u",
	    runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid);
    }
    if (def_preserve_groups) {
	command_info[info_len++] = "preserve_groups=true";
    } else {
	int i, len;
	gid_t egid;
	size_t glsize;
	char *cp, *gid_list;
	struct group_list *grlist = sudo_get_grlist(runas_pw);

	/* We reserve an extra spot in the list for the effective gid. */
	glsize = sizeof("runas_groups=") - 1 +
	    ((grlist->ngids + 1) * (MAX_UID_T_LEN + 1));
	gid_list = sudo_emalloc(glsize);
	memcpy(gid_list, "runas_groups=", sizeof("runas_groups=") - 1);
	cp = gid_list + sizeof("runas_groups=") - 1;

	/* On BSD systems the effective gid is the first group in the list. */
	egid = runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid;
	len = snprintf(cp, glsize - (cp - gid_list), "%u", egid);
	if (len < 0 || (size_t)len >= glsize - (cp - gid_list)) {
	    sudo_warnx(U_("internal error, %s overflow"), __func__);
	    goto done;
	}
	cp += len;
	for (i = 0; i < grlist->ngids; i++) {
	    if (grlist->gids[i] != egid) {
		len = snprintf(cp, glsize - (cp - gid_list), ",%u",
		     (unsigned int) grlist->gids[i]);
		if (len < 0 || (size_t)len >= glsize - (cp - gid_list)) {
		    sudo_warnx(U_("internal error, %s overflow"), __func__);
		    goto done;
		}
		cp += len;
	    }
	}
	command_info[info_len++] = gid_list;
	sudo_grlist_delref(grlist);
    }
    if (def_closefrom >= 0)
	sudo_easprintf(&command_info[info_len++], "closefrom=%d", def_closefrom);
    if (def_noexec)
	command_info[info_len++] = sudo_estrdup("noexec=true");
    if (def_exec_background)
	command_info[info_len++] = sudo_estrdup("exec_background=true");
    if (def_set_utmp)
	command_info[info_len++] = sudo_estrdup("set_utmp=true");
    if (def_use_pty)
	command_info[info_len++] = sudo_estrdup("use_pty=true");
    if (def_utmp_runas)
	command_info[info_len++] = sudo_new_key_val("utmp_user", runas_pw->pw_name);
    if (cmnd_umask != 0777)
	sudo_easprintf(&command_info[info_len++], "umask=0%o", (unsigned int)cmnd_umask);
#ifdef HAVE_LOGIN_CAP_H
    if (def_use_loginclass)
	command_info[info_len++] = sudo_new_key_val("login_class", login_class);
#endif /* HAVE_LOGIN_CAP_H */
#ifdef HAVE_SELINUX
    if (user_role != NULL)
	command_info[info_len++] = sudo_new_key_val("selinux_role", user_role);
    if (user_type != NULL)
	command_info[info_len++] = sudo_new_key_val("selinux_type", user_type);
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
    if (runas_privs != NULL)
	command_info[info_len++] = sudo_new_key_val("runas_privs", runas_privs);
    if (runas_limitprivs != NULL)
	command_info[info_len++] = sudo_new_key_val("runas_limitprivs", runas_limitprivs);
#endif /* HAVE_SELINUX */

    /* Fill in exec environment info */
    *(exec_args->argv) = argv;
    *(exec_args->envp) = envp;
    *(exec_args->info) = command_info;

    rval = true;

done:
    debug_return_bool(rval);
}

static int
sudoers_policy_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], char * const envp[], char * const args[])
{
    struct sudo_conf_debug_file_list debug_files = TAILQ_HEAD_INITIALIZER(debug_files);
    struct sudoers_policy_open_info info;
    const char *plugin_path = NULL;
    char * const *cur;
    debug_decl(sudoers_policy_open, SUDOERS_DEBUG_PLUGIN)

    sudo_version = version;
    sudo_conv = conversation;
    sudo_printf = plugin_printf;

    /* Plugin args are only specified for API version 1.2 and higher. */
    if (sudo_version < SUDO_API_MKVERSION(1, 2))
	args = NULL;

    /* Initialize the debug subsystem.  */
    for (cur = settings; *cur != NULL; cur++) {
	if (strncmp(*cur, "debug_flags=", sizeof("debug_flags=") - 1) == 0) {
	    sudoers_debug_parse_flags(&debug_files,
		*cur + sizeof("debug_flags=") - 1);
	    continue;
	}
	if (strncmp(*cur, "plugin_path=", sizeof("plugin_path=") - 1) == 0) {
	    plugin_path = *cur + sizeof("plugin_path=") - 1;
	    continue;
	}
    }
    sudoers_debug_register(plugin_path, &debug_files);

    /* Call the sudoers init function. */
    info.settings = settings;
    info.user_info = user_info;
    info.plugin_args = args;
    debug_return_bool(sudoers_policy_init(&info, envp));
}

static void
sudoers_policy_close(int exit_status, int error_code)
{
    debug_decl(sudoers_policy_close, SUDOERS_DEBUG_PLUGIN)

    /* We do not currently log the exit status. */
    if (error_code) {
	errno = error_code;
	sudo_warn(U_("unable to execute %s"), safe_cmnd);
    }

    /* Close the session we opened in sudoers_policy_init_session(). */
    if (ISSET(sudo_mode, MODE_RUN|MODE_EDIT))
	(void)sudo_auth_end_session(runas_pw);

    /* Deregister the callback for sudo_fatal()/sudo_fatalx(). */
    sudo_fatal_callback_deregister(sudoers_cleanup);

    /* Free remaining references to password and group entries. */
    /* XXX - move cleanup to function in sudoers.c */
    sudo_pw_delref(sudo_user.pw);
    sudo_user.pw = NULL;
    sudo_pw_delref(runas_pw);
    runas_pw = NULL;
    if (runas_gr != NULL) {
	sudo_gr_delref(runas_gr);
	runas_gr = NULL;
    }
    if (user_group_list != NULL) {
	sudo_grlist_delref(user_group_list);
	user_group_list = NULL;
    }
    sudo_efree(user_gids);
    user_gids = NULL;

    sudoers_debug_deregister();

    return;
}

/*
 * The init_session function is called before executing the command
 * and before uid/gid changes occur.
 * Returns 1 on success, 0 on failure and -1 on error.
 */
static int
sudoers_policy_init_session(struct passwd *pwd, char **user_env[])
{
    debug_decl(sudoers_policy_init_session, SUDOERS_DEBUG_PLUGIN)

    /* user_env is only specified for API version 1.2 and higher. */
    if (sudo_version < SUDO_API_MKVERSION(1, 2))
	user_env = NULL;

    debug_return_bool(sudo_auth_begin_session(pwd, user_env));
}

static int
sudoers_policy_check(int argc, char * const argv[], char *env_add[],
    char **command_infop[], char **argv_out[], char **user_env_out[])
{
    struct sudoers_exec_args exec_args;
    int rval;
    debug_decl(sudoers_policy_check, SUDOERS_DEBUG_PLUGIN)

    if (!ISSET(sudo_mode, MODE_EDIT))
	SET(sudo_mode, MODE_RUN);

    exec_args.argv = argv_out;
    exec_args.envp = user_env_out;
    exec_args.info = command_infop;

    rval = sudoers_policy_main(argc, argv, 0, env_add, &exec_args);
    if (rval == true && sudo_version >= SUDO_API_MKVERSION(1, 3)) {
	/* Unset close function if we don't need it to avoid extra process. */
	if (!def_log_input && !def_log_output && !def_use_pty &&
	    !sudo_auth_needs_end_session())
	    sudoers_policy.close = NULL;
    }
    debug_return_bool(rval);
}

static int
sudoers_policy_validate(void)
{
    debug_decl(sudoers_policy_validate, SUDOERS_DEBUG_PLUGIN)

    user_cmnd = "validate";
    SET(sudo_mode, MODE_VALIDATE);

    debug_return_bool(sudoers_policy_main(0, NULL, I_VERIFYPW, NULL, NULL));
}

static void
sudoers_policy_invalidate(int remove)
{
    debug_decl(sudoers_policy_invalidate, SUDOERS_DEBUG_PLUGIN)

    user_cmnd = "kill";
    remove_timestamp(remove);
    sudoers_cleanup();

    debug_return;
}

static int
sudoers_policy_list(int argc, char * const argv[], int verbose,
    const char *list_user)
{
    int rval;
    debug_decl(sudoers_policy_list, SUDOERS_DEBUG_PLUGIN)

    user_cmnd = "list";
    if (argc)
	SET(sudo_mode, MODE_CHECK);
    else
	SET(sudo_mode, MODE_LIST);
    if (verbose)
	long_list = 1;
    if (list_user) {
	list_pw = sudo_getpwnam(list_user);
	if (list_pw == NULL) {
	    sudo_warnx(U_("unknown user: %s"), list_user);
	    debug_return_bool(-1);
	}
    }
    rval = sudoers_policy_main(argc, argv, I_LISTPW, NULL, NULL);
    if (list_user) {
	sudo_pw_delref(list_pw);
	list_pw = NULL;
    }

    debug_return_bool(rval);
}

static int
sudoers_policy_version(int verbose)
{
    debug_decl(sudoers_policy_version, SUDOERS_DEBUG_PLUGIN)

    sudo_printf(SUDO_CONV_INFO_MSG, _("Sudoers policy plugin version %s\n"),
	PACKAGE_VERSION);
    sudo_printf(SUDO_CONV_INFO_MSG, _("Sudoers file grammar version %d\n"),
	SUDOERS_GRAMMAR_VERSION);

    if (verbose) {
	sudo_printf(SUDO_CONV_INFO_MSG, _("\nSudoers path: %s\n"), sudoers_file);
#ifdef HAVE_LDAP
# ifdef _PATH_NSSWITCH_CONF
	sudo_printf(SUDO_CONV_INFO_MSG, _("nsswitch path: %s\n"), _PATH_NSSWITCH_CONF);
# endif
	sudo_printf(SUDO_CONV_INFO_MSG, _("ldap.conf path: %s\n"), path_ldap_conf);
	sudo_printf(SUDO_CONV_INFO_MSG, _("ldap.secret path: %s\n"), path_ldap_secret);
#endif
	dump_auth_methods();
	dump_defaults();
	sudo_printf(SUDO_CONV_INFO_MSG, "\n");
	if (interfaces_string != NULL) {
	    dump_interfaces(interfaces_string);
	    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
	}
    }
    debug_return_bool(true);
}

/*
 * Register environment function hooks.
 * Note that we have not registered sudoers with the debug subsystem yet.
 */
static void
sudoers_policy_register_hooks(int version, int (*register_hook)(struct sudo_hook *hook))
{
    struct sudo_hook hook;

    memset(&hook, 0, sizeof(hook));
    hook.hook_version = SUDO_HOOK_VERSION;

    hook.hook_type = SUDO_HOOK_SETENV;
    hook.hook_fn = sudoers_hook_setenv;
    register_hook(&hook);

    hook.hook_type = SUDO_HOOK_UNSETENV;
    hook.hook_fn = sudoers_hook_unsetenv;
    register_hook(&hook);

    hook.hook_type = SUDO_HOOK_GETENV;
    hook.hook_fn = sudoers_hook_getenv;
    register_hook(&hook);

    hook.hook_type = SUDO_HOOK_PUTENV;
    hook.hook_fn = sudoers_hook_putenv;
    register_hook(&hook);
}

__dso_public struct policy_plugin sudoers_policy = {
    SUDO_POLICY_PLUGIN,
    SUDO_API_VERSION,
    sudoers_policy_open,
    sudoers_policy_close,
    sudoers_policy_version,
    sudoers_policy_check,
    sudoers_policy_list,
    sudoers_policy_validate,
    sudoers_policy_invalidate,
    sudoers_policy_init_session,
    sudoers_policy_register_hooks
};
