/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2010-2022 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>

#include "sudoers.h"
#include "sudoers_version.h"
#include "interfaces.h"

static char **command_info;

/*
 * Command execution args to be filled in: argv, envp and command info.
 */
struct sudoers_exec_args {
    char ***argv;
    char ***envp;
    char ***info;
};

static unsigned int sudo_version;
static const char *interfaces_string;
sudo_conv_t sudo_conv;
sudo_printf_t sudo_printf;
struct sudo_plugin_event * (*plugin_event_alloc)(void);
const char *path_ldap_conf = _PATH_LDAP_CONF;
const char *path_ldap_secret = _PATH_LDAP_SECRET;
static bool session_opened;
int sudoedit_nfiles;

extern sudo_dso_public struct policy_plugin sudoers_policy;

#ifdef HAVE_BSD_AUTH_H
char *login_style;
#endif /* HAVE_BSD_AUTH_H */

static int
parse_bool(const char *line, int varlen, int *flags, int fval)
{
    debug_decl(parse_bool, SUDOERS_DEBUG_PLUGIN);

    switch (sudo_strtobool(line + varlen + 1)) {
    case true:
	SET(*flags, fval);
	debug_return_int(true);
    case false:
	CLR(*flags, fval);
	debug_return_int(false);
    default:
	sudo_warnx(U_("invalid %.*s set by sudo front-end"),
	    varlen, line);
	debug_return_int(-1);
    }
}

#define RUN_VALID_FLAGS	(MODE_ASKPASS|MODE_PRESERVE_ENV|MODE_RESET_HOME|MODE_IMPLIED_SHELL|MODE_LOGIN_SHELL|MODE_NONINTERACTIVE|MODE_IGNORE_TICKET|MODE_UPDATE_TICKET|MODE_PRESERVE_GROUPS|MODE_SHELL|MODE_RUN|MODE_POLICY_INTERCEPTED)
#define EDIT_VALID_FLAGS	(MODE_ASKPASS|MODE_NONINTERACTIVE|MODE_IGNORE_TICKET|MODE_UPDATE_TICKET|MODE_EDIT)
#define LIST_VALID_FLAGS	(MODE_ASKPASS|MODE_NONINTERACTIVE|MODE_IGNORE_TICKET|MODE_UPDATE_TICKET|MODE_LIST|MODE_CHECK)
#define VALIDATE_VALID_FLAGS	(MODE_ASKPASS|MODE_NONINTERACTIVE|MODE_IGNORE_TICKET|MODE_UPDATE_TICKET|MODE_VALIDATE)
#define INVALIDATE_VALID_FLAGS	(MODE_ASKPASS|MODE_NONINTERACTIVE|MODE_IGNORE_TICKET|MODE_UPDATE_TICKET|MODE_INVALIDATE)

/*
 * Deserialize args, settings and user_info arrays.
 * Fills in struct sudo_user and other common sudoers state.
 */
int
sudoers_policy_deserialize_info(void *v, struct defaults_list *defaults)
{
    struct sudoers_open_info *info = v;
    const char *p, *errstr, *groups = NULL;
    const char *remhost = NULL;
    unsigned char uuid[16];
    char * const *cur;
    int flags = MODE_UPDATE_TICKET;
    debug_decl(sudoers_policy_deserialize_info, SUDOERS_DEBUG_PLUGIN);

#define MATCHES(s, v)	\
    (strncmp((s), (v), sizeof(v) - 1) == 0)

#define INVALID(v) do {	\
    sudo_warnx(U_("invalid %.*s set by sudo front-end"), \
	(int)(sizeof(v) - 2), (v)); \
} while (0)

#define CHECK(s, v) do {	\
    if ((s)[sizeof(v) - 1] == '\0') { \
	INVALID(v); \
	goto bad; \
    } \
} while (0)

    if (sudo_gettime_real(&sudo_user.submit_time) == -1) {
	sudo_warn("%s", U_("unable to get time of day"));
	goto bad;
    }

    /* Parse sudo.conf plugin args. */
    sudoers_file = _PATH_SUDOERS;
    sudoers_mode = SUDOERS_MODE;
    sudoers_uid = SUDOERS_UID;
    sudoers_gid = SUDOERS_GID;
    if (info->plugin_args != NULL) {
	for (cur = info->plugin_args; *cur != NULL; cur++) {
	    if (MATCHES(*cur, "error_recovery=")) {
		int val = sudo_strtobool(*cur + sizeof("error_recovery=") - 1);
		if (val == -1) {
		    INVALID("error_recovery=");	/* Not a fatal error. */
		} else {
		    sudoers_recovery = val;
		}
		continue;
	    }
	    if (MATCHES(*cur, "sudoers_file=")) {
		CHECK(*cur, "sudoers_file=");
		sudoers_file = *cur + sizeof("sudoers_file=") - 1;
		continue;
	    }
	    if (MATCHES(*cur, "sudoers_uid=")) {
		p = *cur + sizeof("sudoers_uid=") - 1;
		sudoers_uid = (uid_t) sudo_strtoid(p, &errstr);
		if (errstr != NULL) {
		    sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		    goto bad;
		}
		continue;
	    }
	    if (MATCHES(*cur, "sudoers_gid=")) {
		p = *cur + sizeof("sudoers_gid=") - 1;
		sudoers_gid = (gid_t) sudo_strtoid(p, &errstr);
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
		CHECK(*cur, "ldap_conf=");
		path_ldap_conf = *cur + sizeof("ldap_conf=") - 1;
		continue;
	    }
	    if (MATCHES(*cur, "ldap_secret=")) {
		CHECK(*cur, "ldap_secret=");
		path_ldap_secret = *cur + sizeof("ldap_secret=") - 1;
		continue;
	    }
	}
    }

    /* Parse command line settings. */
    sudo_user.flags = 0;
    user_closefrom = -1;
    sudoedit_nfiles = 0;
    sudo_mode = 0;
    for (cur = info->settings; *cur != NULL; cur++) {
	if (MATCHES(*cur, "closefrom=")) {
	    errno = 0;
	    p = *cur + sizeof("closefrom=") - 1;
	    user_closefrom = sudo_strtonum(p, 3, INT_MAX, &errstr);
	    if (user_closefrom == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "cmnd_chroot=")) {
	    CHECK(*cur, "cmnd_chroot=");
	    user_runchroot = *cur + sizeof("cmnd_chroot=") - 1;
	    if (strlen(user_runchroot) >= PATH_MAX) {
		sudo_warnx(U_("path name for \"%s\" too long"), "cmnd_chroot");
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "cmnd_cwd=")) {
	    CHECK(*cur, "cmnd_cwd=");
	    user_runcwd = *cur + sizeof("cmnd_cwd=") - 1;
	    if (strlen(user_runcwd) >= PATH_MAX) {
		sudo_warnx(U_("path name for \"%s\" too long"), "cmnd_cwd");
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "runas_user=")) {
	    CHECK(*cur, "runas_user=");
	    sudo_user.runas_user = *cur + sizeof("runas_user=") - 1;
	    SET(sudo_user.flags, RUNAS_USER_SPECIFIED);
	    continue;
	}
	if (MATCHES(*cur, "runas_group=")) {
	    CHECK(*cur, "runas_group=");
	    sudo_user.runas_group = *cur + sizeof("runas_group=") - 1;
	    SET(sudo_user.flags, RUNAS_GROUP_SPECIFIED);
	    continue;
	}
	if (MATCHES(*cur, "prompt=")) {
	    /* Allow epmpty prompt. */
	    user_prompt = *cur + sizeof("prompt=") - 1;
	    if (!append_default("passprompt_override", NULL, true, NULL, defaults))
		goto oom;
	    continue;
	}
	if (MATCHES(*cur, "set_home=")) {
	    if (parse_bool(*cur, sizeof("set_home") - 1, &flags,
		MODE_RESET_HOME) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "preserve_environment=")) {
	    if (parse_bool(*cur, sizeof("preserve_environment") - 1, &flags,
		MODE_PRESERVE_ENV) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "run_shell=")) {
	    if (parse_bool(*cur, sizeof("run_shell") -1, &flags,
		MODE_SHELL) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "login_shell=")) {
	    if (parse_bool(*cur, sizeof("login_shell") - 1, &flags,
		MODE_LOGIN_SHELL) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "implied_shell=")) {
	    if (parse_bool(*cur, sizeof("implied_shell") - 1, &flags,
		MODE_IMPLIED_SHELL) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "preserve_groups=")) {
	    if (parse_bool(*cur, sizeof("preserve_groups") - 1, &flags,
		MODE_PRESERVE_GROUPS) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "ignore_ticket=")) {
	    if (parse_bool(*cur, sizeof("ignore_ticket") -1, &flags,
		MODE_IGNORE_TICKET) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "update_ticket=")) {
	    if (parse_bool(*cur, sizeof("update_ticket") -1, &flags,
		MODE_UPDATE_TICKET) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "noninteractive=")) {
	    if (parse_bool(*cur, sizeof("noninteractive") - 1, &flags,
		MODE_NONINTERACTIVE) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "sudoedit=")) {
	    if (parse_bool(*cur, sizeof("sudoedit") - 1, &flags,
		MODE_EDIT) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "login_class=")) {
	    CHECK(*cur, "login_class=");
	    login_class = *cur + sizeof("login_class=") - 1;
	    if (!append_default("use_loginclass", NULL, true, NULL, defaults))
		goto oom;
	    continue;
	}
	if (MATCHES(*cur, "intercept_ptrace=")) {
	    if (parse_bool(*cur, sizeof("intercept_ptrace") - 1, &sudo_user.flags,
		    HAVE_INTERCEPT_PTRACE) == -1)
		goto bad;
	    continue;
	}
	if (MATCHES(*cur, "intercept_setid=")) {
	    if (parse_bool(*cur, sizeof("intercept_setid") - 1, &sudo_user.flags,
		    CAN_INTERCEPT_SETID) == -1)
		goto bad;
	    continue;
	}
#ifdef HAVE_SELINUX
	if (MATCHES(*cur, "selinux_role=")) {
	    CHECK(*cur, "selinux_role=");
	    free(user_role);
	    user_role = strdup(*cur + sizeof("selinux_role=") - 1);
	    if (user_role == NULL)
		goto oom;
	    continue;
	}
	if (MATCHES(*cur, "selinux_type=")) {
	    CHECK(*cur, "selinux_type=");
	    free(user_type);
	    user_type = strdup(*cur + sizeof("selinux_type=") - 1);
	    if (user_type == NULL)
		goto oom;
	    continue;
	}
#endif /* HAVE_SELINUX */
#ifdef HAVE_APPARMOR
	if (MATCHES(*cur, "apparmor_profile=")) {
	    CHECK(*cur, "apparmor_profile=");
	    free(user_apparmor_profile);
	    user_apparmor_profile = strdup(*cur + sizeof("apparmor_profile=") - 1);
	    if (user_apparmor_profile == NULL)
		goto oom;
	    continue;
	}
#endif /* HAVE_APPARMOR */
#ifdef HAVE_BSD_AUTH_H
	if (MATCHES(*cur, "bsdauth_type=")) {
	    CHECK(*cur, "bsdauth_type=");
	    login_style = *cur + sizeof("bsdauth_type=") - 1;
	    continue;
	}
#endif /* HAVE_BSD_AUTH_H */
	if (MATCHES(*cur, "network_addrs=")) {
	    interfaces_string = *cur + sizeof("network_addrs=") - 1;
	    if (!set_interfaces(interfaces_string)) {
		sudo_warn("%s", U_("unable to parse network address list"));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "max_groups=")) {
	    errno = 0;
	    p = *cur + sizeof("max_groups=") - 1;
	    sudo_user.max_groups = sudo_strtonum(p, 1, 1024, &errstr);
	    if (sudo_user.max_groups == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "remote_host=")) {
	    CHECK(*cur, "remote_host=");
	    remhost = *cur + sizeof("remote_host=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "timeout=")) {
	    p = *cur + sizeof("timeout=") - 1;
	    user_timeout = parse_timeout(p);
	    if (user_timeout == -1) {
		if (errno == ERANGE)
		    sudo_warnx(U_("%s: %s"), p, U_("timeout value too large"));
		else
		    sudo_warnx(U_("%s: %s"), p, U_("invalid timeout value"));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "askpass=")) {
	    if (parse_bool(*cur, sizeof("askpass") - 1, &flags,
		MODE_ASKPASS) == -1)
		goto bad;
	    continue;
	}
#ifdef ENABLE_SUDO_PLUGIN_API
	if (MATCHES(*cur, "plugin_dir=")) {
	    CHECK(*cur, "plugin_dir=");
	    path_plugin_dir = *cur + sizeof("plugin_dir=") - 1;
	    continue;
	}
#endif
    }
    /* Ignore ticket trumps update. */
    if (ISSET(flags, MODE_IGNORE_TICKET))
	CLR(flags, MODE_UPDATE_TICKET);

    user_gid = (gid_t)-1;
    user_uid = (gid_t)-1;
    user_umask = (mode_t)-1;
    for (cur = info->user_info; *cur != NULL; cur++) {
	if (MATCHES(*cur, "user=")) {
	    CHECK(*cur, "user=");
	    free(user_name);
	    if ((user_name = strdup(*cur + sizeof("user=") - 1)) == NULL)
		goto oom;
	    continue;
	}
	if (MATCHES(*cur, "uid=")) {
	    p = *cur + sizeof("uid=") - 1;
	    user_uid = (uid_t) sudo_strtoid(p, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "gid=")) {
	    p = *cur + sizeof("gid=") - 1;
	    user_gid = (gid_t) sudo_strtoid(p, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "groups=")) {
	    CHECK(*cur, "groups=");
	    groups = *cur + sizeof("groups=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "cwd=")) {
	    CHECK(*cur, "cwd=");
	    free(user_cwd);
	    if ((user_cwd = strdup(*cur + sizeof("cwd=") - 1)) == NULL)
		goto oom;
	    continue;
	}
	if (MATCHES(*cur, "tty=")) {
	    CHECK(*cur, "tty=");
	    free(user_ttypath);
	    if ((user_ttypath = strdup(*cur + sizeof("tty=") - 1)) == NULL)
		goto oom;
	    user_tty = user_ttypath;
	    if (strncmp(user_tty, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
		user_tty += sizeof(_PATH_DEV) - 1;
	    continue;
	}
	if (MATCHES(*cur, "host=")) {
	    CHECK(*cur, "host=");
	    if (user_shost != user_host)
		free(user_shost);
	    free(user_host);
	    if ((user_host = strdup(*cur + sizeof("host=") - 1)) == NULL)
		goto oom;
	    if ((p = strchr(user_host, '.')) != NULL) {
		user_shost = strndup(user_host, (size_t)(p - user_host));
		if (user_shost == NULL)
		    goto oom;
	    } else {
		user_shost = user_host;
	    }
	    continue;
	}
	if (MATCHES(*cur, "lines=")) {
	    errno = 0;
	    p = *cur + sizeof("lines=") - 1;
	    sudo_user.lines = sudo_strtonum(p, 1, INT_MAX, &errstr);
	    if (sudo_user.lines == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "cols=")) {
	    errno = 0;
	    p = *cur + sizeof("cols=") - 1;
	    sudo_user.cols = sudo_strtonum(p, 1, INT_MAX, &errstr);
	    if (sudo_user.cols == 0) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "sid=")) {
	    p = *cur + sizeof("sid=") - 1;
	    user_sid = (pid_t) sudo_strtoid(p, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "tcpgid=")) {
	    p = *cur + sizeof("tcpgid=") - 1;
	    user_tcpgid = (pid_t) sudo_strtoid(p, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
	if (MATCHES(*cur, "umask=")) {
	    p = *cur + sizeof("umask=") - 1;
	    sudo_user.umask = sudo_strtomode(p, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("%s: %s"), *cur, U_(errstr));
		goto bad;
	    }
	    continue;
	}
    }

    /* User name, user-ID, group-ID and host name must be specified. */
    if (user_name == NULL) {
	sudo_warnx("%s", U_("user name not set by sudo front-end"));
	goto bad;
    }
    if (user_uid == (uid_t)-1) {
	sudo_warnx("%s", U_("user-ID not set by sudo front-end"));
	goto bad;
    }
    if (user_gid == (gid_t)-1) {
	sudo_warnx("%s", U_("group-ID not set by sudo front-end"));
	goto bad;
    }
    if (user_host == NULL) {
	sudo_warnx("%s", U_("host name not set by sudo front-end"));
	goto bad;
    }

    if (user_srunhost != user_runhost)
	free(user_srunhost);
    free(user_runhost);
    if ((user_runhost = strdup(remhost ? remhost : user_host)) == NULL)
	goto oom;
    if ((p = strchr(user_runhost, '.')) != NULL) {
	user_srunhost = strndup(user_runhost, (size_t)(p - user_runhost));
	if (user_srunhost == NULL)
	    goto oom;
    } else {
	user_srunhost = user_runhost;
    }
    if (user_cwd == NULL) {
	if ((user_cwd = strdup("unknown")) == NULL)
	    goto oom;
    }
    if (user_runcwd == NULL) {
	/* Unlike user_cwd, user_runcwd is not free()d. */
	user_runcwd = user_cwd;
    }
    if (user_tty == NULL) {
	if ((user_tty = strdup("unknown")) == NULL)
	    goto oom;
	/* user_ttypath remains NULL */
    }

    if (groups != NULL) {
	/* sudo_parse_gids() will print a warning on error. */
	user_ngids = sudo_parse_gids(groups, &user_gid, &user_gids);
	if (user_ngids == -1)
	    goto bad;
    }

    /* umask is only set in user_info[] for API 1.10 and above. */
    if (user_umask == (mode_t)-1) {
	user_umask = umask(0);
	umask(user_umask);
    }

    /* Always reset the environment for a login shell. */
    if (ISSET(flags, MODE_LOGIN_SHELL))
	def_env_reset = true;

    /* Some systems support fexecve() which we use for digest matches. */
    cmnd_fd = -1;

    /* Create a UUID to store in the event log. */
    sudo_uuid_create(uuid);
    if (sudo_uuid_to_string(uuid, sudo_user.uuid_str, sizeof(sudo_user.uuid_str)) == NULL) {
	sudo_warnx("%s", U_("unable to generate UUID"));
	goto bad;
    }

    /*
     * Set intercept defaults based on flags set above.
     * We pass -1 as the operator to indicate it is set by the front end.
     */
    if (ISSET(sudo_user.flags, HAVE_INTERCEPT_PTRACE)) {
	if (!append_default("intercept_type", "trace", -1, NULL, defaults))
	    goto oom;
    }
    if (ISSET(sudo_user.flags, CAN_INTERCEPT_SETID)) {
	if (!append_default("intercept_allow_setid", NULL, -1, NULL, defaults))
	    goto oom;
    }

#ifdef NO_ROOT_MAILER
    eventlog_set_mailuid(user_uid);
#endif

    /* Dump settings and user info (XXX - plugin args) */
    for (cur = info->settings; *cur != NULL; cur++)
	sudo_debug_printf(SUDO_DEBUG_INFO, "settings: %s", *cur);
    for (cur = info->user_info; *cur != NULL; cur++)
	sudo_debug_printf(SUDO_DEBUG_INFO, "user_info: %s", *cur);

#undef MATCHES
#undef INVALID
#undef CHECK
    debug_return_int(flags);

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
bad:
    debug_return_int(MODE_ERROR);
}

/*
 * Store the execution environment and other front-end settings.
 * Builds up the command_info list and sets argv and envp.
 * Consumes iolog_path if not NULL.
 * Returns true on success, else false.
 */
bool
sudoers_policy_store_result(bool accepted, char *argv[], char *envp[],
    mode_t cmnd_umask, char *iolog_path, void *v)
{
    struct sudoers_exec_args *exec_args = v;
    int info_len = 0;
    debug_decl(sudoers_policy_store_result, SUDOERS_DEBUG_PLUGIN);

    if (exec_args == NULL)
	debug_return_bool(true);	/* nothing to do */

    /* Free old data, if any. */
    if (command_info != NULL) {
	char **cur;
	sudoers_gc_remove(GC_VECTOR, command_info);
	for (cur = command_info; *cur != NULL; cur++)
	    free(*cur);
	free(command_info);
    }

    /* Increase the length of command_info as needed, it is *not* checked. */
    command_info = calloc(73, sizeof(char *));
    if (command_info == NULL)
	goto oom;

    if (safe_cmnd != NULL) {
	command_info[info_len] = sudo_new_key_val("command", safe_cmnd);
	if (command_info[info_len++] == NULL)
	    goto oom;
    }
    if (def_log_subcmds) {
	if ((command_info[info_len++] = strdup("log_subcmds=true")) == NULL)
	    goto oom;
    }
    if (iolog_enabled) {
	if (iolog_path)
	    command_info[info_len++] = iolog_path;	/* now owned */
	if (def_log_stdin) {
	    if ((command_info[info_len++] = strdup("iolog_stdin=true")) == NULL)
		goto oom;
	}
	if (def_log_stdout) {
	    if ((command_info[info_len++] = strdup("iolog_stdout=true")) == NULL)
		goto oom;
	}
	if (def_log_stderr) {
	    if ((command_info[info_len++] = strdup("iolog_stderr=true")) == NULL)
		goto oom;
	}
	if (def_log_ttyin) {
	    if ((command_info[info_len++] = strdup("iolog_ttyin=true")) == NULL)
		goto oom;
	}
	if (def_log_ttyout) {
	    if ((command_info[info_len++] = strdup("iolog_ttyout=true")) == NULL)
		goto oom;
	}
	if (def_compress_io) {
	    if ((command_info[info_len++] = strdup("iolog_compress=true")) == NULL)
		goto oom;
	}
	if (def_iolog_flush) {
	    if ((command_info[info_len++] = strdup("iolog_flush=true")) == NULL)
		goto oom;
	}
	if ((command_info[info_len++] = sudo_new_key_val("log_passwords",
		def_log_passwords ? "true" : "false")) == NULL)
	    goto oom;
	if (!SLIST_EMPTY(&def_passprompt_regex)) {
	    char *passprompt_regex =
		serialize_list("passprompt_regex", &def_passprompt_regex);
	    if (passprompt_regex == NULL)
		goto oom;
	    command_info[info_len++] = passprompt_regex;
	}
	if (def_maxseq != NULL) {
	    if ((command_info[info_len++] = sudo_new_key_val("maxseq", def_maxseq)) == NULL)
		goto oom;
	}
    }
    if (ISSET(sudo_mode, MODE_EDIT)) {
	if ((command_info[info_len++] = strdup("sudoedit=true")) == NULL)
	    goto oom;
	if (sudoedit_nfiles > 0) {
	    if (asprintf(&command_info[info_len++], "sudoedit_nfiles=%d",
		sudoedit_nfiles) == -1)
		goto oom;
	}
	if (!def_sudoedit_checkdir) {
	    if ((command_info[info_len++] = strdup("sudoedit_checkdir=false")) == NULL)
		goto oom;
	}
	if (def_sudoedit_follow) {
	    if ((command_info[info_len++] = strdup("sudoedit_follow=true")) == NULL)
		goto oom;
	}
    }
    if (def_runcwd && strcmp(def_runcwd, "*") != 0) {
	/* Set cwd to explicit value in sudoers. */
	if (!expand_tilde(&def_runcwd, runas_pw->pw_name)) {
	    sudo_warnx(U_("invalid working directory: %s"), def_runcwd);
	    goto bad;
	}
	if ((command_info[info_len++] = sudo_new_key_val("cwd", def_runcwd)) == NULL)
	    goto oom;
    } else if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
	/* Set cwd to run user's homedir. */
	if ((command_info[info_len++] = sudo_new_key_val("cwd", runas_pw->pw_dir)) == NULL)
	    goto oom;
	if ((command_info[info_len++] = strdup("cwd_optional=true")) == NULL)
	    goto oom;
    }
    if ((command_info[info_len++] = sudo_new_key_val("runas_user", runas_pw->pw_name)) == NULL)
	goto oom;
    if (runas_gr != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("runas_group", runas_gr->gr_name)) == NULL)
	    goto oom;
    }
    if (def_stay_setuid) {
	if (asprintf(&command_info[info_len++], "runas_uid=%u",
	    (unsigned int)user_uid) == -1)
	    goto oom;
	if (asprintf(&command_info[info_len++], "runas_gid=%u",
	    (unsigned int)user_gid) == -1)
	    goto oom;
	if (asprintf(&command_info[info_len++], "runas_euid=%u",
	    (unsigned int)runas_pw->pw_uid) == -1)
	    goto oom;
	if (asprintf(&command_info[info_len++], "runas_egid=%u",
	    runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid) == -1)
	    goto oom;
    } else {
	if (asprintf(&command_info[info_len++], "runas_uid=%u",
	    (unsigned int)runas_pw->pw_uid) == -1)
	    goto oom;
	if (asprintf(&command_info[info_len++], "runas_gid=%u",
	    runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid) == -1)
	    goto oom;
    }
    if (def_preserve_groups) {
	if ((command_info[info_len++] = strdup("preserve_groups=true")) == NULL)
	    goto oom;
    } else {
	int i, len;
	gid_t egid;
	size_t glsize;
	char *cp, *gid_list;
	struct gid_list *gidlist;

	/* Only use results from a group db query, not the front end. */
	gidlist = sudo_get_gidlist(runas_pw, ENTRY_TYPE_QUERIED);

	/* We reserve an extra spot in the list for the effective gid. */
	glsize = sizeof("runas_groups=") - 1 +
	    ((gidlist->ngids + 1) * (MAX_UID_T_LEN + 1));
	gid_list = malloc(glsize);
	if (gid_list == NULL) {
	    sudo_gidlist_delref(gidlist);
	    goto oom;
	}
	memcpy(gid_list, "runas_groups=", sizeof("runas_groups=") - 1);
	cp = gid_list + sizeof("runas_groups=") - 1;

	/* On BSD systems the effective gid is the first group in the list. */
	egid = runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid;
	len = snprintf(cp, glsize - (cp - gid_list), "%u", (unsigned int)egid);
	if (len < 0 || (size_t)len >= glsize - (cp - gid_list)) {
	    sudo_warnx(U_("internal error, %s overflow"), __func__);
	    free(gid_list);
	    sudo_gidlist_delref(gidlist);
	    goto bad;
	}
	cp += len;
	for (i = 0; i < gidlist->ngids; i++) {
	    if (gidlist->gids[i] != egid) {
		len = snprintf(cp, glsize - (cp - gid_list), ",%u",
		     (unsigned int) gidlist->gids[i]);
		if (len < 0 || (size_t)len >= glsize - (cp - gid_list)) {
		    sudo_warnx(U_("internal error, %s overflow"), __func__);
		    free(gid_list);
		    sudo_gidlist_delref(gidlist);
		    goto bad;
		}
		cp += len;
	    }
	}
	command_info[info_len++] = gid_list;
	sudo_gidlist_delref(gidlist);
    }
    if (def_closefrom >= 0) {
	if (asprintf(&command_info[info_len++], "closefrom=%d", def_closefrom) == -1)
	    goto oom;
    }
    if (def_ignore_iolog_errors) {
	if ((command_info[info_len++] = strdup("ignore_iolog_errors=true")) == NULL)
	    goto oom;
    }
    if (def_intercept) {
	if ((command_info[info_len++] = strdup("intercept=true")) == NULL)
	    goto oom;
    }
    if (def_intercept_type == trace) {
	if ((command_info[info_len++] = strdup("use_ptrace=true")) == NULL)
	    goto oom;
    }
    if (def_intercept_verify) {
	if ((command_info[info_len++] = strdup("intercept_verify=true")) == NULL)
	    goto oom;
    }
    if (def_noexec) {
	if ((command_info[info_len++] = strdup("noexec=true")) == NULL)
	    goto oom;
    }
    if (def_exec_background) {
	if ((command_info[info_len++] = strdup("exec_background=true")) == NULL)
	    goto oom;
    }
    if (def_set_utmp) {
	if ((command_info[info_len++] = strdup("set_utmp=true")) == NULL)
	    goto oom;
    }
    if (def_use_pty) {
	if ((command_info[info_len++] = strdup("use_pty=true")) == NULL)
	    goto oom;
    }
    if (def_utmp_runas) {
	if ((command_info[info_len++] = sudo_new_key_val("utmp_user", runas_pw->pw_name)) == NULL)
	    goto oom;
    }
    if (def_iolog_mode != (S_IRUSR|S_IWUSR)) {
	if (asprintf(&command_info[info_len++], "iolog_mode=0%o", (unsigned int)def_iolog_mode) == -1)
	    goto oom;
    }
    if (def_iolog_user != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("iolog_user", def_iolog_user)) == NULL)
	    goto oom;
    }
    if (def_iolog_group != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("iolog_group", def_iolog_group)) == NULL)
	    goto oom;
    }
    if (!SLIST_EMPTY(&def_log_servers)) {
	char *log_servers = serialize_list("log_servers", &def_log_servers);
	if (log_servers == NULL)
	    goto oom;
	command_info[info_len++] = log_servers;

	if (asprintf(&command_info[info_len++], "log_server_timeout=%u", def_log_server_timeout) == -1)
	    goto oom;
    }

    if ((command_info[info_len++] = sudo_new_key_val("log_server_keepalive",
	    def_log_server_keepalive ? "true" : "false")) == NULL)
        goto oom;

    if ((command_info[info_len++] = sudo_new_key_val("log_server_verify",
	    def_log_server_verify ? "true" : "false")) == NULL)
        goto oom;

    if (def_log_server_cabundle != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("log_server_cabundle", def_log_server_cabundle)) == NULL)
            goto oom;
    }
    if (def_log_server_peer_cert != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("log_server_peer_cert", def_log_server_peer_cert)) == NULL)
            goto oom;
    }
    if (def_log_server_peer_key != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("log_server_peer_key", def_log_server_peer_key)) == NULL)
            goto oom;
    }

    if (def_command_timeout > 0 || user_timeout > 0) {
	int timeout = user_timeout;
    if (timeout == 0 || (def_command_timeout > 0 && def_command_timeout < timeout))
	    timeout = def_command_timeout;
	if (asprintf(&command_info[info_len++], "timeout=%u", timeout) == -1)
	    goto oom;
    }
    if (def_runchroot != NULL && strcmp(def_runchroot, "*") != 0) {
	if (!expand_tilde(&def_runchroot, runas_pw->pw_name)) {
	    sudo_warnx(U_("invalid chroot directory: %s"), def_runchroot);
	    goto bad;
	}
        if ((command_info[info_len++] = sudo_new_key_val("chroot", def_runchroot)) == NULL)
            goto oom;
    }
    if (cmnd_umask != ACCESSPERMS) {
	if (asprintf(&command_info[info_len++], "umask=0%o", (unsigned int)cmnd_umask) == -1)
	    goto oom;
    }
    if (force_umask) {
	if ((command_info[info_len++] = strdup("umask_override=true")) == NULL)
	    goto oom;
    }
    if (cmnd_fd != -1) {
	if (sudo_version < SUDO_API_MKVERSION(1, 9)) {
	    /* execfd only supported by plugin API 1.9 and higher */
	    close(cmnd_fd);
	    cmnd_fd = -1;
	} else {
	    if (asprintf(&command_info[info_len++], "execfd=%d", cmnd_fd) == -1)
		goto oom;
	}
    }
    if (def_rlimit_as != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_as", def_rlimit_as)) == NULL)
            goto oom;
    }
    if (def_rlimit_core != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_core", def_rlimit_core)) == NULL)
            goto oom;
    }
    if (def_rlimit_cpu != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_cpu", def_rlimit_cpu)) == NULL)
            goto oom;
    }
    if (def_rlimit_data != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_data", def_rlimit_data)) == NULL)
            goto oom;
    }
    if (def_rlimit_fsize != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_fsize", def_rlimit_fsize)) == NULL)
            goto oom;
    }
    if (def_rlimit_locks != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_locks", def_rlimit_locks)) == NULL)
            goto oom;
    }
    if (def_rlimit_memlock != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_memlock", def_rlimit_memlock)) == NULL)
            goto oom;
    }
    if (def_rlimit_nofile != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_nofile", def_rlimit_nofile)) == NULL)
            goto oom;
    }
    if (def_rlimit_nproc != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_nproc", def_rlimit_nproc)) == NULL)
            goto oom;
    }
    if (def_rlimit_rss != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_rss", def_rlimit_rss)) == NULL)
            goto oom;
    }
    if (def_rlimit_stack != NULL) {
        if ((command_info[info_len++] = sudo_new_key_val("rlimit_stack", def_rlimit_stack)) == NULL)
            goto oom;
    }
#ifdef HAVE_LOGIN_CAP_H
    if (def_use_loginclass) {
	if ((command_info[info_len++] = sudo_new_key_val("login_class", login_class)) == NULL)
	    goto oom;
    }
#endif /* HAVE_LOGIN_CAP_H */
#ifdef HAVE_SELINUX
    if (def_selinux && user_role != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("selinux_role", user_role)) == NULL)
	    goto oom;
    }
    if (def_selinux && user_type != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("selinux_type", user_type)) == NULL)
	    goto oom;
    }
#endif /* HAVE_SELINUX */
#ifdef HAVE_APPARMOR
	if (user_apparmor_profile != NULL) {
	    if ((command_info[info_len++] = sudo_new_key_val("apparmor_profile", user_apparmor_profile)) == NULL)
		goto oom;
	}
#endif /* HAVE_APPARMOR */
#ifdef HAVE_PRIV_SET
    if (runas_privs != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("runas_privs", runas_privs)) == NULL)
	    goto oom;
    }
    if (runas_limitprivs != NULL) {
	if ((command_info[info_len++] = sudo_new_key_val("runas_limitprivs", runas_limitprivs)) == NULL)
	    goto oom;
    }
#endif /* HAVE_PRIV_SET */

    /* Fill in exec environment info. */
    *(exec_args->argv) = argv;
    *(exec_args->envp) = envp;
    *(exec_args->info) = command_info;

    /* Free command_info on exit. */
    sudoers_gc_add(GC_VECTOR, command_info);

    debug_return_bool(true);

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
bad:
    free(audit_msg);
    audit_msg = NULL;
    while (info_len--)
	free(command_info[info_len]);
    free(command_info);
    debug_return_bool(false);
}

static int
sudoers_policy_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], char * const envp[], char * const args[],
    const char **errstr)
{
    struct sudo_conf_debug_file_list debug_files = TAILQ_HEAD_INITIALIZER(debug_files);
    struct sudoers_open_info info;
    const char *cp, *plugin_path = NULL;
    char * const *cur;
    int ret;
    debug_decl(sudoers_policy_open, SUDOERS_DEBUG_PLUGIN);

    sudo_version = version;
    sudo_conv = conversation;
    sudo_printf = plugin_printf;
    if (sudoers_policy.event_alloc != NULL)
	plugin_event_alloc = sudoers_policy.event_alloc;

    /* Plugin args are only specified for API version 1.2 and higher. */
    if (sudo_version < SUDO_API_MKVERSION(1, 2))
	args = NULL;

    /* Initialize the debug subsystem.  */
    for (cur = settings; (cp = *cur) != NULL; cur++) {
	if (strncmp(cp, "debug_flags=", sizeof("debug_flags=") - 1) == 0) {
	    cp += sizeof("debug_flags=") - 1;
	    if (!sudoers_debug_parse_flags(&debug_files, cp))
		debug_return_int(-1);
	    continue;
	}
	if (strncmp(cp, "plugin_path=", sizeof("plugin_path=") - 1) == 0) {
	    plugin_path = cp + sizeof("plugin_path=") - 1;
	    continue;
	}
    }
    if (!sudoers_debug_register(plugin_path, &debug_files))
	debug_return_int(-1);

    /* Call the sudoers init function. */
    info.settings = settings;
    info.user_info = user_info;
    info.plugin_args = args;
    ret = sudoers_init(&info, log_parse_error, envp);

    /* The audit functions set audit_msg on failure. */
    if (ret != 1 && audit_msg != NULL) {
	if (sudo_version >= SUDO_API_MKVERSION(1, 15))
	    *errstr = audit_msg;
    }

    debug_return_int(ret);
}

static void
sudoers_policy_close(int exit_status, int error_code)
{
    debug_decl(sudoers_policy_close, SUDOERS_DEBUG_PLUGIN);

    if (session_opened) {
	/* Close the session we opened in sudoers_policy_init_session(). */
	(void)sudo_auth_end_session(runas_pw);

	if (error_code) {
	    errno = error_code;
	    sudo_warn(U_("unable to execute %s"), safe_cmnd);
	} else {
	    log_exit_status(exit_status);
	}
    }

    /* Deregister the callback for sudo_fatal()/sudo_fatalx(). */
    sudo_fatal_callback_deregister(sudoers_cleanup);

    /* Free stashed copy of the environment. */
    (void)env_init(NULL);

    /* Free sudoers sources, sudo_user and passwd/group caches. */
    sudoers_cleanup();

    /* command_info is freed by the g/c code. */
    command_info = NULL;

    /* Free error message passed back to front-end, if any. */
    free(audit_msg);
    audit_msg = NULL;

    /* sudoers_debug_deregister() calls sudo_debug_exit() for us. */
    sudoers_debug_deregister();
}

/*
 * The init_session function is called before executing the command
 * and before uid/gid changes occur.
 * Returns 1 on success, 0 on failure and -1 on error.
 */
static int
sudoers_policy_init_session(struct passwd *pwd, char **user_env[],
    const char **errstr)
{
    int ret;
    debug_decl(sudoers_policy_init_session, SUDOERS_DEBUG_PLUGIN);

    /* user_env is only specified for API version 1.2 and higher. */
    if (sudo_version < SUDO_API_MKVERSION(1, 2))
	user_env = NULL;

    ret = sudo_auth_begin_session(pwd, user_env);

    if (ret == 1) {
	session_opened = true;
    } else if (audit_msg != NULL) {
	/* The audit functions set audit_msg on failure. */
	if (sudo_version >= SUDO_API_MKVERSION(1, 15))
	    *errstr = audit_msg;
    }
    debug_return_int(ret);
}

static int
sudoers_policy_check(int argc, char * const argv[], char *env_add[],
    char **command_infop[], char **argv_out[], char **user_env_out[],
    const char **errstr)
{
    int valid_flags = RUN_VALID_FLAGS;
    struct sudoers_exec_args exec_args;
    int ret;
    debug_decl(sudoers_policy_check, SUDOERS_DEBUG_PLUGIN);

    if (ISSET(sudo_mode, MODE_EDIT))
	valid_flags = EDIT_VALID_FLAGS;
    else
	SET(sudo_mode, MODE_RUN);

    if ((sudo_mode & valid_flags) != sudo_mode) {
	sudo_warnx(U_("%s: invalid mode flags from sudo front end: 0x%x"),
	    __func__, sudo_mode);
	debug_return_int(-1);
    }

    exec_args.argv = argv_out;
    exec_args.envp = user_env_out;
    exec_args.info = command_infop;

    ret = sudoers_policy_main(argc, argv, 0, env_add, false, &exec_args);
#ifndef NO_LEAKS
    if (ret == true && sudo_version >= SUDO_API_MKVERSION(1, 3)) {
	/* Unset close function if we don't need it to avoid extra process. */
	if (!iolog_enabled && !def_use_pty && !def_log_exit_status &&
		SLIST_EMPTY(&def_log_servers) && !sudo_auth_needs_end_session())
	    sudoers_policy.close = NULL;
    }
#endif

    /* The audit functions set audit_msg on failure. */
    if (ret != 1 && audit_msg != NULL) {
	if (sudo_version >= SUDO_API_MKVERSION(1, 15))
	    *errstr = audit_msg;
    }
    debug_return_int(ret);
}

static int
sudoers_policy_validate(const char **errstr)
{
    char *argv[] = { (char *)"validate", NULL };
    const int argc = 1;
    int ret;
    debug_decl(sudoers_policy_validate, SUDOERS_DEBUG_PLUGIN);

    SET(sudo_mode, MODE_VALIDATE);
    if ((sudo_mode & VALIDATE_VALID_FLAGS) != sudo_mode) {
	sudo_warnx(U_("%s: invalid mode flags from sudo front end: 0x%x"),
	    __func__, sudo_mode);
	debug_return_int(-1);
    }

    ret = sudoers_policy_main(argc, argv, I_VERIFYPW, NULL, false, NULL);

    /* The audit functions set audit_msg on failure. */
    if (ret != 1 && audit_msg != NULL) {
	if (sudo_version >= SUDO_API_MKVERSION(1, 15))
	    *errstr = audit_msg;
    }
    debug_return_int(ret);
}

static void
sudoers_policy_invalidate(int unlinkit)
{
    debug_decl(sudoers_policy_invalidate, SUDOERS_DEBUG_PLUGIN);

    SET(sudo_mode, MODE_INVALIDATE);
    if ((sudo_mode & INVALIDATE_VALID_FLAGS) != sudo_mode) {
	sudo_warnx(U_("%s: invalid mode flags from sudo front end: 0x%x"),
	    __func__, sudo_mode);
    } else {
	timestamp_remove(unlinkit);
    }

    debug_return;
}

static int
sudoers_policy_list(int argc, char * const argv[], int verbose,
    const char *list_user, const char **errstr)
{
    char *list_argv[] = { (char *)"list", NULL };
    int ret;
    debug_decl(sudoers_policy_list, SUDOERS_DEBUG_PLUGIN);

    if (argc == 0) {
	SET(sudo_mode, MODE_LIST);
	argc = 1;
	argv = list_argv;
    } else {
	SET(sudo_mode, MODE_CHECK);
    }

    if ((sudo_mode & LIST_VALID_FLAGS) != sudo_mode) {
	sudo_warnx(U_("%s: invalid mode flags from sudo front end: 0x%x"),
	    __func__, sudo_mode);
	debug_return_int(-1);
    }

    if (list_user) {
	list_pw = sudo_getpwnam(list_user);
	if (list_pw == NULL) {
	    sudo_warnx(U_("unknown user %s"), list_user);
	    debug_return_int(-1);
	}
    }
    ret = sudoers_policy_main(argc, argv, I_LISTPW, NULL, verbose, NULL);
    if (list_user) {
	sudo_pw_delref(list_pw);
	list_pw = NULL;
    }

    /* The audit functions set audit_msg on failure. */
    if (ret != 1 && audit_msg != NULL) {
	if (sudo_version >= SUDO_API_MKVERSION(1, 15))
	    *errstr = audit_msg;
    }
    debug_return_int(ret);
}

static int
sudoers_policy_version(int verbose)
{
    debug_decl(sudoers_policy_version, SUDOERS_DEBUG_PLUGIN);

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
    debug_return_int(true);
}

static struct sudo_hook sudoers_hooks[] = {
    { SUDO_HOOK_VERSION, SUDO_HOOK_SETENV, sudoers_hook_setenv, NULL },
    { SUDO_HOOK_VERSION, SUDO_HOOK_UNSETENV, sudoers_hook_unsetenv, NULL },
    { SUDO_HOOK_VERSION, SUDO_HOOK_GETENV, sudoers_hook_getenv, NULL },
    { SUDO_HOOK_VERSION, SUDO_HOOK_PUTENV, sudoers_hook_putenv, NULL },
    { 0, 0, NULL, NULL }
};

/*
 * Register environment function hooks.
 * Note that we have not registered sudoers with the debug subsystem yet.
 */
static void
sudoers_policy_register_hooks(int version, int (*register_hook)(struct sudo_hook *hook))
{
    struct sudo_hook *hook;

    for (hook = sudoers_hooks; hook->hook_fn != NULL; hook++) {
	if (register_hook(hook) != 0) {
	    sudo_warn_nodebug(
		U_("unable to register hook of type %d (version %d.%d)"),
		hook->hook_type, SUDO_API_VERSION_GET_MAJOR(hook->hook_version),
		SUDO_API_VERSION_GET_MINOR(hook->hook_version));
	}
    }
}

/*
 * De-register environment function hooks.
 */
static void
sudoers_policy_deregister_hooks(int version, int (*deregister_hook)(struct sudo_hook *hook))
{
    struct sudo_hook *hook;

    for (hook = sudoers_hooks; hook->hook_fn != NULL; hook++) {
	if (deregister_hook(hook) != 0) {
	    sudo_warn_nodebug(
		U_("unable to deregister hook of type %d (version %d.%d)"),
		hook->hook_type, SUDO_API_VERSION_GET_MAJOR(hook->hook_version),
		SUDO_API_VERSION_GET_MINOR(hook->hook_version));
	}
    }
}

sudo_dso_public struct policy_plugin sudoers_policy = {
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
    sudoers_policy_register_hooks,
    sudoers_policy_deregister_hooks,
    NULL /* event_alloc() filled in by sudo */
};
