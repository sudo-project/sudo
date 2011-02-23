/*
 * Copyright (c) 1993-1996, 1998-2011 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * For a brief history of sudo, please see the HISTORY file included
 * with this distribution.
 */

#define _SUDO_MAIN

#ifdef __TANDEM
# include <floss.h>
#endif

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
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
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <grp.h>
#include <time.h>
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif
#include <netinet/in.h>
#include <netdb.h>
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
# ifndef LOGIN_DEFROOTCLASS
#  define LOGIN_DEFROOTCLASS	"daemon"
# endif
#endif
#ifdef HAVE_SELINUX
# include <selinux/selinux.h>
#endif
#ifdef HAVE_MBR_CHECK_MEMBERSHIP
# include <membership.h>
#endif
#include <ctype.h>
#include <setjmp.h>

#include "sudoers.h"
#include "lbuf.h"
#include "interfaces.h"
#include "auth/sudo_auth.h"

/*
 * Prototypes
 */
static void init_vars(char * const *);
static int set_cmnd(int);
static void set_loginclass(struct passwd *);
static void set_runasgr(char *);
static void set_runaspw(char *);
static int sudoers_policy_version(int verbose);
static int deserialize_info(char * const settings[], char * const user_info[]);
static char *find_editor(int nfiles, char **files, char ***argv_out);
static void create_admin_success_flag(void);

/* XXX */
extern int runas_ngroups;
extern GETGROUPS_T *runas_groups;

/*
 * Globals
 */
const char *sudoers_file = _PATH_SUDOERS;
mode_t sudoers_mode = SUDOERS_MODE;
uid_t sudoers_uid = SUDOERS_UID;
gid_t sudoers_gid = SUDOERS_GID;
struct sudo_user sudo_user;
struct passwd *list_pw;
struct interface *interfaces;
int long_list;
int debug_level;
uid_t timestamp_uid;
extern int errorlineno;
extern int parse_error;
extern char *errorfile;
#ifdef HAVE_LOGIN_CAP_H
login_cap_t *lc;
#endif /* HAVE_LOGIN_CAP_H */
#ifdef HAVE_BSD_AUTH_H
char *login_style;
#endif /* HAVE_BSD_AUTH_H */
sudo_conv_t sudo_conv;
sudo_printf_t sudo_printf;
int sudo_mode;

static char *prev_user;
static char *runas_user;
static char *runas_group;
static struct sudo_nss_list *snl;
static const char *interfaces_string;
static sigaction_t saved_sa_int, saved_sa_quit, saved_sa_tstp;

/* XXX - must be extern for audit bits of sudo_auth.c */
int NewArgc;
char **NewArgv;

/* plugin_error.c */
extern sigjmp_buf error_jmp;

static int
sudoers_policy_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], char * const envp[])
{
    volatile int sources = 0;
    sigaction_t sa;
    struct sudo_nss *nss;

    if (!sudo_conv)
	sudo_conv = conversation;
    if (!sudo_printf)
	sudo_printf = plugin_printf;

    if (sigsetjmp(error_jmp, 1)) {
	/* called via error(), errorx() or log_error() */
	rewind_perms();
	return -1;
    }

    /*
     * Signal setup:
     *	Ignore keyboard-generated signals so the user cannot interrupt
     *  us at some point and avoid the logging.
     *  Install handler to wait for children when they exit.
     */
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGINT, &sa, &saved_sa_int);
    (void) sigaction(SIGQUIT, &sa, &saved_sa_quit);
    (void) sigaction(SIGTSTP, &sa, &saved_sa_tstp);

    sudo_setpwent();
    sudo_setgrent();

    /* Initialize environment functions (including replacements). */
    env_init(envp);

    /* Setup defaults data structures. */
    init_defaults();

    /* Parse settings and user_info */
    sudo_mode = deserialize_info(settings, user_info);

    init_vars(envp);		/* XXX - move this later? */

    /* Parse nsswitch.conf for sudoers order. */
    snl = sudo_read_nss();

    set_perms(PERM_INITIAL);

    /* Open and parse sudoers, set global defaults */
    tq_foreach_fwd(snl, nss) {
	if (nss->open(nss) == 0 && nss->parse(nss) == 0) {
	    sources++;
	    if (nss->setdefs(nss) != 0)
		log_error(NO_STDERR|NO_EXIT, "problem with defaults entries");
	}
    }
    if (sources == 0) {
	warningx("no valid sudoers sources found, quitting");
	return -1;
    }

    /* XXX - collect post-sudoers parse settings into a function */

    /*
     * Initialize external group plugin.
     */
    if (def_group_plugin) {
	switch (group_plugin_load(def_group_plugin)) {
	case -1:
	    return -1;
	case FALSE:
	    def_group_plugin = NULL;
	}
    }

    /*
     * Set runas passwd/group entries based on command line or sudoers.
     * Note that if runas_group was specified without runas_user we
     * defer setting runas_pw so the match routines know to ignore it.
     */
    if (runas_group != NULL) {
	set_runasgr(runas_group);
	if (runas_user != NULL)
	    set_runaspw(runas_user);
    } else
	set_runaspw(runas_user ? runas_user : def_runas_default);

    if (!update_defaults(SETDEF_RUNAS))
	log_error(NO_STDERR|NO_EXIT, "problem with defaults entries");

    if (def_fqdn)
	set_fqdn();	/* deferred until after sudoers is parsed */

    /* Set login class if applicable. */
    set_loginclass(sudo_user.pw);

    restore_perms();

    return TRUE;
}

static void
sudoers_policy_close(int exit_status, int error_code)
{
    if (sigsetjmp(error_jmp, 1)) {
	/* called via error(), errorx() or log_error() */
	return;
    }

    /* We do not currently log the exit status. */
    if (error_code)
	warningx("unable to execute %s: %s", safe_cmnd, strerror(error_code));

    /* Close the session we opened in sudoers_policy_init_session(). */
    if (ISSET(sudo_mode, MODE_RUN|MODE_EDIT))
	(void)auth_end_session();

    /* Free remaining references to password and group entries. */
    pw_delref(sudo_user.pw);
    pw_delref(runas_pw);
    if (runas_gr != NULL)
	gr_delref(runas_gr);
}

/*
 * The init_session function is called before executing the command
 * and before uid/gid changes occur.
 */
static int
sudoers_policy_init_session(struct passwd *pwd)
{
    if (sigsetjmp(error_jmp, 1)) {
	/* called via error(), errorx() or log_error() */
	return -1;
    }

    return auth_begin_session(pwd);
}

static int
sudoers_policy_main(int argc, char * const argv[], int pwflag, char *env_add[],
    char **command_infop[], char **argv_out[], char **user_env_out[])
{
    static char *command_info[32]; /* XXX */
    char **edit_argv = NULL;
    struct sudo_nss *nss;
    int cmnd_status = -1, validated;
    volatile int info_len = 0;
    volatile int rval = FALSE;

    if (sigsetjmp(error_jmp, 1)) {
	/* error recovery via error(), errorx() or log_error() */
	rewind_perms();
	return -1;
    }

    /* Is root even allowed to run sudo? */
    if (user_uid == 0 && !def_root_sudo) {
        warningx("sudoers specifies that root is not allowed to sudo");
        goto done;
    }    

    /* Check for -C overriding def_closefrom. */
    if (user_closefrom >= 0 && user_closefrom != def_closefrom) {
	if (!def_closefrom_override) {
	    warningx("you are not permitted to use the -C option");
	    goto done;
	}
	def_closefrom = user_closefrom;
    }

    set_perms(PERM_INITIAL);

    /* Environment variables specified on the command line. */
    if (env_add != NULL && env_add[0] != NULL)
	sudo_user.env_vars = env_add;

    /*
     * Make a local copy of argc/argv, with special handling
     * for pseudo-commands and the '-i' option.
     */
    if (argc == 0) {
	NewArgc = 1;
	NewArgv = emalloc2(NewArgc + 1, sizeof(char *));
	NewArgv[0] = user_cmnd;
	NewArgv[1] = NULL;
    } else {
	NewArgc = argc;
	NewArgv = emalloc2(NewArgc + 1, sizeof(char *));
	memcpy(NewArgv, argv, argc * sizeof(char *));
	NewArgv[NewArgc] = NULL;
	if (ISSET(sudo_mode, MODE_LOGIN_SHELL))
	    NewArgv[0] = estrdup(runas_pw->pw_shell);
    }

    /* Find command in path */
    cmnd_status = set_cmnd(sudo_mode);
    if (cmnd_status == -1) {
	rval = -1;
	goto done;
    }

#ifdef HAVE_SETLOCALE
    if (!setlocale(LC_ALL, def_sudoers_locale)) {
	warningx("unable to set locale to \"%s\", using \"C\"",
	    def_sudoers_locale);
	setlocale(LC_ALL, "C");
    }
#endif

    /*
     * Check sudoers sources.
     */
    validated = FLAG_NO_USER | FLAG_NO_HOST;
    tq_foreach_fwd(snl, nss) {
	validated = nss->lookup(nss, validated, pwflag);

	if (ISSET(validated, VALIDATE_OK)) {
	    /* Handle "= auth" in netsvc.conf */
	    if (nss->ret_if_found)
		break;
	} else {
	    /* Handle [NOTFOUND=return] */
	    if (nss->ret_if_notfound)
		break;
	}
    }

    if (safe_cmnd == NULL)
	safe_cmnd = estrdup(user_cmnd);

#ifdef HAVE_SETLOCALE
    setlocale(LC_ALL, "");
#endif

    /* If only a group was specified, set runas_pw based on invoking user. */
    if (runas_pw == NULL)
	set_runaspw(user_name);

    /*
     * Look up the timestamp dir owner if one is specified.
     */
    if (def_timestampowner) {
	struct passwd *pw;

	if (*def_timestampowner == '#')
	    pw = sudo_getpwuid(atoi(def_timestampowner + 1));
	else
	    pw = sudo_getpwnam(def_timestampowner);
	if (!pw)
	    log_error(0, "timestamp owner (%s): No such user",
		def_timestampowner);
	timestamp_uid = pw->pw_uid;
	pw_delref(pw);
    }

    /* If given the -P option, set the "preserve_groups" flag. */
    if (ISSET(sudo_mode, MODE_PRESERVE_GROUPS))
	def_preserve_groups = TRUE;

    /* If no command line args and "shell_noargs" is not set, error out. */
    if (ISSET(sudo_mode, MODE_IMPLIED_SHELL) && !def_shell_noargs) {
	rval = -2; /* usage error */
	goto done;
    }

    /* Bail if a tty is required and we don't have one.  */
    if (def_requiretty) {
	int fd = open(_PATH_TTY, O_RDWR|O_NOCTTY);
	if (fd == -1) {
	    audit_failure(NewArgv, "no tty");
	    warningx("sorry, you must have a tty to run sudo");
	    goto done;
	} else
	    (void) close(fd);
    }

    /*
     * We don't reset the environment for sudoedit or if the user
     * specified the -E command line flag and they have setenv privs.
     */
    if (ISSET(sudo_mode, MODE_EDIT) ||
	(ISSET(sudo_mode, MODE_PRESERVE_ENV) && def_setenv))
	def_env_reset = FALSE;

    /* Build a new environment that avoids any nasty bits. */
    rebuild_env(def_noexec);

    /* Require a password if sudoers says so.  */
    if (def_authenticate) {
	int rc = check_user(validated, sudo_mode);
	if (rc != TRUE) {
	    rval = rc;
	    goto done;
	}
    }

    /* If run as root with SUDO_USER set, set sudo_user.pw to that user. */
    /* XXX - causes confusion when root is not listed in sudoers */
    if (sudo_mode & (MODE_RUN | MODE_EDIT) && prev_user != NULL) {
	if (user_uid == 0 && strcmp(prev_user, "root") != 0) {
	    struct passwd *pw;

	    if ((pw = sudo_getpwnam(prev_user)) != NULL) {
		    if (sudo_user.pw != NULL)
			pw_delref(sudo_user.pw);
		    sudo_user.pw = pw;
#ifdef HAVE_MBR_CHECK_MEMBERSHIP
		    mbr_uid_to_uuid(user_uid, user_uuid);
#endif
	    }
	}
    }

    /* If the user was not allowed to run the command we are done. */
    if (!ISSET(validated, VALIDATE_OK)) {
	if (ISSET(validated, FLAG_NO_USER | FLAG_NO_HOST)) {
	    audit_failure(NewArgv, "No user or host");
	    log_denial(validated, 1);
	} else {
	    if (def_path_info) {
		/*
		 * We'd like to not leak path info at all here, but that can
		 * *really* confuse the users.  To really close the leak we'd
		 * have to say "not allowed to run foo" even when the problem
		 * is just "no foo in path" since the user can trivially set
		 * their path to just contain a single dir.
		 */
		log_denial(validated,
		    !(cmnd_status == NOT_FOUND_DOT || cmnd_status == NOT_FOUND));
		if (cmnd_status == NOT_FOUND)
		    warningx("%s: command not found", user_cmnd);
		else if (cmnd_status == NOT_FOUND_DOT)
		    warningx("ignoring `%s' found in '.'\nUse `sudo ./%s' if this is the `%s' you wish to run.", user_cmnd, user_cmnd, user_cmnd);
	    } else {
		/* Just tell the user they are not allowed to run foo. */
		log_denial(validated, 1);
	    }
	    audit_failure(NewArgv, "validation failure");
	}
	goto done;
    }

    /* Create Ubuntu-style dot file to indicate sudo was successful. */
    create_admin_success_flag();

    /* Finally tell the user if the command did not exist. */
    if (cmnd_status == NOT_FOUND_DOT) {
	audit_failure(NewArgv, "command in current directory");
	warningx("ignoring `%s' found in '.'\nUse `sudo ./%s' if this is the `%s' you wish to run.", user_cmnd, user_cmnd, user_cmnd);
	goto done;
    } else if (cmnd_status == NOT_FOUND) {
	audit_failure(NewArgv, "%s: command not found", user_cmnd);
	warningx("%s: command not found", user_cmnd);
	goto done;
    }

    /* If user specified env vars make sure sudoers allows it. */
    if (ISSET(sudo_mode, MODE_RUN) && !def_setenv) {
	if (ISSET(sudo_mode, MODE_PRESERVE_ENV)) {
	    warningx("sorry, you are not allowed to preserve the environment");
	    goto done;
	} else
	    validate_env_vars(sudo_user.env_vars);
    }

    if (ISSET(sudo_mode, (MODE_RUN | MODE_EDIT)) && (def_log_input || def_log_output)) {
	if (def_iolog_file && def_iolog_dir) {
	    if (strstr(def_iolog_file, "%{seq}") != NULL) /* XXX - inline? */
		io_nextid(def_iolog_dir, sudo_user.sessid);
	    command_info[info_len++] = expand_iolog_path("iolog_path=",
		def_iolog_dir, def_iolog_file, NULL);
	}
	if (def_log_input) {
	    command_info[info_len++] = estrdup("iolog_stdin=true");
	    command_info[info_len++] = estrdup("iolog_ttyin=true");
	}
	if (def_log_output) {
	    command_info[info_len++] = estrdup("iolog_stdout=true");
	    command_info[info_len++] = estrdup("iolog_stderr=true");
	    command_info[info_len++] = estrdup("iolog_ttyout=true");
	}
	if (def_compress_io)
	    command_info[info_len++] = estrdup("iolog_compress=true");
    }

    log_allowed(validated);
    if (ISSET(sudo_mode, MODE_CHECK))
	rval = display_cmnd(snl, list_pw ? list_pw : sudo_user.pw);
    else if (ISSET(sudo_mode, MODE_LIST))
	display_privs(snl, list_pw ? list_pw : sudo_user.pw); /* XXX - return val */

    /* Cleanup sudoers sources */
    tq_foreach_fwd(snl, nss) {
	nss->close(nss);
    }
    if (def_group_plugin)
	group_plugin_unload();

    if (ISSET(sudo_mode, (MODE_VALIDATE|MODE_CHECK|MODE_LIST)))
	goto done;

    /*
     * Set umask based on sudoers.
     * If user's umask is more restrictive, OR in those bits too
     * unless umask_override is set.
     */
    if (def_umask != 0777) {
	mode_t mask = def_umask;
	if (!def_umask_override) {
	    mode_t omask = umask(mask);
	    mask |= omask;
	    umask(omask);
	}
	easprintf(&command_info[info_len++], "umask=0%o", (unsigned int)mask);
    }

    if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
	char *p;

	/* Convert /bin/sh -> -sh so shell knows it is a login shell */
	if ((p = strrchr(NewArgv[0], '/')) == NULL)
	    p = NewArgv[0];
	*p = '-';
	NewArgv[0] = p;

	/* Set cwd to run user's homedir. */
	command_info[info_len++] = fmt_string("cwd", runas_pw->pw_dir);

#if defined(__linux__) || defined(_AIX)
	/* Insert system-wide environment variables. */
	read_env_file(_PATH_ENVIRONMENT, TRUE);
#endif
    }

    /* Insert system-wide environment variables. */
    if (def_env_file)
	read_env_file(def_env_file, FALSE);

    /* Insert user-specified environment variables. */
    insert_env_vars(sudo_user.env_vars);

    /* Restore signal handlers before we exec. */
    (void) sigaction(SIGINT, &saved_sa_int, NULL);
    (void) sigaction(SIGQUIT, &saved_sa_quit, NULL);
    (void) sigaction(SIGTSTP, &saved_sa_tstp, NULL);

    if (ISSET(sudo_mode, MODE_EDIT)) {
	char *editor = find_editor(NewArgc - 1, NewArgv + 1, &edit_argv);
	if (!editor)
	    goto done;
	command_info[info_len++] = fmt_string("command", editor);
	command_info[info_len++] = estrdup("sudoedit=true");
    } else {
	command_info[info_len++] = fmt_string("command", safe_cmnd);
    }
    if (def_stay_setuid) {
	easprintf(&command_info[info_len++], "runas_uid=%u",
	    (unsigned int)user_uid);
	easprintf(&command_info[info_len++], "runas_gid=%u",
	    (unsigned int)user_gid);
	easprintf(&command_info[info_len++], "runas_euid=%u",
	    (unsigned int)runas_pw->pw_uid);
	easprintf(&command_info[info_len++], "runas_egid=%u",
	    runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid);
    } else {
	easprintf(&command_info[info_len++], "runas_uid=%u",
	    (unsigned int)runas_pw->pw_uid);
	easprintf(&command_info[info_len++], "runas_gid=%u",
	    runas_gr ? (unsigned int)runas_gr->gr_gid :
	    (unsigned int)runas_pw->pw_gid);
    }
    if (def_preserve_groups) {
	command_info[info_len++] = "preserve_groups=true";
    } else if (runas_ngroups != -1) {
	int i, len;
	size_t glsize;
	char *cp, *gid_list;

	glsize = sizeof("runas_groups=") - 1 + (runas_ngroups * (MAX_UID_T_LEN + 1));
	gid_list = emalloc(glsize);
	memcpy(gid_list, "runas_groups=", sizeof("runas_groups=") - 1);
	cp = gid_list + sizeof("runas_groups=") - 1;
	for (i = 0; i < runas_ngroups; i++) {
	    /* XXX - check rval */
	    len = snprintf(cp, glsize - (cp - gid_list), "%s%u",
		 i ? "," : "", (unsigned int) runas_groups[i]);
	    cp += len;
	}
	command_info[info_len++] = gid_list;
    }
    if (def_closefrom >= 0)
	easprintf(&command_info[info_len++], "closefrom=%d", def_closefrom);
#ifdef HAVE_SELINUX
    if (user_role != NULL)
	command_info[info_len++] = fmt_string("selinux_role", user_role);
    if (user_type != NULL)
	command_info[info_len++] = fmt_string("selinux_type", user_type);
#endif /* HAVE_SELINUX */

    /* Must audit before uid change. */
    audit_success(NewArgv);

    *command_infop = command_info;

    *argv_out = edit_argv ? edit_argv : NewArgv;
    *user_env_out = env_get(); /* our private copy */

    rval = TRUE;

    restore_perms();

done:
    /* Close the password and group files and free up memory. */
    sudo_endpwent();
    sudo_endgrent();

    return rval;
}

static int
sudoers_policy_check(int argc, char * const argv[], char *env_add[],
    char **command_infop[], char **argv_out[], char **user_env_out[])
{
    if (!ISSET(sudo_mode, MODE_EDIT))
	SET(sudo_mode, MODE_RUN);

    return sudoers_policy_main(argc, argv, 0, env_add, command_infop,
	argv_out, user_env_out);
}

static int
sudoers_policy_validate(void)
{
    user_cmnd = "validate";
    SET(sudo_mode, MODE_VALIDATE);

    return sudoers_policy_main(0, NULL, I_VERIFYPW, NULL, NULL, NULL, NULL);
}

static void
sudoers_policy_invalidate(int remove)
{
    user_cmnd = "kill";
    if (sigsetjmp(error_jmp, 1) == 0) {
	remove_timestamp(remove);
	plugin_cleanup(0);
    }
}

static int
sudoers_policy_list(int argc, char * const argv[], int verbose,
    const char *list_user)
{
    int rval;

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
	    warningx("unknown user: %s", list_user);
	    return -1;
	}
    }
    rval = sudoers_policy_main(argc, argv, I_LISTPW, NULL, NULL, NULL, NULL);
    if (list_user) {
	pw_delref(list_pw);
	list_pw = NULL;
    }

    return rval;
}

/*
 * Initialize timezone, set umask, fill in ``sudo_user'' struct and
 * load the ``interfaces'' array.
 */
static void
init_vars(char * const envp[])
{
    char * const * ep;

#ifdef HAVE_TZSET
    (void) tzset();		/* set the timezone if applicable */
#endif /* HAVE_TZSET */

    for (ep = envp; *ep; ep++) {
	/* XXX - don't fill in if empty string */
	switch (**ep) {
	    case 'K':
		if (strncmp("KRB5CCNAME=", *ep, 11) == 0)
		    user_ccname = *ep + 11;
		break;
	    case 'P':
		if (strncmp("PATH=", *ep, 5) == 0)
		    user_path = *ep + 5;
		break;
	    case 'S':
		if (!user_prompt && strncmp("SUDO_PROMPT=", *ep, 12) == 0)
		    user_prompt = *ep + 12;
		else if (strncmp("SUDO_USER=", *ep, 10) == 0)
		    prev_user = *ep + 10;
		break;
	    }
    }

    /*
     * Get a local copy of the user's struct passwd with the shadow password
     * if necessary.  It is assumed that euid is 0 at this point so we
     * can read the shadow passwd file if necessary.
     */
    if ((sudo_user.pw = sudo_getpwnam(user_name)) == NULL) {
	struct passwd pw;

	/* Create a fake struct passwd for log_error(). */
	memset(&pw, 0, sizeof(pw));
	pw.pw_uid = getuid();
	pw.pw_name = user_name;
	sudo_user.pw = &pw;

	/*
	 * It is not unusual for users to place "sudo -k" in a .logout
	 * file which can cause sudo to be run during reboot after the
	 * YP/NIS/NIS+/LDAP/etc daemon has died.
	 */
	if (sudo_mode == MODE_KILL || sudo_mode == MODE_INVALIDATE)
	    errorx(1, "unknown user: %s", user_name);
	log_error(0, "unknown user: %s", user_name);
	/* NOTREACHED */
    }
#ifdef HAVE_MBR_CHECK_MEMBERSHIP
    mbr_uid_to_uuid(user_uid, user_uuid);
#endif

    /* It is now safe to use log_error() and set_perms() */
}

/*
 * Fill in user_cmnd, user_args, user_base and user_stat variables
 * and apply any command-specific defaults entries.
 */
static int
set_cmnd(int sudo_mode)
{
    int rval;
    char *path = user_path;

    /* Resolve the path and return. */
    rval = FOUND;
    user_stat = emalloc(sizeof(struct stat));

    /* Default value for cmnd, overridden below. */
    if (user_cmnd == NULL)
	user_cmnd = NewArgv[0];

    if (sudo_mode & (MODE_RUN | MODE_EDIT | MODE_CHECK)) {
	if (ISSET(sudo_mode, MODE_RUN | MODE_CHECK)) {
	    if (def_secure_path && !user_is_exempt())
		path = def_secure_path;
	    set_perms(PERM_RUNAS);
	    rval = find_path(NewArgv[0], &user_cmnd, user_stat, path,
		def_ignore_dot);
	    restore_perms();
	    if (rval != FOUND) {
		/* Failed as root, try as invoking user. */
		set_perms(PERM_USER);
		rval = find_path(NewArgv[0], &user_cmnd, user_stat, path,
		    def_ignore_dot);
		restore_perms();
	    }
	}

	/* set user_args */
	if (NewArgc > 1) {
	    char *to, **from;
	    size_t size, n;

	    /* Alloc and build up user_args. */
	    for (size = 0, from = NewArgv + 1; *from; from++)
		size += strlen(*from) + 1;
	    user_args = emalloc(size);
	    for (to = user_args, from = NewArgv + 1; *from; from++) {
		n = strlcpy(to, *from, size - (to - user_args));
		if (n >= size - (to - user_args))
		    errorx(1, "internal error, set_cmnd() overflow");
		to += n;
		*to++ = ' ';
	    }
	    *--to = '\0';
	}
    }
    if (strlen(user_cmnd) >= PATH_MAX)
	errorx(1, "%s: file name too long", user_cmnd);

    if ((user_base = strrchr(user_cmnd, '/')) != NULL)
	user_base++;
    else
	user_base = user_cmnd;

    if (!update_defaults(SETDEF_CMND))
	log_error(NO_STDERR|NO_EXIT, "problem with defaults entries");

    if (!runas_user && !runas_group)
	set_runaspw(def_runas_default);	/* may have been updated above */

    return rval;
}

/*
 * Open sudoers and sanity check mode/owner/type.
 * Returns a handle to the sudoers file or NULL on error.
 */
FILE *
open_sudoers(const char *sudoers, int doedit, int *keepopen)
{
    struct stat statbuf;
    FILE *fp = NULL;
    int rootstat;

    /*
     * Fix the mode and group on sudoers file from old default.
     * Only works if file system is readable/writable by root.
     */
    if ((rootstat = stat_sudoers(sudoers, &statbuf)) == 0 &&
	sudoers_uid == statbuf.st_uid && sudoers_mode != 0400 &&
	(statbuf.st_mode & 0007777) == 0400) {

	if (chmod(sudoers, sudoers_mode) == 0) {
	    warningx("fixed mode on %s", sudoers);
	    SET(statbuf.st_mode, sudoers_mode);
	    if (statbuf.st_gid != sudoers_gid) {
		if (chown(sudoers, (uid_t) -1, sudoers_gid) == 0) {
		    warningx("set group on %s", sudoers);
		    statbuf.st_gid = sudoers_gid;
		} else
		    warning("unable to set group on %s", sudoers);
	    }
	} else
	    warning("unable to fix mode on %s", sudoers);
    }

    /*
     * Sanity checks on sudoers file.  Must be done as sudoers
     * file owner.  We already did a stat as root, so use that
     * data if we can't stat as sudoers file owner.
     */
    set_perms(PERM_SUDOERS);

    if (rootstat != 0 && stat_sudoers(sudoers, &statbuf) != 0)
	log_error(USE_ERRNO|NO_EXIT, "can't stat %s", sudoers);
    else if (!S_ISREG(statbuf.st_mode))
	log_error(NO_EXIT, "%s is not a regular file", sudoers);
    else if ((statbuf.st_mode & 07577) != sudoers_mode)
	log_error(NO_EXIT, "%s is mode 0%o, should be 0%o", sudoers,
	    (unsigned int) (statbuf.st_mode & 07777),
	    (unsigned int) sudoers_mode);
    else if (statbuf.st_uid != sudoers_uid)
	log_error(NO_EXIT, "%s is owned by uid %u, should be %u", sudoers,
	    (unsigned int) statbuf.st_uid, (unsigned int) sudoers_uid);
    else if (statbuf.st_gid != sudoers_gid)
	log_error(NO_EXIT, "%s is owned by gid %u, should be %u", sudoers,
	    (unsigned int) statbuf.st_gid, (unsigned int) sudoers_gid);
    else if ((fp = fopen(sudoers, "r")) == NULL)
	log_error(USE_ERRNO|NO_EXIT, "can't open %s", sudoers);
    else {
	/*
	 * Make sure we can actually read sudoers so we can present the
	 * user with a reasonable error message (unlike the lexer).
	 */
	if (statbuf.st_size != 0 && fgetc(fp) == EOF) {
	    log_error(USE_ERRNO|NO_EXIT, "can't read %s", sudoers);
	    fclose(fp);
	    fp = NULL;
	}
    }

    if (fp != NULL) {
	rewind(fp);
	(void) fcntl(fileno(fp), F_SETFD, 1);
    }

    restore_perms();		/* change back to root */
    return fp;
}

#ifdef HAVE_LOGIN_CAP_H
static void
set_loginclass(struct passwd *pw)
{
    int errflags;

    /*
     * Don't make it a fatal error if the user didn't specify the login
     * class themselves.  We do this because if login.conf gets
     * corrupted we want the admin to be able to use sudo to fix it.
     */
    if (login_class)
	errflags = NO_MAIL|MSG_ONLY;
    else
	errflags = NO_MAIL|MSG_ONLY|NO_EXIT;

    if (login_class && strcmp(login_class, "-") != 0) {
	if (user_uid != 0 &&
	    strcmp(runas_user ? runas_user : def_runas_default, "root") != 0)
	    errorx(1, "only root can use -c %s", login_class);
    } else {
	login_class = pw->pw_class;
	if (!login_class || !*login_class)
	    login_class =
		(pw->pw_uid == 0) ? LOGIN_DEFROOTCLASS : LOGIN_DEFCLASS;
    }

    lc = login_getclass(login_class);
    if (!lc || !lc->lc_class || strcmp(lc->lc_class, login_class) != 0) {
	log_error(errflags, "unknown login class: %s", login_class);
	if (!lc)
	    lc = login_getclass(NULL);	/* needed for login_getstyle() later */
    }
}
#else
static void
set_loginclass(struct passwd *pw)
{
}
#endif /* HAVE_LOGIN_CAP_H */

/*
 * Look up the fully qualified domain name and set user_host and user_shost.
 */
void
set_fqdn(void)
{
#ifdef HAVE_GETADDRINFO
    struct addrinfo *res0, hint;
#else
    struct hostent *hp;
#endif
    char *p;

#ifdef HAVE_GETADDRINFO
    zero_bytes(&hint, sizeof(hint));
    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_CANONNAME;
    if (getaddrinfo(user_host, NULL, &hint, &res0) != 0) {
#else
    if (!(hp = gethostbyname(user_host))) {
#endif
	log_error(MSG_ONLY|NO_EXIT,
	    "unable to resolve host %s", user_host);
    } else {
	if (user_shost != user_host)
	    efree(user_shost);
	efree(user_host);
#ifdef HAVE_GETADDRINFO
	user_host = estrdup(res0->ai_canonname);
	freeaddrinfo(res0);
#else
	user_host = estrdup(hp->h_name);
#endif
    }
    if ((p = strchr(user_host, '.')) != NULL)
	user_shost = estrndup(user_host, (size_t)(p - user_host));
    else
	user_shost = user_host;
}

/*
 * Get passwd entry for the user we are going to run commands as
 * and store it in runas_pw.  By default, commands run as "root".
 */
static void
set_runaspw(char *user)
{
    if (runas_pw != NULL)
	pw_delref(runas_pw);
    if (*user == '#') {
	if ((runas_pw = sudo_getpwuid(atoi(user + 1))) == NULL)
	    runas_pw = sudo_fakepwnam(user, runas_gr ? runas_gr->gr_gid : 0);
    } else {
	if ((runas_pw = sudo_getpwnam(user)) == NULL) {
	    audit_failure(NewArgv, "unknown user: %s", user);
	    log_error(NO_MAIL|MSG_ONLY, "unknown user: %s", user);
	}
    }
}

/*
 * Get group entry for the group we are going to run commands as
 * and store it in runas_gr.
 */
static void
set_runasgr(char *group)
{
    if (runas_gr != NULL)
	gr_delref(runas_gr);
    if (*group == '#') {
	if ((runas_gr = sudo_getgrgid(atoi(group + 1))) == NULL)
	    runas_gr = sudo_fakegrnam(group);
    } else {
	if ((runas_gr = sudo_getgrnam(group)) == NULL)
	    log_error(NO_MAIL|MSG_ONLY, "unknown group: %s", group);
    }
}

/*
 * Cleanup hook for error()/errorx()
 */
void
plugin_cleanup(int gotsignal)
{
    struct sudo_nss *nss;

    if (!gotsignal) {
	if (snl != NULL) {
	    tq_foreach_fwd(snl, nss)
		nss->close(nss);
	}
	if (def_group_plugin)
	    group_plugin_unload();
	sudo_endpwent();
	sudo_endgrent();
    }
}

static int
sudoers_policy_version(int verbose)
{
    if (sigsetjmp(error_jmp, 1)) {
	/* error recovery via error(), errorx() or log_error() */
	return -1;
    }

    sudo_printf(SUDO_CONV_INFO_MSG, "Sudoers policy plugin version %s\n",
	PACKAGE_VERSION);

    if (verbose) {
	sudo_printf(SUDO_CONV_INFO_MSG, "\nSudoers path: %s\n", sudoers_file);
#ifdef HAVE_LDAP
# ifdef _PATH_NSSWITCH_CONF
	sudo_printf(SUDO_CONV_INFO_MSG, "nsswitch path: %s\n", _PATH_NSSWITCH_CONF);
# endif
	sudo_printf(SUDO_CONV_INFO_MSG, "ldap.conf path: %s\n", _PATH_LDAP_CONF);
	sudo_printf(SUDO_CONV_INFO_MSG, "ldap.secret path: %s\n", _PATH_LDAP_SECRET);
#endif
	dump_auth_methods();
	dump_defaults();
	sudo_printf(SUDO_CONV_INFO_MSG, "\n");
	dump_interfaces(interfaces_string);
	sudo_printf(SUDO_CONV_INFO_MSG, "\n");
    }
    return TRUE;
}

static int
deserialize_info(char * const settings[], char * const user_info[])
{
    char * const *cur;
    const char *p;
    int flags = 0;

#define MATCHES(s, v) (strncmp(s, v, sizeof(v) - 1) == 0)

    /* Parse command line settings. */
    user_closefrom = -1;
    for (cur = settings; *cur != NULL; cur++) {
	if (MATCHES(*cur, "closefrom=")) {
	    user_closefrom = atoi(*cur + sizeof("closefrom=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "debug_level=")) {
	    debug_level = atoi(*cur + sizeof("debug_level=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "runas_user=")) {
	    runas_user = *cur + sizeof("runas_user=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "runas_group=")) {
	    runas_group = *cur + sizeof("runas_group=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "prompt=")) {
	    user_prompt = *cur + sizeof("prompt=") - 1;
	    def_passprompt_override = TRUE;
	    continue;
	}
	if (MATCHES(*cur, "set_home=")) {
	    if (atobool(*cur + sizeof("set_home=") - 1) == TRUE)
		SET(flags, MODE_RESET_HOME);
	    continue;
	}
	if (MATCHES(*cur, "preserve_environment=")) {
	    if (atobool(*cur + sizeof("preserve_environment=") - 1) == TRUE)
		SET(flags, MODE_PRESERVE_ENV);
	    continue;
	}
	if (MATCHES(*cur, "login_shell=")) {
	    if (atobool(*cur + sizeof("login_shell=") - 1) == TRUE) {
		SET(flags, MODE_LOGIN_SHELL);
		def_env_reset = TRUE;
	    }
	    continue;
	}
	if (MATCHES(*cur, "implied_shell=")) {
	    if (atobool(*cur + sizeof("implied_shell=") - 1) == TRUE)
		SET(flags, MODE_IMPLIED_SHELL);
	    continue;
	}
	if (MATCHES(*cur, "preserve_groups=")) {
	    if (atobool(*cur + sizeof("preserve_groups=") - 1) == TRUE)
		SET(flags, MODE_PRESERVE_GROUPS);
	    continue;
	}
	if (MATCHES(*cur, "ignore_ticket=")) {
	    if (atobool(*cur + sizeof("ignore_ticket=") - 1) == TRUE)
		SET(flags, MODE_IGNORE_TICKET);
	    continue;
	}
	if (MATCHES(*cur, "sudoedit=")) {
	    if (atobool(*cur + sizeof("sudoedit=") - 1) == TRUE)
		SET(flags, MODE_EDIT);
	    continue;
	}
	if (MATCHES(*cur, "login_class=")) {
	    login_class = *cur + sizeof("login_class=") - 1;
	    def_use_loginclass = TRUE;
	    continue;
	}
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
#if !defined(HAVE_GETPROGNAME) && !defined(HAVE___PROGNAME)
	if (MATCHES(*cur, "progname=")) {
	    setprogname(*cur + sizeof("progname=") - 1);
	    continue;
	}
#endif
	if (MATCHES(*cur, "network_addrs=")) {
	    interfaces_string = *cur + sizeof("network_addrs=") - 1;
	    set_interfaces(interfaces_string);
	    continue;
	}
	if (MATCHES(*cur, "sudoers_file=")) {
	    sudoers_file = *cur + sizeof("sudoers_file=") - 1;
	    continue;
	}
	if (MATCHES(*cur, "sudoers_uid=")) {
	    sudoers_uid = (uid_t) atoi(*cur + sizeof("sudoers_uid=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "sudoers_gid=")) {
	    sudoers_gid = (gid_t) atoi(*cur + sizeof("sudoers_gid=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "sudoers_mode=")) {
	    sudoers_mode = (mode_t) strtol(*cur + sizeof("sudoers_mode=") - 1,
		NULL, 8);
	    continue;
	}
    }

    for (cur = user_info; *cur != NULL; cur++) {
	if (MATCHES(*cur, "user=")) {
	    user_name = estrdup(*cur + sizeof("user=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "uid=")) {
	    user_uid = (uid_t) atoi(*cur + sizeof("uid=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "gid=")) {
	    user_gid = (gid_t) atoi(*cur + sizeof("gid=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "groups=")) {
	    /* Count number of groups */
	    const char *val = *cur + sizeof("groups=") - 1;
	    const char *cp;
	    if (val[0] != '\0') {
		user_ngroups = 1;
		for (cp = val; *cp != '\0'; cp++) {
		    if (*cp == ',')
			user_ngroups++;
		}

		user_groups = emalloc2(user_ngroups, sizeof(GETGROUPS_T));
		user_ngroups = 0;
		cp = val;
		for (;;) {
		    /* XXX - strtol would be better here */
		    user_groups[user_ngroups++] = atoi(cp);
		    cp = strchr(cp, ',');
		    if (cp == NULL)
			break;
		    cp++; /* skip over comma */
		}
	    }
	    continue;
	}
	if (MATCHES(*cur, "cwd=")) {
	    user_cwd = estrdup(*cur + sizeof("cwd=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "tty=")) {
	    user_tty = user_ttypath = estrdup(*cur + sizeof("tty=") - 1);
	    if (strncmp(user_tty, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
		user_tty += sizeof(_PATH_DEV) - 1;
	    continue;
	}
	if (MATCHES(*cur, "host=")) {
	    user_host = user_shost = estrdup(*cur + sizeof("host=") - 1);
	    if ((p = strchr(user_host, '.')))
		user_shost = estrndup(user_host, (size_t)(p - user_host));
	    continue;
	}
	if (MATCHES(*cur, "lines=")) {
	    sudo_user.lines = atoi(*cur + sizeof("lines=") - 1);
	    continue;
	}
	if (MATCHES(*cur, "cols=")) {
	    sudo_user.cols = atoi(*cur + sizeof("cols=") - 1);
	    continue;
	}
    }
    if (user_cwd == NULL)
	user_cwd = "unknown";
    if (user_tty == NULL)
	user_tty = "unknown"; /* user_ttypath remains NULL */

#undef MATCHES
    return flags;
}

static char *
resolve_editor(char *editor, int nfiles, char **files, char ***argv_out)
{
    char *cp, **nargv, *editor_path = NULL;
    int ac, i, nargc, wasblank;

    editor = estrdup(editor); /* becomes part of argv_out */

    /*
     * Split editor into an argument vector; editor is reused (do not free).
     * The EDITOR and VISUAL environment variables may contain command
     * line args so look for those and alloc space for them too.
     */
    nargc = 1;
    for (wasblank = FALSE, cp = editor; *cp != '\0'; cp++) {
	if (isblank((unsigned char) *cp))
	    wasblank = TRUE;
	else if (wasblank) {
	    wasblank = FALSE;
	    nargc++;
	}
    }
    /* If we can't find the editor in the user's PATH, give up. */
    cp = strtok(editor, " \t");
    if (cp == NULL ||
	find_path(cp, &editor_path, NULL, getenv("PATH"), 0) != FOUND) {
	efree(editor);
	return NULL;
    }
    nargv = (char **) emalloc2(nargc + 1 + nfiles + 1, sizeof(char *));
    for (ac = 0; cp != NULL && ac < nargc; ac++) {
	nargv[ac] = cp;
	cp = strtok(NULL, " \t");
    }
    nargv[ac++] = "--";
    for (i = 0; i < nfiles; )
	nargv[ac++] = files[i++];
    nargv[ac] = NULL;

    *argv_out = nargv;
    return editor_path;
}

/*
 * Determine which editor to use.  We don't need to worry about restricting
 * this to a "safe" editor since it runs with the uid of the invoking user,
 * not the runas (privileged) user.
 */
static char *
find_editor(int nfiles, char **files, char ***argv_out)
{
    char *cp, *editor, *editor_path = NULL, **ev, *ev0[4];

    /*
     * If any of SUDO_EDITOR, VISUAL or EDITOR are set, choose the first one.
     */
    ev0[0] = "SUDO_EDITOR";
    ev0[1] = "VISUAL";
    ev0[2] = "EDITOR";
    ev0[3] = NULL;
    for (ev = ev0; *ev != NULL; ev++) {
	if ((editor = getenv(*ev)) != NULL && *editor != '\0') {
	    editor_path = resolve_editor(editor, nfiles, files, argv_out);
	    if (editor_path != NULL)
		break;
	}
    }
    if (editor_path == NULL) {
	/* def_editor could be a path, split it up */
	editor = estrdup(def_editor);
	cp = strtok(editor, ":");
	while (cp != NULL && editor_path == NULL) {
	    editor_path = resolve_editor(cp, nfiles, files, argv_out);
	    cp = strtok(NULL, ":");
	}
	if (editor_path)
	    efree(editor);
    }
    if (!editor_path) {
	audit_failure(NewArgv, "%s: command not found", editor);
	warningx("%s: command not found", editor);
    }
    return editor_path;
}

#ifdef USE_ADMIN_FLAG
static void
create_admin_success_flag(void)
{
    struct stat statbuf;
    char flagfile[PATH_MAX];
    int fd, n;

    /* Check whether the user is in the admin group. */
    if (!user_in_group(sudo_user.pw, "admin"))
	return;

    /* Build path to flag file. */
    n = snprintf(flagfile, sizeof(flagfile), "%s/.sudo_as_admin_successful",
	user_dir);
    if (n <= 0 || n >= sizeof(flagfile))
	return;

    /* Create admin flag file if it doesn't already exist. */
    set_perms(PERM_USER);
    if (stat(flagfile, &statbuf) != 0) {
	fd = open(flagfile, O_CREAT|O_WRONLY|O_EXCL, 0644);
	close(fd);
    }
    restore_perms();
}
#else /* !USE_ADMIN_FLAG */
static void
create_admin_success_flag(void)
{
    /* STUB */
}
#endif /* USE_ADMIN_FLAG */

struct policy_plugin sudoers_policy = {
    SUDO_POLICY_PLUGIN,
    SUDO_API_VERSION,
    sudoers_policy_open,
    sudoers_policy_close,
    sudoers_policy_version,
    sudoers_policy_check,
    sudoers_policy_list,
    sudoers_policy_validate,
    sudoers_policy_invalidate,
    sudoers_policy_init_session
};
