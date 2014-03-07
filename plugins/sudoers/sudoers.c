/*
 * Copyright (c) 1993-1996, 1998-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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

#define _SUDO_MAIN

#ifdef __TANDEM
# include <floss.h>
#endif

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
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
#include <netdb.h>
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
# ifndef LOGIN_DEFROOTCLASS
#  define LOGIN_DEFROOTCLASS	"daemon"
# endif
# ifndef LOGIN_SETENV
#  define LOGIN_SETENV	0
# endif
#endif
#ifdef HAVE_SELINUX
# include <selinux/selinux.h>
#endif
#include <ctype.h>
#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif

#include "sudoers.h"
#include "auth/sudo_auth.h"
#include "secure_path.h"

/*
 * Prototypes
 */
static char *find_editor(int nfiles, char **files, char ***argv_out);
static int cb_runas_default(const char *);
static int cb_sudoers_locale(const char *);
static int set_cmnd(void);
static void create_admin_success_flag(void);
static void init_vars(char * const *);
static void set_fqdn(void);
static void set_loginclass(struct passwd *);
static void set_runasgr(const char *);
static void set_runaspw(const char *);
static bool tty_present(void);

/*
 * Globals
 */
struct sudo_user sudo_user;
struct passwd *list_pw;
int long_list;
uid_t timestamp_uid;
#ifdef HAVE_BSD_AUTH_H
char *login_style;
#endif /* HAVE_BSD_AUTH_H */
int sudo_mode;

static char *prev_user;
static char *runas_user;
static char *runas_group;
static struct sudo_nss_list *snl;

/* XXX - must be extern for audit bits of sudo_auth.c */
int NewArgc;
char **NewArgv;

int
sudoers_policy_init(void *info, char * const envp[])
{
    volatile int sources = 0;
    struct sudo_nss *nss, *nss_next;
    debug_decl(sudoers_policy_init, SUDO_DEBUG_PLUGIN)

    bindtextdomain("sudoers", LOCALEDIR);

    sudo_setpwent();
    sudo_setgrent();

    /* Register fatal/fatalx callback. */
    fatal_callback_register(sudoers_cleanup);

    /* Initialize environment functions (including replacements). */
    env_init(envp);

    /* Setup defaults data structures. */
    init_defaults();

    /* Parse info from front-end. */
    sudo_mode = sudoers_policy_deserialize_info(info, &runas_user, &runas_group);

    init_vars(envp);		/* XXX - move this later? */

    /* Parse nsswitch.conf for sudoers order. */
    snl = sudo_read_nss();

    /* LDAP or NSS may modify the euid so we need to be root for the open. */
    set_perms(PERM_ROOT);

    /* Open and parse sudoers, set global defaults */
    TAILQ_FOREACH_SAFE(nss, snl, entries, nss_next) {
        if (nss->open(nss) == 0 && nss->parse(nss) == 0) {
            sources++;
            if (nss->setdefs(nss) != 0)
                log_warning(NO_STDERR, N_("problem with defaults entries"));
        } else {
	    TAILQ_REMOVE(snl, nss, entries);
        }
    }
    if (sources == 0) {
	warningx(U_("no valid sudoers sources found, quitting"));
	debug_return_bool(-1);
    }

    /* XXX - collect post-sudoers parse settings into a function */

    /*
     * Initialize external group plugin, if any.
     */
    if (def_group_plugin) {
	if (group_plugin_load(def_group_plugin) != true)
	    def_group_plugin = NULL;
    }

    /*
     * Set runas passwd/group entries based on command line or sudoers.
     * Note that if runas_group was specified without runas_user we
     * defer setting runas_pw so the match routines know to ignore it.
     */
    /* XXX - qpm4u does more here as it may have already set runas_pw */
    if (runas_group != NULL) {
	set_runasgr(runas_group);
	if (runas_user != NULL)
	    set_runaspw(runas_user);
    } else
	set_runaspw(runas_user ? runas_user : def_runas_default);

    if (!update_defaults(SETDEF_RUNAS))
	log_warning(NO_STDERR, N_("problem with defaults entries"));

    if (def_fqdn)
	set_fqdn();	/* deferred until after sudoers is parsed */

    /* Set login class if applicable. */
    set_loginclass(runas_pw ? runas_pw : sudo_user.pw);

    restore_perms();

    debug_return_bool(true);
}

int
sudoers_policy_main(int argc, char * const argv[], int pwflag, char *env_add[],
    void *closure)
{
    char **edit_argv = NULL;
    char *iolog_path = NULL;
    mode_t cmnd_umask = 0777;
    struct sudo_nss *nss;
    int cmnd_status = -1, oldlocale, validated;
    volatile int rval = true;
    debug_decl(sudoers_policy_main, SUDO_DEBUG_PLUGIN)

    /* XXX - would like to move this to policy.c but need the cleanup. */
    if (fatal_setjmp() != 0) {
	/* error recovery via fatal(), fatalx() or log_fatal() */
	rval = -1;
	goto done;
    }

    /* Is root even allowed to run sudo? */
    if (user_uid == 0 && !def_root_sudo) {
        warningx(U_("sudoers specifies that root is not allowed to sudo"));
        goto bad;
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
	/* Must leave an extra slot before NewArgv for bash's --login */
	NewArgc = argc;
	NewArgv = emalloc2(NewArgc + 2, sizeof(char *));
	memcpy(++NewArgv, argv, argc * sizeof(char *));
	NewArgv[NewArgc] = NULL;
	if (ISSET(sudo_mode, MODE_LOGIN_SHELL) && runas_pw != NULL)
	    NewArgv[0] = estrdup(runas_pw->pw_shell);
    }

    /* If given the -P option, set the "preserve_groups" flag. */
    if (ISSET(sudo_mode, MODE_PRESERVE_GROUPS))
	def_preserve_groups = true;

    /* Find command in path and apply per-command Defaults. */
    cmnd_status = set_cmnd();

    /* Check for -C overriding def_closefrom. */
    if (user_closefrom >= 0 && user_closefrom != def_closefrom) {
	if (!def_closefrom_override) {
	    warningx(U_("you are not permitted to use the -C option"));
	    goto bad;
	}
	def_closefrom = user_closefrom;
    }

    /*
     * Check sudoers sources, using the locale specified in sudoers.
     */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);
    validated = FLAG_NO_USER | FLAG_NO_HOST;
    TAILQ_FOREACH(nss, snl, entries) {
	validated = nss->lookup(nss, validated, pwflag);

	if (ISSET(validated, VALIDATE_OK)) {
	    /* Handle [SUCCESS=return] */
	    if (nss->ret_if_found)
		break;
	} else {
	    /* Handle [NOTFOUND=return] */
	    if (nss->ret_if_notfound)
		break;
	}
    }

    /* Restore user's locale. */
    sudoers_setlocale(oldlocale, NULL);

    if (safe_cmnd == NULL)
	safe_cmnd = estrdup(user_cmnd);

    /* If only a group was specified, set runas_pw based on invoking user. */
    if (runas_pw == NULL)
	set_runaspw(user_name);

    /*
     * Look up the timestamp dir owner if one is specified.
     */
    if (def_timestampowner) {
	struct passwd *pw = NULL;

	if (*def_timestampowner == '#') {
	    const char *errstr;
	    uid_t uid = atoid(def_timestampowner + 1, NULL, NULL, &errstr);
	    if (errstr == NULL)
		pw = sudo_getpwuid(uid);
	}
	if (pw == NULL)
	    pw = sudo_getpwnam(def_timestampowner);
	if (pw != NULL) {
	    timestamp_uid = pw->pw_uid;
	    sudo_pw_delref(pw);
	} else {
	    log_warning(0, N_("timestamp owner (%s): No such user"),
		def_timestampowner);
	    timestamp_uid = ROOT_UID;
	}
    }

    /* If no command line args and "shell_noargs" is not set, error out. */
    if (ISSET(sudo_mode, MODE_IMPLIED_SHELL) && !def_shell_noargs) {
	rval = -2; /* usage error */
	goto done;
    }

    /* Bail if a tty is required and we don't have one.  */
    if (def_requiretty && !tty_present()) {
	audit_failure(NewArgv, N_("no tty"));
	warningx(U_("sorry, you must have a tty to run sudo"));
	goto bad;
    }

    /*
     * We don't reset the environment for sudoedit or if the user
     * specified the -E command line flag and they have setenv privs.
     */
    if (ISSET(sudo_mode, MODE_EDIT) ||
	(ISSET(sudo_mode, MODE_PRESERVE_ENV) && def_setenv))
	def_env_reset = false;

    /* Build a new environment that avoids any nasty bits. */
    rebuild_env();

    /* Require a password if sudoers says so.  */
    rval = check_user(validated, sudo_mode);
    if (rval != true) {
	if (!ISSET(validated, VALIDATE_OK))
	    log_denial(validated, false);
	goto done;
    }

    /* If run as root with SUDO_USER set, set sudo_user.pw to that user. */
    /* XXX - causes confusion when root is not listed in sudoers */
    if (sudo_mode & (MODE_RUN | MODE_EDIT) && prev_user != NULL) {
	if (user_uid == 0 && strcmp(prev_user, "root") != 0) {
	    struct passwd *pw;

	    if ((pw = sudo_getpwnam(prev_user)) != NULL) {
		    if (sudo_user.pw != NULL)
			sudo_pw_delref(sudo_user.pw);
		    sudo_user.pw = pw;
	    }
	}
    }

    /* If the user was not allowed to run the command we are done. */
    if (!ISSET(validated, VALIDATE_OK)) {
	log_failure(validated, cmnd_status);
	goto bad;
    }

    /* Create Ubuntu-style dot file to indicate sudo was successful. */
    create_admin_success_flag();

    /* Finally tell the user if the command did not exist. */
    if (cmnd_status == NOT_FOUND_DOT) {
	audit_failure(NewArgv, N_("command in current directory"));
	warningx(U_("ignoring `%s' found in '.'\nUse `sudo ./%s' if this is the `%s' you wish to run."), user_cmnd, user_cmnd, user_cmnd);
	goto bad;
    } else if (cmnd_status == NOT_FOUND) {
	if (ISSET(sudo_mode, MODE_CHECK)) {
	    audit_failure(NewArgv, N_("%s: command not found"), NewArgv[0]);
	    warningx(U_("%s: command not found"), NewArgv[0]);
	} else {
	    audit_failure(NewArgv, N_("%s: command not found"), user_cmnd);
	    warningx(U_("%s: command not found"), user_cmnd);
	}
	goto bad;
    }

    /* If user specified env vars make sure sudoers allows it. */
    if (ISSET(sudo_mode, MODE_RUN) && !def_setenv) {
	if (ISSET(sudo_mode, MODE_PRESERVE_ENV)) {
	    warningx(U_("sorry, you are not allowed to preserve the environment"));
	    goto bad;
	} else
	    validate_env_vars(sudo_user.env_vars);
    }

    if (ISSET(sudo_mode, (MODE_RUN | MODE_EDIT))) {
	if ((def_log_input || def_log_output) && def_iolog_file && def_iolog_dir) {
	    const char prefix[] = "iolog_path=";
	    iolog_path = expand_iolog_path(prefix, def_iolog_dir,
		def_iolog_file, &sudo_user.iolog_file);
	    sudo_user.iolog_file++;
	}
    }

    log_allowed(validated);
    if (ISSET(sudo_mode, MODE_CHECK))
	rval = display_cmnd(snl, list_pw ? list_pw : sudo_user.pw);
    else if (ISSET(sudo_mode, MODE_LIST))
	display_privs(snl, list_pw ? list_pw : sudo_user.pw); /* XXX - return val */

    /* Cleanup sudoers sources */
    TAILQ_FOREACH(nss, snl, entries) {
	nss->close(nss);
    }
    if (def_group_plugin)
	group_plugin_unload();

    if (ISSET(sudo_mode, (MODE_VALIDATE|MODE_CHECK|MODE_LIST))) {
	/* rval already set appropriately */
	goto done;
    }

    /*
     * Set umask based on sudoers.
     * If user's umask is more restrictive, OR in those bits too
     * unless umask_override is set.
     */
    if (def_umask != 0777) {
	cmnd_umask = def_umask;
	if (!def_umask_override)
	    cmnd_umask |= user_umask;
    }

    if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
	char *p;

	/* Convert /bin/sh -> -sh so shell knows it is a login shell */
	if ((p = strrchr(NewArgv[0], '/')) == NULL)
	    p = NewArgv[0];
	*p = '-';
	NewArgv[0] = p;

	/*
	 * Newer versions of bash require the --login option to be used
	 * in conjunction with the -c option even if the shell name starts
	 * with a '-'.  Unfortunately, bash 1.x uses -login, not --login
	 * so this will cause an error for that.
	 */
	if (NewArgc > 1 && strcmp(NewArgv[0], "-bash") == 0 &&
	    strcmp(NewArgv[1], "-c") == 0) {
	    /* Use the extra slot before NewArgv so we can store --login. */
	    NewArgv--;
	    NewArgc++;
	    NewArgv[0] = NewArgv[1];
	    NewArgv[1] = "--login";
	}

#if defined(_AIX) || (defined(__linux__) && !defined(HAVE_PAM))
	/* Insert system-wide environment variables. */
	read_env_file(_PATH_ENVIRONMENT, true);
#endif
#ifdef HAVE_LOGIN_CAP_H
	/* Set environment based on login class. */
	if (login_class) {
	    login_cap_t *lc = login_getclass(login_class);
	    if (lc != NULL) {
		setusercontext(lc, runas_pw, runas_pw->pw_uid, LOGIN_SETPATH|LOGIN_SETENV);
		login_close(lc);
	    }
	}
#endif /* HAVE_LOGIN_CAP_H */
    }

    /* Insert system-wide environment variables. */
    if (def_env_file)
	read_env_file(def_env_file, false);

    /* Insert user-specified environment variables. */
    insert_env_vars(sudo_user.env_vars);

    if (ISSET(sudo_mode, MODE_EDIT)) {
	efree(safe_cmnd);
	safe_cmnd = find_editor(NewArgc - 1, NewArgv + 1, &edit_argv);
	if (safe_cmnd == NULL)
	    goto bad;
    }

    /* Must audit before uid change. */
    audit_success(NewArgv);

    /* Setup execution environment to pass back to front-end. */
    rval = sudoers_policy_exec_setup(edit_argv ? edit_argv : NewArgv,
	env_get(), cmnd_umask, iolog_path, closure);

    /* Zero out stashed copy of environment, it is owned by the front-end. */
    env_init(NULL);

    goto done;

bad:
    rval = false;

done:
    fatal_disable_setjmp();
    rewind_perms();

    /* Close the password and group files and free up memory. */
    sudo_endpwent();
    sudo_endgrent();

    debug_return_bool(rval);
}

/*
 * Initialize timezone and fill in ``sudo_user'' struct.
 */
static void
init_vars(char * const envp[])
{
    char * const * ep;
    bool unknown_user = false;
    debug_decl(init_vars, SUDO_DEBUG_PLUGIN)

    sudoers_initlocale(setlocale(LC_ALL, NULL), def_sudoers_locale);

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
     * Get a local copy of the user's struct passwd if we don't already
     * have one.
     */
    if (sudo_user.pw == NULL) {
	if ((sudo_user.pw = sudo_getpwnam(user_name)) == NULL) {
	    /*
	     * It is not unusual for users to place "sudo -k" in a .logout
	     * file which can cause sudo to be run during reboot after the
	     * YP/NIS/NIS+/LDAP/etc daemon has died.
	     */
	    if (sudo_mode == MODE_KILL || sudo_mode == MODE_INVALIDATE)
		fatalx(U_("unknown uid: %u"), (unsigned int) user_uid);

	    /* Need to make a fake struct passwd for the call to log_fatal(). */
	    sudo_user.pw = sudo_mkpwent(user_name, user_uid, user_gid, NULL, NULL);
	    unknown_user = true;
	}
    }

    /*
     * Get group list and store initialize permissions.
     */
    if (user_group_list == NULL)
	user_group_list = sudo_get_grlist(sudo_user.pw);
    set_perms(PERM_INITIAL);

    /* Set runas callback. */
    sudo_defs_table[I_RUNAS_DEFAULT].callback = cb_runas_default;

    /* Set locale callback. */
    sudo_defs_table[I_SUDOERS_LOCALE].callback = cb_sudoers_locale;

    /* Set maxseq callback. */
    sudo_defs_table[I_MAXSEQ].callback = io_set_max_sessid;

    /* It is now safe to use log_fatal() and set_perms() */
    if (unknown_user)
	log_fatal(0, N_("unknown uid: %u"), (unsigned int) user_uid);
    debug_return;
}

/*
 * Fill in user_cmnd, user_args, user_base and user_stat variables
 * and apply any command-specific defaults entries.
 */
static int
set_cmnd(void)
{
    int rval;
    char *path = user_path;
    debug_decl(set_cmnd, SUDO_DEBUG_PLUGIN)

    /* Resolve the path and return. */
    rval = FOUND;
    user_stat = ecalloc(1, sizeof(struct stat));

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
	    char *to, *from, **av;
	    size_t size, n;

	    /* Alloc and build up user_args. */
	    for (size = 0, av = NewArgv + 1; *av; av++)
		size += strlen(*av) + 1;
	    user_args = emalloc(size);
	    if (ISSET(sudo_mode, MODE_SHELL|MODE_LOGIN_SHELL)) {
		/*
		 * When running a command via a shell, the sudo front-end
		 * escapes potential meta chars.  We unescape non-spaces
		 * for sudoers matching and logging purposes.
		 */
		for (to = user_args, av = NewArgv + 1; (from = *av); av++) {
		    while (*from) {
			if (from[0] == '\\' && !isspace((unsigned char)from[1]))
			    from++;
			*to++ = *from++;
		    }
		    *to++ = ' ';
		}
		*--to = '\0';
	    } else {
		for (to = user_args, av = NewArgv + 1; *av; av++) {
		    n = strlcpy(to, *av, size - (to - user_args));
		    if (n >= size - (to - user_args))
			fatalx(U_("internal error, %s overflow"), "set_cmnd()");
		    to += n;
		    *to++ = ' ';
		}
		*--to = '\0';
	    }
	}
    }
    if (strlen(user_cmnd) >= PATH_MAX) {
	errno = ENAMETOOLONG;
	fatal("%s", user_cmnd);
    }

    if ((user_base = strrchr(user_cmnd, '/')) != NULL)
	user_base++;
    else
	user_base = user_cmnd;

    if (!update_defaults(SETDEF_CMND))
	log_warning(NO_STDERR, N_("problem with defaults entries"));

    debug_return_int(rval);
}

/*
 * Open sudoers and sanity check mode/owner/type.
 * Returns a handle to the sudoers file or NULL on error.
 */
FILE *
open_sudoers(const char *sudoers, bool doedit, bool *keepopen)
{
    struct stat sb;
    FILE *fp = NULL;
    debug_decl(open_sudoers, SUDO_DEBUG_PLUGIN)

    set_perms(PERM_SUDOERS);

    switch (sudo_secure_file(sudoers, sudoers_uid, sudoers_gid, &sb)) {
	case SUDO_PATH_SECURE:
	    /*
	     * If we are expecting sudoers to be group readable by
	     * SUDOERS_GID but it is not, we must open the file as root,
	     * not uid 1.
	     */
	    if (sudoers_uid == ROOT_UID && ISSET(sudoers_mode, S_IRGRP)) {
		if (!ISSET(sb.st_mode, S_IRGRP) || sb.st_gid != SUDOERS_GID) {
		    restore_perms();
		    set_perms(PERM_ROOT);
		}
	    }
	    /*
	     * Open sudoers and make sure we can read it so we can present
	     * the user with a reasonable error message (unlike the lexer).
	     */
	    if ((fp = fopen(sudoers, "r")) == NULL) {
		log_warning(USE_ERRNO, N_("unable to open %s"), sudoers);
	    } else {
		if (sb.st_size != 0 && fgetc(fp) == EOF) {
		    log_warning(USE_ERRNO, N_("unable to read %s"),
			sudoers);
		    fclose(fp);
		    fp = NULL;
		} else {
		    /* Rewind fp and set close on exec flag. */
		    rewind(fp);
		    (void) fcntl(fileno(fp), F_SETFD, 1);
		}
	    }
	    break;
	case SUDO_PATH_MISSING:
	    log_warning(USE_ERRNO, N_("unable to stat %s"), sudoers);
	    break;
	case SUDO_PATH_BAD_TYPE:
	    log_warning(0, N_("%s is not a regular file"), sudoers);
	    break;
	case SUDO_PATH_WRONG_OWNER:
	    log_warning(0, N_("%s is owned by uid %u, should be %u"),
		sudoers, (unsigned int) sb.st_uid, (unsigned int) sudoers_uid);
	    break;
	case SUDO_PATH_WORLD_WRITABLE:
	    log_warning(0, N_("%s is world writable"), sudoers);
	    break;
	case SUDO_PATH_GROUP_WRITABLE:
	    log_warning(0, N_("%s is owned by gid %u, should be %u"),
		sudoers, (unsigned int) sb.st_gid, (unsigned int) sudoers_gid);
	    break;
	default:
	    /* NOTREACHED */
	    break;
    }

    restore_perms();		/* change back to root */

    debug_return_ptr(fp);
}

#ifdef HAVE_LOGIN_CAP_H
static void
set_loginclass(struct passwd *pw)
{
    const int errflags = NO_MAIL|MSG_ONLY;
    login_cap_t *lc;
    debug_decl(set_loginclass, SUDO_DEBUG_PLUGIN)

    if (!def_use_loginclass)
	debug_return;

    if (login_class && strcmp(login_class, "-") != 0) {
	if (user_uid != 0 && pw->pw_uid != 0)
	    fatalx(U_("only root can use `-c %s'"), login_class);
    } else {
	login_class = pw->pw_class;
	if (!login_class || !*login_class)
	    login_class =
		(pw->pw_uid == 0) ? LOGIN_DEFROOTCLASS : LOGIN_DEFCLASS;
    }

    /* Make sure specified login class is valid. */
    lc = login_getclass(login_class);
    if (!lc || !lc->lc_class || strcmp(lc->lc_class, login_class) != 0) {
	/*
	 * Don't make it a fatal error if the user didn't specify the login
	 * class themselves.  We do this because if login.conf gets
	 * corrupted we want the admin to be able to use sudo to fix it.
	 */
	if (login_class)
	    log_fatal(errflags, N_("unknown login class: %s"), login_class);
	else
	    log_warning(errflags, N_("unknown login class: %s"), login_class);
	def_use_loginclass = false;
    }
    login_close(lc);
    debug_return;
}
#else
static void
set_loginclass(struct passwd *pw)
{
}
#endif /* HAVE_LOGIN_CAP_H */

#ifndef AI_FQDN
# define AI_FQDN AI_CANONNAME
#endif

/*
 * Look up the fully qualified domain name and set user_host and user_shost.
 * Use AI_FQDN if available since "canonical" is not always the same as fqdn.
 */
static void
set_fqdn(void)
{
    struct addrinfo *res0, hint;
    char *p;
    debug_decl(set_fqdn, SUDO_DEBUG_PLUGIN)

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_FQDN;
    if (getaddrinfo(user_host, NULL, &hint, &res0) != 0) {
	log_warning(MSG_ONLY, N_("unable to resolve host %s"), user_host);
    } else {
	if (user_shost != user_host)
	    efree(user_shost);
	efree(user_host);
	user_host = estrdup(res0->ai_canonname);
	freeaddrinfo(res0);
	if ((p = strchr(user_host, '.')) != NULL)
	    user_shost = estrndup(user_host, (size_t)(p - user_host));
	else
	    user_shost = user_host;
    }
    debug_return;
}

/*
 * Get passwd entry for the user we are going to run commands as
 * and store it in runas_pw.  By default, commands run as "root".
 */
static void
set_runaspw(const char *user)
{
    struct passwd *pw = NULL;
    debug_decl(set_runaspw, SUDO_DEBUG_PLUGIN)

    if (*user == '#') {
	const char *errstr;
	uid_t uid = atoid(user + 1, NULL, NULL, &errstr);
	if (errstr == NULL) {
	    if ((pw = sudo_getpwuid(uid)) == NULL)
		pw = sudo_fakepwnam(user, runas_gr ? runas_gr->gr_gid : 0);
	}
    }
    if (pw == NULL) {
	if ((pw = sudo_getpwnam(user)) == NULL)
	    log_fatal(NO_MAIL|MSG_ONLY, N_("unknown user: %s"), user);
    }
    if (runas_pw != NULL)
	sudo_pw_delref(runas_pw);
    runas_pw = pw;
    debug_return;
}

/*
 * Get group entry for the group we are going to run commands as
 * and store it in runas_gr.
 */
static void
set_runasgr(const char *group)
{
    struct group *gr = NULL;
    debug_decl(set_runasgr, SUDO_DEBUG_PLUGIN)

    if (*group == '#') {
	const char *errstr;
	gid_t gid = atoid(group + 1, NULL, NULL, &errstr);
	if (errstr == NULL) {
	    if ((gr = sudo_getgrgid(gid)) == NULL)
		gr = sudo_fakegrnam(group);
	}
    }
    if (gr == NULL) {
	if ((gr = sudo_getgrnam(group)) == NULL)
	    log_fatal(NO_MAIL|MSG_ONLY, N_("unknown group: %s"), group);
    }
    if (runas_gr != NULL)
	sudo_gr_delref(runas_gr);
    runas_gr = gr;
    debug_return;
}

/*
 * Callback for runas_default sudoers setting.
 */
static int
cb_runas_default(const char *user)
{
    /* Only reset runaspw if user didn't specify one. */
    if (!runas_user && !runas_group)
	set_runaspw(user);
    return true;
}

/*
 * Callback for sudoers_locale sudoers setting.
 */
static int
cb_sudoers_locale(const char *locale)
{
    sudoers_initlocale(NULL, locale);
    return true;
}

/*
 * Cleanup hook for fatal()/fatalx()
 */
void
sudoers_cleanup(void)
{
    struct sudo_nss *nss;
    debug_decl(sudoers_cleanup, SUDO_DEBUG_PLUGIN)

    if (snl != NULL) {
	TAILQ_FOREACH(nss, snl, entries) {
	    nss->close(nss);
	}
    }
    if (def_group_plugin)
	group_plugin_unload();
    sudo_endpwent();
    sudo_endgrent();

    debug_return;
}

static char *
resolve_editor(const char *ed, size_t edlen, int nfiles, char **files, char ***argv_out)
{
    char *cp, **nargv, *editor, *editor_path = NULL;
    int ac, i, nargc;
    bool wasblank;
    debug_decl(resolve_editor, SUDO_DEBUG_PLUGIN)

    /* Note: editor becomes part of argv_out and is not freed. */
    editor = emalloc(edlen + 1);
    memcpy(editor, ed, edlen);
    editor[edlen] = '\0';

    /*
     * Split editor into an argument vector; editor is reused (do not free).
     * The EDITOR and VISUAL environment variables may contain command
     * line args so look for those and alloc space for them too.
     */
    nargc = 1;
    for (wasblank = false, cp = editor; *cp != '\0'; cp++) {
	if (isblank((unsigned char) *cp))
	    wasblank = true;
	else if (wasblank) {
	    wasblank = false;
	    nargc++;
	}
    }
    /* If we can't find the editor in the user's PATH, give up. */
    cp = strtok(editor, " \t");
    if (cp == NULL ||
	find_path(cp, &editor_path, NULL, getenv("PATH"), 0) != FOUND) {
	efree(editor);
	debug_return_str(NULL);
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
    debug_return_str(editor_path);
}

/*
 * Determine which editor to use.  We don't need to worry about restricting
 * this to a "safe" editor since it runs with the uid of the invoking user,
 * not the runas (privileged) user.
 */
static char *
find_editor(int nfiles, char **files, char ***argv_out)
{
    const char *cp, *ep, *editor;
    char *editor_path = NULL, **ev, *ev0[4];
    size_t len;
    debug_decl(find_editor, SUDO_DEBUG_PLUGIN)

    /*
     * If any of SUDO_EDITOR, VISUAL or EDITOR are set, choose the first one.
     */
    ev0[0] = "SUDO_EDITOR";
    ev0[1] = "VISUAL";
    ev0[2] = "EDITOR";
    ev0[3] = NULL;
    for (ev = ev0; editor_path == NULL && *ev != NULL; ev++) {
	if ((editor = getenv(*ev)) != NULL && *editor != '\0') {
	    editor_path = resolve_editor(editor, strlen(editor), nfiles,
		files, argv_out);
	}
    }
    if (editor_path == NULL) {
	/* def_editor could be a path, split it up, avoiding strtok() */
	cp = editor = def_editor;
	do {
	    if ((ep = strchr(cp, ':')) != NULL)
		len = ep - cp;
	    else
		len = strlen(cp);
	    editor_path = resolve_editor(cp, len, nfiles, files, argv_out);
	    cp = ep + 1;
	} while (ep != NULL && editor_path == NULL);
    }
    if (!editor_path) {
	audit_failure(NewArgv, N_("%s: command not found"), editor);
	warningx(U_("%s: command not found"), editor);
    }
    debug_return_str(editor_path);
}

#ifdef USE_ADMIN_FLAG
static void
create_admin_success_flag(void)
{
    struct stat statbuf;
    char flagfile[PATH_MAX];
    int fd, n;
    debug_decl(create_admin_success_flag, SUDO_DEBUG_PLUGIN)

    /* Check whether the user is in the admin group. */
    if (!user_in_group(sudo_user.pw, "admin"))
	debug_return;

    /* Build path to flag file. */
    n = snprintf(flagfile, sizeof(flagfile), "%s/.sudo_as_admin_successful",
	user_dir);
    if (n <= 0 || (size_t)n >= sizeof(flagfile))
	debug_return;

    /* Create admin flag file if it doesn't already exist. */
    set_perms(PERM_USER);
    if (stat(flagfile, &statbuf) != 0) {
	fd = open(flagfile, O_CREAT|O_WRONLY|O_EXCL, 0644);
	close(fd);
    }
    restore_perms();
    debug_return;
}
#else /* !USE_ADMIN_FLAG */
static void
create_admin_success_flag(void)
{
    /* STUB */
}
#endif /* USE_ADMIN_FLAG */

static bool
tty_present(void)
{
#if defined(HAVE_STRUCT_KINFO_PROC2_P_TDEV) || defined(HAVE_STRUCT_KINFO_PROC_P_TDEV) || defined(HAVE_STRUCT_KINFO_PROC_KI_TDEV) || defined(HAVE_STRUCT_KINFO_PROC_KP_EPROC_E_TDEV) || defined(HAVE_STRUCT_PSINFO_PR_TTYDEV) || defined(HAVE_PSTAT_GETPROC) || defined(__linux__)
    return user_ttypath != NULL;
#else
    int fd = open(_PATH_TTY, O_RDWR|O_NOCTTY);
    if (fd != -1)
	close(fd);
    return fd != -1;
#endif
}
