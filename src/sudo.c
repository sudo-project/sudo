/*
 * Copyright (c) 2009-2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifdef __TANDEM
# include <floss.h>
#endif

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
#ifdef HAVE_SETRLIMIT
# include <sys/time.h>
# include <sys/resource.h>
#endif
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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <grp.h>
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
#endif

#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

#ifdef USING_NONUNIX_GROUPS
# include "nonunix.h"
#endif

/*
 * Local variables
 */
struct plugin_container policy_plugin;
struct plugin_container_list io_plugins;
int debug_level;

/*
 * Local functions
 */
static void fix_fds(void);
static void disable_coredumps(void);
static char **get_user_info(struct user_details *);
static void command_info_to_details(char * const info[],
    struct command_details *details);
static int run_command(struct command_details *details, char *argv[],
    char *envp[]);

/* XXX - header file */
extern const char *list_user, *runas_user, *runas_group;

/* Needed by tgetpass when executing askpass helper */
struct user_details user_details;

#if defined(RLIMIT_CORE) && !defined(SUDO_DEVEL)
static struct rlimit corelimit;
#endif /* RLIMIT_CORE && !SUDO_DEVEL */

int
main(int argc, char *argv[], char *envp[])
{
    int nargc, sudo_mode;
    char **nargv, **settings, **env_add;
    char **user_info, **command_info, **argv_out, **user_env_out;
    struct plugin_container *plugin, *next;
    struct command_details command_details;
    int ok;
#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    extern char *malloc_options;
    malloc_options = "AFGJPR";
#endif

#ifdef HAVE_SETLOCALE
    setlocale(LC_ALL, "");
#endif

#if !defined(HAVE_GETPROGNAME) && !defined(HAVE___PROGNAME)
    if (argc > 0)
	setprogname(argv[0]);
#endif

    if (geteuid() != 0)
	errorx(1, "must be setuid root");

    /* Turn off core dumps and make sure fds 0-2 are open. */
    disable_coredumps();
    fix_fds();

    /* Fill in user_info with user name, uid, cwd, etc. */
    memset(&user_details, 0, sizeof(user_details));
    user_info = get_user_info(&user_details);

    /* Parse command line arguments. */
    sudo_mode = parse_args(argc, argv, &nargc, &nargv, &settings, &env_add);

    /* Read sudo.conf and load plugins. */
    sudo_load_plugins(_PATH_SUDO_CONF, &policy_plugin, &io_plugins);

    /* Open policy plugin. */
    ok = policy_plugin.u.policy->open(SUDO_API_VERSION, sudo_conversation,
	settings, user_info, envp);
    if (ok != TRUE) {
	if (ok == -2)
	    usage(1);
	else
	    errorx(1, "unable to initialize policy plugin");
    }

    sudo_debug(9, "sudo_mode %d", sudo_mode);
    switch (sudo_mode & MODE_MASK) {
	case MODE_VERSION:
	    policy_plugin.u.policy->show_version(!user_details.uid);
	    tq_foreach_fwd(&io_plugins, plugin) {
		ok = plugin->u.io->open(SUDO_API_VERSION, sudo_conversation,
		    settings, user_info, envp);
		if (ok == TRUE)
		    plugin->u.io->show_version(user_details.uid == ROOT_UID);
	    }
	    break;
	case MODE_VALIDATE:
	case MODE_VALIDATE|MODE_INVALIDATE:
	    if (policy_plugin.u.policy->validate == NULL) {
		warningx("policy plugin %s does not support the -v flag",
		    policy_plugin.name);
		ok = FALSE;
	    } else {
		ok = policy_plugin.u.policy->validate();
	    }
	    exit(ok != TRUE);
	case MODE_KILL:
	case MODE_INVALIDATE:
	    if (policy_plugin.u.policy->invalidate == NULL) {
		warningx("policy plugin %s does not support the -k/-K flags",
		    policy_plugin.name);
		exit(1);
	    }
	    policy_plugin.u.policy->invalidate(sudo_mode == MODE_KILL);
	    exit(0);
	    break;
	case MODE_CHECK:
	case MODE_CHECK|MODE_INVALIDATE:
	case MODE_LIST:
	case MODE_LIST|MODE_INVALIDATE:
	    if (policy_plugin.u.policy->list == NULL) {
		warningx("policy plugin %s does not support listing privileges",
		    policy_plugin.name);
		ok = FALSE;
	    } else {
		ok = policy_plugin.u.policy->list(nargc, nargv,
		    ISSET(sudo_mode, MODE_LONG_LIST), list_user);
	    }
	    exit(ok != TRUE);
	case MODE_RUN:
	    ok = policy_plugin.u.policy->check_policy(nargc, nargv, env_add,
		&command_info, &argv_out, &user_env_out);
	    sudo_debug(8, "policy plugin returns %d", ok);
	    if (ok != TRUE) {
		if (ok == -2)
		    usage(1);
		exit(1); /* plugin printed error message */
	    }
	    /* Open I/O plugins once policy plugin succeeds. */
	    for (plugin = io_plugins.first; plugin != NULL; plugin = next) {
		next = plugin->next;
		ok = plugin->u.io->open(SUDO_API_VERSION, sudo_conversation, settings,
		    user_info, envp);
		switch (ok) {
		case TRUE:
		    break;
		case FALSE:
		    /* I/O plugin asked to be disabled, remove from list. */
		    tq_remove(&io_plugins, plugin);
		    break;
		case -2:
		    usage(1);
		    break;
		default:
		    errorx(1, "error initializing I/O plugin %s", plugin->name);
		}
	    }
	    command_info_to_details(command_info, &command_details);
	    /* Restore coredumpsize resource limit before running. */
#if defined(RLIMIT_CORE) && !defined(SUDO_DEVEL)
	    (void) setrlimit(RLIMIT_CORE, &corelimit);
#endif /* RLIMIT_CORE && !SUDO_DEVEL */
	    /* run_command will call the close method for us */
	    run_command(&command_details, argv_out, user_env_out);
	    break;
	case MODE_EDIT:
	    /* XXX - fill in */
	    break;
	default:
	    errorx(1, "unexpected sudo mode 0x%x", sudo_mode);
    }
    exit(0);
}

/*
 * Ensure that stdin, stdout and stderr are open; set to /dev/null if not.
 * Some operating systems do this automatically in the kernel or libc.
 */
static void
fix_fds(void)
{
    int miss[3], devnull = -1;

    /*
     * stdin, stdout and stderr must be open; set them to /dev/null
     * if they are closed.
     */
    miss[STDIN_FILENO] = fcntl(STDIN_FILENO, F_GETFL, 0) == -1;
    miss[STDOUT_FILENO] = fcntl(STDOUT_FILENO, F_GETFL, 0) == -1;
    miss[STDERR_FILENO] = fcntl(STDERR_FILENO, F_GETFL, 0) == -1;
    if (miss[STDIN_FILENO] || miss[STDOUT_FILENO] || miss[STDERR_FILENO]) {
	if ((devnull = open(_PATH_DEVNULL, O_RDWR, 0644)) != -1) {
	    if (miss[STDIN_FILENO])
		(void) dup2(devnull, STDIN_FILENO);
	    if (miss[STDOUT_FILENO])
		(void) dup2(devnull, STDOUT_FILENO);
	    if (miss[STDERR_FILENO])
		(void) dup2(devnull, STDERR_FILENO);
	    if (devnull > STDERR_FILENO)
		close(devnull);
	}
    }
}

static char *
get_user_groups(struct user_details *ud)
{
    char *gid_list = NULL;
#ifdef HAVE_GETGROUPS
    size_t glsize;
    char *cp;
    int i, len;

    if ((ud->ngroups = getgroups(0, NULL)) <= 0)
	return NULL;

    ud->groups = emalloc2(ud->ngroups, sizeof(GETGROUPS_T));
    if (getgroups(ud->ngroups, ud->groups) < 0)
	error(1, "can't get group vector");
    glsize = sizeof("groups=") - 1 + (ud->ngroups * (MAX_UID_T_LEN + 1));
    gid_list = emalloc(glsize);
    memcpy(gid_list, "groups=", sizeof("groups=") - 1);
    cp = gid_list + sizeof("groups=") - 1;
    for (i = 0; i < ud->ngroups; i++) {
	/* XXX - check rval */
	len = snprintf(cp, glsize - (cp - gid_list), "%s%lu",
	    i ? "," : "", (unsigned long)ud->groups[i]);
	cp += len;
    }
#endif
    return gid_list;
}

/*
 * Return user information as an array of name=value pairs.
 * and fill in struct user_details (which shares the same strings).
 */
static char **
get_user_info(struct user_details *ud)
{
    char cwd[PATH_MAX];
    char host[MAXHOSTNAMELEN];
    char **user_info, *cp;
    struct passwd *pw;
    int i = 0;

    /* XXX - bound check number of entries */
    user_info = emalloc2(32, sizeof(char *));

    ud->uid = getuid();
    ud->euid = geteuid();
    ud->gid = getgid();
    ud->egid = getegid();

    pw = getpwuid(ud->uid);
    if (pw == NULL)
	errorx(1, "unknown uid %lu: who are you?", (unsigned long)ud->uid);

    user_info[i] = fmt_string("user", pw->pw_name);
    if (user_info[i] == NULL)
	errorx(1, "unable to allocate memory");
    ud->username = user_info[i] + sizeof("user=") - 1;

    /* Stash user's shell for use with the -s flag; don't pass to plugin. */
    if ((ud->shell = getenv("SHELL")) == NULL || ud->shell[0] == '\0') {
	ud->shell = pw->pw_shell[0] ? pw->pw_shell : _PATH_BSHELL;
    }
    ud->shell = estrdup(ud->shell);

    easprintf(&user_info[++i], "uid=%lu", (unsigned long)ud->uid);
    easprintf(&user_info[++i], "euid=%lu", (unsigned long)ud->euid);
    easprintf(&user_info[++i], "gid=%lu", (unsigned long)ud->gid);
    easprintf(&user_info[++i], "egid=%lu", (unsigned long)ud->egid);

    if ((cp = get_user_groups(ud)) != NULL)
	user_info[++i] = cp;

    if (getcwd(cwd, sizeof(cwd)) != NULL) {
	user_info[++i] = fmt_string("cwd", cwd);
	if (user_info[i] == NULL)
	    errorx(1, "unable to allocate memory");
	ud->cwd = user_info[i] + sizeof("cwd=") - 1;
    }

    if ((cp = ttyname(STDIN_FILENO)) || (cp = ttyname(STDOUT_FILENO)) ||
	(cp = ttyname(STDERR_FILENO))) {
	user_info[++i] = fmt_string("tty", cp);
	if (user_info[i] == NULL)
	    errorx(1, "unable to allocate memory");
	ud->tty = user_info[i] + sizeof("tty=") - 1;
    }

    if (gethostname(host, sizeof(host)) == 0)
	host[sizeof(host) - 1] = '\0';
    else
	strlcpy(host, "localhost", sizeof(host));
    user_info[++i] = fmt_string("host", host);
    if (user_info[i] == NULL)
	errorx(1, "unable to allocate memory");
    ud->host = user_info[i] + sizeof("host=") - 1;

    get_ttysize(&ud->ts_lines, &ud->ts_cols);
    easprintf(&user_info[++i], "lines=%d", ud->ts_lines);
    easprintf(&user_info[++i], "cols=%d", ud->ts_cols);

    user_info[++i] = NULL;

    return user_info;
}

/*
 * Convert a command_info array into a command_details structure.
 */
static void
command_info_to_details(char * const info[], struct command_details *details)
{
    int i;
    long lval;
    unsigned long ulval;
    char *cp, *ep;

    memset(details, 0, sizeof(*details));

#define SET_STRING(s, n) \
    if (strncmp(s, info[i], sizeof(s) - 1) == 0 && info[i][sizeof(s) - 1]) { \
	details->n = info[i] + sizeof(s) - 1; \
	break; \
    }

    for (i = 0; info[i] != NULL; i++) {
	sudo_debug(9, "command info: %s", info[i]);
	switch (info[i][0]) {
	    case 'c':
		SET_STRING("chroot=", chroot)
		SET_STRING("command=", command)
		SET_STRING("cwd=", cwd)
		break;
	    case 'l':
		SET_STRING("login_class=", login_class)
		break;
	    case 'n':
		/* XXX - bounds check  -NZERO to NZERO (inclusive). */
		if (strncmp("nice=", info[i], sizeof("nice=") - 1) == 0) {
		    cp = info[i] + sizeof("nice=") - 1;
		    if (*cp == '\0')
			break;
		    errno = 0;
		    lval = strtol(cp, &ep, 0);
		    if (*cp != '\0' && *ep == '\0' &&
			!(errno == ERANGE &&
			(lval == LONG_MAX || lval == LONG_MIN)) &&
			lval < INT_MAX && lval > INT_MIN) {
			details->priority = (int)lval;
			SET(details->flags, CD_SET_PRIORITY);
		    }
		    break;
		}
		if (strncmp("noexec=", info[i], sizeof("noexec=") - 1) == 0) {
		    if (atobool(info[i] + sizeof("noexec=") - 1) == TRUE)
			SET(details->flags, CD_NOEXEC);
		    break;
		}
		break;
	    case 'p':
		if (strncmp("preserve_groups=", info[i], sizeof("preserve_groups=") - 1) == 0) {
		    if (atobool(info[i] + sizeof("preserve_groups=") - 1) == TRUE)
			SET(details->flags, CD_PRESERVE_GROUPS);
		    break;
		}
		break;
	    case 'r':
		if (strncmp("runas_egid=", info[i], sizeof("runas_egid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_egid=") - 1;
		    if (*cp == '\0')
			break;
		    errno = 0;
		    ulval = strtoul(cp, &ep, 0);
		    if (*cp != '\0' && *ep == '\0' &&
			(errno != ERANGE || ulval != ULONG_MAX)) {
			details->egid = (gid_t)ulval;
			SET(details->flags, CD_SET_EGID);
		    }
		    break;
		}
		if (strncmp("runas_euid=", info[i], sizeof("runas_euid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_euid=") - 1;
		    if (*cp == '\0')
			break;
		    errno = 0;
		    ulval = strtoul(cp, &ep, 0);
		    if (*cp != '\0' && *ep == '\0' &&
			(errno != ERANGE || ulval != ULONG_MAX)) {
			details->euid = (uid_t)ulval;
			SET(details->flags, CD_SET_EUID);
		    }
		    break;
		}
		if (strncmp("runas_gid=", info[i], sizeof("runas_gid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_gid=") - 1;
		    if (*cp == '\0')
			break;
		    errno = 0;
		    ulval = strtoul(cp, &ep, 0);
		    if (*cp != '\0' && *ep == '\0' &&
			(errno != ERANGE || ulval != ULONG_MAX)) {
			details->gid = (gid_t)ulval;
			SET(details->flags, CD_SET_GID);
		    }
		    break;
		}
		if (strncmp("runas_groups=", info[i], sizeof("runas_groups=") - 1) == 0) {
		    int j;

		    /* count groups, alloc and fill in */
		    cp = info[i] + sizeof("runas_groups=") - 1;
		    if (*cp == '\0')
			break;
		    for (;;) {
			details->ngroups++;
			if ((cp = strchr(cp, ',')) == NULL)
			    break;
			cp++;
		    }
		    details->groups = emalloc2(details->ngroups, sizeof(GETGROUPS_T));
		    cp = info[i] + sizeof("runas_groups=") - 1;
		    for (j = 0; j < details->ngroups;) {
			errno = 0;
			ulval = strtoul(cp, &ep, 0);
			if (*cp == '\0' || (*ep != ',' && *ep != '\0') ||
			    (ulval == ULONG_MAX && errno == ERANGE)) {
			    break;
			}
			details->groups[j++] = (gid_t)ulval;
			cp = ep + 1;
		    }
		    details->ngroups = j;
		    break;
		}
		if (strncmp("runas_uid=", info[i], sizeof("runas_uid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_uid=") - 1;
		    if (*cp == '\0')
			break;
		    errno = 0;
		    ulval = strtoul(cp, &ep, 0);
		    if (*cp != '\0' && *ep == '\0' &&
			(errno != ERANGE || ulval != ULONG_MAX)) {
			details->uid = (uid_t)ulval;
			SET(details->flags, CD_SET_UID);
		    }
		    break;
		}
		break;
	    case 's':
		SET_STRING("selinux_role=", selinux_role)
		SET_STRING("selinux_type=", selinux_type)
		break;
	    case 't':
		if (strncmp("timeout=", info[i], sizeof("timeout=") - 1) == 0) {
		    cp = info[i] + sizeof("timeout=") - 1;
		    if (*cp == '\0')
			break;
		    errno = 0;
		    lval = strtol(cp, &ep, 0);
		    if (*cp != '\0' && *ep == '\0' &&
			!(errno == ERANGE &&
			(lval == LONG_MAX || lval == LONG_MIN)) &&
			lval <= INT_MAX && lval >= 0) {
			details->timeout = (int)lval;
			SET(details->flags, CD_SET_TIMEOUT);
		    }
		    break;
		}
		break;
	    case 'u':
		if (strncmp("umask=", info[i], sizeof("umask=") - 1) == 0) {
		    cp = info[i] + sizeof("umask=") - 1;
		    if (*cp == '\0')
			break;
		    errno = 0;
		    ulval = strtoul(cp, &ep, 8);
		    if (*cp != '\0' && *ep == '\0' &&
			(errno != ERANGE || ulval != ULONG_MAX)) {
			details->umask = (uid_t)ulval;
			SET(details->flags, CD_SET_UMASK);
		    }
		}
		break;
	}
    }

    if (!ISSET(details->flags, CD_SET_EUID))
	details->euid = details->uid;
}

/*
 * Disable core dumps to avoid dropping a core with user password in it.
 * We will reset this limit before executing the command.
 * Not all operating systems disable core dumps for setuid processes.
 */
static void
disable_coredumps(void)
{
#if defined(__linux__) || (defined(RLIMIT_CORE) && !defined(SUDO_DEVEL))
    struct rlimit rl;
#endif

#if defined(__linux__)
    /*
     * Unlimit the number of processes since Linux's setuid() will
     * apply resource limits when changing uid and return EAGAIN if
     * nproc would be violated by the uid switch.
     */
    rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_NPROC, &rl)) {
	if (getrlimit(RLIMIT_NPROC, &rl) == 0) {
	    rl.rlim_cur = rl.rlim_max;
	    (void)setrlimit(RLIMIT_NPROC, &rl);
	}
    }
#endif /* __linux__ */
#if defined(RLIMIT_CORE) && !defined(SUDO_DEVEL)
    /*
     * Turn off core dumps.
     */
    (void) getrlimit(RLIMIT_CORE, &corelimit);
    memcpy(&rl, &corelimit, sizeof(struct rlimit));
    rl.rlim_cur = 0;
    (void) setrlimit(RLIMIT_CORE, &rl);
#endif /* RLIMIT_CORE && !SUDO_DEVEL */
}

/*
 * Cleanup hook for error()/errorx()
 */
void
cleanup(int gotsignal)
{
#if 0 /* XXX */
    struct sudo_nss *nss;

    if (!gotsignal) {
	if (snl != NULL) {
	    tq_foreach_fwd(snl, nss)
		nss->close(nss);
	}
	sudo_endpwent();
	sudo_endgrent();
    }
#ifdef _PATH_SUDO_TRANSCRIPT
    if (def_transcript)
	term_restore(STDIN_FILENO, 0);
#endif
#endif
}

/*
 * Setup the execution environment immediately prior to the call to execve()
 */
int
exec_setup(struct command_details *details)
{
    struct passwd *pw;

    pw = getpwuid(details->euid);
    if (pw != NULL) {
#ifdef HAVE_GETUSERATTR
	aix_setlimits(pw->pw_name);
#endif
#ifdef HAVE_LOGIN_CAP_H
	if (details->login_class) {
	    int flags;
	    login_cap_t *lc;

	    /*
	     * We only use setusercontext() to set the nice value and rlimits.
	     */
	    lc = login_getclass((char *)details->login_class);
	    if (!lc) {
		warningx("unknown login class %s", details->login_class);
		errno = ENOENT;
		goto done;
	    }
	    flags = LOGIN_SETRESOURCES|LOGIN_SETPRIORITY;
	    if (setusercontext(lc, pw, pw->pw_uid, flags)) {
		if (pw->pw_uid != ROOT_UID) {
		    warning("unable to set user context");
		    goto done;
		} else
		    warning("unable to set user context");
	    }
	}
#endif /* HAVE_LOGIN_CAP_H */
    }

    /*
     * Set groups, including supplementary group vector.
     */
#ifdef HAVE_SETEUID
    if (ISSET(details->flags, CD_SET_EGID) && setegid(details->egid)) {
	warning("unable to set egid to runas gid");
	goto done;
    }
#endif
    if (ISSET(details->flags, CD_SET_GID) && setgid(details->gid)) {
	warning("unable to set gid to runas gid");
	goto done;
    }

    if (!ISSET(details->flags, CD_PRESERVE_GROUPS)) {
#ifdef HAVE_GETGROUPS
	if (details->ngroups >= 0) {
	    if (setgroups(details->ngroups, details->groups) < 0) {
		warning("unable to set supplementary group IDs");
		goto done;
	    }
	}
#else
	if (pw && initgroups(pw->pw_name, pw->pw_gid) < 0) {
	    warning("unable to set supplementary group IDs");
	    goto done;
	}
#endif
    }

    if (ISSET(details->flags, CD_SET_PRIORITY)) {
	if (setpriority(PRIO_PROCESS, 0, details->priority) != 0) {
	    warning("unable to set process priority");
	    goto done;
	}
    }
    if (ISSET(details->flags, CD_SET_UMASK))
	(void) umask(details->umask);
    if (details->chroot) {
	if (chroot(details->chroot) != 0 || chdir("/") != 0) {
	    warning("unable to change root to %s", details->chroot);
	    goto done;
	}
    }
    if (details->cwd) {
	/* cwd is relative to the new root, if any */
	if (chdir(details->cwd) != 0) {
	    warning("unable to change directory to %s", details->cwd);
	    goto done;
	}
    }

    /* Must set uids last */
#ifdef HAVE_SETRESUID
    if (setresuid(details->uid, details->euid, details->euid) != 0) {
	warning("unable to change to runas uid");
	goto done;
    }
#elif HAVE_SETREUID
    if (setreuid(details->uid, details->euid) != 0) {
	warning("unable to change to runas uid");
	goto done;
    }
#else
    if (seteuid(details->euid) != 0 || setuid(details->euid) != 0) {
	warning("unable to change to runas uid");
	goto done;
    }
#endif /* !HAVE_SETRESUID && !HAVE_SETREUID */

    errno = 0;

done:
    return errno;
}

/*
 * Run the command and wait for it to complete.
 */
static int
run_command(struct command_details *details, char *argv[], char *envp[])
{
    struct plugin_container *plugin;
    struct command_status cstat;
    int exitcode = 1;

    cstat.type = CMD_INVALID;
    cstat.val = 0;

    /*
     * XXX - missing closefrom(), may not be possible in new scheme
     *       also no background support
     */

    /* If there are I/O plugins, allocate a pty and exec */
    if (!tq_empty(&io_plugins)) {
	sudo_debug(8, "script mode");
	script_setup(details->euid);
    }
    script_execve(details, argv, envp, &cstat);

    switch (cstat.type) {
    case CMD_ERRNO:
	/* exec_setup() or execve() returned an error. */
	policy_plugin.u.policy->close(0, cstat.val);
	tq_foreach_fwd(&io_plugins, plugin) {
	    plugin->u.io->close(0, cstat.val);
	}
	exitcode = 1;
	break;
    case CMD_WSTATUS:
	/* Command ran, exited or was killed. */
	policy_plugin.u.policy->close(cstat.val, 0);
	tq_foreach_fwd(&io_plugins, plugin) {
	    plugin->u.io->close(0, cstat.val);
	}
	if (WIFEXITED(cstat.val))
	    exitcode = WEXITSTATUS(cstat.val);
	else if (WIFSIGNALED(cstat.val))
	    exitcode = WTERMSIG(cstat.val) | 128;
	break;
    default:
	warningx("unexpected child termination condition: %d", cstat.type);
	break;
    }
    exit(exitcode);
}

/*
 * Simple debugging/logging.
 */
void
sudo_debug(int level, const char *fmt, ...)
{
    va_list ap;
    char *fmt2;

    if (level > debug_level)
	return;

    /* Backet fmt with program name and a newline to make it a single write */
    easprintf(&fmt2, "%s: %s\n", getprogname(), fmt);
    va_start(ap, fmt);
    vfprintf(stderr, fmt2, ap);
    va_end(ap);
    efree(fmt2);
}
