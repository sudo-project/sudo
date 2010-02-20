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

#include <sudo_usage.h>
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

/* Used by getprogname() unless crt0 supports getting program name. */
int Argc;
char **Argv;

#if defined(RLIMIT_CORE) && !defined(SUDO_DEVEL)
static struct rlimit corelimit;
#endif /* RLIMIT_CORE && !SUDO_DEVEL */
sigaction_t saved_sa_int, saved_sa_quit, saved_sa_tstp;

int
main(int argc, char *argv[], char *envp[])
{
    sigaction_t sa;
    int nargc, sudo_mode;
    char **nargv, **settings, **env_add;
    char **user_info, **command_info, **argv_out, **user_env_out;
    struct plugin_container *plugin;
    struct user_details user_details;
    struct command_details command_details;
    int ok;
#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    extern char *malloc_options;
    malloc_options = "AFGJPR";
#endif

    Argc = argc;
    Argv = argv;

#ifdef HAVE_SETLOCALE
    setlocale(LC_ALL, "");
#endif

    if (geteuid() != 0)
	errorx(1, "must be setuid root");

    /* XXX - Must be done before shadow file lookups... */
#if defined(HAVE_GETPRPWNAM) && defined(HAVE_SET_AUTH_PARAMETERS)
    (void) set_auth_parameters(Argc, Argv);
# ifdef HAVE_INITPRIVS
    initprivs();
# endif
#endif /* HAVE_GETPRPWNAM && HAVE_SET_AUTH_PARAMETERS */

    /*
     * Signal setup:
     *	Ignore keyboard-generated signals so the user cannot interrupt
     *  us at some point and avoid the logging.
     * XXX - leave this to the plugin?
     */
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGINT, &sa, &saved_sa_int);
    (void) sigaction(SIGQUIT, &sa, &saved_sa_quit);
    (void) sigaction(SIGTSTP, &sa, &saved_sa_tstp);

    /* Turn off core dumps and make sure fds 0-2 are open. */
    disable_coredumps();
    fix_fds();

    /* Parse command line arguments. */
    sudo_mode = parse_args(Argc, Argv, &nargc, &nargv, &settings, &env_add);

    /* Read sudo.conf and load plugins. */
    sudo_load_plugins(_PATH_SUDO_CONF, &policy_plugin, &io_plugins);

    /* Fill in user_info with user name, uid, cwd, etc. */
    memset(&user_details, 0, sizeof(user_details));
    user_info = get_user_info(&user_details);

    /* Open each plugin (XXX - check for errors). */
    policy_plugin.u.policy->open(SUDO_API_VERSION, sudo_conversation,
	settings, user_info, envp);
    tq_foreach_fwd(&io_plugins, plugin) {
	/* XXX - remove from list if open returns 0 */
	plugin->u.io->open(SUDO_API_VERSION, sudo_conversation, settings,
	    user_info, envp);
    }

    sudo_debug(9, "sudo_mode %d", sudo_mode);
    switch (sudo_mode & MODE_MASK) {
	case MODE_VERSION:
	    policy_plugin.u.policy->show_version(!user_details.uid);
	    tq_foreach_fwd(&io_plugins, plugin) {
		plugin->u.io->show_version(!user_details.uid);
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
	    if (policy_plugin.u.policy->validate == NULL) {
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
	    if (ok != TRUE)
		exit(ok); /* plugin printed error message */
	    command_info_to_details(command_info, &command_details);
	    /* Restore coredumpsize resource limit before running. */
#if defined(RLIMIT_CORE) && !defined(SUDO_DEVEL)
	    (void) setrlimit(RLIMIT_CORE, &corelimit);
#endif /* RLIMIT_CORE && !SUDO_DEVEL */
	    /* run_command will call close for us */
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
    int i;

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
	snprintf(cp, glsize - (cp - gid_list), "%lu%s",
	    (unsigned long)ud->groups[i], i ? "," : "");
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
    ud->username = user_info[i] + sizeof("user=") - 1;

    easprintf(&user_info[++i], "uid=%lu", (unsigned long)ud->uid);
    easprintf(&user_info[++i], "euid=%lu", (unsigned long)ud->euid);
    easprintf(&user_info[++i], "gid=%lu", (unsigned long)ud->gid);
    easprintf(&user_info[++i], "egid=%lu", (unsigned long)ud->egid);

    if ((cp = get_user_groups(ud)) != NULL)
	user_info[++i] = cp;

    if (getcwd(cwd, sizeof(cwd)) != NULL) {
	user_info[++i] = fmt_string("cwd", cwd);
	ud->cwd = user_info[i] + sizeof("cwd=") - 1;
    }

    if ((cp = ttyname(STDIN_FILENO)) || (cp = ttyname(STDOUT_FILENO)) ||
	(cp = ttyname(STDERR_FILENO))) {
	user_info[++i] = fmt_string("tty", cp);
	ud->tty = user_info[i] + sizeof("tty=") - 1;
    }

    if (gethostname(host, sizeof(host)) == 0)
	host[sizeof(host) - 1] = '\0';
    else
	strlcpy(host, "localhost", sizeof(host));
    user_info[++i] = fmt_string("host", host);
    ud->host = user_info[i] + sizeof("host=") - 1;

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

    for (i = 0; info[i] != NULL; i++) {
	/* XXX - should ignore empty entries */
	switch (info[i][0]) {
	    case 'c':
		if (strncmp("chroot=", info[i], sizeof("chroot=") - 1) == 0) {
		    details->chroot = info[i] + sizeof("chroot=") - 1;
		    break;
		}
		if (strncmp("command=", info[i], sizeof("command=") - 1) == 0) {
		    details->command = info[i] + sizeof("command=") - 1;
		    break;
		}
		if (strncmp("cwd=", info[i], sizeof("cwd=") - 1) == 0) {
		    details->cwd = info[i] + sizeof("cwd=") - 1;
		    break;
		}
		break;
	    case 'l':
		if (strncmp("login_class=", info[i], sizeof("login_class=") - 1) == 0) {
		    details->login_class = info[i] + sizeof("login_class=") - 1;
		    break;
		}
		break;
	    case 'n':
		/* XXX - bounds check  -NZERO to NZERO (inclusive). */
		if (strncmp("nice=", info[i], sizeof("nice=") - 1) == 0) {
		    cp = info[i] + sizeof("nice=") - 1;
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
		    if (atobool(info[i] + sizeof("noexec=") - 1))
			SET(details->flags, CD_NOEXEC);
		    break;
		}
		break;
	    case 'p':
		if (strncmp("preserve_groups=", info[i], sizeof("preserve_groups=") - 1) == 0) {
		    if (atobool(info[i] + sizeof("preserve_groups=") - 1))
			SET(details->flags, CD_PRESERVE_GROUPS);
		    break;
		}
		break;
	    case 'r':
		if (strncmp("runas_egid=", info[i], sizeof("runas_egid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_egid=") - 1;
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
			if (*cp != '\0' && (*ep == ',' || *ep == '\0') &&
			    (errno != ERANGE || ulval != ULONG_MAX)) {
			    details->groups[j++] = (gid_t)ulval;
			}
		    }
		    details->ngroups = j;
		    break;
		}
		if (strncmp("runas_uid=", info[i], sizeof("runas_uid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_uid=") - 1;
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
		if (strncmp("selinux_role=", info[i], sizeof("selinux_role=") - 1) == 0) {
		    details->selinux_role = info[i] + sizeof("selinux_role=") - 1;
		    break;
		}
		if (strncmp("selinux_type=", info[i], sizeof("selinux_type=") - 1) == 0) {
		    details->selinux_type = info[i] + sizeof("selinux_type=") - 1;
		    break;
		}
		break;
	    case 't':
		if (strncmp("timeout=", info[i], sizeof("timeout=") - 1) == 0) {
		    cp = info[i] + sizeof("timeout=") - 1;
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
cleanup(gotsignal)
    int gotsignal;
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
	/* XXX - may need to initgroups anyway--plugin may not have list */
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
    if (ISSET(details->flags, CD_SET_TIMEOUT))
	alarm(details->timeout);
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

static sig_atomic_t sigchld;

static void
sigchild(int s)
{
    sigchld = 1;
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
     *       or selinux...
     */

    /* If there are I/O plugins, allocate a pty and exec */
    if (!tq_empty(&io_plugins)) {
	sudo_debug(8, "script mode");
	script_setup(details->euid);
	script_execve(details, argv, envp, &cstat);
    } else {
	pid_t child, pid;
	int nready, sv[2];
	ssize_t nread;
	sigaction_t sa;
	fd_set *fdsr;

	zero_bytes(&sa, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	/* Want select() to be interrupted when child dies. */
	sa.sa_handler = sigchild;
	sigaction(SIGCHLD, &sa, NULL);
     
	/* Ignore SIGPIPE from other end of socketpair. */
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sv) != 0)
		error(1, "cannot create sockets");

	child = fork();
	if (child == -1)
	    error(1, "unable to fork");

	if (child == 0) {
	    /* child */
	    close(sv[0]);
	    if (exec_setup(details) == 0) {
		/* XXX - fallback via /bin/sh */
		execve(details->command, argv, envp);
	    }
	    cstat.type = CMD_ERRNO;
	    cstat.val = errno;
	    write(sv[1], &cstat, sizeof(cstat));
	    _exit(1);
	}
	close(sv[1]);
	sudo_debug(9, "waiting for child");

	/* wait for child to complete or for data on sv[0] */
	fdsr = (fd_set *)emalloc2(howmany(sv[0] + 1, NFDBITS), sizeof(fd_mask));
	zero_bytes(fdsr, howmany(sv[0] + 1, NFDBITS) * sizeof(fd_mask));
	FD_SET(sv[0], fdsr);
	for (;;) {
	    if (sigchld) {
		sigchld = 0;
		do {
		    pid = waitpid(child, &cstat.val, WNOHANG);
		    if (pid == child)
			cstat.type = CMD_WSTATUS;
		} while (pid == -1 && errno == EINTR);
		if (cstat.type == CMD_WSTATUS) {
		    /* command terminated, we're done */
		    break;
		}
	    }
	    nready = select(sv[0] + 1, fdsr, NULL, NULL, NULL);
	    if (nready == -1) {
		if (errno == EINTR)
		    continue;
		error(1, "select failed");
	    }
	    if (FD_ISSET(sv[0], fdsr)) {
		/* read child status */
		nread = recv(sv[0], &cstat, sizeof(cstat), 0);
		if (nread == -1) {
		    if (errno == EINTR)
			continue;
		} else if (nread != sizeof(cstat)) {
		    warningx("error reading command status");
		}
		break; /* XXX */
	    }
	}
    }

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

    if (level > debug_level)
	return;

    fputs(getprogname(), stderr);
    fputs(": ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    putc('\n', stderr);
}
