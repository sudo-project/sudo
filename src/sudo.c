/*
 * Copyright (c) 2009-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/time.h>
#include <sys/resource.h>
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <grp.h>
#include <pwd.h>
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
#endif
#ifdef HAVE_PROJECT_H
# include <project.h>
# include <sys/task.h>
#endif
#ifdef HAVE_SELINUX
# include <selinux/selinux.h>
#endif
#ifdef HAVE_SETAUTHDB
# include <usersec.h>
#endif /* HAVE_SETAUTHDB */
#if defined(HAVE_GETPRPWNAM) && defined(HAVE_SET_AUTH_PARAMETERS)
# ifdef __hpux
#  undef MAXINT
#  include <hpsecurity.h>
# else
#  include <sys/security.h>
# endif /* __hpux */
# include <prot.h>
#endif /* HAVE_GETPRPWNAM && HAVE_SET_AUTH_PARAMETERS */
#ifdef HAVE_PRIV_SET
# include <priv.h>
#endif
#if defined(HAVE_STRUCT_KINFO_PROC_P_TDEV) || defined (HAVE_STRUCT_KINFO_PROC_KP_EPROC_E_TDEV)
# include <sys/sysctl.h>
#elif defined(HAVE_STRUCT_KINFO_PROC_KI_TDEV)
# include <sys/sysctl.h>
# include <sys/user.h>
#endif

#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"
#include <sudo_usage.h>

/*
 * Local variables
 */
struct plugin_container policy_plugin;
struct plugin_container_list io_plugins;
struct user_details user_details;
const char *list_user, *runas_user, *runas_group; /* extern for parse_args.c */
static int sudo_mode;

/*
 * Local functions
 */
static void fix_fds(void);
static void disable_coredumps(void);
static char **get_user_info(struct user_details *);
static void command_info_to_details(char * const info[],
    struct command_details *details);
static int policy_open(struct plugin_container *plugin, char * const settings[],
    char * const user_info[], char * const user_env[]);
static void policy_close(struct plugin_container *plugin, int exit_status,
    int error);
static int iolog_open(struct plugin_container *plugin, char * const settings[],
    char * const user_info[], char * const command_details[],
    int argc, char * const argv[], char * const user_env[]);
static void iolog_close(struct plugin_container *plugin, int exit_status,
    int error);

/* Policy plugin convenience functions. */
static int policy_open(struct plugin_container *plugin, char * const settings[],
    char * const user_info[], char * const user_env[]);
static void policy_close(struct plugin_container *plugin, int exit_status,
    int error);
static int policy_show_version(struct plugin_container *plugin, int verbose);
static int policy_check(struct plugin_container *plugin, int argc,
    char * const argv[], char *env_add[], char **command_info[],
    char **argv_out[], char **user_env_out[]);
static int policy_list(struct plugin_container *plugin, int argc,
    char * const argv[], int verbose, const char *list_user);
static int policy_validate(struct plugin_container *plugin);
static void policy_invalidate(struct plugin_container *plugin, int remove);
static int policy_init_session(struct plugin_container *plugin,
    struct passwd *pwd);

/* I/O log plugin convenience functions. */
static int iolog_open(struct plugin_container *plugin, char * const settings[],
    char * const user_info[], char * const command_details[],
    int argc, char * const argv[], char * const user_env[]);
static void iolog_close(struct plugin_container *plugin, int exit_status,
    int error);
static int iolog_show_version(struct plugin_container *plugin, int verbose);

#if defined(RLIMIT_CORE) && !defined(SUDO_DEVEL)
static struct rlimit corelimit;
#endif /* RLIMIT_CORE && !SUDO_DEVEL */
#if defined(__linux__)
static struct rlimit nproclimit;
#endif

#ifdef HAVE_LOGIN_CAP_H
extern char **environ;
#endif

int
main(int argc, char *argv[], char *envp[])
{
    int nargc, ok, exitcode = 0;
    char **nargv, **settings, **env_add;
    char **user_info, **command_info, **argv_out, **user_env_out;
    struct plugin_container *plugin, *next;
    struct command_details command_details;
    sigset_t mask;
    debug_decl(main, SUDO_DEBUG_MAIN)

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    {
	extern char *malloc_options;
	malloc_options = "AFGJPR";
    }
#endif

#if !defined(HAVE_GETPROGNAME) && !defined(HAVE___PROGNAME)
    if (argc > 0)
	setprogname(argv[0]);
#endif

#ifdef HAVE_SETLOCALE
    setlocale(LC_ALL, "");
#endif
    bindtextdomain(PACKAGE_NAME, LOCALEDIR);
    textdomain(PACKAGE_NAME);

    /* Must be done before we do any password lookups */
#if defined(HAVE_GETPRPWNAM) && defined(HAVE_SET_AUTH_PARAMETERS)
    (void) set_auth_parameters(argc, argv);
# ifdef HAVE_INITPRIVS
    initprivs();
# endif
#endif /* HAVE_GETPRPWNAM && HAVE_SET_AUTH_PARAMETERS */

    if (geteuid() != 0)
	errorx(1, _("must be setuid root"));

    /* Reset signal mask, disable core dumps and make sure fds 0-2 are open. */
    (void) sigemptyset(&mask);
    (void) sigprocmask(SIG_SETMASK, &mask, NULL);
    disable_coredumps();
    fix_fds();

    /* Fill in user_info with user name, uid, cwd, etc. */
    memset(&user_details, 0, sizeof(user_details));
    user_info = get_user_info(&user_details);

    /* Read sudo.conf. */
    sudo_conf_read();

    /* Parse command line arguments. */
    sudo_mode = parse_args(argc, argv, &nargc, &nargv, &settings, &env_add);
    sudo_debug_printf(SUDO_DEBUG_DEBUG, "sudo_mode %d", sudo_mode);

    /* Print sudo version early, in case of plugin init failure. */
    if (ISSET(sudo_mode, MODE_VERSION)) {
	printf(_("Sudo version %s\n"), PACKAGE_VERSION);
	if (user_details.uid == ROOT_UID)
	    (void) printf(_("Configure options: %s\n"), CONFIGURE_ARGS);
    }

    /* Load plugins. */
    if (!sudo_load_plugins(&policy_plugin, &io_plugins))
	errorx(1, _("fatal error, unable to load plugins"));

    /* Open policy plugin. */
    ok = policy_open(&policy_plugin, settings, user_info, envp);
    if (ok != 1) {
	if (ok == -2)
	    usage(1);
	else
	    errorx(1, _("unable to initialize policy plugin"));
    }

    switch (sudo_mode & MODE_MASK) {
	case MODE_VERSION:
	    policy_show_version(&policy_plugin, !user_details.uid);
	    tq_foreach_fwd(&io_plugins, plugin) {
		ok = iolog_open(plugin, settings, user_info, NULL,
		    nargc, nargv, envp);
		if (ok == 1)
		    iolog_show_version(plugin, !user_details.uid);
	    }
	    break;
	case MODE_VALIDATE:
	case MODE_VALIDATE|MODE_INVALIDATE:
	    ok = policy_validate(&policy_plugin);
	    exit(ok != 1);
	case MODE_KILL:
	case MODE_INVALIDATE:
	    policy_invalidate(&policy_plugin, sudo_mode == MODE_KILL);
	    exit(0);
	    break;
	case MODE_CHECK:
	case MODE_CHECK|MODE_INVALIDATE:
	case MODE_LIST:
	case MODE_LIST|MODE_INVALIDATE:
	    ok = policy_list(&policy_plugin, nargc, nargv,
		ISSET(sudo_mode, MODE_LONG_LIST), list_user);
	    exit(ok != 1);
	case MODE_EDIT:
	case MODE_RUN:
	    ok = policy_check(&policy_plugin, nargc, nargv, env_add,
		&command_info, &argv_out, &user_env_out);
	    sudo_debug_printf(SUDO_DEBUG_INFO, "policy plugin returns %d", ok);
	    if (ok != 1) {
		if (ok == -2)
		    usage(1);
		exit(1); /* plugin printed error message */
	    }
	    /* Open I/O plugins once policy plugin succeeds. */
	    for (plugin = io_plugins.first; plugin != NULL; plugin = next) {
		next = plugin->next;
		ok = iolog_open(plugin, settings, user_info,
		    command_info, nargc, nargv, envp);
		switch (ok) {
		case 1:
		    break;
		case 0:
		    /* I/O plugin asked to be disabled, remove from list. */
		    tq_remove(&io_plugins, plugin);
		    break;
		case -2:
		    usage(1);
		    break;
		default:
		    errorx(1, _("error initializing I/O plugin %s"),
			plugin->name);
		}
	    }
	    command_info_to_details(command_info, &command_details);
	    command_details.argv = argv_out;
	    command_details.envp = user_env_out;
	    if (ISSET(sudo_mode, MODE_BACKGROUND))
		SET(command_details.flags, CD_BACKGROUND);
	    /* Restore coredumpsize resource limit before running. */
#if defined(RLIMIT_CORE) && !defined(SUDO_DEVEL)
	    (void) setrlimit(RLIMIT_CORE, &corelimit);
#endif /* RLIMIT_CORE && !SUDO_DEVEL */
	    if (ISSET(command_details.flags, CD_SUDOEDIT)) {
		exitcode = sudo_edit(&command_details);
	    } else {
		exitcode = run_command(&command_details);
	    }
	    /* The close method was called by sudo_edit/run_command. */
	    break;
	default:
	    errorx(1, _("unexpected sudo mode 0x%x"), sudo_mode);
    }
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);                
    exit(exitcode);
}

/*
 * Ensure that stdin, stdout and stderr are open; set to /dev/null if not.
 * Some operating systems do this automatically in the kernel or libc.
 */
static void
fix_fds(void)
{
    int miss[3], devnull = -1;
    debug_decl(fix_fds, SUDO_DEBUG_UTIL)

    /*
     * stdin, stdout and stderr must be open; set them to /dev/null
     * if they are closed.
     */
    miss[STDIN_FILENO] = fcntl(STDIN_FILENO, F_GETFL, 0) == -1;
    miss[STDOUT_FILENO] = fcntl(STDOUT_FILENO, F_GETFL, 0) == -1;
    miss[STDERR_FILENO] = fcntl(STDERR_FILENO, F_GETFL, 0) == -1;
    if (miss[STDIN_FILENO] || miss[STDOUT_FILENO] || miss[STDERR_FILENO]) {
	if ((devnull = open(_PATH_DEVNULL, O_RDWR, 0644)) == -1)
	    error(1, _("unable to open %s"), _PATH_DEVNULL);
	if (miss[STDIN_FILENO] && dup2(devnull, STDIN_FILENO) == -1)
	    error(1, "dup2");
	if (miss[STDOUT_FILENO] && dup2(devnull, STDOUT_FILENO) == -1)
	    error(1, "dup2");
	if (miss[STDERR_FILENO] && dup2(devnull, STDERR_FILENO) == -1)
	    error(1, "dup2");
	if (devnull > STDERR_FILENO)
	    close(devnull);
    }
    debug_return;
}

/*
 * Allocate space for groups and fill in using getgrouplist()
 * for when we cannot use getgroups().
 */
static int
fill_group_list(struct user_details *ud)
{
    int maxgroups, tries, rval = -1;
    debug_decl(fill_group_list, SUDO_DEBUG_UTIL)

#if defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
    maxgroups = (int)sysconf(_SC_NGROUPS_MAX);
    if (maxgroups < 0)
#endif
	maxgroups = NGROUPS_MAX;

    /*
     * It is possible to belong to more groups in the group database
     * than NGROUPS_MAX.  We start off with NGROUPS_MAX * 2 entries
     * and double this as needed.
     */
    ud->groups = NULL;
    ud->ngroups = maxgroups;
    for (tries = 0; tries < 10 && rval == -1; tries++) {
	ud->ngroups *= 2;
	efree(ud->groups);
	ud->groups = emalloc2(ud->ngroups, sizeof(GETGROUPS_T));
	rval = getgrouplist(ud->username, ud->gid, ud->groups, &ud->ngroups);
    }
    debug_return_int(rval);
}

static char *
get_user_groups(struct user_details *ud)
{
    char *cp, *gid_list = NULL;
    size_t glsize;
    int i, len;
    debug_decl(get_user_groups, SUDO_DEBUG_UTIL)

    /*
     * Systems with mbr_check_membership() support more than NGROUPS_MAX
     * groups so we cannot use getgroups().
     */
    ud->groups = NULL;
#ifndef HAVE_MBR_CHECK_MEMBERSHIP
    if ((ud->ngroups = getgroups(0, NULL)) > 0) {
	ud->groups = emalloc2(ud->ngroups, sizeof(GETGROUPS_T));
	if (getgroups(ud->ngroups, ud->groups) < 0) {
	    efree(ud->groups);
	    ud->groups = NULL;
	}
    }
#endif /* HAVE_MBR_CHECK_MEMBERSHIP */
    if (ud->groups == NULL) {
	if (fill_group_list(ud) == -1)
	    error(1, _("unable to get group vector"));
    }

    /*
     * Format group list as a comma-separated string of gids.
     */
    glsize = sizeof("groups=") - 1 + (ud->ngroups * (MAX_UID_T_LEN + 1));
    gid_list = emalloc(glsize);
    memcpy(gid_list, "groups=", sizeof("groups=") - 1);
    cp = gid_list + sizeof("groups=") - 1;
    for (i = 0; i < ud->ngroups; i++) {
	/* XXX - check rval */
	len = snprintf(cp, glsize - (cp - gid_list), "%s%u",
	    i ? "," : "", (unsigned int)ud->groups[i]);
	cp += len;
    }
    debug_return_str(gid_list);
}

/*
 * How to access the tty device number in struct kinfo_proc.
 */
#if defined(HAVE_STRUCT_KINFO_PROC_KP_EPROC_E_TDEV)
# define sudo_kp_tdev		kp_eproc.e_tdev
# define sudo_kp_namelen	4
#elif defined(HAVE_STRUCT_KINFO_PROC_KI_TDEV)
# define sudo_kp_tdev		ki_tdev
# define sudo_kp_namelen	4
#elif defined(HAVE_STRUCT_KINFO_PROC_P_TDEV)
# define sudo_kp_tdev		p_tdev
# define sudo_kp_namelen	6
#endif

#ifdef sudo_kp_tdev
/*
 * Return a string from ttyname() containing the tty to which the process is
 * attached or NULL if there is no tty associated with the process (or its
 * parent).  First tries sysctl using the current pid, then the parent's pid.
 * Falls back on ttyname of std{in,out,err} if that fails.
 */
static char *
get_process_tty(void)
{
    char *tty = NULL;
    struct kinfo_proc *ki_proc = NULL;
    size_t size = sizeof(*ki_proc);
    int i, mib[6], rc;
    debug_decl(get_process_tty, SUDO_DEBUG_UTIL)

    /*
     * Lookup tty for this process and, failing that, our parent.
     * Even if we redirect std{in,out,err} the kernel should still know.
     */
    for (i = 0; tty == NULL && i < 2; i++) {
	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = i ? (int)getppid() : (int)getpid();
	mib[4] = sizeof(*ki_proc);
	mib[5] = 1;
	do {
	    size += size / 10;
	    ki_proc = erealloc(ki_proc, size);
	    rc = sysctl(mib, sudo_kp_namelen, ki_proc, &size, NULL, 0);
	} while (rc == -1 && errno == ENOMEM);
	if (rc != -1) {
	    tty = devname(ki_proc->sudo_kp_tdev, S_IFCHR);
	    if (*tty != '/') {
		sudo_debug_printf(SUDO_DEBUG_WARN,
		    "unable to map device number %u to name: %s",
		    ki_proc->sudo_kp_tdev, tty);
		tty = NULL;
	    }
	} else {
	    sudo_debug_printf(SUDO_DEBUG_WARN,
		"unable to resolve tty via KERN_PROC: %s", strerror(errno));
	}
    }

    /* If all else fails, fall back on ttyname(). */
    if (tty == NULL) {
	if ((tty = ttyname(STDIN_FILENO)) == NULL &&
	    (tty = ttyname(STDOUT_FILENO)) == NULL)
	    tty = ttyname(STDERR_FILENO);
    }

    debug_return_str(tty);
}
#else
/*
 * Return a string from ttyname() containing the tty to which the process is
 * attached or NULL if there is no tty associated with the process (or its
 * parent).  First tries std{in,out,err} then falls back to the parent's /proc
 * entry.  We could try following the parent all the way to pid 1 but
 * /proc/%d/status is system-specific (text on Linux, a struct on Solaris).
 */
static char *
get_process_tty(void)
{
    char path[PATH_MAX], *tty = NULL;
    pid_t ppid;
    int i, fd;
    debug_decl(get_process_tty, SUDO_DEBUG_UTIL)

    if ((tty = ttyname(STDIN_FILENO)) == NULL &&
	(tty = ttyname(STDOUT_FILENO)) == NULL &&
	(tty = ttyname(STDERR_FILENO)) == NULL) {
	/* No tty for child, check the parent via /proc. */
	ppid = getppid();
	for (i = STDIN_FILENO; i < STDERR_FILENO && tty == NULL; i++) {
	    snprintf(path, sizeof(path), "/proc/%d/fd/%d", ppid, i);
	    fd = open(path, O_RDONLY|O_NOCTTY, 0);
	    if (fd != -1) {
		tty = ttyname(fd);
		close(fd);
	    }
	}
    }

    debug_return_str(tty);
}
#endif /* sudo_kp_tdev */

/*
 * Return user information as an array of name=value pairs.
 * and fill in struct user_details (which shares the same strings).
 */
static char **
get_user_info(struct user_details *ud)
{
    char *cp, **user_info, cwd[PATH_MAX], host[MAXHOSTNAMELEN];
    struct passwd *pw;
    int i = 0;
    debug_decl(get_user_info, SUDO_DEBUG_UTIL)

    /* XXX - bound check number of entries */
    user_info = emalloc2(32, sizeof(char *));

    ud->uid = getuid();
    ud->euid = geteuid();
    ud->gid = getgid();
    ud->egid = getegid();

    pw = getpwuid(ud->uid);
    if (pw == NULL)
	errorx(1, _("unknown uid %u: who are you?"), (unsigned int)ud->uid);

    user_info[i] = fmt_string("user", pw->pw_name);
    if (user_info[i] == NULL)
	errorx(1, _("unable to allocate memory"));
    ud->username = user_info[i] + sizeof("user=") - 1;

    /* Stash user's shell for use with the -s flag; don't pass to plugin. */
    if ((ud->shell = getenv("SHELL")) == NULL || ud->shell[0] == '\0') {
	ud->shell = pw->pw_shell[0] ? pw->pw_shell : _PATH_BSHELL;
    }
    ud->shell = estrdup(ud->shell);

    easprintf(&user_info[++i], "uid=%u", (unsigned int)ud->uid);
    easprintf(&user_info[++i], "euid=%u", (unsigned int)ud->euid);
    easprintf(&user_info[++i], "gid=%u", (unsigned int)ud->gid);
    easprintf(&user_info[++i], "egid=%u", (unsigned int)ud->egid);

    if ((cp = get_user_groups(ud)) != NULL)
	user_info[++i] = cp;

    if (getcwd(cwd, sizeof(cwd)) != NULL) {
	user_info[++i] = fmt_string("cwd", cwd);
	if (user_info[i] == NULL)
	    errorx(1, _("unable to allocate memory"));
	ud->cwd = user_info[i] + sizeof("cwd=") - 1;
    }

    if ((cp = get_process_tty()) != NULL) {
	user_info[++i] = fmt_string("tty", cp);
	if (user_info[i] == NULL)
	    errorx(1, _("unable to allocate memory"));
	ud->tty = user_info[i] + sizeof("tty=") - 1;
    }

    if (gethostname(host, sizeof(host)) == 0)
	host[sizeof(host) - 1] = '\0';
    else
	strlcpy(host, "localhost", sizeof(host));
    user_info[++i] = fmt_string("host", host);
    if (user_info[i] == NULL)
	errorx(1, _("unable to allocate memory"));
    ud->host = user_info[i] + sizeof("host=") - 1;

    get_ttysize(&ud->ts_lines, &ud->ts_cols);
    easprintf(&user_info[++i], "lines=%d", ud->ts_lines);
    easprintf(&user_info[++i], "cols=%d", ud->ts_cols);

    user_info[++i] = NULL;

    debug_return_ptr(user_info);
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
    debug_decl(command_info_to_details, SUDO_DEBUG_PCOMM)

    memset(details, 0, sizeof(*details));
    details->closefrom = -1;

#define SET_STRING(s, n) \
    if (strncmp(s, info[i], sizeof(s) - 1) == 0 && info[i][sizeof(s) - 1]) { \
	details->n = info[i] + sizeof(s) - 1; \
	break; \
    }

    sudo_debug_printf(SUDO_DEBUG_INFO, "command info from plugin:");
    for (i = 0; info[i] != NULL; i++) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "    %d: %s", i, info[i]);
	switch (info[i][0]) {
	    case 'c':
		SET_STRING("chroot=", chroot)
		SET_STRING("command=", command)
		SET_STRING("cwd=", cwd)
		if (strncmp("closefrom=", info[i], sizeof("closefrom=") - 1) == 0) {
		    cp = info[i] + sizeof("closefrom=") - 1;
		    if (*cp == '\0')
			break;
		    errno = 0;
		    lval = strtol(cp, &ep, 0);
		    if (*cp != '\0' && *ep == '\0' &&
			!(errno == ERANGE &&
			(lval == LONG_MAX || lval == LONG_MIN)) &&
			lval < INT_MAX && lval > INT_MIN) {
			details->closefrom = (int)lval;
		    }
		    break;
		}
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
		    if (atobool(info[i] + sizeof("noexec=") - 1) == true)
			SET(details->flags, CD_NOEXEC);
		    break;
		}
		break;
	    case 'p':
		if (strncmp("preserve_groups=", info[i], sizeof("preserve_groups=") - 1) == 0) {
		    if (atobool(info[i] + sizeof("preserve_groups=") - 1) == true)
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
		    if (details->ngroups != 0) {
			details->groups =
			    emalloc2(details->ngroups, sizeof(GETGROUPS_T));
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
		    }
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
		if (strncmp("set_utmp=", info[i], sizeof("set_utmp=") - 1) == 0) {
		    if (atobool(info[i] + sizeof("set_utmp=") - 1) == true)
			SET(details->flags, CD_SET_UTMP);
		    break;
		}
		if (strncmp("sudoedit=", info[i], sizeof("sudoedit=") - 1) == 0) {
		    if (atobool(info[i] + sizeof("sudoedit=") - 1) == true)
			SET(details->flags, CD_SUDOEDIT);
		    break;
		}
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
		    break;
		}
		if (strncmp("use_pty=", info[i], sizeof("use_pty=") - 1) == 0) {
		    if (atobool(info[i] + sizeof("use_pty=") - 1) == true)
			SET(details->flags, CD_USE_PTY);
		    break;
		}
		SET_STRING("utmp_user=", utmp_user)
		break;
	}
    }

    if (!ISSET(details->flags, CD_SET_EUID))
	details->euid = details->uid;

#ifdef HAVE_SELINUX
    if (details->selinux_role != NULL && is_selinux_enabled() > 0)
	SET(details->flags, CD_RBAC_ENABLED);
#endif
    debug_return;
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
    debug_decl(disable_coredumps, SUDO_DEBUG_UTIL)

#if defined(__linux__)
    /*
     * Unlimit the number of processes since Linux's setuid() will
     * apply resource limits when changing uid and return EAGAIN if
     * nproc would be violated by the uid switch.
     */
    (void) getrlimit(RLIMIT_NPROC, &nproclimit);
    rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_NPROC, &rl)) {
	memcpy(&rl, &nproclimit, sizeof(struct rlimit));
	rl.rlim_cur = rl.rlim_max;
	(void)setrlimit(RLIMIT_NPROC, &rl);
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
    debug_return;
}

#ifdef HAVE_PROJECT_H
static void
set_project(struct passwd *pw)
{
    struct project proj;
    char buf[PROJECT_BUFSZ];
    int errval;
    debug_decl(set_project, SUDO_DEBUG_UTIL)

    /*
     * Collect the default project for the user and settaskid
     */
    setprojent();
    if (getdefaultproj(pw->pw_name, &proj, buf, sizeof(buf)) != NULL) {
	errval = setproject(proj.pj_name, pw->pw_name, TASK_NORMAL);
	switch(errval) {
	case 0:
	    break;
	case SETPROJ_ERR_TASK:
	    switch (errno) {
	    case EAGAIN:
		warningx(_("resource control limit has been reached"));
		break;
	    case ESRCH:
		warningx(_("user \"%s\" is not a member of project \"%s\""),
		    pw->pw_name, proj.pj_name);
		break;
	    case EACCES:
		warningx(_("the invoking task is final"));
		break;
	    default:
		warningx(_("could not join project \"%s\""), proj.pj_name);
	    }
	case SETPROJ_ERR_POOL:
	    switch (errno) {
	    case EACCES:
		warningx(_("no resource pool accepting default bindings "
		    "exists for project \"%s\""), proj.pj_name);
		break;
	    case ESRCH:
		warningx(_("specified resource pool does not exist for "
		    "project \"%s\""), proj.pj_name);
		break;
	    default:
		warningx(_("could not bind to default resource pool for "
		    "project \"%s\""), proj.pj_name);
	    }
	    break;
	default:
	    if (errval <= 0) {
		warningx(_("setproject failed for project \"%s\""), proj.pj_name);
	    } else {
		warningx(_("warning, resource control assignment failed for "
		    "project \"%s\""), proj.pj_name);
	    }
	}
    } else {
	warning("getdefaultproj");
    }
    endprojent();
    debug_return;
}
#endif /* HAVE_PROJECT_H */

/*
 * Disable execution of child processes in the command we are about
 * to run.  On systems with privilege sets, we can remove the exec
 * privilege.  On other systems we use LD_PRELOAD and the like.
 */
static void
disable_execute(struct command_details *details)
{
#ifdef _PATH_SUDO_NOEXEC
    char *cp, **ev, **nenvp;
    int env_len = 0, env_size = 128;
#endif /* _PATH_SUDO_NOEXEC */
    debug_decl(disable_execute, SUDO_DEBUG_UTIL)

#ifdef HAVE_PRIV_SET
    /* Solaris privileges, remove PRIV_PROC_EXEC post-execve. */
    if (priv_set(PRIV_OFF, PRIV_LIMIT, "PRIV_PROC_EXEC", NULL) == 0)
	debug_return;
    warning(_("unable to remove PRIV_PROC_EXEC from PRIV_LIMIT"));
#endif /* HAVE_PRIV_SET */

#ifdef _PATH_SUDO_NOEXEC
    nenvp = emalloc2(env_size, sizeof(char *));
    for (ev = details->envp; *ev != NULL; ev++) {
	if (env_len + 2 > env_size) {
	    env_size += 128;
	    nenvp = erealloc3(nenvp, env_size, sizeof(char *));
	}
	/*
	 * Prune out existing preloaded libraries.
	 * XXX - should save and append instead of replacing.
	 */
# if defined(__darwin__) || defined(__APPLE__)
	if (strncmp(*ev, "DYLD_INSERT_LIBRARIES=", sizeof("DYLD_INSERT_LIBRARIES=") - 1) == 0)
	    continue;
	if (strncmp(*ev, "DYLD_FORCE_FLAT_NAMESPACE=", sizeof("DYLD_INSERT_LIBRARIES=") - 1) == 0)
	    continue;
# elif defined(__osf__) || defined(__sgi)
	if (strncmp(*ev, "_RLD_LIST=", sizeof("_RLD_LIST=") - 1) == 0)
	    continue;
# elif defined(_AIX)
	if (strncmp(*ev, "LDR_PRELOAD=", sizeof("LDR_PRELOAD=") - 1) == 0)
	    continue;
# else
	if (strncmp(*ev, "LD_PRELOAD=", sizeof("LD_PRELOAD=") - 1) == 0)
	    continue;
# endif
	nenvp[env_len++] = *ev;
    }

    /*
     * Preload a noexec file?  For a list of LD_PRELOAD-alikes, see
     * http://www.fortran-2000.com/ArnaudRecipes/sharedlib.html
     * XXX - need to support 32-bit and 64-bit variants
     */
# if defined(__darwin__) || defined(__APPLE__)
    nenvp[env_len++] = "DYLD_FORCE_FLAT_NAMESPACE=";
    cp = fmt_string("DYLD_INSERT_LIBRARIES", sudo_conf_noexec_path());
# elif defined(__osf__) || defined(__sgi)
    easprintf(&cp, "_RLD_LIST=%s:DEFAULT", sudo_conf_noexec_path());
# elif defined(_AIX)
    cp = fmt_string("LDR_PRELOAD", sudo_conf_noexec_path());
# else
    cp = fmt_string("LD_PRELOAD", sudo_conf_noexec_path());
# endif
    if (cp == NULL)
	errorx(1, _("unable to allocate memory"));
    nenvp[env_len++] = cp;
    nenvp[env_len] = NULL;

    details->envp = nenvp;
#endif /* _PATH_SUDO_NOEXEC */
    debug_return;
}

/*
 * Setup the execution environment immediately prior to the call to execve()
 * Returns true on success and false on failure.
 */
bool
exec_setup(struct command_details *details, const char *ptyname, int ptyfd)
{
    bool rval = false;
    struct passwd *pw;
    debug_decl(exec_setup, SUDO_DEBUG_EXEC)

#ifdef HAVE_SETAUTHDB
    aix_setauthdb(IDtouser(details->euid));
#endif
    pw = getpwuid(details->euid);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif

    /*
     * Call policy plugin's session init before other setup occurs.
     * The session init code is expected to print an error as needed.
     */
    if (policy_init_session(&policy_plugin, pw) != true)
	goto done;

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	if (selinux_setup(details->selinux_role, details->selinux_type,
	    ptyname ? ptyname : user_details.tty, ptyfd) == -1)
	    goto done;
    }
#endif

    if (pw != NULL) {
#ifdef HAVE_PROJECT_H
	set_project(pw);
#endif
#ifdef HAVE_GETUSERATTR
	aix_prep_user(pw->pw_name, ptyname ? ptyname : user_details.tty);
#endif
#ifdef HAVE_LOGIN_CAP_H
	if (details->login_class) {
	    int flags;
	    login_cap_t *lc;

	    /*
	     * We only use setusercontext() to set the nice value and rlimits
	     * unless this is a login shell (sudo -i).
	     */
	    lc = login_getclass((char *)details->login_class);
	    if (!lc) {
		warningx(_("unknown login class %s"), details->login_class);
		errno = ENOENT;
		goto done;
	    }
	    if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
		/* Set everything except user, group and login name. */
		flags = LOGIN_SETALL;
		CLR(flags, LOGIN_SETGROUP|LOGIN_SETLOGIN|LOGIN_SETUSER);
		CLR(details->flags, CD_SET_UMASK); /* LOGIN_UMASK instead */
		/* Swap in the plugin-supplied environment for LOGIN_SETENV */
		environ = details->envp;
	    } else {
		flags = LOGIN_SETRESOURCES|LOGIN_SETPRIORITY;
	    }
	    if (setusercontext(lc, pw, pw->pw_uid, flags)) {
		if (pw->pw_uid != ROOT_UID) {
		    warning(_("unable to set user context"));
		    goto done;
		} else
		    warning(_("unable to set user context"));
	    }
	    if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
		/* Stash the updated environment pointer in command details */
		details->envp = environ;
	    }
	}
#endif /* HAVE_LOGIN_CAP_H */
    }

    /*
     * Set groups, including supplementary group vector.
     */
#ifdef HAVE_SETEUID
    if (ISSET(details->flags, CD_SET_EGID) && setegid(details->egid)) {
	warning(_("unable to set effective gid to runas gid %u"),
	    (unsigned int)details->egid);
	goto done;
    }
#endif
    if (ISSET(details->flags, CD_SET_GID) && setgid(details->gid)) {
	warning(_("unable to set gid to runas gid %u"),
	    (unsigned int)details->gid);
	goto done;
    }

    if (!ISSET(details->flags, CD_PRESERVE_GROUPS)) {
	if (details->ngroups >= 0) {
	    if (sudo_setgroups(details->ngroups, details->groups) < 0) {
		warning(_("unable to set supplementary group IDs"));
		goto done;
	    }
	}
    }

    if (ISSET(details->flags, CD_SET_PRIORITY)) {
	if (setpriority(PRIO_PROCESS, 0, details->priority) != 0) {
	    warning(_("unable to set process priority"));
	    goto done;
	}
    }
    if (ISSET(details->flags, CD_SET_UMASK))
	(void) umask(details->umask);
    if (details->chroot) {
	if (chroot(details->chroot) != 0 || chdir("/") != 0) {
	    warning(_("unable to change root to %s"), details->chroot);
	    goto done;
	}
    }

    if (ISSET(details->flags, CD_NOEXEC))
	disable_execute(details);

#ifdef HAVE_SETRESUID
    if (setresuid(details->uid, details->euid, details->euid) != 0) {
	warning(_("unable to change to runas uid (%u, %u)"), details->uid,
	    details->euid);
	goto done;
    }
#elif HAVE_SETREUID
    if (setreuid(details->uid, details->euid) != 0) {
	warning(_("unable to change to runas uid (%u, %u)"),
	    (unsigned int)details->uid, (unsigned int)details->euid);
	goto done;
    }
#else
    if (seteuid(details->euid) != 0 || setuid(details->euid) != 0) {
	warning(_("unable to change to runas uid (%u, %u)"), details->uid,
	    details->euid);
	goto done;
    }
#endif /* !HAVE_SETRESUID && !HAVE_SETREUID */

    /*
     * Only change cwd if we have chroot()ed or the policy modules
     * specifies a different cwd.  Must be done after uid change.
     */
    if (details->cwd) {
	if (details->chroot || strcmp(details->cwd, user_details.cwd) != 0) {
	    /* Note: cwd is relative to the new root, if any. */
	    if (chdir(details->cwd) != 0) {
		warning(_("unable to change directory to %s"), details->cwd);
		goto done;
	    }
	}
    }

    /*
     * Restore nproc resource limit if pam_limits didn't do it for us.
     * We must do this *after* the uid change to avoid potential EAGAIN
     * from setuid().
     */
#if defined(__linux__)
    {
	struct rlimit rl;
	if (getrlimit(RLIMIT_NPROC, &rl) == 0) {
	    if (rl.rlim_cur == RLIM_INFINITY && rl.rlim_max == RLIM_INFINITY)
		(void) setrlimit(RLIMIT_NPROC, &nproclimit);
	}
    }
#endif

    rval = true;

done:
    debug_return_bool(rval);
}

/*
 * Run the command and wait for it to complete.
 */
int
run_command(struct command_details *details)
{
    struct plugin_container *plugin;
    struct command_status cstat;
    int exitcode = 1;
    debug_decl(run_command, SUDO_DEBUG_EXEC)

    cstat.type = CMD_INVALID;
    cstat.val = 0;

    sudo_execve(details, &cstat);

    switch (cstat.type) {
    case CMD_ERRNO:
	/* exec_setup() or execve() returned an error. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "calling policy close with errno");
	policy_close(&policy_plugin, 0, cstat.val);
	tq_foreach_fwd(&io_plugins, plugin) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG, "calling I/O close with errno");
	    iolog_close(plugin, 0, cstat.val);
	}
	exitcode = 1;
	break;
    case CMD_WSTATUS:
	/* Command ran, exited or was killed. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "calling policy close with wait status");
	policy_close(&policy_plugin, cstat.val, 0);
	tq_foreach_fwd(&io_plugins, plugin) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG,
		"calling I/O close with wait status");
	    iolog_close(plugin, cstat.val, 0);
	}
	if (WIFEXITED(cstat.val))
	    exitcode = WEXITSTATUS(cstat.val);
	else if (WIFSIGNALED(cstat.val))
	    exitcode = WTERMSIG(cstat.val) | 128;
	break;
    default:
	warningx(_("unexpected child termination condition: %d"), cstat.type);
	break;
    }
    debug_return_int(exitcode);
}

static int
policy_open(struct plugin_container *plugin, char * const settings[],
    char * const user_info[], char * const user_env[])
{
    debug_decl(policy_open, SUDO_DEBUG_PCOMM)
    debug_return_bool(plugin->u.policy->open(SUDO_API_VERSION,
	sudo_conversation, _sudo_printf, settings, user_info, user_env));
}

static void
policy_close(struct plugin_container *plugin, int exit_status, int error)
{
    debug_decl(policy_close, SUDO_DEBUG_PCOMM)
    plugin->u.policy->close(exit_status, error);
    debug_return;
}

static int
policy_show_version(struct plugin_container *plugin, int verbose)
{
    debug_decl(policy_show_version, SUDO_DEBUG_PCOMM)
    debug_return_bool(plugin->u.policy->show_version(verbose));
}

static int
policy_check(struct plugin_container *plugin, int argc, char * const argv[],
    char *env_add[], char **command_info[], char **argv_out[],
    char **user_env_out[])
{
    debug_decl(policy_check, SUDO_DEBUG_PCOMM)
    debug_return_bool(plugin->u.policy->check_policy(argc, argv, env_add,
	command_info, argv_out, user_env_out));
}

static int
policy_list(struct plugin_container *plugin, int argc, char * const argv[],
    int verbose, const char *list_user)
{
    debug_decl(policy_list, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->list == NULL) {
	warningx(_("policy plugin %s does not support listing privileges"),
	    plugin->name);
	debug_return_bool(false);
    }
    debug_return_bool(plugin->u.policy->list(argc, argv, verbose, list_user));
}

static int
policy_validate(struct plugin_container *plugin)
{
    debug_decl(policy_validate, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->validate == NULL) {
	warningx(_("policy plugin %s does not support the -v option"),
	    plugin->name);
	debug_return_bool(false);
    }
    debug_return_bool(plugin->u.policy->validate());
}

static void
policy_invalidate(struct plugin_container *plugin, int remove)
{
    debug_decl(policy_invalidate, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->invalidate == NULL) {
	errorx(1, _("policy plugin %s does not support the -k/-K options"),
	    plugin->name);
    }
    plugin->u.policy->invalidate(remove);
    debug_return;
}

static int
policy_init_session(struct plugin_container *plugin, struct passwd *pwd)
{
    debug_decl(policy_init_session, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->init_session)
	debug_return_bool(plugin->u.policy->init_session(pwd));
    debug_return_bool(true);
}

static int
iolog_open(struct plugin_container *plugin, char * const settings[],
    char * const user_info[], char * const command_info[],
    int argc, char * const argv[], char * const user_env[])
{
    int rval;
    debug_decl(iolog_open, SUDO_DEBUG_PCOMM)

    /*
     * Backwards compatibility for API major 1, minor 0
     */
    switch (plugin->u.generic->version) {
    case SUDO_API_MKVERSION(1, 0):
	rval = plugin->u.io_1_0->open(plugin->u.io_1_0->version,
	    sudo_conversation, _sudo_printf, settings, user_info, argc, argv,
	    user_env);
	break;
    default:
	rval = plugin->u.io->open(SUDO_API_VERSION, sudo_conversation,
	    _sudo_printf, settings, user_info, command_info, argc, argv,
	    user_env);
    }
    debug_return_bool(rval);
}

static void
iolog_close(struct plugin_container *plugin, int exit_status, int error)
{
    debug_decl(iolog_close, SUDO_DEBUG_PCOMM)
    plugin->u.io->close(exit_status, error);
    debug_return;
}

static int
iolog_show_version(struct plugin_container *plugin, int verbose)
{
    debug_decl(iolog_show_version, SUDO_DEBUG_PCOMM)
    debug_return_bool(plugin->u.io->show_version(verbose));
}
