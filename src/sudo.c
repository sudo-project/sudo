/*
 * Copyright (c) 2009-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
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
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
# ifndef LOGIN_SETENV
#  define LOGIN_SETENV	0
# endif
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

#include <sudo_usage.h>
#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

/*
 * Local variables
 */
struct plugin_container policy_plugin;
struct plugin_container_list io_plugins = TAILQ_HEAD_INITIALIZER(io_plugins);
struct user_details user_details;
const char *list_user; /* extern for parse_args.c */
static struct command_details command_details;
static int sudo_mode;

/*
 * Local functions
 */
static void fix_fds(void);
static void disable_coredumps(void);
static void sudo_check_suid(const char *path);
static char **get_user_info(struct user_details *);
static void command_info_to_details(char * const info[],
    struct command_details *details);

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

/* I/O log plugin convenience functions. */
static int iolog_open(struct plugin_container *plugin, char * const settings[],
    char * const user_info[], char * const command_details[],
    int argc, char * const argv[], char * const user_env[]);
static void iolog_close(struct plugin_container *plugin, int exit_status,
    int error);
static int iolog_show_version(struct plugin_container *plugin, int verbose);
static void iolog_unlink(struct plugin_container *plugin);

#ifdef RLIMIT_CORE
static struct rlimit corelimit;
#endif
#ifdef __linux__
static struct rlimit nproclimit;
#endif

__dso_public int main(int argc, char *argv[], char *envp[]);

int
main(int argc, char *argv[], char *envp[])
{
    int nargc, ok, exitcode = 0;
    char **nargv, **settings, **env_add;
    char **user_info, **command_info, **argv_out, **user_env_out;
    struct plugin_container *plugin, *next;
    sigset_t mask;
    debug_decl(main, SUDO_DEBUG_MAIN)

    os_init(argc, argv, envp);

    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE_NAME, LOCALEDIR);
    textdomain(PACKAGE_NAME);

#ifdef HAVE_TZSET
    (void) tzset();
#endif /* HAVE_TZSET */

    /* Must be done before we do any password lookups */
#if defined(HAVE_GETPRPWNAM) && defined(HAVE_SET_AUTH_PARAMETERS)
    (void) set_auth_parameters(argc, argv);
# ifdef HAVE_INITPRIVS
    initprivs();
# endif
#endif /* HAVE_GETPRPWNAM && HAVE_SET_AUTH_PARAMETERS */

    /* Make sure we are setuid root. */
    sudo_check_suid(argv[0]);

    /* Reset signal mask, save signal state and make sure fds 0-2 are open. */
    (void) sigemptyset(&mask);
    (void) sigprocmask(SIG_SETMASK, &mask, NULL);
    save_signals();
    fix_fds();

    /* Read sudo.conf. */
    sudo_conf_read(NULL);

    /* Fill in user_info with user name, uid, cwd, etc. */
    memset(&user_details, 0, sizeof(user_details));
    user_info = get_user_info(&user_details);

    /* Disable core dumps if not enabled in sudo.conf. */
    disable_coredumps();

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
	fatalx(U_("fatal error, unable to load plugins"));

    /* Open policy plugin. */
    ok = policy_open(&policy_plugin, settings, user_info, envp);
    if (ok != 1) {
	if (ok == -2)
	    usage(1);
	else
	    fatalx(U_("unable to initialize policy plugin"));
    }

    init_signals();

    switch (sudo_mode & MODE_MASK) {
	case MODE_VERSION:
	    policy_show_version(&policy_plugin, !user_details.uid);
	    TAILQ_FOREACH(plugin, &io_plugins, entries) {
		ok = iolog_open(plugin, settings, user_info, NULL,
		    nargc, nargv, envp);
		if (ok != -1)
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
	    TAILQ_FOREACH_SAFE(plugin, &io_plugins, entries, next) {
		ok = iolog_open(plugin, settings, user_info,
		    command_info, nargc, nargv, envp);
		switch (ok) {
		case 1:
		    break;
		case 0:
		    /* I/O plugin asked to be disabled, remove and free. */
		    iolog_unlink(plugin);
		    break;
		case -2:
		    usage(1);
		    break;
		default:
		    fatalx(U_("error initializing I/O plugin %s"),
			plugin->name);
		}
	    }
	    /* Setup command details and run command/edit. */
	    command_info_to_details(command_info, &command_details);
	    command_details.argv = argv_out;
	    command_details.envp = user_env_out;
	    if (ISSET(sudo_mode, MODE_BACKGROUND))
		SET(command_details.flags, CD_BACKGROUND);
	    /* Become full root (not just setuid) so user cannot kill us. */
	    if (setuid(ROOT_UID) == -1)
		warning("setuid(%d)", ROOT_UID);
	    /* Restore coredumpsize resource limit before running. */
#ifdef RLIMIT_CORE
	    if (sudo_conf_disable_coredump())
		(void) setrlimit(RLIMIT_CORE, &corelimit);
#endif /* RLIMIT_CORE */
	    if (ISSET(command_details.flags, CD_SUDOEDIT)) {
		exitcode = sudo_edit(&command_details);
	    } else {
		exitcode = run_command(&command_details);
	    }
	    /* The close method was called by sudo_edit/run_command. */
	    break;
	default:
	    fatalx(U_("unexpected sudo mode 0x%x"), sudo_mode);
    }
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);                
    exit(exitcode);
}

int
os_init_common(int argc, char *argv[], char *envp[])
{
    initprogname(argc > 0 ? argv[0] : "sudo");
#ifdef STATIC_SUDOERS_PLUGIN
    preload_static_symbols();
#endif
    return 0;
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
	    fatal(U_("unable to open %s"), _PATH_DEVNULL);
	if (miss[STDIN_FILENO] && dup2(devnull, STDIN_FILENO) == -1)
	    fatal("dup2");
	if (miss[STDOUT_FILENO] && dup2(devnull, STDOUT_FILENO) == -1)
	    fatal("dup2");
	if (miss[STDERR_FILENO] && dup2(devnull, STDERR_FILENO) == -1)
	    fatal("dup2");
	if (devnull > STDERR_FILENO)
	    close(devnull);
    }
    debug_return;
}

/*
 * Allocate space for groups and fill in using getgrouplist()
 * for when we cannot (or don't want to) use getgroups().
 */
static int
fill_group_list(struct user_details *ud, int system_maxgroups)
{
    int tries, rval = -1;
    debug_decl(fill_group_list, SUDO_DEBUG_UTIL)

    /*
     * If user specified a max number of groups, use it, otherwise keep
     * trying getgrouplist() until we have enough room in the array.
     */
    ud->ngroups = sudo_conf_max_groups();
    if (ud->ngroups > 0) {
	ud->groups = emalloc2(ud->ngroups, sizeof(GETGROUPS_T));
	/* No error on insufficient space if user specified max_groups. */
	(void)getgrouplist(ud->username, ud->gid, ud->groups, &ud->ngroups);
	rval = 0;
    } else {
	/*
	 * It is possible to belong to more groups in the group database
	 * than NGROUPS_MAX.  We start off with NGROUPS_MAX * 4 entries
	 * and double this as needed.
	 */
	ud->groups = NULL;
	ud->ngroups = system_maxgroups << 1;
	for (tries = 0; tries < 10 && rval == -1; tries++) {
	    ud->ngroups <<= 1;
	    efree(ud->groups);
	    ud->groups = emalloc2(ud->ngroups, sizeof(GETGROUPS_T));
	    rval = getgrouplist(ud->username, ud->gid, ud->groups, &ud->ngroups);
	}
    }
    debug_return_int(rval);
}

static char *
get_user_groups(struct user_details *ud)
{
    char *cp, *gid_list = NULL;
    size_t glsize;
    int i, len, maxgroups, group_source;
    debug_decl(get_user_groups, SUDO_DEBUG_UTIL)

#if defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
    maxgroups = (int)sysconf(_SC_NGROUPS_MAX);
    if (maxgroups < 0)
#endif
	maxgroups = NGROUPS_MAX;

    ud->groups = NULL;
    group_source = sudo_conf_group_source();
    if (group_source != GROUP_SOURCE_DYNAMIC) {
	if ((ud->ngroups = getgroups(0, NULL)) > 0) {
	    /* Use groups from kernel if not too many or source is static. */
	    if (ud->ngroups < maxgroups || group_source == GROUP_SOURCE_STATIC) {
		ud->groups = emalloc2(ud->ngroups, sizeof(GETGROUPS_T));
		if (getgroups(ud->ngroups, ud->groups) < 0) {
		    efree(ud->groups);
		    ud->groups = NULL;
		}
	    }
	}
    }
    if (ud->groups == NULL) {
	/*
	 * Query group database if kernel list is too small or disabled.
	 * Typically, this is because NFS can only support up to 16 groups.
	 */
	if (fill_group_list(ud, maxgroups) == -1)
	    fatal(U_("unable to get group vector"));
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
 * Return user information as an array of name=value pairs.
 * and fill in struct user_details (which shares the same strings).
 */
static char **
get_user_info(struct user_details *ud)
{
    char *cp, **user_info, cwd[PATH_MAX], host[HOST_NAME_MAX + 1];
    struct passwd *pw;
    int fd, i = 0;
    debug_decl(get_user_info, SUDO_DEBUG_UTIL)

    /* XXX - bound check number of entries */
    user_info = emalloc2(32, sizeof(char *));

    ud->pid = getpid();
    ud->ppid = getppid();
    ud->pgid = getpgid(0);
    ud->tcpgid = (pid_t)-1;
    fd = open(_PATH_TTY, O_RDWR|O_NOCTTY|O_NONBLOCK, 0);
    if (fd != -1) {
	ud->tcpgid = tcgetpgrp(fd);
	close(fd);
    }
    ud->sid = getsid(0);

    ud->uid = getuid();
    ud->euid = geteuid();
    ud->gid = getgid();
    ud->egid = getegid();

    pw = getpwuid(ud->uid);
    if (pw == NULL)
	fatalx(U_("unknown uid %u: who are you?"), (unsigned int)ud->uid);

    user_info[i] = fmt_string("user", pw->pw_name);
    if (user_info[i] == NULL)
	fatal(NULL);
    ud->username = user_info[i] + sizeof("user=") - 1;

    /* Stash user's shell for use with the -s flag; don't pass to plugin. */
    if ((ud->shell = getenv("SHELL")) == NULL || ud->shell[0] == '\0') {
	ud->shell = pw->pw_shell[0] ? pw->pw_shell : _PATH_BSHELL;
    }
    ud->shell = estrdup(ud->shell);

    easprintf(&user_info[++i], "pid=%d", (int)ud->pid);
    easprintf(&user_info[++i], "ppid=%d", (int)ud->ppid);
    easprintf(&user_info[++i], "pgid=%d", (int)ud->pgid);
    easprintf(&user_info[++i], "tcpgid=%d", (int)ud->tcpgid);
    easprintf(&user_info[++i], "sid=%d", (int)ud->sid);

    easprintf(&user_info[++i], "uid=%u", (unsigned int)ud->uid);
    easprintf(&user_info[++i], "euid=%u", (unsigned int)ud->euid);
    easprintf(&user_info[++i], "gid=%u", (unsigned int)ud->gid);
    easprintf(&user_info[++i], "egid=%u", (unsigned int)ud->egid);

    if ((cp = get_user_groups(ud)) != NULL)
	user_info[++i] = cp;

    if (getcwd(cwd, sizeof(cwd)) != NULL) {
	user_info[++i] = fmt_string("cwd", cwd);
	if (user_info[i] == NULL)
	    fatal(NULL);
	ud->cwd = user_info[i] + sizeof("cwd=") - 1;
    }

    if ((cp = get_process_ttyname()) != NULL) {
	user_info[++i] = fmt_string("tty", cp);
	if (user_info[i] == NULL)
	    fatal(NULL);
	ud->tty = user_info[i] + sizeof("tty=") - 1;
	efree(cp);
    }

    if (gethostname(host, sizeof(host)) == 0)
	host[sizeof(host) - 1] = '\0';
    else
	strlcpy(host, "localhost", sizeof(host));
    user_info[++i] = fmt_string("host", host);
    if (user_info[i] == NULL)
	fatal(NULL);
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
    id_t id;
    char *cp;
    const char *errstr;
    debug_decl(command_info_to_details, SUDO_DEBUG_PCOMM)

    memset(details, 0, sizeof(*details));
    details->closefrom = -1;
    TAILQ_INIT(&details->preserved_fds);

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
		    details->closefrom = strtonum(cp, 0, INT_MAX, &errstr);
		    if (errstr != NULL)
			fatalx(U_("%s: %s"), info[i], U_(errstr));
		    break;
		}
		break;
	    case 'e':
		if (strncmp("exec_background=", info[i], sizeof("exec_background=") - 1) == 0) {
		    if (atobool(info[i] + sizeof("exec_background=") - 1) == true)
			SET(details->flags, CD_EXEC_BG);
		    break;
		}
		break;
	    case 'l':
		SET_STRING("login_class=", login_class)
		break;
	    case 'n':
		if (strncmp("nice=", info[i], sizeof("nice=") - 1) == 0) {
		    cp = info[i] + sizeof("nice=") - 1;
		    details->priority = strtonum(cp, INT_MIN, INT_MAX, &errstr);
		    if (errstr != NULL)
			fatalx(U_("%s: %s"), info[i], U_(errstr));
		    SET(details->flags, CD_SET_PRIORITY);
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
		if (strncmp("preserve_fds=", info[i], sizeof("preserve_fds=") - 1) == 0) {
		    parse_preserved_fds(&details->preserved_fds,
			info[i] + sizeof("preserve_fds=") - 1);
		    break;
		}
		break;
	    case 'r':
		if (strncmp("runas_egid=", info[i], sizeof("runas_egid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_egid=") - 1;
		    id = atoid(cp, NULL, NULL, &errstr);
		    if (errstr != NULL)
			fatalx(U_("%s: %s"), info[i], U_(errstr));
		    details->egid = (gid_t)id;
		    SET(details->flags, CD_SET_EGID);
		    break;
		}
		if (strncmp("runas_euid=", info[i], sizeof("runas_euid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_euid=") - 1;
		    id = atoid(cp, NULL, NULL, &errstr);
		    if (errstr != NULL)
			fatalx(U_("%s: %s"), info[i], U_(errstr));
		    details->euid = (uid_t)id;
		    SET(details->flags, CD_SET_EUID);
		    break;
		}
		if (strncmp("runas_gid=", info[i], sizeof("runas_gid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_gid=") - 1;
		    id = atoid(cp, NULL, NULL, &errstr);
		    if (errstr != NULL)
			fatalx(U_("%s: %s"), info[i], U_(errstr));
		    details->gid = (gid_t)id;
		    SET(details->flags, CD_SET_GID);
		    break;
		}
		if (strncmp("runas_groups=", info[i], sizeof("runas_groups=") - 1) == 0) {
		    /* parse_gid_list() will call fatalx() on error. */
		    cp = info[i] + sizeof("runas_groups=") - 1;
		    details->ngroups = parse_gid_list(cp, NULL, &details->groups);
		    break;
		}
		if (strncmp("runas_uid=", info[i], sizeof("runas_uid=") - 1) == 0) {
		    cp = info[i] + sizeof("runas_uid=") - 1;
		    id = atoid(cp, NULL, NULL, &errstr);
		    if (errstr != NULL)
			fatalx(U_("%s: %s"), info[i], U_(errstr));
		    details->uid = (uid_t)id;
		    SET(details->flags, CD_SET_UID);
		    break;
		}
#ifdef HAVE_PRIV_SET
		if (strncmp("runas_privs=", info[i], sizeof("runas_privs=") - 1) == 0) {
                    const char *endp;
		    cp = info[i] + sizeof("runas_privs=") - 1;
	            if (*cp != '\0') {
			details->privs = priv_str_to_set(cp, ",", &endp);
			if (details->privs == NULL)
			    warning("invalid runas_privs %s", endp);
		    }
		    break;
		}
		if (strncmp("runas_limitprivs=", info[i], sizeof("runas_limitprivs=") - 1) == 0) {
                    const char *endp;
		    cp = info[i] + sizeof("runas_limitprivs=") - 1;
	            if (*cp != '\0') {
			details->limitprivs = priv_str_to_set(cp, ",", &endp);
			if (details->limitprivs == NULL)
			    warning("invalid runas_limitprivs %s", endp);
		    }
		    break;
		}
#endif /* HAVE_PRIV_SET */
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
		    details->timeout = strtonum(cp, 0, INT_MAX, &errstr);
		    if (errstr != NULL)
			fatalx(U_("%s: %s"), info[i], U_(errstr));
		    SET(details->flags, CD_SET_TIMEOUT);
		    break;
		}
		break;
	    case 'u':
		if (strncmp("umask=", info[i], sizeof("umask=") - 1) == 0) {
		    cp = info[i] + sizeof("umask=") - 1;
		    details->umask = atomode(cp, &errstr);
		    if (errstr != NULL)
			fatalx(U_("%s: %s"), info[i], U_(errstr));
		    SET(details->flags, CD_SET_UMASK);
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

#ifdef HAVE_SETAUTHDB
    aix_setauthdb(IDtouser(details->euid));
#endif
    details->pw = getpwuid(details->euid);
    if (details->pw != NULL && (details->pw = pw_dup(details->pw)) == NULL)
	fatal(NULL);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif

#ifdef HAVE_SELINUX
    if (details->selinux_role != NULL && is_selinux_enabled() > 0)
	SET(details->flags, CD_RBAC_ENABLED);
#endif
    debug_return;
}

static void
sudo_check_suid(const char *sudo)
{
    char pathbuf[PATH_MAX];
    struct stat sb;
    bool qualified;
    debug_decl(sudo_check_suid, SUDO_DEBUG_PCOMM)

    if (geteuid() != 0) {
	/* Search for sudo binary in PATH if not fully qualified. */
	qualified = strchr(sudo, '/') != NULL;
	if (!qualified) {
	    char *path = getenv_unhooked("PATH");
	    if (path != NULL) {
		int len;
		char *cp, *colon;

		cp = path = estrdup(path);
		do {
		    if ((colon = strchr(cp, ':')))
			*colon = '\0';
		    len = snprintf(pathbuf, sizeof(pathbuf), "%s/%s", cp, sudo);
		    if (len <= 0 || (size_t)len >= sizeof(pathbuf))
			continue;
		    if (access(pathbuf, X_OK) == 0) {
			sudo = pathbuf;
			qualified = true;
			break;
		    }
		    cp = colon + 1;
		} while (colon);
		efree(path);
	    }
	}

	if (qualified && stat(sudo, &sb) == 0) {
	    /* Try to determine why sudo was not running as root. */
	    if (sb.st_uid != ROOT_UID || !ISSET(sb.st_mode, S_ISUID)) {
		fatalx(
		    U_("%s must be owned by uid %d and have the setuid bit set"),
		    sudo, ROOT_UID);
	    } else {
		fatalx(U_("effective uid is not %d, is %s on a file system "
		    "with the 'nosuid' option set or an NFS file system without"
		    " root privileges?"), ROOT_UID, sudo);
	    }
	} else {
	    fatalx(
		U_("effective uid is not %d, is sudo installed setuid root?"),
		ROOT_UID);
	}
    }
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
#if defined(RLIMIT_CORE)
    struct rlimit rl;
    debug_decl(disable_coredumps, SUDO_DEBUG_UTIL)

    /*
     * Turn off core dumps?
     */
    if (sudo_conf_disable_coredump()) {
	(void) getrlimit(RLIMIT_CORE, &corelimit);
	memcpy(&rl, &corelimit, sizeof(struct rlimit));
	rl.rlim_cur = 0;
	(void) setrlimit(RLIMIT_CORE, &rl);
    }
    debug_return;
#endif /* RLIMIT_CORE */
}

/*
 * Unlimit the number of processes since Linux's setuid() will
 * apply resource limits when changing uid and return EAGAIN if
 * nproc would be exceeded by the uid switch.
 */
static void
unlimit_nproc(void)
{
#ifdef __linux__
    struct rlimit rl;
    debug_decl(unlimit_nproc, SUDO_DEBUG_UTIL)

    (void) getrlimit(RLIMIT_NPROC, &nproclimit);
    rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
	memcpy(&rl, &nproclimit, sizeof(struct rlimit));
	rl.rlim_cur = rl.rlim_max;
	(void)setrlimit(RLIMIT_NPROC, &rl);
    }
    debug_return;
#endif /* __linux__ */
}

/*
 * Restore saved value of RLIMIT_NPROC.
 */
static void
restore_nproc(void)
{
#ifdef __linux__
    debug_decl(restore_nproc, SUDO_DEBUG_UTIL)

    (void) setrlimit(RLIMIT_NPROC, &nproclimit);

    debug_return;
#endif /* __linux__ */
}

/*
 * Setup the execution environment immediately prior to the call to execve()
 * Returns true on success and false on failure.
 */
bool
exec_setup(struct command_details *details, const char *ptyname, int ptyfd)
{
    bool rval = false;
    debug_decl(exec_setup, SUDO_DEBUG_EXEC)

#ifdef HAVE_SELINUX
    if (ISSET(details->flags, CD_RBAC_ENABLED)) {
	if (selinux_setup(details->selinux_role, details->selinux_type,
	    ptyname ? ptyname : user_details.tty, ptyfd) == -1)
	    goto done;
    }
#endif

    if (details->pw != NULL) {
#ifdef HAVE_PROJECT_H
	set_project(details->pw);
#endif
#ifdef HAVE_PRIV_SET
	if (details->privs != NULL) {
	    if (setppriv(PRIV_SET, PRIV_INHERITABLE, details->privs) != 0) {
		warning("unable to set privileges");
		goto done;
	    }
	}
	if (details->limitprivs != NULL) {
	    if (setppriv(PRIV_SET, PRIV_LIMIT, details->limitprivs) != 0) {
		warning("unable to set limit privileges");
		goto done;
	    }
	} else if (details->privs != NULL) {
	    if (setppriv(PRIV_SET, PRIV_LIMIT, details->privs) != 0) {
		warning("unable to set limit privileges");
		goto done;
	    }
	}
#endif /* HAVE_PRIV_SET */

#ifdef HAVE_GETUSERATTR
	aix_prep_user(details->pw->pw_name, ptyname ? ptyname : user_details.tty);
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
		warningx(U_("unknown login class %s"), details->login_class);
		errno = ENOENT;
		goto done;
	    }
	    if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
		/* Set everything except user, group and login name. */
		flags = LOGIN_SETALL;
		CLR(flags, LOGIN_SETGROUP|LOGIN_SETLOGIN|LOGIN_SETUSER|LOGIN_SETENV|LOGIN_SETPATH);
		CLR(details->flags, CD_SET_UMASK); /* LOGIN_UMASK instead */
	    } else {
		flags = LOGIN_SETRESOURCES|LOGIN_SETPRIORITY;
	    }
	    if (setusercontext(lc, details->pw, details->pw->pw_uid, flags)) {
		warning(U_("unable to set user context"));
		if (details->pw->pw_uid != ROOT_UID)
		    goto done;
	    }
	}
#endif /* HAVE_LOGIN_CAP_H */
    }

    /*
     * Set groups, including supplementary group vector.
     */
    if (!ISSET(details->flags, CD_PRESERVE_GROUPS)) {
	if (details->ngroups >= 0) {
	    if (sudo_setgroups(details->ngroups, details->groups) < 0) {
		warning(U_("unable to set supplementary group IDs"));
		goto done;
	    }
	}
    }
#ifdef HAVE_SETEUID
    if (ISSET(details->flags, CD_SET_EGID) && setegid(details->egid)) {
	warning(U_("unable to set effective gid to runas gid %u"),
	    (unsigned int)details->egid);
	goto done;
    }
#endif
    if (ISSET(details->flags, CD_SET_GID) && setgid(details->gid)) {
	warning(U_("unable to set gid to runas gid %u"),
	    (unsigned int)details->gid);
	goto done;
    }

    if (ISSET(details->flags, CD_SET_PRIORITY)) {
	if (setpriority(PRIO_PROCESS, 0, details->priority) != 0) {
	    warning(U_("unable to set process priority"));
	    goto done;
	}
    }
    if (ISSET(details->flags, CD_SET_UMASK))
	(void) umask(details->umask);
    if (details->chroot) {
	if (chroot(details->chroot) != 0 || chdir("/") != 0) {
	    warning(U_("unable to change root to %s"), details->chroot);
	    goto done;
	}
    }

    /* 
     * Unlimit the number of processes since Linux's setuid() will
     * return EAGAIN if RLIMIT_NPROC would be exceeded by the uid switch.
     */
    unlimit_nproc();

#ifdef HAVE_SETRESUID
    if (setresuid(details->uid, details->euid, details->euid) != 0) {
	warning(U_("unable to change to runas uid (%u, %u)"), details->uid,
	    details->euid);
	goto done;
    }
#elif defined(HAVE_SETREUID)
    if (setreuid(details->uid, details->euid) != 0) {
	warning(U_("unable to change to runas uid (%u, %u)"),
	    (unsigned int)details->uid, (unsigned int)details->euid);
	goto done;
    }
#else
    if (seteuid(details->euid) != 0 || setuid(details->euid) != 0) {
	warning(U_("unable to change to runas uid (%u, %u)"), details->uid,
	    details->euid);
	goto done;
    }
#endif /* !HAVE_SETRESUID && !HAVE_SETREUID */

    /* Restore previous value of RLIMIT_NPROC. */
    restore_nproc();

    /*
     * Only change cwd if we have chroot()ed or the policy modules
     * specifies a different cwd.  Must be done after uid change.
     */
    if (details->cwd) {
	if (details->chroot || strcmp(details->cwd, user_details.cwd) != 0) {
	    /* Note: cwd is relative to the new root, if any. */
	    if (chdir(details->cwd) != 0) {
		warning(U_("unable to change directory to %s"), details->cwd);
		goto done;
	    }
	}
    }

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

    sudo_execute(details, &cstat);

    switch (cstat.type) {
    case CMD_ERRNO:
	/* exec_setup() or execve() returned an error. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "calling policy close with errno %d", cstat.val);
	policy_close(&policy_plugin, 0, cstat.val);
	TAILQ_FOREACH(plugin, &io_plugins, entries) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG,
		"calling I/O close with errno %d", cstat.val);
	    iolog_close(plugin, 0, cstat.val);
	}
	exitcode = 1;
	break;
    case CMD_WSTATUS:
	/* Command ran, exited or was killed. */
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "calling policy close with wait status %d", cstat.val);
	policy_close(&policy_plugin, cstat.val, 0);
	TAILQ_FOREACH(plugin, &io_plugins, entries) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG,
		"calling I/O close with wait status %d", cstat.val);
	    iolog_close(plugin, cstat.val, 0);
	}
	if (WIFEXITED(cstat.val))
	    exitcode = WEXITSTATUS(cstat.val);
	else if (WIFSIGNALED(cstat.val))
	    exitcode = WTERMSIG(cstat.val) | 128;
	break;
    default:
	warningx(U_("unexpected child termination condition: %d"), cstat.type);
	break;
    }
    debug_return_int(exitcode);
}

static int
policy_open(struct plugin_container *plugin, char * const settings[],
    char * const user_info[], char * const user_env[])
{
    int rval;
    debug_decl(policy_open, SUDO_DEBUG_PCOMM)

    /*
     * Backwards compatibility for older API versions
     */
    switch (plugin->u.generic->version) {
    case SUDO_API_MKVERSION(1, 0):
    case SUDO_API_MKVERSION(1, 1):
	rval = plugin->u.policy_1_0->open(plugin->u.io_1_0->version,
	    sudo_conversation, _sudo_printf, settings, user_info, user_env);
	break;
    default:
	rval = plugin->u.policy->open(SUDO_API_VERSION, sudo_conversation,
	    _sudo_printf, settings, user_info, user_env, plugin->options);
    }

    debug_return_bool(rval);
}

static void
policy_close(struct plugin_container *plugin, int exit_status, int error)
{
    debug_decl(policy_close, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->close != NULL)
	plugin->u.policy->close(exit_status, error);
    else
	warning(U_("unable to execute %s"), command_details.command);
    debug_return;
}

static int
policy_show_version(struct plugin_container *plugin, int verbose)
{
    debug_decl(policy_show_version, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->show_version == NULL)
	debug_return_bool(true);
    debug_return_bool(plugin->u.policy->show_version(verbose));
}

static int
policy_check(struct plugin_container *plugin, int argc, char * const argv[],
    char *env_add[], char **command_info[], char **argv_out[],
    char **user_env_out[])
{
    debug_decl(policy_check, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->check_policy == NULL) {
	fatalx(U_("policy plugin %s is missing the `check_policy' method"),
	    plugin->name);
    }
    debug_return_bool(plugin->u.policy->check_policy(argc, argv, env_add,
	command_info, argv_out, user_env_out));
}

static int
policy_list(struct plugin_container *plugin, int argc, char * const argv[],
    int verbose, const char *list_user)
{
    debug_decl(policy_list, SUDO_DEBUG_PCOMM)
    if (plugin->u.policy->list == NULL) {
	warningx(U_("policy plugin %s does not support listing privileges"),
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
	warningx(U_("policy plugin %s does not support the -v option"),
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
	fatalx(U_("policy plugin %s does not support the -k/-K options"),
	    plugin->name);
    }
    plugin->u.policy->invalidate(remove);
    debug_return;
}

int
policy_init_session(struct command_details *details)
{
    int rval = true;
    debug_decl(policy_init_session, SUDO_DEBUG_PCOMM)

    if (policy_plugin.u.policy->init_session) {
	/*
	 * Backwards compatibility for older API versions
	 */
	switch (policy_plugin.u.generic->version) {
	case SUDO_API_MKVERSION(1, 0):
	case SUDO_API_MKVERSION(1, 1):
	    rval = policy_plugin.u.policy_1_0->init_session(details->pw);
	    break;
	default:
	    rval = policy_plugin.u.policy->init_session(details->pw,
		&details->envp);
	}
    }
    debug_return_bool(rval);
}

static int
iolog_open(struct plugin_container *plugin, char * const settings[],
    char * const user_info[], char * const command_info[],
    int argc, char * const argv[], char * const user_env[])
{
    int rval;
    debug_decl(iolog_open, SUDO_DEBUG_PCOMM)

    /*
     * Backwards compatibility for older API versions
     */
    switch (plugin->u.generic->version) {
    case SUDO_API_MKVERSION(1, 0):
	rval = plugin->u.io_1_0->open(plugin->u.io_1_0->version,
	    sudo_conversation, _sudo_printf, settings, user_info, argc, argv,
	    user_env);
	break;
    case SUDO_API_MKVERSION(1, 1):
	rval = plugin->u.io_1_1->open(plugin->u.io_1_1->version,
	    sudo_conversation, _sudo_printf, settings, user_info,
	    command_info, argc, argv, user_env);
	break;
    default:
	rval = plugin->u.io->open(SUDO_API_VERSION, sudo_conversation,
	    _sudo_printf, settings, user_info, command_info,
	    argc, argv, user_env, plugin->options);
    }
    debug_return_bool(rval);
}

static void
iolog_close(struct plugin_container *plugin, int exit_status, int error)
{
    debug_decl(iolog_close, SUDO_DEBUG_PCOMM)
    if (plugin->u.io->close != NULL)
	plugin->u.io->close(exit_status, error);
    debug_return;
}

static int
iolog_show_version(struct plugin_container *plugin, int verbose)
{
    debug_decl(iolog_show_version, SUDO_DEBUG_PCOMM)
    if (plugin->u.io->show_version == NULL)
	debug_return_bool(true);
    debug_return_bool(plugin->u.io->show_version(verbose));
}

/*
 * Remove the specified I/O logging plugin from the io_plugins list.
 * Deregisters any hooks before unlinking, then frees the container.
 */
static void
iolog_unlink(struct plugin_container *plugin)
{
    debug_decl(iolog_unlink, SUDO_DEBUG_PCOMM)

    /* Deregister hooks, if any. */
    if (plugin->u.io->version >= SUDO_API_MKVERSION(1, 2)) {
	if (plugin->u.io->deregister_hooks != NULL)
	    plugin->u.io->deregister_hooks(SUDO_HOOK_VERSION,
		deregister_hook);
    }
    /* Remove from io_plugins list and free. */
    TAILQ_REMOVE(&io_plugins, plugin, entries);
    efree(plugin);

    debug_return;
}
