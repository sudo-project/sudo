/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1993-1996, 1998-2005, 2007-2022
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef SUDO_SUDO_H
#define SUDO_SUDO_H

#include <limits.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#ifdef HAVE_PRIV_SET
# include <priv.h>
#endif

#include "pathnames.h"
#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_event.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_queue.h"
#include "sudo_util.h"

/* Enable asserts() to avoid static analyzer false positives. */
#if !(defined(SUDO_DEVEL) || defined(__clang_analyzer__) || defined(__COVERITY__))
# define NDEBUG
#endif

/*
 * Various modes sudo can be in (based on arguments) in hex
 */
#define MODE_RUN		0x00000001
#define MODE_EDIT		0x00000002
#define MODE_VALIDATE		0x00000004
#define MODE_INVALIDATE		0x00000008
#define MODE_KILL		0x00000010
#define MODE_VERSION		0x00000020
#define MODE_HELP		0x00000040
#define MODE_LIST		0x00000080
#define MODE_CHECK		0x00000100
#define MODE_MASK		0x0000ffff

/* Mode flags */
/* XXX - prune this */
#define MODE_BACKGROUND		0x00010000
#define MODE_SHELL		0x00020000
#define MODE_LOGIN_SHELL	0x00040000
#define MODE_IMPLIED_SHELL	0x00080000
#define MODE_RESET_HOME		0x00100000
#define MODE_PRESERVE_GROUPS	0x00200000
#define MODE_PRESERVE_ENV	0x00400000
#define MODE_NONINTERACTIVE	0x00800000
#define MODE_LONG_LIST		0x01000000

/* Indexes into sudo_settings[] args, must match parse_args.c. */
#define ARG_BSDAUTH_TYPE	 0
#define ARG_LOGIN_CLASS		 1
#define ARG_PRESERVE_ENVIRONMENT 2
#define ARG_RUNAS_GROUP		 3
#define ARG_SET_HOME		 4
#define ARG_USER_SHELL		 5
#define ARG_LOGIN_SHELL		 6
#define ARG_IGNORE_TICKET	 7
#define ARG_UPDATE_TICKET	 8
#define ARG_PROMPT		 9
#define ARG_SELINUX_ROLE	10
#define ARG_SELINUX_TYPE	11
#define ARG_RUNAS_USER		12
#define ARG_PROGNAME		13
#define ARG_IMPLIED_SHELL	14
#define ARG_PRESERVE_GROUPS	15
#define ARG_NONINTERACTIVE	16
#define ARG_SUDOEDIT		17
#define ARG_CLOSEFROM		18
#define ARG_NET_ADDRS		19
#define ARG_MAX_GROUPS		20
#define ARG_PLUGIN_DIR		21
#define ARG_REMOTE_HOST		22
#define ARG_TIMEOUT		23
#define ARG_CHROOT		24
#define ARG_CWD			25
#define ARG_ASKPASS		26
#define ARG_INTERCEPT_SETID	27
#define ARG_INTERCEPT_PTRACE	28
#define ARG_APPARMOR_PROFILE	29

/*
 * Flags for tgetpass()
 */
#define TGP_NOECHO	0x00		/* turn echo off reading pw (default) */
#define TGP_ECHO	0x01		/* leave echo on when reading passwd */
#define TGP_STDIN	0x02		/* read from stdin, not /dev/tty */
#define TGP_ASKPASS	0x04		/* read from askpass helper program */
#define TGP_MASK	0x08		/* mask user input when reading */
#define TGP_NOECHO_TRY	0x10		/* turn off echo if possible */
#define TGP_BELL	0x20		/* bell on password prompt */

/* name/value pairs for command line settings. */
struct sudo_settings {
    const char *name;
    const char *value;
};

/* Sudo user credentials */
struct sudo_cred {
    uid_t uid;
    uid_t euid;
    uid_t gid;
    uid_t egid;
    int ngroups;
    GETGROUPS_T *groups;
};

struct user_details {
    struct sudo_cred cred;
    pid_t pid;
    pid_t ppid;
    pid_t pgid;
    pid_t tcpgid;
    pid_t sid;
    const char *username;
    const char *cwd;
    const char *tty;
    const char *host;
    const char *shell;
    int ts_rows;
    int ts_cols;
};

#define CD_SET_UID		0x00000001
#define CD_SET_EUID		0x00000002
#define CD_SET_GID		0x00000004
#define CD_SET_EGID		0x00000008
#define CD_PRESERVE_GROUPS	0x00000010
#define CD_INTERCEPT		0x00000020
#define CD_NOEXEC		0x00000040
#define CD_SET_PRIORITY		0x00000080
#define CD_SET_UMASK		0x00000100
#define CD_SET_TIMEOUT		0x00000200
#define CD_SUDOEDIT		0x00000400
#define CD_BACKGROUND		0x00000800
#define CD_RBAC_ENABLED		0x00001000
#define CD_USE_PTY		0x00002000
#define CD_SET_UTMP		0x00004000
#define CD_EXEC_BG		0x00008000
#define CD_SUDOEDIT_FOLLOW	0x00010000
#define CD_SUDOEDIT_CHECKDIR	0x00020000
#define CD_SET_GROUPS		0x00040000
#define CD_LOGIN_SHELL		0x00080000
#define CD_OVERRIDE_UMASK	0x00100000
#define CD_LOG_SUBCMDS		0x00200000
#define CD_USE_PTRACE		0x00400000
#define CD_FEXECVE		0x00800000
#define CD_INTERCEPT_VERIFY	0x01000000
#define CD_RBAC_SET_CWD		0x02000000
#define CD_CWD_OPTIONAL		0x04000000

struct preserved_fd {
    TAILQ_ENTRY(preserved_fd) entries;
    int lowfd;
    int highfd;
    int flags;
};
TAILQ_HEAD(preserved_fd_list, preserved_fd);

struct command_details {
    struct sudo_cred cred;
    mode_t umask;
    int argc;
    int priority;
    int timeout;
    int closefrom;
    int flags;
    int execfd;
    int nfiles;
    struct preserved_fd_list preserved_fds;
    struct passwd *pw;
    const char *command;
    const char *runas_user;
    const char *cwd;
    const char *login_class;
    const char *chroot;
    const char *selinux_role;
    const char *selinux_type;
    const char *apparmor_profile;
    const char *utmp_user;
    const char *tty;
    char **argv;
    char **envp;
    struct sudo_event_base *evbase;
#ifdef HAVE_PRIV_SET
    priv_set_t *privs;
    priv_set_t *limitprivs;
#endif
    char * const *info;
};

/* Status passed between parent and child via socketpair */
struct command_status {
#define CMD_INVALID	0
#define CMD_ERRNO	1
#define CMD_WSTATUS	2
#define CMD_SIGNO	3
#define CMD_PID		4
#define CMD_TTYWINCH	5
    int type;
    int val;
};

/* Garbage collector data types. */
enum sudo_gc_types {
    GC_UNKNOWN,
    GC_VECTOR,
    GC_PTR
};

/* For fatal() and fatalx() (XXX - needed?) */
void cleanup(int);

/* tgetpass.c */
char *tgetpass(const char *prompt, int timeout, int flags,
    struct sudo_conv_callback *callback);

/* exec.c */
int sudo_execute(struct command_details *details, struct command_status *cstat);

/* parse_args.c */
int parse_args(int argc, char **argv, int *old_optind, int *nargc,
    char ***nargv, struct sudo_settings **settingsp, char ***env_addp);
extern int tgetpass_flags;

/* get_pty.c */
bool get_pty(int *leader, int *follower, char *name, size_t namesz, uid_t uid);

/* sudo.c */
int policy_init_session(struct command_details *details);
int run_command(struct command_details *details);
int os_init_common(int argc, char *argv[], char *envp[]);
bool gc_add(enum sudo_gc_types type, void *v);
bool set_user_groups(struct command_details *details);
struct sudo_plugin_event *sudo_plugin_event_alloc(void);
bool audit_accept(const char *plugin_name, unsigned int plugin_type,
    char * const command_info[], char * const run_argv[],
    char * const run_envp[]);
bool audit_reject(const char *plugin_name, unsigned int plugin_type,
    const char *audit_msg, char * const command_info[]);
bool audit_error(const char *plugin_name, unsigned int plugin_type,
    const char *audit_msg, char * const command_info[]);
bool approval_check(char * const command_info[], char * const run_argv[],
    char * const run_envp[]);
extern const char *list_user;
extern struct user_details user_details;
extern int sudo_debug_instance;

/* sudo_edit.c */
int sudo_edit(struct command_details *details);

/* parse_args.c */
sudo_noreturn void usage(void);

/* openbsd.c */
int os_init_openbsd(int argc, char *argv[], char *envp[]);

/* selinux.c */
int selinux_audit_role_change(void);
int selinux_getexeccon(const char *role, const char *type);
int selinux_relabel_tty(const char *ttyn, int ttyfd);
int selinux_restore_tty(void);
int selinux_setexeccon(void);
void selinux_execve(int fd, const char *path, char *const argv[],
    char *envp[], const char *rundir, int flags);

/* apparmor.c */
int apparmor_is_enabled(void);
int apparmor_prepare(const char* new_profile);

/* solaris.c */
void set_project(struct passwd *);
int os_init_solaris(int argc, char *argv[], char *envp[]);

/* hooks.c */
/* XXX - move to sudo_plugin_int.h? */
struct sudo_hook;
int register_hook(struct sudo_hook *hook);
int deregister_hook(struct sudo_hook *hook);
int process_hooks_getenv(const char *name, char **val);
int process_hooks_setenv(const char *name, const char *value, int overwrite);
int process_hooks_putenv(char *string);
int process_hooks_unsetenv(const char *name);

/* env_hooks.c */
char *getenv_unhooked(const char *name);

/* interfaces.c */
int get_net_ifs(char **addrinfo);

/* ttyname.c */
char *get_process_ttyname(char *name, size_t namelen);

/* signal.c */
struct sigaction;
int sudo_sigaction(int signo, struct sigaction *sa, struct sigaction *osa);
void init_signals(void);
void restore_signals(void);
void save_signals(void);
bool signal_pending(int signo);

/* preload.c */
void preload_static_symbols(void);

/* preserve_fds.c */
int add_preserved_fd(struct preserved_fd_list *pfds, int fd);
void closefrom_except(int startfd, struct preserved_fd_list *pfds);
void parse_preserved_fds(struct preserved_fd_list *pfds, const char *fdstr);

/* setpgrp_nobg.c */
int tcsetpgrp_nobg(int fd, pid_t pgrp_id);

/* limits.c */
void disable_coredump(void);
void restore_limits(void);
void restore_nproc(void);
void set_policy_rlimits(void);
void unlimit_nproc(void);
void unlimit_sudo(void);
int serialize_rlimits(char **info, size_t info_max);
bool parse_policy_rlimit(const char *str);

/* exec_ptrace.c */
void exec_ptrace_fix_flags(struct command_details *details);
bool exec_ptrace_intercept_supported(void);
bool exec_ptrace_subcmds_supported(void);

#endif /* SUDO_SUDO_H */
