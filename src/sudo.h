/*
 * Copyright (c) 1993-1996, 1998-2005, 2007-2010
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
 * $Sudo: sudo.h,v 1.290 2009/12/12 16:12:26 millert Exp $
 */

#ifndef _SUDO_SUDO_H
#define _SUDO_SUDO_H

#include <limits.h>

#include <pathnames.h>
#include "missing.h"
#include "alloc.h"
#include "error.h"
#include "fileops.h"
#include "list.h"

#ifdef __TANDEM
# define ROOT_UID       65535
#else
# define ROOT_UID       0
#endif

/*
 * Pseudo-boolean values
 */
#undef TRUE
#define TRUE                     1
#undef FALSE
#define FALSE                    0

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

/*
 * We used to use the system definition of PASS_MAX or _PASSWD_LEN,
 * but that caused problems with various alternate authentication
 * methods.  So, we just define our own and assume that it is >= the
 * system max.
 */
#define SUDO_PASS_MAX	256

/*
 * Flags for tgetpass()
 */
#define TGP_NOECHO	0x00		/* turn echo off reading pw (default) */
#define TGP_ECHO	0x01		/* leave echo on when reading passwd */
#define TGP_STDIN	0x02		/* read from stdin, not /dev/tty */
#define TGP_ASKPASS	0x04		/* read from askpass helper program */
#define TGP_MASK	0x08		/* mask user input when reading */
#define TGP_NOECHO_TRY	0x10		/* turn off echo if possible */

struct user_details {
    uid_t uid;
    uid_t euid;
    uid_t gid;
    uid_t egid;
    const char *username;
    const char *cwd;
    const char *tty;
    const char *host;
    const char *shell;
    GETGROUPS_T *groups;
    int ngroups;
    int ts_cols;
    int ts_lines;
};

#define CD_SET_UID		0x0001
#define CD_SET_EUID		0x0002
#define CD_SET_GID		0x0004
#define CD_SET_EGID		0x0008
#define CD_PRESERVE_GROUPS	0x0010
#define CD_NOEXEC		0x0020
#define CD_SET_PRIORITY		0x0040
#define CD_SET_UMASK		0x0080
#define CD_SET_TIMEOUT		0x0100
#define CD_SUDOEDIT		0x0200
#define CD_BACKGROUND		0x0400
#define CD_RBAC_ENABLED		0x0800
#define CD_USE_PTY		0x1000

struct command_details {
    uid_t uid;
    uid_t euid;
    gid_t gid;
    gid_t egid;
    mode_t umask;
    int priority;
    int timeout;
    int ngroups;
    int closefrom;
    int flags;
    GETGROUPS_T *groups;
    const char *command;
    const char *cwd;
    const char *login_class;
    const char *chroot;
    const char *selinux_role;
    const char *selinux_type;
};

/* Status passed between parent and child via socketpair */
struct command_status {
#define CMD_INVALID 0
#define CMD_ERRNO 1
#define CMD_WSTATUS 2
#define CMD_SIGNO 3
    int type;
    int val;
};

struct timeval;

/* For error() and errorx() (XXX - needed?) */
void cleanup(int);

/* tgetpass.c */
char *tgetpass(const char *, int, int);
int tty_present(void);
extern const char *askpass_path;

/* zero_bytes.c */
void zero_bytes(volatile void *, size_t);

/* exec.c */
int sudo_execve(struct command_details *details, char *argv[], char *envp[],
    struct command_status *cstat);
void save_signals(void);
void restore_signals(void);

/* term.c */
int term_cbreak(int);
int term_copy(int, int);
int term_noecho(int);
int term_raw(int, int);
int term_restore(int, int);

/* fmt_string.h */
char *fmt_string(const char *var, const char *value);

/* atobool.c */
int atobool(const char *str);

/* parse_args.c */
int parse_args(int argc, char **argv, int *nargc, char ***nargv,
    char ***settingsp, char ***env_addp);
extern int tgetpass_flags;

/* get_pty.c */
int get_pty(int *master, int *slave, char *name, size_t namesz, uid_t uid);

/* ttysize.c */
void get_ttysize(int *rowp, int *colp);

/* sudo.c */
int exec_setup(struct command_details *details, const char *ptyname, int ptyfd);
int run_command(struct command_details *details, char *argv[],   
    char *envp[]);
void sudo_debug(int level, const char *format, ...) __printflike(2, 3);
extern int debug_level;
extern const char *list_user, *runas_user, *runas_group;
extern struct user_details user_details;

/* sudo_edit.c */
int sudo_edit(struct command_details *details, char *argv[], char *envp[]);

/* parse_args.c */
void usage(int);

/* selinux.c */
int selinux_restore_tty(void);
int selinux_setup(const char *role, const char *type, const char *ttyn,
    int ttyfd);
void selinux_execve(const char *path, char *argv[], char *envp[]);

/* aix.c */
void aix_prep_user(char *user, const char *tty);
void aix_restoreauthdb(void);
void aix_setauthdb(char *user);

/* interfaces.c */
int get_net_ifs(char **addrinfo);

#ifndef errno
extern int errno;
#endif

#endif /* _SUDO_SUDO_H */
