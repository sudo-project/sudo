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
 */

#ifndef _SUDO_SUDO_H
#define _SUDO_SUDO_H

#include <pathnames.h>
#include <limits.h>
#include "compat.h"
#include "alloc.h"
#include "defaults.h"
#include "error.h"
#include "list.h"
#include "logging.h"
#include "missing.h"
#include "sudo_nss.h"

#ifdef HAVE_MBR_CHECK_MEMBERSHIP
# include <membership.h>
#endif

/*
 * Info pertaining to the invoking user.
 */
struct sudo_user {
    struct passwd *pw;
    struct passwd *_runas_pw;
    struct group *_runas_gr;
    struct stat *cmnd_stat;
    char *path;
    char *shell;
    char *tty;
    char *ttypath;
    char *host;
    char *shost;
    char *prompt;
    char *cmnd;
    char *cmnd_args;
    char *cmnd_base;
    char *cmnd_safe;
    char *class_name;
    char *krb5_ccname;
    char *display;
    char *askpass;
    int   ngroups;
    GETGROUPS_T *groups;
    struct list_member *env_vars;
#ifdef HAVE_SELINUX
    char *role;
    char *type;
#endif
    char  cwd[PATH_MAX];
    char  sessid[7];
#ifdef HAVE_MBR_CHECK_MEMBERSHIP
    uuid_t uuid;
#endif
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

/*
 * Return values for sudoers_lookup(), also used as arguments for log_auth()
 * Note: cannot use '0' as a value here.
 */
/* XXX - VALIDATE_SUCCESS and VALIDATE_FAILURE instead? */
#define VALIDATE_ERROR          0x001
#define VALIDATE_OK		0x002
#define VALIDATE_NOT_OK		0x004
#define FLAG_CHECK_USER		0x010
#define FLAG_NO_USER		0x020
#define FLAG_NO_HOST		0x040
#define FLAG_NO_CHECK		0x080

/*
 * Pseudo-boolean values
 */
#undef TRUE
#define TRUE                     1
#undef FALSE
#define FALSE                    0

/*
 * find_path()/load_cmnd() return values
 */
#define FOUND                    1
#define NOT_FOUND                0
#define NOT_FOUND_DOT		-1

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
#define MODE_LISTDEFS		0x00000200
#define MODE_MASK		0x0000ffff

/* Mode flags */
#define MODE_BACKGROUND		0x00010000
#define MODE_SHELL		0x00020000
#define MODE_LOGIN_SHELL	0x00040000
#define MODE_IMPLIED_SHELL	0x00080000
#define MODE_RESET_HOME		0x00100000
#define MODE_PRESERVE_GROUPS	0x00200000
#define MODE_PRESERVE_ENV	0x00400000
#define MODE_NONINTERACTIVE	0x00800000

/*
 * Used with set_perms()
 */
#define PERM_ROOT                0x00
#define PERM_USER                0x01
#define PERM_FULL_USER           0x02
#define PERM_SUDOERS             0x03
#define PERM_RUNAS               0x04
#define PERM_FULL_RUNAS          0x05
#define PERM_TIMESTAMP           0x06
#define PERM_NOEXIT              0x10 /* flag */
#define PERM_MASK                0xf0

/*
 * Shortcuts for sudo_user contents.
 */
#define user_name		(sudo_user.pw->pw_name)
#define user_passwd		(sudo_user.pw->pw_passwd)
#define user_uid		(sudo_user.pw->pw_uid)
#define user_uuid		(sudo_user.uuid)
#define user_gid		(sudo_user.pw->pw_gid)
#define user_dir		(sudo_user.pw->pw_dir)
#define user_shell		(sudo_user.shell)
#define user_ngroups		(sudo_user.ngroups)
#define user_groups		(sudo_user.groups)
#define user_tty		(sudo_user.tty)
#define user_ttypath		(sudo_user.ttypath)
#define user_cwd		(sudo_user.cwd)
#define user_cmnd		(sudo_user.cmnd)
#define user_args		(sudo_user.cmnd_args)
#define user_base		(sudo_user.cmnd_base)
#define user_stat		(sudo_user.cmnd_stat)
#define user_path		(sudo_user.path)
#define user_prompt		(sudo_user.prompt)
#define user_host		(sudo_user.host)
#define user_shost		(sudo_user.shost)
#define user_ccname		(sudo_user.krb5_ccname)
#define user_display		(sudo_user.display)
#define user_askpass		(sudo_user.askpass)
#define safe_cmnd		(sudo_user.cmnd_safe)
#define login_class		(sudo_user.class_name)
#define runas_pw		(sudo_user._runas_pw)
#define runas_gr		(sudo_user._runas_gr)
#define user_role		(sudo_user.role)
#define user_type		(sudo_user.type)

/*
 * We used to use the system definition of PASS_MAX or _PASSWD_LEN,
 * but that caused problems with various alternate authentication
 * methods.  So, we just define our own and assume that it is >= the
 * system max.
 */
#define SUDO_PASS_MAX	256

/*
 * Flags for lock_file()
 */
#define SUDO_LOCK	1		/* lock a file */
#define SUDO_TLOCK	2		/* test & lock a file (non-blocking) */
#define SUDO_UNLOCK	4		/* unlock a file */

/*
 * Flags for tgetpass()
 */
#define TGP_ECHO	0x01		/* leave echo on when reading passwd */
#define TGP_STDIN	0x02		/* read from stdin, not /dev/tty */
#define TGP_ASKPASS	0x04		/* read from askpass helper program */

struct lbuf;
struct passwd;
struct stat;
struct timeval;

/* aix.c */
void aix_prep_user __P((char *, char *));
void aix_setauthdb __P((char *user));
void aix_restoreauthdb __P((void));

/* boottime.c */
int get_boottime __P((struct timeval *));

/* check.c */
int user_is_exempt	__P((void));
void check_user		__P((int, int));
void remove_timestamp	__P((int));

/* env.c */
char **env_get		__P((void));
void env_init		__P((int lazy));
void init_envtables	__P((void));
void insert_env_vars	__P((struct list_member *));
void read_env_file	__P((const char *, int));
void rebuild_env	__P((int));
void validate_env_vars	__P((struct list_member *));

/* exec.c */
int sudo_execve __P((const char *path, char *argv[], char *envp[], uid_t uid,
    struct command_status *cstat, int dowait, int bgmode));

/* fileops.c */
char *sudo_parseln	__P((FILE *));
int lock_file		__P((int, int));
int touch		__P((int, char *, struct timeval *));

/* find_path.c */
int find_path		__P((char *, char **, struct stat *, char *, int));

/* getspwuid.c */
char *sudo_getepw	__P((const struct passwd *));

/* gettime.c */
int gettime		__P((struct timeval *));

/* goodpath.c */
char *sudo_goodpath	__P((const char *, struct stat *));

/* gram.y */
int yyparse		__P((void));

/* iolog.c */
int io_log_open __P((void));
int log_stderr __P((const char *buf, unsigned int len));
int log_stdin __P((const char *buf, unsigned int len));
int log_stdout __P((const char *buf, unsigned int len));
int log_ttyin __P((const char *buf, unsigned int len));
int log_ttyout __P((const char *buf, unsigned int len));
void io_log_close __P((void));
void io_nextid __P((void));

/* pam.c */
int pam_begin_session	__P((struct passwd *));
int pam_end_session	__P((void));

/* parse.c */
int sudo_file_open	__P((struct sudo_nss *));
int sudo_file_close	__P((struct sudo_nss *));
int sudo_file_setdefs	__P((struct sudo_nss *));
int sudo_file_lookup	__P((struct sudo_nss *, int, int));
int sudo_file_parse	__P((struct sudo_nss *));
int sudo_file_display_cmnd __P((struct sudo_nss *, struct passwd *));
int sudo_file_display_defaults __P((struct sudo_nss *, struct passwd *, struct lbuf *));
int sudo_file_display_bound_defaults __P((struct sudo_nss *, struct passwd *, struct lbuf *));
int sudo_file_display_privs __P((struct sudo_nss *, struct passwd *, struct lbuf *));

/* parse_args.c */
int parse_args __P((int, char **));

/* get_pty.c */
int get_pty __P((int *master, int *slave, char *name, size_t namesz, uid_t uid));

/* pwutil.c */
int user_in_group	__P((struct passwd *, const char *));
struct group *sudo_fakegrnam __P((const char *));
struct group *sudo_getgrgid __P((gid_t));
struct group *sudo_getgrnam __P((const char *));
struct passwd *sudo_fakepwnam __P((const char *, gid_t));
struct passwd *sudo_getpwnam __P((const char *));
struct passwd *sudo_getpwuid __P((uid_t));
void sudo_endgrent	__P((void));
void sudo_endpwent	__P((void));
void sudo_endspent	__P((void));
void sudo_setgrent	__P((void));
void sudo_setpwent	__P((void));
void sudo_setspent	__P((void));

/* selinux.c */
int selinux_restore_tty __P((void));
int selinux_setup __P((const char *role, const char *type, const char *ttyn,
    int ttyfd));
void selinux_execve __P((const char *path, char *argv[], char *envp[]));

/* set_perms.c */
int set_perms		__P((int));

/* sudo.c */
FILE *open_sudoers	__P((const char *, int, int *));
int exec_setup		__P((int, const char *, int));
void cleanup		__P((int));
void set_fqdn		__P((void));

/* sudo_auth.c */
void verify_user	__P((struct passwd *, char *));
void pass_warn		__P((FILE *));
void dump_auth_methods	__P((void));

/* sudo_nss.c */
void display_privs	__P((struct sudo_nss_list *, struct passwd *));
int display_cmnd	__P((struct sudo_nss_list *, struct passwd *));

/* term.c */
int term_cbreak __P((int));
int term_copy __P((int, int));
int term_noecho __P((int));
int term_raw __P((int, int));
int term_restore __P((int, int));

/* tgetpass.c */
char *tgetpass		__P((const char *, int, int));
int tty_present		__P((void));

/* timestr.c */
char *get_timestr __P((time_t, int));

/* toke.l */
#define YY_DECL int yylex __P((void))
YY_DECL;

/* zero_bytes.c */
void zero_bytes		__P((volatile void *, size_t));

/* Only provide extern declarations outside of sudo.c. */
#ifndef _SUDO_MAIN
extern struct sudo_user sudo_user;
extern struct passwd *auth_pw, *list_pw;

extern int tgetpass_flags;
extern int long_list;
extern int sudo_mode;
extern uid_t timestamp_uid;
/* XXX - conflicts with the one in visudo */
int run_command __P((const char *path, char *argv[], char *envp[], uid_t uid, int dowait));
#endif
#ifndef errno
extern int errno;
#endif

#endif /* _SUDO_SUDO_H */
