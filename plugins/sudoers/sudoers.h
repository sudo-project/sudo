/*
 * Copyright (c) 1993-1996, 1998-2005, 2007-2011
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

#ifndef _SUDO_SUDOERS_H
#define _SUDO_SUDOERS_H

#include <limits.h>

#include <pathnames.h>
#include "missing.h"
#include "error.h"
#include "alloc.h"
#include "list.h"
#include "fileops.h"
#include "defaults.h"
#include "logging.h"
#include "sudo_nss.h"
#include "sudo_plugin.h"

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
    char *name;
    char *path;
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
    int   closefrom;
    int   ngroups;
    uid_t uid;
    uid_t gid;
    int   lines;
    int   cols;
    GETGROUPS_T *groups;
    char * const * env_vars;
#ifdef HAVE_SELINUX
    char *role;
    char *type;
#endif
    char *cwd;
    char  sessid[7];
#ifdef HAVE_MBR_CHECK_MEMBERSHIP
    uuid_t uuid;
#endif
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
#define FOUND                   0
#define NOT_FOUND               1
#define NOT_FOUND_DOT		2

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
#define MODE_IGNORE_TICKET	0x01000000

/*
 * Used with set_perms()
 */
#define PERM_INITIAL             0x00
#define PERM_ROOT                0x01
#define PERM_USER                0x02
#define PERM_FULL_USER           0x03
#define PERM_SUDOERS             0x04
#define PERM_RUNAS               0x05
#define PERM_TIMESTAMP           0x06
#define PERM_NOEXIT              0x10 /* flag */
#define PERM_MASK                0xf0

/*
 * Shortcuts for sudo_user contents.
 */
#define user_name		(sudo_user.name)
#define user_uid		(sudo_user.uid)
#define user_gid		(sudo_user.gid)
#define user_passwd		(sudo_user.pw->pw_passwd)
#define user_uuid		(sudo_user.uuid)
#define user_dir		(sudo_user.pw->pw_dir)
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
#define safe_cmnd		(sudo_user.cmnd_safe)
#define login_class		(sudo_user.class_name)
#define runas_pw		(sudo_user._runas_pw)
#define runas_gr		(sudo_user._runas_gr)
#define user_role		(sudo_user.role)
#define user_type		(sudo_user.type)
#define user_closefrom		(sudo_user.closefrom)

#ifdef __TANDEM
# define ROOT_UID       65535
#else
# define ROOT_UID       0
#endif

/*
 * We used to use the system definition of PASS_MAX or _PASSWD_LEN,
 * but that caused problems with various alternate authentication
 * methods.  So, we just define our own and assume that it is >= the
 * system max.
 */
#define SUDO_PASS_MAX	256

struct lbuf;
struct passwd;
struct stat;
struct timeval;

/*
 * Function prototypes
 */
#define YY_DECL int yylex(void)

/* goodpath.c */
char *sudo_goodpath(const char *, struct stat *);

/* findpath.c */
int find_path(char *, char **, struct stat *, char *, int);

/* check.c */
int check_user(int, int);
void remove_timestamp(int);
int user_is_exempt(void);

/* sudo_auth.c */
int verify_user(struct passwd *, char *);
int auth_begin_session(struct passwd *);
int auth_end_session();

/* parse.c */
int sudo_file_open(struct sudo_nss *);
int sudo_file_close(struct sudo_nss *);
int sudo_file_setdefs(struct sudo_nss *);
int sudo_file_lookup(struct sudo_nss *, int, int);
int sudo_file_parse(struct sudo_nss *);
int sudo_file_display_cmnd(struct sudo_nss *, struct passwd *);
int sudo_file_display_defaults(struct sudo_nss *, struct passwd *, struct lbuf *);
int sudo_file_display_bound_defaults(struct sudo_nss *, struct passwd *, struct lbuf *);
int sudo_file_display_privs(struct sudo_nss *, struct passwd *, struct lbuf *);

/* set_perms.c */
void rewind_perms(void);
int set_perms(int);
void restore_perms(void);
int pam_prep_user(struct passwd *);

/* gram.y */
int yyparse(void);

/* toke.l */
YY_DECL;

/* defaults.c */
void dump_defaults(void);
void dump_auth_methods(void);

/* getspwuid.c */
char *sudo_getepw(const struct passwd *);

/* zero_bytes.c */
void zero_bytes(volatile void *, size_t);

/* sudo_nss.c */
void display_privs(struct sudo_nss_list *, struct passwd *);
int display_cmnd(struct sudo_nss_list *, struct passwd *);

/* pwutil.c */
void sudo_setgrent(void);
void sudo_endgrent(void);
void sudo_setpwent(void);
void sudo_endpwent(void);
void sudo_setspent(void);
void sudo_endspent(void);
struct passwd *sudo_getpwnam(const char *);
struct passwd *sudo_fakepwnam(const char *, gid_t);
struct passwd *sudo_getpwuid(uid_t);
struct group *sudo_getgrnam(const char *);
struct group *sudo_fakegrnam(const char *);
struct group *sudo_getgrgid(gid_t);
void gr_addref(struct group *);
void gr_delref(struct group *);
void pw_addref(struct passwd *);
void pw_delref(struct passwd *);
int user_in_group(struct passwd *, const char *);

/* timestr.c */
char *get_timestr(time_t, int);

/* atobool.c */
int atobool(const char *str);

/* boottime.c */
int get_boottime(struct timeval *);

/* iolog.c */
void io_nextid(char *iolog_dir, char sessid[7]);

/* iolog_path.c */
char *expand_iolog_path(const char *prefix, const char *dir, const char *file,
    char **slashp);

/* env.c */
char **env_get(void);
void env_init(char * const envp[]);
void init_envtables(void);
void insert_env_vars(char * const envp[]);
void read_env_file(const char *, int);
void rebuild_env(int);
void validate_env_vars(char * const envp[]);

/* fmt_string.c */
char *fmt_string(const char *, const char *);

/* sudoers.c */
void plugin_cleanup(int);
void set_fqdn(void);
FILE *open_sudoers(const char *, int, int *);

/* aix.c */
void aix_restoreauthdb(void);
void aix_setauthdb(char *user);

/* group_plugin.c */
int group_plugin_load(char *plugin_info);
void group_plugin_unload(void);
int group_plugin_query(const char *user, const char *group,
    const struct passwd *pwd);

#ifndef _SUDO_MAIN
extern struct sudo_user sudo_user;
extern struct passwd *list_pw;
extern const char *sudoers_file;
extern mode_t sudoers_mode;
extern uid_t sudoers_uid;
extern gid_t sudoers_gid;
extern int long_list;
extern int sudo_mode;
extern uid_t timestamp_uid;
extern sudo_conv_t sudo_conv;
extern sudo_printf_t sudo_printf;
#endif

/* Some systems don't declare errno in errno.h */
#ifndef errno
extern int errno;
#endif

#endif /* _SUDO_SUDOERS_H */
