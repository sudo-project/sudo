/*
 * Copyright (c) 1994,1996,1998,1999 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $Sudo$
 */

#ifndef _SUDO_SUDO_H
#define _SUDO_SUDO_H

#include <pathnames.h>
#include "compat.h"
#include "logging.h"

/*
 * Info pertaining to the invoking user.
 */
struct sudo_user {
    struct passwd *pw;
    char *tty;
    char  cwd[MAXPATHLEN];
    char *host;
    char *shost;
    char *runas;
    char *prompt;
    char *cmnd_safe;
    char *cmnd;
    char *cmnd_args;
};

/*
 * Return values for validate()
 * Also arguments for log_auth()
 */
#define VALIDATE_OK              0x00
#define VALIDATE_OK_NOPASS       0x01
#define VALIDATE_NO_USER         0x02
#define VALIDATE_NOT_OK          0x03
#define VALIDATE_NOT_OK_NOPASS   0x04
#define VALIDATE_ERROR          -1

/*
 * Boolean values
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
 * Various modes sudo can be in (based on arguments) in octal
 */
#define MODE_RUN                 00001
#define MODE_VALIDATE            00002
#define MODE_INVALIDATE          00004
#define MODE_KILL                00010
#define MODE_VERSION             00020
#define MODE_HELP                00040
#define MODE_LIST                00100
#define MODE_BACKGROUND          00200
#define MODE_SHELL               00400
#define MODE_RESET_HOME          01000

/*
 * Used with set_perms()
 */
#define PERM_ROOT                0x00
#define PERM_USER                0x01
#define PERM_FULL_USER           0x02
#define PERM_SUDOERS             0x03
#define PERM_RUNAS	         0x04

/*
 * Shortcuts for sudo_user contents.
 */
#define user_name		(sudo_user.pw->pw_name)
#define user_passwd		(sudo_user.pw->pw_passwd)
#define user_uid		(sudo_user.pw->pw_uid)
#define user_gid		(sudo_user.pw->pw_gid)
#define user_shell		(sudo_user.pw->pw_shell)
#define user_dir		(sudo_user.pw->pw_dir)
#define user_tty		(sudo_user.tty)
#define user_cwd		(sudo_user.cwd)
#define user_runas		(sudo_user.runas)
#define user_cmnd		(sudo_user.cmnd)
#define user_args		(sudo_user.cmnd_args)
#define user_prompt		(sudo_user.prompt)
#define user_host		(sudo_user.host)
#define user_shost		(sudo_user.shost)
#define safe_cmnd		(sudo_user.cmnd_safe)

/*
 * We used to use the system definition of PASS_MAX or _PASSWD_LEN,
 * but that caused problems with various alternate authentication
 * methods.  So, we just define our own and assume that it is >= the
 * system max.
 */
#define SUDO_PASS_MAX	256

/*
 * Function prototypes
 */
#define YY_DECL int yylex __P((void))

#ifndef HAVE_GETCWD
char *getcwd		__P((char *, size_t size));
#endif
#if !defined(HAVE_PUTENV) && !defined(HAVE_SETENV)
int putenv		__P((const char *));
#endif
char *sudo_goodpath	__P((const char *));
int sudo_setenv		__P((char *, char *));
char *tgetpass		__P((const char *, int, int));
int find_path		__P((char *, char **));
void check_user		__P((void));
void verify_user	__P((void));
int validate		__P((int));
void set_perms		__P((int, int));
void remove_timestamp	__P((int));
int check_secureware	__P((char *));
void sia_attempt_auth	__P((void));
void pam_attempt_auth	__P((void));
int yyparse		__P((void));
void pass_warn		__P((FILE *));
VOID *emalloc		__P((size_t));
VOID *erealloc		__P((VOID *, size_t));
char *estrdup		__P((const char *));
void easprintf		__P((char **, const char *, ...));
void evasprintf		__P((char **, const char *, va_list));
YY_DECL;

/* Only provide extern declarations outside of sudo.c. */
#ifndef _SUDO_SUDO_C
extern struct sudo_user sudo_user;

extern int Argc;
extern char **Argv;
extern int NewArgc;
extern char **NewArgv;
extern FILE *sudoers_fp;
#endif
extern int errno;

#endif /* _SUDO_SUDO_H */
