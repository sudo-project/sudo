/*
 * CU sudo version 1.3.1 (based on Root Group sudo version 1.1)
 *
 * This software comes with no waranty whatsoever, use at your own risk.
 *
 * Please send bugs, changes, problems to sudo-bugs@cs.colorado.edu
 *
 */

/*
 *  sudo version 1.1 allows users to execute commands as root
 *  Copyright (C) 1991  The Root Group, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _SUDO_SUDO_H
#define _SUDO_SUDO_H

#include "compat.h"		/* XXX - should this be here? */
#include "pathnames.h"		/* XXX - should this be here? */

/* Max length for a command */
#define MAXCOMMANDLENGTH	MAXPATHLEN

typedef union {
    int int_val;
    char char_val[MAXCOMMANDLENGTH];
}   YYSTYPE;

typedef struct list {
    int type;
    char op;
    char *data;
    struct list *next;
}   LIST, *LINK;

struct interface {
    struct in_addr addr;
    struct in_addr netmask;
};


/*
 * Maximum number of characters to log per entry.  The syslogger
 * will log this much, after that, it truncates the log line.
 * We need this here to make sure that we continue with another
 * syslog(3) call if the internal buffer is moe than 1023 characters.
 */
#ifndef MAXSYSLOGLEN
#  define MAXSYSLOGLEN		960
#endif

/*
 * Maximum number of characters to log per entry.
 * This is the largest possible line length (worst case)
 */
#ifndef MAXLOGLEN
#  ifndef ARG_MAX
#    ifdef NCARGS
#      define ARG_MAX		NCARGS
#    else
#      ifdef _POSIX_ARG_MAX
#        define ARG_MAX		_POSIX_ARG_MAX
#      else
#        define ARG_MAX		4096
#      endif
#    endif
#  endif
#  define MAXLOGLEN		(49 + MAXPATHLEN + MAXPATHLEN + ARG_MAX)
#endif

#define SLOG_SYSLOG              0x01
#define SLOG_FILE                0x02
#define SLOG_BOTH                0x03

#define VALIDATE_OK              0x00
#define VALIDATE_NO_USER         0x01
#define VALIDATE_NOT_OK          0x02
#define VALIDATE_ERROR          -1

/*
 *  the arguments passed to log_error() are ANDed with GLOBAL_PROBLEM
 *  If the result is TRUE, the argv is NOT logged with the error message
 */

#define GLOBAL_PROBLEM           0x20
#define GLOBAL_NO_PW_ENT         ( 0x01 | GLOBAL_PROBLEM )
#define GLOBAL_NO_HOSTNAME       ( 0x02 | GLOBAL_PROBLEM )
#define GLOBAL_HOST_UNREGISTERED ( 0x03 | GLOBAL_PROBLEM )
#define PASSWORD_NOT_CORRECT     0x04
#define ALL_SYSTEMS_GO           0x00
#define NO_SUDOERS_FILE          ( 0x05 | GLOBAL_PROBLEM )
#define GLOBAL_NO_AUTH_ENT       ( 0x06 | GLOBAL_PROBLEM )

#undef TRUE
#define TRUE                     0x01
#undef FALSE
#define FALSE                    0x00

#define TYPE1                    0x11
#define TYPE2                    0x12
#define TYPE3                    0x13

#define FOUND_USER               0x14
#define NOT_FOUND_USER           0x15
#define MATCH                    0x16
#define NO_MATCH                 0x17
#define QUIT_NOW                 0x18
#define PARSE_ERROR              0x19

#define USER_LIST                0x00
#define HOST_LIST                0x01
#define CMND_LIST                0x02
#define EXTRA_LIST               0x03

#define MODE_RUN                 0x00
#define MODE_VALIDATE            0x01
#define MODE_KILL                0x02
#define MODE_VERSION             0x03
#define MODE_HELP                0x04
#define MODE_LIST                0x05

#define PERM_ROOT                0x00
#define PERM_FULL_ROOT           0x01
#define PERM_USER                0x02
#define PERM_FULL_USER           0x03
#define PERM_SUDOERS             0x04

/*
 * Prototypes
 */


/* These are the functions that are called in sudo(8) */

#ifndef HAVE_STRDUP
char *strdup		__P((const char *));
#endif
#ifndef HAVE_GETCWD
char *getcwd		__P((char *, size_t));
#endif
#if !defined(HAVE_PUTENV) && !defined(HAVE_SETENV)
int putenv		__P((const char *));
#endif
char *sudo_realpath	__P((const char *, char *));
int sudo_setenv		__P((char *, char *));
char *tgetpass		__P((char *, int));
char *find_path		__P((char *));
void log_error		__P((int));
void inform_user	__P((int));
void check_user		__P((void));
int validate		__P((void));
void set_perms		__P((int));
void remove_timestamp	__P((void));
#ifdef HAVE_SKEY
char *skey_getpass	__P((char *, struct passwd *, int));
char *skey_crypt	__P((char *, char *, struct passwd *, int));
#endif /* HAVE_SKEY */


/*
 * Most of these variables are declared in main() so they don't need
 * to be extern'ed here if this is main...
 */
#ifndef MAIN
extern uid_t uid;
extern char host[];
extern char cwd[];
extern struct interface *interfaces;
extern int num_interfaces;
extern char *user;
extern char *epasswd;
extern char *cmnd;
extern int Argc;
extern char **Argv;
#endif
extern int errno;

#endif /* _SUDO_SUDO_H */
