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
 *
 *  $Id$
 */

#ifndef _SUDO_SUDO_H
#define _SUDO_SUDO_H

#include "compat.h"
#include "pathnames.h"

/* Max length for a command */
#define MAXCOMMANDLENGTH	MAXPATHLEN

/*
 * IP address and netmask pairs for checking against local interfaces.
 */
struct interface {
    struct in_addr addr;
    struct in_addr netmask;
};

/*
 * Data structure used in parsing sudoers;
 * top of stack values are the ones that
 * apply when parsing is done & can be
 * accessed by *_matches macros
 */
struct matchstack {
	int user;
	int cmnd;
	int host;
};

extern struct matchstack match[];
extern int top;

#define user_matches	(match[top-1].user)
#define cmnd_matches	(match[top-1].cmnd)
#define host_matches	(match[top-1].host)

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
#define PASSWORDS_NOT_CORRECT    0x05
#define ALL_SYSTEMS_GO           0x00
#define NO_SUDOERS_FILE          ( 0x06 | GLOBAL_PROBLEM )
#define GLOBAL_NO_AUTH_ENT       ( 0x07 | GLOBAL_PROBLEM )
#define BAD_SUDOERS_FILE         ( 0x08 | GLOBAL_PROBLEM )
#define SUDOERS_NO_OWNER         ( 0x09 | GLOBAL_PROBLEM )
#define SUDOERS_WRONG_OWNER      ( 0x0A | GLOBAL_PROBLEM )
#define SUDOERS_NOT_FILE         ( 0x0B | GLOBAL_PROBLEM )
#define SUDOERS_RW_OTHER         ( 0x0C | GLOBAL_PROBLEM )

/*
 * Boolean values
 */
#undef TRUE
#define TRUE                     0x01
#undef FALSE
#define FALSE                    0x00

/*
 * Various modes sudo can be in (based on arguments)
 */
#define MODE_RUN                 0x00
#define MODE_VALIDATE            0x01
#define MODE_KILL                0x02
#define MODE_VERSION             0x03
#define MODE_HELP                0x04
#define MODE_LIST                0x05

/*
 * Used with set_perms()
 */
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
char *sudo_goodpath	__P((const char *));
int sudo_setenv		__P((char *, char *));
char *tgetpass		__P((char *, int));
char * find_path	__P((char *));
void log_error		__P((int));
void inform_user	__P((int));
void check_user		__P((void));
int validate		__P((void));
void set_perms		__P((int));
void remove_timestamp	__P((void));
void load_interfaces	__P((void));
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
