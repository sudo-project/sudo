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

#include "pathnames.h"

/* Configurable OPTIONS--these can be overridden from the Makefile */
  
/*
 *  Define FQDN if you have fully qualified hostnames in your SUDOERS file
 */
#ifndef FQDN
#  undef FQDN
#endif

/*
 *  Define SYSLOG if you want to use syslog(3) instead of a log file.
 *  (This is a nice feature.  You can collect all your sudo logs at
 *   a single host.)
 */
#ifndef SYSLOG
#  define SYSLOG
#endif

/*
 *  Uncomment this if you want to log to a file *and* via syslog(3)
 */
/* #define BOTH_LOGS */

/*
 *  If you define NO_ROOT_SUDO, sudo will exit if called by root.
 */
#ifndef NO_ROOT_SUDO
#  undef NO_ROOT_SUDO
#endif

/*
 *  Who should own the sudoers file?  This is normally root *unless*
 *  you want to access the sudoers file over NFS.
 */
#ifndef SUDOERS_OWNER
#  define SUDOERS_OWNER	"root"
#endif

/*
 *  If you define EXEMPTGROUP, sudo will not ask for a password for
 *  users of this group.
 */
#ifndef EXEMPTGROUP
#  undef EXEMPTGROUP 100
#endif
  
/*
 *  Define SEND_MAIL_WHEN_NO_USER if you want a message sent to ALERTMAIL
 *  when the user is not in the SUDOERS file.  (This is generally the case.)
 */
#ifndef SEND_MAIL_WHEN_NO_USER
#  define SEND_MAIL_WHEN_NO_USER
#endif
  
/*
 *  Define SEND_MAIL_WHEN_NOT_OK if you want a message sent to ALERTMAIL
 *  when the user is in the SUDOERS but does not have permission to execute
 *  the command entered.  (This can be used at paranoid sites.)
 */
#ifndef SEND_MAIL_WHEN_NOT_OK
#  undef SEND_MAIL_WHEN_NOT_OK
#endif
 
/*
 *  Define ENV_EDITOR if you want the EDITOR and VISUAL envariables to
 *  be consulted by visudo(8).
 */
#ifndef ENV_EDITOR
#  undef ENV_EDITOR
#endif
 
/*
 *  Change the "define" to "undef" if you want the full copyright message
 *  along with the "we expect you have..." banner.
 */
#ifndef SHORT_MESSAGE
#  define SHORT_MESSAGE
#endif
 
/*
 *  Define USE_INSULTS if you want to be insulted for typing an
 *  incorrect password just like the original sudo(8).
 */
#ifndef USE_INSULTS
#  undef USE_INSULTS
#endif
 
/*
 *  Define HAL if you want lines from 2001 instead of insults.
 *  (Note: you must define USE_INSULTS too.)
 */
#ifndef HAL
#  undef HAL
#endif
 
/*
 *  Define USE_EXECV if you want to use execv() instead of execvp().
 */
#ifndef USE_EXECV
#  undef USE_EXECV
#endif

/*
 *  Number of minutes that can elapse before sudo will ask for a passwd again
 */
#ifndef TIMEOUT
#  define TIMEOUT		5
#endif

/*
 *  Number of minutes that can elapse before a user enters a password
 */
#ifndef PASSWORD_TIMEOUT
#  define PASSWORD_TIMEOUT	5
#endif

/*
 *  Number of times sudo will let you guess are you password before screaming
 */
#ifndef TRIES_FOR_PASSWORD
#  define TRIES_FOR_PASSWORD	3
#endif

/*
 *  Message that is displayed if you incorrectly enter your password
 */
#ifndef INCORRECT_PASSWORD
#  define INCORRECT_PASSWORD	"Sorry, try again."
#endif

/*
 *  If the MAILER macro is changed make sure it will work in logging.c,
 *  there is some sendmail mail specific stuff in the send_mail() routine
 *  ( e.g.  the argv for the execvp() ).  MAILER should ALWAYS be fully
 *  quallified.  (_PATH_SENDMAIL defined in pathanmes.h)
 *  If you do *not* run sendmail or another mailer, comment out the
 *  #define MAILER below.
 */
#ifndef MAILER
#  define MAILER		_PATH_SENDMAIL
#endif

/*
 *  Subject of the mail sent to ALERTMAIL
 */
#ifndef MAILSUBJECT
#  define MAILSUBJECT		"*** SECURITY information ***"
#endif

/*
 *  Recipient of mail from sudo
 */
#ifndef ALERTMAIL
#  define ALERTMAIL		"root"
#endif

/*
 *  Location of the editor
 */
#ifndef EDITOR
#  define EDITOR		_PATH_VI
#endif

/*
 *  Uncomment to hardcode the PATH envariable in sudo
 */
/*#define SECURE_PATH		"/bin:/usr/ucb:/usr/bin:/usr/etc:/etc" /**/

/*
 *  Umask that sudo should use, change the "#define" to an "#undef"
 *  to preserve the umask of the caller.
 */
#ifndef UMASK
#  define UMASK			022
#endif /* UMASK */

/**********  You probably don't want to modify anything below here  ***********/

#ifdef USE_EXECV
#  define EXEC	execv
#else
#  define EXEC	execvp
#endif /* USE_EXECV */

/*
 * Some systems (ie ISC V/386) do not define MAXPATHLEN even in param.h
 */
#ifndef MAXPATHLEN
#  define MAXPATHLEN		1024
#endif

/*
 * Some systems do not define MAXHOSTNAMELEN.
 */
#ifndef MAXHOSTNAMELEN
#  define MAXHOSTNAMELEN	64
#endif

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
 * Syslog(3) parameters
 */

#ifdef SYSLOG
#  include <syslog.h>
#  ifndef Syslog_ident
#    define Syslog_ident	"sudo"
#  endif
#  ifndef Syslog_options
#    define Syslog_options	0
#  endif
#  if !defined(Syslog_facility) && defined(LOG_LOCAL2)
#    define Syslog_facility	LOG_LOCAL2
#  endif
#  ifndef Syslog_priority_OK
#    define Syslog_priority_OK	LOG_NOTICE
#  endif
#  ifndef Syslog_priority_NO
#    define Syslog_priority_NO	LOG_ALERT
#  endif
#  ifndef BOTH_LOGS
#    undef			_PATH_SUDO_LOGFILE
#  endif
#endif	/* SYSLOG  */

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

/*
 * Maximum number of characters per physical log file line.
 * This is only used if you are logging to a file.  It basically
 * just means "wrap lines after MAXLOGFILELEN characters."
 * Word wrapping is done where possible.  If you don't want word
 * wrap, set this to be MAXLOGLEN.
 */
#ifndef MAXLOGFILELEN
#  define MAXLOGFILELEN		80
#endif

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


/*
 * Emulate seteuid() and setegid() for HP-UX
 */
#ifdef __hpux
#  define seteuid(__EUID)	(setresuid((uid_t)-1, __EUID, (uid_t)-1))
#  define setegid(__EGID)	(setresgid((gid_t)-1, __EGID, (gid_t)-1))
#endif	/* __hpux */

/*
 * Emulate seteuid() and setegid() for AIX
 */
#ifdef _AIX
#  define seteuid(__EUID)	(setuidx(ID_EFFECTIVE|ID_REAL, __EUID))
#  define setegid(__EGID)	(setgidx(ID_EFFECTIVE|ID_REAL, __EGID))
#endif	/* _AIX */

#endif /* _SUDO_SUDO_H */
