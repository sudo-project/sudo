/*
 * CU sudo version 1.3 (based on Root Group sudo version 1.1)
 *
 * This software comes with no waranty whatsoever, use at your own risk.
 *
 * Please send bugs, changes, problems to sudo-bugs.cs.colorado.edu
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

/*        The following macros can be defined when compiling
  
           FQDN                   - if you have fully qualified hostnames
                                    in your SUDOERS files
 
           SYSLOG                 - if you want to use syslog instead
                                    of a log file
                                    ( This is a nice feature.  You can
                                      collect all your sudo logs at a
                                      single host)
 
           NO_ROOT_SUDO           - sudo will exit if called by root
  
           SOLARIS                - define if using Solaris 2.x

           SEND_MAIL_WHEN_NOT_OK  - if you want a message sent to ALERTMAIL
                                    when the user is in the SUDOERS but
                                    does not have permission to execute
                                    the command entered
                                    ( This can be used at paranoid sites )
 
           SEND_MAIL_WHEN_NO_USER - if you want a message sent to ALERTMAIL
                                    when the user is not in the SUDOERS file
                                    ( This is generally the case )
 
           TIMEDIR                  the directory where the timestamp 
                                    files are kept.
 
           TIMEOUT                  the number of minutes that can elapse
                                    before sudo will ask for a passwd again
 
           TRIES_FOR_PASSWORD       the number of times sudo will let you
                                    guess are you password before screaming
 
           INCORRECT_PASSWORD       the message that is displayed if you 
                                    incorrectly enter your password
 
           MAILSUBJECT              the subject of the mail sent to ALERTMAIL
 
           ALERTMAIL                the recipient of mail from sudo
 
           SUDOERS                  the location of the sudoers file
 
           TMPSUDOERS               the location of the lock file for visudo
 
           EDITOR                   the location of the editor
 
           ENV_EDITOR               if this variable is defined then the
                                    EDITOR and VISUAL envariables are consulted
 
           LOGFILE                  log file location IF NOT USING SYSLOG
 
           SYSLOG                   if this variable is defined, sudo will log
                                    using the 4.3 BSD style syslog facility

           SECURE_PATH              if this variable is set, its value is
				    used as the PATH variable
 
           BROKEN_GETPASS           if using a os with a broken getpass()
                                    hpux,aix,irix need this, sudo.h has details
 
           NEED_STRDUP              if your os lacks strdup(3)
 
           USE_CWD                  if you have getcwd() and not getwd()
                                    (defined by default for hpux)

           USE_TERMIO               if you have sysV terminal control
                                    (defined by default for hpux and irix)
 
           SHORT_MESSAGE            if you don't want the full copyright message
                                    with the "we expect you have..." banner
 
           USE_INSULTS              if you want to be insulted for typing an
                                    incorrect password like the original sudo(8)
 
           HAL                      if you want lines from 2001 instead of
                                    insults (must define USE_INSULTS too)
 
           STD_HEADERS              if you have ansi-compliant header files
*/


#ifndef TIMEDIR
#define TIMEDIR			"/tmp/.odus"
#endif

#ifndef TIMEOUT
#define TIMEOUT			5
#endif

#ifndef TRIES_FOR_PASSWORD
#define TRIES_FOR_PASSWORD	3
#endif

#ifndef INCORRECT_PASSWORD
#define INCORRECT_PASSWORD	"Sorry, try again."
#endif

/*
 *  If the MAILER macro is changed make sure it will work in
 *  logging.c  --  there is some sendmail mail specific stuff in
 *  the send_mail() routine  ( e.g.  the argv for the execvp() )
 *  MAILER should ALWAYS be fully quallified.
 */

#ifndef MAILER
#define MAILER			"/usr/lib/sendmail"
#endif

#ifndef MAILSUBJECT
#define MAILSUBJECT		"*** SECURITY information ***"
#endif

#ifndef ALERTMAIL
#define ALERTMAIL		"root"
#endif

#ifndef SUDOERS
#define SUDOERS			"/etc/sudoers"
#endif

#ifndef TMPSUDOERS
#define TMPSUDOERS		"/etc/stmp"
#endif

#ifndef EDITOR
#if defined(hpux) || defined(__alpha) || defined(_AIX) || defined(__ksr__) || \
    defined(sgi)
#define EDITOR			"/usr/bin/vi"
#else
#define EDITOR			"/usr/ucb/vi"
#endif
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN		64
#endif

#define MAXCOMMANDLENGTH         MAXPATHLEN

/*#define SECURE_PATH		"/bin:/usr/ucb/:/usr/bin:/usr/etc:/etc" /**/

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

#ifndef hpux
YYSTYPE yylval, yyval;
#else
YYSTYPE yylval;
#endif

/*
 * SYSLOG should be defined in the makefile
 */
#ifdef SYSLOG
#include <syslog.h>
#ifndef Syslog_ident
#define Syslog_ident        "sudo"
#endif
#ifndef Syslog_options
#define Syslog_options      LOG_PID
#endif
#ifndef Syslog_facility
#define Syslog_facility     LOG_LOCAL2
#endif
#ifndef Syslog_priority_OK
#define Syslog_priority_OK  LOG_NOTICE
#endif
#ifndef Syslog_priority_NO
#define Syslog_priority_NO  LOG_ALERT
#endif
#else
#ifndef LOGFILE
#if defined(ultrix) || defined(sun)
#define LOGFILE "/var/adm/sudo.log"
#else
#define LOGFILE "/usr/adm/sudo.log"
#endif	/* /var vs. /usr */
#endif	/* LOGFILE */
#endif	/* SYSLOG  */

/*
 * Maximum number of characters to log per entry.
 * The syslogger will log this much, after that,
 * it truncates the log line. We need this here
 * to make sure that we get ellipses when the log
 * line is longer than 990 characters.
 */
#ifndef MAXLOGLEN
#define MAXLOGLEN 990
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

/* These are the functions that are called in sudo */
#ifdef NEED_STRDUP
char *strdup();
#endif
char *find_path();
void load_globals();
void log_error();
void inform_user();
void check_user();
void clean_envp();
int validate();
void be_root();
void be_user();
void be_full_user();

/* Most of these variables are declared in main() so they don't need
 * to be extern'ed here if this is main...
 */
#ifndef MAIN
extern uid_t uid;
extern char *host;
extern char *user;
extern char *cmnd;
extern int Argc;
extern char **Argv;
#endif
extern int errno;

/*
 * This is to placate hpux
 */
#ifdef hpux
# define getdtablesize()	(sysconf(_SC_OPEN_MAX))
# define seteuid(__EUID)	(setresuid((uid_t)-1, __EUID, (uid_t)-1))
#endif	/* hpux */

/*
 * Sun's cpp doesn't define this but it should
 */
#if defined(SOLARIS) && !defined(__svr4__)
# define __svr4__
#endif /* SOLARIS */
