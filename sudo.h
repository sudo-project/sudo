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
 *  If you make modifications to the source, we would be happy to have
 *  them to include in future releases.  Feel free to send them to:
 *      Jeff Nieusma                       nieusma@rootgroup.com
 *      3959 Arbol CT                      (303) 447-8093
 *      Boulder, CO 80301-1752             
 */

/*        The following macros can be defined when compiling

          FQDN                   - if you have fully qualified hostnames
                                   in your SUDOERS files

          SYSLOG                 - if you want to use syslog instead
                                   of a log file
				   ( This is a nice feature.  You can 
				     collect all you sudo logs at a
				     central host.  The default is for
				     sudo to log at the local2 facility. )

          SEND_MAIL_WHEN_NOT_OK  - if you want a message sent to ALERTMAIL
                                   when the user is in the SUDOERS but
                                   does not have permission to execute
                                   the command entered
				   ( This can be used at paranoid sites )

          SEND_MAIL_WHEN_NO_USER - if you want a message sent to ALERTMAIL
				   when the user is not in the SUDOERS file
				   ( This is generally the case )

          BROKEN_GETPASS         - if your os has a broken version of getpass()
				   sysV and variants are suspect.  Test by
				   doing an rsh host "sudo echo hi" when
				   the timestamp has expired and if it doesn't
				   prompt for a passwd you need to defined this.
				   HP-UX, AIX, and IRIX need this defined.
				   You'll probably want it if you are a sysV
				   based unix. To test, compile w/o it and try:
				   rsh hostname "sudo whoami" and see if getpass
				   will read from stdin as well as /dev/tty.
				   If not, define BROKEN_GETPASS.
*/


#ifndef TIMEDIR
#define TIMEDIR "/tmp/.odus"
#endif

#ifndef TIMEOUT
#define TIMEOUT 5
#endif

#ifndef TRIES_FOR_PASSWORD
#define TRIES_FOR_PASSWORD 3
#endif

#ifndef INCORRECT_PASSWORD
#define INCORRECT_PASSWORD "Sorry, try again."
#endif

/*
 *  If the MAILER macro is changed make sure it will work in
 *  logging.c  --  there is some sendmail mail specific stuff in
 *  the send_mail() routine  ( e.g.  the argv for the execv() )
 *  MAILER should ALWAYS be fully quallified.
 */

#ifndef MAILER
#define MAILER "/usr/lib/sendmail"
#endif

#ifndef MAILSUBJECT
#define MAILSUBJECT "*** SECURITY information ***"
#endif

#ifndef ALERTMAIL
#define ALERTMAIL "root"
#endif

#ifndef SUDOERS
#define SUDOERS "/etc/sudoers"
#endif

#ifndef TMPSUDOERS
#define TMPSUDOERS "/etc/stmp"
#endif

#ifndef EDITOR
#define EDITOR "/usr/ucb/vi"
#endif

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define MAXCOMMANDLENGTH         0x030

typedef union {
    int int_val;
    char char_val[MAXCOMMANDLENGTH];
    } YYSTYPE;

typedef struct list {
    int type;
    char op;
    char *data;
    struct list *next;
    } LIST, *LINK;

#ifndef hpux
YYSTYPE yylval, yyval;
#else
YYSTYPE yylval;
#endif



 
#ifdef SYSLOG   /* SYSLOG should be defined in the makefile */
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
#endif  /* /var vs. /usr */
#endif  /* LOGFILE */
#endif  /* SYSLOG  */

                       /* Maximum number of characters to log per entry. */
#ifndef MAXLOGLEN      /* The syslogger will log this much, after that,  */
#define MAXLOGLEN 990  /* it truncates the log line. We need this here   */
#endif                 /* to make sure that we get ellipses when the log */
		       /* line is longer than 990 characters.            */


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
char *find_path();
char *strdup();
void load_globals();
void log_error();
void inform_user();
void check_user();
int validate();

/* Most of these variables are declared in main() so they don't need
 * to be extern'ed here if this is main...
 */
#ifndef MAIN
#ifdef MULTIMAX
extern unsigned short uid;
#else
extern uid_t uid;
#endif
extern char *host;
extern char *user;
extern char *cmnd;
extern char **Argv;
extern int  Argc;
#endif
extern int errno;

/* This is to placate hpux */
#ifdef hpux
#define setruid(__RUID)  (setresuid((uid_t)(__RUID), (uid_t) -1, (uid_t) -1))
#define getdtablesize()  (sysconf(_SC_OPEN_MAX))
#endif
