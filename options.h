/*
 *  CU sudo version 1.5.7
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
 *  Please send bugs, changes, problems to sudo-bugs@courtesan.com
 *
 *  $Id$
 */

#ifndef _SUDO_OPTIONS_H
#define _SUDO_OPTIONS_H

/*
 * DANGER DANGER DANGER!
 * Before you change anything here read through the OPTIONS file
 * for a description of what this stuff does.
 */

/* User-configurable Sudo runtime options */

#define SEND_MAIL_WHEN_NO_USER	/* send mail when user not in sudoers file */
/*#define SEND_MAIL_WHEN_NOT_OK	/* send mail if no permissions to run command */
#define SHORT_MESSAGE		/* short sudo message, no copyright printed */
/*#define NO_MESSAGE		/* no sudo "lecture" message */
#define MAILSUBJECT "*** SECURITY information for %h ***" /* mail subject */
/*#define SHELL_IF_NO_ARGS	/* if sudo is given no arguments run a shell */
/*#define SHELL_SETS_HOME	/* -s sets $HOME to runas user's homedir */
/*#define OTP_ONLY		/* validate user via OTP (skey/opie) only */
/*#define STUB_LOAD_INTERFACES	/* don't try to read ether interfaces */

/**********  You probably don't want to modify anything below here  ***********/

#ifdef USE_EXECV
#  define EXEC	execv
#else
#  define EXEC	execvp
#endif /* USE_EXECV */

/*
 * syslog(3) parameters
 */

#if (LOGGING & SLOG_SYSLOG)
#  include <syslog.h>
#  ifndef Syslog_ident
#    define Syslog_ident	"sudo"
#  endif
#  ifndef Syslog_options
#    define Syslog_options	0
#  endif
#  if !defined(Syslog_facility) && defined(LOG_NFACILITIES)
#    define Syslog_facility	LOGFAC
#  endif
#  ifndef Syslog_priority_OK
#    define Syslog_priority_OK	LOG_NOTICE
#  endif
#  ifndef Syslog_priority_NO
#    define Syslog_priority_NO	LOG_ALERT
#  endif
#endif	/* LOGGING & SLOG_SYSLOG */

#endif /* _SUDO_OPTIONS_H */
