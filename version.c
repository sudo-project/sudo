/*
 * Copyright (c) 1996, 1998, 1999 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * 4. Products derived from this software may not be called "Sudo" nor
 *    may "Sudo" appear in their names without specific prior written
 *    permission from the author.
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
 */

#include "config.h"

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <sys/types.h>
#include <sys/param.h>

#define SYSLOG_NAMES

#include "sudo.h"
#include "version.h"
#include "auth/sudo_auth.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

#if (LOGGING & SLOG_SYSLOG) && defined(HAVE_SYSLOG_NAMES)
static char *num_to_name __P((int, CODE *));
#endif /* SLOG_SYSLOG && HAVE_SYSLOG_NAMES */

/*
 * Print version and configure info.
 */
void
print_version()
{
    extern sudo_auth auth_switch[];
    sudo_auth *auth;

    (void) printf("Sudo version %s\n", version);

    /*
     * Print compile-time options if root.
     * At some point these will all be in a structure of some kind
     * to allow overriding the defaults from sudoers.
     * XXX - reorganize for readability.
     */
    if (getuid() == 0) {
	(void) printf("\nSudoers file: %s, mode 0%o, uid %d, gid %d\n",
	    _PATH_SUDOERS, SUDOERS_MODE, SUDOERS_UID, SUDOERS_GID);
	(void) printf("Sudoers temp file: %s\n", _PATH_SUDOERS_TMP);

#ifdef NO_AUTHENTICATION
	(void) puts("No Authentication required by default.\n");
#endif

	(void) fputs("Authentication methods:", stdout);
	for (auth = auth_switch; auth->name; auth++) {
	    (void) putchar(' ');
	    (void) fputs(auth->name, stdout);
	}
	(void) putchar('\n');

	(void) fputs("Logging:\n", stdout);
#if (LOGGING & SLOG_SYSLOG)
# ifdef HAVE_SYSLOG_NAMES
	printf("    syslog: facility '%s', failures to '%s', success to '%s'\n",
	    num_to_name(LOGFAC, facilitynames),
	    num_to_name(PRI_FAILURE, prioritynames),
	    num_to_name(PRI_SUCCESS, prioritynames));
# else
	printf("    syslog: facility #%d, failures to #%d, success to #%d\n",
	    LOGFAC, PRI_FAILURE, PRI_SUCCESS);
# endif /* HAVE_SYSLOG_NAMES */
#endif /* SLOG_SYSLOG */
#if (LOGGING & SLOG_FILE)
	(void) printf("    log file: %s", _PATH_SUDO_LOGFILE);
# ifdef HOST_IN_LOG
	(void) fputs(", host in log", stdout);
# endif
# ifdef WRAP_LOG
	(void) printf(", lines wrap after %d characters", MAXLOGFILELEN);
# endif
	(void) putchar('\n');
#endif /* SLOG_FILE */

#ifdef USE_TTY_TICKETS
	(void) puts("Timestamp type: userdir/tty");
#else
	(void) puts("Timestamp type: userdir");
#endif

#if TIMEOUT
	(void) printf("Ticket file timeout: %d minutes\n", TIMEOUT);
#endif

#ifdef USE_INSULTS
	(void) fputs("Insult types:", stdout);
# ifdef CLASSIC_INSULTS
	(void) fputs(" classic", stdout);
# endif
# ifdef CSOPS_INSULTS
	(void) fputs(" CSOps", stdout);
# endif
# ifdef HAL_INSULTS
	(void) fputs(" hal", stdout);
# endif
# ifdef GOONS_INSULTS
	(void) fputs(" goons", stdout);
# endif
	(void) putchar('\n');
# else
	(void) printf("Incorrect password message: %s\n", INCORRECT_PASSWORD);
#endif

#ifdef SUDO_UMASK
	(void) printf("Umask to enforce: 0%o\n", SUDO_UMASK);
#endif

#if !defined(WITHOUT_PASSWD) && PASSWORD_TIMEOUT
	(void) printf("Password timeout: %d minutes\n", PASSWORD_TIMEOUT);
#endif

	(void) printf("Password attempts allowed: %d\n", TRIES_FOR_PASSWORD);

	(void) printf("Default user to run commands as: %s\n", RUNAS_DEFAULT);

#ifdef FQDN
	(void) puts("Fully qualified hostnames required in sudoers");
#endif

#ifdef NO_ROOT_SUDO
	(void) puts("Root may not run sudo");
#endif

#ifdef EXEMPTGROUP
	(void) printf("Users in group %s are exempt from password and PATH requirements\n", EXEMPTGROUP);
#endif

#ifdef ENV_EDITOR
	(void) printf("Default editor for visudo: %s\n", EDITOR);
#else
	(void) printf("Editor for visudo: %s\n", EDITOR);
#endif

#if defined(IGNORE_DOT_PATH) || defined(DONT_LEAK_PATH_INFO) || defined(SECURE_PATH)
	puts("$PATH options:");
#ifdef SECURE_PATH
	(void) printf("    PATH override: %s\n", SECURE_PATH);
#endif
# ifdef IGNORE_DOT_PATH
	(void) puts("    ignore '.'");
# endif
# ifdef DONT_LEAK_PATH_INFO
	(void) puts("    no information leakage");
# endif
#endif

#ifdef _PATH_SENDMAIL
	(void) printf("Mailer path: %s\n", _PATH_SENDMAIL);
	(void) printf("Send mail to: %s\n", ALERTMAIL);
	(void) printf("Mail subject: %s\n", MAILSUBJECT);
	(void) fputs("Send mail on: 'error'", stdout);
# ifdef SEND_MAIL_WHEN_NO_USER
	(void) fputs(" 'unlisted user'", stdout);
# endif
# ifdef SEND_MAIL_WHEN_NO_HOST
	(void) fputs(" 'unlisted on host'", stdout);
# endif
# ifdef SEND_MAIL_WHEN_NOT_OK
	(void) fputs(" 'authentication failure'", stdout);
# endif
	(void) putchar('\n');
#endif

#ifdef SHELL_IF_NO_ARGS
	puts("When invoked with no arguments sudo will start a shell");
#endif

#ifdef SHELL_SETS_HOME
	puts("Sudo will set $HOME to the homedir of the target user");
#endif

	(void) printf("Default password prompt: %s\n", PASSPROMPT);

	(void) fputs("Lecture user the first time they run sudo? ", stdout);
#ifndef NO_LECTURE
	(void) puts("yes");
#else
	(void) puts("no");
#endif
    }
}

#if (LOGGING & SLOG_SYSLOG) && defined(HAVE_SYSLOG_NAMES)
/*
 * Convert a syslog number to a name.  At some point in the
 * future, sudo will have its own tables internally so syslog
 * can be configured at run time.
 */
static char *
num_to_name(num, table)
    int num;
    CODE *table;
{
    CODE *t;

    for (t = table; t->c_name; t++)
	if (t->c_val == num)
	    return(t->c_name);

    return("unknown");
}
#endif /* SLOG_SYSLOG && HAVE_SYSLOG_NAMES */
