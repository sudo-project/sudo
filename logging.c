/*
 * Copyright (c) 1994-1996,1998-1999 Todd C. Miller <Todd.Miller@courtesan.com>
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
 */

#include "config.h"

#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <pwd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "sudo.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

#if (LOGGING & SLOG_SYSLOG)
static void do_syslog		__P((int, char *));
#endif
#if (LOGGING & SLOG_FILE)
static void do_logfile		__P((char *));
#endif
static void send_mail		__P((char *));

#if (LOGGING & SLOG_SYSLOG)
# ifdef BROKEN_SYSLOG
#  define MAXSYSLOGTRIES	16	/* num of retries for broken syslogs */
#  define SYSLOG		syslog_wrapper

static void syslog_wrapper	__P((int, char *, char *, char *));

/*
 * Some versions of syslog(3) don't guarantee success and return
 * an int (notably HP-UX < 10.0).  So, if at first we don't succeed,
 * try, try again...
 */
static void
syslog_wrapper(pri, fmt, ap)
    int pri;
    const char *fmt;
    va_list ap;
{
    int i;

    for (i = 0; i < MAXSYSLOGTRIES; i++)
	if (vsyslog(pri, fmt, ap) == 0)
	    break;
}
# else
#  define SYSLOG		syslog
# endif /* BROKEN_SYSLOG */

/*
 * Log a message to syslog, pre-pending the username and splitting the
 * message into parts if it is longer than MAXSYSLOGLEN.
 */
static void
do_syslog(pri, msg)
    int pri;
    char *msg;
{
    int count;
    char *p;
    char *tmp;
    char save;

    /*
     * Log the full line, breaking into multiple syslog(3) calls if necessary
     */
    for (p = msg, count = 0; count < strlen(msg) / MAXSYSLOGLEN + 1; count++) {
	if (strlen(p) > MAXSYSLOGLEN) {
	    /*
	     * Break up the line into what will fit on one syslog(3) line
	     * Try to break on a word boundary if possible.
	     */
	    for (tmp = p + MAXSYSLOGLEN; tmp > p && *tmp != ' '; tmp--)
		;
	    if (tmp <= p)
		tmp = p + MAXSYSLOGLEN;

	    /* NULL terminate line, but save the char to restore later */
	    save = *tmp;
	    *tmp = '\0';

	    if (count == 0)
		SYSLOG(pri, "%8.8s : %s", user_name, p);
	    else
		SYSLOG(pri, "%8.8s : (command continued) %s", user_name, p);

	    *tmp = save;			/* restore saved character */

	    /* Eliminate leading whitespace */
	    for (p = tmp; *p != ' '; p++)
		;
	} else {
	    if (count == 0)
		SYSLOG(pri, "%8.8s : %s", user_name, p);
	    else
		SYSLOG(pri, "%8.8s : (command continued) %s", user_name, p);
	}
    }
}
#endif /* LOGGING & SLOG_SYSLOG */

#if (LOGGING & SLOG_FILE)
static void
do_logfile(msg)
    char *msg;
{
    char *full_line;
    char *beg, *oldend, *end;
    FILE *fp;
    mode_t oldmask;
    time_t now;
    int oldeuid = geteuid();
    int maxlen = MAXLOGFILELEN;

    now = time((time_t) 0);

    /* Become root if we are not already. */
    if (oldeuid)
	set_perms(PERM_ROOT, 0);

    oldmask = umask(077);
    /* XXX - lock log file */
    fp = fopen(_PATH_SUDO_LOGFILE, "a");
    (void) umask(oldmask);
    if (fp == NULL) {
	easprintf(&full_line, "Can't open log file: %s: %s",
	    _PATH_SUDO_LOGFILE, strerror(errno));
	send_mail(full_line);
	free(full_line);
    } else {
# ifndef WRAP_LOG
#  ifdef HOST_IN_LOG
	(void) fprintf(fp, "%15.15s : %s : HOST=%s : %s\n", ctime(&now) + 4,
	    user_name, user_shost, msg);
#  else
	(void) fprintf(fp, "%15.15s : %s : %s\n", ctime(&now) + 4, user_name,
	    msg);
#  endif
# else
#  ifdef HOST_IN_LOG
	easprintf(&full_line, "%15.15s : %s : HOST=%s : %s",
	    ctime(&now) + 4, user_name, user_shost, msg);
#  else
	easprintf(&full_line, "%15.15s : %s : %s", ctime(&now) + 4,
	    user_name, msg);
#  endif

	/*
	 * Print out full_line with word wrap
	 */
	beg = end = full_line;
	while (beg) {
	    oldend = end;
	    end = strchr(oldend, ' ');

	    if (maxlen > 0 && end) {
		*end = '\0';
		if (strlen(beg) > maxlen) {
		    /* too far, need to back up & print the line */

		    if (beg == (char *)full_line)
			maxlen -= 4;		/* don't indent first line */

		    *end = ' ';
		    if (oldend != beg) {
			/* rewind & print */
		    	end = oldend-1;
			while (*end == ' ')
			    --end;
			*(++end) = '\0';
			(void) fprintf(fp, "%s\n    ", beg);
			*end = ' ';
		    } else {
			(void) fprintf(fp, "%s\n    ", beg);
		    }

		    /* reset beg to point to the start of the new substring */
		    beg = end;
		    while (*beg == ' ')
			++beg;
		} else {
		    /* we still have room */
		    *end = ' ';
		}

		/* remove leading whitespace */
		while (*end == ' ')
		    ++end;
	    } else {
		/* final line */
		(void) fprintf(fp, "%s\n", beg);
		beg = NULL;			/* exit condition */
	    }
	}
	free(full_line);
# endif
	(void) fclose(fp);
    }

    if (oldeuid)
	set_perms(PERM_USER, 0);	/* relinquish root */
}
#endif /* LOGGING & SLOG_FILE */

/*
 * Two main functions, log_error() to log errors and log_auth() to
 * log allow/deny messages.
 */
void
log_auth(status, inform_user)
    int status;
    int inform_user;
{
    char *message;
    char *logline;
#if (LOGGING & SLOG_SYSLOG)
    int pri = Syslog_priority_NO;
#endif /* LOGGING & SLOG_SYSLOG */

    /* Set error message, if any. */
    switch (status) {
	case VALIDATE_OK:
	case VALIDATE_OK_NOPASS:
	    message = "";
	    break;
	case VALIDATE_NO_USER:
	    message = "user NOT in sudoers ; ";
	    break;
	case VALIDATE_NOT_OK:
	case VALIDATE_NOT_OK_NOPASS:
	    message = "command not allowed ; ";
	    break;
	default:
	    message = "unknown error ; ";
    }

    if (user_args)
	easprintf(&logline, "%sTTY=%s ; PWD=%s ; USER=%s ; COMMAND=%s %s",
	    message, user_tty, user_cwd, user_runas, user_cmnd, user_args);
    else
	easprintf(&logline, "%sTTY=%s ; PWD=%s ; USER=%s ; COMMAND=%s",
	    message, user_tty, user_cwd, user_runas, user_cmnd);

    /*
     * Inform the user if they failed to authenticate and send a
     * copy of the error via mail if compiled with the appropriate option.
     */
    switch (status) {
	case VALIDATE_OK:
	case VALIDATE_OK_NOPASS:
#if (LOGGING & SLOG_SYSLOG)
	    pri = Syslog_priority_OK;
#endif /* LOGGING & SLOG_SYSLOG */
#ifdef SEND_MAIL_WHEN_OK
	    send_mail(logline);
#endif
	    break;
	case VALIDATE_NO_USER:
#ifdef SEND_MAIL_WHEN_NO_USER
	    send_mail(logline);
#endif
	    if (inform_user)
		(void) fprintf(stderr, "%s is not in the sudoers file.  %s",
		    user_name, "This incident will be reported.\n");
	    break;
	case VALIDATE_NOT_OK:
	case VALIDATE_NOT_OK_NOPASS:
#ifdef SEND_MAIL_WHEN_NOT_OK
	    send_mail(logline);
#endif
	    if (inform_user) {
		(void) fprintf(stderr,
		    "Sorry, user %s is not allowed to execute '%s",
		    user_name, user_cmnd);
		if (user_args) {
		    fputc(' ', stderr);
		    fputs(user_args, stderr);
		}
		(void) fprintf(stderr, "' as %s on %s.\n", user_runas, user_host);
	    }
	    break;
	default:
	    send_mail(logline);
	    if (inform_user)
		(void) fprintf(stderr, "An unknown error has occurred.\n");
	    break;
    }

    /*
     * Log to syslog and/or a file.
     */
#if (LOGGING & SLOG_SYSLOG)
    do_syslog(pri, logline);
#endif
#if (LOGGING & SLOG_FILE)
    do_logfile(logline);
#endif

    free(logline);
}

void
#ifdef __STDC__
log_error(int flags, const char *fmt, ...)
#else
log_error(va_alist)
    va_dcl
#endif
{
    int serrno = errno;
    char *message;
    char *logline;
    va_list ap;
#ifdef __STDC__
    va_start(ap, fmt);
#else
    int flags;
    const char *fmt;

    va_start(ap);
    flags = va_arg(ap, int);
    fmt = va_arg(ap, const char *);
#endif

    /* Expand printf-style format + args. */
    evasprintf(&message, fmt, ap);
    va_end(ap);

    if (flags & MSG_ONLY)
	logline = message;
    else if (flags & USE_ERRNO) {
	if (user_args) {
	    easprintf(&logline,
		"%s: %s ; TTY=%s ; PWD=%s ; USER=%s ; COMMAND=%s %s",
		message, strerror(serrno), user_tty, user_cwd, user_runas,
		user_cmnd, user_args);
	} else {
	    easprintf(&logline,
		"%s: %s ; TTY=%s ; PWD=%s ; USER=%s ; COMMAND=%s", message,
		strerror(serrno), user_tty, user_cwd, user_runas, user_cmnd);
	}
    } else {
	if (user_args) {
	    easprintf(&logline,
		"%s ; TTY=%s ; PWD=%s ; USER=%s ; COMMAND=%s %s", message,
		user_tty, user_cwd, user_runas, user_cmnd, user_args);
	} else {
	    easprintf(&logline,
		"%s ; TTY=%s ; PWD=%s ; USER=%s ; COMMAND=%s", message,
		user_tty, user_cwd, user_runas, user_cmnd);
	}
    }

    /*
     * Tell the user.
     */
    (void) fprintf(stderr, "%s: %s", Argv[0], message);
    if (flags & USE_ERRNO)
	(void) fprintf(stderr, ": %s", strerror(serrno));
    (void) fputc('\n', stderr);

    /*
     * Send a copy of the error via mail.
     */
    if (!(flags & NO_MAIL))
	send_mail(logline);

    /*
     * Log to syslog and/or a file.
     */
#if (LOGGING & SLOG_SYSLOG)
    do_syslog(Syslog_priority_NO, logline);
#endif
#if (LOGGING & SLOG_FILE)
    do_logfile(logline);
#endif

    free(logline);
    if (message != logline);
	free(message);

    /* Wait for mail to finish sending and exit. */
    if (!(flags & NO_EXIT)) {
	reapchild(0);
	exit(1);
    }
}

#ifdef _PATH_SENDMAIL
static void
send_mail(line)
    char *line;
{
    FILE *mail;
    char *p;
    int pfd[2], pid;
    time_t now;
#ifdef POSIX_SIGNALS
    struct sigaction sa;

    (void) memset((VOID *)&sa, 0, sizeof(sa));
#endif /* POSIX_SIGNALS */

    /* Catch children as they die... */
#ifdef POSIX_SIGNALS
    sa.sa_handler = reapchild;
    (void) sigaction(SIGCHLD, &sa, NULL);
#else
    (void) signal(SIGCHLD, reapchild);
#endif /* POSIX_SIGNALS */

    if ((pid = fork()) > 0) {	/* Child. */

	/* We do an explicit wait() later on... */
#ifdef POSIX_SIGNALS
	sa.sa_handler = SIG_DFL;
	(void) sigaction(SIGCHLD, &sa, NULL);
#else
	(void) signal(SIGCHLD, SIG_DFL);
#endif /* POSIX_SIGNALS */

	if (pipe(pfd) == -1) {
	    (void) fprintf(stderr, "%s: cannot open pipe failed: %s\n",
		Argv[0], strerror(errno));
	    exit(1);
	}

	switch (pid = fork()) {
	    case -1:
		/* Error. */
		/* XXX - parent will continue, return an exit val to
		   let parent know and abort? */
		(void) fprintf(stderr, "%s: cannot fork: %s\n",
		    Argv[0], strerror(errno));
		exit(1);
		break;
	    case 0:
		/* Grandchild. */
		(void) close(pfd[1]);
		(void) dup2(pfd[0], STDIN_FILENO);
		(void) close(pfd[0]);
		/* Run sendmail as invoking user, not root. */
		set_perms(PERM_FULL_USER, 0);
		execl(_PATH_SENDMAIL, "sendmail", "-t", NULL);
		_exit(127);
		break;
	}

	mail = fdopen(pfd[1], "w");
	(void) close(pfd[0]);

	/* Pipes are all setup, send message via sendmail. */
	(void) fprintf(mail, "To: %s\nSubject: ", ALERTMAIL);
	for (p = MAILSUBJECT; *p; p++) {
	    /* Expand escapes in the subject */
	    if (*p == '%' && *(p+1) != '%') {
		switch (*(++p)) {
		    case 'h':
			(void) fputs(user_host, mail);
			break;
		    case 'u':
			(void) fputs(user_name, mail);
			break;
		    default:
			p--;
			break;
		}
	    } else
		(void) fputc(*p, mail);
	}
	now = time((time_t) 0);
	p = ctime(&now) + 4;
	(void) fprintf(mail, "\n\n%s : %15.15s : %s : %s\n\n", user_host, p,
	    user_name, line);
	fclose(mail);
	reapchild(0);
	exit(0);
    } else {
	/* Parent, just return unless there is an error. */
	if (pid == -1) {
	    (void) fprintf(stderr, "%s: cannot fork: %s\n",
		Argv[0], strerror(errno));
	    exit(1);
	}
    }
}
#else
static void
send_mail(line)
    char *line;
{
    return;
}
#endif

/*
 * SIGCHLD sig handler--wait for children as they die.
 */
RETSIGTYPE
reapchild(sig)
    int sig;
{
    int status, serrno = errno;

#ifdef sudo_waitpid
    while (sudo_waitpid(-1, &status, WNOHANG) != -1)
	;
#else
    (void) wait(&status);
#endif
#ifndef POSIX_SIGNALS
    (void) signal(SIGCHLD, reapchild);
#endif /* POSIX_SIGNALS */
    errno = serrno;
}
