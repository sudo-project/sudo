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
 * 
 ****************************************************************
 *
 *  logging.c
 *
 *  this file supports the general logging facilities
 *  if you want to change any error messages, this is probably
 *  the place to be...
 *
 *  Jeff Nieusma   Thu Mar 21 23:39:04 MST 1991
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include "sudo.h"

void log_error();
void readchild();
static void send_mail();
static void reapchild();
static int appropriate();

static char logline[MAXLOGLEN + 8];

/**********************************************************************
 *
 *  log_error()
 *
 *  This function attempts to deliver mail to ALERTMAIL and either
 *  syslogs the error or writes it to the log file
 */

void log_error(code)
    int code;
{
    char cwd[MAXPATHLEN + 1];
    int argc;
    char **argv;
    register char *p;
    register int count;
#ifndef SYSLOG
    register FILE *fp;
    time_t now;
#else
    register int pri;		/* syslog priority */
#endif

    /*
     * there is no need to log the date and time twice if using syslog
     */
#ifndef SYSLOG
    now = time((time_t) 0);
    (void) sprintf(logline, "%19.19s : %8.8s : ", ctime(&now), user);
#else
    (void) sprintf(logline, "%8.8s : ", user);
#endif

    /*
     * we need a pointer to the end of logline
     */
    p = logline + strlen(logline);

    /*
     * so we know where we are...
     */
#ifdef USE_CWD
    getcwd(cwd, (size_t) (MAXPATHLEN + 1));
#else
    getwd(cwd);
#endif

    switch (code) {

	case ALL_SYSTEMS_GO:
	    (void) sprintf(p, "PWD=%s ; COMMAND=", cwd);
#ifdef SYSLOG
	    pri = Syslog_priority_OK;
#endif
	    break;

	case VALIDATE_NO_USER:
	    (void) sprintf(p, "user NOT in sudoers ; PWD=%s ; COMMAND=", cwd);
#ifdef SYSLOG
	    pri = Syslog_priority_NO;
#endif
	    break;

	case VALIDATE_NOT_OK:
	    (void) sprintf(p, "command not allowed ; PWD=%s ; COMMAND=", cwd);
#ifdef SYSLOG
	    pri = Syslog_priority_NO;
#endif
	    break;

	case VALIDATE_ERROR:
	    (void) sprintf(p, "error in %s ; PWD=%s ; command: ", SUDOERS, cwd);
#ifdef SYSLOG
	    pri = Syslog_priority_NO;
#endif
	    break;

	case GLOBAL_NO_PW_ENT:
	    (void) sprintf(p, "There is no /etc/passwd entry for uid %d.  ",
		uid);
#ifdef SYSLOG
	    pri = Syslog_priority_NO;
#endif
	    break;

	case PASSWORD_NOT_CORRECT:
	    (void) sprintf(p, "%d incorrect passwords ; PWD=%s ; COMMAND=",
		    TRIES_FOR_PASSWORD, cwd);
#ifdef SYSLOG
	    pri = Syslog_priority_NO;
#endif
	    break;

	case GLOBAL_NO_HOSTNAME:
	    strcat(p, "This machine does not have a hostname ");
#ifdef SYSLOG
	    pri = Syslog_priority_NO;
#endif
	    break;

	case NO_SUDOERS_FILE:
	    switch (errno) {
		case ENOENT:
		    (void) sprintf(p, "There is no %s file.  ", SUDOERS);
		    break;
		case EACCES:
		    (void) sprintf(p, "%s needs to run setuid root.  ",
			Argv[0]);
		    break;
		default:
		    (void) sprintf(p, "There is a problem opening %s ",
			SUDOERS);
		    break;
	    }
#ifdef SYSLOG
	    pri = Syslog_priority_NO;
#endif
	    break;

	case GLOBAL_HOST_UNREGISTERED:
	    (void) sprintf(p, "gethostbyname() cannot find host %s ", host);
#ifdef SYSLOG
	    pri = Syslog_priority_NO;
#endif
	    break;

	default:
	    strcat(p, "found a wierd error : ");
#ifdef SYSLOG
	    pri = Syslog_priority_NO;
#endif
	    break;
    }


    /*
     * if this error is from load_globals() don't put  argv in the message
     */
    if (!(code & GLOBAL_PROBLEM)) {

	strcat(logline, cmnd);	/* stuff the command into the logline */
	strcat(logline, " ");

	argc = Argc - 2;
	argv = Argv;
	argv++;
	p = logline + strlen(logline);
	count = (int) (logline + MAXLOGLEN - p);

	/*
	 * now stuff as much of the rest of the line as will fit
	 */
	while (count > 0 && argc--) {
	    strncpy(p, *++argv, count);
	    strcat(p, " ");
	    p += 1 + (count < strlen(*argv) ? count : strlen(*argv));
	    count = (int) (logline + MAXLOGLEN - p);
	}
	if (count <= 0)		/* if the line is too long, */
	    strcat(p, " ... ");	/* add an elipsis to the end */

    }
    if (appropriate(code))
	send_mail();

#ifdef SYSLOG
    openlog(Syslog_ident, Syslog_options, Syslog_facility);
    syslog(pri, logline);
    closelog();
#else
    if ((fp = fopen(LOGFILE, "a")) == NULL) {
	(void) sprintf(logline, "Can\'t open log file: %s", LOGFILE);
	send_mail();
    } else {
	(void) fprintf(fp, "%s\n", logline);
	(void) fclose(fp);
    }
#endif
}



/**********************************************************************
 *
 *  send_mail()
 *
 *  This function attempts to mail to ALERTMAIL about the sudo error
 *
 */

char *exec_argv[] = {"sendmail",
		     "-t",
		     ALERTMAIL,
		     (char *) NULL};

static void send_mail()
{
    char *mailer = MAILER;
    char *subject = MAILSUBJECT;
    int fd[2];
    char buf[MAXLOGLEN + 1024];

    if ((mailer = find_path(mailer)) == NULL) {
	(void) fprintf(stderr, "%s not found\n", mailer);
	exit(1);
    }
    (void) signal(SIGCHLD, reapchild);

    if (fork())
	return;

    /*
     * we don't want any security problems ...
     */
    if (setuid(uid)) {
	perror("setuid(uid)");
	exit(1);
    }
    (void) signal(SIGHUP, SIG_IGN);
    (void) signal(SIGINT, SIG_IGN);
    (void) signal(SIGQUIT, SIG_IGN);

    if (pipe(fd)) {
	perror("send_mail: pipe");
	exit(1);
    }
    (void) dup2(fd[0], 0);
    (void) dup2(fd[1], 1);
    (void) close(fd[0]);
    (void) close(fd[1]);

    if (!fork()) {		/* child */
	(void) close(1);
	execve(mailer, exec_argv, Envp);

	/* this should not happen */
	perror("execve");
	exit(1);
    } else {			/* parent */
	(void) close(0);

	/* feed the data to sendmail */
	(void) sprintf(buf, "To: %s\nSubject: %s\n\n%s\n\n",
		ALERTMAIL, subject, logline);
	write(1, buf, strlen(buf));
	close(1);

	exit(0);
    }
}



/****************************************************************
 *
 *  reapchild()
 *
 *  This function gets rid fo all the ugly zombies
 */

static void reapchild()
{
        (void) wait(NULL);
}



/**********************************************************************
 *
 *  inform_user ()
 *
 *  This function lets the user know what is happening 
 *  when an error occurs
 */

void inform_user(code)
    int code;
{

    switch (code) {
	case VALIDATE_NO_USER:
	    (void) fprintf(stderr,
		    "%s is not in the sudoers file.  This incident will be reported.\n\n",
		    user);
	    break;

	case VALIDATE_NOT_OK:
	    (void) fprintf(stderr,
		    "Sorry, user %s is not allowed to execute %s\n\n",
		    user, cmnd);
	    break;

	case VALIDATE_ERROR:
	    (void) fprintf(stderr,
		    "Sorry, there is a fatal error in the sudoers file.\n\n");
	    break;

	case GLOBAL_NO_PW_ENT:
	    (void) fprintf(stderr,
		    "Intruder Alert!  You don\'t exist in the passwd file\n\n");
	    break;

	case GLOBAL_NO_HOSTNAME:
	    (void) fprintf(stderr,
		    "This machine does not have a hostname\n\n");
	    break;

	case GLOBAL_HOST_UNREGISTERED:
	    (void) fprintf(stderr,
		    "This machine is not available via gethostbyname()\n\n");
	    break;

	case PASSWORD_NOT_CORRECT:
	    (void) fprintf(stderr, "Password not entered correctly after %d tries\n\n",
		    TRIES_FOR_PASSWORD);
	    break;

	default:
	    (void) fprintf(stderr,
		    "Something wierd happened.\n\n");
	    break;
    }
}



/****************************************************************
 *
 *  appropriate()
 *
 *  This function determines whether to send mail or not...
 */

static int appropriate(code)
    int code;
{

    switch (code) {

    /* 
     * these will NOT send mail
     */
    case VALIDATE_OK:
    case PASSWORD_NOT_CORRECT:
/*  case ALL_SYSTEMS_GO:               this is the same as OK */
	return (0);
	break;

    case VALIDATE_NO_USER:
#ifdef SEND_MAIL_WHEN_NO_USER
	return (1);
#else
	return (0);
#endif
	break;

    case VALIDATE_NOT_OK:
#ifdef SEND_MAIL_WHEN_NOT_OK
	return (1);
#else
	return (0);
#endif
	break;

    /*
     * these WILL send mail
     */
    case VALIDATE_ERROR:
    case NO_SUDOERS_FILE:
    default:
	return (1);
	break;

    }
}
