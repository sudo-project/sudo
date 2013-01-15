/*
 * Copyright (c) 1994-1996, 1998-2012 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#ifdef __TANDEM
# include <floss.h>
#endif

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_SETLOCALE
# include <locale.h>
#endif /* HAVE_SETLOCALE */
#ifdef HAVE_NL_LANGINFO
# include <langinfo.h>
#endif /* HAVE_NL_LANGINFO */
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include "sudo.h"

static void do_syslog		__P((int, char *));
static void do_logfile		__P((char *));
static void send_mail		__P((const char *fmt, ...));
static int should_mail		__P((int));
static void mysyslog		__P((int, const char *, ...));
static char *new_logline	__P((const char *, int));

extern char **NewArgv;	/* XXX - for auditing */

#define MAXSYSLOGTRIES	16	/* num of retries for broken syslogs */

/*
 * We do an openlog(3)/closelog(3) for each message because some
 * authentication methods (notably PAM) use syslog(3) for their
 * own nefarious purposes and may call openlog(3) and closelog(3).
 * Note that because we don't want to assume that all systems have
 * vsyslog(3) (HP-UX doesn't) "%m" will not be expanded.
 * Sadly this is a maze of #ifdefs.
 */
static void
#ifdef __STDC__
mysyslog(int pri, const char *fmt, ...)
#else
mysyslog(pri, fmt, va_alist)
    int pri;
    const char *fmt;
    va_dcl
#endif
{
#ifdef BROKEN_SYSLOG
    int i;
#endif
    char buf[MAXSYSLOGLEN+1];
    va_list ap;

#ifdef __STDC__
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
#ifdef LOG_NFACILITIES
    openlog("sudo", 0, def_syslog);
#else
    openlog("sudo", 0);
#endif
    vsnprintf(buf, sizeof(buf), fmt, ap);
#ifdef BROKEN_SYSLOG
    /*
     * Some versions of syslog(3) don't guarantee success and return
     * an int (notably HP-UX < 10.0).  So, if at first we don't succeed,
     * try, try again...
     */
    for (i = 0; i < MAXSYSLOGTRIES; i++)
	if (syslog(pri, "%s", buf) == 0)
	    break;
#else
    syslog(pri, "%s", buf);
#endif /* BROKEN_SYSLOG */
    va_end(ap);
    closelog();
}

#define FMT_FIRST "%8s : %s"
#define FMT_CONTD "%8s : (command continued) %s"

/*
 * Log a message to syslog, pre-pending the username and splitting the
 * message into parts if it is longer than MAXSYSLOGLEN.
 */
static void
do_syslog(pri, msg)
    int pri;
    char *msg;
{
    size_t len, maxlen;
    char *p, *tmp, save;
    const char *fmt;

#ifdef HAVE_SETLOCALE
    const char *old_locale = estrdup(setlocale(LC_ALL, NULL));
    if (!setlocale(LC_ALL, def_sudoers_locale))
	setlocale(LC_ALL, "C");
#endif /* HAVE_SETLOCALE */

    /*
     * Log the full line, breaking into multiple syslog(3) calls if necessary
     */
    fmt = FMT_FIRST;
    maxlen = MAXSYSLOGLEN - (sizeof(FMT_FIRST) - 6 + strlen(user_name));
    for (p = msg; *p != '\0'; ) {
	len = strlen(p);
	if (len > maxlen) {
	    /*
	     * Break up the line into what will fit on one syslog(3) line
	     * Try to avoid breaking words into several lines if possible.
	     */
	    tmp = memrchr(p, ' ', maxlen);
	    if (tmp == NULL)
		tmp = p + maxlen;

	    /* NULL terminate line, but save the char to restore later */
	    save = *tmp;
	    *tmp = '\0';

	    mysyslog(pri, fmt, user_name, p);

	    *tmp = save;			/* restore saved character */

	    /* Advance p and eliminate leading whitespace */
	    for (p = tmp; *p == ' '; p++)
		;
	} else {
	    mysyslog(pri, fmt, user_name, p);
	    p += len;
	}
	fmt = FMT_CONTD;
	maxlen = MAXSYSLOGLEN - (sizeof(FMT_CONTD) - 6 + strlen(user_name));
    }

#ifdef HAVE_SETLOCALE
    setlocale(LC_ALL, old_locale);
    efree((void *)old_locale);
#endif /* HAVE_SETLOCALE */
}

static void
do_logfile(msg)
    char *msg;
{
    char *full_line;
    size_t len;
    mode_t oldmask;
    time_t now;
    FILE *fp;

    oldmask = umask(077);
    fp = fopen(def_logfile, "a");
    (void) umask(oldmask);
    if (fp == NULL) {
	send_mail("Can't open log file: %s: %s", def_logfile, strerror(errno));
    } else if (!lock_file(fileno(fp), SUDO_LOCK)) {
	send_mail("Can't lock log file: %s: %s", def_logfile, strerror(errno));
    } else {
#ifdef HAVE_SETLOCALE
	const char *old_locale = estrdup(setlocale(LC_ALL, NULL));
	if (!setlocale(LC_ALL, def_sudoers_locale))
	    setlocale(LC_ALL, "C");
#endif /* HAVE_SETLOCALE */

	now = time(NULL);
	if (def_loglinelen < sizeof(LOG_INDENT)) {
	    /* Don't pretty-print long log file lines (hard to grep) */
	    if (def_log_host)
		(void) fprintf(fp, "%s : %s : HOST=%s : %s\n",
		    get_timestr(now, def_log_year), user_name, user_shost, msg);
	    else
		(void) fprintf(fp, "%s : %s : %s\n",
		    get_timestr(now, def_log_year), user_name, msg);
	} else {
	    if (def_log_host)
		len = easprintf(&full_line, "%s : %s : HOST=%s : %s",
		    get_timestr(now, def_log_year), user_name, user_shost, msg);
	    else
		len = easprintf(&full_line, "%s : %s : %s",
		    get_timestr(now, def_log_year), user_name, msg);

	    /*
	     * Print out full_line with word wrap around def_loglinelen chars.
	     */
	    writeln_wrap(fp, full_line, len, def_loglinelen);
	    efree(full_line);
	}
	(void) fflush(fp);
	(void) lock_file(fileno(fp), SUDO_UNLOCK);
	(void) fclose(fp);

#ifdef HAVE_SETLOCALE
	setlocale(LC_ALL, old_locale);
	efree((void *)old_locale);
#endif /* HAVE_SETLOCALE */
    }
}

/*
 * Log, audit and mail the denial message, optionally informing the user.
 */
void
log_denial(status, inform_user)
    int status;
    int inform_user;
{
    char *message;
    char *logline;

    /* Handle auditing first. */
    if (ISSET(status, FLAG_NO_USER | FLAG_NO_HOST))
	audit_failure(NewArgv, "No user or host");
    else
	audit_failure(NewArgv, "validation failure");

    /* Set error message. */
    if (ISSET(status, FLAG_NO_USER))
	message = "user NOT in sudoers";
    else if (ISSET(status, FLAG_NO_HOST))
	message = "user NOT authorized on host";
    else
	message = "command not allowed";

    logline = new_logline(message, 0);

    if (should_mail(status))
	send_mail("%s", logline);	/* send mail based on status */

    /* Inform the user if they failed to authenticate.  */
    if (inform_user) {
	if (ISSET(status, FLAG_NO_USER))
	    (void) fprintf(stderr, "%s is not in the sudoers file.  %s",
		user_name, "This incident will be reported.\n");
	else if (ISSET(status, FLAG_NO_HOST))
	    (void) fprintf(stderr, "%s is not allowed to run sudo on %s.  %s",
		user_name, user_shost, "This incident will be reported.\n");
	else if (ISSET(status, FLAG_NO_CHECK))
	    (void) fprintf(stderr, "Sorry, user %s may not run sudo on %s.\n",
		user_name, user_shost);
	else
	    (void) fprintf(stderr,
		"Sorry, user %s is not allowed to execute '%s%s%s' as %s%s%s on %s.\n",
		user_name, user_cmnd, user_args ? " " : "",
		user_args ? user_args : "",
		list_pw ? list_pw->pw_name : runas_pw ?
		runas_pw->pw_name : user_name, runas_gr ? ":" : "",
		runas_gr ? runas_gr->gr_name : "", user_host);
    }

    /*
     * Log via syslog and/or a file.
     */
    if (def_syslog)
	do_syslog(def_syslog_badpri, logline);
    if (def_logfile)
	do_logfile(logline);

    efree(logline);
}

/*
 * Log and audit that user was not allowed to run the command.
 */
void
log_failure(status, flags)
    int status;
    int flags;
{
    int inform_user = TRUE;

    /* The user doesn't always get to see the log message (path info). */
    if (!ISSET(status, FLAG_NO_USER | FLAG_NO_HOST) && def_path_info &&
	(flags == NOT_FOUND_DOT || flags == NOT_FOUND))
	inform_user = FALSE;
    log_denial(status, inform_user);

    if (!inform_user) {
	/*
	 * We'd like to not leak path info at all here, but that can
	 * *really* confuse the users.  To really close the leak we'd
	 * have to say "not allowed to run foo" even when the problem
	 * is just "no foo in path" since the user can trivially set
	 * their path to just contain a single dir.
	 */
	if (flags == NOT_FOUND)
	    warningx("%s: command not found", user_cmnd);
	else if (flags == NOT_FOUND_DOT)
	    warningx("ignoring `%s' found in '.'\nUse `sudo ./%s' if this is the `%s' you wish to run.", user_cmnd, user_cmnd, user_cmnd);
    }
}

/*
 * Log and audit that user was not able to authenticate themselves.
 */
void
log_auth_failure(status, tries)
    int status;
    int tries;
{
    int flags = NO_MAIL;

    /* Handle auditing first. */
    audit_failure(NewArgv, "authentication failure");

    /*
     * Do we need to send mail?
     * We want to avoid sending multiple messages for the same command
     * so if we are going to send an email about the denial, that takes
     * precedence.
     */
    if (ISSET(status, VALIDATE_OK)) {
	/* Command allowed, auth failed; do we need to send mail? */
	if (def_mail_badpass || def_mail_always)
	    flags = 0;
    } else {
	/* Command denied, auth failed; make sure we don't send mail twice. */
	if (def_mail_badpass && !should_mail(status))
	    flags = 0;
	/* Don't log the bad password message, we'll log a denial instead. */
	flags |= NO_LOG;
    }

    /*
     * If sudoers denied the command we'll log that separately.
     */
    if (ISSET(status, FLAG_BAD_PASSWORD)) {
	log_error(flags, "%d incorrect password attempt%s",
	    tries, tries == 1 ? "" : "s");
    } else if (ISSET(status, FLAG_NON_INTERACTIVE)) {
	log_error(flags, "a password is required");
    }
}

/*
 * Log and potentially mail the allowed command.
 */
void
log_allowed(status)
    int status;
{
    char *logline;

    logline = new_logline(NULL, 0);

    if (should_mail(status))
	send_mail("%s", logline);	/* send mail based on status */

    /*
     * Log via syslog and/or a file.
     */
    if (def_syslog)
	do_syslog(def_syslog_goodpri, logline);
    if (def_logfile)
	do_logfile(logline);

    efree(logline);
}

/*
 * Perform logging for log_error()/log_fatal()
 */
static void
vlog_error(flags, fmt, ap)
    int flags;
    const char *fmt;
    va_list ap;
{
    int serrno = errno;
    char *message;
    char *logline;

    /* Become root if we are not already to avoid user interference */
    set_perms(PERM_ROOT|PERM_NOEXIT);

    /* Expand printf-style format + args. */
    evasprintf(&message, fmt, ap);

    if (ISSET(flags, MSG_ONLY))
	logline = message;
    else
	logline = new_logline(message, ISSET(flags, USE_ERRNO) ? serrno : 0);

    /*
     * Tell the user.
     */
    if (!ISSET(flags, NO_STDERR)) {
	if (ISSET(flags, USE_ERRNO))
	    warning("%s", message);
	else
	    warningx("%s", message);
    }
    if (logline != message)
        efree(message);

    /*
     * Send a copy of the error via mail.
     */
    if (!ISSET(flags, NO_MAIL))
	send_mail("%s", logline);

    /*
     * Log to syslog and/or a file.
     */
    if (!ISSET(flags, NO_LOG)) {
	if (def_syslog)
	    do_syslog(def_syslog_badpri, logline);
	if (def_logfile)
	    do_logfile(logline);
    }

    efree(logline);
}

void
#ifdef __STDC__
log_error(int flags, const char *fmt, ...)
#else
log_error(flags, fmt, va_alist)
    int flags;
    const char *fmt;
    va_dcl
#endif
{
    va_list ap;

    /* Log the error. */
#ifdef __STDC__
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    vlog_error(flags, fmt, ap);
    va_end(ap);
}

void
#ifdef __STDC__
log_fatal(int flags, const char *fmt, ...)
#else
log_fatal(flags, fmt, va_alist)
    int flags;
    const char *fmt;
    va_dcl
#endif
{
    va_list ap;

    /* Log the error. */
#ifdef __STDC__
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    vlog_error(flags, fmt, ap);
    va_end(ap);

    /* Clean up and exit. */
    cleanup(0);
    exit(1);
}

#define MAX_MAILFLAGS	63

/*
 * Send a message to MAILTO user
 */
static void
#ifdef __STDC__
send_mail(const char *fmt, ...)
#else
send_mail(fmt, va_alist)
    const char *fmt;
    va_dcl
#endif
{
    FILE *mail;
    char *p;
    int fd, pfd[2], status;
    pid_t pid, rv;
    sigaction_t sa;
    va_list ap;
#ifndef NO_ROOT_MAILER
    static char *root_envp[] = {
	"HOME=/",
	"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	"LOGNAME=root",
	"USERNAME=root",
	"USER=root",
	NULL
    };
#endif /* NO_ROOT_MAILER */

    /* Just return if mailer is disabled. */
    if (!def_mailerpath || !def_mailto)
	return;

    /* Fork and return, child will daemonize. */
    switch (pid = fork()) {
	case -1:
	    /* Error. */
	    error(1, "cannot fork");
	    break;
	case 0:
	    /* Child. */
	    switch (pid = fork()) {
		case -1:
		    /* Error. */
		    mysyslog(LOG_ERR, "cannot fork: %m");
		    _exit(1);
		case 0:
		    /* Grandchild continues below. */
		    break;
		default:
		    /* Parent will wait for us. */
		    _exit(0);
	    }
	    break;
	default:
	    /* Parent. */
	    do {
#ifdef HAVE_WAITPID
		rv = waitpid(pid, &status, 0);
#else
		rv = wait(&status);
#endif
	    } while (rv == -1 && errno == EINTR);
	    return;
    }

    /* Daemonize - disassociate from session/tty. */
    if (setsid() == -1)
      warning("setsid");
    if (chdir("/") == -1)
      warning("chdir(/)");
    if ((fd = open(_PATH_DEVNULL, O_RDWR, 0644)) != -1) {
	(void) dup2(fd, STDIN_FILENO);
	(void) dup2(fd, STDOUT_FILENO);
	(void) dup2(fd, STDERR_FILENO);
    }

#ifdef HAVE_SETLOCALE
    if (!setlocale(LC_ALL, def_sudoers_locale)) {
	setlocale(LC_ALL, "C");
	efree(def_sudoers_locale);
	def_sudoers_locale = estrdup("C");
    }
#endif /* HAVE_SETLOCALE */

    /* Close password, group and other fds so we don't leak. */
    sudo_endpwent();
    sudo_endgrent();
    closefrom(STDERR_FILENO + 1);

    /* Ignore SIGPIPE in case mailer exits prematurely (or is missing). */
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGPIPE, &sa, NULL);

    if (pipe(pfd) == -1) {
	mysyslog(LOG_ERR, "cannot open pipe: %m");
	_exit(1);
    }

    switch (pid = fork()) {
	case -1:
	    /* Error. */
	    mysyslog(LOG_ERR, "cannot fork: %m");
	    _exit(1);
	    break;
	case 0:
	    {
		char *argv[MAX_MAILFLAGS + 1];
		char *mpath, *mflags;
		int i;

		/* Child, set stdin to output side of the pipe */
		if (pfd[0] != STDIN_FILENO) {
		    if (dup2(pfd[0], STDIN_FILENO) == -1) {
			mysyslog(LOG_ERR, "cannot dup stdin: %m");
			_exit(127);
		    }
		    (void) close(pfd[0]);
		}
		(void) close(pfd[1]);

		/* Build up an argv based on the mailer path and flags */
		mflags = estrdup(def_mailerflags);
		mpath = estrdup(def_mailerpath);
		if ((argv[0] = strrchr(mpath, ' ')))
		    argv[0]++;
		else
		    argv[0] = mpath;

		i = 1;
		if ((p = strtok(mflags, " \t"))) {
		    do {
			argv[i] = p;
		    } while (++i < MAX_MAILFLAGS && (p = strtok(NULL, " \t")));
		}
		argv[i] = NULL;

		/*
		 * Depending on the config, either run the mailer as root
		 * (so user cannot kill it) or as the user (for the paranoid).
		 */
#ifndef NO_ROOT_MAILER
		set_perms(PERM_ROOT|PERM_NOEXIT);
		execve(mpath, argv, root_envp);
#else
		set_perms(PERM_FULL_USER|PERM_NOEXIT);
		execv(mpath, argv);
#endif /* NO_ROOT_MAILER */
		mysyslog(LOG_ERR, "cannot execute %s: %m", mpath);
		_exit(127);
	    }
	    break;
    }

    (void) close(pfd[0]);
    mail = fdopen(pfd[1], "w");

    /* Pipes are all setup, send message. */
    (void) fprintf(mail, "To: %s\nFrom: %s\nAuto-Submitted: %s\nSubject: ",
	def_mailto, def_mailfrom ? def_mailfrom : user_name, "auto-generated");
    for (p = def_mailsub; *p; p++) {
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

#ifdef HAVE_NL_LANGINFO
    if (strcmp(def_sudoers_locale, "C") != 0)
	(void) fprintf(mail, "\nContent-Type: text/plain; charset=\"%s\"\nContent-Transfer-Encoding: 8bit", nl_langinfo(CODESET));
#endif /* HAVE_NL_LANGINFO */

    (void) fprintf(mail, "\n\n%s : %s : %s : ", user_host,
	get_timestr(time(NULL), def_log_year), user_name);
#ifdef __STDC__
    va_start(ap, fmt);
#else
    va_start(ap);
#endif
    (void) vfprintf(mail, fmt, ap);
    va_end(ap);
    fputs("\n\n", mail);

    fclose(mail);
    do {
#ifdef HAVE_WAITPID
        rv = waitpid(pid, &status, 0);
#else
        rv = wait(&status);
#endif
    } while (rv == -1 && errno == EINTR);
    _exit(0);
}

/*
 * Determine whether we should send mail based on "status" and defaults options.
 */
static int
should_mail(status)
    int status;
{

    return def_mail_always || ISSET(status, VALIDATE_ERROR) ||
	(def_mail_no_user && ISSET(status, FLAG_NO_USER)) ||
	(def_mail_no_host && ISSET(status, FLAG_NO_HOST)) ||
	(def_mail_no_perms && !ISSET(status, VALIDATE_OK));
}

#define	LL_TTY_STR	"TTY="
#define	LL_CWD_STR	"PWD="		/* XXX - should be CWD= */
#define	LL_USER_STR	"USER="
#define	LL_GROUP_STR	"GROUP="
#define	LL_ENV_STR	"ENV="
#define	LL_CMND_STR	"COMMAND="
#define	LL_TSID_STR	"TSID="

/*
 * Allocate and fill in a new logline.
 */
static char *
new_logline(message, serrno)
    const char *message;
    int serrno;
{
    size_t len = 0;
    char *evstr = NULL;
    char *errstr = NULL;
    char *line;

    /*
     * Compute line length
     */
    if (message != NULL)
	len += strlen(message) + 3;
    if (serrno) {
	errstr = strerror(serrno);
	len += strlen(errstr) + 3;
    }
    len += sizeof(LL_TTY_STR) + 2 + strlen(user_tty);
    len += sizeof(LL_CWD_STR) + 2 + strlen(user_cwd);
    if (runas_pw != NULL)
	len += sizeof(LL_USER_STR) + 2 + strlen(runas_pw->pw_name);
    if (runas_gr != NULL)
	len += sizeof(LL_GROUP_STR) + 2 + strlen(runas_gr->gr_name);
    if (sudo_user.sessid[0] != '\0')
	len += sizeof(LL_TSID_STR) + 2 + strlen(sudo_user.sessid);
    if (sudo_user.env_vars != NULL) {
	size_t evlen = 0;
	struct list_member *cur;
	for (cur = sudo_user.env_vars; cur != NULL; cur = cur->next)
	    evlen += strlen(cur->value) + 1;
	evstr = emalloc(evlen);
	evstr[0] = '\0';
	for (cur = sudo_user.env_vars; cur != NULL; cur = cur->next) {
	    strlcat(evstr, cur->value, evlen);
	    strlcat(evstr, " ", evlen);	/* NOTE: last one will fail */
	}
	len += sizeof(LL_ENV_STR) + 2 + evlen;
    }
    /* Note: we log "sudo -l command arg ..." as "list command arg ..." */
    len += sizeof(LL_CMND_STR) - 1 + strlen(user_cmnd);
    if (ISSET(sudo_mode, MODE_CHECK))
	len += sizeof("list ") - 1;
    if (user_args != NULL)
	len += strlen(user_args) + 1;

    /*
     * Allocate and build up the line.
     */
    line = emalloc(++len);
    line[0] = '\0';

    if (message != NULL) {
	if (strlcat(line, message, len) >= len ||
	    strlcat(line, errstr ? " : " : " ; ", len) >= len)
	    goto toobig;
    }
    if (serrno) {
	if (strlcat(line, errstr, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (strlcat(line, LL_TTY_STR, len) >= len ||
	strlcat(line, user_tty, len) >= len ||
	strlcat(line, " ; ", len) >= len)
	goto toobig;
    if (strlcat(line, LL_CWD_STR, len) >= len ||
	strlcat(line, user_cwd, len) >= len ||
	strlcat(line, " ; ", len) >= len)
	goto toobig;
    if (runas_pw != NULL) {
	if (strlcat(line, LL_USER_STR, len) >= len ||
	    strlcat(line, runas_pw->pw_name, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (runas_gr != NULL) {
	if (strlcat(line, LL_GROUP_STR, len) >= len ||
	    strlcat(line, runas_gr->gr_name, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (sudo_user.sessid[0] != '\0') {
	if (strlcat(line, LL_TSID_STR, len) >= len ||
	    strlcat(line, sudo_user.sessid, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
    }
    if (evstr != NULL) {
	if (strlcat(line, LL_ENV_STR, len) >= len ||
	    strlcat(line, evstr, len) >= len ||
	    strlcat(line, " ; ", len) >= len)
	    goto toobig;
	efree(evstr);
    }
    if (strlcat(line, LL_CMND_STR, len) >= len)
	goto toobig;
    if (ISSET(sudo_mode, MODE_CHECK) && strlcat(line, "list ", len) >= len)
	goto toobig;
    if (strlcat(line, user_cmnd, len) >= len)
	goto toobig;
    if (user_args != NULL) {
	if (strlcat(line, " ", len) >= len ||
	    strlcat(line, user_args, len) >= len)
	    goto toobig;
    }

    return line;
toobig:
    errorx(1, "internal error: insufficient space for log line");
}
