/*
 * Copyright (c) 1994-1996, 1998-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef HAVE_NL_LANGINFO
# include <langinfo.h>
#endif /* HAVE_NL_LANGINFO */
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>

#include "sudoers.h"

/* Special message for log_warning() so we know to use ngettext() */
#define INCORRECT_PASSWORD_ATTEMPT	((char *)0x01)

static void do_syslog(int, char *);
static void do_logfile(char *);
static void send_mail(const char *fmt, ...);
static int should_mail(int);
static void mysyslog(int, const char *, ...);
static char *new_logline(const char *, int);

extern char **NewArgv; /* XXX - for auditing */

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
mysyslog(int pri, const char *fmt, ...)
{
#ifdef BROKEN_SYSLOG
    int i;
#endif
    char buf[MAXSYSLOGLEN+1];
    va_list ap;
    debug_decl(mysyslog, SUDO_DEBUG_LOGGING)

    va_start(ap, fmt);
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
    debug_return;
}

/*
 * Log a message to syslog, pre-pending the username and splitting the
 * message into parts if it is longer than MAXSYSLOGLEN.
 */
static void
do_syslog(int pri, char *msg)
{
    size_t len, maxlen;
    char *p, *tmp, save;
    const char *fmt;
    int oldlocale;
    debug_decl(do_syslog, SUDO_DEBUG_LOGGING)

    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    /*
     * Log the full line, breaking into multiple syslog(3) calls if necessary
     */
    fmt = _("%8s : %s");
    maxlen = MAXSYSLOGLEN - (strlen(fmt) - 5 + strlen(user_name));
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
	fmt = _("%8s : (command continued) %s");
	maxlen = MAXSYSLOGLEN - (strlen(fmt) - 5 + strlen(user_name));
    }

    sudoers_setlocale(oldlocale, NULL);

    debug_return;
}

static void
do_logfile(char *msg)
{
    char *full_line;
    size_t len;
    mode_t oldmask;
    int oldlocale;
    FILE *fp;
    debug_decl(do_logfile, SUDO_DEBUG_LOGGING)

    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    oldmask = umask(077);
    fp = fopen(def_logfile, "a");
    (void) umask(oldmask);
    if (fp == NULL) {
	send_mail(_("unable to open log file: %s: %s"),
	    def_logfile, strerror(errno));
    } else if (!lock_file(fileno(fp), SUDO_LOCK)) {
	send_mail(_("unable to lock log file: %s: %s"),
	    def_logfile, strerror(errno));
    } else {
	const char *timestr = get_timestr(time(NULL), def_log_year);
	if (timestr == NULL)
	    timestr = "invalid date";
	if ((size_t)def_loglinelen < sizeof(LOG_INDENT)) {
	    /* Don't pretty-print long log file lines (hard to grep) */
	    if (def_log_host) {
		(void) fprintf(fp, "%s : %s : HOST=%s : %s\n",
		    timestr, user_name, user_srunhost, msg);
	    } else {
		(void) fprintf(fp, "%s : %s : %s\n", timestr, user_name, msg);
	    }
	} else {
	    if (def_log_host) {
		len = easprintf(&full_line, "%s : %s : HOST=%s : %s",
		    timestr, user_name, user_srunhost, msg);
	    } else {
		len = easprintf(&full_line, "%s : %s : %s",
		    timestr, user_name, msg);
	    }

	    /*
	     * Print out full_line with word wrap around def_loglinelen chars.
	     */
	    writeln_wrap(fp, full_line, len, def_loglinelen);
	    efree(full_line);
	}
	(void) fflush(fp);
	(void) lock_file(fileno(fp), SUDO_UNLOCK);
	(void) fclose(fp);
    }
    sudoers_setlocale(oldlocale, NULL);

    debug_return;
}

/*
 * Log, audit and mail the denial message, optionally informing the user.
 */
void
log_denial(int status, bool inform_user)
{
    const char *message;
    char *logline;
    int oldlocale;
    debug_decl(log_denial, SUDO_DEBUG_LOGGING)

    /* Handle auditing first (audit_failure() handles the locale itself). */
    if (ISSET(status, FLAG_NO_USER | FLAG_NO_HOST))
	audit_failure(NewArgv, N_("No user or host"));
    else
	audit_failure(NewArgv, N_("validation failure"));

    /* Log and mail messages should be in the sudoers locale. */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    /* Set error message. */
    if (ISSET(status, FLAG_NO_USER))
	message = _("user NOT in sudoers");
    else if (ISSET(status, FLAG_NO_HOST))
	message = _("user NOT authorized on host");
    else
	message = _("command not allowed");

    logline = new_logline(message, 0);

    /* Become root if we are not already. */
    set_perms(PERM_ROOT|PERM_NOEXIT);

    if (should_mail(status))
	send_mail("%s", logline);	/* send mail based on status */

    /*
     * Log via syslog and/or a file.
     */
    if (def_syslog)
	do_syslog(def_syslog_badpri, logline);
    if (def_logfile)
	do_logfile(logline);

    restore_perms();

    efree(logline);

    /* Restore locale. */
    sudoers_setlocale(oldlocale, NULL);

    /* Inform the user if they failed to authenticate (in their locale).  */
    if (inform_user) {
	sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);

	if (ISSET(status, FLAG_NO_USER)) {
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("%s is not in the sudoers "
		"file.  This incident will be reported.\n"), user_name);
	} else if (ISSET(status, FLAG_NO_HOST)) {
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("%s is not allowed to run sudo "
		"on %s.  This incident will be reported.\n"),
		user_name, user_srunhost);
	} else if (ISSET(status, FLAG_NO_CHECK)) {
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("Sorry, user %s may not run "
		"sudo on %s.\n"), user_name, user_srunhost);
	} else {
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("Sorry, user %s is not allowed "
		"to execute '%s%s%s' as %s%s%s on %s.\n"),
		user_name, user_cmnd, user_args ? " " : "",
		user_args ? user_args : "",
		list_pw ? list_pw->pw_name : runas_pw ?
		runas_pw->pw_name : user_name, runas_gr ? ":" : "",
		runas_gr ? runas_gr->gr_name : "", user_host);
	}
	sudoers_setlocale(oldlocale, NULL);
    }
    debug_return;
}

/*
 * Log and audit that user was not allowed to run the command.
 */
void
log_failure(int status, int flags)
{
    bool inform_user = true;
    debug_decl(log_failure, SUDO_DEBUG_LOGGING)

    /* The user doesn't always get to see the log message (path info). */
    if (!ISSET(status, FLAG_NO_USER | FLAG_NO_HOST) && def_path_info &&
	(flags == NOT_FOUND_DOT || flags == NOT_FOUND))
	inform_user = false;
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
	    warningx(U_("%s: command not found"), user_cmnd);
	else if (flags == NOT_FOUND_DOT)
	    warningx(U_("ignoring `%s' found in '.'\nUse `sudo ./%s' if this is the `%s' you wish to run."), user_cmnd, user_cmnd, user_cmnd);
    }

    debug_return;
}

/*
 * Log and audit that user was not able to authenticate themselves.
 */
void
log_auth_failure(int status, unsigned int tries)
{
    int flags = NO_MAIL;
    debug_decl(log_auth_failure, SUDO_DEBUG_LOGGING)

    /* Handle auditing first. */
    audit_failure(NewArgv, N_("authentication failure"));

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
    if (ISSET(status, FLAG_BAD_PASSWORD))
	log_warning(flags, INCORRECT_PASSWORD_ATTEMPT, tries);
    else if (ISSET(status, FLAG_NON_INTERACTIVE))
	log_warning(flags, N_("a password is required"));

    debug_return;
}

/*
 * Log and potentially mail the allowed command.
 */
void
log_allowed(int status)
{
    char *logline;
    int oldlocale;
    debug_decl(log_allowed, SUDO_DEBUG_LOGGING)

    /* Log and mail messages should be in the sudoers locale. */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    logline = new_logline(NULL, 0);

    /* Become root if we are not already. */
    set_perms(PERM_ROOT|PERM_NOEXIT);

    if (should_mail(status))
	send_mail("%s", logline);	/* send mail based on status */

    /*
     * Log via syslog and/or a file.
     */
    if (def_syslog)
	do_syslog(def_syslog_goodpri, logline);
    if (def_logfile)
	do_logfile(logline);

    restore_perms();

    efree(logline);

    sudoers_setlocale(oldlocale, NULL);

    debug_return;
}

/*
 * Perform logging for log_warning()/log_fatal()
 */
static void
vlog_warning(int flags, const char *fmt, va_list ap)
{
    int oldlocale, serrno = errno;
    char *logline, *message;
    va_list ap2;
    debug_decl(vlog_error, SUDO_DEBUG_LOGGING)

    /* Need extra copy of ap for warning() below. */
    if (!ISSET(flags, NO_STDERR))
	va_copy(ap2, ap);

    /* Log messages should be in the sudoers locale. */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    /* Expand printf-style format + args (with a special case). */
    if (fmt == INCORRECT_PASSWORD_ATTEMPT) {
	unsigned int tries = va_arg(ap, unsigned int);
	easprintf(&message, ngettext("%u incorrect password attempt",
	    "%u incorrect password attempts", tries), tries);
    } else {
	evasprintf(&message, _(fmt), ap);
    }

    /* Log to debug file. */
    if (USE_ERRNO) {
	sudo_debug_printf2(NULL, NULL, 0,
	    SUDO_DEBUG_WARN|SUDO_DEBUG_ERRNO|sudo_debug_subsys, "%s", message);
    } else {
	sudo_debug_printf2(NULL, NULL, 0,
	    SUDO_DEBUG_WARN|sudo_debug_subsys, "%s", message);
    }

    if (ISSET(flags, MSG_ONLY)) {
	logline = message;
    } else {
	logline = new_logline(message, ISSET(flags, USE_ERRNO) ? serrno : 0);
        efree(message);
    }

    /* Become root if we are not already. */
    set_perms(PERM_ROOT|PERM_NOEXIT);

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

    restore_perms();

    efree(logline);

    sudoers_setlocale(oldlocale, NULL);

    /*
     * Tell the user (in their locale).
     */
    if (!ISSET(flags, NO_STDERR)) {
	sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);
	if (fmt == INCORRECT_PASSWORD_ATTEMPT) {
	    unsigned int tries = va_arg(ap2, unsigned int);
	    warningx_nodebug(ngettext("%u incorrect password attempt",
		"%u incorrect password attempts", tries), tries);
	} else {
	    if (ISSET(flags, USE_ERRNO))
		vwarning_nodebug(_(fmt), ap2);
	    else
		vwarningx_nodebug(_(fmt), ap2);
	}
	sudoers_setlocale(oldlocale, NULL);
	va_end(ap2);
    }

    debug_return;
}

void
log_warning(int flags, const char *fmt, ...)
{
    va_list ap;
    debug_decl(log_error, SUDO_DEBUG_LOGGING)

    /* Log the error. */
    va_start(ap, fmt);
    vlog_warning(flags, fmt, ap);
    va_end(ap);

    debug_return;
}

void
log_fatal(int flags, const char *fmt, ...)
{
    va_list ap;
    debug_decl(log_error, SUDO_DEBUG_LOGGING)

    /* Log the error. */
    va_start(ap, fmt);
    vlog_warning(flags, fmt, ap);
    va_end(ap);

    /* Exit the plugin. */
    sudoers_cleanup();
    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
    fatal_longjmp(1);
}

#define MAX_MAILFLAGS	63

/*
 * Send a message to MAILTO user
 */
static void
send_mail(const char *fmt, ...)
{
    FILE *mail;
    char *p;
    const char *timestr;
    int fd, pfd[2], status;
    pid_t pid, rv;
    sigaction_t sa;
    struct stat sb;
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
    debug_decl(send_mail, SUDO_DEBUG_LOGGING)

    /* Just return if mailer is disabled. */
    if (!def_mailerpath || !def_mailto)
	debug_return;

    /* Make sure the mailer exists and is a regular file. */
    if (stat(def_mailerpath, &sb) != 0 || !S_ISREG(sb.st_mode))
	debug_return;

    /* Fork and return, child will daemonize. */
    switch (pid = sudo_debug_fork()) {
	case -1:
	    /* Error. */
	    fatal(U_("unable to fork"));
	    break;
	case 0:
	    /* Child. */
	    switch (pid = fork()) {
		case -1:
		    /* Error. */
		    mysyslog(LOG_ERR, _("unable to fork: %m"));
		    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to fork: %s",
			strerror(errno));
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
		rv = waitpid(pid, &status, 0);
	    } while (rv == -1 && errno == EINTR);
	    return; /* not debug */
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

    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, NULL);

    /* Close password, group and other fds so we don't leak. */
    sudo_endpwent();
    sudo_endgrent();
    closefrom(STDERR_FILENO + 1);

    /* Ignore SIGPIPE in case mailer exits prematurely (or is missing). */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT;
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGPIPE, &sa, NULL);

    if (pipe(pfd) == -1) {
	mysyslog(LOG_ERR, _("unable to open pipe: %m"));
	sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to open pipe: %s",
	    strerror(errno));
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	_exit(1);
    }

    switch (pid = sudo_debug_fork()) {
	case -1:
	    /* Error. */
	    mysyslog(LOG_ERR, _("unable to fork: %m"));
	    sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to fork: %s",
		strerror(errno));
	    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	    _exit(1);
	    break;
	case 0:
	    {
		char *argv[MAX_MAILFLAGS + 1];
		char *mflags, *mpath = def_mailerpath;
		int i;

		/* Child, set stdin to output side of the pipe */
		if (pfd[0] != STDIN_FILENO) {
		    if (dup2(pfd[0], STDIN_FILENO) == -1) {
			mysyslog(LOG_ERR, _("unable to dup stdin: %m"));
			sudo_debug_printf(SUDO_DEBUG_ERROR,
			    "unable to dup stdin: %s", strerror(errno));
			_exit(127);
		    }
		    (void) close(pfd[0]);
		}
		(void) close(pfd[1]);

		/* Build up an argv based on the mailer path and flags */
		mflags = estrdup(def_mailerflags);
		if ((argv[0] = strrchr(mpath, '/')))
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
		mysyslog(LOG_ERR, _("unable to execute %s: %m"), mpath);
		sudo_debug_printf(SUDO_DEBUG_ERROR, "unable to execute %s: %s",
		    mpath, strerror(errno));
		_exit(127);
	    }
	    break;
    }

    (void) close(pfd[0]);
    mail = fdopen(pfd[1], "w");

    /* Pipes are all setup, send message. */
    (void) fprintf(mail, "To: %s\nFrom: %s\nAuto-Submitted: %s\nSubject: ",
	def_mailto, def_mailfrom ? def_mailfrom : user_name, "auto-generated");
    for (p = _(def_mailsub); *p; p++) {
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

    if ((timestr = get_timestr(time(NULL), def_log_year)) == NULL)
	timestr = "invalid date";
    (void) fprintf(mail, "\n\n%s : %s : %s : ", user_host, timestr, user_name);
    va_start(ap, fmt);
    (void) vfprintf(mail, fmt, ap);
    va_end(ap);
    fputs("\n\n", mail);

    fclose(mail);
    do {
        rv = waitpid(pid, &status, 0);
    } while (rv == -1 && errno == EINTR);
    sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
    _exit(0);
}

/*
 * Determine whether we should send mail based on "status" and defaults options.
 */
static int
should_mail(int status)
{
    debug_decl(should_mail, SUDO_DEBUG_LOGGING)

    debug_return_bool(def_mail_always || ISSET(status, VALIDATE_ERROR) ||
	(def_mail_no_user && ISSET(status, FLAG_NO_USER)) ||
	(def_mail_no_host && ISSET(status, FLAG_NO_HOST)) ||
	(def_mail_no_perms && !ISSET(status, VALIDATE_OK)));
}

#define	LL_TTY_STR	"TTY="
#define	LL_CWD_STR	"PWD="		/* XXX - should be CWD= */
#define	LL_USER_STR	"USER="
#define	LL_GROUP_STR	"GROUP="
#define	LL_ENV_STR	"ENV="
#define	LL_CMND_STR	"COMMAND="
#define	LL_TSID_STR	"TSID="

#define IS_SESSID(s) ( \
    isalnum((unsigned char)(s)[0]) && isalnum((unsigned char)(s)[1]) && \
    (s)[2] == '/' && \
    isalnum((unsigned char)(s)[3]) && isalnum((unsigned char)(s)[4]) && \
    (s)[5] == '/' && \
    isalnum((unsigned char)(s)[6]) && isalnum((unsigned char)(s)[7]) && \
    (s)[8] == '\0')

/*
 * Allocate and fill in a new logline.
 */
static char *
new_logline(const char *message, int serrno)
{
    char *line, *errstr = NULL, *evstr = NULL;
#ifndef SUDOERS_NO_SEQ
    char sessid[7];
#endif
    const char *tsid = NULL;
    size_t len = 0;
    debug_decl(new_logline, SUDO_DEBUG_LOGGING)

#ifndef SUDOERS_NO_SEQ
    /* A TSID may be a sudoers-style session ID or a free-form string. */
    if (sudo_user.iolog_file != NULL) {
	if (IS_SESSID(sudo_user.iolog_file)) {
	    sessid[0] = sudo_user.iolog_file[0];
	    sessid[1] = sudo_user.iolog_file[1];
	    sessid[2] = sudo_user.iolog_file[3];
	    sessid[3] = sudo_user.iolog_file[4];
	    sessid[4] = sudo_user.iolog_file[6];
	    sessid[5] = sudo_user.iolog_file[7];
	    sessid[6] = '\0';
	    tsid = sessid;
	} else {
	    tsid = sudo_user.iolog_file;
	}
    }
#endif

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
    if (tsid != NULL)
	len += sizeof(LL_TSID_STR) + 2 + strlen(tsid);
    if (sudo_user.env_vars != NULL) {
	size_t evlen = 0;
	char * const *ep;

	for (ep = sudo_user.env_vars; *ep != NULL; ep++)
	    evlen += strlen(*ep) + 1;
	evstr = emalloc(evlen);
	evstr[0] = '\0';
	for (ep = sudo_user.env_vars; *ep != NULL; ep++) {
	    strlcat(evstr, *ep, evlen);
	    strlcat(evstr, " ", evlen);	/* NOTE: last one will fail */
	}
	len += sizeof(LL_ENV_STR) + 2 + evlen;
    }
    if (user_cmnd != NULL) {
	/* Note: we log "sudo -l command arg ..." as "list command arg ..." */
	len += sizeof(LL_CMND_STR) - 1 + strlen(user_cmnd);
	if (ISSET(sudo_mode, MODE_CHECK))
	    len += sizeof("list ") - 1;
	if (user_args != NULL)
	    len += strlen(user_args) + 1;
    }

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
    if (tsid != NULL) {
	if (strlcat(line, LL_TSID_STR, len) >= len ||
	    strlcat(line, tsid, len) >= len ||
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
    if (user_cmnd != NULL) {
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
    }

    debug_return_str(line);
toobig:
    fatalx(U_("internal error: insufficient space for log line"));
}
