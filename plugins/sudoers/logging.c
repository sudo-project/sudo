/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1994-1996, 1998-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#ifdef __TANDEM
# include <floss.h>
#endif

#include <config.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_NL_LANGINFO
# include <langinfo.h>
#endif /* HAVE_NL_LANGINFO */
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif

#include "sudoers.h"

/* Special message for log_warning() so we know to use ngettext() */
#define INCORRECT_PASSWORD_ATTEMPT	((char *)0x01)

static bool should_mail(int);

/*
 * Log, audit and mail the denial message, optionally informing the user.
 */
bool
log_denial(int status, bool inform_user)
{
    struct eventlog evlog;
    const char *message;
    int oldlocale;
    int evl_flags = 0;
    bool mailit, ret = true;
    debug_decl(log_denial, SUDOERS_DEBUG_LOGGING);

    /* Send mail based on status. */
    mailit = should_mail(status);

    /* Set error message. */
    if (ISSET(status, FLAG_NO_USER))
	message = N_("user NOT in sudoers");
    else if (ISSET(status, FLAG_NO_HOST))
	message = N_("user NOT authorized on host");
    else
	message = N_("command not allowed");

    /* Do auditing first (audit_failure() handles the locale itself). */
    audit_failure(NewArgv, "%s", message);

    if (def_log_denied || mailit) {
	/* Log and mail messages should be in the sudoers locale. */
	sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

	if (mailit) {
	    SET(evl_flags, EVLOG_MAIL);
	    if (!def_log_denied)
		SET(evl_flags, EVLOG_MAIL_ONLY);
	}
	sudoers_to_eventlog(&evlog);
	if (!eventlog_reject(&evlog, evl_flags, message, NULL, NULL))
	    ret = false;

	/* Restore locale. */
	sudoers_setlocale(oldlocale, NULL);
    }

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
    debug_return_bool(ret);
}

/*
 * Log and audit that user was not allowed to run the command.
 */
bool
log_failure(int status, int flags)
{
    bool ret, inform_user = true;
    debug_decl(log_failure, SUDOERS_DEBUG_LOGGING);

    /* The user doesn't always get to see the log message (path info). */
    if (!ISSET(status, FLAG_NO_USER | FLAG_NO_HOST) && def_path_info &&
	(flags == NOT_FOUND_DOT || flags == NOT_FOUND))
	inform_user = false;
    ret = log_denial(status, inform_user);

    if (!inform_user) {
	/*
	 * We'd like to not leak path info at all here, but that can
	 * *really* confuse the users.  To really close the leak we'd
	 * have to say "not allowed to run foo" even when the problem
	 * is just "no foo in path" since the user can trivially set
	 * their path to just contain a single dir.
	 */
	if (flags == NOT_FOUND)
	    sudo_warnx(U_("%s: command not found"), user_cmnd);
	else if (flags == NOT_FOUND_DOT)
	    sudo_warnx(U_("ignoring \"%s\" found in '.'\nUse \"sudo ./%s\" if this is the \"%s\" you wish to run."), user_cmnd, user_cmnd, user_cmnd);
    }

    debug_return_bool(ret);
}

/*
 * Log and audit that user was not able to authenticate themselves.
 */
bool
log_auth_failure(int status, unsigned int tries)
{
    int flags = 0;
    bool ret = true;
    debug_decl(log_auth_failure, SUDOERS_DEBUG_LOGGING);

    /* Do auditing first (audit_failure() handles the locale itself). */
    audit_failure(NewArgv, "%s", N_("authentication failure"));

    /*
     * Do we need to send mail?
     * We want to avoid sending multiple messages for the same command
     * so if we are going to send an email about the denial, that takes
     * precedence.
     */
    if (ISSET(status, VALIDATE_SUCCESS)) {
	/* Command allowed, auth failed; do we need to send mail? */
	if (def_mail_badpass || def_mail_always)
	    SET(flags, SLOG_SEND_MAIL);
    } else {
	/* Command denied, auth failed; make sure we don't send mail twice. */
	if (def_mail_badpass && !should_mail(status))
	    SET(flags, SLOG_SEND_MAIL);
	/* Don't log the bad password message, we'll log a denial instead. */
	SET(flags, SLOG_NO_LOG);
    }

    /*
     * If sudoers denied the command we'll log that separately.
     */
    if (ISSET(status, FLAG_BAD_PASSWORD))
	ret = log_warningx(flags, INCORRECT_PASSWORD_ATTEMPT, tries);
    else if (ISSET(status, FLAG_NON_INTERACTIVE))
	ret = log_warningx(flags, N_("a password is required"));

    debug_return_bool(ret);
}

/*
 * Log and potentially mail the allowed command.
 */
bool
log_allowed(void)
{
    struct eventlog evlog;
    int oldlocale;
    int evl_flags = 0;
    bool mailit, ret = true;
    debug_decl(log_allowed, SUDOERS_DEBUG_LOGGING);

    /* Send mail based on status. */
    mailit = should_mail(VALIDATE_SUCCESS);

    if (def_log_allowed || mailit) {
	/* Log and mail messages should be in the sudoers locale. */
	sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

	sudoers_to_eventlog(&evlog);
	if (mailit) {
	    SET(evl_flags, EVLOG_MAIL);
	    if (!def_log_allowed)
		SET(evl_flags, EVLOG_MAIL_ONLY);
	}
	if (!eventlog_accept(&evlog, evl_flags, NULL, NULL))
	    ret = false;

	sudoers_setlocale(oldlocale, NULL);
    }

    debug_return_bool(ret);
}

/*
 * Format an authentication failure message, using either
 * authfail_message from sudoers or a locale-specific message.
 */
static int
fmt_authfail_message(char **str, va_list ap)
{
    unsigned int tries = va_arg(ap, unsigned int);
    char *src, *dst0, *dst, *dst_end;
    size_t size;
    int len;
    debug_decl(fmt_authfail_message, SUDOERS_DEBUG_LOGGING);

    if (def_authfail_message == NULL) {
	debug_return_int(asprintf(str, ngettext("%u incorrect password attempt",
	    "%u incorrect password attempts", tries), tries));
    }

    src = def_authfail_message;
    size = strlen(src) + 33;
    if ((dst0 = dst = malloc(size)) == NULL)
	debug_return_int(-1);
    dst_end = dst + size;

    /* Always leave space for the terminating NUL. */
    while (*src != '\0' && dst + 1 < dst_end) {
	if (src[0] == '%') {
	    switch (src[1]) {
	    case '%':
		src++;
		break;
	    case 'd':
		len = snprintf(dst, dst_end - dst, "%u", tries);
		if (len < 0 || len >= (int)(dst_end - dst))
		    goto done;
		dst += len;
		src += 2;
		continue;
	    default:
		break;
	    }
	}
	*dst++ = *src++;
    }
done:
    *dst = '\0';

    *str = dst0;
#ifdef __clang_analyzer__
    /* clang analyzer false positive */
    if (__builtin_expect(dst < dst0, 0))
	__builtin_trap();
#endif
    debug_return_int(dst - dst0);
}

/*
 * Perform logging for log_warning()/log_warningx().
 */
static bool
vlog_warning(int flags, int errnum, const char *fmt, va_list ap)
{
    struct eventlog evlog;
    struct timespec now;
    const char *errstr = NULL;
    char *message;
    bool ret = true;
    int len, oldlocale;
    int evl_flags = 0;
    va_list ap2;
    debug_decl(vlog_warning, SUDOERS_DEBUG_LOGGING);

    /* Do auditing first (audit_failure() handles the locale itself). */
    if (ISSET(flags, SLOG_AUDIT)) {
	va_copy(ap2, ap);
	vaudit_failure(NewArgv, fmt, ap2);
	va_end(ap2);
    }

    /* Need extra copy of ap for sudo_vwarn()/sudo_vwarnx() below. */
    va_copy(ap2, ap);

    /* Log messages should be in the sudoers locale. */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    /* Expand printf-style format + args (with a special case). */
    if (fmt == INCORRECT_PASSWORD_ATTEMPT) {
	len = fmt_authfail_message(&message, ap);
    } else {
	len = vasprintf(&message, _(fmt), ap);
    }
    if (len == -1) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	ret = false;
	goto done;
    }

    if (ISSET(flags, SLOG_USE_ERRNO))
	errstr = strerror(errnum);
    else if (ISSET(flags, SLOG_GAI_ERRNO))
	errstr = gai_strerror(errnum);

    /* Log to debug file. */
    if (errstr != NULL) {
	sudo_debug_printf2(NULL, NULL, 0,
	    SUDO_DEBUG_WARN|sudo_debug_subsys, "%s: %s", message, errstr);
    } else {
	sudo_debug_printf2(NULL, NULL, 0,
	    SUDO_DEBUG_WARN|sudo_debug_subsys, "%s", message);
    }

    if (ISSET(flags, SLOG_SEND_MAIL) || !ISSET(flags, SLOG_NO_LOG)) {
	if (sudo_gettime_real(&now) == -1) {
	    sudo_warn("%s", U_("unable to get time of day"));
	    goto done;
	}
	if (ISSET(flags, SLOG_RAW_MSG))
	    SET(evl_flags, EVLOG_RAW);
	if (ISSET(flags, SLOG_SEND_MAIL)) {
	    SET(evl_flags, EVLOG_MAIL);
	    if (ISSET(flags, SLOG_NO_LOG))
		SET(evl_flags, EVLOG_MAIL_ONLY);
	}
	sudoers_to_eventlog(&evlog);
	eventlog_alert(&evlog, evl_flags, &now, message, errstr);
    }

    /*
     * Tell the user (in their locale).
     */
    if (!ISSET(flags, SLOG_NO_STDERR)) {
	sudoers_setlocale(SUDOERS_LOCALE_USER, NULL);
	if (fmt == INCORRECT_PASSWORD_ATTEMPT) {
	    len = fmt_authfail_message(&message, ap2);
	    if (len == -1) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		ret = false;
		goto done;
	    }
	    sudo_warnx_nodebug("%s", message);
	    free(message);
	} else {
	    if (ISSET(flags, SLOG_USE_ERRNO)) {
		errno = errnum;
		sudo_vwarn_nodebug(_(fmt), ap2);
	    } else if (ISSET(flags, SLOG_GAI_ERRNO)) {
		sudo_gai_vwarn_nodebug(errnum, _(fmt), ap2);
	    } else
		sudo_vwarnx_nodebug(_(fmt), ap2);
	}
    }

done:
    va_end(ap2);
    sudoers_setlocale(oldlocale, NULL);

    debug_return_bool(ret);
}

bool
log_warning(int flags, const char *fmt, ...)
{
    va_list ap;
    bool ret;
    debug_decl(log_warning, SUDOERS_DEBUG_LOGGING);

    /* Log the error. */
    va_start(ap, fmt);
    ret = vlog_warning(flags|SLOG_USE_ERRNO, errno, fmt, ap);
    va_end(ap);

    debug_return_bool(ret);
}

bool
log_warningx(int flags, const char *fmt, ...)
{
    va_list ap;
    bool ret;
    debug_decl(log_warningx, SUDOERS_DEBUG_LOGGING);

    /* Log the error. */
    va_start(ap, fmt);
    ret = vlog_warning(flags, 0, fmt, ap);
    va_end(ap);

    debug_return_bool(ret);
}

bool
gai_log_warning(int flags, int errnum, const char *fmt, ...)
{
    va_list ap;
    bool ret;
    debug_decl(gai_log_warning, SUDOERS_DEBUG_LOGGING);

    /* Log the error. */
    va_start(ap, fmt);
    ret = vlog_warning(flags|SLOG_GAI_ERRNO, errnum, fmt, ap);
    va_end(ap);

    debug_return_bool(ret);
}

/*
 * Determine whether we should send mail based on "status" and defaults options.
 */
static bool
should_mail(int status)
{
    debug_decl(should_mail, SUDOERS_DEBUG_LOGGING);

    debug_return_bool(def_mail_always || ISSET(status, VALIDATE_ERROR) ||
	(def_mail_all_cmnds && ISSET(sudo_mode, (MODE_RUN|MODE_EDIT))) ||
	(def_mail_no_user && ISSET(status, FLAG_NO_USER)) ||
	(def_mail_no_host && ISSET(status, FLAG_NO_HOST)) ||
	(def_mail_no_perms && !ISSET(status, VALIDATE_SUCCESS)));
}

/*
 * Build a struct eventlog from sudoers data.
 * The values in the resulting eventlog struct should not be freed.
 */
void
sudoers_to_eventlog(struct eventlog *evlog)
{
    debug_decl(sudoers_to_eventlog, SUDOERS_DEBUG_LOGGING);

    memset(evlog, 0, sizeof(*evlog));
    /* TODO: iolog_path */
    evlog->iolog_file = sudo_user.iolog_file;
    evlog->command = safe_cmnd;
    evlog->cwd = user_cwd;
    if (def_runchroot != NULL && strcmp(def_runchroot, "*") != 0) {
	evlog->runchroot = def_runchroot;
    }
    if (def_runcwd && strcmp(def_runcwd, "*") != 0) {
	evlog->runcwd = def_runcwd;
    } else if (ISSET(sudo_mode, MODE_LOGIN_SHELL)) {
	evlog->runcwd = runas_pw->pw_dir;
    } else {
	evlog->runcwd = user_cwd;
    }
    if (runas_gr != NULL) {
	evlog->rungroup = runas_gr->gr_name;
    }
    evlog->runuser = runas_pw->pw_name;
    evlog->submithost = user_host;
    evlog->submituser = user_name;
    /* TODO - submitgroup */
    evlog->ttyname = user_ttypath;
    evlog->argv = NewArgv;
    evlog->env_add = (char **)sudo_user.env_vars;
    evlog->envp = env_get();
    evlog->submit_time = sudo_user.submit_time;
    evlog->lines = sudo_user.lines;
    evlog->columns = sudo_user.cols;
    evlog->runuid = runas_pw->pw_uid;
    evlog->rungid = runas_pw->pw_gid;

    debug_return;
}

static FILE *
sudoers_log_open(int type, const char *log_file)
{
    static bool warned = false; /* XXX */
    bool uid_changed;
    FILE *fp = NULL;
    mode_t oldmask;
    debug_decl(sudoers_log_open, SUDOERS_DEBUG_DEFAULTS);

    switch (type) {
	case EVLOG_SYSLOG:
	    openlog("sudo", def_syslog_pid ? LOG_PID : 0, def_syslog);
	    break;
	case EVLOG_FILE:
	    /* Open log file as root, mode 0600. */
	    oldmask = umask(S_IRWXG|S_IRWXO);
	    uid_changed = set_perms(PERM_ROOT);
	    fp = fopen(log_file, "a");
	    if (uid_changed && !restore_perms()) {
		if (fp != NULL) {
		    fclose(fp);
		    fp = NULL;
		}
	    }
	    (void) umask(oldmask);
	    if (fp == NULL && !warned) {
		log_warning(SLOG_SEND_MAIL|SLOG_NO_LOG,
		    N_("unable to open log file: %s"), log_file);
	    }
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unsupported log type %d", type);
	    break;
    }

    debug_return_ptr(fp);
}

static void
sudoers_log_close(int type, FILE *fp)
{
    debug_decl(sudoers_log_close, SUDOERS_DEBUG_DEFAULTS);

    switch (type) {
	case EVLOG_SYSLOG:
	    break;
	case EVLOG_FILE:
	    if (fp != NULL) {
		fclose(fp);
	    } else {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "tried to close NULL");
	    }
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unsupported log type %d", type);
	    break;
    }

    debug_return;
}

void
update_eventlog_config(void)
{
    struct eventlog_config evconf;
    debug_decl(update_eventlog_config, SUDOERS_DEBUG_DEFAULTS);

    memset(&evconf, 0, sizeof(evconf));
    if (def_syslog) {
	evconf.type |= EVLOG_SYSLOG;
	evconf.syslog_acceptpri = def_syslog_goodpri;
	evconf.syslog_rejectpri = def_syslog_badpri;
	evconf.syslog_alertpri = def_syslog_badpri;
	evconf.syslog_maxlen = def_syslog_maxlen;
    }
    if (def_logfile) {
	evconf.type |= EVLOG_FILE;
	evconf.logpath = def_logfile;
    }
    evconf.format = EVLOG_SUDO;
    evconf.time_fmt = def_log_year ? "%h %e %T %Y" : "%h %e %T";
    if (!def_log_host)
	evconf.omit_hostname = true;
#ifdef NO_ROOT_MAILER
    evconf.mailuid = user_uid;
#else
    evconf.mailuid = ROOT_UID;
#endif
    evconf.mailerpath = def_mailerpath;
    evconf.mailerflags = def_mailerflags;
    evconf.mailfrom = def_mailfrom;
    evconf.mailto = def_mailto;
    evconf.open_log = sudoers_log_open;
    evconf.close_log = sudoers_log_close;

    eventlog_setconf(&evconf);

    debug_return;
}
