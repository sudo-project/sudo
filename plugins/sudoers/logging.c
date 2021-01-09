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
#include "log_client.h"

static bool should_mail(int);
static bool warned = false;

extern struct policy_plugin sudoers_policy;	/* XXX */

#ifdef SUDOERS_LOG_CLIENT
/*
 * Convert a defaults-style list to a stringlist.
 */
static struct sudoers_str_list *
list_to_strlist(struct list_members *list)
{
    struct sudoers_str_list *strlist;
    struct sudoers_string *str;
    struct list_member *item;
    debug_decl(slist_to_strlist, SUDOERS_DEBUG_LOGGING);

    if ((strlist = str_list_alloc()) == NULL)
	goto oom;

    SLIST_FOREACH(item, list, entries) {
	if ((str = sudoers_string_alloc(item->value)) == NULL)
	    goto oom;
	/* List is in reverse order, insert at head to fix that. */
	STAILQ_INSERT_HEAD(strlist, str, entries);
    }

    debug_return_ptr(strlist);
oom:
    str_list_free(strlist);
    debug_return_ptr(NULL);
}

bool
init_log_details(struct log_details *details, struct eventlog *evlog)
{
    struct sudoers_str_list *log_servers = NULL;
    debug_decl(init_log_details, SUDOERS_DEBUG_LOGGING);

    memset(details, 0, sizeof(*details));

    if ((log_servers = list_to_strlist(&def_log_servers)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_bool(false);
    }

    details->evlog = evlog;
    details->ignore_log_errors = def_ignore_logfile_errors;
    details->log_servers = log_servers;
    details->server_timeout.tv_sec = def_log_server_timeout;
    details->keepalive = def_log_server_keepalive;
#if defined(HAVE_OPENSSL)
    details->ca_bundle = def_log_server_cabundle;
    details->cert_file = def_log_server_peer_cert;
    details->key_file = def_log_server_peer_key;
    details->verify_server = def_log_server_verify;
#endif /* HAVE_OPENSSL */

    debug_return_bool(true);
}

bool
log_server_reject(struct eventlog *evlog, const char *message,
    struct sudo_plugin_event * (*event_alloc)(void))
{
    struct client_closure *client_closure;
    struct log_details details;
    bool ret = false;
    debug_decl(log_server_reject, SUDOERS_DEBUG_LOGGING);

    if (SLIST_EMPTY(&def_log_servers))
	debug_return_bool(true);

    if (!init_log_details(&details, evlog))
	debug_return_bool(false);

    /* Open connection to log server, send hello and reject messages. */
    client_closure = log_server_open(&details, &sudo_user.submit_time, false,
	SEND_REJECT, message, event_alloc);
    if (client_closure != NULL) {
	client_closure_free(client_closure);
	ret = true;
    }

    /* Only the log_servers string list is dynamically allocated. */
    str_list_free(details.log_servers);
    debug_return_bool(ret);
}

bool
log_server_alert(struct eventlog *evlog, struct timespec *now,
    const char *message, const char *errstr,
    struct sudo_plugin_event * (*event_alloc)(void))
{
    struct client_closure *client_closure;
    struct log_details details;
    char *emessage = NULL;
    bool ret = false;
    debug_decl(log_server_alert, SUDOERS_DEBUG_LOGGING);

    if (SLIST_EMPTY(&def_log_servers))
	debug_return_bool(true);

    if (!init_log_details(&details, evlog))
	goto done;

    if (errstr != NULL) {
	if (asprintf(&emessage, _("%s: %s"), message, errstr) == -1) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
    }

    /* Open connection to log server, send hello and alert messages. */
    client_closure = log_server_open(&details, now, false,
	SEND_ALERT, emessage ? emessage : message, event_alloc);
    if (client_closure != NULL) {
	client_closure_free(client_closure);
	ret = true;
    }

done:
    /* Only the log_servers string list is dynamically allocated. */
    free(emessage);
    str_list_free(details.log_servers);
    debug_return_bool(ret);
}
#else
bool
log_server_reject(struct eventlog *evlog, const char *message,
    struct sudo_plugin_event * (*event_alloc)(void))
{
    return true;
}

bool
log_server_alert(struct eventlog *evlog, struct timespec *now,
    const char *message, const char *errstr,
    struct sudo_plugin_event * (*event_alloc)(void))
{
    return true;
}
#endif /* SUDOERS_LOG_CLIENT */

/*
 * Log a reject event to syslog, a log file, sudo_logsrvd and/or email.
 */
static bool
log_reject(const char *message, bool logit, bool mailit)
{
    int evl_flags = 0;
    struct eventlog evlog;
    bool ret = true;
    debug_decl(log_reject, SUDOERS_DEBUG_LOGGING);

    if (mailit) {
	SET(evl_flags, EVLOG_MAIL);
	if (!logit)
	    SET(evl_flags, EVLOG_MAIL_ONLY);
    }
    sudoers_to_eventlog(&evlog, NewArgv, env_get());
    if (!eventlog_reject(&evlog, evl_flags, message, NULL, NULL))
	ret = false;

    if (!log_server_reject(&evlog, message, sudoers_policy.event_alloc))
	ret = false;

    debug_return_bool(ret);
}

/*
 * Log, audit and mail the denial message, optionally informing the user.
 */
bool
log_denial(int status, bool inform_user)
{
    const char *message;
    int oldlocale;
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

	if (!log_reject(message, def_log_denied, mailit))
	    ret = false;

	/* Restore locale. */
	sudoers_setlocale(oldlocale, NULL);
    }

    /* Inform the user of the failure (in their locale).  */
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
 * Format an authentication failure message, using either
 * authfail_message from sudoers or a locale-specific message.
 */
static int
fmt_authfail_message(char **str, unsigned int tries)
{
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
 * Log and audit that user was not able to authenticate themselves.
 */
bool
log_auth_failure(int status, unsigned int tries)
{
    char *message = NULL;
    int oldlocale;
    bool ret = true;
    bool mailit = false;
    bool logit = true;
    debug_decl(log_auth_failure, SUDOERS_DEBUG_LOGGING);

    /* Do auditing first (audit_failure() handles the locale itself). */
    audit_failure(NewArgv, "%s", N_("authentication failure"));

    /* If sudoers denied the command we'll log that separately. */
    if (!ISSET(status, FLAG_BAD_PASSWORD|FLAG_NON_INTERACTIVE))
	logit = false;

    /*
     * Do we need to send mail?
     * We want to avoid sending multiple messages for the same command
     * so if we are going to send an email about the denial, that takes
     * precedence.
     */
    if (ISSET(status, VALIDATE_SUCCESS)) {
	/* Command allowed, auth failed; do we need to send mail? */
	if (def_mail_badpass || def_mail_always)
	    mailit = true;
	if (!def_log_denied)
	    logit = false;
    } else {
	/* Command denied, auth failed; make sure we don't send mail twice. */
	if (def_mail_badpass && !should_mail(status))
	    mailit = true;
	/* Don't log the bad password message, we'll log a denial instead. */
	logit = false;
    }

    if (logit || mailit) {
	/* Log and mail messages should be in the sudoers locale. */
	sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

	if (ISSET(status, FLAG_BAD_PASSWORD)) {
	    if (fmt_authfail_message(&message, tries) == -1) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		ret = false;
	    } else {
		ret = log_reject(message, logit, mailit);
		free(message);
	    }
	} else {
	    ret = log_reject(_("a password is required"), logit, mailit);
	}

	/* Restore locale. */
	sudoers_setlocale(oldlocale, NULL);
    }

    /* Inform the user if they failed to authenticate (in their locale).  */
    sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);

    if (ISSET(status, FLAG_BAD_PASSWORD)) {
	if (fmt_authfail_message(&message, tries) == -1) {
	    sudo_warnx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	    ret = false;
	} else {
	    sudo_warnx("%s", message);
	    free(message);
	}
    } else {
	sudo_warnx("%s", _("a password is required"));
    }

    sudoers_setlocale(oldlocale, NULL);

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

	sudoers_to_eventlog(&evlog, NewArgv, env_get());
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

    /* Expand printf-style format + args. */
    len = vasprintf(&message, _(fmt), ap);
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
	sudoers_to_eventlog(&evlog, NewArgv, env_get());
	eventlog_alert(&evlog, evl_flags, &now, message, errstr);

	log_server_alert(&evlog, &now, message, errstr,
	    sudoers_policy.event_alloc);
    }

    /*
     * Tell the user (in their locale).
     */
    if (!ISSET(flags, SLOG_NO_STDERR)) {
	sudoers_setlocale(SUDOERS_LOCALE_USER, NULL);
	if (ISSET(flags, SLOG_USE_ERRNO)) {
	    errno = errnum;
	    sudo_vwarn_nodebug(_(fmt), ap2);
	} else if (ISSET(flags, SLOG_GAI_ERRNO)) {
	    sudo_gai_vwarn_nodebug(errnum, _(fmt), ap2);
	} else {
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
sudoers_to_eventlog(struct eventlog *evlog, char * const argv[],
    char * const envp[])
{
    struct group *grp;
    debug_decl(sudoers_to_eventlog, SUDOERS_DEBUG_LOGGING);

    /* We rely on the reference held by the group cache. */
    if ((grp = sudo_getgrgid(sudo_user.pw->pw_gid)) != NULL)
	sudo_gr_delref(grp);

    memset(evlog, 0, sizeof(*evlog));
    evlog->iolog_file = sudo_user.iolog_file;
    evlog->iolog_path = sudo_user.iolog_path;
    evlog->command = safe_cmnd ? safe_cmnd : (argv ? argv[0] : NULL);
    evlog->cwd = user_cwd;
    if (def_runchroot != NULL && strcmp(def_runchroot, "*") != 0) {
	evlog->runchroot = def_runchroot;
    }
    if (def_runcwd && strcmp(def_runcwd, "*") != 0) {
	evlog->runcwd = def_runcwd;
    } else if (ISSET(sudo_mode, MODE_LOGIN_SHELL) && runas_pw != NULL) {
	evlog->runcwd = runas_pw->pw_dir;
    } else {
	evlog->runcwd = user_cwd;
    }
    evlog->rungroup = runas_gr ? runas_gr->gr_name : sudo_user.runas_group;
    evlog->submithost = user_host;
    evlog->submituser = user_name;
    if (grp != NULL)
	evlog->submitgroup = grp->gr_name;
    evlog->ttyname = user_ttypath;
    evlog->argv = (char **)argv;
    evlog->env_add = (char **)sudo_user.env_vars;
    evlog->envp = (char **)envp;
    evlog->submit_time = sudo_user.submit_time;
    evlog->lines = sudo_user.lines;
    evlog->columns = sudo_user.cols;
    if (runas_pw != NULL) {
	evlog->rungid = runas_pw->pw_gid;
	evlog->runuid = runas_pw->pw_uid;
	evlog->runuser = runas_pw->pw_name;
    } else {
	evlog->rungid = (gid_t)-1;
	evlog->runuid = (uid_t)-1;
	evlog->runuser = sudo_user.runas_user;
    }

    debug_return;
}

static FILE *
sudoers_log_open(int type, const char *log_file)
{
    bool uid_changed;
    FILE *fp = NULL;
    mode_t oldmask;
    int fd, flags;
    char *omode;
    debug_decl(sudoers_log_open, SUDOERS_DEBUG_LOGGING);

    switch (type) {
	case EVLOG_SYSLOG:
	    openlog("sudo", def_syslog_pid ? LOG_PID : 0, def_syslog);
	    break;
	case EVLOG_FILE:
	    /* Open log file as root, mode 0600 (cannot append to JSON). */
	    if (def_log_format == json) {
		flags = O_RDWR|O_CREAT;
		omode = "w";
	    } else {
		flags = O_WRONLY|O_APPEND|O_CREAT;
		omode = "a";
	    }
	    oldmask = umask(S_IRWXG|S_IRWXO);
	    uid_changed = set_perms(PERM_ROOT);
	    fd = open(log_file, flags, S_IRUSR|S_IWUSR);
	    if (uid_changed && !restore_perms()) {
		if (fd != -1) {
		    close(fd);
		    fd = -1;
		}
	    }
	    (void) umask(oldmask);
	    if (fd == -1 || (fp = fdopen(fd, omode)) == NULL) {
		if (!warned) {
		    warned = true;
		    log_warning(SLOG_SEND_MAIL|SLOG_NO_LOG,
			N_("unable to open log file: %s"), log_file);
		}
		if (fd != -1)
		    close(fd);
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
    debug_decl(sudoers_log_close, SUDOERS_DEBUG_LOGGING);

    switch (type) {
	case EVLOG_SYSLOG:
	    break;
	case EVLOG_FILE:
	    if (fp == NULL) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "tried to close NULL log stream");
		break;
	    }
	    (void)fflush(fp);
	    if (ferror(fp) && !warned) {
		warned = true;
		log_warning(SLOG_SEND_MAIL|SLOG_NO_LOG,
		    N_("unable to write log file: %s"), def_logfile);
	    }
	    fclose(fp);
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unsupported log type %d", type);
	    break;
    }

    debug_return;
}

void
init_eventlog_config(void)
{
    int logtype = 0;
#ifdef NO_ROOT_MAILER
    uid_t mailuid = user_uid;
#else
    uid_t mailuid = ROOT_UID;
#endif
    debug_decl(init_eventlog_config, SUDOERS_DEBUG_LOGGING);

    if (def_syslog)
	logtype |= EVLOG_SYSLOG;
    if (def_logfile)
	logtype |= EVLOG_FILE;

    eventlog_set_type(logtype);
    eventlog_set_format(def_log_format == sudo ? EVLOG_SUDO : EVLOG_JSON);
    eventlog_set_syslog_acceptpri(def_syslog_goodpri);
    eventlog_set_syslog_rejectpri(def_syslog_badpri);
    eventlog_set_syslog_alertpri(def_syslog_badpri);
    eventlog_set_syslog_maxlen(def_syslog_maxlen);
    eventlog_set_file_maxlen(def_loglinelen);
    eventlog_set_mailuid(mailuid);
    eventlog_set_omit_hostname(!def_log_host);
    eventlog_set_logpath(def_logfile);
    eventlog_set_time_fmt(def_log_year ? "%h %e %T %Y" : "%h %e %T");
    eventlog_set_mailerpath(def_mailerpath);
    eventlog_set_mailerflags(def_mailerflags);
    eventlog_set_mailfrom(def_mailfrom);
    eventlog_set_mailto(def_mailto);
    eventlog_set_mailsub(def_mailsub);
    eventlog_set_open_log(sudoers_log_open);
    eventlog_set_close_log(sudoers_log_close);

    debug_return;
}
