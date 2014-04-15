/*
 * Copyright (c) 1999-2005, 2007-2014
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <config.h>

#include <sys/types.h>
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
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <ctype.h>

#include "sudoers.h"
#include "parse.h"
#include <gram.h>

/*
 * For converting between syslog numbers and strings.
 */
struct strmap {
    char *name;
    int num;
};

#ifdef LOG_NFACILITIES
static struct strmap facilities[] = {
#ifdef LOG_AUTHPRIV
	{ "authpriv",	LOG_AUTHPRIV },
#endif
	{ "auth",	LOG_AUTH },
	{ "daemon",	LOG_DAEMON },
	{ "user",	LOG_USER },
	{ "local0",	LOG_LOCAL0 },
	{ "local1",	LOG_LOCAL1 },
	{ "local2",	LOG_LOCAL2 },
	{ "local3",	LOG_LOCAL3 },
	{ "local4",	LOG_LOCAL4 },
	{ "local5",	LOG_LOCAL5 },
	{ "local6",	LOG_LOCAL6 },
	{ "local7",	LOG_LOCAL7 },
	{ NULL,		-1 }
};
#endif /* LOG_NFACILITIES */

static struct strmap priorities[] = {
	{ "alert",	LOG_ALERT },
	{ "crit",	LOG_CRIT },
	{ "debug",	LOG_DEBUG },
	{ "emerg",	LOG_EMERG },
	{ "err",	LOG_ERR },
	{ "info",	LOG_INFO },
	{ "notice",	LOG_NOTICE },
	{ "warning",	LOG_WARNING },
	{ NULL,		-1 }
};

/*
 * Local prototypes.
 */
static bool store_int(char *, struct sudo_defs_types *, int);
static bool store_list(char *, struct sudo_defs_types *, int);
static bool store_mode(char *, struct sudo_defs_types *, int);
static bool store_str(char *, struct sudo_defs_types *, int);
static bool store_syslogfac(char *, struct sudo_defs_types *, int);
static bool store_syslogpri(char *, struct sudo_defs_types *, int);
static bool store_tuple(char *, struct sudo_defs_types *, int);
static bool store_uint(char *, struct sudo_defs_types *, int);
static bool store_float(char *, struct sudo_defs_types *, int);
static void list_op(char *, size_t, struct sudo_defs_types *, enum list_ops);
static const char *logfac2str(int);
static const char *logpri2str(int);

/*
 * Table describing compile-time and run-time options.
 */
#include <def_data.c>

/*
 * Print version and configure info.
 */
void
dump_defaults(void)
{
    struct sudo_defs_types *cur;
    struct list_member *item;
    struct def_values *def;
    char *desc;
    debug_decl(dump_defaults, SUDO_DEBUG_DEFAULTS)

    for (cur = sudo_defs_table; cur->name; cur++) {
	if (cur->desc) {
	    desc = _(cur->desc);
	    switch (cur->type & T_MASK) {
		case T_FLAG:
		    if (cur->sd_un.flag)
			sudo_printf(SUDO_CONV_INFO_MSG, "%s\n", desc);
		    break;
		case T_STR:
		    if (cur->sd_un.str) {
			sudo_printf(SUDO_CONV_INFO_MSG, desc, cur->sd_un.str);
			sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    }
		    break;
		case T_LOGFAC:
		    if (cur->sd_un.ival) {
			sudo_printf(SUDO_CONV_INFO_MSG, desc,
			    logfac2str(cur->sd_un.ival));
			sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    }
		    break;
		case T_LOGPRI:
		    if (cur->sd_un.ival) {
			sudo_printf(SUDO_CONV_INFO_MSG, desc,
			    logpri2str(cur->sd_un.ival));
			sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    }
		    break;
		case T_INT:
		    sudo_printf(SUDO_CONV_INFO_MSG, desc, cur->sd_un.ival);
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
		case T_UINT:
		    sudo_printf(SUDO_CONV_INFO_MSG, desc, cur->sd_un.uival);
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
		case T_FLOAT:
		    sudo_printf(SUDO_CONV_INFO_MSG, desc, cur->sd_un.fval);
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
		case T_MODE:
		    sudo_printf(SUDO_CONV_INFO_MSG, desc, cur->sd_un.mode);
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
		case T_LIST:
		    if (!SLIST_EMPTY(&cur->sd_un.list)) {
			sudo_printf(SUDO_CONV_INFO_MSG, "%s\n", desc);
			SLIST_FOREACH(item, &cur->sd_un.list, entries) {
			    sudo_printf(SUDO_CONV_INFO_MSG,
				"\t%s\n", item->value);
			}
		    }
		    break;
		case T_TUPLE:
		    for (def = cur->values; def->sval; def++) {
			if (cur->sd_un.tuple == def->nval) {
			    sudo_printf(SUDO_CONV_INFO_MSG, desc, def->sval);
			    break;
			}
		    }
		    sudo_printf(SUDO_CONV_INFO_MSG, "\n");
		    break;
	    }
	}
    }
    debug_return;
}

/*
 * Sets/clears an entry in the defaults structure
 * If a variable that takes a value is used in a boolean
 * context with op == 0, disable that variable.
 * Eg. you may want to turn off logging to a file for some hosts.
 * This is only meaningful for variables that are *optional*.
 */
bool
set_default(char *var, char *val, int op)
{
    struct sudo_defs_types *cur;
    int num;
    debug_decl(set_default, SUDO_DEBUG_DEFAULTS)

    for (cur = sudo_defs_table, num = 0; cur->name; cur++, num++) {
	if (strcmp(var, cur->name) == 0)
	    break;
    }
    if (!cur->name) {
	warningx(U_("unknown defaults entry `%s'"), var);
	debug_return_bool(false);
    }

    switch (cur->type & T_MASK) {
	case T_LOGFAC:
	    if (!store_syslogfac(val, cur, op)) {
		if (val)
		    warningx(U_("value `%s' is invalid for option `%s'"),
			val, var);
		else
		    warningx(U_("no value specified for `%s'"), var);
		debug_return_bool(false);
	    }
	    break;
	case T_LOGPRI:
	    if (!store_syslogpri(val, cur, op)) {
		if (val)
		    warningx(U_("value `%s' is invalid for option `%s'"),
			val, var);
		else
		    warningx(U_("no value specified for `%s'"), var);
		debug_return_bool(false);
	    }
	    break;
	case T_STR:
	    if (!val) {
		/* Check for bogus boolean usage or lack of a value. */
		if (!ISSET(cur->type, T_BOOL) || op != false) {
		    warningx(U_("no value specified for `%s'"), var);
		    debug_return_bool(false);
		}
	    }
	    if (ISSET(cur->type, T_PATH) && val && *val != '/') {
		warningx(U_("values for `%s' must start with a '/'"), var);
		debug_return_bool(false);
	    }
	    if (!store_str(val, cur, op)) {
		warningx(U_("value `%s' is invalid for option `%s'"), val, var);
		debug_return_bool(false);
	    }
	    break;
	case T_INT:
	    if (!val) {
		/* Check for bogus boolean usage or lack of a value. */
		if (!ISSET(cur->type, T_BOOL) || op != false) {
		    warningx(U_("no value specified for `%s'"), var);
		    debug_return_bool(false);
		}
	    }
	    if (!store_int(val, cur, op)) {
		warningx(U_("value `%s' is invalid for option `%s'"), val, var);
		debug_return_bool(false);
	    }
	    break;
	case T_UINT:
	    if (!val) {
		/* Check for bogus boolean usage or lack of a value. */
		if (!ISSET(cur->type, T_BOOL) || op != false) {
		    warningx(U_("no value specified for `%s'"), var);
		    debug_return_bool(false);
		}
	    }
	    if (!store_uint(val, cur, op)) {
		warningx(U_("value `%s' is invalid for option `%s'"), val, var);
		debug_return_bool(false);
	    }
	    break;
	case T_FLOAT:
	    if (!val) {
		/* Check for bogus boolean usage or lack of a value. */
		if (!ISSET(cur->type, T_BOOL) || op != false) {
		    warningx(U_("no value specified for `%s'"), var);
		    debug_return_bool(false);
		}
	    }
	    if (!store_float(val, cur, op)) {
		warningx(U_("value `%s' is invalid for option `%s'"), val, var);
		debug_return_bool(false);
	    }
	    break;
	case T_MODE:
	    if (!val) {
		/* Check for bogus boolean usage or lack of a value. */
		if (!ISSET(cur->type, T_BOOL) || op != false) {
		    warningx(U_("no value specified for `%s'"), var);
		    debug_return_bool(false);
		}
	    }
	    if (!store_mode(val, cur, op)) {
		warningx(U_("value `%s' is invalid for option `%s'"), val, var);
		debug_return_bool(false);
	    }
	    break;
	case T_FLAG:
	    if (val) {
		warningx(U_("option `%s' does not take a value"), var);
		debug_return_bool(false);
	    }
	    cur->sd_un.flag = op;
	    break;
	case T_LIST:
	    if (!val) {
		/* Check for bogus boolean usage or lack of a value. */
		if (!ISSET(cur->type, T_BOOL) || op != false) {
		    warningx(U_("no value specified for `%s'"), var);
		    debug_return_bool(false);
		}
	    }
	    if (!store_list(val, cur, op)) {
		warningx(U_("value `%s' is invalid for option `%s'"), val, var);
		debug_return_bool(false);
	    }
	    break;
	case T_TUPLE:
	    if (!val && !ISSET(cur->type, T_BOOL)) {
		warningx(U_("no value specified for `%s'"), var);
		debug_return_bool(false);
	    }
	    if (!store_tuple(val, cur, op)) {
		warningx(U_("value `%s' is invalid for option `%s'"), val, var);
		debug_return_bool(false);
	    }
	    break;
    }

    debug_return_bool(true);
}

/*
 * Set default options to compiled-in values.
 * Any of these may be overridden at runtime by a "Defaults" file.
 */
void
init_defaults(void)
{
    static int firsttime = 1;
    struct sudo_defs_types *def;
    debug_decl(init_defaults, SUDO_DEBUG_DEFAULTS)

    /* Clear any old settings. */
    if (!firsttime) {
	for (def = sudo_defs_table; def->name; def++) {
	    switch (def->type & T_MASK) {
		case T_STR:
		    efree(def->sd_un.str);
		    def->sd_un.str = NULL;
		    break;
		case T_LIST:
		    list_op(NULL, 0, def, freeall);
		    break;
	    }
	    memset(&def->sd_un, 0, sizeof(def->sd_un));
	}
    }

    /* First initialize the flags. */
#ifdef LONG_OTP_PROMPT
    def_long_otp_prompt = true;
#endif
#ifdef IGNORE_DOT_PATH
    def_ignore_dot = true;
#endif
#ifdef ALWAYS_SEND_MAIL
    def_mail_always = true;
#endif
#ifdef SEND_MAIL_WHEN_NO_USER
    def_mail_no_user = true;
#endif
#ifdef SEND_MAIL_WHEN_NO_HOST
    def_mail_no_host = true;
#endif
#ifdef SEND_MAIL_WHEN_NOT_OK
    def_mail_no_perms = true;
#endif
#ifndef NO_TTY_TICKETS
    def_tty_tickets = true;
#endif
#ifndef NO_LECTURE
    def_lecture = once;
#endif
#ifndef NO_AUTHENTICATION
    def_authenticate = true;
#endif
#ifndef NO_ROOT_SUDO
    def_root_sudo = true;
#endif
#ifdef HOST_IN_LOG
    def_log_host = true;
#endif
#ifdef SHELL_IF_NO_ARGS
    def_shell_noargs = true;
#endif
#ifdef SHELL_SETS_HOME
    def_set_home = true;
#endif
#ifndef DONT_LEAK_PATH_INFO
    def_path_info = true;
#endif
#ifdef FQDN
    def_fqdn = true;
#endif
#ifdef USE_INSULTS
    def_insults = true;
#endif
#ifdef ENV_EDITOR
    def_env_editor = true;
#endif
#ifdef UMASK_OVERRIDE
    def_umask_override = true;
#endif
    def_iolog_file = estrdup("%{seq}");
    def_iolog_dir = estrdup(_PATH_SUDO_IO_LOGDIR);
    def_sudoers_locale = estrdup("C");
    def_env_reset = ENV_RESET;
    def_set_logname = true;
    def_closefrom = STDERR_FILENO + 1;
    def_pam_service = estrdup("sudo");
#ifdef HAVE_PAM_LOGIN
    def_pam_login_service = estrdup("sudo-i");
#else
    def_pam_login_service = estrdup("sudo");
#endif
#ifdef NO_PAM_SESSION
    def_pam_session = false;
#else
    def_pam_session = true;
#endif
#ifdef HAVE_INNETGR
    def_use_netgroups = true;
#endif

    /* Syslog options need special care since they both strings and ints */
#if (LOGGING & SLOG_SYSLOG)
    (void) store_syslogfac(LOGFAC, &sudo_defs_table[I_SYSLOG], true);
    (void) store_syslogpri(PRI_SUCCESS, &sudo_defs_table[I_SYSLOG_GOODPRI],
	true);
    (void) store_syslogpri(PRI_FAILURE, &sudo_defs_table[I_SYSLOG_BADPRI],
	true);
#endif

    /* Password flags also have a string and integer component. */
    (void) store_tuple("any", &sudo_defs_table[I_LISTPW], true);
    (void) store_tuple("all", &sudo_defs_table[I_VERIFYPW], true);

    /* Then initialize the int-like things. */
#ifdef SUDO_UMASK
    def_umask = SUDO_UMASK;
#else
    def_umask = 0777;
#endif
    def_loglinelen = MAXLOGFILELEN;
    def_timestamp_timeout = TIMEOUT;
    def_passwd_timeout = PASSWORD_TIMEOUT;
    def_passwd_tries = TRIES_FOR_PASSWORD;
#ifdef HAVE_ZLIB_H
    def_compress_io = true;
#endif

    /* Now do the strings */
    def_mailto = estrdup(MAILTO);
    def_mailsub = estrdup(N_(MAILSUBJECT));
    def_badpass_message = estrdup(_(INCORRECT_PASSWORD));
    def_lecture_status_dir = estrdup(_PATH_SUDO_LECTURE_DIR);
    def_timestampdir = estrdup(_PATH_SUDO_TIMEDIR);
    def_passprompt = estrdup(_(PASSPROMPT));
    def_runas_default = estrdup(RUNAS_DEFAULT);
#ifdef _PATH_SUDO_SENDMAIL
    def_mailerpath = estrdup(_PATH_SUDO_SENDMAIL);
    def_mailerflags = estrdup("-t");
#endif
#if (LOGGING & SLOG_FILE)
    def_logfile = estrdup(_PATH_SUDO_LOGFILE);
#endif
#ifdef EXEMPTGROUP
    def_exempt_group = estrdup(EXEMPTGROUP);
#endif
#ifdef SECURE_PATH
    def_secure_path = estrdup(SECURE_PATH);
#endif
    def_editor = estrdup(EDITOR);
    def_set_utmp = true;
    def_pam_setcred = true;

    /* Finally do the lists (currently just environment tables). */
    init_envtables();

    firsttime = 0;

    debug_return;
}

/*
 * Update the defaults based on what was set by sudoers.
 * Pass in an OR'd list of which default types to update.
 */
bool
update_defaults(int what)
{
    struct defaults *def;
    bool rc = true;
    debug_decl(update_defaults, SUDO_DEBUG_DEFAULTS)

    TAILQ_FOREACH(def, &defaults, entries) {
	switch (def->type) {
	    case DEFAULTS:
		if (ISSET(what, SETDEF_GENERIC) &&
		    !set_default(def->var, def->val, def->op))
		    rc = false;
		break;
	    case DEFAULTS_USER:
#if 1
		if (ISSET(what, SETDEF_USER)) {
		    int m;
		    m = userlist_matches(sudo_user.pw, def->binding);
		    if (m == ALLOW) {
			if (!set_default(def->var, def->val, def->op))
			    rc = false;
		    }
		}
#else
		if (ISSET(what, SETDEF_USER) &&
		    userlist_matches(sudo_user.pw, def->binding) == ALLOW &&
		    !set_default(def->var, def->val, def->op))
		    rc = false;
#endif
		break;
	    case DEFAULTS_RUNAS:
		if (ISSET(what, SETDEF_RUNAS) &&
		    runaslist_matches(def->binding, NULL, NULL, NULL) == ALLOW &&
		    !set_default(def->var, def->val, def->op))
		    rc = false;
		break;
	    case DEFAULTS_HOST:
		if (ISSET(what, SETDEF_HOST) &&
		    hostlist_matches(def->binding) == ALLOW &&
		    !set_default(def->var, def->val, def->op))
		    rc = false;
		break;
	    case DEFAULTS_CMND:
		if (ISSET(what, SETDEF_CMND) &&
		    cmndlist_matches(def->binding) == ALLOW &&
		    !set_default(def->var, def->val, def->op))
		    rc = false;
		break;
	}
    }
    debug_return_bool(rc);
}

/*
 * Check the defaults entries without actually setting them.
 * Pass in an OR'd list of which default types to check.
 */
bool
check_defaults(int what, bool quiet)
{
    struct sudo_defs_types *cur;
    struct defaults *def;
    bool rc = true;
    debug_decl(check_defaults, SUDO_DEBUG_DEFAULTS)

    TAILQ_FOREACH(def, &defaults, entries) {
	switch (def->type) {
	    case DEFAULTS:
		if (!ISSET(what, SETDEF_GENERIC))
		    continue;
		break;
	    case DEFAULTS_USER:
		if (!ISSET(what, SETDEF_USER))
		    continue;
		break;
	    case DEFAULTS_RUNAS:
		if (!ISSET(what, SETDEF_RUNAS))
		    continue;
		break;
	    case DEFAULTS_HOST:
		if (!ISSET(what, SETDEF_HOST))
		    continue;
		break;
	    case DEFAULTS_CMND:
		if (!ISSET(what, SETDEF_CMND))
		    continue;
		break;
	}
	for (cur = sudo_defs_table; cur->name != NULL; cur++) {
	    if (strcmp(def->var, cur->name) == 0)
		break;
	}
	if (cur->name == NULL) {
	    if (!quiet)
		warningx(U_("unknown defaults entry `%s'"), def->var);
	    rc = false;
	}
    }
    debug_return_bool(rc);
}

static bool
store_int(char *val, struct sudo_defs_types *def, int op)
{
    const char *errstr;
    int i;
    debug_decl(store_int, SUDO_DEBUG_DEFAULTS)

    if (op == false) {
	def->sd_un.ival = 0;
    } else {
	i = strtonum(val, INT_MIN, INT_MAX, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: %s", val, errstr);
	    debug_return_bool(false);
	}
	def->sd_un.ival = i;
    }
    if (def->callback)
	debug_return_bool(def->callback(val));
    debug_return_bool(true);
}

static bool
store_uint(char *val, struct sudo_defs_types *def, int op)
{
    const char *errstr;
    unsigned int u;
    debug_decl(store_uint, SUDO_DEBUG_DEFAULTS)

    if (op == false) {
	def->sd_un.uival = 0;
    } else {
	u = strtonum(val, 0, UINT_MAX, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s: %s", val, errstr);
	    debug_return_bool(false);
	}
	def->sd_un.uival = u;
    }
    if (def->callback)
	debug_return_bool(def->callback(val));
    debug_return_bool(true);
}

static bool
store_float(char *val, struct sudo_defs_types *def, int op)
{
    char *endp;
    double d;
    debug_decl(store_float, SUDO_DEBUG_DEFAULTS)

    if (op == false) {
	def->sd_un.fval = 0.0;
    } else {
	d = strtod(val, &endp);
	if (*endp != '\0')
	    debug_return_bool(false);
	/* XXX - should check against HUGE_VAL */
	def->sd_un.fval = d;
    }
    if (def->callback)
	debug_return_bool(def->callback(val));
    debug_return_bool(true);
}

static bool
store_tuple(char *val, struct sudo_defs_types *def, int op)
{
    struct def_values *v;
    debug_decl(store_tuple, SUDO_DEBUG_DEFAULTS)

    /*
     * Look up tuple value by name to find enum def_tuple value.
     * For negation to work the first element of enum def_tuple
     * must be equivalent to boolean false.
     */
    if (!val) {
	def->sd_un.ival = (op == false) ? 0 : 1;
    } else {
	for (v = def->values; v->sval != NULL; v++) {
	    if (strcmp(v->sval, val) == 0) {
		def->sd_un.tuple = v->nval;
		break;
	    }
	}
	if (v->sval == NULL)
	    debug_return_bool(false);
    }
    if (def->callback)
	debug_return_bool(def->callback(val));
    debug_return_bool(true);
}

static bool
store_str(char *val, struct sudo_defs_types *def, int op)
{
    debug_decl(store_str, SUDO_DEBUG_DEFAULTS)

    efree(def->sd_un.str);
    if (op == false)
	def->sd_un.str = NULL;
    else
	def->sd_un.str = estrdup(val);
    if (def->callback)
	debug_return_bool(def->callback(val));
    debug_return_bool(true);
}

static bool
store_list(char *str, struct sudo_defs_types *def, int op)
{
    char *start, *end;
    debug_decl(store_list, SUDO_DEBUG_DEFAULTS)

    /* Remove all old members. */
    if (op == false || op == true)
	list_op(NULL, 0, def, freeall);

    /* Split str into multiple space-separated words and act on each one. */
    if (op != false) {
	end = str;
	do {
	    /* Remove leading blanks, if nothing but blanks we are done. */
	    for (start = end; isblank((unsigned char)*start); start++)
		;
	    if (*start == '\0')
		break;

	    /* Find end position and perform operation. */
	    for (end = start; *end && !isblank((unsigned char)*end); end++)
		;
	    list_op(start, end - start, def, op == '-' ? delete : add);
	} while (*end++ != '\0');
    }
    debug_return_bool(true);
}

static bool
store_syslogfac(char *val, struct sudo_defs_types *def, int op)
{
    struct strmap *fac;
    debug_decl(store_syslogfac, SUDO_DEBUG_DEFAULTS)

    if (op == false) {
	def->sd_un.ival = false;
	debug_return_bool(true);
    }
#ifdef LOG_NFACILITIES
    if (!val)
	debug_return_bool(false);
    for (fac = facilities; fac->name && strcmp(val, fac->name); fac++)
	;
    if (fac->name == NULL)
	debug_return_bool(false);		/* not found */

    def->sd_un.ival = fac->num;
#else
    def->sd_un.ival = -1;
#endif /* LOG_NFACILITIES */
    debug_return_bool(true);
}

static const char *
logfac2str(int n)
{
#ifdef LOG_NFACILITIES
    struct strmap *fac;
    debug_decl(logfac2str, SUDO_DEBUG_DEFAULTS)

    for (fac = facilities; fac->name && fac->num != n; fac++)
	;
    debug_return_const_str(fac->name);
#else
    return "default";
#endif /* LOG_NFACILITIES */
}

static bool
store_syslogpri(char *val, struct sudo_defs_types *def, int op)
{
    struct strmap *pri;
    debug_decl(store_syslogpri, SUDO_DEBUG_DEFAULTS)

    if (op == false || !val)
	debug_return_bool(false);

    for (pri = priorities; pri->name && strcmp(val, pri->name); pri++)
	;
    if (pri->name == NULL)
	debug_return_bool(false); 	/* not found */

    def->sd_un.ival = pri->num;
    debug_return_bool(true);
}

static const char *
logpri2str(int n)
{
    struct strmap *pri;
    debug_decl(logpri2str, SUDO_DEBUG_DEFAULTS)

    for (pri = priorities; pri->name && pri->num != n; pri++)
	;
    debug_return_const_str(pri->name);
}

static bool
store_mode(char *val, struct sudo_defs_types *def, int op)
{
    mode_t mode;
    const char *errstr;
    debug_decl(store_mode, SUDO_DEBUG_DEFAULTS)

    if (op == false) {
	def->sd_un.mode = 0777;
    } else {
	mode = atomode(val, &errstr);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"%s is %s", val, errstr);
	    debug_return_bool(false);
	}
	def->sd_un.mode = mode;
    }
    if (def->callback)
	debug_return_bool(def->callback(val));
    debug_return_bool(true);
}

static void
list_op(char *val, size_t len, struct sudo_defs_types *def, enum list_ops op)
{
    struct list_member *cur, *prev = NULL;
    debug_decl(list_op, SUDO_DEBUG_DEFAULTS)

    if (op == freeall) {
	while ((cur = SLIST_FIRST(&def->sd_un.list)) != NULL) {
	    SLIST_REMOVE_HEAD(&def->sd_un.list, entries);
	    efree(cur->value);
	    efree(cur);
	}
	debug_return;
    }

    SLIST_FOREACH(cur, &def->sd_un.list, entries) {
	if ((strncmp(cur->value, val, len) == 0 && cur->value[len] == '\0')) {

	    if (op == add)
		debug_return;		/* already exists */

	    /* Delete node */
	    if (prev == NULL)
		SLIST_REMOVE_HEAD(&def->sd_un.list, entries);
	    else
		SLIST_REMOVE_AFTER(prev, entries);
	    efree(cur->value);
	    efree(cur);
	    break;
	}
	prev = cur;
    }

    /* Add new node to the head of the list. */
    if (op == add) {
	cur = ecalloc(1, sizeof(struct list_member));
	cur->value = estrndup(val, len);
	SLIST_INSERT_HEAD(&def->sd_un.list, cur, entries);
    }
    debug_return;
}
