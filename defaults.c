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
#include <sys/types.h>
#include <sys/param.h>

#include "sudo.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * For converting between syslog numbers and strings.
 */
struct strmap {
    char *name;
    int num;
};

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
static int store_int __P((char *, int, int));
static int store_str __P((char *, int, int));
static int store_syslogfac __P((char *, int, int));
static int store_syslogpri __P((char *, int, int));
static int store_umask __P((char *, int, int));
static char *num_to_name __P((int, struct strmap *));

/*
 * Structure describing compile-time and run-time options.
 * Index for T_INT starts at one since index 0 is for flags.
 * XXX - syslog things should be strings (and !facility should turn off)
 * XXX - some of these names are pretty lame.
 */
struct sudo_defs_types {
    char *name;
    unsigned int type;
    unsigned int index;
    int (*store) __P((char *, int, int));
    char *desc;
} sudo_defs_table[] = {
    {
	"long_otp_prompt", T_FLAG, FL_LONG_OTP_PROMPT, NULL,
	"Put OTP prompt on its own line"
    }, {
	"ignore_dot", T_FLAG, FL_IGNORE_DOT, NULL,
	"Ignore '.' in $PATH"
    }, {
	"mail_if_no_user", T_FLAG, FL_MAIL_IF_NOUSER, NULL,
	"Send mail if the user is not in sudoers"
    }, {
	"mail_if_no_host", T_FLAG, FL_MAIL_IF_NOHOST, NULL,
	"Send mail if the user is not in sudoers for this host"
    }, {
	"mail_if_no_perms", T_FLAG, FL_MAIL_IF_NOPERMS, NULL,
	"Send mail if the user is not allowed to run a command"
    }, { 
	"tty_tickets", T_FLAG, FL_TTY_TICKETS, NULL,
	"Use a separate timestamp for each user/tty combo"
    }, { 
	"lecture", T_FLAG, FL_LECTURE, NULL,
	"Lecture user the first time they run sudo"
    }, { 
	"authenticate", T_FLAG, FL_AUTHENTICATE, NULL,
	"Require users to authenticate by default"
    }, { 
	"root_sudo", T_FLAG, FL_ROOT_SUDO, NULL,
	"Root may run sudo"
    }, { 
	"log_host", T_FLAG, FL_LOG_HOST, NULL,
	"Log the hostname in the (non-syslog) log file"
    }, { 
	"log_year", T_FLAG, FL_LOG_YEAR, NULL,
	"Log the year in the (non-syslog) log file"
    }, { 
	"shell_noargs", T_FLAG, FL_SHELL_NOARGS, NULL,
	"If sudo is invoked with no arguments, start a shell"
    }, { 
	"set_home", T_FLAG, FL_SET_HOME, NULL,
	"Set $HOME to the target user when starting a shell with -s"
    }, { 
	"path_info", T_FLAG, FL_PATH_INFO, NULL,
	"Allow some information gathering to give useful error messages"
    }, { 
	"fqdn", T_FLAG, FL_FQDN, NULL,
	"Require fully-qualified hsotnames in the sudoers file"
    }, { 
	"insults", T_FLAG, FL_INSULTS, NULL,
	"Insult the user when they enter an incorrect password"
    }, { 
	"syslog", T_INT|T_BOOL, I_LOGFAC, store_syslogfac,
	"Syslog facility: %s"
    }, { 
	"syslog_goodpri", T_INT, I_GOODPRI, store_syslogpri,
	"Syslog priority to use when user authenticates successfully: %s"
    }, { 
	"syslog_badpri", T_INT, I_BADPRI, store_syslogpri,
	"Syslog priority to use when user authenticates unsuccessfully: %s"
    }, { 
	"loglinelen", T_INT, I_LOGLEN, store_int,
	"Number of length at which to wrap log file lines (0 for no wrap): %d"
    }, { 
	"timestamp_timeout", T_INT, I_TS_TIMEOUT, store_int,
	"Authentication timestamp timeout: %d minutes"
    }, { 
	"passwd_timeout", T_INT, I_PW_TIMEOUT, store_int,
	"Password prompt timeout: %d minutes"
    }, { 
	"passwd_tries", T_INT, I_PW_TRIES, store_int,
	"Number of tries to enter a password: %d"
    }, { 
	"umask", T_INT|T_BOOL, I_UMASK, store_umask,
	"Umask to use or 0777 to use user's: 0%o"
    }, { 
	"logfile", T_STR, I_LOGFILE, store_str,
	"Path to log file: %s"
    }, { 
	"mailerpath", T_STR, I_MAILERPATH, store_str,
	"Path to mail program: %s"
    }, { 
	"mailerflags", T_STR, I_MAILERARGS, store_str,
	"Flags for mail program: %s"
    }, { 
	"alertmail", T_STR, I_ALERTMAIL, store_str,
	"Address to send mail to: %s"
    }, { 
	"mailsub", T_STR, I_MAILSUB, store_str,
	"Subject line for mail messages: %s"
    }, { 
	"badpass_message", T_STR, I_BADPASS_MSG, store_str,
	"Incorrect password message: %s"
    }, { 
	"timestampdir", T_STR, I_TIMESTAMPDIR, store_str,
	"Path to authentication timestamp dir: %s"
    }, { 
	"exempt_group", T_STR, I_EXEMPT_GRP, store_str,
	"Users in this group are exempt from password and PATH requirements: %s"
    }, { 
	"passprompt", T_STR, I_PASSPROMPT, store_str,
	"Default password prompt: %s"
    }, { 
	"runas_default", T_STR, I_RUNAS_DEF, store_str,
	"Default user to run commands as: %s"
    }, { 
	"secure_path", T_STR, I_SECURE_PATH, store_str,
	"Override user's $PATH with: %s"
    }, {
	NULL, 0, 0, NULL, NULL
    }
};

unsigned int sudo_inttable[SUDO_INTTABLE_LAST];
char *sudo_strtable[SUDO_STRTABLE_LAST];

/*
 * Print version and configure info.
 */
void
dump_defaults()
{
    struct sudo_defs_types *cur;

    for (cur = sudo_defs_table; cur->name; cur++) {
	switch (cur->type & T_MASK) {
	    case T_FLAG:
		if ((sudo_inttable[I_FLAGS]) & (cur->index))
		    puts(cur->desc);
		break;
	    case T_STR:
		if (sudo_strtable[cur->index]) {
		    (void) printf(cur->desc, sudo_strtable[cur->index]);
		    putchar('\n');
		}
		break;
	    case T_INT:
		if (cur->index == I_LOGFAC)
		    (void) printf(cur->desc,
			num_to_name(sudo_inttable[cur->index], facilities));
		else if (cur->index == I_GOODPRI || cur->index == I_BADPRI)
		    (void) printf(cur->desc,
			num_to_name(sudo_inttable[cur->index], priorities));
		else
		    (void) printf(cur->desc, sudo_inttable[cur->index]);
		putchar('\n');
		break;
	}
    }

#ifdef ENV_EDITOR
    (void) printf("Default editor for visudo: %s\n", EDITOR);
#else
    (void) printf("Editor for visudo: %s\n", EDITOR);
#endif
}

/*
 * List each option along with its description.
 */
void
list_options()
{
    struct sudo_defs_types *cur;
    char *p;

    (void) puts("Available options in a sudoers ``Defaults'' line:\n");
    for (cur = sudo_defs_table; cur->name; cur++) {
	switch (cur->type & T_MASK) {
	    case T_FLAG:
		(void) printf("%s: %s\n", cur->name, cur->desc);
		break;
	    case T_STR:
	    case T_INT:
		p = strrchr(cur->desc, ':');
		if (p)
		    (void) printf("%s: %.*s\n", cur->name, p - cur->desc,
			cur->desc);
		else
		    (void) printf("%s: %s\n", cur->name, cur->desc);
		break;
	}
    }
}

/*
 * Convert a syslog number to a name.
 */
static char *
num_to_name(num, table)
    int num;
    struct strmap *table;
{
    struct strmap *t;

    for (t = table; t->name; t++)
	if (t->num == num)
	    return(t->name);

    return("disabled");
}

/*
 * Sets/clears an entry in the defaults structure
 * If a variable that takes a value is used in a boolean
 * context with op == 0, disable that variable.
 * Eg. you may want to turn off logging to a file for some hosts.
 * This is only meaningful for variables that are *optional*.
 */
int
set_default(var, val, op)
    char *var;
    char *val;
    int op;     /* TRUE or FALSE */
{
    struct sudo_defs_types *cur;
    extern int sudolineno;

    for (cur = sudo_defs_table; cur->name; cur++) {
	if (strcmp(var, cur->name) == 0)
	    break;
    }
    if (!cur->name) {
	(void) fprintf(stderr,
	    "%s: unknown defaults entry `%s' referenced near line %d\n", Argv[0],
	    var, sudolineno);
	return(FALSE);
    }

    switch (cur->type & T_MASK) {
	case T_STR:
	    if (!val) {
		/* Check for bogus boolean usage or lack of a value. */
		if (!(cur->type & T_BOOL) || op != FALSE) {
		    (void) fprintf(stderr,
			"%s: no value specified for `%s' on line %d\n", Argv[0],
			var, sudolineno);
		    return(FALSE);
		}
	    }
	    if (!cur->store(val, cur->index, op)) {
		(void) fprintf(stderr,
		    "%s: value '%s' is invalid for option '%s'\n", Argv[0],
		    val, var);
		return(FALSE);
	    }
	    break;
	case T_INT:
	    if (!val) {
		/* Check for bogus boolean usage or lack of a value. */
		if (!(cur->type & T_BOOL) || op != FALSE) {
		    (void) fprintf(stderr,
			"%s: no value specified for `%s' on line %d\n", Argv[0],
			var, sudolineno);
		    return(FALSE);
		}
	    }
	    if (!cur->store(val, cur->index, op)) {
		(void) fprintf(stderr,
		    "%s: value '%s' is invalid for option '%s'\n", Argv[0],
		    val, var);
		return(FALSE);
	    }
	    break;
	case T_FLAG:
	    if (val) {
		(void) fprintf(stderr,
		    "%s: option `%s' does not take a value on line %d\n",
		    Argv[0], var, sudolineno);
		return(FALSE);
	    }
	    if (op == TRUE)
		sudo_inttable[0] |= cur->index;
	    else
		sudo_inttable[0] &= ~(cur->index);
	    break;
    }

    return(TRUE);
}

/*
 * Set default options to compiled-in values.
 * Any of these may be overridden at runtime by a "Defaults" file.
 */
void
init_defaults()
{
    static int firsttime = 1;
    int i;

    /* Free any strings that were set. */
    if (!firsttime) {
	for (i = 0; i < SUDO_STRTABLE_LAST; i++)
	    if (sudo_strtable[i])
		free(sudo_strtable[i]);
    }

    memset(sudo_strtable, 0, sizeof(sudo_strtable));
    memset(sudo_inttable, 0, sizeof(sudo_inttable));

    /* First initialize the flags. */
#ifdef LONG_OTP_PROMPT
    sudo_inttable[I_FLAGS] |= FL_LONG_OTP_PROMPT;
#endif
#ifdef IGNORE_DOT_PATH
    sudo_inttable[I_FLAGS] |= FL_IGNORE_DOT;
#endif
#ifdef ALWAYS_SEND_MAIL
    sudo_inttable[I_FLAGS] |= FL_MAIL_ALWAYS;
#endif
#ifdef SEND_MAIL_WHEN_NO_USER
    sudo_inttable[I_FLAGS] |= FL_MAIL_IF_NOUSER;
#endif
#ifdef SEND_MAIL_WHEN_NO_HOST
    sudo_inttable[I_FLAGS] |= FL_MAIL_IF_NOHOST;
#endif
#ifdef SEND_MAIL_WHEN_NOT_OK
    sudo_inttable[I_FLAGS] |= FL_MAIL_IF_NOPERMS;
#endif
#ifdef USE_TTY_TICKETS
    sudo_inttable[I_FLAGS] |= FL_TTY_TICKETS;
#endif
#ifndef NO_LECTURE
    sudo_inttable[I_FLAGS] |= FL_LECTURE;
#endif
#ifndef NO_AUTHENTICATION
    sudo_inttable[I_FLAGS] |= FL_AUTHENTICATE;
#endif
#ifndef NO_ROOT_SUDO
    sudo_inttable[I_FLAGS] |= FL_ROOT_SUDO;
#endif
#ifdef HOST_IN_LOG
    sudo_inttable[I_FLAGS] |= FL_LOG_HOST;
#endif
#ifdef SHELL_IF_NO_ARGS
    sudo_inttable[I_FLAGS] |= FL_SHELL_NOARGS;
#endif
#ifdef SHELL_SETS_HOME
    sudo_inttable[I_FLAGS] |= FL_SET_HOME;
#endif
#ifndef DONT_LEAK_PATH_INFO
    sudo_inttable[I_FLAGS] |= FL_PATH_INFO;
#endif
#ifdef FQDN
    sudo_inttable[I_FLAGS] |= FL_FQDN;
#endif
#ifdef USE_INSULTS
    sudo_inttable[I_FLAGS] |= FL_INSULTS;
#endif

    /* Then initialize the ints. */
#if (LOGGING & SLOG_SYSLOG)
    sudo_inttable[I_LOGFAC] = LOGFAC;
    sudo_inttable[I_GOODPRI] = PRI_SUCCESS;
    sudo_inttable[I_BADPRI] = PRI_FAILURE;
#else
    sudo_inttable[I_LOGFAC] = (unsigned int)-1;
#endif
#ifdef SUDO_UMASK
    sudo_inttable[I_UMASK] = SUDO_UMASK;
#else
    sudo_inttable[I_UMASK] = 0777;
#endif
    sudo_inttable[I_LOGLEN] = MAXLOGFILELEN;
    sudo_inttable[I_TS_TIMEOUT] = TIMEOUT;
    sudo_inttable[I_PW_TIMEOUT] = PASSWORD_TIMEOUT;
    sudo_inttable[I_PW_TRIES] = TRIES_FOR_PASSWORD;

    /* Finally do the strings */
    sudo_strtable[I_ALERTMAIL] = estrdup(ALERTMAIL);
    sudo_strtable[I_MAILSUB] = estrdup(MAILSUBJECT);
    sudo_strtable[I_BADPASS_MSG] = estrdup(INCORRECT_PASSWORD);
    sudo_strtable[I_TIMESTAMPDIR] = estrdup(_PATH_SUDO_TIMEDIR);
    sudo_strtable[I_PASSPROMPT] = estrdup(PASSPROMPT);
    sudo_strtable[I_RUNAS_DEF] = estrdup(RUNAS_DEFAULT);
#ifdef _PATH_SENDMAIL
    sudo_strtable[I_MAILERPATH] = estrdup(_PATH_SENDMAIL);
#endif
#if (LOGGING & SLOG_FILE)
    sudo_strtable[I_LOGFILE] = estrdup(_PATH_SUDO_LOGFILE);
#endif
#ifdef EXEMPTGROUP
    sudo_strtable[I_EXEMPT_GRP] = estrdup(EXEMPTGROUP);
#endif
#ifdef SECURE_PATH
    sudo_strtable[I_SECURE_PATH] = estrdup(SECURE_PATH);
#endif
#if 0
    /* XXX - implement */
    sudo_strtable[I_MAILERARGS] = estrdup(XXX);
#endif

    /*
     * The following depend on the above values.
     * We use a pointer to the string so that if its
     * value changes we get the change.
     */
    if (user_runas == NULL)
	user_runas = &sudo_strtable[I_RUNAS_DEF];

    firsttime = 0;
}

static int
store_int(val, index, op)
    char *val;
    int index;
    int op;
{
    char *endp;
    unsigned long ul;

    if (op == FALSE) {
	sudo_inttable[index] = 0;
    } else {
	ul = strtoul(val, &endp, 10);
	if (*endp != '\0')
	    return(FALSE);
	/* XXX - should check against UINT_MAX */
	sudo_inttable[index] = (unsigned int)ul;
    }
    return(TRUE);
}

static int
store_str(val, index, op)
    char *val;
    int index;
    int op;
{

    if (sudo_strtable[index])
	free(sudo_strtable[index]);
    if (op == FALSE)
	sudo_strtable[index] = NULL;
    else
	sudo_strtable[index] = estrdup(val);
    return(TRUE);
}

static int
store_syslogfac(val, index, op)
    char *val;
    int index;
    int op;
{
    struct strmap *fac;

    if (op == FALSE) {
	sudo_inttable[index] = (unsigned int)-1;
	return(TRUE);
    }

    for (fac = facilities; fac->name && strcmp(val, fac->name); fac++)
	;
    if (fac->name == NULL)
	return(FALSE);
    sudo_inttable[index] = fac->num;
    return(TRUE);
}

static int
store_syslogpri(val, index, op)
    char *val;
    int index;
    int op;
{
    struct strmap *pri;

    if (op == FALSE)
	return(FALSE);

    for (pri = priorities; pri->name && strcmp(val, pri->name); pri++)
	;
    if (pri->name == NULL)
	return(FALSE);
    sudo_inttable[index] = pri->num;
    return(TRUE);
}

static int
store_umask(val, index, op)
    char *val;
    int index;
    int op;
{
    char *endp;
    unsigned long ul;

    if (op == FALSE) {
	sudo_inttable[index] = 0777;
    } else {
	ul = strtoul(val, &endp, 8);
	if (*endp != '\0' || ul >= 0777)
	    return(FALSE);
	sudo_inttable[index] = (mode_t)ul;
    }
    return(TRUE);
}
