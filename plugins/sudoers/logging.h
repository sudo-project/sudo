/*
 * Copyright (c) 1999-2005, 2009-2013
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
 */

#ifndef _SUDOERS_LOGGING_H
#define _SUDOERS_LOGGING_H

#include <syslog.h>
#ifdef __STDC__
# include <stdarg.h>
#else
# include <varargs.h>
#endif

/* Logging types */
#define SLOG_SYSLOG		0x01
#define SLOG_FILE		0x02
#define SLOG_BOTH		0x03

/*
 * Values for sudoers_setlocale()
 */
#define SUDOERS_LOCALE_USER     0
#define SUDOERS_LOCALE_SUDOERS  1

/* Flags for log_warning()/log_fatal() */
#define MSG_ONLY		0x01
#define USE_ERRNO		0x02
#define NO_MAIL			0x04
#define NO_STDERR		0x08
#define NO_LOG			0x10

/*
 * Maximum number of characters to log per entry.  The syslogger
 * will log this much, after that, it truncates the log line.
 * We need this here to make sure that we continue with another
 * syslog(3) call if the internal buffer is more than 1023 characters.
 */
#ifndef MAXSYSLOGLEN
# define MAXSYSLOGLEN		960
#endif

/*
 * Indentation level for file-based logs when word wrap is enabled.
 */
#define LOG_INDENT	"    "

bool sudoers_setlocale(int newlocale, int *prevlocale);
int sudoers_getlocale(void);
void audit_success(char *exec_args[]);
void audit_failure(char *exec_args[], char const *const fmt, ...) __printflike(2, 3);
void log_allowed(int status);
void log_auth_failure(int status, unsigned int tries);
void log_denial(int status, bool inform_user);
void log_failure(int status, int flags);
void log_warning(int flags, const char *fmt, ...) __printflike(2, 3);
void log_fatal(int flags, const char *fmt, ...) __printflike(2, 3) __attribute__((__noreturn__));
void sudoers_initlocale(const char *ulocale, const char *slocale);
void writeln_wrap(FILE *fp, char *line, size_t len, size_t maxlen);

#endif /* _SUDOERS_LOGGING_H */
