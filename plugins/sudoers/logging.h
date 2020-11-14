/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2005, 2009-2018
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef SUDOERS_LOGGING_H
#define SUDOERS_LOGGING_H

#include <stdarg.h>

/*
 * Values for sudoers_setlocale()
 */
#define SUDOERS_LOCALE_USER     0
#define SUDOERS_LOCALE_SUDOERS  1

/* Logging types */
#define SLOG_SYSLOG		0x01
#define SLOG_FILE		0x02
#define SLOG_BOTH		0x03

/* Flags for log_warning()/log_warningx() */
#define SLOG_USE_ERRNO		0x01	/* internal use only */
#define SLOG_GAI_ERRNO		0x02	/* internal use only */
#define SLOG_RAW_MSG		0x04	/* do not format msg before logging */
#define SLOG_SEND_MAIL		0x08	/* log via mail */
#define SLOG_NO_STDERR		0x10	/* do not log via stderr */
#define SLOG_NO_LOG		0x20	/* do not log via file or syslog */
#define SLOG_AUDIT		0x40	/* send message to audit as well */

/* XXX - needed for auditing */
extern int NewArgc;
extern char **NewArgv;
extern char *audit_msg;

union sudo_defs_val;
struct sudo_plugin_event;
struct log_details;

bool sudoers_warn_setlocale(bool restore, int *cookie);
bool sudoers_setlocale(int locale_type, int *prev_locale);
int sudoers_getlocale(void);
int audit_failure(char *const argv[], char const *const fmt, ...) __printflike(2, 3);
int vaudit_failure(char *const argv[], char const *const fmt, va_list ap) __printflike(2, 0);
bool log_allowed(void);
bool log_auth_failure(int status, unsigned int tries);
bool log_denial(int status, bool inform_user);
bool log_failure(int status, int flags);
bool log_server_alert(struct eventlog *evlog, struct timespec *now, const char *message, const char *errstr, struct sudo_plugin_event * (*event_alloc)(void));
bool log_server_reject(struct eventlog *evlog, const char *message, struct sudo_plugin_event * (*event_alloc)(void));
bool log_warning(int flags, const char *fmt, ...) __printflike(2, 3);
bool log_warningx(int flags, const char *fmt, ...) __printflike(2, 3);
bool gai_log_warning(int flags, int errnum, const char *fmt, ...) __printflike(3, 4);
bool sudoers_initlocale(const char *ulocale, const char *slocale);
bool sudoers_locale_callback(const union sudo_defs_val *);
void sudoers_to_eventlog(struct eventlog *evlog, char * const argv[], char *const envp[]);
void init_eventlog_config(void);
bool init_log_details(struct log_details *details, struct eventlog *evlog);

#endif /* SUDOERS_LOGGING_H */
