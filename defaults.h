/*
 * Copyright (c) 1999 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * $Sudo$
 */

#ifndef _SUDO_DEFAULTS_H
#define _SUDO_DEFAULTS_H

/*
 * Four types of defaults: strings, integers, booleans, and flags.
 * Note that flags have their value in the index field.
 * Also, T_INT or T_STR may be ANDed with T_BOOL to indicate that
 * a value is not required.
 */
#define T_INT	0x01
#define T_STR	0x02
#define T_FLAG	0x08
#define T_MASK	0x0F
#define T_BOOL	0x10

/*
 * Flag values
 */
#define FL_LONG_OTP_PROMPT	0x00001
#define FL_IGNORE_DOT		0x00002
#define FL_MAIL_ALWAYS		0x00004
#define FL_MAIL_IF_NOUSER	0x00008
#define FL_MAIL_IF_NOHOST	0x00010
#define FL_MAIL_IF_NOPERMS	0x00020
#define FL_TTY_TICKETS		0x00040
#define FL_LECTURE		0x00080
#define FL_AUTHENTICATE		0x00100
#define FL_ROOT_SUDO		0x00200
#define FL_LOG_HOST		0x00400
#define FL_SHELL_NOARGS		0x00800
#define FL_SET_HOME		0x01000
#define FL_PATH_INFO		0x02000
#define FL_FQDN			0x04000
#define FL_INSULTS		0x08000
#define FL_MAX			0xFFFFF

/*
 * Indexes into sudo_inttable
 */
#define	I_FLAGS		0	/* various flags, as listed above */
#define	I_LOGFAC	1	/* syslog facility */
#define	I_GOODPRI	2	/* syslog priority for successful auth */
#define	I_BADPRI	3	/* syslog priority for unsuccessful auth */
#define	I_LOGLEN	4	/* wrap log file line after N chars */
#define	I_TS_TIMEOUT	5	/* timestamp stale after N minutes */
#define	I_PW_TIMEOUT	6	/* exit if pass not entered in N minutes */
#define	I_PW_TRIES	7	/* exit after N bad password tries */
#define	I_UMASK		8	/* umask to use or 0777 to use user's */

/*
 * Indexes into sudo_strtable
 */
#define	I_LOGFILE	0	/* path to logfile (or NULL for none) */
#define	I_MAILERPATH	1	/* path to sendmail or other mailer */
#define	I_MAILERARGS	2	/* flags to pass to the mailer */
#define	I_ALERTMAIL	3	/* who to send bitch mail to */
#define	I_MAILSUB	4	/* subject line of mail msg */
#define	I_BADPASS_MSG	5	/* what to say when passwd is wrong */
#define	I_TIMESTAMPDIR	6	/* path to timestamp dir */
#define	I_EXEMPT_GRP	7	/* no password or PATH override for these */
#define	I_PASSPROMPT	8	/* password prompt */
#define	I_RUNAS_DEF	9	/* default user to run commands as */
#define	I_SECURE_PATH	10	/* set $PATH to this if not NULL */

#define SUDO_INTTABLE_LAST	9
#define SUDO_STRTABLE_LAST	11

#define sudo_flag_set(_f)	(sudo_inttable[I_FLAGS] & (_f))

extern unsigned int sudo_inttable[SUDO_INTTABLE_LAST];
extern char *sudo_strtable[SUDO_STRTABLE_LAST];

/*
 * Prototypes
 */
void dump_default	__P((void));
int set_default		__P((char *, char *, int));
void init_defaults	__P((void));
void list_options	__P((void));

#endif /* _SUDO_DEFAULTS_H */
