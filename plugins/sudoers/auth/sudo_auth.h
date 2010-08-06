/*
 * Copyright (c) 1999-2005, 2007-2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef SUDO_AUTH_H
#define SUDO_AUTH_H

/* Auth function return values.  */
#define AUTH_SUCCESS	0
#define AUTH_FAILURE	1
#define AUTH_INTR	2
#define AUTH_FATAL	3

typedef struct sudo_auth {
    int flags;			/* various flags, see below */
    int status;			/* status from verify routine */
    char *name;			/* name of the method as a string */
    void *data;			/* method-specific data pointer */
    int (*init)(struct passwd *pw, char **prompt, struct sudo_auth *auth);
    int (*setup)(struct passwd *pw, char **prompt, struct sudo_auth *auth);
    int (*verify)(struct passwd *pw, char *p, struct sudo_auth *auth);
    int (*cleanup)(struct passwd *pw, struct sudo_auth *auth);
    int (*begin_session)(struct passwd *pw, struct sudo_auth *auth);
    int (*end_session)(struct sudo_auth *auth);
} sudo_auth;

/* Values for sudo_auth.flags.  */
#define FLAG_USER	0x01	/* functions must run as the user, not root */
#define FLAG_DISABLED	0x02	/* method disabled */
#define FLAG_STANDALONE	0x04	/* standalone auth method */
#define FLAG_ONEANDONLY	0x08	/* one and only auth method */

/* Shortcuts for using the flags above. */
#define NEEDS_USER(x)		((x)->flags & FLAG_USER)
#define IS_DISABLED(x)		((x)->flags & FLAG_DISABLED)
#define IS_STANDALONE(x)	((x)->flags & FLAG_STANDALONE)
#define IS_ONEANDONLY(x)	((x)->flags & FLAG_ONEANDONLY)

/* Like tgetpass() but uses conversation function */
char *auth_getpass(const char *prompt, int timeout, int type);

/* Pointer to conversation function to use with auth_getpass(). */
extern sudo_conv_t sudo_conv;

/* Prototypes for standalone methods */
int fwtk_init(struct passwd *pw, char **prompt, sudo_auth *auth);
int fwtk_verify(struct passwd *pw, char *prompt, sudo_auth *auth);
int fwtk_cleanup(struct passwd *pw, sudo_auth *auth);
int pam_init(struct passwd *pw, char **prompt, sudo_auth *auth);
int pam_verify(struct passwd *pw, char *prompt, sudo_auth *auth);
int pam_cleanup(struct passwd *pw, sudo_auth *auth);
int pam_begin_session(struct passwd *pw, sudo_auth *auth);
int pam_end_session(sudo_auth *auth);
int sia_setup(struct passwd *pw, char **prompt, sudo_auth *auth);
int sia_verify(struct passwd *pw, char *prompt, sudo_auth *auth);
int sia_cleanup(struct passwd *pw, sudo_auth *auth);
int aixauth_verify(struct passwd *pw, char *pass, sudo_auth *auth);
int aixauth_cleanup(struct passwd *pw, sudo_auth *auth);
int bsdauth_init(struct passwd *pw, char **prompt, sudo_auth *auth);
int bsdauth_verify(struct passwd *pw, char *prompt, sudo_auth *auth);
int bsdauth_cleanup(struct passwd *pw, sudo_auth *auth);

/* Prototypes for normal methods */
int passwd_init(struct passwd *pw, char **prompt, sudo_auth *auth);
int passwd_verify(struct passwd *pw, char *pass, sudo_auth *auth);
int passwd_cleanup(struct passwd *pw, sudo_auth *auth);
int secureware_init(struct passwd *pw, char **prompt, sudo_auth *auth);
int secureware_verify(struct passwd *pw, char *pass, sudo_auth *auth);
int secureware_cleanup(struct passwd *pw, sudo_auth *auth);
int rfc1938_setup(struct passwd *pw, char **prompt, sudo_auth *auth);
int rfc1938_verify(struct passwd *pw, char *pass, sudo_auth *auth);
int afs_verify(struct passwd *pw, char *pass, sudo_auth *auth);
int dce_verify(struct passwd *pw, char *pass, sudo_auth *auth);
int kerb4_init(struct passwd *pw, char **prompt, sudo_auth *auth);
int kerb4_verify(struct passwd *pw, char *pass, sudo_auth *auth);
int kerb5_init(struct passwd *pw, char **prompt, sudo_auth *auth);
int kerb5_verify(struct passwd *pw, char *pass, sudo_auth *auth);
int kerb5_cleanup(struct passwd *pw, sudo_auth *auth);
int securid_init(struct passwd *pw, char **prompt, sudo_auth *auth);
int securid_setup(struct passwd *pw, char **prompt, sudo_auth *auth);
int securid_verify(struct passwd *pw, char *pass, sudo_auth *auth);

/* Fields: name, flags, init, setup, verify, cleanup, begin_sess, end_sess */
#define AUTH_ENTRY(n, f, i, s, v, c, b, e) \
	{ (f), AUTH_FAILURE, (n), NULL, (i), (s), (v), (c) , (b), (e) },

#endif /* SUDO_AUTH_H */
