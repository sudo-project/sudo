/*
 * Copyright (c) 1999 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#ifndef SUDO_AUTH_H
#define SUDO_AUTH_H

#define AUTH_SUCCESS	0
#define AUTH_FAILURE	1
#define AUTH_FATAL	2

typedef struct sudo_auth {
    int need_root;		/* must run as root? */
    int configured;		/* auth type configured on this host? */
    int status;			/* status from verify routine */
    char *name;
    void *data;			/* method-specific data pointer */
    int (*setup) __P((struct passwd *pw, char **prompt, void **data));
    int (*verify) __P((struct passwd *pw, char *p, void **data));
    int (*cleanup) __P((struct passwd *pw, int status, void **data));
} sudo_auth;

/* Prototypes for standalone methods */
int fwtk_setup __P((struct passwd *pw, char **prompt, void **data));
int fwtk_verify __P((struct passwd *pw, char *prompt, void **data));
int fwtk_cleanup __P((struct passwd *pw, int status, void **data));
int pam_setup __P((struct passwd *pw, char **prompt, void **data));
int pam_verify __P((struct passwd *pw, char *prompt, void **data));
int pam_cleanup __P((struct passwd *pw, int status, void **data));
int sia_setup __P((struct passwd *pw, char **prompt, void **data));
int sia_verify __P((struct passwd *pw, char *prompt, void **data));
int sia_cleanup __P((struct passwd *pw, int status, void **data));
int aixauth_verify __P((struct passwd *pw, char *pass, void **data));
int dce_verify __P((struct passwd *pw, char *pass, void **data));

/* Prototypes for normal methods */
int passwd_verify __P((struct passwd *pw, char *pass, void **data));
int secureware_setup __P((struct passwd *pw, char **prompt, void **data));
int secureware_verify __P((struct passwd *pw, char *pass, void **data));
int rfc1938_setup __P((struct passwd *pw, char **prompt, void **data));
int rfc1938_verify __P((struct passwd *pw, char *pass, void **data));
int afs_verify __P((struct passwd *pw, char *pass, void **data));
int kerb4_setup __P((struct passwd *pw, char **prompt, void **data));
int kerb4_verify __P((struct passwd *pw, char *pass, void **data));
int kerb5_setup __P((struct passwd *pw, char **prompt, void **data));
int kerb5_verify __P((struct passwd *pw, char *pass, void **data));

/* Fields: need_root, name, setup, verify, cleanup */
#define AUTH_ENTRY(r, n, s, v, c) { r, 1, AUTH_FAILURE, n, NULL, s, v, c },

/* Some methods cannots (or should not) interoperate with any others */
#if defined(HAVE_PAM)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "pam", pam_setup, pam_verify, pam_cleanup)
#elif defined(HAVE_SECURID)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "SecurId", securid_setup, securid_verify, NULL)
#elif defined(HAVE_SIA)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "sia", sia_setup, sia_verify, sia_cleanup)
#elif defined(HAVE_DCE)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "dce", NULL, dce_verify, NULL)
#elif defined(HAVE_AUTHENTICATE)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "aixauth", NULL, aixauth_verify, NULL)
#elif defined(HAVE_FWTK)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "fwtk", fwtk_setup, fwtk_verify, fwtk_cleanup)
#elif defined(OTP_ONLY) && (defined(HAVE_SKEY) || defined(HAVE_OPIE))
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "rfc1938", rfc1938_setup, rfc1938_verify, NULL)
#  define AUTH_STANDALONE_GETPASS
#endif

#endif /* SUDO_AUTH_H */
