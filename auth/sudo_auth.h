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
int aixauth_verify __P((struct passwd *pw, char *prompt, void **data));

/* Prototypes for normal methods */
int passwd_verify __P((struct passwd *pw, char *pass, void **data));
int secureware_setup __P((struct passwd *pw, char **prompt, void **data));
int secureware_verify __P((struct passwd *pw, char *pass, void **data));
int skey_setup __P((struct passwd *pw, char **prompt, void **data));
int skey_verify __P((struct passwd *pw, char *pass, void **data));
int opie_setup __P((struct passwd *pw, char **prompt, void **data));
int opie_verify __P((struct passwd *pw, char *pass, void **data));
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
	AUTH_ENTRY(1, "pam", pam_setup, passwd_verify, pam_cleanup)
#elif defined(HAVE_SECURID)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "SecurId", securid_setup, securid_verify, NULL)
#elif defined(HAVE_SIA)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "sia", sia_setup, sia_verify, sia_cleanup)
#elif defined(HAVE_AUTHENTICATE)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "aixauth", NULL, aixauth_verify, NULL)
#elif defined(HAVE_FWTK)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "fwtk", fwtk_setup, fwtk_verify, fwtk_cleanup)
#elif defined(HAVE_SKEY) && defined(OTP_ONLY)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "skey", skey_setup, skey_verify, NULL)
#  define AUTH_STANDALONE_GETPASS
#elif defined(HAVE_OPIE) && defined(OTP_ONLY)
#  define AUTH_STANDALONE \
	AUTH_ENTRY(1, "opie", opie_setup, opie_verify, NULL)
#  define AUTH_STANDALONE_GETPASS
#endif

#endif /* SUDO_AUTH_H */
