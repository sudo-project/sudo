/*
 * CU sudo version 1.4 (based on Root Group sudo version 1.1)
 *
 * This software comes with no waranty whatsoever, use at your own risk.
 *
 * Please send bugs, changes, problems to sudo-bugs@cs.colorado.edu
 *
 */

/*
 *  sudo version 1.1 allows users to execute commands as root
 *  Copyright (C) 1991  The Root Group, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *******************************************************************
 *
 *  check.c
 *
 *  check_user() only returns if the user's timestamp file
 *  is current or if they enter a correct password.
 *
 *  Jeff Nieusma  Thu Mar 21 22:39:07 MST 1991
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

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
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
#include "sudo.h"
#include <options.h>
#include "insults.h"
#if defined(SHADOW_TYPE) && (SHADOW_TYPE == SPW_SECUREWARE)
#  include <sys/security.h>
#  include <prot.h>
#endif /* SHADOW_TYPE == SPW_SECUREWARE */
#ifdef HAVE_KERB4
#  include <krb.h>
#endif /* HAVE_KERB4 */
#ifdef HAVE_AFS
#  include <usersec.h>
#  include <afs/kauth.h>
#  include <afs/kautils.h>
#endif /* HAVE_AFS */
#ifdef HAVE_SECURID
#  include <sdi_athd.h>
#  include <sdconf.h>
#  include <sdacmvls.h>
#endif /* HAVE_SECURID */
#ifdef HAVE_SKEY
#  include <skey.h>
#endif /* HAVE_SKEY */
#ifdef HAVE_UTIME
#  ifdef HAVE_UTIME_H
#    include <utime.h>
#  endif /* HAVE_UTIME_H */
#else
#  include "emul/utime.h"
#endif /* HAVE_UTIME */


/*
 * Prototypes for local functions
 */
static int   check_timestamp		__P((void));
static void  check_passwd		__P((void));
static int   touch			__P((char *));
static void  update_timestamp		__P((void));
static void  reminder			__P((void));
#ifdef HAVE_KERB4
static int   sudo_krb_validate_user	__P((struct passwd *, char *));
#endif /* HAVE_KERB4 */
#ifdef HAVE_SKEY
static char *sudo_skeyprompt		__P((struct skey *, char *));
#endif /* HAVE_SKEY */
int   user_is_exempt			__P((void));

/*
 * Globals
 */
static int   timedir_is_good;
static char  timestampfile[MAXPATHLEN + 1];
#ifdef HAVE_SECURID
union config_record configure;
#endif /* HAVE_SECURID */
#ifdef HAVE_SKEY
struct skey skey;
#endif
#if (SHADOW_TYPE == SPW_SECUREWARE) && defined(__alpha)
extern uchar_t crypt_type;
#endif /* SPW_SECUREWARE && __alpha */



/********************************************************************
 *
 *  check_user()
 *
 *  This function only returns if the user can successfully
 *  verify who s/he is.  
 */

void check_user()
{
    register int rtn;
    mode_t oldmask;

    if (user_is_exempt())	/* some users don't need to enter a passwd */
	return;

    oldmask = umask(077);	/* make sure the timestamp files are private */

    rtn = check_timestamp();
    if (rtn && user_uid) {	/* if timestamp is not current... */
	if (rtn == 2)
	    reminder();		/* do the reminder if ticket file is new */
	check_passwd();
    }

    update_timestamp();
    (void) umask(oldmask);	/* want a real umask to exec() the command */

}



/********************************************************************
 *
 *  user_is_exempt()
 *
 *  this function checks the user is exempt from supplying a password.
 */

int user_is_exempt()
{
#ifdef EXEMPTGROUP
    struct group *grp;
    char **gr_mem;

    if ((grp = getgrnam(EXEMPTGROUP)) == NULL)
	return(FALSE);

    if (getgid() == grp->gr_gid)
	return(TRUE);

    for (gr_mem = grp->gr_mem; *gr_mem; gr_mem++) {
	if (strcmp(user_name, *gr_mem) == 0)
	    return(TRUE);
    }

    return(FALSE);
#else
    return(FALSE);
#endif
}



/********************************************************************
 *
 *  check_timestamp()
 *
 *  this function checks the timestamp file.  If it is within
 *  TIMEOUT minutes, no password will be required
 */

static int check_timestamp()
{
    register char *p;
    struct stat statbuf;
    register int timestamp_is_old = -1;
    time_t now;

#ifdef USE_TTY_TICKETS
    if (p = strrchr(tty, '/'))
	p++;
    else
	p = tty;

    (void) sprintf(timestampfile, "%s/%s.%s", _PATH_SUDO_TIMEDIR, user_name, p);
#else
    (void) sprintf(timestampfile, "%s/%s", _PATH_SUDO_TIMEDIR, user_name);
#endif /* USE_TTY_TICKETS */

    timedir_is_good = 1;	/* now there's an assumption for ya... */

    /* become root */
    set_perms(PERM_ROOT);

    /*
     * walk through the path one directory at a time
     */
    for (p = timestampfile + 1; (p = strchr(p, '/')); *p++ = '/') {
	*p = '\0';
	if (stat(timestampfile, &statbuf) < 0) {
	    if (strcmp(timestampfile, _PATH_SUDO_TIMEDIR))
		(void) fprintf(stderr, "Cannot stat() %s\n", timestampfile);
	    timedir_is_good = 0;
	    *p = '/';
	    break;
	}
    }

    /*
     * if all the directories are stat()able
     */
    if (timedir_is_good) {
	/*
	 * last component in _PATH_SUDO_TIMEDIR must be owned by root
	 * and mode 0700 or we ignore the timestamps in it.
	 */
	if (statbuf.st_uid != 0 || (statbuf.st_mode & 0000077)) {
	    timedir_is_good = 0;
	    timestamp_is_old = 2;
	    log_error(BAD_STAMPDIR);
	    inform_user(BAD_STAMPDIR);
	} else if (stat(timestampfile, &statbuf)) {
	    /* timestamp file does not exist? */
	    timestamp_is_old = 2;	/* return (2)          */
	} else {
	    /* check the time against the timestamp file */
	    now = time((time_t *) NULL);
	    if (TIMEOUT && now - statbuf.st_mtime < 60 * TIMEOUT)
		/* check for bogus time on the stampfile */
		if (statbuf.st_mtime > now + 60 * TIMEOUT * 2) {
		    timestamp_is_old = 2;	/* bogus time value */
		    log_error(BAD_STAMPFILE);
		    inform_user(BAD_STAMPFILE);
		} else {
		    timestamp_is_old = 0;	/* time value is reasonable */
		}
	    else
		timestamp_is_old = 1;	/* else make 'em enter password */
	}
    }
    /*
     * there was a problem stat()ing a directory
     */
    else {
	timestamp_is_old = 2;	/* user has to enter password + reminder */
	/* make the TIMEDIR directory */
	if (mkdir(_PATH_SUDO_TIMEDIR, S_IRWXU)) {
	    perror("check_timestamp: mkdir");
	    timedir_is_good = 0;
	} else {
	    timedir_is_good = 1;	/* _PATH_SUDO_TIMEDIR now exists */
	}
    }

    /* relinquish root */
    set_perms(PERM_USER);

    return (timestamp_is_old);
}



/********************************************************************
 *
 *  touch()
 *
 *  This function updates the access and modify times on a file
 *  via utime(2).
 */

static int touch(file)
    char *file;
{
#if defined(HAVE_UTIME) && !defined(HAVE_UTIME_NULL)
#ifdef HAVE_UTIME_POSIX
#define UTP		(&ut)
    struct utimbuf ut;

    ut.actime = ut.modtime = time(NULL);
#else
#define UTP		(ut)
    /* old BSD <= 4.3 has no struct utimbuf */
    time_t ut[2];

    ut[0] = ut[1] = time(NULL);
#endif /* HAVE_UTIME_POSIX */
#else
#define UTP		NULL
#endif /* HAVE_UTIME && !HAVE_UTIME_NULL */

    return(utime(file, UTP));
}
#undef UTP



/********************************************************************
 *
 *  update_timestamp()
 *
 *  This function changes the timestamp to "now"
 */

static void update_timestamp()
{
    if (timedir_is_good) {
	/* become root */
	set_perms(PERM_ROOT);

	if (touch(timestampfile) < 0) {
	    int fd = open(timestampfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	    if (fd < 0)
		perror("update_timestamp: open");
	    close(fd);
	}

	/* relinquish root */
	set_perms(PERM_USER);
    }
}



/********************************************************************
 *
 *  remove_timestamp()
 *
 *  This function removes the timestamp ticket file
 */

void remove_timestamp()
{
#ifdef USE_TTY_TICKETS
    char *p;

    if (p = strrchr(tty, '/'))
	p++;
    else
	p = tty;

    (void) sprintf(timestampfile, "%s/%s.%s", _PATH_SUDO_TIMEDIR, user_name, p);
#else
    (void) sprintf(timestampfile, "%s/%s", _PATH_SUDO_TIMEDIR, user_name);
#endif /* USE_TTY_TICKETS */

    /* become root */
    set_perms(PERM_ROOT);

    /* remove the ticket file */
    (void) unlink(timestampfile);

    /* relinquish root */
    set_perms(PERM_USER);
}



/********************************************************************
 *
 *  check_passwd()
 *
 *  This function grabs the user's password and checks with the password
 *  in /etc/passwd (or uses other specified authentication method).
 */

#ifdef HAVE_SECURID
static void check_passwd()
{
    struct SD_CLIENT sd_dat, *sd;		/* SecurID data block */
    register int counter = TRIES_FOR_PASSWORD;

    (void) memset (&sd_dat, 0, sizeof(sd_dat));
    sd = &sd_dat;

    /* Initialize SecurID. */
    set_perms(PERM_ROOT);
    creadcfg();
    if (sd_init(sd) != 0) {
	(void) fprintf(stderr, "%s: Cannot contact SecurID server\n", Argv[0]);
	exit(1);
    }

    /*
     * you get TRIES_FOR_PASSWORD times to guess your password
     */
    while (counter > 0) {
	if (sd_auth(sd) == ACM_OK) {
	    set_perms(PERM_USER);
	    return;
	}

	--counter;		/* otherwise, try again  */
#ifdef USE_INSULTS
	(void) fprintf(stderr, "%s\n", INSULT);
#else
	(void) fprintf(stderr, "%s\n", INCORRECT_PASSWORD);
#endif /* USE_INSULTS */
    }
    set_perms(PERM_USER);

    if (counter > 0) {
	log_error(PASSWORD_NOT_CORRECT);
	inform_user(PASSWORD_NOT_CORRECT);
    } else {
	log_error(PASSWORDS_NOT_CORRECT);
	inform_user(PASSWORDS_NOT_CORRECT);
    }

    exit(1);
}
#else /* !HAVE_SECURID */
static void check_passwd()
{
    char *pass;			/* this is what gets entered    */
    register int counter = TRIES_FOR_PASSWORD;
#ifdef HAVE_AFS
    int code;
    long password_expires = -1;
    char *reason;
#endif /* HAVE_AFS */
#if defined(SHADOW_TYPE) && (SHADOW_TYPE == SPW_SECUREWARE)
    char salt[2];		/* Need the salt to perform the encryption */
    register int i;
#endif /* SHADOW_TYPE == SECUREWARE */
#if defined(HAVE_KERB4) && defined(USE_GETPASS)
    char kpass[_PASSWD_LEN];
#endif /* HAVE_KERB4 && USE_GETPASS */

    /*
     * you get TRIES_FOR_PASSWORD times to guess your password
     */
    while (counter > 0) {

#ifdef HAVE_SKEY
    /* rewrite the prompt if using s/key since the challenge can change */
    set_perms(PERM_ROOT);
    prompt = sudo_skeyprompt(&skey, prompt);
    set_perms(PERM_USER);
#endif /* HAVE_SKEY */

    /* get a password from the user */
#ifdef USE_GETPASS
#  ifdef HAVE_KERB4
	(void) des_read_pw_string(kpass, sizeof(kpass) - 1, prompt, 0);
	pass = kpass;
#  else
	pass = (char *) getpass(prompt);
#  endif /* HAVE_KERB4 */
#else
	pass = tgetpass(prompt, PASSWORD_TIMEOUT * 60);
#endif /* USE_GETPASS */

	/* Exit loop on nil password */
	if (!pass || *pass == '\0') {
	    if (counter == TRIES_FOR_PASSWORD)
		exit(0);
	    else
		break;
	}

#ifdef HAVE_SKEY
	/* Only check s/key db if the user exists there */
	if (skey.logname) {
	    set_perms(PERM_ROOT);
	    if (skeyverify(&skey, pass) == 0) {
		set_perms(PERM_USER);
		return;             /* if the key is correct return() */
	    }
	    set_perms(PERM_USER);
	}
#endif /* HAVE_SKEY */
#if !defined(HAVE_SKEY) || !defined(SKEY_ONLY)
	/*
	 * If we use shadow passwords with a different crypt(3)
	 * check that here, else use standard crypt(3).
	 */
#  ifdef SHADOW_TYPE
#    if (SHADOW_TYPE == SPW_ULTRIX4)
	if (!strcmp(user_passwd, (char *)crypt16(pass, user_passwd)))
	    return;		/* if the passwd is correct return() */
#    endif /* ULTRIX4 */
#    if (SHADOW_TYPE == SPW_SECUREWARE) && !defined(__alpha)
	strncpy(salt, user_passwd, 2);
	i = AUTH_SALT_SIZE + AUTH_CIPHERTEXT_SEG_CHARS;
	if (strncmp(user_passwd, crypt(pass, salt), i) == 0)
	    return;           /* if the passwd is correct return() */
#    endif /* SECUREWARE && !__alpha */
#    if (SHADOW_TYPE == SPW_SECUREWARE) && defined(__alpha)
	if (crypt_type == AUTH_CRYPT_BIGCRYPT) {
	    if (!strcmp(user_passwd, bigcrypt(pass, user_passwd)))
		return;             /* if the passwd is correct return() */
	} else if (crypt_type == AUTH_CRYPT_CRYPT16) {
	    if (!strcmp(user_passwd, crypt16(pass, user_passwd)))
		return;             /* if the passwd is correct return() */
	} else {
	    (void) fprintf(stderr,
                    "%s: Sorry, I don't know how to deal with crypt type %d.\n",
                    Argv[0]);
	    exit(1);
	}
#    endif /* SECUREWARE && __alpha */
#  endif /* SHADOW_TYPE */

	/* Normal UN*X password check */
	if (!strcmp(user_passwd, (char *) crypt(pass, user_passwd)))
	    return;		/* if the passwd is correct return() */

#  ifdef HAVE_KERB4
	if (user_uid && sudo_krb_validate_user(user_pw_ent, pass) == 0)
	    return;
#  endif /* HAVE_KERB4 */

#  ifdef HAVE_AFS
	code = ka_UserAuthenticateGeneral(KA_USERAUTH_VERSION+KA_USERAUTH_DOSETPAG,
                                          user_name,
                                          (char *) 0, 
                                          (char *) 0,
                                          pass,
                                          0,
                                          &password_expires,
                                          0,
                                          &reason);
	if (code == 0)
	    return;
#  endif /* HAVE_AFS */
#  ifdef HAVE_DCE
	/* 
	 * consult the DCE registry for password validation
	 * note that dce_pwent trashes pass upon return...
	 */
	if (dce_pwent(user_name, pass))
	    return;
#  endif /* HAVE_DCE */
#endif /* !HAVE_SKEY || !SKEY_ONLY */

	--counter;		/* otherwise, try again  */
#ifdef USE_INSULTS
	(void) fprintf(stderr, "%s\n", INSULT);
#else
	(void) fprintf(stderr, "%s\n", INCORRECT_PASSWORD);
#endif /* USE_INSULTS */
    }

    if (counter > 0) {
	log_error(PASSWORD_NOT_CORRECT);
	inform_user(PASSWORD_NOT_CORRECT);
    } else {
	log_error(PASSWORDS_NOT_CORRECT);
	inform_user(PASSWORDS_NOT_CORRECT);
    }

    exit(1);
}
#endif /* HAVE_SECURID */


#ifdef HAVE_KERB4
/********************************************************************
 *
 *  sudo_krb_validate_user()
 *
 *  Validate a user via kerberos.
 */
static int sudo_krb_validate_user(pw_ent, pass)
    struct passwd *pw_ent;
    char *pass;
{
    char realm[REALM_SZ];
    char tkfile[sizeof(_PATH_SUDO_TIMEDIR) + 4 + MAX_UID_T_LEN];
    int k_errno;

    /* Get the local realm */
    if (krb_get_lrealm(realm, 1) != KSUCCESS)
	(void) fprintf(stderr, "Warning: Unable to get local kerberos realm\n");

    /*
     * Set the ticket file to be in sudo sudo timedir so we don't
     * wipe out other kerberos tickets.
     */
    (void) sprintf(tkfile, "%s/tkt%ld", _PATH_SUDO_TIMEDIR,
		   (long) pw_ent->pw_uid);
    (void) krb_set_tkt_string(tkfile);

    /*
     * Update the ticket if password is ok.  Kerb4 expects
     * the ruid and euid to be the same here so we setuid to root.
     */
    set_perms(PERM_ROOT);
    k_errno = krb_get_pw_in_tkt(pw_ent->pw_name, "", realm, "krbtgt", realm,
	DEFAULT_TKT_LIFE, pass);

    /*
     * If we authenticated, destroy the ticket now that we are done with it.
     * If not, warn on a "real" error.
     */
    if (k_errno == INTK_OK)
	dest_tkt();
    else if (k_errno != INTK_BADPW && k_errno != KDC_PR_UNKNOWN)
	(void) fprintf(stderr, "Warning: Kerberos error: %s\n",
		       krb_err_txt[k_errno]);

    /* done with rootly stuff */
    set_perms(PERM_USER);

    return(!(k_errno == INTK_OK));
}
#endif /* HAVE_KERB4 */


#ifdef HAVE_SKEY
/********************************************************************
 *
 *  sudo_skeyprompt()
 *
 *  This function rewrites and return the prompt based the
 *  s/key challenge *  and fills in the user's skey structure.
 */

static char *sudo_skeyprompt(user_skey, p)
    struct skey *user_skey;
    char *p;
{
    char skeyprompt[80];
#ifndef LONG_SKEY_PROMPT
    static char *old_prompt = NULL;
    static int plen;
    char *new_prompt;
#endif /* LONG_SKEY_PROMPT */

    /* return the old prompt if we cannot get s/key info */
    if (skeychallenge(user_skey, user_name, skeyprompt)) {
#  ifdef SKEY_ONLY
	(void) fprintf(stderr, "%s: You do not exist in the s/key database.\n",
		       Argv[0]);
	exit(1);
#  else
	user_skey->logname = NULL;
	return(p);
#  endif /* SKEY_ONLY */
    }

#ifdef LONG_SKEY_PROMPT
    /* separate s/key challenge and prompt for easy snarfing */
    if (skeyprompt[0] == 's' && skeyprompt[1] == '/')
	(void) puts(&skeyprompt[2]);
    else
	(void) puts(skeyprompt);

    /* return old prompt unmodified */
    return(p);

#else

    /* keep a pointer to the original prompt around for future reference */
    if (old_prompt == NULL) {
	old_prompt = p;
	plen = strlen(p);

	/* ignore trailing colon's */
	if (p[plen - 1] == ':')
	    plen--;
    } else {
	(void) free(p);
    }

    if ((new_prompt = (char *) malloc(plen + strlen(skeyprompt) + 5)) == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* embed the s/key challenge into the new password prompt */
    (void) strncpy(new_prompt, old_prompt, plen);
    (void) sprintf(new_prompt + plen, " [%s]:", skeyprompt);

    return(new_prompt);
#endif /* LONG_SKEY_PROMPT */
}
#endif /* HAVE_SKEY */


/********************************************************************
 *
 *  reminder()
 *
 *  this function just prints the the reminder message
 */

static void reminder()
{
#ifdef SHORT_MESSAGE
    (void) fprintf(stderr, "\n%s\n%s\n\n%s\n%s\n\n",
#else
    (void) fprintf(stderr, "\n%s\n%s\n%s\n%s\n\n%s\n%s\n\n%s\n%s\n\n",
	"    CU sudo version 1.4, based on Root Group sudo version 1.1",
	"    sudo version 1.1, Copyright (C) 1991 The Root Group, Inc.",
	"    sudo comes with ABSOLUTELY NO WARRANTY.  This is free software,",
	"    and you are welcome to redistribute it under certain conditions.",
#endif
	"We trust you have received the usual lecture from the local System",
	"Administrator. It usually boils down to these two things:",
	"        #1) Respect the privacy of others.",
	"        #2) Think before you type."
    );
    
    (void) fflush(stderr);
}
