/*
 * CU sudo version 1.3.1 (based on Root Group sudo version 1.1)
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
#include "sudo.h"
#include "options.h"
#include "insults.h"
#ifdef __svr4__
#include <shadow.h>
#endif /* __svr4__ */
#if defined(__osf__) && defined(HAVE_C2_SECURITY)
#include <sys/security.h>
#include <prot.h>
#endif /* __osf__ && HAVE_C2_SECURITY */
#if defined(ultrix) && defined(HAVE_C2_SECURITY)
#include <auth.h>
#endif /* ultrix && HAVE_C2_SECURITY */
#if defined(__convex__) && defined(HAVE_C2_SECURITY)
#include <sys/security.h>
#include <prot.h>
#endif /* __convex__ && HAVE_C2_SECURITY */
#if defined(SUNOS4) && defined(HAVE_C2_SECURITY)
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#endif /* SUNOS4 && HAVE_C2_SECURITY */
#ifdef HAVE_KERB4
#include <krb.h>
#endif /* HAVE_KERB4 */
#ifdef HAVE_AFS
#include <usersec.h>
#include <afs/kauth.h>
#include <afs/kautils.h>
#endif /* HAVE_AFS */
#ifdef HAVE_UTIME
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif /* HAVE_UTIME_H */
#else
#include "utime.h"
#endif /* HAVE_UTIME */


/*
 * Prototypes for local functions
 */
static int   check_timestamp		__P((void));
static void  check_passwd		__P((void));
static void  update_timestamp		__P((void));
static void  reminder			__P((void));
static char *osf_C2_crypt		__P((char *, char *));
static int   sudo_krb_validate_user	__P((char *, char *));
int   user_is_exempt			__P((void));

/*
 * Globals
 */
static int   timedir_is_good;
static char *timestampfile_p;

/*
 * Defines for Digital Un*x 3.x enhanced security
 */
#define C2_MAXPASS	100
#define C2_MAXENPASS	200
#define C2_SEGSIZE	8


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
    if (rtn && uid) {		/* if timestamp is not current... */
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
 *  this function checks the user is exempt from supplying a password
 *  XXX - should check more that just real gid via getgrnam.
 */

int user_is_exempt()
{
#ifdef EXEMPTGROUP
    return((getgid() == EXEMPTGROUP));
#else
    return(0);
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
    static char timestampfile[MAXPATHLEN + 1];
    register char *p;
    struct stat statbuf;
    register int timestamp_is_old = -1;
    time_t now;

    (void) sprintf(timestampfile, "%s/%s", _PATH_SUDO_TIMEDIR, user);
    timestampfile_p = timestampfile;

    timedir_is_good = 1;	/* now there's an assumption for ya... */

    /* become root */
    set_perms(PERM_ROOT);

    /*
     * walk through the path one directory at a time
     */
    for (p = timestampfile + 1; p = strchr(p, '/'); *p++ = '/') {
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
	if (statbuf.st_uid != 0 || !(statbuf.st_mode & S_IRWXU)) {
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
		if (statbuf.st_mtime > now + 60 * TIMEOUT) {
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
 *  update_timestamp()
 *
 *  This function changes the timestamp to now
 */

static void update_timestamp()
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

    if (timedir_is_good) {
	/* become root */
	set_perms(PERM_ROOT);

	if (utime(timestampfile_p, UTP) < 0) {
	    int fd = open(timestampfile_p, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	    if (fd < 0)
		perror("update_timestamp: open");
	    close(fd);
	}

	/* relinquish root */
	set_perms(PERM_USER);
    }
}
#undef UTP



/********************************************************************
 *
 *  remove_timestamp()
 *
 *  This function removes the timestamp ticket file
 */

void remove_timestamp()
{
    char timestampfile[MAXPATHLEN + 1];

    (void) sprintf(timestampfile, "%s/%s", _PATH_SUDO_TIMEDIR, user);

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
 *  This function grabs the user's password and checks with 
 *  the password in /etc/passwd
 */

static void check_passwd()
{
#ifdef HAVE_AFS
    int code;
    long password_expires = -1;
    char *reason;
#endif /* HAVE_AFS */
#ifdef __svr4__
    struct spwd *spw_ent;
#endif /* __svr4__ */
#if defined(__hpux) && defined(HAVE_C2_SECURITY)
    struct s_passwd *spw_ent;
#endif /* __hpux && HAVE_C2_SECURITY */
#if defined(SUNOS4) && defined(HAVE_C2_SECURITY)
    struct passwd_adjunct *pwa;
#endif /* SUNOS4 && HAVE_C2_SECURITY */
#if defined(__osf__) && defined(HAVE_C2_SECURITY)
    struct pr_passwd *spw_ent;
#endif /* __osf__ && HAVE_C2_SECURITY */
#if defined(ultrix) && defined(HAVE_C2_SECURITY)
    AUTHORIZATION *spw_ent;
#endif /* ultrix && HAVE_C2_SECURITY */
#if defined(__convex__) && defined(HAVE_C2_SECURITY)
    char salt[2];		/* Need the salt to perform the encryption */
    register int i;
    struct pr_passwd *spw_ent;
#endif /* __convex__ && HAVE_C2_SECURITY */
#ifdef HAVE_SKEY
    int pw_ok = 1;
    struct passwd *pw_ent = getpwuid(uid);
#endif /* HAVE_SKEY */
    char *encrypted=epasswd;	/* this comes from /etc/passwd  */
#if defined(HAVE_KERB4) && defined(USE_GETPASS)
    char kpass[_PASSWD_LEN];
#endif /* HAVE_KERB4 && USE_GETPASS */
    char *pass;			/* this is what gets entered    */
    register int counter = TRIES_FOR_PASSWORD;

#if defined(__hpux) && defined(HAVE_C2_SECURITY)
    /*
     * grab encrypted password from shadow pw file
     * or just use the regular one...
     */
    set_perms(PERM_ROOT);
    spw_ent = getspwuid(uid);
    set_perms(PERM_USER);
    if (spw_ent && spw_ent -> pw_passwd)
	encrypted = spw_ent -> pw_passwd;
#endif /* __hpux && HAVE_C2_SECURITY */
#if defined(__osf__) && defined(HAVE_C2_SECURITY)
    /*
     * grab encrypted password from protected passwd file
     * or just use the regular one...
     */
    set_perms(PERM_ROOT);
    spw_ent = getprpwuid(uid);
    set_perms(PERM_USER);
    if (spw_ent)
	encrypted = spw_ent -> ufld.fd_encrypt;
#endif /* __osf__ && HAVE_C2_SECURITY */
#if defined(ultrix) && defined(HAVE_C2_SECURITY)
    /*
     * grab encrypted password from /etc/auth
     * or just use the regular one...
     */
    set_perms(PERM_ROOT);
    spw_ent = getauthuid(uid);
    set_perms(PERM_USER);
    if (spw_ent && spw_ent -> a_password)
	encrypted = spw_ent -> a_password;
#endif /* ultrix && HAVE_C2_SECURITY */
#ifdef __svr4__
    /*
     * SVR4 should always have a shadow password file
     * so if this fails it is a fatal error.
     */
    set_perms(PERM_ROOT);
    spw_ent = getspnam(user);
    set_perms(PERM_USER);
    if (spw_ent == NULL) {
	(void) sprintf(user, "%u", uid);
	log_error(GLOBAL_NO_PW_ENT);
	inform_user(GLOBAL_NO_PW_ENT);
	exit(1);
    }
    encrypted = spw_ent -> sp_pwdp;
#endif /* __svr4__ */
#if defined(__convex__) && defined(HAVE_C2_SECURITY)
    /*
     * Convex with C2 security
     */
    set_perms(PERM_ROOT);
    spw_ent = getprpwnam(pw_ent->pw_name);
    set_perms(PERM_USER);
    if (spw_ent == (struct pr_passwd *)NULL) {
	(void) sprintf(user, "%u", uid);
	log_error(GLOBAL_NO_AUTH_ENT);
	inform_user(GLOBAL_NO_AUTH_ENT);
	exit(1);
    }
    encrypted = spw_ent->ufld.fd_encrypt;
#endif /* __convex__ && HAVE_C2_SECURITY */
#if defined(SUNOS4) && (HAVE_C2_SECURITY)
    /*
     * SunOS with C2 security
     */
    set_perms(PERM_ROOT);
    pwa = getpwanam(user);
    set_perms(PERM_USER);
    if (pwa == (struct passwd_adjunct *)NULL) {
	(void) sprintf(user, "%u", uid);
	log_error(GLOBAL_NO_PW_ENT);
	inform_user(GLOBAL_NO_PW_ENT);
	exit(1);
    }
#endif /* SUNOS4 && HAVE_C2_SECURITY */

    /*
     * you get TRIES_FOR_PASSWORD times to guess your password
     */
    while (counter > 0) {
#ifdef HAVE_SKEY
	pass = skey_getpass(prompt, pw_ent, pw_ok);
#else
#ifdef USE_GETPASS
#ifdef HAVE_KERB4
	(void) des_read_pw_string(kpass, sizeof(kpass) - 1, prompt, 0);
	pass = kpass;
#else
	pass = (char *) getpass(prompt);
#endif /* HAVE_KERB4 */
#else
	pass = tgetpass(prompt, PASSWORD_TIMEOUT * 60);
#endif /* USE_GETPASS */
#endif /* HAVE_SKEY */
	if (!pass || *pass == '\0')
	    if (counter == TRIES_FOR_PASSWORD)
		exit(0);
	    else
		break;
#if defined(__convex__) && defined(HAVE_C2_SECURITY)
	strncpy(salt, spw_ent->ufld.fd_encrypt, 2);
	i = AUTH_SALT_SIZE + AUTH_CIPHERTEXT_SEG_CHARS;
	if (strncmp(encrypted, crypt(pass, salt), i) == 0)
	    return;           /* if the passwd is correct return() */
#else
#if defined(ultrix) && defined(HAVE_C2_SECURITY)
	if (spw_ent && !strcmp(encrypted, (char *) crypt16(pass, encrypted)))
	    return;		/* if the passwd is correct return() */
#endif /* ultrix && HAVE_C2_SECURITY */
#if defined(__osf__) && defined(HAVE_C2_SECURITY)
	if (spw_ent && !strcmp(encrypted, osf_C2_crypt(pass,encrypted)))
	    return;             /* if the passwd is correct return() */
#endif /* __osf__ && HAVE_C2_SECURITY */
#ifdef HAVE_SKEY
	if (!strcmp(pw_ent->pw_passwd, skey_crypt(pass, pw_ent->pw_passwd,
	    pw_ent, pw_ok)))
	    return;             /* if the passwd is correct return() */
#else
	if (!strcmp(encrypted, (char *) crypt(pass, encrypted)))
	    return;		/* if the passwd is correct return() */
#endif /* HAVE_SKEY */
#endif /* __convex__ && HAVE_C2_SECURITY */
#ifdef HAVE_KERB4
	if (uid && sudo_krb_validate_user(user, pass) == 0)
	    return;
#endif /* HAVE_KERB4 */
#ifdef HAVE_AFS
	code = ka_UserAuthenticateGeneral(KA_USERAUTH_VERSION+KA_USERAUTH_DOSETPAG,
                                          user,
                                          (char *) 0, 
                                          (char *) 0,
                                          pass,
                                          0,
                                          &password_expires,
                                          0,
                                          &reason);
	if (code == 0)
	    return;
#endif /* HAVE_AFS */
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


#if defined(__osf__) && defined(HAVE_C2_SECURITY)
/********************************************************************
 * osf_C2_crypt()  - returns OSF/1 3.0 enhanced security encrypted
 *               password.  crypt() produces, given an eight
 *               character segment, an encrypted 13 character
 *               with the first two the salt and the remaining
 *               11 characters the encrypted password.  OSF/1 uses
 *               crypt() on each 8 character segment appending each
 *               resulting encrypted segment except the first two
 *               character (salt) after the first segement.  See
 *               OSF/1 Security documentation section 16.4.
 * Programmer: Richard Jackson, George Mason University
 */
static char *osf_C2_crypt(pass, encrypt_salt)
    char *pass;
    char *encrypt_salt;
{
    static char     enpass[C2_MAXENPASS];
    char   segpass[C2_MAXPASS];	    /* segment of original password */
    char   segenpass[C2_MAXENPASS]; /* segment of encrypted password */
    char   salt[3];		    /* salt for crypt() */
    int    segnum;		    /* num of 8 char pw segments to process */
    int    len;			    /* length of passwd */
    int    i;

    /*
     * calculate the num of pw segs to process
     */
    len = strlen(pass);
    if ((len % C2_SEGSIZE) > 0)
	segnum = (len / C2_SEGSIZE) + 1;	/* ie, 9 chars is 2 segments */
    else
	segnum = (len / C2_SEGSIZE);		/* ie, 8 chars is 1 segment */

    strncpy(salt, encrypt_salt, 2);		/* starting salt */
    for (i = 0; i < segnum; i++) {
	strncpy(segpass, (pass + (i * C2_SEGSIZE)), C2_SEGSIZE);

	strncpy(segenpass, (char *) crypt(segpass, salt), C2_MAXENPASS);

	strncpy(salt, (segenpass + 2), 2);  /* next salt is from previous seg */

	if (i == 0)
	    strncpy(enpass, segenpass, C2_MAXENPASS);
	else
	    strncat(enpass, (segenpass + 2), C2_MAXENPASS);
    }

    return(enpass);
}
#endif /* __osf__ && HAVE_C2_SECURITY */


#ifdef HAVE_KERB4
/********************************************************************
 *
 *  sudo_krb_validate_user()
 *
 *  Validate a user via kerberos.
 */
static int sudo_krb_validate_user(user, pass)
    char *user, *pass;
{
    char realm[REALM_SZ];
    char tkfile[13 + sizeof(_PATH_SUDO_TIMEDIR)];	/* uid is 10 char max */
    int k_errno;

    /* Get the local realm */
    if (krb_get_lrealm(realm, 1) != KSUCCESS)
	(void) fprintf(stderr, "Warning: Unable to get local kerberos realm\n");

    /*
     * Set the ticket file to be in sudo sudo timedir so we don't
     * wipe out other kerberos tickets.
     */
    (void) sprintf(tkfile, "%s/tkt%d", _PATH_SUDO_TIMEDIR, uid);
    (void) krb_set_tkt_string(tkfile);

    /*
     * Update the ticket if password is ok.  Kerb4 expects
     * the ruid and euid to be the same here so we setuid to root.
     */
    set_perms(PERM_ROOT);
    k_errno = krb_get_pw_in_tkt(user, "", realm, "krbtgt", realm,
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
	"    CU sudo version 1.3.1, based on Root Group sudo version 1.1",
	"    sudo version 1.1, Copyright (C) 1991 The Root Group, Inc.",
	"    sudo comes with ABSOLUTELY NO WARRANTY.  This is free software,",
	"    and you are welcome to redistribute it under certain conditions.",
#endif
	"We trust you have received the usual lecture from the local Systems",
	"Administrator. It usually boils down to these two things:",
	"        #1) Respect the privacy of others.",
	"        #2) Think before you type."
    );
    
    (void) fflush(stderr);
}
