/*
 * CU sudo version 1.3.1 (based on Root Group sudo version 1.1)
 *
 * This software comes with no waranty whatsoever, use at your own risk.
 *
 * Please send bugs, changes, problems to sudo-bugs.cs.colorado.edu
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
#include <pwd.h>
#include "sudo.h"
#include "insults.h"
#ifdef __svr4__
#include <shadow.h>
#endif /* __svr4__ */
#if defined(ultrix) && defined(HAVE_C2_SECURITY)
#include <auth.h>
#endif /* ultrix && HAVE_C2_SECURITY */
#if defined(__convex__) && defined(HAVE_C2_SECURITY)
#include <sys/security.h>
#include <prot.h>
#endif /* __convex__ && HAVE_C2_SECURITY */
#ifdef HAVE_AFS
#include <usersec.h>
#include <afs/kauth.h>
#include <afs/kautils.h>
#endif /* HAVE_AFS */


/*
 * Prototypes for local functions
 */
static int   check_timestamp	__P((void));
static void  check_passwd	__P((void));
static void  update_timestamp	__P((void));
static void  reminder		__P((void));

/*
 * Globals
 */
static int   timedir_is_good;
static char *timestampfile_p;


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
    be_root();

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
	if (stat(timestampfile, &statbuf)) {	/* does the file exist?    */
	    timestamp_is_old = 2;	/* return (2)          */
	} else {		/* otherwise, check the time */
	    now = time((time_t *) NULL);
	    if (now - statbuf.st_mtime < 60 * TIMEOUT)
		timestamp_is_old = 0;	/* if file is recent, return(0) */
	    else
		timestamp_is_old = 1;	/* else make 'em enter password */
	}
    }
    /*
     * there was a problem stat()ing a directory
     */
    else {
	timestamp_is_old = 2;	/* user has to enter password + reminder */
	if (mkdir(_PATH_SUDO_TIMEDIR, 0700)) {	/* make the TIMEDIR directory */
	    perror("check_timestamp: mkdir");
	    timedir_is_good = 0;
	} else {
	    timedir_is_good = 1;/* _PATH_SUDO_TIMEDIR now exists         */
	}
    }

    /* relinquish root */
    be_user();

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
    register int fd;

    /* become root */
    be_root();

    if (timedir_is_good) {
	(void) unlink(timestampfile_p);
	if ((fd = open(timestampfile_p, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0)
	    perror("update_timestamp: open");
	close(fd);
    }

    /* relinquish root */
    be_user();
}



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
    be_root();

    /* remove the ticket file */
    (void) unlink(timestampfile);

    /* relinquish root */
    be_user();
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
#if defined (__hpux) && defined(HAVE_C2_SECURITY)
    struct s_passwd *spw_ent;
#endif /* __hpux && HAVE_C2_SECURITY */
#if defined (ultrix) && defined(HAVE_C2_SECURITY)
    AUTHORIZATION *spw_ent;
#endif /* ultrix && HAVE_C2_SECURITY */
#if defined (__convex__) && defined(HAVE_C2_SECURITY)
    char salt[2];		/* Need the salt to perform the encryption */
    register int i;
    struct pr_passwd *spw_ent;
#endif /* __convex__ && HAVE_C2_SECURITY */
    char *encrypted=epasswd;	/* this comes from /etc/passwd  */
    char *pass;			/* this is what gets entered    */
    register int counter = TRIES_FOR_PASSWORD;

#if defined (__hpux) && defined(HAVE_C2_SECURITY)
    /*
     * grab encrypted password from shadow pw file
     * or just use the regular one...
     */
    be_root();
    spw_ent = getspwuid(uid);
    be_user();
    if (spw_ent && spw_ent -> pw_passwd)
	encrypted = spw_ent -> pw_passwd;
#endif /* __hpux && HAVE_C2_SECURITY */
#if defined (ultrix) && defined(HAVE_C2_SECURITY)
    /*
     * grab encrypted password from /etc/auth
     * or just use the regular one...
     */
    be_root();
    spw_ent = getauthuid(uid);
    be_user();
    if (spw_ent && spw_ent -> a_password)
	encrypted = spw_ent -> a_password;
#endif /* ultrix && HAVE_C2_SECURITY */
#ifdef __svr4__
    /*
     * SVR4 should always have a shadow password file
     * so if this fails it is a fatal error.
     */
    be_root();
    spw_ent = getspnam(user);
    be_user();
    if (spw_ent == NULL) {
	(void) sprintf(user, "%u", uid);
	log_error(GLOBAL_NO_PW_ENT);
	inform_user(GLOBAL_NO_PW_ENT);
	exit(1);
    }
    encrypted = spw_ent -> sp_pwdp;
#endif /* __svr4__ */
#if defined (__convex__) && defined(HAVE_C2_SECURITY)
    /*
     * Convex with C2 security
     */
    be_root();
    spw_ent = getprpwnam(pw_ent->pw_name);
    be_user();
    if (spw_ent == (struct pr_passwd *)NULL) {
	(void) sprintf(user, "%u", uid);
	log_error(GLOBAL_NO_AUTH_ENT);
	inform_user(GLOBAL_NO_AUTH_ENT);
	exit(1);
    }
    encrypted = spw_ent->ufld.fd_encrypt;
#endif /* __convex__ && HAVE_C2_SECURITY */

    /*
     * you get TRIES_FOR_PASSWORD times to guess your password
     */
    while (counter > 0) {
#ifdef USE_GETPASS
	pass = (char *) getpass("Password:");
#else
	pass = tgetpass("Password:", PASSWORD_TIMEOUT);
#endif /* USE_GETPASS */
	if (!pass || *pass == '\0')
	    exit(0);
#if defined (__convex__) && defined(HAVE_C2_SECURITY)
	strncpy(salt, spw_ent->ufld.fd_encrypt, 2);
	i = AUTH_SALT_SIZE + AUTH_CIPHERTEXT_SEG_CHARS;
	if (strncmp(encrypted, crypt(pass, salt), i) == 0)
	    return;           /* if the passwd is correct return() */
#else
#if defined (ultrix) && defined(HAVE_C2_SECURITY)
	if (spw_ent && !strcmp(encrypted, (char *) crypt16(pass, encrypted)))
	    return;		/* if the passwd is correct return() */
#endif /* ultrix && HAVE_C2_SECURITY */
	if (!strcmp(encrypted, (char *) crypt(pass, encrypted)))
	    return;		/* if the passwd is correct return() */
#endif /* __convex__ && HAVE_C2_SECURITY */
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

    log_error(PASSWORD_NOT_CORRECT);
    inform_user(PASSWORD_NOT_CORRECT);

    exit(1);
}



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
