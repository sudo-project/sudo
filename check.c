/*
 * CU sudo version 1.3 (based on Root Group sudo version 1.1)
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

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/file.h>
#include <pwd.h>
#include "sudo.h"
#include "insults.h"

char *getpass();

static int check_timestamp();
static void check_passwd();
static void update_timestamp();
static void reminder();
static char *timestampfile_p;

static int timedir_is_good;


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

    umask(077);			/* make sure the timestamp files are private */

    if (setuid(0)) {		/* have to be root to see timestamps */
	perror("setuid(0)");
	exit(1);
    }
    rtn = check_timestamp();
    if (setruid(uid)) {		/* don't want to be root longer than
				 * necessary */
#ifndef _AIX
	perror("setruid(uid)");
	exit(1);
#endif
    }
    if (rtn && uid)		/* if timestamp is not current... */
	check_passwd();

    if (setuid(0)) {		/* have to be root to play with timestamps */
	perror("setuid(0)");
	exit(1);
    }
    update_timestamp();
    if (setruid(uid)) {		/* don't want to be root longer than
				 * necessary */
#ifndef _AIX
	perror("setruid(uid)");
	exit(1);
#endif
    }
    umask(022);			/* want a real umask to exec() the command */

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

    (void) sprintf(timestampfile, "%s/%s", TIMEDIR, user);
    timestampfile_p = timestampfile;

    timedir_is_good = 1;	/* now there's an assumption for ya... */


    /*
     * walk through the path one directory at a time
     */
    for (p = timestampfile + 1; p = index(p, '/'); *p++ = '/') {
	*p = '\0';
	if (stat(timestampfile, &statbuf) < 0) {
	    if (strcmp(timestampfile, TIMEDIR))
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
	    if (uid)
		reminder();	/* if not, do the reminder */
	    timestamp_is_old = 1;	/* and return (1)          */
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
	timestamp_is_old = 1;	/* user has to enter password */
	if (mkdir(TIMEDIR, 0700)) {	/* make the TIMEDIR directory */
	    perror("check_timestamp: mkdir");
	    timedir_is_good = 0;
	} else {
	    timedir_is_good = 1;/* TIMEDIR now exists         */
	    reminder();
	}
    }

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

    if (timedir_is_good) {
	unlink(timestampfile_p);
	if ((fd = open(timestampfile_p, O_WRONLY | O_CREAT | O_TRUNC, 0600)) < 0)
	    perror("update_timestamp: open");
	close(fd);
    }
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
#if !(defined (linux) && defined (SHADOW_PWD))
    char *crypt();
#endif /* linux */
    struct passwd *pw_ent;
    char *encrypted;		/* this comes from /etc/passwd  */
    char *pass;			/* this is what gets entered    */
    register int counter = TRIES_FOR_PASSWORD;

    if ((pw_ent = getpwuid(uid)) == NULL) {
	(void) sprintf(user, "%u", uid);
	log_error(GLOBAL_NO_PW_ENT);
	inform_user(GLOBAL_NO_PW_ENT);
	exit(1);
    }
    encrypted = pw_ent -> pw_passwd;

    /*
     * you get TRIES_FOR_PASSWORD times to guess your password
     */
    while (counter > 0) {
	pass = getpass("Password:");
	if (*pass == (char) NULL)
	    exit(0);
	if (!strcmp(encrypted, crypt(pass, encrypted)))
	    return;		/* if the passwd is correct return() */
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
    (void) fprintf(stderr, "\n%s\n%s\n%s\n\n%s\n%s\n\n%s\n%s\n\n",
	"    CU sudo version 1.3, based on Root Group sudo version 1.1",
	"    sudo version 1.1, Copyright (C) 1991 The Root Group, Inc.",
	"    sudo comes with ABSOLUTELY NO WARRANTY.  This is free software,",
	"    and you are welcome to redistribute it under certain conditions.",
#endif
	"We trust you have received the usual lecture from the local Systems",
	"Administrator. It usually boils down to these two things:",
	"        #1) Respect the privacy of others.",
	"        #2) Think before you type."
    );
    
    (void)fflush(stderr);
}
