/*
 *  CU sudo version 1.6 -- allows users to execute commands as root and others
 *  Copyright (c) 1991  The Root Group, Inc.
 *  Copyright (c) 1994,1996,1998,1999 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 *  Please send bugs, changes, problems to sudo-bugs@courtesan.com
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
#include <signal.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_UTIME
#  ifdef HAVE_UTIME_H
#    include <utime.h>
#  endif /* HAVE_UTIME_H */
#else
#  include "emul/utime.h"
#endif /* HAVE_UTIME */

#include "sudo.h"
#include "version.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Prototypes for local functions
 */
static int   check_timestamp		__P((void));
static int   touch			__P((char *));
static void  update_timestamp		__P((void));
static void  reminder			__P((void));
static char *expand_prompt		__P((char *, char *, char *));
int   user_is_exempt			__P((void));


/*
 * Globals
 */
static int   timedir_is_good;
static char  timestampfile[MAXPATHLEN];


/********************************************************************
 *
 *  check_user()
 *
 *  This function only returns if the user can successfully
 *  verify who s/he is.  
 */

void
check_user()
{
    int rtn;
#ifdef POSIX_SIGNALS
    sigset_t set, oset;
#else
    int omask;
#endif /* POSIX_SIGNALS */

    if (user_is_exempt())	/* some users don't need to enter a passwd */
	return;

    /*
     * Block SIGINT and SIGTSTP during authentication so the user
     * can't abort the logging.
     */
#ifdef POSIX_SIGNALS
    (void) sigemptyset(&set);
    (void) sigaddset(&set, SIGINT);
    (void) sigaddset(&set, SIGTSTP);
    (void) sigprocmask(SIG_BLOCK, &set, &oset);
#else
    omask = sigblock(sigmask(SIGINT)|sigmask(SIGTSTP));
#endif /* POSIX_SIGNALS */

    rtn = check_timestamp();
    if (rtn && user_uid) {	/* if timestamp is not current... */
#ifndef NO_MESSAGE
	if (rtn == 2)
	    reminder();		/* do the reminder if ticket file is new */
#endif /* NO_MESSAGE */

	/* expand any escapes in the prompt */
	prompt = expand_prompt(prompt, user_name, shost);

#ifdef HAVE_SIA
	sia_attempt_auth();
#elif HAVE_PAM
	pam_attempt_auth();
#else  /* !HAVE_SIA && !HAVE_PAM */
	check_passwd();
#endif /* HAVE_SIA */
    }

    /* Unblock signals */
#ifdef POSIX_SIGNALS
    (void) sigprocmask(SIG_SETMASK, &oset, NULL);
#else
    (void) sigsetmask(omask);       
#endif /* POSIX_SIGNALS */

    update_timestamp();
}


/********************************************************************
 *
 *  user_is_exempt()
 *
 *  this function checks the user is exempt from supplying a password.
 */

int
user_is_exempt()
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

static int
check_timestamp()
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

    if (sizeof(_PATH_SUDO_TIMEDIR) + strlen(user_name) + strlen(p) + 2 >
	sizeof(timestampfile)) {
	(void) fprintf(stderr, "%s: path too long: %s/%s:%s\n", Argv[0],
		       _PATH_SUDO_TIMEDIR, user_name, p);
	exit(1);                                              
    }
    (void) sprintf(timestampfile, "%s/%s:%s", _PATH_SUDO_TIMEDIR, user_name, p);
#else
    if (sizeof(_PATH_SUDO_TIMEDIR) + strlen(user_name) + 1 >
	sizeof(timestampfile)) {
	(void) fprintf(stderr, "%s: path too long: %s/%s\n", Argv[0],
		       _PATH_SUDO_TIMEDIR, user_name);
	exit(1);                                              
    }
    (void) sprintf(timestampfile, "%s/%s", _PATH_SUDO_TIMEDIR, user_name);
#endif /* USE_TTY_TICKETS */

    timedir_is_good = 1;	/* now there's an assumption for ya... */

    /* become root */
    set_perms(PERM_ROOT, 0);

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
	    if (TIMEOUT && now - statbuf.st_mtime < 60 * TIMEOUT) {
		/* check for bogus time on the stampfile */
		if (statbuf.st_mtime > now + 60 * TIMEOUT * 2) {
		    timestamp_is_old = 2;	/* bogus time value */
		    log_error(BAD_STAMPFILE);
		    inform_user(BAD_STAMPFILE);
		    remove_timestamp();
		} else {
		    timestamp_is_old = 0;	/* time value is reasonable */
		}
	    } else {
		timestamp_is_old = 1;	/* else make 'em enter password */
	    }
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
    set_perms(PERM_USER, 0);

    return (timestamp_is_old);
}


/********************************************************************
 *
 *  touch()
 *
 *  This function updates the access and modify times on a file
 *  via utime(2).
 */

static int
touch(file)
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

static void
update_timestamp()
{
    if (timedir_is_good) {
	/* become root */
	set_perms(PERM_ROOT, 0);

	if (touch(timestampfile) < 0) {
	    int fd = open(timestampfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	    if (fd < 0)
		perror("update_timestamp: open");
	    else
		close(fd);
	}

	/* relinquish root */
	set_perms(PERM_USER, 0);
    }
}


/********************************************************************
 *
 *  remove_timestamp()
 *
 *  This function removes the timestamp ticket file
 */

void
remove_timestamp()
{
#ifdef USE_TTY_TICKETS
    char *p;

    if (p = strrchr(tty, '/'))
	p++;
    else
	p = tty;

    if (sizeof(_PATH_SUDO_TIMEDIR) + strlen(user_name) + strlen(p) + 2 >
	sizeof(timestampfile)) {
	(void) fprintf(stderr, "%s: path too long: %s/%s:%s\n", Argv[0],
		       _PATH_SUDO_TIMEDIR, user_name, p);
	exit(1);                                              
    }
    (void) sprintf(timestampfile, "%s/%s:%s", _PATH_SUDO_TIMEDIR, user_name, p);
#else
    if (sizeof(_PATH_SUDO_TIMEDIR) + strlen(user_name) + 1 >
	sizeof(timestampfile)) {
	(void) fprintf(stderr, "%s: path too long: %s/%s\n", Argv[0],
		       _PATH_SUDO_TIMEDIR, user_name);
	exit(1);                                              
    }
    (void) sprintf(timestampfile, "%s/%s", _PATH_SUDO_TIMEDIR, user_name);
#endif /* USE_TTY_TICKETS */

    /* become root */
    set_perms(PERM_ROOT, 0);

    /* remove the ticket file */
    (void) unlink(timestampfile);

    /* relinquish root */
    set_perms(PERM_USER, 0);
}


#ifndef NO_MESSAGE
/********************************************************************
 *
 *  reminder()
 *
 *  this function just prints the the reminder message
 */

static void
reminder()
{
#ifdef SHORT_MESSAGE
    (void) fprintf(stderr, "\n%s\n%s\n\n%s\n%s\n\n",
#else
    (void) fprintf(stderr, "\n%s%s%s\n%s\n%s\n%s\n\n%s\n%s\n\n%s\n%s\n\n",
	"    CU Sudo version ", version,
	", Copyright (c) 1991 The Root Group, Inc.",
	"    Copyright (c) 1994, 1996, 1998, 1999 Todd C. Miller.",
	"    sudo comes with ABSOLUTELY NO WARRANTY.  This is free software,",
	"    and you are welcome to redistribute it under certain conditions.",
#endif
	"We trust you have received the usual lecture from the local System",
	"Administrator. It usually boils down to these two things:",
	"        #1) Respect the privacy of others.",
	"        #2) Think before you type."
    );
}
#endif /* NO_MESSAGE */


/********************************************************************
 *
 *  expand_prompt()
 *
 *  expand %h and %u in the prompt and pass back the dynamically
 *  allocated result.  Returns the same string if no escapes.
 */

static char *
expand_prompt(old_prompt, user, host)
    char *old_prompt;
    char *user;
    char *host;
{
    size_t len;
    int subst;
    char *p, *np, *new_prompt, lastchar;

    /* How much space do we need to malloc for the prompt? */
    subst = 0;
    for (p = old_prompt, len = strlen(old_prompt), lastchar = '\0'; *p; p++) {
	if (lastchar == '%') {
	    if (*p == 'h') {
		len += strlen(shost) - 2;
		subst = 1;
	    } else if (*p == 'u') {
		len += strlen(user_name) - 2;
		subst = 1;
	    }
	}

	if (lastchar == '%' && *p == '%') {
	    lastchar = '\0';
	    len--;
	} else
	    lastchar = *p;
    }

    if (subst) {
	new_prompt = (char *) emalloc(len + 1);
	for (p = prompt, np = new_prompt; *p; p++) {
	    if (lastchar == '%' && (*p == 'h' || *p == 'u' || *p == '%')) {
		/* substiture user/host name */
		if (*p == 'h') {
		    np--;
		    strcpy(np, shost);
		    np += strlen(shost);
		} else if (*p == 'u') {
		    np--;
		    strcpy(np, user_name);
		    np += strlen(user_name);
		}
	    } else
		*np++ = *p;

	    if (lastchar == '%' && *p == '%')
		lastchar = '\0';
	    else
		lastchar = *p;
	}
	*np = '\0';
    } else
	new_prompt = prompt;

    return(new_prompt);
}
