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
 **************************************************************************
 *
 *   sudo.c
 *
 *   This is the main() routine for sudo
 *
 *   sudo is a program to allow users to execute commands 
 *   as root.  The commands are defined in a global network-
 *   wide file and can be distributed.
 *
 *   sudo has been hacked far and wide.  Too many people to
 *   know about.  It's about time to come up with a secure
 *   version that will work well in a network.
 *
 *   This most recent version is done by:
 *
 *              Jeff Nieusma <nieusma@rootgroup.com>
 *              Dave Hieb    <davehieb@rootgroup.com>
 *
 *   However, due to the fact that both of the above are no longer
 *   working at Root Group, I am maintaining the "CU version" of
 *   sudo.
 *		Todd Miller  <millert@cs.colorado.edu>
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#define MAIN

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
#ifdef HAVE_MALLOC_H 
#include <malloc.h>   
#endif /* HAVE_MALLOC_H */ 
#include <pwd.h>
#include <netdb.h>
#include <sys/param.h>
#ifdef _AIX
#include <sys/id.h>
#endif /* _AIX */
#include "sudo.h"

#ifndef STDC_HEADERS
extern char *malloc();
#ifdef HAVE_STRDUP
extern char *strdup();
#endif /* HAVE_STRDUP */
#endif /* STDC_HEADERS */


int Argc;
char **Argv;
char *host;
char *user;
char *cmnd;
uid_t uid;


/*
 * local functions not visible outside sudo.c
 */
static void usage();
static void load_globals();
static void rmenv();
static void clean_env();


/********************************************************************
 *
 *  main ()
 *
 *  the driving force behind sudo...
 */

main(argc, argv)
    int argc;
    char **argv;
{
    int rtn;

    Argv = argv;
    Argc = argc;

    /*
     * if nothing is passed, we don't need to do anything...
     */
    if (argc < 2)
	usage();

    /*
     * close all file descriptors to make sure we have a nice
     * clean slate from which to work.  
     */
    for (rtn = getdtablesize() - 1; rtn > 3; rtn--)
	(void) close(rtn);

    load_globals();		/* load the user host cmnd and uid variables */

    /*
     * We only want to be root when we absolutely need it.
     * This will effectively do setreuid(0, uid) but for portability...
     */
    be_root();
    be_user();

    clean_env(environ);		/* clean up the environment (no LD_*) */

    rtn = validate();
    switch (rtn) {

    case VALIDATE_OK:
	check_user();
	log_error(ALL_SYSTEMS_GO);
	be_root();
#ifdef USE_EXECV
	execv(cmnd, &Argv[1]);
#else /* USE_EXECV */
	execvp(cmnd, &Argv[1]);
#endif /* USE_EXECV */
	perror(cmnd);		/* exec failed! */
	exit(-1);
	break;

    case VALIDATE_NO_USER:
    case VALIDATE_NOT_OK:
    case VALIDATE_ERROR:
    default:
	log_error(rtn);
	be_full_user();
	inform_user(rtn);
	exit(1);
	break;
    }
}



/**********************************************************************
 *
 *  load_globals()
 *
 *  This function primes the important global variables:
 *  user, host, cmnd, uid
 */

static void load_globals()
{
    struct passwd *pw_ent;
    struct hostent *h_ent;
    char path[MAXPATHLEN + 1];
    char *p;


    if ((user = (char *) malloc(9)) == NULL) {
	perror("malloc");
	exit(1);
    }
    if ((host = (char *) malloc(MAXHOSTNAMELEN + 1)) == NULL) {
	perror("malloc");
	exit(1);
    }
    uid = getuid();		/* we need to tuck this away for safe keeping */

#ifdef UMASK
    (void) umask((mode_t)UMASK);
#endif /* UMASK */


    /*
     * loading the cmnd global variable from argv[1]
     */
    strncpy(path, Argv[1], MAXPATHLEN)[MAXPATHLEN] = 0;
    /* become root for find_path() only */
    be_root();
    cmnd = find_path(path);	/* get the absolute path */
    be_user();
    if (cmnd == NULL) {
	(void) fprintf(stderr, "%s: %s: command not found\n", Argv[0], Argv[1]);
	exit(1);
    }
    cmnd = strdup(cmnd);

#ifdef NO_ROOT_SUDO
    if (uid == 0) {
	(void) fprintf(stderr, "You are already root, you don\'t need to use sudo.\n");
	exit(1);
    }
#endif

    /*
     * loading the user global variable from the passwd file
     */
    if ((pw_ent = getpwuid(uid)) == NULL) {
	(void) sprintf(user, "%u", uid);
	log_error(GLOBAL_NO_PW_ENT);
	inform_user(GLOBAL_NO_PW_ENT);
	exit(1);
    }
    strncpy(user, pw_ent -> pw_name, 8)[8] = '\0';


    /*
     * loading the host global variable from gethostname() & gethostbyname()
     */
    if ((gethostname(host, MAXHOSTNAMELEN))) {
	strcpy(host, "amnesiac");
	log_error(GLOBAL_NO_HOSTNAME);
	inform_user(GLOBAL_NO_HOSTNAME);
    } else {
	if ((h_ent = gethostbyname(host)) == NULL)
	    log_error(GLOBAL_HOST_UNREGISTERED);
	else
	    strcpy(host, h_ent -> h_name);

    /*
     * We don't want to return the fully quallified name all the time...
     */
#ifndef FQDN
	if ((p = strchr(host, '.')))
	    *p = '\0';
#endif
    }

}



/**********************************************************************
 *
 * usage()
 *
 *  this function just gives you instructions and exits
 */

static void usage()
{
    (void) fprintf(stderr, "usage: %s command\n", *Argv);
    exit(1);
}



/**********************************************************************
 *
 *  clean_env()
 *
 *  This function builds cleans up the environ pointer so that all execv*()'s
 *  omit LD_* variables and hard-code PATH if SECURE_PATH is defined.
 */

static void clean_env(envp)
    char **envp;
{

    /*
     * omit all LD_* environmental vars
     */
    rmenv(envp, "LD_", 3);
#ifdef hpux
    rmenv(envp, "SHLIB_PATH", 10);
#endif /* hpux */
#ifdef __alpha
    rmenv(envp, "_RLD_", 5);
#endif /* __alpha */

#ifdef SECURE_PATH
    putenv("PATH=" SECURE_PATH);
#endif /* SECURE_PATH */
}



/**********************************************************************
 *
 * be_root()
 *
 *  this function sets the real and effective uids to 0
 */

void be_root()
{
    if (setuid(0)) {
        perror("setuid(0)");
        exit(1); 
    }
}



/**********************************************************************
 *
 * be_user()
 *
 *  this function sets the effective uid to the value of uid.
 *  Naturally, we need to do something completely different for AIX.
 */

#ifdef _AIX
void be_user()
{
    if (setuidx(ID_EFFECTIVE|ID_REAL, uid)) {
        perror("setuidx(ID_EFFECTIVE|ID_REAL, uid)");
        exit(1); 
    }
}
#else /* _AIX */
void be_user()
{
    if (seteuid(uid)) {
        perror("seteuid(uid)");
        exit(1); 
    }
}
#endif /* _AIX */



/**********************************************************************
 *
 * be_full_user()
 *
 *  this function sets the real and effective uids to the value of uid
 *  since our euid is probably already uid we need to setuid(0) first
 */

void be_full_user()
{
    if (setuid(0)) {
        perror("setuid(0)");
        exit(1); 
    }
    if (setuid(uid)) {
        perror("setuid(uid)");
        exit(1); 
    }
}

/**********************************************************************
 *
 * rmenv()
 *
 *  this function removes things from the environment that match the
 *  string "s" up to length len [ie: with strncmp()].
 */

static void rmenv(envp, s, len)
    char ** envp;				/* pointer to environment */
    char * s;					/* string to search for */
    int len;					/* how much of it to check */
{
    char ** tenvp;				/* temp env pointer */
    char ** move;				/* used to move around */

    /*
     * cycle through the environment and purge strings that match s
     */
    for (tenvp=envp; *tenvp; tenvp++) {
	if (!strncmp(*tenvp, s, len)) {
	    /* matched: remove by shifting everything below one up */
	    for (move=tenvp; *move; move++)
		*move = *(move+1);
	    tenvp--;
	}
    }
}
