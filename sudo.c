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

#include <stdio.h>
#ifdef STD_HEADERS
#include <stdlib.h>
#ifndef NeXT
#include <unistd.h>
#endif /* !NeXT */
#endif /* STD_HEADERS */
#include <string.h>
#include <strings.h>
#include <pwd.h>
#include <netdb.h>
#include <sys/param.h>
#ifdef _AIX
#include <sys/id.h>
#endif /* _AIX */
#include "sudo.h"
#ifndef STD_HEADERS
extern char *malloc();
#ifndef NEED_STRDUP
extern char *strdup();
#endif
#endif

int Argc;
char **Argv;
char **Envp;
char *host;
char *user;
char *cmnd;
uid_t uid;


static void usage();


/********************************************************************
 *
 *  main ()
 *
 *  the driving force behind sudo...
 */

main(argc, argv, envp)
    int argc;
    char **argv;
    char **envp;
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

    clean_envp(envp);		/* build Envp based on envp (w/o LD_*) */

    rtn = validate();
    switch (rtn) {

    case VALIDATE_OK:
	check_user();
	log_error(ALL_SYSTEMS_GO);
	be_root();
	execve(cmnd, &Argv[1], Envp);
	perror(cmnd);		/* execve() failed! */
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

void load_globals()
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
	if ((p = index(host, '.')))
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
 *  clean_envp()
 *
 *  This function builds Envp, the environment pointer to be
 *  used for all execve()'s and omits LD_* variables
 */

void clean_envp(envp)
    char **envp;
{
    int envlen;
    char **tenvp;

    for (envlen = 0; envp[envlen]; envlen++);	/* noop */
    ++envlen;

    Envp = (char **) malloc(sizeof(char **) * envlen);

    if (Envp == NULL) {
	perror("clean_envp:  malloc");
	exit(1);
    }

    /*
     * omit all LD_* environmental vars
     */
    for (tenvp = Envp; *envp; envp++)
#ifdef hpux
	if (strncmp("LD_", *envp, 3) && strncmp("SHLIB_PATH", *envp, 10)) {
#else
#ifdef __alpha
	if (strncmp("LD_", *envp, 3) && strncmp("_RLD_", *envp, 5)) {
#else
	if (strncmp("LD_", *envp, 3)) {
#endif /* __alpha */
#endif /* hpux */
#ifdef SECURE_PATH
	    if (!strncmp("PATH=", *envp, 5))
		*tenvp++ = "PATH=" SECURE_PATH;
	    else
#endif /* SECURE_PATH */
		*tenvp++ = *envp;
	}
    *tenvp = NULL;
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
 *  this function sets the effective uid to the value of uid
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
