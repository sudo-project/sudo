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
 *  If you make modifications to the source, we would be happy to have
 *  them to include in future releases.  Feel free to send them to:
 *      Jeff Nieusma                       nieusma@rootgroup.com
 *      3959 Arbol CT                      (303) 447-8093
 *      Boulder, CO 80301-1752             
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
 */

#define MAIN

#include <stdio.h>
#ifdef hpux
#include <unistd.h>
#endif
#include <string.h>
#include <strings.h>
#include <pwd.h>
#include <netdb.h>
#include <sys/param.h>
#include "sudo.h"
extern char *malloc();

int  Argc;
char **Argv;
char **Envp;
char *host;
char *user;
char *cmnd;
#ifdef MULTIMAX
unsigned short uid;
#else
uid_t uid;
#endif



/********************************************************************
 *
 *  main ()
 *
 *  the driving force behind sudo...
 */

main(argc, argv, envp)
int argc; char **argv; char **envp;
{
static void usage();
int rtn;

Argv=argv;
Argc=argc;

/* if nothing is passed, we don't need to do anything... */
if ( argc < 2 ) usage();

/* close all file descriptors to make sure we have a nice
 * clean slate from which to work.  
 */
for ( rtn = getdtablesize() - 1 ; rtn > 3; rtn -- )
    (void)close(rtn);

load_globals();    /* load the user host cmnd and uid variables */

clean_envp(envp);  /* build Envp based on envp (w/o LD_*) */

if ( setuid(0) ) {
    perror("setuid(0)");
    exit(1);
    }
rtn=validate();
if ( setruid(uid) ) {
#ifndef _AIX
    perror("setruid(uid)");
    exit(1);
#endif
    }

switch ( rtn ) {

    case VALIDATE_OK:
	    check_user();
            log_error( ALL_SYSTEMS_GO );
            if ( setuid(0) ) {
		perror("setuid(0)");
		exit(1);
		}
            execve(cmnd, &Argv[1], Envp);
	    perror(cmnd);
	    break;
	    
    case VALIDATE_NO_USER:
    case VALIDATE_NOT_OK: 
    case VALIDATE_ERROR:
    default:
	    log_error ( rtn );
	    if ( setuid ( uid ) ) {
		perror("setuid(uid)");
		exit(1);
		}
	    inform_user ( rtn );
	    exit (1);
	    break;

    }

    return(-1);		/* If we get here it's an error (execve failed) */
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
char path[MAXPATHLEN+1];
char *p;


if ( (user=malloc(9)) == NULL ) {
    perror ("malloc");
    exit (1);
    }
if ( (host=malloc(MAXHOSTNAMELEN+1)) == NULL ) {
    perror ("malloc");
    exit (1);
    }

uid = getuid();            /* we need to tuck this away for safe keeping */


/* loading the cmnd global variable from argv[1] */

strncpy(path, Argv[1], MAXPATHLEN)[MAXPATHLEN] = 0;  
cmnd = find_path ( path );  /* get the absolute path */
if ( cmnd == NULL ) {
    fprintf ( stderr, "%s: %s: command not found\n", Argv[0], Argv[1] );
    exit (1);
    }
cmnd = strdup ( cmnd );

#ifdef NO_ROOT_SUDO
if ( uid == 0 ) {
    fprintf(stderr, "You are already root, you don\'t need to use sudo.\n");
    exit (1);
    }
#endif

/* loading the user global variable from the passwd file */

if ( (pw_ent = getpwuid( uid )) == NULL ) {
    sprintf ( user, "%u", uid );
    log_error( GLOBAL_NO_PW_ENT );
    inform_user ( GLOBAL_NO_PW_ENT );
    exit (1);
    }
strncpy ( user, pw_ent -> pw_name, 8 ) [8] = '\0';


/* loading the host global variable from gethostname() & gethostbyname() */

if (( gethostname ( host, MAXHOSTNAMELEN ))) {
    strcpy ( host, "amnesiac" );
    log_error ( GLOBAL_NO_HOSTNAME );
    inform_user ( GLOBAL_NO_HOSTNAME );
    }
else {
    if ( ( h_ent = gethostbyname ( host) ) == NULL ) 
	log_error ( GLOBAL_HOST_UNREGISTERED );
    else 
	strcpy ( host, h_ent -> h_name );

/* We don't want to return the fully quallified name all the time...  */

#ifndef FQDN
    if ( (p = index ( host, '.' )) ) *p='\0';
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
fprintf( stderr, "usage: %s command\n", *Argv);
exit (1);
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
char ** tenvp;

for ( envlen=0; envp[envlen]; envlen++ )
    ; /* noop */

Envp = (char **) malloc ( sizeof (char **) * envlen );

if ( Envp == NULL ) {
    perror ("clean_envp:  malloc");
    exit (1);
}

/* omit all LD_* environmental vars */
for ( tenvp=Envp; *envp; envp++ )
    if ( strncmp ("LD_", *envp, 3) )
	*tenvp++ = *envp;

*tenvp = NULL;
}
