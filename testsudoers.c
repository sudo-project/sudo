/*
 *  CU sudo version 1.3.6
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
 *  Please send bugs, changes, problems to sudo-bugs@cs.colorado.edu
 *
 *******************************************************************
 *
 *  testsudoers.c -- frontend for parser testing and developement.
 *
 *  Chris Jepeway <jepeway@cs.utk.edu>
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
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
#include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <ctype.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/stat.h>
#include <dirent.h>

#include "sudo.h"

/*
 * Globals
 */
int parse_error = FALSE;
extern int clearaliases;
extern struct interface *interfaces;
extern int num_interfaces;

char *cmnd = NULL;
char *cmnd_args = NULL;
char host[MAXHOSTNAMELEN+1];
char cwd[MAXPATHLEN+1];
struct passwd *sudo_pw_ent;
char **Argv;
int  Argc;
uid_t uid;


/*
 * return TRUE if cmnd matches, in the sudo sense,
 * the pathname in path; otherwise, return FALSE
 */
int path_matches(cmnd, path)
    char *cmnd, *path;
{
    int clen, plen;
    char *args;

    if (cmnd == NULL)
	return(FALSE);

    if ((args = strchr(path, ' ')))  
	*args++ = '\0';

    plen = strlen(path);
    if (path[plen - 1] != '/') {
	if (strcmp(cmnd, path) == 0) {
	    if (!cmnd_args && !args)
		return(TRUE);
	    else if (cmnd_args && args)
		return((strcmp(cmnd_args, args) == 0));
	    else
		return(FALSE);
	} else
	    return(FALSE);
    }

    clen = strlen(cmnd);
    if (clen < plen + 1)
	/* path cannot be the parent dir of cmnd */
	return(FALSE);

    if (strchr(cmnd + plen + 1, '/') != NULL)
	/* path could only be an anscestor of cmnd -- */
	/* ignoring, of course, things like // & /./  */
	return(FALSE);

    /* see whether path is the prefix of cmnd */
    return((strncmp(cmnd, path, plen) == 0));
}


int addr_matches(n)
    char *n;
{
    int i;
    struct in_addr addr;

    addr.s_addr = inet_addr(n);

    for (i = 0; i < num_interfaces; i++)
	if (interfaces[i].addr.s_addr == addr.s_addr ||
	    (interfaces[i].addr.s_addr & interfaces[i].netmask.s_addr)
	    == addr.s_addr)
	    return(TRUE);

    return(FALSE);
}


int netgr_matches(netgr, host, user)
    char *netgr;
    char *host;
    char *user;
{
#ifdef HAVE_GETDOMAINNAME
    static char *domain = (char *) -1;
#else
    static char *domain = NULL;
#endif /* HAVE_GETDOMAINNAME */

    /* make sure we have a valid netgroup, sudo style */
    if (*netgr != '+')
	return(FALSE);

#ifdef HAVE_GETDOMAINNAME
    /* get the domain name (if any) */
    if (domain == (char *) -1) {
	if ((domain = (char *) malloc(MAXHOSTNAMELEN + 1)) == NULL) {
	    perror("malloc");
	    (void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	    exit(1);
	}

	if (getdomainname(domain, MAXHOSTNAMELEN + 1) != 0 || *domain == '\0') {
	    (void) free(domain);
	    domain = NULL;
	}
    }
#endif /* HAVE_GETDOMAINNAME */

#ifdef HAVE_INNETGR
    return(innetgr(netgr+1, host, user, domain));
#else
    return(FALSE);
#endif /* HAVE_INNETGR */
}


void set_perms(i)
    int i;
{
    return;
}


main(argc, argv)
    int argc;
    char **argv;
{
    struct passwd pw_ent;
#ifdef	YYDEBUG
    extern int yydebug;
    yydebug = 1;
#endif

    if (argc != 4) {
	(void) fprintf(stderr, "usage: %s <command> <user> <host>\n", argv[0]);
	exit(1);
    }

    Argv = argv;
    Argc = argc;

    sudo_pw_ent = &pw_ent;		/* need sudo_pw_ent->pw_name defined */

    cmnd = argv[1];
    pw_ent.pw_name = argv[2];
    strcpy(host, argv[3]);

    clearaliases = 0;

    load_interfaces();

    if (yyparse() || parse_error) {
	(void) printf("doesn't parse.\n");
    } else {
	(void) printf("parses OK.\n\n");
	if (top == 0)
	    (void) printf("User %s not found\n", pw_ent.pw_name);
	else while (top) {
	    (void) printf("[%d]\n", top-1);
	    (void) printf("user_match: %d\n", user_matches);
	    (void) printf("host_match: %d\n", host_matches);
	    (void) printf("cmnd_match: %d\n", cmnd_matches);
	    top--;
	}
    }

    /* dump aliases */
    (void) printf("Matching Aliases --\n");
    dumpaliases();
}
