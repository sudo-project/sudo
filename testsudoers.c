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
 * parse.c, sudo project
 * David R. Hieb
 * March 18, 1991
 *
 * routines to implement and maintain the parsing and list management.
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
#ifdef HAVE_MALLOC_H 
#include <malloc.h>
#endif /* HAVE_MALLOC_H */ 
#include <ctype.h>
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

char *cmnd;
char *user;
char host[MAXHOSTNAMELEN+1];
char cwd[MAXPATHLEN+1];
char *epasswd = NULL;
char **Argv;
int  Argc;
uid_t uid;

/*
 * return TRUE if cmnd matches, in the sudo sense,
 * the pathname in path; otherwise, return FALSE
 */
int
path_matches(cmnd, path)
char *cmnd, *path;
{
    int clen, plen;

    if (cmnd == NULL)
	return FALSE;

    plen = strlen(path);
    if (path[plen] != '/')
	return strcmp(cmnd, path) == 0;

    clen = strlen(cmnd);
    if (clen < plen + 1)
	/* path cannot be the parent dir of cmnd */
	return FALSE;

    if (strchr(cmnd + plen + 1, '/') != NULL)
	/* path could only be an anscestor of cmnd -- */
	/* ignoring, of course, things like // & /./  */
	return FALSE;

    /* see whether path is the prefix of cmnd */
    return strncmp(cmnd, path, plen) == 0;
}

int
addr_matches(n)
char *n;
{
    struct in_addr **in;
    struct hostent *he;
    int ntwk;

    ntwk = inet_network(n);

    if ((he = gethostbyname(host)) == NULL)
	return FALSE;
    if (he->h_length != sizeof **in) {
	yyerror("IP addrs broken\n");
	return FALSE;
    }
    for (in = (struct in_addr **) he->h_addr_list; *in; in++)
	if (inet_netof(**in) ==	ntwk)
	    return TRUE;

    return FALSE;
}

void
set_perms(i)
int i;
{
    return;
}

main(argc, argv)
int argc;
char **argv;
{
#ifdef	YYDEBUG
    extern int yydebug;
    yydebug = 1;
#endif

    if (argc != 4) {
	fprintf(stderr, "usage: %s <command> <user> <host>\n", argv[0]);
	exit(1);
    }

    Argv = argv;
    Argc = argc;

    cmnd = argv[1];
    user = argv[2];
    strcpy(host, argv[3]);

    if (yyparse() || parse_error)
	printf("doesn't parse.\n");
    else {
	printf("parses OK.\n\n");
	if (top == 0)
	    printf("User %s not found\n", user);
	else while (top) {
	    printf("[%d]\n", top-1);
	    printf("user_match: %d\n", user_matches);
	    printf("host_match: %d\n", host_matches);
	    printf("cmnd_match: %d\n", cmnd_matches);
	    top--;
	}
    }

    /* dump aliases */
    printf("Matching Aliases --\n");
    dumpaliases();
}
