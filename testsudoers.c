/*
 *  CU sudo version 1.5.2
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
 *  Please send bugs, changes, problems to sudo-bugs@courtesan.com
 *
 *******************************************************************
 *
 *  testsudoers.c -- frontend for parser testing and development.
 *
 *  Chris Jepeway <jepeway@cs.utk.edu>
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#  include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#  include <strings.h>
#endif /* HAVE_STRINGS_H */
#if defined(HAVE_FNMATCH) && defined(HAVE_FNMATCH_H)
#  include <fnmatch.h>
#else
#  ifndef HAVE_FNMATCH
#    include "emul/fnmatch.h"
#  endif /* HAVE_FNMATCH */
#endif /* HAVE_FNMATCH_H */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
#  include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#ifdef HAVE_NETGROUP_H
#  include <netgroup.h>
#endif /* HAVE_NETGROUP_H */
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
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
char *runas_user = "root";
char host[MAXHOSTNAMELEN+1];
char *shost;
char cwd[MAXPATHLEN+1];
struct passwd *user_pw_ent;
char **Argv, **NewArgv;
int  Argc, NewArgc;
uid_t uid;


/*
 * return TRUE if cmnd matches, in the sudo sense,
 * the pathname in path; otherwise, return FALSE
 */
int command_matches(cmnd, user_args, path, sudoers_args)
    char *cmnd;
    char *user_args;
    char *path;
    char *sudoers_args;
{
    int clen, plen;
    char *args;

    if (cmnd == NULL)
	return(FALSE);

    if ((args = strchr(path, ' ')))  
	*args++ = '\0';

    if (has_meta(path)) {
	if (fnmatch(path, cmnd, FNM_PATHNAME))
	    return(FALSE);
	if (!sudoers_args)
	    return(TRUE);
	else if (!user_args && sudoers_args && !strcmp("\"\"", sudoers_args))
	    return(TRUE);
	else if (sudoers_args)
	    return((fnmatch(sudoers_args, user_args ? user_args : "", 0) == 0));
	else
	    return(FALSE);
    } else {
	plen = strlen(path);
	if (path[plen - 1] != '/') {
	    if (strcmp(cmnd, path))
		return(FALSE);
	    if (!sudoers_args)
		return(TRUE);
	    else if (!user_args && sudoers_args && !strcmp("\"\"", sudoers_args))
		return(TRUE);
	    else if (sudoers_args)
		return((fnmatch(sudoers_args, user_args ? user_args : "", 0) == 0));
	    else
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
}


int addr_matches(n)
    char *n;
{
    int i;
    char *m;
    struct in_addr addr, mask;

    /* If there's an explicate netmask, use it. */
    if ((m = strchr(n, '/'))) {
	*m++ = '\0';
	mask.s_addr = inet_addr(m);
	addr.s_addr = inet_addr(n);
	*(m - 1) = '/';               

	for (i = 0; i < num_interfaces; i++)
	    if ((interfaces[i].addr.s_addr & mask.s_addr) == addr.s_addr)
		return(TRUE);
    } else {
	addr.s_addr = inet_addr(n);

	for (i = 0; i < num_interfaces; i++)
	    if (interfaces[i].addr.s_addr == addr.s_addr ||
		(interfaces[i].addr.s_addr & interfaces[i].netmask.s_addr)
		== addr.s_addr)
		return(TRUE);
    }

    return(FALSE);
}


int usergr_matches(group, user)
    char *group;
    char *user;
{
    struct group *grpent;
    char **cur;

    /* make sure we have a valid usergroup, sudo style */
    if (*group++ != '%')
	return(FALSE);

    if ((grpent = getgrnam(group)) == NULL) 
	return(FALSE);

    /*
     * Check against user's real gid as well as group's user list
     */
    if (getgid() == grpent->gr_gid)
	return(TRUE);

    for (cur=grpent->gr_mem; *cur; cur++) {
	if (strcmp(*cur, user) == 0)
	    return(TRUE);
    }

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
    if (*netgr++ != '+')
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
    return(innetgr(netgr, host, user, domain));
#else
    return(FALSE);
#endif /* HAVE_INNETGR */
}


void set_perms(i, j)
    int i, j;
{
    return;
}


int main(argc, argv)
    int argc;
    char **argv;
{
    struct passwd pw_ent;
    char *p;
#ifdef	YYDEBUG
    extern int yydebug;
    yydebug = 1;
#endif

    Argv = argv;
    Argc = argc;

    if (Argc >= 6 && strcmp(Argv[1], "-u") == 0) {
	runas_user = Argv[2];
	pw_ent.pw_name = Argv[3];
	strcpy(host, Argv[4]);
	cmnd = Argv[5];

	NewArgv = &Argv[5];
	NewArgc = Argc - 5;
    } else if (Argc >= 4) {
	pw_ent.pw_name = Argv[1];
	strcpy(host, Argv[2]);
	cmnd = Argv[3];

	NewArgv = &Argv[3];
	NewArgc = Argc - 3;
    } else {
	(void) fprintf(stderr, "usage: %s [-u user] <user> <host> <command> [args]\n", Argv[0]);
	exit(1);
    }

    user_pw_ent = &pw_ent;		/* need user_pw_ent->pw_name defined */

    if ((p = strchr(host, '.'))) {
	*p = '\0';
	if ((shost = strdup(host)) == NULL) {
	    perror("malloc");
	    (void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	    exit(1);
	}
	*p = '.';
    } else {
	shost = &host[0];
    }

    /* fill in cmnd_args from NewArgv */
    if (NewArgc > 1) {
	size_t size;
	char *to, **from;

	size = (size_t) NewArgv[NewArgc-1] + strlen(NewArgv[NewArgc-1]) -
	       (size_t) NewArgv[1] + 1;
	if ((cmnd_args = (char *) malloc(size)) == NULL) {
	    perror("malloc");
	    (void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);  
	    exit(1);
	}
	for (to = cmnd_args, from = &NewArgv[1]; *from; from++) {
	    *to++ = ' ';
	    (void) strcpy(to, *from);
	    to += strlen(*from);
	}
    }

    /* need to keep aliases around for dumpaliases() */
    clearaliases = 0;

    /* load ip addr/mask for each interface */
    load_interfaces();

    /* allocate space for data structures in the parser */
    init_parser();

    if (yyparse() || parse_error) {
	(void) printf("doesn't parse.\n");
    } else {
	(void) printf("parses OK.\n\n");
	if (top == 0)
	    (void) printf("User %s not found\n", pw_ent.pw_name);
	else while (top) {
	    (void) printf("[%d]\n", top-1);
	    (void) printf("user_match : %d\n", user_matches);
	    (void) printf("host_match : %d\n", host_matches);
	    (void) printf("cmnd_match : %d\n", cmnd_matches);
	    (void) printf("no_passwd  : %d\n", no_passwd);
	    (void) printf("runas_match: %d\n", runas_matches);
	    (void) printf("runas      : %s\n", runas_user);
	    top--;
	}
    }

    /* dump aliases */
    (void) printf("Matching Aliases --\n");
    dumpaliases();

    exit(0);
}


/*
 * Returns TRUE if "s" has shell meta characters in it,
 * else returns FALSE.
 */
int has_meta(s)
    char *s;
{
    register char *t;
    
    for (t = s; *t; t++) {
	if (*t == '\\' || *t == '?' || *t == '*' || *t == '[' || *t == ']')
	    return(TRUE);
    }
    return(FALSE);
}
