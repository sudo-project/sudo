/*
 *  CU sudo version 1.3.7
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
 * parse.c -- sudo parser frontend and comparison routines.
 *
 * Chris Jepeway <jepeway@cs.utk.edu>
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
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
#include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <ctype.h>
#include <grp.h>
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "sudo.h"
#include <options.h>

extern FILE *yyin, *yyout;

/*
 * Globals
 */
int parse_error = FALSE;

/*
 * this routine is called from the sudo.c module and tries to validate
 * the user, host and command triplet.
 */
int validate(check_cmnd)
    int check_cmnd;
{
    FILE *sudoers_fp;
    int return_code;

    /* become sudoers file owner */
    set_perms(PERM_SUDOERS);

    if ((sudoers_fp = fopen(_PATH_SUDO_SUDOERS, "r")) == NULL) {
	perror(_PATH_SUDO_SUDOERS);
	log_error(NO_SUDOERS_FILE);
	exit(1);
    }
    yyin = sudoers_fp;
    yyout = stdout;

    return_code = yyparse();

    /*
     * don't need to keep this open...
     */
    (void) fclose(sudoers_fp);

    /* relinquish extra privs */
    set_perms(PERM_ROOT);
    set_perms(PERM_USER);

    if (return_code || parse_error)
	return(VALIDATE_ERROR);

    if (top == 0)
	/*
	 * nothing on the top of the stack =>
	 * user doesn't appear in sudoers
	 */
	return(VALIDATE_NO_USER);

    /*
     * Only check the actual command if the check_cmnd
     * flag is set.  It is not set for the "validate"
     * and "list" pseudo-commands.  Always check the
     * host and user.
     */
    if (check_cmnd == FALSE)
	while (top) {
	    if (host_matches == TRUE)
		/* user may always do validate or list on allowed hosts */
		return(VALIDATE_OK);
	    top--;
	}
    else
	while (top) {
	    if (host_matches == TRUE)
		if (cmnd_matches == TRUE)
		    /* user was granted access to cmnd on host */
		    return(VALIDATE_OK);
		else if (cmnd_matches == FALSE)
		    /* user was explicitly denied acces to cmnd on host */
		    return(VALIDATE_NOT_OK);
	    top--;
	}

    /*
     * we popped everything off the stack =>
     * user was mentioned, but not explicitly
     * granted nor denied access => say no
     */
    return(VALIDATE_NOT_OK);
}



/*
 * If path doesn't end in /, return TRUE iff cmnd & path name the same inode;
 * otherwise, return TRUE if cmnd names one of the inodes in path
 */
int path_matches(cmnd, path)
    char *cmnd, *path;
{
    int plen;
    struct stat pst;
    DIR *dirp;
    struct dirent *dent;
    char buf[MAXPATHLEN+1];
    static char *c;
    char *args;

    /* don't bother with pseudo commands like "validate" */
    if (*cmnd != '/')
	return(FALSE);

    /* only need to stat cmnd once since it never changes */
    if (cmnd_st.st_dev == 0) {
	if (stat(cmnd, &cmnd_st) < 0)
	    return(FALSE);
	if ((c = strrchr(cmnd, '/')) == NULL)
	    c = cmnd;
	else
	    c++;
    }

    /* if the given path has command line args, split them out */
    if ((args = strchr(path, ' ')))
	*args++ = '\0';

    plen = strlen(path);
    if (path[plen - 1] != '/') {
#ifdef FAST_MATCH
	char *p;

	/* only proceed if the basenames of cmnd and path are the same */
	if ((p = strrchr(path, '/')) == NULL)
	    p = path;
	else
	    p++;
	if (strcmp(c, p))
	    return(FALSE);
#endif /* FAST_MATCH */

	if (stat(path, &pst) < 0)
	    return(FALSE);

	/* put things back the way we found 'em */
	if (args)
	    *(args - 1) = ' ';

	/*
	 * Return true if inode/device matches and there are no args
	 * (in sudoers or command) or if the args match;
	 * else return false.
	 */
	if (cmnd_st.st_dev == pst.st_dev && cmnd_st.st_ino == pst.st_ino) {
	    if (!args)
		return(TRUE);
	    else if (cmnd_args && args)
		return((strcmp(cmnd_args, args) == 0));
	    else
		return(FALSE);
	} else
	    return(FALSE);
    }

    /*
     * Grot through path's directory entries, looking for cmnd.
     */
    dirp = opendir(path);
    if (dirp == NULL)
	return(FALSE);

    while ((dent = readdir(dirp)) != NULL) {
	strcpy(buf, path);
	strcat(buf, dent->d_name);
#ifdef FAST_MATCH
	/* only stat if basenames are not the same */
	if (strcmp(c, dent->d_name))
	    continue;
#endif /* FAST_MATCH */
	if (stat(buf, &pst) < 0)
	    continue;
	if (cmnd_st.st_dev == pst.st_dev && cmnd_st.st_ino == pst.st_ino)
	    break;
    }

    closedir(dirp);
    return(dent != NULL);
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
