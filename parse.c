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
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#else
#include <sys/dir.h>
#endif /* HAVE_DIRENT_H */

#include "sudo.h"
#include "options.h"

extern FILE *yyin, *yyout;

/*
 * Globals
 */
int parse_error = FALSE;

/*
 * this routine is called from the sudo.c module and tries to validate
 * the user, host and command triplet.
 */
int validate()
{
    FILE *sudoers_fp;
    int i, return_code;

    /* become root */
    set_perms(PERM_ROOT);

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

    /* relinquish root */
    set_perms(PERM_USER);

    if (return_code || parse_error)
	return(VALIDATE_ERROR);

    if (top == 0)
	/*
	 * nothing on the top of the stack =>
	 * user doesn't appear in sudoers
	 */
	return(VALIDATE_NO_USER);

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
int
path_matches(cmnd, path)
char *cmnd, *path;
{
    int plen;
    struct stat cst, pst;
    DIR *dirp;
#ifdef HAVE_DIRENT_H
    struct dirent *dent;
#else
    struct direct *dent;
#endif /* HAVE_DIRENT_H */
    char buf[MAXCOMMANDLENGTH+1];

    if (stat(cmnd, &cst) < 0)
	return(FALSE);

    plen = strlen(path);
    if (path[plen - 1] != '/') {
	if (stat(path, &pst) < 0)
	    return(FALSE);
	return(cst.st_dev == pst.st_dev && cst.st_ino == pst.st_ino);
    }

    /* grot through path's directory entries, looking for cmnd */
    dirp = opendir(path);
    if (dirp == NULL)
	return(FALSE);

    while ((dent = readdir(dirp)) != NULL) {
	strcpy(buf, path);
	strcat(buf, dent->d_name);
	if (stat(buf, &pst) < 0)
	    continue;
	if (cst.st_dev == pst.st_dev && cst.st_ino == pst.st_ino)
	    break;
    }

    closedir(dirp);
    return(dent != NULL);
}



int
ntwk_matches(n)
char* n;
{
    int i;
    int ntwk;

    ntwk = inet_network(n);

    for (i = 0; i < num_interfaces; i++)
	if (interfaces[i].addr.s_addr == ntwk ||
	(interfaces[i].addr.s_addr & interfaces[i].netmask.s_addr) == ntwk)
	return(TRUE);

    return(FALSE);
}
