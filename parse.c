/*
 *  CU sudo version 1.3.1
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

    /*
     * if the cmnd is the pseudo-command "validate"
     * return VALIDATE_OK if the host matches, else
     * check host and command.
     */
    if (!strcmp(cmnd, "validate"))
	while (top) {
	    if (host_matches == TRUE)
		/* user may always do validate on allowed hosts */
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
int
path_matches(cmnd, path)
char *cmnd, *path;
{
    int plen;
    struct stat cst, pst;
    DIR *dirp;
    struct dirent *dent;
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
	strcat(buf, (char *) NAMLEN(dent));
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
