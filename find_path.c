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
 *******************************************************************
 *
 *  This module contains the find_path() command that returns
 *  a pointer to a static area with the absolute path of the 
 *  command or NULL if the command is not found in the path
 *
 *  I also added the strdup() function in here after I found most
 *  systems don't have it...
 *
 *  Jeff Nieusma  Thu Mar 21 23:11:23 MST 1991
 */

/*
 *  Most of this code has been rewritten to fix bugs and bears little
 *  resemblence to the original.  As such, this file conforms to my
 *  personal coding style.
 *
 *  Todd C. Miller (millert@colorado.edu) Sat Sep  4 12:22:04 MDT 1993
 */

#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include "sudo.h"

extern char *malloc();
extern char *getenv();
extern char *strcpy();
extern int fprintf();
extern int readlink();
extern int stat();
extern int lstat();
#ifdef USE_CWD
extern char *getcwd();
#else
extern char *getwd();
#endif


/*******************************************************************
 *
 *  find_path()
 *
 *  this function finds the full pathname for a command
 */

char *find_path(file)
    char *file;
{
    register char *n;			/* for traversing path */
    char *path = NULL;			/* contents of PATH env var */
    char fn[MAXPATHLEN+1];		/* filename (path + file) */
    struct stat statbuf;		/* for stat(2) */
    int statfailed;			/* stat(2) return value */
    char *qualify();

    if (strlen(file) > MAXPATHLEN) {
	fprintf(stderr, "%s:  path too long:  %s\n", Argv[0], file);
	exit(1);
    }
	
    /* do we need to search the path? */
    if (index(file, '/'))
	return (qualify(file));

    /* grab PATH out of environment and make a local copy */
    if ((path = getenv("PATH") ) == NULL)
	return (NULL);

    if ((path = strdup(path)) == NULL) {
	perror("find_path:  malloc");
	exit(1);
    }

    while ((n = index(path, ':'))) {
	*n='\0';
	strcpy(fn, path);
	strcat(fn, "/");
	strcat(fn, file);

	/* stat the file to make sure it exists and is executable */
	statfailed = stat(fn, &statbuf);
	if (!statfailed && (statbuf.st_mode & 0000111))
	    return (qualify(fn));
	else if (!statfailed || errno == ENOENT || errno == ENOTDIR)
	    path=n+1;
	else {
	    perror("find_path:  stat");
	    exit(1);
	}
    }
    return(NULL);
}


/******************************************************************
 *
 *  qualify()
 *
 *  this function takes a path and makes it fully qualified and resolves
 *  all symbolic links, returning the fully qualfied path.
 */

char *qualify(n)
    char *n;				/* name to make fully qualified */
{
    char *beg = NULL;			/* begining of a path component */
    char *end;				/* end of a path component */
    static char full[MAXPATHLEN+1];	/* the fully qualified name */
    char name[MAXPATHLEN+1];		/* local copy of n */
    struct stat statbuf;		/* for lstat() */
    char *tmp;				/* temporary pointer */

    /* is it a bogus path? */
    if (stat(n, &statbuf)) {
    	if (errno == ENOENT)
	    return(NULL);
	else {
	    perror("qualify:  stat");
	    exit(1);
	}
    }

    /* if n is relative, fill full with working dir */
    if (*n != '/') {
#ifdef USE_CWD
	if (!getcwd(full, (size_t)(MAXPATHLEN+1))) {
#else
	if (!getwd(full)) {
#endif
	    fprintf(stderr, "%s:  Can't get working directory!\n", Argv[0]);
	    exit(1);
	}
    } else
	full[0] = '\0';

    (void)strcpy(name, n);		/* working copy... */

    do {				/* while (end) */
	if (beg)
	    beg = end + 1;		/* skip past the NULL */
	else
	    beg = name;			/* just starting out... */

	/* find and terminate end of path component */
	if ((end = index(beg, '/')))
	    *end = '\0';

	if (beg == end)
	    continue;
	else if (!strcmp(beg, "."))
	    ;				/* ignore "." */
	else if (!strcmp(beg, "..")) {
	    if ((tmp = rindex(full, '/')))
		*tmp = '\0';
	} else {
	    strcat(full, "/");
	    strcat(full, beg);		/* copy in new component */
	}

	/* if we used ../.. to go past the root dir just continue */
	if (!full[0])
	    continue;

	/* check for symbolic links */
	if (lstat(full, &statbuf)) {
	    perror("qualify:  lstat");
	    exit(1);
	}

	if ((statbuf.st_mode & S_IFMT) == S_IFLNK) {
	    int linklen;		/* length of link contents */
	    char newname[MAXPATHLEN+1];	/* temp storage to build new name */

	    linklen = readlink(full, newname, sizeof(newname));
	    newname[linklen] = '\0';
	    
	    /* check to make sure we don't go past MAXPATHLEN */
	    ++end;
	    if (end != (char *)1) {
		if (linklen + strlen(end) >= MAXPATHLEN) {
		    fprintf(stderr, "%s:  path too long:  %s/%s\n", Argv[0],
								newname, end);
		    exit(1);
		}

		strcat(newname, "/");
		strcat(newname, end);	/* copy what's left of end */
	    }

	    if (newname[0] == '/')	/* reset full if necesary */
		full[0] = '\0';
	    else
		if ((tmp = rindex(full, '/')))	/* remove component from full */
		    *tmp = '\0';

	    strcpy(name, newname);	/* reset name with new path */
	    beg = NULL;			/* since we have a new name */
	}
    } while (end);

    /* if we resolved to "/" full[0] will be NULL */
    if (!full[0])
	strcpy(full, "/");

    return((char *)full);
}


#ifdef NEED_STRDUP
/******************************************************************
 *
 *  strdup()
 *
 *  this function returns a pointer a string copied into 
 *  a malloc()ed buffer
 */

char *strdup(s1)
    char *s1;
{
    char *s;

    if ((s = (char *) malloc(strlen(s1) + 1)) == NULL)
	return (NULL);

    (void)strcpy(s, s1);
    return(s);
}
#endif
