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
 *  This module contains the find_path() function that returns
 *  TRUE if the command was found and FALSE if not.
 *  If find_path() returns TRUE, the copyin paramters command and
 *  ocommand contain the resolved and unresolved pathnames respectively.
 *  NOTE: if "." or "" exists in PATH it will be searched last.
 *
 *  Todd C. Miller (millert@colorado.edu) Sat Sep  4 12:22:04 MDT 1993
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
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif /* HAVE_MALLOC_H */
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include "sudo.h"
#include "options.h"

#ifndef STDC_HEADERS
#ifndef __GNUC__		/* gcc has its own malloc */
extern char *malloc	__P((size_t));
#endif /* __GNUC__ */
extern char *getenv	__P((const char *));
extern char *strcpy	__P((char *, const char *));
extern int fprintf	__P((FILE *, const char *, ...));
extern ssize_t readlink	__P((const char *, char *, size_t));
extern int stat		__P((const char *, struct stat *));
extern int lstat	__P((const char *, struct stat *));
#ifdef HAVE_STRDUP
extern char *strdup	__P((const char *));
#endif /* HAVE_STRDUP */
#endif /* !STDC_HEADERS */


#ifndef _S_IFMT
#define _S_IFMT		S_IFMT
#endif /* _S_IFMT */
#ifndef _S_IFLNK
#define _S_IFLNK	S_IFLNK
#endif /* _S_IFLNK */


/*
 * Globals
 */
static char * realpath_exec	__P((char *, char *, char *));


/*******************************************************************
 *
 *  find_path()
 *
 *  this function finds the full pathname for a command
 */

int find_path(file, command, ocommand)
    char *file;			/* file to find */
    char **command;		/* copyout parameter */
    char **ocommand;		/* copyout parameter */
{
    register char *n;		/* for traversing path */
    char *path = NULL;		/* contents of PATH env var */
    char *origpath;		/* so we can free path later */
    char *result = NULL;	/* result of path/file lookup */
    int checkdot = 0;		/* check current dir? */

    if (strlen(file) > MAXPATHLEN) {
	(void) fprintf(stderr, "%s:  path too long:  %s\n", Argv[0], file);
	exit(1);
    }

    /*
     * allocate memory for command
     */
    *command = (char *) malloc(MAXPATHLEN + 1);
    if (*command == NULL) {
	perror("malloc");
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /*
     * do we need to search the path?
     */
    if (strchr(file, '/')) {
	/* store the unresolved command in ocommand */
	if (ocommand) {
	    *ocommand = strdup(file);
	    if (*ocommand == NULL) {
		perror("malloc");
		(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
		exit(1);
	    }
	}
	return((sudo_realpath(file, *command)) ? TRUE : FALSE);
    }

    /*
     * grab PATH out of environment and make a local copy
     */
    if ((path = getenv("PATH")) == NULL)
	return (FALSE);

    if ((path = strdup(path)) == NULL) {
	fprintf(stderr, "sudo: out of memory!\n");
	exit(1);
    }
    origpath=path;

    do {
	if ((n = strchr(path, ':')))
	    *n = '\0';

	/*
	 * search current dir last if it is in PATH This will miss sneaky
	 * things like using './' or './/' 
	 */
	if (*path == '\0' || (*path == '.' && *(path + 1) == '\0')) {
	    checkdot = 1;
	    path = n + 1;
	    continue;
	}

	/*
	 * resolve the path and exit the loop if found
	 */
	if ((result = realpath_exec(path, file, *command)))
	    break;

	path = n + 1;

    } while (n);

    /*
     * check current dir if dot was in the PATH
     */
    if (!result && checkdot) {
	path = ".";
	result = realpath_exec(path, file, *command);
    }

    /*
     * save old (unresolved) command
     */
    if (result && ocommand) {
	*ocommand = (char *) malloc(strlen(path) + strlen(file) + 2);
	if (*ocommand == NULL) {
	    perror("malloc");
	    (void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	    exit(1);
	}
	(void) sprintf(*ocommand, "%s/%s", path, file);
    }

    (void) free(origpath);

    return(result ? TRUE : FALSE);
}


/*******************************************************************
 *
 *  realpath_exec()
 *
 *  This function calls realpath() to resolve the path and checks
 *  so see that file is executable.  Returns the resolved path on
 *  success and NULL on failure (or if file is not executable).
 */

static char * realpath_exec(path, file, command)
    char * path;
    char * file;
    char * command;
{
    char fn[MAXPATHLEN+1];		/* filename (path + file) */
    struct stat statbuf;		/* for stat(2) */

    (void) sprintf(fn, "%s/%s", path, file);

    /* resolve the path */
    errno = 0;
    if (sudo_realpath(fn, command)) {
	/* stat the file to make sure it is executable and a file */
	if (stat(command, &statbuf) == 0 && S_ISREG(statbuf.st_mode) &&
	    (statbuf.st_mode & 0000111))
	    return(command);
    } else if (errno && errno != ENOENT && errno != ENOTDIR && errno != EINVAL
	&& errno != EPERM && errno != EACCES) {
	/* sudo_realpath() got an error */
	fprintf(stderr, "sudo: Error resolving %s: ", fn);
	perror("");
    }

    return(NULL);
}
