/*
 *  CU sudo version 1.5.5
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
 *  This module contains getcwd(3) for those systems that lack it.
 *  getcwd(3) returns a pointer to the current working dir.  It uses
 *  path as a copy-out parameter and malloc(3)s space if path is NULL.
 *  This implementation of getcwd(3) restricts len(path) to be < MAXPATHLEN.
 *
 *  Todd C. Miller (millert@colorado.edu) Fri Jun  3 18:32:19 MDT 1994
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
#  include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/in.h>

#include <pathnames.h>
#include "compat.h"

#ifndef STDC_HEADERS
#ifndef __GNUC__		/* gcc has its own malloc */
extern char *malloc	__P((size_t));
#endif /* __GNUC__ */
extern char *strcpy	__P((char *, const char *));
extern int   strlen	__P((const char *));
extern char *getwd	__P((char *));
extern char *fgets	__P((char *, int, FILE *));
#endif /* !STDC_HEADERS */


/*
 * Since we can't count on this being defined...
 */
extern int errno;


/******************************************************************
 *
 *  getcwd()
 *
 *  getcwd() returns a pointer to the current working dir.  It uses
 *  path as a copy-out parameter and malloc(3)s space if path is NULL.
 */

char * getcwd(path, psize)
    char * path;				/* path to copy into */
    size_t psize;				/* size of path */
{
    char buf[MAXPATHLEN+1];			/* +1 for the newline */
    size_t blen;				/* length of buf */
    FILE * pwd;					/* stream for "pwd" process */
    int fd[2];					/* for pipe(2) */
    pid_t pid;					/* pid of "pwd" process */
    int status;					/* status from wait(2) */

    /* sanity check */
    if (path && psize == 0) {
	errno = EINVAL;
	return(NULL);
    }

    /*
     * open a pipe to pwd and read a line
     */
    if (pipe(fd) < 0)
    	return(NULL);
    switch ((pid = fork())) {
	case -1:
	    /* fork failed */
	    (void) close(fd[0]);
	    (void) close(fd[1]);
	    return(NULL);
	case 0:
	    /* in child */
	    (void) dup2(fd[0], 0);
	    (void) dup2(fd[1], 1);
	    (void) close(fd[0]);
	    (void) close(fd[1]);
	    execl(_PATH_PWD, "pwd", NULL);
	    _exit(-1);		/* should not happen */
    }

    /* in parent */
    if ((pwd = fdopen(fd[0], "r")) == NULL) {
	(void) close(fd[0]);
	(void) close(fd[1]);
	return(NULL);
    }

    if (!fgets(buf, sizeof(buf), pwd)) {
	errno = EACCES;				/* what an assumption... */
	pclose(pwd); 
	return(NULL);
    }

    /* wait for the pipe to close */
    while (wait(&status) != pid)
	;

    blen = strlen(buf);
    if (buf[blen - 1] == '\n')
	buf[--blen] = '\0';			/* remove newline */
    else if (blen >= MAXPATHLEN) {
	errno = ENAMETOOLONG;			/* only possible w/o newline */
	return(NULL);
    }

    /* sanity check */
    if (path && psize < blen + 1) {
	errno = ERANGE;
	return(NULL);
    }

    if (path == NULL) {
	if (!(path = (char *) malloc(MAXPATHLEN))) {
	    errno = ENOMEM;
	    return(NULL);
	}
    }

    (void) strcpy(path, buf);
    return(path);
}
