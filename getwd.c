/*
 *  CU sudo version 1.5.1
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
 *  This module contains getwd(3) for those systems that lack it.
 *  getwd(3) returns a pointer to the current working dir.  It uses
 *  path as a copy-out parameter.
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
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <pathnames.h>
#include "compat.h"

#ifndef STDC_HEADERS
extern char *strcpy	__P((char *, const char *));
extern int   strlen	__P((const char *));
extern char *getwd	__P((char *));
extern FILE *popen	__P((const char *, const char *));
extern int   pclose	__P((FILE *));
extern char *fgets	__P((char *, int, FILE *));
#endif /* !STDC_HEADERS */


#ifndef _PATH_PWD
#define _PATH_PWD	"pwd"
#endif /* _PATH_PWD */


/*
 * Since we can't count on this being defined...
 */
extern int errno;


/******************************************************************
 *
 *  getwd()
 *
 *  getwd() returns a pointer to the current working dir.  It uses
 *  path as a copy-out parameter.
 *  getwd() will use getcwd() if available, else it will use pwd(1).
 */

char * getwd(path)
    char * path;				/* path to copy into */
{
#ifndef HAVE_GETCWD
    char buf[MAXPATHLEN+1];			/* temp buffer */
    FILE * pwd;					/* for popen */
#endif /* HAVE_GETCWD */

    if (path == NULL) {
	errno = EINVAL;
	return(NULL);
    }

#ifdef HAVE_GETCWD
    return(getcwd(path, MAXPATHLEN));
#else
    /*
     * open a pipe to pwd and read a line
     */
    if (!(pwd = popen(_PATH_PWD, "r")))
	return(NULL);

    if (!fgets(buf, sizeof(buf), pwd)) {
	errno = EACCES;				/* what an assumption... */
	pclose(pwd); 
	return(NULL);
    }
    pclose(pwd); 

    buf[strlen(buf)-1] = '\0';			/* remove newline */

    (void) strcpy(path, buf);
    return(path);
#endif /* HAVE_GETCWD */
}
