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
 *  This module contains putenv(3) for those systems that lack it.
 *
 *  Todd C. Miller (millert@colorado.edu) Sun Aug  7 20:30:17 MDT 1994
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"

#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
#include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <errno.h>
#include <sys/param.h>

#include "compat.h"

#if !defined(STDC_HEADERS) && !defined(__GNUC__)
extern char *malloc	__P((size_t));
#endif /* !STDC_HEADERS && !gcc */


/*
 * Since we can't count on this being defined...
 */
extern int errno;


int putenv              __P((const char *));


/******************************************************************
 *
 *  putenv()
 *
 *  putenv(3) places a string of the for "name=value" into the environment.
 *  Note that this string becomes a part of the environment.
 */

int putenv(str)
    const char *str;
{
    char **current;
    int matchlen, envlen=0;
    char *tmp;
    char **newenv;
    static int first=1;
    extern char ** environ;

    /*
     * find out how much of str to match when searching
     * for a string to replace.
     */
    if ((tmp = index(str, '=')) == NULL || tmp == str)
	matchlen = strlen(str);
    else
	matchlen = (int) (tmp - str);
    ++matchlen;

    /*
     * Search for an existing string in the environment and find the
     * length of environ.  If found, replace and exit.
     */
    for (current=environ; *current; current++) {
	++envlen;

	if (strncmp(str, *current, matchlen) == 0) {
	    /* found it, now insert the new version */
	    *current = (char *)str;
	    return(0);
	}
    }

    /*
     * There wasn't already a slot so add space for a new slot.
     * If this is our first time through, use malloc(), else realloc().
     */
    if (first) {
	newenv = (char **) malloc(sizeof(char *) * (envlen + 2));
	if (newenv == NULL)
	    return(-1);

	first=0;
	(void) memcpy(newenv, environ, sizeof(char *) * envlen);
    } else {
	newenv = (char **) realloc((char *)environ, sizeof(char *) * (envlen + 2));
	if (newenv == NULL)
	    return(-1);
    }

    /* actually add in the new entry */
    environ = newenv;
    environ[envlen] = (char *)str;
    environ[envlen+1] = NULL;

    return(0);
}
