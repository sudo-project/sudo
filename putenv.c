/*
 * Copyright (c) 1996, 1998, 1999 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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

#include "compat.h"

#if !defined(STDC_HEADERS) && !defined(__GNUC__)
extern VOID *malloc	__P((size_t));
#endif /* !STDC_HEADERS && !gcc */

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */


/*
 * putenv() places a string of the for "name=value" into the environment.
 * Note that this string becomes a part of the environment.
 */
int
putenv(str)
    const char *str;
{
    char **current;
    int matchlen, envlen=0;
    char *tmp;
    char **newenv;
    static int first=1;
    extern char ** environ;

    /*
     * Find out how much of str to match when searching
     * for a string to replace.
     */
    if ((tmp = strchr(str, '=')) == NULL || tmp == str)
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

    /* Actually add in the new entry... */
    environ = newenv;
    environ[envlen] = (char *)str;
    environ[envlen+1] = NULL;

    return(0);
}
