/*
 *  CU sudo version 1.6
 *  Copyright (c) 1999 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *  This module contains memory allocation routines used by sudo.
 *
 *  Todd C. Miller <Todd.Miller@courtesan.com> Fri Jun  3 18:32:19 MDT 1994
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

#ifndef STDC_HEADERS
#ifndef __GNUC__		/ *gcc has its own malloc */
extern VOID *malloc	__P((size_t));
#endif /* __GNUC__ */
#endif /* !STDC_HEADERS */

extern char **Argv;		/* from sudo.c */

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */


/**********************************************************************
 *
 * emalloc()
 *
 *  emalloc() calls the system malloc(3) and exits with an error if
 *  malloc(3) fails.
 */

VOID *emalloc(size)
    size_t size;
{
    VOID *ptr;

    if ((ptr = malloc(size)) == NULL) {
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }
    return(ptr);
}

/**********************************************************************
 *
 * erealloc()
 *
 *  erealloc() calls the system realloc(3) and exits with an error if
 *  realloc(3) fails.  You can call erealloc() with a NULL pointer even
 *  if the system realloc(3) does not support this.
 */

VOID *erealloc(ptr, size)
    VOID *ptr;
    size_t size;
{

    if ((ptr = ptr ? realloc(ptr, size) : malloc(size)) == NULL) {
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }
    return(ptr);
}

/**********************************************************************
 *
 * estrdup()
 *
 *  estrdup() is like strdup(3) except that it exits with an error if
 *  malloc(3) fails.  NOTE: unlike strdup(3), estrdup(NULL) is legal.
 */

char *estrdup(src)
    const char *src;
{
    char *dst = NULL;

    if (src != NULL) {
	dst = (char *) emalloc(strlen(src) + 1);
	(void) strcpy(dst, src);
    }
    return(dst);
}
