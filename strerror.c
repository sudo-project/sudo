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
 *  This module emulates strerror(3) for those systems that lack it.
 */

#include <stdio.h>
#include <errno.h>

#include "config.h"

#ifndef HAVE_STRERROR

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Map errno -> error string.
 */
char *
strerror(n)
    int n;
{
    extern int sys_nerr;
    extern char *sys_errlist[];

    if (n > 0 && n < sys_nerr)
	return(sys_errlist[n]);
    else
	return("Unknown error");
}

#endif /* HAVE_STRERROR */
