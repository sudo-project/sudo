/*
 *  CU sudo version 1.6
 *  Copyright (c) 1996, 1998, 1999 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *  This module emulates utime(3) via utimes(2) for those systems that
 *  lack utime(2).
 *  utime(3) sets the access and mod times of the named file.
 *
 *  Todd C. Miller <Todd.Miller@courtesan.com> Sat Jun 17 16:42:41 MDT 1995
 */

#include "config.h"

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <sys/types.h>
#include <sys/time.h>

#include <pathnames.h>
#include "compat.h"
#include "emul/utime.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */


/******************************************************************
 *
 *  utime()
 *
 *  Emulate utime(3) via utimes(2).
 *  utime(3) sets the access and mod times of the named file.
 */

int utime(file, tvp)
    const char *file;					/* file to udpate */
    const struct utimbuf *utp;				/* what to update to */
{
    if (upt) {
	struct timeval tv[2];

	tv[0].tv_sec = ut.actime;
	tv[0].tv_usec = 0;

	tv[1].tv_sec = ut.modtime;
	tv[1].tv_usec = 0;

	return(utimes(file, tv);
    } else {
	return(utimes(file, NULL);
    }
}
