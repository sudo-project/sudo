/*
 *  CU sudo version 1.5.5b2
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
 *  $Id$
 */

#ifndef	_UTIME_H
#define	_UTIME_H

struct	utimbuf {
	time_t	actime;		/* access time */
	time_t	modtime;	/* mod time */
};

int utime	__P((const char *, const struct utimbuf *));

#endif	/* _UTIME_H */
