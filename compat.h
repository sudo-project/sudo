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
 */

#ifndef _SUDO_COMPAT_H
#define _SUDO_COMPAT_H

/*
 * Macros that may be missing on some Operating Systems
 */

/* Deal with ansi stuff reasonably.  */
#ifndef  __P
#  if defined (__cplusplus) || defined (__STDC__)
#    define __P(args)     args
#  else
#    define __P(args)     ()
#  endif
#endif /* __P */

/*
 * Some systems (ie ISC V/386) do not define MAXPATHLEN even in param.h
 */
#ifndef MAXPATHLEN
#  define MAXPATHLEN		1024
#endif

/*
 * Some systems do not define MAXHOSTNAMELEN.
 */
#ifndef MAXHOSTNAMELEN
#  define MAXHOSTNAMELEN	64
#endif

/*
 * Emulate seteuid() and setegid() for HP-UX
 */
#ifdef __hpux
#  define seteuid(__EUID)	(setresuid((uid_t)-1, __EUID, (uid_t)-1))
#  define setegid(__EGID)	(setresgid((gid_t)-1, __EGID, (gid_t)-1))
#endif	/* __hpux */

/*
 * Emulate seteuid() and setegid() for AIX
 */
#ifdef _AIX
#  include <sys/id.h>
#  define seteuid(__EUID)	(setuidx(ID_EFFECTIVE|ID_REAL, __EUID))
#  define setegid(__EGID)	(setgidx(ID_EFFECTIVE|ID_REAL, __EGID))
#endif	/* _AIX */

#endif /* _SUDO_COMPAT_H */
