/*
 *  CU sudo version 1.3.6
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
 * 4.2BSD lacks FD_* macros (we only use FD_SET and FD_ZERO)
 */
#ifndef FD_SETSIZE
#define FD_SET(fd, fds)		((fds) -> fds_bits[0] |= (1 << (fd)))
#define FD_ZERO(fds)		((fds) -> fds_bits[0] = 0)
#endif /* !FD_SETSIZE */

/*
 * Posix versions for those without...
 */
#ifndef _S_IFMT
#  define _S_IFMT		S_IFMT
#endif /* _S_IFMT */
#ifndef _S_IFREG
#  define _S_IFREG		S_IFREG
#endif /* _S_IFREG */
#ifndef _S_IFDIR
#  define _S_IFDIR		S_IFDIR
#endif /* _S_IFDIR */
#ifndef S_ISREG
#  define S_ISREG(m)		(((m) & _S_IFMT) == _S_IFREG)
#endif /* S_ISREG */
#ifndef S_ISDIR
#  define S_ISDIR(m)		(((m) & _S_IFMT) == _S_IFDIR)
#endif /* S_ISDIR */

/*
 * Some OS's may not have this.
 */
#ifndef S_IRWXU
#  define S_IRWXU		0000700		/* rwx for owner */
#endif /* S_IRWXU */

/*
 * For kerberos, max password len is 128
 */
#ifdef HAVE_KERB4
#  undef _PASSWD_LEN
#  define _PASSWD_LEN	128
#endif /* HAVE_KERB4 */
#ifdef HAVE_DCE
#  undef _PASSWD_LEN
#  define _PASSWD_LEN	256
#endif /* HAVE_DCE */

/*
 * Some OS's lack these
 */
#ifndef UID_NO_CHANGE
#  define UID_NO_CHANGE	((uid_t) -1)
#endif /* UID_NO_CHANGE */
#ifndef GID_NO_CHANGE
#  define GID_NO_CHANGE	((gid_t) -1)
#endif /* GID_NO_CHANGE */

/*
 * Emulate seteuid() and setegid() for HP-UX
 */
#ifdef __hpux
#  define seteuid(_EUID)	(setresuid(UID_NO_CHANGE, _EUID, UID_NO_CHANGE))
#  define setegid(_EGID)	(setresgid(GID_NO_CHANGE, _EGID, GID_NO_CHANGE))
#endif	/* __hpux */

/*
 * Emulate seteuid() and setegid() for AIX
 */
#ifdef _AIX
#  include <sys/id.h>
#  define seteuid(_EUID)	(setuidx(ID_EFFECTIVE|ID_REAL, _EUID))
#  define setegid(_EGID)	(setgidx(ID_EFFECTIVE|ID_REAL, _EGID))
#endif	/* _AIX */

#endif /* _SUDO_COMPAT_H */
