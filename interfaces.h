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
 *  $Sudo$
 */

#ifndef _SUDO_INTERFACES_H
#define _SUDO_INTERFACES_H

/*
 * IP address and netmask pairs for checking against local interfaces.
 */
struct interface {
    struct in_addr addr;
    struct in_addr netmask;
};

/*
 * Prototypes for external functions.
 */
void load_interfaces	__P((void));

/*
 * Definitions for external variables.
 */
#ifndef MAIN
extern struct interface *interfaces;
extern int num_interfaces;
#endif

#endif /* _SUDO_INTERFACES_H */
