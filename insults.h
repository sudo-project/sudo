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
 *
 *  $Id$
 */

#ifndef _SUDO_INSULTS_H
#define _SUDO_INSULTS_H

#ifdef USE_INSULTS

/*
 * Choose a set of insults, the default is to use the insults from
 * "sudo classic" (in the original edition of the Sys Admin book).
 */
#ifdef HAL
#  include "ins_2001.h"
#else
#  ifdef GOONS
#    include "ins_goons.h"
#  else
#    include "ins_classic.h"
#  endif /* GOONS */
#endif /* HAL */

/*
 * return a pseudo-random insult.
 */
#define INSULT		(insults[time(NULL) % NOFINSULTS])

#endif /* USE_INSULTS */

#endif /* _SUDO_INSULTS_H */
