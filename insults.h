#ifdef USE_INSULTS
/*
 *  CU sudo version 1.3
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
 *  Please send bugs, changes, problems to sudo-bugs.cs.colorado.edu
 */

/*
 * To add insult to injury, just add to the following strings and
 * adjust NOFINSULTS accordingly.  This code taken from the original
 * sudo(8).
 */

char *insults[] = {
     "Wrong!  You cheating scum!\n",
     "No soap, honkie-lips.\n",
     "Where did you learn to type?\n",
     "Are you on drugs?\n",
     "My pet ferret can type better than you!\n",
     "You type like i drive.\n",
     "Do you think like you type?\n",
     "Your mind just hasn't been the same since the electro-shock, has it?\n"
};

#define NOFINSULTS 8 /* number of insults - 1 */

/*
 *	return a random insult.
 */

#define INSULT		(insults[time(NULL) % NOFINSULTS])

#endif /* USE_INSULTS */
