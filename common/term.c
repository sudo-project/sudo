/*
 * Copyright (c) 2011 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <termios.h>

#include "missing.h"

#ifndef TCSASOFT
# define TCSASOFT	0
#endif
#ifndef ECHONL
# define ECHONL		0
#endif
#ifndef IEXTEN
# define IEXTEN		0
#endif
#ifndef IUCLC
# define IUCLC		0
#endif

#ifndef _POSIX_VDISABLE
# ifdef VDISABLE
#  define _POSIX_VDISABLE	VDISABLE
# else
#  define _POSIX_VDISABLE	0
# endif
#endif

static struct termios term, oterm;
static int changed;
int term_erase;
int term_kill;

int
term_restore(int fd, int flush)
{
    if (changed) {
	int flags = TCSASOFT;
	flags |= flush ? TCSAFLUSH : TCSADRAIN;
	if (tcsetattr(fd, flags, &oterm) != 0)
	    return 0;
	changed = 0;
    }
    return 1;
}

int
term_noecho(int fd)
{
    if (!changed && tcgetattr(fd, &oterm) != 0)
	return 0;
    (void) memcpy(&term, &oterm, sizeof(term));
    CLR(term.c_lflag, ECHO|ECHONL);
#ifdef VSTATUS
    term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
    if (tcsetattr(fd, TCSADRAIN|TCSASOFT, &term) == 0) {
	changed = 1;
	return 1;
    }
    return 0;
}

int
term_raw(int fd, int isig)
{
    struct termios term;

    if (!changed && tcgetattr(fd, &oterm) != 0)
	return 0;
    (void) memcpy(&term, &oterm, sizeof(term));
    /* Set terminal to raw mode */
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    CLR(term.c_iflag, ICRNL | IGNCR | INLCR | IUCLC | IXON);
    CLR(term.c_oflag, OPOST);
    CLR(term.c_lflag, ECHO | ICANON | ISIG | IEXTEN);
    if (isig)
	SET(term.c_lflag, ISIG);
    if (tcsetattr(fd, TCSADRAIN|TCSASOFT, &term) == 0) {
	changed = 1;
    	return 1;
    }
    return 0;
}

int
term_cbreak(int fd)
{
    if (!changed && tcgetattr(fd, &oterm) != 0)
	return 0;
    (void) memcpy(&term, &oterm, sizeof(term));
    /* Set terminal to half-cooked mode */
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    CLR(term.c_lflag, ECHO | ECHONL | ICANON | IEXTEN);
    SET(term.c_lflag, ISIG);
#ifdef VSTATUS
    term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
    if (tcsetattr(fd, TCSADRAIN|TCSASOFT, &term) == 0) {
	term_erase = term.c_cc[VERASE];
	term_kill = term.c_cc[VKILL];
	changed = 1;
	return 1;
    }
    return 0;
}

int
term_copy(int src, int dst)
{
    struct termios tt;

    if (tcgetattr(src, &tt) != 0)
	return 0;
    if (tcsetattr(dst, TCSANOW|TCSASOFT, &tt) != 0)
	return 0;
    return 1;
}
