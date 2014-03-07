/*
 * Copyright (c) 2011-2014 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>

#include "missing.h"
#include "sudo_debug.h"
#include "sudo_util.h"

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

/* tgetpass() needs to know the erase and kill chars for cbreak mode. */
int term_erase;
int term_kill;

static volatile sig_atomic_t got_sigttou;

/*
 * SIGTTOU signal handler for term_restore that just sets a flag.
 */
static void sigttou(int signo)
{
    got_sigttou = 1;
}

/*
 * Like tcsetattr() but restarts on EINTR _except_ for SIGTTOU.
 * Returns 0 on success or -1 on failure, setting errno.
 * Sets got_sigttou on failure if interrupted by SIGTTOU.
 */
static int
tcsetattr_nobg(int fd, int flags, struct termios *tp)
{
    sigaction_t sa, osa;
    int rc;

    /*
     * If we receive SIGTTOU from tcsetattr() it means we are
     * not in the foreground process group.
     * This should be less racy than using tcgetpgrp().
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sigttou;
    got_sigttou = 0;
    sigaction(SIGTTOU, &sa, &osa);
    do {
	rc = tcsetattr(fd, flags, tp);
    } while (rc != 0 && errno == EINTR && !got_sigttou);
    sigaction(SIGTTOU, &osa, NULL);

    return rc;
}

/*
 * Restore saved terminal settings if we are in the foreground process group.
 * Returns true on success or false on failure.
 */
bool
term_restore(int fd, bool flush)
{
    debug_decl(term_restore, SUDO_DEBUG_UTIL)

    if (changed) {
	const int flags = flush ? (TCSASOFT|TCSAFLUSH) : (TCSASOFT|TCSADRAIN);
	if (tcsetattr_nobg(fd, flags, &oterm) != 0)
	    debug_return_bool(false);
	changed = 0;
    }
    debug_return_bool(true);
}

/*
 * Disable terminal echo.
 * Returns true on success or false on failure.
 */
bool
term_noecho(int fd)
{
    debug_decl(term_noecho, SUDO_DEBUG_UTIL)

again:
    if (!changed && tcgetattr(fd, &oterm) != 0)
	debug_return_bool(false);
    (void) memcpy(&term, &oterm, sizeof(term));
    CLR(term.c_lflag, ECHO|ECHONL);
#ifdef VSTATUS
    term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
    if (tcsetattr_nobg(fd, TCSADRAIN|TCSASOFT, &term) == 0) {
	changed = 1;
	debug_return_bool(true);
    }
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    debug_return_bool(false);
}

/*
 * Set terminal to raw mode.
 * Returns true on success or false on failure.
 */
bool
term_raw(int fd, int isig)
{
    struct termios term;
    debug_decl(term_raw, SUDO_DEBUG_UTIL)

again:
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
    if (tcsetattr_nobg(fd, TCSADRAIN|TCSASOFT, &term) == 0) {
	changed = 1;
    	debug_return_bool(true);
    }
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    debug_return_bool(false);
}

/*
 * Set terminal to cbreak mode.
 * Returns true on success or false on failure.
 */
bool
term_cbreak(int fd)
{
    debug_decl(term_cbreak, SUDO_DEBUG_UTIL)

again:
    if (!changed && tcgetattr(fd, &oterm) != 0)
	return 0;
    (void) memcpy(&term, &oterm, sizeof(term));
    /* Set terminal to half-cooked mode */
    term.c_cc[VMIN] = 1;
    term.c_cc[VTIME] = 0;
    /* cppcheck-suppress redundantAssignment */
    CLR(term.c_lflag, ECHO | ECHONL | ICANON | IEXTEN);
    /* cppcheck-suppress redundantAssignment */
    SET(term.c_lflag, ISIG);
#ifdef VSTATUS
    term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
    if (tcsetattr_nobg(fd, TCSADRAIN|TCSASOFT, &term) == 0) {
	term_erase = term.c_cc[VERASE];
	term_kill = term.c_cc[VKILL];
	changed = 1;
	debug_return_bool(true);
    }
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    debug_return_bool(false);
}

/*
 * Copy terminal settings from one descriptor to another.
 * Returns true on success or false on failure.
 */
bool
term_copy(int src, int dst)
{
    struct termios tt;
    debug_decl(term_copy, SUDO_DEBUG_UTIL)

again:
    if (tcgetattr(src, &tt) != 0)
	debug_return_bool(false);
    if (tcsetattr_nobg(dst, TCSANOW|TCSASOFT, &tt) == 0)
	debug_return_bool(true);
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    debug_return_bool(false);
}
