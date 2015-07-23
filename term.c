/*
 * Copyright (c) 2009-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <errno.h>
#include <signal.h>
#ifdef HAVE_TERMIOS_H
# include <termios.h>
#else
# ifdef HAVE_TERMIO_H
#  include <termio.h>
# else
#  include <sgtty.h>
#  include <sys/ioctl.h>
# endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include "sudo.h"

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

/*
 * Compat macros for non-termios systems.
 */
#ifndef HAVE_TERMIOS_H
# ifdef HAVE_TERMIO_H
#  undef termios
#  define termios		termio
#  define tcgetattr(f, t)	ioctl(f, TCGETA, t)
#  define tcsetattr(f, a, t)	ioctl(f, a, t)
#  undef TCSAFLUSH
#  define TCSAFLUSH		TCSETAF
#  undef TCSADRAIN
#  define TCSADRAIN		TCSETAW
# else /* SGTTY */
#  undef termios
#  define termios		sgttyb
#  define c_lflag		sg_flags
#  define tcgetattr(f, t)	ioctl(f, TIOCGETP, t)
#  define tcsetattr(f, a, t)	ioctl(f, a, t)
#  undef TCSAFLUSH
#  define TCSAFLUSH		TIOCSETP
#  undef TCSADRAIN
#  define TCSADRAIN		TIOCSETN
# endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */

typedef struct termios sudo_term_t;

static sudo_term_t term, oterm;
static int changed;

/* tgetpass() needs to know the erase and kill chars for cbreak mode. */
int term_erase;
int term_kill;

static volatile sig_atomic_t got_sigttou;

/*
 * SIGTTOU signal handler for term_restore that just sets a flag.
 */
static void
sigttou(signo)
    int signo;
{
    got_sigttou = 1;
}

/*
 * Like tcsetattr() but restarts on EINTR _except_ for SIGTTOU.
 * Returns 0 on success or -1 on failure, setting errno.
 * Sets got_sigttou on failure if interrupted by SIGTTOU.
 */
static int
tcsetattr_nobg(fd, flags, tp)
    int fd;
    int flags;
    struct termios *tp;
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
 * Returns 1 on success or 0 on failure.
 */
int
term_restore(fd, flush)
    int fd;
    int flush;
{
    if (changed) {
	const int flags = flush ? (TCSASOFT|TCSAFLUSH) : (TCSASOFT|TCSADRAIN);
	if (tcsetattr_nobg(fd, flags, &oterm) != 0)
	    return 0;
	changed = 0;
    }
    return 1;
}

/*
 * Disable terminal echo.
 * Returns 1 on success or 0 on failure.
 */
int
term_noecho(fd)
    int fd;
{
again:
    if (!changed && tcgetattr(fd, &oterm) != 0)
	return 0;
    (void) memcpy(&term, &oterm, sizeof(term));
    CLR(term.c_lflag, ECHO|ECHONL);
#ifdef VSTATUS
    term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
    if (tcsetattr_nobg(fd, TCSADRAIN|TCSASOFT, &term) == 0) {
	changed = 1;
	return 1;
    }
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    return 0;
}

#if defined(HAVE_TERMIOS_H) || defined(HAVE_TERMIO_H)

/*
 * Set terminal to raw mode.
 * Returns 1 on success or 0 on failure.
 */
int
term_raw(fd, isig)
    int fd;
    int isig;
{
    struct termios term;

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
    	return 1;
    }
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    return 0;
}

/*
 * Set terminal to cbreak mode.
 * Returns 1 on success or 0 on failure.
 */
int
term_cbreak(fd)
    int fd;
{
again:
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
    if (tcsetattr_nobg(fd, TCSADRAIN|TCSASOFT, &term) == 0) {
	term_erase = term.c_cc[VERASE];
	term_kill = term.c_cc[VKILL];
	changed = 1;
	return 1;
    }
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    return 0;
}

/*
 * Copy terminal settings from one descriptor to another.
 * Returns 1 on success or 0 on failure.
 */
int
term_copy(src, dst)
    int src;
    int dst;
{
    struct termios tt;

again:
    if (tcgetattr(src, &tt) != 0)
	return 0;
    /* XXX - add TCSANOW compat define */
    if (tcsetattr_nobg(dst, TCSANOW|TCSASOFT, &tt) == 0)
	return 1;
    if (got_sigttou) {
	/* We were in the background, so tt is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    return 0;
}

#else /* SGTTY */

#define ioctl_nobg(f, r, s)	tcsetattr_nobg((f), (r), (s))

/*
 * Set terminal to raw mode.
 * Returns 1 on success or 0 on failure.
 */
int
term_raw(fd, isig)
    int fd;
    int isig;
{
again:
    if (!changed && ioctl(fd, TIOCGETP, &oterm) != 0)
	return 0;
    (void) memcpy(&term, &oterm, sizeof(term));
    /* Set terminal to raw mode */
    /* XXX - how to support isig? */
    CLR(term.c_lflag, ECHO);
    SET(term.sg_flags, RAW);
    if (ioctl_nobg(fd, TIOCSETP, &term) == 0) {
	changed = 1;
	return 1;
    }
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    return 0;
}

/*
 * Set terminal to cbreak mode.
 * Returns 1 on success or 0 on failure.
 */
int
term_cbreak(fd)
    int fd;
{
again:
    if (!changed && ioctl(fd, TIOCGETP, &oterm) != 0)
	return 0;
    (void) memcpy(&term, &oterm, sizeof(term));
    /* Set terminal to half-cooked mode */
    CLR(term.c_lflag, ECHO);
    SET(term.sg_flags, CBREAK);
    if (ioctl_nobg(fd, TIOCSETP, &term) == 0) {
	term_erase = term.sg_erase;
	term_kill = term.sg_kill;
	changed = 1;
	return 1;
    }
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    return 0;
}

/*
 * Copy terminal settings from one descriptor to another.
 * Returns 1 on success or 0 on failure.
 */
int
term_copy(src, dst)
    int src;
    int dst;
{
    struct sgttyb b;
    struct tchars tc;
    struct ltchars lc;
    int l, lb;

again:
    if (ioctl(src, TIOCGETP, &b) != 0 || ioctl(src, TIOCGETC, &tc) != 0 ||
	ioctl(src, TIOCGETD, &l) != 0 || ioctl(src, TIOCGLTC, &lc) != 0 ||
	ioctl(src, TIOCLGET, &lb)) {
	return 0;
    }
    if (ioctl_nobg(dst, TIOCSETP, &b) != 0 ||
	ioctl_nobg(dst, TIOCSETC, &tc) != 0 ||
	ioctl_nobg(dst, TIOCSLTC, &lc) != 0 ||
	ioctl_nobg(dst, TIOCLSET, &lb) != 0 ||
	ioctl_nobg(dst, TIOCSETD, &l) != 0) {
	return 0;
    }
    if (got_sigttou) {
	/* We were in the background, so oterm is probably bogus. */
	kill(getpid(), SIGTTOU);
	goto again;
    }
    return 1;
}

#endif
