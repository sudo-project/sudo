/*
 * Copyright (c) 1996, 1998-2004 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#ifdef __TANDEM
# include <floss.h>
#endif

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_SYS_BSDTYPES_H
# include <sys/bsdtypes.h>
#endif /* HAVE_SYS_BSDTYPES_H */
#include <sys/time.h>
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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
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

#include "sudo.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

#ifndef TCSASOFT
# define TCSASOFT	0
#endif
#ifndef ECHONL
# define ECHONL	0
#endif

#ifndef _POSIX_VDISABLE
# ifdef VDISABLE
#  define _POSIX_VDISABLE	VDISABLE
# else
#  define _POSIX_VDISABLE	0
# endif
#endif

/*
 * Abstract method of getting at the term flags.
 */
#undef TERM
#undef tflags
#ifdef HAVE_TERMIOS_H
# define TERM			termios
# define tflags			c_lflag
# define term_getattr(f, t)	tcgetattr(f, t)
# define term_setattr(f, t)	tcsetattr(f, TCSAFLUSH|TCSASOFT, t)
#else
# ifdef HAVE_TERMIO_H
# define TERM			termio
# define tflags			c_lflag
# define term_getattr(f, t)	ioctl(f, TCGETA, t)
# define term_setattr(f, t)	ioctl(f, TCSETAF, t)
# else
#  define TERM			sgttyb
#  define tflags		sg_flags
#  define term_getattr(f, t)	ioctl(f, TIOCGETP, t)
#  define term_setattr(f, t)	ioctl(f, TIOCSETP, t)
# endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */

static volatile sig_atomic_t signo;

static void handler __P((int));

/*
 * Like getpass(3) but with timeout and echo flags.
 */
char *
tgetpass(prompt, timeout, flags)
    const char *prompt;
    int timeout;
    int flags;
{
    sigaction_t sa, savealrm, saveint, savehup, savequit, saveterm;
    sigaction_t savetstp, savettin, savettou;
    FILE *input, *output;
    struct TERM term, oterm;
    char *pass, *ep;
    static char buf[SUDO_PASS_MAX + 1];
    int fd, save_errno;

restart:
    /* Open /dev/tty for reading/writing if possible else use stdin/stderr. */
    if (ISSET(flags, TGP_STDIN) ||
	(fd = open(_PATH_TTY, O_RDWR|O_NOCTTY)) == -1 ||
	(input = output = fdopen(fd, "r+")) == NULL) {
	input = stdin;
	output = stderr;
	(void) fflush(output);
    }

    /*
     * Catch signals that would otherwise cause the user to end
     * up with echo turned off in the shell.  Don't worry about
     * things like SIGALRM and SIGPIPE for now.
     */
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;		/* don't restart system calls */
    sa.sa_handler = handler;
    (void) sigaction(SIGALRM, &sa, &savealrm);
    (void) sigaction(SIGINT, &sa, &saveint);
    (void) sigaction(SIGHUP, &sa, &savehup);
    (void) sigaction(SIGQUIT, &sa, &savequit);
    (void) sigaction(SIGTERM, &sa, &saveterm);
    (void) sigaction(SIGTSTP, &sa, &savetstp);
    (void) sigaction(SIGTTIN, &sa, &savettin);
    (void) sigaction(SIGTTOU, &sa, &savettou);

    /* Turn echo off/on as specified by flags.  */
    if (term_getattr(fileno(input), &oterm) == 0) {
	(void) memcpy(&term, &oterm, sizeof(term));
	if (!ISSET(flags, TGP_ECHO))
	    CLR(term.tflags, (ECHO | ECHONL));
#ifdef VSTATUS
	term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
	(void) term_setattr(fileno(input), &term);
    } else {
	memset(&term, 0, sizeof(term));
	memset(&oterm, 0, sizeof(oterm));
    }

    if (prompt) {
	(void) fputs(prompt, output);
	(void) fflush(output);
	if (input == output)
	    (void) rewind(input);
    }

    if (timeout > 0)
	alarm(timeout);
    pass = fgets(buf, sizeof(buf), input);
    alarm(0);
    if (pass != NULL) {
	ep = pass + strlen(pass);
	while (ep > pass && (*--ep == '\n' || *ep == '\r'))
		*ep = '\0';
    }
    save_errno = errno;

    if (!ISSET(term.tflags, ECHO))
	fputc('\n', output);

    /* Restore old tty settings and signals. */
    if (memcmp(&term, &oterm, sizeof(term)) != 0)
	(void) term_setattr(fileno(input), &oterm);
    (void) sigaction(SIGALRM, &savealrm, NULL);
    (void) sigaction(SIGINT, &saveint, NULL);
    (void) sigaction(SIGHUP, &savehup, NULL);
    (void) sigaction(SIGQUIT, &savequit, NULL);
    (void) sigaction(SIGTERM, &saveterm, NULL);
    (void) sigaction(SIGTSTP, &savetstp, NULL);
    (void) sigaction(SIGTTIN, &savettin, NULL);
    (void) sigaction(SIGTTOU, &savettou, NULL);
    if (input != stdin)
	(void) fclose(input);

    /*
     * If we were interrupted by a signal, resend it to ourselves
     * now that we have restored the signal handlers.
     */
    if (signo) {
	kill(getpid(), signo); 
	switch (signo) {
	    case SIGTSTP:
	    case SIGTTIN:
	    case SIGTTOU:
		signo = 0;
		goto restart;
	}
    }

    errno = save_errno;
    return(pass);
}

static void
handler(s)
    int s;
{
    if (s != SIGALRM)
	signo = s;
}
