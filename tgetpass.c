/*
 *  CU sudo version 1.3.7
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
 *******************************************************************
 *
 *  This module contains tgetpass(), getpass(3) with a timeout.
 *  It should work on any OS that supports sgtty (4BSD), termio (SYSV),
 *  or termios (POSIX) line disciplines.
 *
 *  Todd C. Miller  Sun Jun  5 17:22:31 MDT 1994
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <pwd.h>
#include <sys/types.h>
#ifdef _AIX
#include <sys/select.h>
#endif /* _AIX */
#include <sys/time.h>
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#else
#ifdef HAVE_TERMIO_H
#include <termio.h>
#else
#include <sgtty.h>
#include <sys/ioctl.h>
#endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */

#include <pathnames.h>
#include "compat.h"

#ifndef _PASSWD_LEN
#  ifdef HAVE_C2_SECURITY
#    define	_PASSWD_LEN	24
#  else
#    define	_PASSWD_LEN	8
#  endif /* HAVE_C2_SECURITY */
#endif /* _PASSWD_LEN */


/******************************************************************
 *
 *  tgetpass()
 *
 *  this function prints a prompt and gets a password from /dev/tty
 *  or stdin.  Echo is turned off (if possible) during password entry
 *  and input will time out based on the value of timeout.
 */

char * tgetpass(prompt, timeout)
    const char *prompt;
    int timeout;
{
#ifdef HAVE_TERMIOS_H
    struct termios term;
#else
#ifdef HAVE_TERMIO_H
    struct termio term;
#else
    struct sgttyb ttyb;
#endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */
    FILE * input, * output;
    static char buf[_PASSWD_LEN + 1];
#ifdef POSIX_SIGNALS
    sigset_t oldmask;
    sigset_t mask;
#else
    int oldmask;
#endif
#ifdef HAVE_TERMIOS_H
    tcflag_t svflagval;
#else
    unsigned short svflagval;
#endif
    fd_set readfds;
    struct timeval tv;
    char *tmp;

    /*
     * mask out SIGINT, should probably just catch it.
     */
#ifdef POSIX_SIGNALS
    (void) memset((VOID *)&mask, 0, sizeof(mask));
    (void) sigaddset(&mask, SIGINT);
    (void) sigprocmask(SIG_BLOCK, &mask, &oldmask);
#else
    oldmask = sigblock(sigmask(SIGINT));
#endif

    /*
     * open /dev/tty for reading/writing if possible or use
     * stdin and stderr instead.
     */
    input = fopen(_PATH_TTY, "r+");
    if (!input) {
	input = stdin;
	output = stderr;
	(void) fflush(output);
    } else {
	output = input;
    }

    /*
     * turn off echo
     */
#ifdef HAVE_TERMIOS_H
    (void) tcgetattr(fileno(input), &term);
    svflagval = term.c_lflag;
    term.c_lflag &= ~ECHO;
    (void) tcsetattr(fileno(input), TCSAFLUSH, &term);
#else
#ifdef HAVE_TERMIO_H
    (void) ioctl(fileno(input), TCGETA, &term);
    svflagval = term.c_lflag;
    term.c_lflag &= ~ECHO;
    (void) ioctl(fileno(input), TCSETA, &term);
#else
    (void) ioctl(fileno(input), TIOCGETP, &ttyb);
    svflagval = ttyb.sg_flags;
    ttyb.sg_flags &= ~ECHO;
    (void) ioctl(fileno(input), TIOCSETP, &ttyb);
#endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */

    /* print the prompt */
    (void) fputs(prompt, output);

    /* rewind if necesary */
    if (input == output) {
	(void) fflush(output);
	(void) rewind(output);
    }

    /* setup for select(2) */
    FD_ZERO(&readfds);
    FD_SET(fileno(input), &readfds);

    /* set timeout for select */
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    /* return NULL if nothing to read by timeout */
#ifdef HAVE_SYSCONF
    if (select(sysconf(_SC_OPEN_MAX), &readfds, NULL, NULL, &tv) <= 0) {
#else
    if (select(getdtablesize(), &readfds, NULL, NULL, &tv) <= 0) {
#endif /* HAVE_SYSCONF */
	buf[0] = '\0';
	goto cleanup;
    }

    /* get the password */
    if (!fgets(buf, sizeof(buf), input)) {
	buf[0] = '\0';
	goto cleanup;
    }

    if (*(tmp = &buf[strlen(buf)-1]) == '\n')
	*tmp = '\0';

cleanup:

     /* turn on echo */
#ifdef HAVE_TERMIOS_H
    term.c_lflag = svflagval;
    (void) tcsetattr(fileno(input), TCSAFLUSH, &term);
#else
#ifdef HAVE_TERMIO_H
    term.c_lflag = svflagval;
    (void) ioctl(fileno(input), TCSETA, &term);
#else
    ttyb.sg_flags = svflagval;
    (void) ioctl(fileno(input), TIOCSETP, &ttyb);
#endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */

    /* rewind if necesary */
    if (input == output) {
	(void) fflush(output);
	(void) rewind(output);
    }
    (void) fputc('\n', output);

    /* restore old signal mask */
#ifdef POSIX_SIGNALS
    (void) sigprocmask(SIG_SETMASK, &oldmask, NULL);
#else
    (void) sigsetmask(oldmask);
#endif

    /* close /dev/tty if that's what we opened */
    if (input != stdin)
	(void) fclose(input);

    return(buf);
}
