#include "config.h"
#include "pathnames.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/types.h>
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

#ifndef _PASSWD_LEN
#define	_PASSWD_LEN	8
#endif /* _PASSWD_LEN */


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
    int input, output;
    static char buf[_PASSWD_LEN + 1];
    int oldmask;
    fd_set readfds;
    struct timeval tv;
#ifdef HAVE_TERMIO_H
    tcflag_t svflagval;
#else
    int svflagval;
#endif
    int i;

    /*
     * mask out SIGINT
     */
    oldmask = sigblock(sigmask(SIGINT));

    /*
     * open /dev/tty for reading/writing if possible or use
     * stdin and stderr instead.
     */
    input = open(_PATH_TTY, O_RDWR);
    if (!input) {
	(void) fflush(stderr);
	input = fileno(stdin);
	output = fileno(stderr);
    } else {
	output = input;
    }

    /*
     * turn off echo
     */
#ifdef HAVE_TERMIOS_H
    (void) tcgetattr(input, &term);
    svflagval = term.c_lflag;
    term.c_lflag &= ~ECHO;
    (void) tcsetattr(input, TCSAFLUSH, &term);
#else
#ifdef HAVE_TERMIO_H
    (void) ioctl(input, TCGETA, &term);
    svflagval = term.c_lflag;
    term.c_lflag &= ~ECHO;
    (void) ioctl(input, TCSETA, &term);
#else
    (void) ioctl(input, TIOCGETP, &ttyb);
    svflagval = ttyb.sg_flags;
    ttyb.sg_flags &= ~ECHO;
    (void) ioctl(input, TIOCSETP, &ttyb);
#endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */

    /* print the prompt & rewind */
    (void) write(output, prompt, strlen(prompt));

    /* setup for select(2) */
    FD_ZERO(&readfds);

    /* get the password */
    for (i=0; i < _PASSWD_LEN; i++) {
	/* do select */
	FD_SET(input, &readfds);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (select(getdtablesize(), &readfds, NULL, NULL, &tv) <= 0) {
	    i = 0;
	    break;
	}
	(void) read(input, &buf[i], 1);
	if (buf[i] == EOF || buf[i] == '\n')
	    break;
    }
    buf[i] = '\0';
    (void) write(output, "\n", 1);

     /* turn on echo */
#ifdef HAVE_TERMIOS_H
    term.c_lflag = svflagval;
    tcsetattr(input, TCSAFLUSH, &term);
#else
#ifdef HAVE_TERMIO_H
    term.c_lflag = svflagval;
    (void) ioctl(input, TCSETA, &term);
#else
    ttyb.sg_flags = svflagval;
    (void) ioctl(input, TIOCSETP, &ttyb);
#endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */

    /* restore old signal mask */
    (void) sigsetmask(oldmask);

    /* close /dev/tty if that's what we opened */
    if (input != fileno(stdin))
	(void) close(input);

    if (buf[0])
	return(buf);
    else
	return(NULL);
}
