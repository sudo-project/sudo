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
    FILE *input, *output;
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
    char c;

    /*
     * mask out SIGINT
     */
    oldmask = sigblock(sigmask(SIGINT));

    /*
     * open /dev/tty for reading/writing if possible or use
     * stdin and stderr instead.
     */
    input = fopen(_PATH_TTY, "r+");
    if (!input) {
	input = stdin;
	output = stderr;
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

    /* print the prompt & rewind */
    (void) fputs(prompt, output);
    (void) fflush(output);
    (void) rewind(output);

    /* setup for select(2) */
    FD_ZERO(&readfds);

    /* get the password */
    buf[0] = NULL;
#if 0
    fgets(buf, sizeof(buf), input);
    buf[sizeof(buf) -1 ] = '\0';
#else
    for (i=0; i < _PASSWD_LEN; i++) {
	/* do select */
	FD_SET(fileno(input), &readfds);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (select(getdtablesize(), &readfds, NULL, NULL, &tv) <= 0) {
	    i = 0;
	    break;
	}
	c = fgetc(input);
	if (c == EOF || c == '\n')
	    break;
	buf[i] = c;
    }
    buf[i] = '\0';
#endif

     /* turn on echo */
#ifdef HAVE_TERMIOS_H
    term.c_lflag = svflagval;
    tcsetattr(fileno(input), TCSAFLUSH, &term);
#else
#ifdef HAVE_TERMIO_H
    term.c_lflag = svflagval;
    (void) ioctl(fileno(fp), TCSETA, &term);
#else
    ttyb.sg_flags = svflagval;
    (void) ioctl(fileno(fp), TIOCSETP, &ttyb);
#endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */

    /* restore old signal mask */
    (void) sigsetmask(oldmask);

    /* close /dev/tty if that's what we opened */
    if (input != stdin)
	(void) fclose(input);

    if (buf[0])
	return(buf);
    else
	/* XXX - set errno? */
	return(NULL);
}
