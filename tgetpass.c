/*
 * Copyright (c) 1996, 1998, 1999 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * 4. Products derived from this software may not be called "Sudo" nor
 *    may "Sudo" appear in their names without specific prior written
 *    permission from the author.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
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
#include <sys/param.h>
#include <sys/types.h>
#ifdef HAVE_SYS_BSDTYPES_H
#include <sys/bsdtypes.h>
#endif /* HAVE_SYS_BSDTYPES_H */
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
#include <sys/time.h>
#include <errno.h>
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

#include "sudo.h"

#ifndef TCSASOFT
#define TCSASOFT	0
#endif /* TCSASOFT */

#ifndef O_NOCTTY
#define O_NOCTTY	0
#endif /* O_NOCTTY */

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */


/*
 * Like getpass(3) but with timeout and echo flags.
 */
char *
tgetpass(prompt, timeout, echo_off)
    const char *prompt;
    int timeout;
    int echo_off;
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
    int n, input, output;
    static char buf[SUDO_PASS_MAX + 1];
    fd_set *readfds;
    struct timeval tv;

    /* Open /dev/tty for reading/writing if possible else use stdin/stderr. */
    if ((input = output = open(_PATH_TTY, O_RDWR|O_NOCTTY)) == -1) {
	input = STDIN_FILENO;
	output = STDERR_FILENO;
    }

    if (prompt)
	(void) write(output, prompt, strlen(prompt) + 1);

    if (echo_off) {
#ifdef HAVE_TERMIOS_H
	(void) tcgetattr(input, &term);
	if ((echo_off = (term.c_lflag & ECHO))) {
	    term.c_lflag &= ~ECHO;
	    (void) tcsetattr(input, TCSAFLUSH|TCSASOFT, &term);
	}
#else
#ifdef HAVE_TERMIO_H
	(void) ioctl(input, TCGETA, &term);
	if ((echo_off = (term.c_lflag & ECHO))) {
	    term.c_lflag &= ~ECHO;
	    (void) ioctl(input, TCSETA, &term);
	}
#else
	(void) ioctl(input, TIOCGETP, &ttyb);
	if ((echo_off = (ttyb.sg_flags & ECHO))) {
	    ttyb.sg_flags &= ~ECHO;
	    (void) ioctl(input, TIOCSETP, &ttyb);
	}
#endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */
    }

    /*
     * Timeout of <= 0 means no timeout.
     */
    if (timeout > 0) {
	/* setup for select(2) */
	n = howmany(input + 1, NFDBITS) * sizeof(fd_mask);
	readfds = (fd_set *) emalloc(n);
	(void) memset((VOID *)readfds, 0, n);
	FD_SET(input, readfds);

	/* set timeout for select */
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	/*
	 * Get password or return empty string if nothing to read by timeout
	 */
	buf[0] = '\0';
	while ((n = select(input + 1, readfds, 0, 0, &tv)) == -1 &&
	    errno == EINTR)
	    ;
	if (n != 0 && (n = read(input, buf, sizeof(buf) - 1)) > 0) {
	    if (buf[n - 1] == '\n')
		n--;
	    buf[n] = '\0';
	}
	free(readfds);
    } else {
	buf[0] = '\0';
	if ((n = read(input, buf, sizeof(buf) - 1)) > 0) {
	    if (buf[n - 1] == '\n')
		n--;
	    buf[n] = '\0';
	}
    }

#ifdef HAVE_TERMIOS_H
    if (echo_off) {
	term.c_lflag |= ECHO;
	(void) tcsetattr(input, TCSAFLUSH|TCSASOFT, &term);
    }
#else
#ifdef HAVE_TERMIO_H
    if (echo_off) {
	term.c_lflag |= ECHO;
	(void) ioctl(input, TCSETA, &term);
    }
#else
    if (echo_off) {
	ttyb.sg_flags |= ECHO;
	(void) ioctl(input, TIOCSETP, &ttyb);
    }
#endif /* HAVE_TERMIO_H */
#endif /* HAVE_TERMIOS_H */

    if (echo_off)
	(void) write(output, "\n", 1);

    if (input != STDIN_FILENO)
	(void) close(input);

    return(buf);
}
