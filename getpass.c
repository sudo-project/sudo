#ifdef BROKEN_GETPASS
/*
 * Copyright (c) 1988 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * This version of getpass() is known to work under Ultrix 4.2/4.3, 4.3 BSD,
 * HP-UX 8.07, AIX 3.1/3.2, and Iirix 4.05F.  It should be easy to change it
 * to suit your tty interface.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)getpass.c	based on 5.3 (Berkeley) 9/22/88";
#endif /* LIBC_SCCS and not lint */

#include <fcntl.h>
#include <sgtty.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <stdio.h>

char *
getpass(prompt)
	char *prompt;
{
#if defined(sgi)
	struct termio ttyb;
#else
	struct sgttyb ttyb;
#endif
	register int ch;
	register char *p;
	FILE *fp, *outfp;
	long omask;
	int fd_tmp;
#if defined(sgi)
	tcflag_t svflagval;
#else
	int svflagval;
#endif
#define	PASSWD_LEN	8
	static char buf[PASSWD_LEN + 1];

	/*
	 * read and write to /dev/tty if possible; else read from
	 * stdin and write to stderr.
	 */
	fd_tmp = open("/dev/tty", O_RDWR);
	if (fd_tmp < 0 || (outfp = fp = fdopen(fd_tmp, "r+")) == NULL) {
		outfp = stderr;
		fp = stdin;
	}

#if defined(sgi)
	(void)ioctl(fileno(fp), TCGETA, &ttyb);
	svflagval = ttyb.c_lflag;
	ttyb.c_lflag &= ~ECHO;
	omask = sigblock(sigmask(SIGINT));
	(void)ioctl(fileno(fp), TCSETA, &ttyb);
#else
	(void)ioctl(fileno(fp), TIOCGETP, &ttyb);
	svflagval = ttyb.sg_flags;
	ttyb.sg_flags &= ~ECHO;
	omask = sigblock(sigmask(SIGINT));
	(void)ioctl(fileno(fp), TIOCSETP, &ttyb);
#endif

	fprintf(outfp, "%s", prompt);
	rewind(outfp);			/* implied flush */
	for (p = buf; (ch = getc(fp)) != EOF && ch != '\n';)
		if (p < buf + PASSWD_LEN)
			*p++ = ch;
	*p = '\0';
	(void)write(fileno(outfp), "\n", 1);

#if defined(sgi)
	ttyb.c_lflag = svflagval;
	(void)ioctl(fileno(fp), TCSETA, &ttyb);
#else
	ttyb.sg_flags = svflagval;
	(void)ioctl(fileno(fp), TIOCSETP, &ttyb);
#endif
	(void)sigsetmask(omask);
	if (fp != stdin)
		(void)fclose(fp);
	return(buf);
}
#endif
