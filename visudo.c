/*
 * CU sudo version 1.3.1 (based on Root Group sudo version 1.1)
 *
 * This software comes with no waranty whatsoever, use at your own risk.
 *
 * Please send bugs, changes, problems to sudo-bugs@cs.colorado.edu
 *
 */

/*
 *  sudo version 1.1 allows users to execute commands as root
 *  Copyright (C) 1991  The Root Group, Inc.
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
 **************************************************************************
 * visudo.c, sudo project
 * David R. Hieb
 * March 18, 1991
 *
 * edit, lock and parse the sudoers file in a fashion similiar to /etc/vipw.
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"

#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <netinet/in.h>

#include "sudo.h"
#include "options.h"
#include "version.h"

#ifndef STDC_HEADERS
extern char *getenv	__P((const char *));
#endif /* !STDC_HEADERS */

extern FILE *yyin, *yyout;
extern int errno, sudolineno;

#ifndef SA_RESETHAND
#define SA_RESETHAND	0
#endif /* SA_RESETHAND */

/*
 * Globals
 */
char **Argv;
char buffer[BUFSIZ];
char *sudoers = _PATH_SUDO_SUDOERS;
char *sudoers_tmp_file = _PATH_SUDO_STMP;
int  status = 0,
     err_line_no = 0,
     parse_error = 0;

char host[] = "";
char *user = "";
char *cmnd = "";


/*
 * local functions not visible outside visudo.c
 */
static void usage	__P((void));
static RETSIGTYPE Exit	__P((int));


/* dummy *_matches routines */
int
path_matches(cmnd, path)
char *cmnd, *path;
{
    return(TRUE);
}

int
ntwk_matches(n)
char *n;
{
    return(TRUE);
}


main(argc, argv)
    int argc;
    char **argv;
{
    int sudoers_fd;
    int sudoers_tmp_fd;
    FILE *sudoers_tmp_fp;
    int num_chars;
    struct stat sbuf;
    struct passwd *sudoers_pw;
    char * Editor = EDITOR;
#ifdef POSIX_SIGNALS
    struct sigaction action;
#endif /* POSIX_SIGNALS */

    Argv = argv;

    if (argc > 1) {
	/*
	 * print version string and exit if we got -V
	 */
	if (!strcmp(Argv[1], "-V")) {
	    (void) printf("visudo version %s\n", version);
	    exit(0);
	} else {
	    usage();
	}

    }

    /*
     * handle the signals
     */
#ifdef POSIX_SIGNALS
    (void) bzero((char *)(&action), sizeof(action));
    action.sa_handler = Exit;
    action.sa_flags = SA_RESETHAND;
    (void) sigaction(SIGILL, &action, NULL);
    (void) sigaction(SIGTRAP, &action, NULL);
    (void) sigaction(SIGBUS, &action, NULL);
    (void) sigaction(SIGSEGV, &action, NULL);
    (void) sigaction(SIGTERM, &action, NULL);

    action.sa_handler = SIG_IGN;
    action.sa_flags = 0;
    (void) sigaction(SIGHUP, &action, NULL);
    (void) sigaction(SIGINT, &action, NULL);
    (void) sigaction(SIGQUIT, &action, NULL);
#else
    (void) signal(SIGILL, Exit);
    (void) signal(SIGTRAP, Exit);
    (void) signal(SIGBUS, Exit);
    (void) signal(SIGSEGV, Exit);
    (void) signal(SIGTERM, Exit);

    (void) signal(SIGHUP, SIG_IGN);
    (void) signal(SIGINT, SIG_IGN);
    (void) signal(SIGQUIT, SIG_IGN);
#endif /* POSIX_SIGNALS */

    /*
     * need to lookup passwd entry for sudoers file owner
     */
    if (!(sudoers_pw = getpwnam(SUDOERS_OWNER))) {
	(void) fprintf(stderr,
                       "%s:  no passwd entry for sudoers file owner (%s)\n",
		       Argv[0], SUDOERS_OWNER);
	exit(1);
    }

    setbuf(stderr, NULL);

    /*
     * we only want SUDOERS_OWNER to be able to read/write the sudoers_tmp_file
     */
    umask(077);

#ifdef ENV_EDITOR
    /*
     * set up the Editor variable correctly
     */
    if ( (Editor = getenv("EDITOR")) == NULL)
	if ( (Editor = getenv("VISUAL")) == NULL )
	    Editor = EDITOR;
#endif /* ENV_EDITOR */

    /*
     * open the sudoers file read only
     */
    if ((sudoers_fd = open(sudoers, O_RDONLY)) < 0) {
	(void) fprintf(stderr, "%s: ", Argv[0]);
	perror(sudoers);
	Exit(0);
    }

    /*
     * open the temporary sudoers file with the correct flags
     */
    if ((sudoers_tmp_fd = open(sudoers_tmp_file, O_WRONLY | O_CREAT | O_EXCL,
        0600)) < 0) {
	if (errno == EEXIST) {
	    (void) fprintf(stderr, "%s: sudoers file busy\n", Argv[0]);
	    exit(1);
	}
	(void) fprintf(stderr, "%s: ", Argv[0]);
	perror(sudoers_tmp_file);
	exit(1);
    }

    /*
     * transfer the contents of the sudoers file to the temporary sudoers file
     */
    while ((num_chars = read(sudoers_fd, buffer, sizeof(buffer))) > 0)
	(void) write(sudoers_tmp_fd, buffer, num_chars);

    (void) close(sudoers_fd);
    (void) close(sudoers_tmp_fd);

    /*
     * make sudoers_tmp_file owned by SUDOERS_OWNER so sudo(8) can read it.
     */
    (void) chown(sudoers_tmp_file, sudoers_pw -> pw_uid, -1);

    do {
	/*
	 * build strings in buffer to be executed by system()
	 */
	if (err_line_no)
	    (void) sprintf(buffer, "%s +%d %s", Editor, err_line_no,
		sudoers_tmp_file);
	else
	    (void) sprintf(buffer, "%s %s", Editor, sudoers_tmp_file);

	/* edit the file */
	if (system(buffer) == 0) {

	    /* can't stat file */
	    if (stat(sudoers_tmp_file, &sbuf) < 0) {
		(void) fprintf(stderr,
		    "%s: can't stat temporary file, %s unchanged\n", sudoers,
		    Argv[0]);
		Exit(0);
	    }

	    /* file has size == 0 */
	    if (sbuf.st_size == 0) {
		(void) fprintf(stderr, "%s: bad temporary file, %s unchanged\n",
                               sudoers, Argv[0]);
		Exit(0);
	    }

	    /* re-open the sudoers file for parsing */
	    if ((sudoers_tmp_fp = fopen(sudoers_tmp_file, "r")) == NULL) {
		(void) fprintf(stderr,
		    "%s: can't re-open temporary file, %s unchanged\n",
		    sudoers, Argv[0]);
		Exit(0);
	    }

#ifdef YY_NEW_FILE
	    /* XXX - this should not be necesary */
	    YY_NEW_FILE
#endif /* YY_NEW_FILE */
	    yyin = sudoers_tmp_fp;
	    yyout = stdout;

	    /* parse the file */
	    if (yyparse()) {
		(void) fprintf(stderr, "yyparse() failed\n");
		Exit(0);
	    }

	    /*
	     * the first time we get an error, set status to sudolineno which
	     * will be the line number after the line with the error. then,
	     * if we have gotten an error, set err_line_no to the correct
	     * line so that when we edit the file err_line_no will be
	     * correct. at this time we also reset status and sudolineno to
	     * their default values so that the next time yyparse() is
	     * called, they will be initialized correctly. 
	     */
	    err_line_no = (status == 0) ? 0 : status - 1;
	    status = 0;
	    sudolineno = 0;

	    (void) fclose(sudoers_tmp_fp);
	}
    } while (err_line_no);

    /*
     * Once the temporary sudoers file is gramatically correct, we can 
     * rename it to the real sudoers file.  If the rename(2) fails
     * we try using mv(1) in case the temp and sudoers files are on
     * different filesystems.
     */
    if (rename(sudoers_tmp_file, sudoers) != 0) {
	int status, len;
	char *tmpbuf;

	/* Print a warning/error */
	(void) fprintf(stderr, "%s: ", Argv[0]);
	perror("rename");

	/* Allocate just enough space for tmpbuf */
	len = sizeof(char) * (strlen(_PATH_MV) + strlen(sudoers_tmp_file) +
	    strlen(sudoers) + 4);
	if ((tmpbuf = (char *) malloc(len)) == NULL) {
	    (void) fprintf(stderr, "%s: cannot allocate memory: ", Argv[0]);
	    perror("");
	    Exit(0);
	}

	(void) sprintf(tmpbuf, "%s %s %s", _PATH_MV, sudoers_tmp_file, sudoers);
	status = system(tmpbuf);
	status = status >> 8;
	if (status) {
	    (void) fprintf(stderr, "Command failed: '%s', %s unchanged.\n",
		tmpbuf, sudoers);
	    Exit(0);
	} else {
	    (void) fprintf(stderr, "Used '%s' instead.\n", tmpbuf);
	}
	(void) free(tmpbuf);
    }

    /*
     * The chmod is a non-fatal error.
     */
    if (chmod(sudoers, 0400) != 0) {
	(void) fprintf(stderr, "%s: Warning, unable to chmod 0400 %s: ",
	    Argv[0], sudoers);
	perror("");
    }

    exit(0);
}


/**********************************************************************
 *
 * usage()
 *
 *  this function just gives you instructions and exits
 */

static void usage()
{
    (void) fprintf(stderr, "usage: %s [-V]\n", Argv[0]);
    exit(1);
}


/**********************************************************************
 *
 * Exit()
 *
 *  this function cleans up and exits
 */

static RETSIGTYPE Exit(sig)
    int sig;
{
    (void) unlink(sudoers_tmp_file);
    exit(1);
}
