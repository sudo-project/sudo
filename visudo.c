/*
 * CU sudo version 1.3 (based on Root Group sudo version 1.1)
 *
 * This software comes with no waranty whatsoever, use at your own risk.
 *
 * Please send bugs, changes, problems to sudo-bugs.cs.colorado.edu
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <errno.h>
#include <signal.h>

#include "sudo.h"

#ifndef STDC_HEADERS
extern char *getenv();
#endif /* !STDC_HEADERS */

extern FILE *yyin, *yyout;
extern int errno, yylineno;

char buffer[BUFSIZ];
char *sudoers = SUDOERS;
int status = 0, err_line_no = 0;
char *sudoers_tmp_file = TMPSUDOERS;
FILE *sudoers_tmp_fp=NULL, *sudoers_fp=NULL;

RETSIGTYPE Exit()
{
    if (sudoers_tmp_fp)
	(void) fclose(sudoers_tmp_fp);

    (void) unlink(sudoers_tmp_file);
    exit(1);
}


main(argc, argv)
    int argc;
    char **argv;
{
    int fd;
    struct stat sbuf;
#ifdef ENV_EDITOR
    char * Editor;
#endif /* ENV_EDITOR */

    /*
     * handle the signals
     */
    (void) signal(SIGILL, Exit);
    (void) signal(SIGTRAP, Exit);
    (void) signal(SIGBUS, Exit);
    (void) signal(SIGSEGV, Exit);
    (void) signal(SIGTERM, Exit);

    (void) signal(SIGHUP, SIG_IGN);
    (void) signal(SIGINT, SIG_IGN);
    (void) signal(SIGQUIT, SIG_IGN);

    setbuf(stderr, NULL);

    /*
     * we only want root to be able to read/write the sudoers_tmp_file
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
    if ((sudoers_fp = fopen(sudoers, "r")) == NULL) {
	(void) fprintf(stderr, "%s: ", *argv);
	perror(sudoers);
	Exit();
    }

    /*
     * open the temporary sudoers file with the correct flags
     */
    if ((fd = open(sudoers_tmp_file, O_WRONLY | O_CREAT | O_EXCL, 0600)) < 0) {
	if (errno == EEXIST) {
	    (void) fprintf(stderr, "%s: sudoers file busy\n", *argv);
	    exit(1);
	}
	(void) fprintf(stderr, "%s: ", *argv);
	perror(sudoers_tmp_file);
	exit(1);
    }

    /*
     * get a STREAM file pointer to the temporary sudoers file
     */
    if ((sudoers_tmp_fp = fdopen(fd, "w")) == NULL) {
	(void) fprintf(stderr, "%s: ", *argv);
	perror(sudoers_tmp_file);
	Exit();
    }

    /*
     * transfer the contents of the sudoers file to the temporary sudoers file
     */
    while (fgets(buffer, sizeof(buffer) - 1, sudoers_fp) != NULL) {
	fputs(buffer, sudoers_tmp_fp);
    }

    (void) fclose(sudoers_fp);
    (void) fclose(sudoers_tmp_fp);

    do {
	/*
	 * build strings in buffer to be executed by system()
	 */
#ifdef ENV_EDITOR
	(void) sprintf(buffer, "%s +%d %s", Editor, err_line_no,
	    sudoers_tmp_file);
#else
	(void) sprintf(buffer, "%s +%d %s", EDITOR, err_line_no,
	    sudoers_tmp_file);
#endif /* ENV_EDITOR */

	/* edit the file */
	if (system(buffer) == 0) {

	    /* can't stat file */
	    if (stat(sudoers_tmp_file, &sbuf) < 0) {
		(void) fprintf(stderr, "%s: can't stat temporary file, %s unchanged\n",
			sudoers, *argv);
		Exit();
	    }

	    /* file has size == 0 */
	    if (sbuf.st_size == 0) {
		(void) fprintf(stderr, "%s: bad temporary file, %s unchanged\n",
			sudoers, *argv);
		Exit();
	    }

	    /* re-open the sudoers file for parsing */
	    if ((sudoers_tmp_fp = fopen(sudoers_tmp_file, "r")) == NULL) {
		(void) fprintf(stderr, "%s: can't re-open temporary file, %s unchanged\n",
			sudoers, *argv);
		Exit();
	    }
	    yyin = sudoers_tmp_fp;
	    yyout = stdout;

	    /* parse the file */
	    if (yyparse()) {
		(void) fprintf(stderr, "yyparse() failed\n");
		Exit();
	    }

	    /*
	     * the first time we get an error, set status to yylineno which
	     * will be the line number after the line with the error. then,
	     * if we have gotten an error, set err_line_no to the correct
	     * line so that when we edit the file err_line_no will be
	     * correct. at this time we also reset status and yylineno to
	     * their default values so that the next time yyparse() is
	     * called, they will be initialized correctly. 
	     */
	    err_line_no = (status == 0) ? 0 : status - 1;
	    status = 0;
	    yylineno = 1;

	    (void) fclose(sudoers_tmp_fp);
	}
    } while (err_line_no);

    /*
     * once the temporary sudoers file is gramatically correct, we can 
     * rename it to the real sudoers file.
     */
    if (rename(sudoers_tmp_file, sudoers) != 0) {
	(void) fprintf(stderr, "%s: ", *argv);
	perror("rename");
    } else {
	if (chmod(sudoers, 0400) != 0)
	    perror("chmod: failed");
	exit(0);
    }
}
