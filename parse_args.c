/*
 * Copyright (c) 1993-1996, 1998-2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <grp.h>

#include "sudo.h"
#include "lbuf.h"
#include <sudo_usage.h>

/*
 * Local functions
 */
static void usage_excl			__P((int))
					    __attribute__((__noreturn__));

/*
 * For sudo.c
 */
extern int NewArgc;
extern char **NewArgv;
extern int user_closefrom;
extern char *runas_user;
extern char *runas_group;

/* For getopt(3) */
extern char *optarg;
extern int optind;

#ifdef HAVE_BSD_AUTH_H
char *login_style;
#endif /* HAVE_BSD_AUTH_H */

/*
 * Command line argument parsing.
 * Sets NewArgc and NewArgv which corresponds to the argc/argv we'll use
 * for the command to be run (if we are running one).
 */
int
parse_args(argc, argv)
    int argc;
    char **argv;
{
    int mode = 0;		/* what mode is sudo to be run in? */
    int flags = 0;		/* mode flags */
    int valid_flags, ch;

    /* First, check to see if we were invoked as "sudoedit". */
    if (strcmp(getprogname(), "sudoedit") == 0)
	mode = MODE_EDIT;

    /* Returns true if the last option string was "--" */
#define got_end_of_args	(optind > 1 && argv[optind - 1][0] == '-' && \
	    argv[optind - 1][1] == '-' && argv[optind - 1][2] == '\0')

    /* Returns true if next option is an environment variable */
#define is_envar (optind < argc && argv[optind][0] != '/' && \
	    strchr(argv[optind], '=') != NULL)

    /* Flags allowed when running a command */
    valid_flags = MODE_BACKGROUND|MODE_PRESERVE_ENV|MODE_RESET_HOME|
		  MODE_LOGIN_SHELL|MODE_INVALIDATE|MODE_NONINTERACTIVE|
		  MODE_PRESERVE_GROUPS|MODE_SHELL;
    for (;;) {
	/*
	 * We disable arg permutation for GNU getopt().
	 * Some trickiness is required to allow environment variables
	 * to be interspersed with command line options.
	 */
	if ((ch = getopt(argc, argv, "+Aa:bC:c:Eeg:HhiKkLlnPp:r:Sst:U:u:Vv")) != -1) {
	    switch (ch) {
		case 'A':
		    SET(tgetpass_flags, TGP_ASKPASS);
		    break;
#ifdef HAVE_BSD_AUTH_H
		case 'a':
		    login_style = optarg;
		    break;
#endif
		case 'b':
		    SET(flags, MODE_BACKGROUND);
		    break;
		case 'C':
		    if ((user_closefrom = atoi(optarg)) < 3) {
			warningx("the argument to -C must be at least 3");
			usage(1);
		    }
		    break;
#ifdef HAVE_LOGIN_CAP_H
		case 'c':
		    login_class = optarg;
		    def_use_loginclass = TRUE;
		    break;
#endif
		case 'E':
		    SET(flags, MODE_PRESERVE_ENV);
		    break;
		case 'e':
		    if (mode && mode != MODE_EDIT)
			usage_excl(1);
		    mode = MODE_EDIT;
		    valid_flags = MODE_INVALIDATE|MODE_NONINTERACTIVE;
		    break;
		case 'g':
		    runas_group = optarg;
		    break;
		case 'H':
		    SET(flags, MODE_RESET_HOME);
		    break;
		case 'h':
		    if (mode && mode != MODE_HELP) {
			if (strcmp(getprogname(), "sudoedit") != 0)
			    usage_excl(1);
		    }
		    mode = MODE_HELP;
		    valid_flags = 0;
		    break;
		case 'i':
		    SET(flags, MODE_LOGIN_SHELL);
		    def_env_reset = TRUE;
		    break;
		case 'k':
		    SET(flags, MODE_INVALIDATE);
		    break;
		case 'K':
		    if (mode && mode != MODE_KILL)
			usage_excl(1);
		    mode = MODE_KILL;
		    valid_flags = 0;
		    break;
		case 'L':
		    if (mode && mode != MODE_LISTDEFS)
			usage_excl(1);
		    mode = MODE_LISTDEFS;
		    valid_flags = MODE_INVALIDATE|MODE_NONINTERACTIVE;
		    break;
		case 'l':
		    if (mode) {
			if (mode == MODE_LIST)
			    long_list = 1;
			else
			    usage_excl(1);
		    }
		    mode = MODE_LIST;
		    valid_flags = MODE_INVALIDATE|MODE_NONINTERACTIVE;
		    break;
		case 'n':
		    SET(flags, MODE_NONINTERACTIVE);
		    break;
		case 'P':
		    SET(flags, MODE_PRESERVE_GROUPS);
		    break;
		case 'p':
		    user_prompt = optarg;
		    def_passprompt_override = TRUE;
		    break;
#ifdef HAVE_SELINUX
		case 'r':
		    user_role = optarg;
		    break;
		case 't':
		    user_type = optarg;
		    break;
#endif
		case 'S':
		    SET(tgetpass_flags, TGP_STDIN);
		    break;
		case 's':
		    SET(flags, MODE_SHELL);
		    break;
		case 'U':
		    if ((list_pw = sudo_getpwnam(optarg)) == NULL)
			errorx(1, "unknown user: %s", optarg);
		    break;
		case 'u':
		    runas_user = optarg;
		    break;
		case 'v':
		    if (mode && mode != MODE_VALIDATE)
			usage_excl(1);
		    mode = MODE_VALIDATE;
		    valid_flags = MODE_INVALIDATE|MODE_NONINTERACTIVE;
		    break;
		case 'V':
		    if (mode && mode != MODE_VERSION)
			usage_excl(1);
		    mode = MODE_VERSION;
		    valid_flags = 0;
		    break;
		default:
		    usage(1);
	    }
	} else if (!got_end_of_args && is_envar) {
	    struct list_member *ev;

	    /* Store environment variable. */
	    ev = emalloc(sizeof(*ev));
	    ev->value = argv[optind];
	    ev->next = sudo_user.env_vars;
	    sudo_user.env_vars = ev;

	    /* Crank optind and resume getopt. */
	    optind++;
	} else {
	    /* Not an option or an environment variable -- we're done. */
	    break;
	}
    }

    NewArgc = argc - optind;
    NewArgv = argv + optind;

    if (!mode) {
	/* Defer -k mode setting until we know whether it is a flag or not */
	if (ISSET(flags, MODE_INVALIDATE) && NewArgc == 0) {
	    mode = MODE_INVALIDATE;	/* -k by itself */
	    CLR(flags, MODE_INVALIDATE);
	    valid_flags = 0;
	} else {
	    mode = MODE_RUN;		/* running a command */
	}
    }

    if (NewArgc > 0 && mode == MODE_LIST)
	mode = MODE_CHECK;

    if (ISSET(flags, MODE_LOGIN_SHELL)) {
	if (ISSET(flags, MODE_SHELL)) {
	    warningx("you may not specify both the `-i' and `-s' options");
	    usage(1);
	}
	if (ISSET(flags, MODE_PRESERVE_ENV)) {
	    warningx("you may not specify both the `-i' and `-E' options");
	    usage(1);
	}
	SET(flags, MODE_SHELL);
    }
    if ((flags & valid_flags) != flags)
	usage(1);
    if (mode == MODE_EDIT &&
       (ISSET(flags, MODE_PRESERVE_ENV) || sudo_user.env_vars != NULL)) {
	if (ISSET(mode, MODE_PRESERVE_ENV))
	    warningx("the `-E' option is not valid in edit mode");
	if (sudo_user.env_vars != NULL)
	    warningx("you may not specify environment variables in edit mode");
	usage(1);
    }
    if ((runas_user != NULL || runas_group != NULL) &&
	!ISSET(mode, MODE_EDIT | MODE_RUN | MODE_CHECK | MODE_VALIDATE)) {
	usage(1);
    }
    if (list_pw != NULL && mode != MODE_LIST && mode != MODE_CHECK) {
	warningx("the `-U' option may only be used with the `-l' option");
	usage(1);
    }
    if (ISSET(tgetpass_flags, TGP_STDIN) && ISSET(tgetpass_flags, TGP_ASKPASS)) {
	warningx("the `-A' and `-S' options may not be used together");
	usage(1);
    }
    if ((NewArgc == 0 && mode == MODE_EDIT) ||
	(NewArgc > 0 && !ISSET(mode, MODE_RUN | MODE_EDIT | MODE_CHECK)))
	usage(1);
    if (NewArgc == 0 && mode == MODE_RUN && !ISSET(flags, MODE_SHELL))
	SET(flags, (MODE_IMPLIED_SHELL | MODE_SHELL));

    return(mode | flags);
}

static int
usage_out(buf)
    const char *buf;
{
    return fputs(buf, stderr);
}

/*
 * Give usage message and exit.
 * The actual usage strings are in sudo_usage.h for configure substitution.
 */
void
usage(exit_val)
    int exit_val;
{
    struct lbuf lbuf;
    char *uvec[6];
    int i, ulen;

    /*
     * Use usage vectors appropriate to the progname.
     */
    if (strcmp(getprogname(), "sudoedit") == 0) {
	uvec[0] = SUDO_USAGE5 + 3;
	uvec[1] = NULL;
    } else {
	uvec[0] = SUDO_USAGE1;
	uvec[1] = SUDO_USAGE2;
	uvec[2] = SUDO_USAGE3;
	uvec[3] = SUDO_USAGE4;
	uvec[4] = SUDO_USAGE5;
	uvec[5] = NULL;
    }

    /*
     * Print usage and wrap lines as needed, depending on the
     * tty width.
     */
    ulen = (int)strlen(getprogname()) + 8;
    lbuf_init(&lbuf, usage_out, ulen, NULL);
    for (i = 0; uvec[i] != NULL; i++) {
	lbuf_append(&lbuf, "usage: ", getprogname(), uvec[i], NULL);
	lbuf_print(&lbuf);
    }
    lbuf_destroy(&lbuf);
    exit(exit_val);
}

/*
 * Tell which options are mutually exclusive and exit.
 */
static void
usage_excl(exit_val)
    int exit_val;
{
    warningx("Only one of the -e, -h, -i, -K, -l, -s, -v or -V options may be specified");
    usage(exit_val);
}
