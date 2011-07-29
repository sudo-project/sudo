/*
 * Copyright (c) 1993-1996, 1998-2011 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <ctype.h>
#include <grp.h>
#include <pwd.h>

#include <sudo_usage.h>
#include "sudo.h"
#include "lbuf.h"

/* For getopt(3) */
extern char *optarg;
extern int optind;

int tgetpass_flags;

/*
 * Local functions.
 */
static void help(void) __attribute__((__noreturn__));
static void usage_excl(int);

/*
 * Mapping of command line flags to name/value settings.
 */
static struct sudo_settings {
    const char *name;
    const char *value;
} sudo_settings[] = {
#define ARG_BSDAUTH_TYPE 0
    { "bsdauth_type" },
#define ARG_LOGIN_CLASS 1
    { "login_class" },
#define ARG_DEBUG_LEVEL 2
    { "debug_level" },
#define ARG_PRESERVE_ENVIRONMENT 3
    { "preserve_environment" },
#define ARG_RUNAS_GROUP 4
    { "runas_group" },
#define ARG_SET_HOME 5
    { "set_home" },
#define ARG_USER_SHELL 6
    { "run_shell" },
#define ARG_LOGIN_SHELL 7
    { "login_shell" },
#define ARG_IGNORE_TICKET 8
    { "ignore_ticket" },
#define ARG_PROMPT 9
    { "prompt" },
#define ARG_SELINUX_ROLE 10
    { "selinux_role" },
#define ARG_SELINUX_TYPE 11
    { "selinux_type" },
#define ARG_RUNAS_USER 12
    { "runas_user" },
#define ARG_PROGNAME 13
    { "progname" },
#define ARG_IMPLIED_SHELL 14
    { "implied_shell" },
#define ARG_PRESERVE_GROUPS 15
    { "preserve_groups" },
#define ARG_NONINTERACTIVE 16
    { "noninteractive" },
#define ARG_SUDOEDIT 17
    { "sudoedit" },
#define ARG_CLOSEFROM 18
    { "closefrom" },
#define ARG_NET_ADDRS 19
    { "network_addrs" },
#define NUM_SETTINGS 20
    { NULL }
};

/*
 * Command line argument parsing.
 * Sets nargc and nargv which corresponds to the argc/argv we'll use
 * for the command to be run (if we are running one).
 */
int
parse_args(int argc, char **argv, int *nargc, char ***nargv, char ***settingsp,
    char ***env_addp)
{
    int mode = 0;		/* what mode is sudo to be run in? */
    int flags = 0;		/* mode flags */
    int valid_flags, ch;
    int i, j;
    char *cp, **env_add, **settings;
    int nenv = 0;
    int env_size = 32;

    env_add = emalloc2(env_size, sizeof(char *));

    /* Pass progname to plugin so it can call setprogname() */
    sudo_settings[ARG_PROGNAME].value = getprogname();

    /* First, check to see if we were invoked as "sudoedit". */
    if (strcmp(getprogname(), "sudoedit") == 0) {
	mode = MODE_EDIT;
	sudo_settings[ARG_SUDOEDIT].value = "true";
    }

    /* Load local IP addresses and masks. */
    if (get_net_ifs(&cp) > 0)
	sudo_settings[ARG_NET_ADDRS].value = cp;

    /* Returns true if the last option string was "--" */
#define got_end_of_args	(optind > 1 && argv[optind - 1][0] == '-' && \
	    argv[optind - 1][1] == '-' && argv[optind - 1][2] == '\0')

    /* Returns true if next option is an environment variable */
#define is_envar (optind < argc && argv[optind][0] != '/' && \
	    strchr(argv[optind], '=') != NULL)

    /* Flags allowed when running a command */
    valid_flags = MODE_BACKGROUND|MODE_PRESERVE_ENV|MODE_RESET_HOME|
		  MODE_LOGIN_SHELL|MODE_NONINTERACTIVE|MODE_SHELL;
    /* XXX - should fill in settings at the end to avoid dupes */
    for (;;) {
	/*
	 * We disable arg permutation for GNU getopt().
	 * Some trickiness is required to allow environment variables
	 * to be interspersed with command line options.
	 */
	if ((ch = getopt(argc, argv, "+Aa:bC:c:D:Eeg:HhiKklnPp:r:Sst:U:u:Vv")) != -1) {
	    switch (ch) {
		case 'A':
		    SET(tgetpass_flags, TGP_ASKPASS);
		    break;
#ifdef HAVE_BSD_AUTH_H
		case 'a':
		    sudo_settings[ARG_BSDAUTH_TYPE].value = optarg;
		    break;
#endif
		case 'b':
		    SET(flags, MODE_BACKGROUND);
		    break;
		case 'C':
		    if (atoi(optarg) < 3) {
			warningx(_("the argument to -C must be a number greater than or equal to 3"));
			usage(1);
		    }
		    sudo_settings[ARG_CLOSEFROM].value = optarg;
		    break;
#ifdef HAVE_LOGIN_CAP_H
		case 'c':
		    sudo_settings[ARG_LOGIN_CLASS].value = optarg;
		    break;
#endif
		case 'D':
		    if ((debug_level = atoi(optarg)) < 1 || debug_level > 9) {
			warningx(_("the argument to -D must be between 1 and 9 inclusive"));
			usage(1);
		    }
		    sudo_settings[ARG_DEBUG_LEVEL].value = optarg;
		    break;
		case 'E':
		    sudo_settings[ARG_PRESERVE_ENVIRONMENT].value = "true";
		    break;
		case 'e':
		    if (mode && mode != MODE_EDIT)
			usage_excl(1);
		    mode = MODE_EDIT;
		    sudo_settings[ARG_SUDOEDIT].value = "true";
		    valid_flags = MODE_NONINTERACTIVE;
		    break;
		case 'g':
		    runas_group = optarg;
		    sudo_settings[ARG_RUNAS_GROUP].value = optarg;
		    break;
		case 'H':
		    sudo_settings[ARG_SET_HOME].value = "true";
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
		    sudo_settings[ARG_LOGIN_SHELL].value = "true";
		    SET(flags, MODE_LOGIN_SHELL);
		    break;
		case 'k':
		    sudo_settings[ARG_IGNORE_TICKET].value = "true";
		    break;
		case 'K':
		    sudo_settings[ARG_IGNORE_TICKET].value = "true";
		    if (mode && mode != MODE_KILL)
			usage_excl(1);
		    mode = MODE_KILL;
		    valid_flags = 0;
		    break;
		case 'l':
		    if (mode) {
			if (mode == MODE_LIST)
			    SET(flags, MODE_LONG_LIST);
			else
			    usage_excl(1);
		    }
		    mode = MODE_LIST;
		    valid_flags = MODE_NONINTERACTIVE|MODE_LONG_LIST;
		    break;
		case 'n':
		    SET(flags, MODE_NONINTERACTIVE);
		    sudo_settings[ARG_NONINTERACTIVE].value = "true";
		    break;
		case 'P':
		    sudo_settings[ARG_PRESERVE_GROUPS].value = "true";
		    break;
		case 'p':
		    sudo_settings[ARG_PROMPT].value = optarg;
		    break;
#ifdef HAVE_SELINUX
		case 'r':
		    sudo_settings[ARG_SELINUX_ROLE].value = optarg;
		    break;
		case 't':
		    sudo_settings[ARG_SELINUX_TYPE].value = optarg;
		    break;
#endif
		case 'S':
		    SET(tgetpass_flags, TGP_STDIN);
		    break;
		case 's':
		    sudo_settings[ARG_USER_SHELL].value = "true";
		    SET(flags, MODE_SHELL);
		    break;
		case 'U':
		    if ((getpwnam(optarg)) == NULL)
			errorx(1, _("unknown user: %s"), optarg);
		    list_user = optarg;
		    break;
		case 'u':
		    runas_user = optarg;
		    sudo_settings[ARG_RUNAS_USER].value = optarg;
		    break;
		case 'v':
		    if (mode && mode != MODE_VALIDATE)
			usage_excl(1);
		    mode = MODE_VALIDATE;
		    valid_flags = MODE_NONINTERACTIVE;
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
	    if (nenv == env_size - 2) {
		env_size *= 2;
		env_add = erealloc3(env_add, env_size, sizeof(char *));
	    }
	    env_add[nenv++] = argv[optind];

	    /* Crank optind and resume getopt. */
	    optind++;
	} else {
	    /* Not an option or an environment variable -- we're done. */
	    break;
	}
    }
    env_add[nenv] = NULL;

    argc -= optind;
    argv += optind;

    if (!mode) {
	/* Defer -k mode setting until we know whether it is a flag or not */
	if (sudo_settings[ARG_IGNORE_TICKET].value != NULL) {
	    if (argc == 0) {
		mode = MODE_INVALIDATE;	/* -k by itself */
		sudo_settings[ARG_IGNORE_TICKET].value = NULL;
		valid_flags = 0;
	    }
	}
	if (!mode)
	    mode = MODE_RUN;		/* running a command */
    }

    if (argc > 0 && mode == MODE_LIST)
	mode = MODE_CHECK;

    if (ISSET(flags, MODE_LOGIN_SHELL)) {
	if (ISSET(flags, MODE_SHELL)) {
	    warningx(_("you may not specify both the `-i' and `-s' options"));
	    usage(1);
	}
	if (ISSET(flags, MODE_PRESERVE_ENV)) {
	    warningx(_("you may not specify both the `-i' and `-E' options"));
	    usage(1);
	}
	SET(flags, MODE_SHELL);
    }
    if ((flags & valid_flags) != flags)
	usage(1);
    if (mode == MODE_EDIT &&
       (ISSET(flags, MODE_PRESERVE_ENV) || env_add[0] != NULL)) {
	if (ISSET(mode, MODE_PRESERVE_ENV))
	    warningx(_("the `-E' option is not valid in edit mode"));
	if (env_add[0] != NULL)
	    warningx(_("you may not specify environment variables in edit mode"));
	usage(1);
    }
    if ((runas_user != NULL || runas_group != NULL) &&
	!ISSET(mode, MODE_EDIT | MODE_RUN | MODE_CHECK | MODE_VALIDATE)) {
	usage(1);
    }
    if (list_user != NULL && mode != MODE_LIST && mode != MODE_CHECK) {
	warningx(_("the `-U' option may only be used with the `-l' option"));
	usage(1);
    }
    if (ISSET(tgetpass_flags, TGP_STDIN) && ISSET(tgetpass_flags, TGP_ASKPASS)) {
	warningx(_("the `-A' and `-S' options may not be used together"));
	usage(1);
    }
    if ((argc == 0 && mode == MODE_EDIT) ||
	(argc > 0 && !ISSET(mode, MODE_RUN | MODE_EDIT | MODE_CHECK)))
	usage(1);
    if (argc == 0 && mode == MODE_RUN && !ISSET(flags, MODE_SHELL)) {
	SET(flags, (MODE_IMPLIED_SHELL | MODE_SHELL));
	sudo_settings[ARG_IMPLIED_SHELL].value = "true";
    }

    if (mode == MODE_HELP)
	help();

    /*
     * For shell mode we need to rewrite argv
     */
    if (ISSET(mode, MODE_RUN) && ISSET(flags, MODE_SHELL)) {
	char **av;
	int ac;

	if (argc == 0) {
	    /* just the shell */
	    ac = argc + 1;
	    av = emalloc2(ac + 1, sizeof(char *));
	    memcpy(av + 1, argv, argc * sizeof(char *));
	} else {
	    /* shell -c "command" */
	    char *cmnd, *src, *dst;
	    size_t cmnd_size = (size_t) (argv[argc - 1] - argv[0]) +
		strlen(argv[argc - 1]) + 1;

	    cmnd = dst = emalloc2(cmnd_size, 2);
	    for (av = argv; *av != NULL; av++) {
		for (src = *av; *src != '\0'; src++) {
		    /* quote potential meta characters */
		    if (!isalnum((unsigned char)*src) && *src != '_' && *src != '-')
			*dst++ = '\\';
		    *dst++ = *src;
		}
		*dst++ = ' ';
	    }
	    if (cmnd != dst)
		dst--;  /* replace last space with a NUL */
	    *dst = '\0';

	    ac = 3;
	    av = emalloc2(ac + 1, sizeof(char *));
	    av[1] = "-c";
	    av[2] = cmnd;
	}
	av[0] = (char *)user_details.shell; /* plugin may override shell */
	av[ac] = NULL;

	argv = av;
	argc = ac;
    }

    /*
     * Format setting_pairs into settings array.
     */
    settings = emalloc2(NUM_SETTINGS + 1, sizeof(char *));
    for (i = 0, j = 0; i < NUM_SETTINGS; i++) {
	if (sudo_settings[i].value) {
	    sudo_debug(9, "settings: %s=%s", sudo_settings[i].name,
		sudo_settings[i].value);
	    settings[j] = fmt_string(sudo_settings[i].name,
		sudo_settings[i].value);
	    if (settings[j] == NULL)
		errorx(1, _("unable to allocate memory"));
	    j++;
	}
    }
    settings[j] = NULL;

    if (mode == MODE_EDIT) {
#if defined(HAVE_SETRESUID) || defined(HAVE_SETREUID) || defined(HAVE_SETEUID)
	/* Must have the command in argv[0]. */
	argc++;
	argv--;
	argv[0] = "sudoedit";
#else
	errorx(1, _("sudoedit is not supported on this platform"));
#endif
    }

    *settingsp = settings;
    *env_addp = env_add;
    *nargc = argc;
    *nargv = argv;
    return mode | flags;
}

static int
usage_err(const char *buf)
{
    return fputs(buf, stderr);
}

static int
usage_out(const char *buf)
{
    return fputs(buf, stdout);
}

/*
 * Give usage message and exit.
 * The actual usage strings are in sudo_usage.h for configure substitution.
 */
void
usage(int fatal)
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
    lbuf_init(&lbuf, fatal ? usage_err : usage_out, ulen, NULL,
	user_details.ts_cols);
    for (i = 0; uvec[i] != NULL; i++) {
	lbuf_append(&lbuf, "usage: %s%s", getprogname(), uvec[i]);
	lbuf_print(&lbuf);
    }
    lbuf_destroy(&lbuf);
    if (fatal)
	exit(1);
}

/*
 * Tell which options are mutually exclusive and exit.
 */
static void
usage_excl(int fatal)
{
    warningx(_("Only one of the -e, -h, -i, -K, -l, -s, -v or -V options may be specified"));
    usage(fatal);
}

static void
help(void)
{
    struct lbuf lbuf;
    int indent = 16;
    const char *pname = getprogname();

    lbuf_init(&lbuf, usage_out, indent, NULL, user_details.ts_cols);
    if (strcmp(pname, "sudoedit") == 0)
	lbuf_append(&lbuf, _("%s - edit files as another user\n\n"), pname);
    else
	lbuf_append(&lbuf, _("%s - execute a command as another user\n\n"), pname);
    lbuf_print(&lbuf);

    usage(0);

    lbuf_append(&lbuf, _("\nOptions:\n"));
#ifdef HAVE_BSD_AUTH_H
    lbuf_append(&lbuf, "  -A            %s",
	_("use helper program for password prompting\n"));
#endif
    lbuf_append(&lbuf, "  -a type       %s",
	_("use specified BSD authentication type\n"));
    lbuf_append(&lbuf, "  -b            %s",
	_("run command in the background\n"));
    lbuf_append(&lbuf, "  -C fd         %s",
	_("close all file descriptors >= fd\n"));
#ifdef HAVE_LOGIN_CAP_H
    lbuf_append(&lbuf, "  -c class      %s",
	_("run command with specified login class\n"));
#endif
    lbuf_append(&lbuf, "  -E            %s",
	_("preserve user environment when executing command\n"));
    lbuf_append(&lbuf, "  -e            %s",
	_("edit files instead of running a command\n"));
    lbuf_append(&lbuf, "  -g group      %s",
	_("execute command as the specified group\n"));
    lbuf_append(&lbuf, "  -H            %s",
	_("set HOME variable to target user's home dir.\n"));
    lbuf_append(&lbuf, "  -h            %s",
	_("display help message and exit\n"));
    lbuf_append(&lbuf, "  -i [command]  %s",
	_("run a login shell as target user\n"));
    lbuf_append(&lbuf, "  -K            %s",
	_("remove timestamp file completely\n"));
    lbuf_append(&lbuf, "  -k            %s",
	_("invalidate timestamp file\n"));
    lbuf_append(&lbuf, "  -l[l] command %s",
	_("list user's available commands\n"));
    lbuf_append(&lbuf, "  -n            %s",
	_("non-interactive mode, will not prompt user\n"));
    lbuf_append(&lbuf, "  -P            %s",
	_("preserve group vector instead of setting to target's\n"));
    lbuf_append(&lbuf, "  -p prompt     %s",
	_("use specified password prompt\n"));
#ifdef HAVE_SELINUX
    lbuf_append(&lbuf, "  -r role       %s",
	_("create SELinux security context with specified role\n"));
#endif
    lbuf_append(&lbuf, "  -S            %s",
	_("read password from standard input\n"));
    lbuf_append(&lbuf,
	"  -s [command]  %s", _("run a shell as target user\n"));
#ifdef HAVE_SELINUX
    lbuf_append(&lbuf, "  -t type       %s",
	_("create SELinux security context with specified role\n"));
#endif
    lbuf_append(&lbuf, "  -U user       %s",
	_("when listing, list specified user's privileges\n"));
    lbuf_append(&lbuf, "  -u user       %s",
	_("run command (or edit file) as specified user\n"));
    lbuf_append(&lbuf, "  -V            %s",
	_("display version information and exit\n"));
    lbuf_append(&lbuf, "  -v            %s",
	_("update user's timestamp without running a command\n"));
    lbuf_append(&lbuf, "  --            %s",
	_("stop processing command line arguments\n"));
    lbuf_print(&lbuf);
    lbuf_destroy(&lbuf);
    exit(0);
}
