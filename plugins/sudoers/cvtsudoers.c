/*
 * Copyright (c) 2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
 */

/*
 * Convert from sudoers format to other formats.
 * Currently outputs to JSON
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sudoers.h"
#include "interfaces.h"
#include "parse.h"
#include "redblack.h"
#include "sudoers_version.h"
#include "sudo_conf.h"
#include <gram.h>

#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

extern bool convert_sudoers_json(const char *output_file);
extern bool convert_sudoers_ldif(const char *output_file, const char *base);
extern void parse_sudoers_options(void);
extern void get_hostname(void);

/*
 * Globals
 */
struct sudo_user sudo_user;
struct passwd *list_pw;
static const char short_opts[] =  "f:ho:V";
static struct option long_opts[] = {
    { "format",		required_argument,	NULL,	'f' },
    { "help",		no_argument,		NULL,	'h' },
#ifdef notyet
    { "input-format",	required_argument,	NULL,	'i' },
#endif
    { "output",		required_argument,	NULL,	'o' },
    { "version",	no_argument,		NULL,	'V' },
    { NULL,		no_argument,		NULL,	'\0' },
};

__dso_public int main(int argc, char *argv[]);
static void help(void) __attribute__((__noreturn__));
static void usage(int);

enum output_formats {
    output_invalid,
    output_json,
    output_ldif
};

int
main(int argc, char *argv[])
{
    int ch, exitcode = EXIT_FAILURE;
    enum output_formats output_format = output_json;
    const char *input_file = NULL;
    const char *output_file = "-";
    debug_decl(main, SUDOERS_DEBUG_MAIN)

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    {
	extern char *malloc_options;
	malloc_options = "S";
    }
#endif

    initprogname(argc > 0 ? argv[0] : "cvtsudoers");
    if (!sudoers_initlocale(setlocale(LC_ALL, ""), def_sudoers_locale))
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    sudo_warn_set_locale_func(sudoers_warn_setlocale);
    bindtextdomain("sudoers", LOCALEDIR); /* XXX - should have visudo domain */
    textdomain("sudoers");

#if 0
    /* Register fatal/fatalx callback. */
    sudo_fatal_callback_register(cvtsudoers_cleanup);
#endif

    /* Read debug and plugin sections of sudo.conf. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG|SUDO_CONF_PLUGINS) == -1)
	goto done;

    /* Initialize the debug subsystem. */
    if (!sudoers_debug_register(getprogname(), sudo_conf_debug_files(getprogname())))
	goto done;

    /* Parse sudoers plugin options, if any. */
    parse_sudoers_options();

    /*
     * Arg handling.
     */
    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	    case 'f':
		if (strcasecmp(optarg, "json") == 0) {
		    output_format = output_json;
		} else if (strcasecmp(optarg, "ldif") == 0) {
		    output_format = output_ldif;
		} else {
		    sudo_warnx("unsupported output format %s", optarg);
		    usage(1);
		}
		break;
	    case 'h':
		help();
		break;
	    case 'o':
		output_file = optarg;
		break;
	    case 'V':
		(void) printf(_("%s version %s\n"), getprogname(),
		    PACKAGE_VERSION);
		(void) printf(_("%s grammar version %d\n"), getprogname(),
		    SUDOERS_GRAMMAR_VERSION);
		exitcode = EXIT_SUCCESS;
		goto done;
	    default:
		usage(1);
	}
    }
    argc -= optind;
    argv += optind;

    /* Input file (defaults to /etc/sudoers). */
    if (argc > 0) {
	/* XXX - allow multiple input files? */
	if (argc > 1)
	    usage(1);
	input_file  = argv[0];
    } else {
	input_file = sudoers_file;
    }

    if (strcmp(input_file, "-") != 0) {
	if (strcmp(input_file, output_file) == 0) {
	    sudo_fatalx(U_("%s: input and output files must be different"),
		input_file);
	}
    }

    /* Mock up a fake sudo_user struct. */
    /* XXX - common with visudo */
    user_cmnd = user_base = "";
    if (geteuid() == 0) {
	const char *user = getenv("SUDO_USER");
	if (user != NULL && *user != '\0')
	    sudo_user.pw = sudo_getpwnam(user);
    }
    if (sudo_user.pw == NULL) {
	if ((sudo_user.pw = sudo_getpwuid(getuid())) == NULL)
	    sudo_fatalx(U_("you do not exist in the %s database"), "passwd");
    }
    get_hostname();

    /* Setup defaults data structures. */
    if (!init_defaults())
	sudo_fatalx(U_("unable to initialize sudoers default values"));

    /* Open sudoers file and parse it. */
    if (strcmp(input_file, "-") == 0) {
	sudoersin = stdin;
	input_file = "stdin";
    } else if ((sudoersin = fopen(input_file, "r")) == NULL)
	sudo_fatal(U_("unable to open %s"), input_file);
    init_parser(input_file, false);
    if (sudoersparse() && !parse_error) {
	sudo_warnx(U_("failed to parse %s file, unknown error"), input_file);
	parse_error = true;
	rcstr_delref(errorfile);
	if ((errorfile = rcstr_dup(input_file)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }
    if (parse_error) {
	if (errorlineno != -1)
	    sudo_warnx(U_("parse error in %s near line %d\n"),
		errorfile, errorlineno);
	else if (errorfile != NULL)
	    sudo_warnx(U_("parse error in %s\n"), errorfile);
	goto done;
    }

    switch (output_format) {
    case output_json:
	exitcode = !convert_sudoers_json(output_file);
	break;
    case output_ldif:
	exitcode = !convert_sudoers_ldif(output_file, NULL);
	break;
    default:
	sudo_fatalx("error: unhandled output format %d", output_format);
    }

done:
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);
    return exitcode;
}

FILE *
open_sudoers(const char *sudoers, bool doedit, bool *keepopen)
{
    return fopen(sudoers, "r");
}

static void
usage(int fatal)
{
    (void) fprintf(fatal ? stderr : stdout,
	"usage: %s [-hV] [-f format] [-o output_file] [sudoers_file]\n",
	    getprogname());
    if (fatal)
	exit(1);
}

static void
help(void)
{
    (void) printf(_("%s - convert between sudoers file formats\n\n"), getprogname());
    usage(0);
    (void) puts(_("\nOptions:\n"
	"  -f, --format=JSON        specify output format\n"
	"  -h, --help               display help message and exit\n"
	"  -o, --output=output_file write sudoers in JSON format to output_file\n"
	"  -V, --version            display version information and exit"));
    exit(0);
}
