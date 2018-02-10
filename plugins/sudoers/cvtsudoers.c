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
 * Convert from the sudoers file format to LDIF or JSON format.
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
#include <errno.h>
#include <fcntl.h>

#include "sudoers.h"
#include "parse.h"
#include "sudoers_version.h"
#include "sudo_conf.h"
#include "sudo_lbuf.h"
#include <gram.h>

#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

static bool convert_sudoers_sudoers(const char *output_file);
extern bool convert_sudoers_json(const char *output_file);
extern bool convert_sudoers_ldif(const char *output_file, const char *base);
extern void get_hostname(void);

/*
 * Globals
 */
struct sudo_user sudo_user;
struct passwd *list_pw;
static const char short_opts[] =  "b:f:ho:V";
static struct option long_opts[] = {
    { "base",		required_argument,	NULL,	'b' },
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
    output_json,
    output_ldif,
    output_sudoers
};

int
main(int argc, char *argv[])
{
    int ch, exitcode = EXIT_FAILURE;
    enum output_formats output_format = output_ldif;
    const char *input_file = "-";
    const char *output_file = "-";
    const char *sudoers_base = NULL;
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

    /* Read debug and plugin sections of sudo.conf. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG|SUDO_CONF_PLUGINS) == -1)
	goto done;

    /* Initialize the debug subsystem. */
    if (!sudoers_debug_register(getprogname(), sudo_conf_debug_files(getprogname())))
	goto done;

    /*
     * Arg handling.
     */
    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	case 'b':
	    sudoers_base = optarg;
	    break;
	case 'f':
	    if (strcasecmp(optarg, "json") == 0) {
		output_format = output_json;
	    } else if (strcasecmp(optarg, "ldif") == 0) {
		output_format = output_ldif;
	    } else if (strcasecmp(optarg, "sudoers") == 0) {
		output_format = output_sudoers;
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

    /* Input file (defaults to stdin). */
    if (argc > 0) {
	/* XXX - allow multiple input files? */
	if (argc > 1)
	    usage(1);
	input_file  = argv[0];
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
	exitcode = !convert_sudoers_ldif(output_file, sudoers_base);
	break;
    case output_sudoers:
	exitcode = !convert_sudoers_sudoers(output_file);
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

/*
 * Display Defaults entries
 */
static bool
print_defaults_sudoers(struct sudo_lbuf *lbuf)
{
    struct defaults *def, *next;
    struct member *m;
    debug_decl(print_defaults_sudoers, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH_SAFE(def, &defaults, entries, next) {
	/* Print Defaults type and binding (if present) */
	switch (def->type) {
	    case DEFAULTS:
		sudo_lbuf_append(lbuf, "Defaults");
		break;
	    case DEFAULTS_HOST:
		sudo_lbuf_append(lbuf, "Defaults@");
		break;
	    case DEFAULTS_USER:
		sudo_lbuf_append(lbuf, "Defaults:");
		break;
	    case DEFAULTS_RUNAS:
		sudo_lbuf_append(lbuf, "Defaults>");
		break;
	    case DEFAULTS_CMND:
		sudo_lbuf_append(lbuf, "Defaults!");
		break;
	}
	TAILQ_FOREACH(m, def->binding, entries) {
	    if (m != TAILQ_FIRST(def->binding))
		sudo_lbuf_append(lbuf, ", ");
	    sudoers_format_member(lbuf, m, NULL, UNSPEC);
	}

	/* Print Defaults with the same binding, there may be multiple. */
	for (;;) {
	    sudo_lbuf_append(lbuf, " ");
	    sudoers_format_default(lbuf, def);
	    next = TAILQ_NEXT(def, entries);
	    if (next == NULL || def->binding != next->binding)
		break;
	    def = next;
	    sudo_lbuf_append(lbuf, ",");
	}
	sudo_lbuf_append(lbuf, "\n");
    }
    debug_return_bool(!sudo_lbuf_error(lbuf));
}

static int
print_alias_sudoers(void *v1, void *v2)
{
    struct alias *a = v1;
    struct sudo_lbuf *lbuf = v2;
    struct member *m;
    debug_decl(print_alias_sudoers, SUDOERS_DEBUG_UTIL)

    sudo_lbuf_append(lbuf, "%s %s = ", alias_type_to_string(a->type),
	a->name);
    TAILQ_FOREACH(m, &a->members, entries) {
	if (m != TAILQ_FIRST(&a->members))
	    sudo_lbuf_append(lbuf, ", ");
	sudoers_format_member(lbuf, m, NULL, UNSPEC);
    }
    sudo_lbuf_append(lbuf, "\n");

    debug_return_int(sudo_lbuf_error(lbuf) ? -1 : 0);
}

/*
 * Display aliases
 */
static bool
print_aliases_sudoers(struct sudo_lbuf *lbuf)
{
    debug_decl(print_aliases_sudoers, SUDOERS_DEBUG_UTIL)

    alias_apply(print_alias_sudoers, lbuf);

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

static FILE *output_fp;		/* global for convert_sudoers_output */

static int
convert_sudoers_output(const char *buf)
{
    return fputs(buf, output_fp);
}

/*
 * Convert back to sudoers.
 */
static bool
convert_sudoers_sudoers(const char *output_file)
{
    bool ret = true;
    struct sudo_lbuf lbuf;
    debug_decl(convert_sudoers_sudoers, SUDOERS_DEBUG_UTIL)

    if (strcmp(output_file, "-") == 0) {
	output_fp = stdout;
    } else {
	if ((output_fp = fopen(output_file, "w")) == NULL)
	    sudo_fatal(U_("unable to open %s"), output_file);
    }

    /* Wrap lines at 80 columns with a 4 character indent. */
    sudo_lbuf_init(&lbuf, convert_sudoers_output, 4, "\\", 80);

    /* Print Defaults */
    if (!print_defaults_sudoers(&lbuf))
	goto done;
    if (lbuf.len > 0) {
	sudo_lbuf_print(&lbuf);
	sudo_lbuf_append(&lbuf, "\n");
    }

    /* Print Aliases */
    if (!print_aliases_sudoers(&lbuf))
	goto done;
    if (lbuf.len > 1) {
	sudo_lbuf_print(&lbuf);
	sudo_lbuf_append(&lbuf, "\n");
    }

    /* Print User_Specs */
    if (!sudoers_format_userspecs(&lbuf, &userspecs, false))
	goto done;
    if (lbuf.len > 1) {
	sudo_lbuf_print(&lbuf);
    }

done:
    if (sudo_lbuf_error(&lbuf)) {
	if (errno == ENOMEM)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	ret = false;
    }
    sudo_lbuf_destroy(&lbuf);

    (void)fflush(output_fp);
    if (ferror(output_fp)) {
	sudo_warn(U_("unable to write to %s"), output_file);
	ret = false;
    }
    if (output_fp != stdout)
	fclose(output_fp);

    debug_return_bool(ret);
}

static void
usage(int fatal)
{
    (void) fprintf(fatal ? stderr : stdout,
	"usage: %s [-hV] [-b dn] [-f format] [-o output_file] [sudoers_file]\n",
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
	"  -b, --base=dn            the base DN for sudo LDAP queries\n"
	"  -f, --format=JSON|LDIF   specify output format (JSON or LDIF)\n"
	"  -h, --help               display help message and exit\n"
	"  -o, --output=output_file write converted sudoers to output_file\n"
	"  -V, --version            display version information and exit"));
    exit(0);
}
