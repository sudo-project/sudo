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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "sudoers.h"
#include "parse.h"
#include "sudoers_version.h"
#include "sudo_conf.h"
#include "sudo_lbuf.h"
#include "cvtsudoers.h"
#include <gram.h>

#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

/*
 * Globals
 */
struct sudo_user sudo_user;
struct passwd *list_pw;
static const char short_opts[] =  "b:c:ef:hi:I:o:O:V";
static struct option long_opts[] = {
    { "base",		required_argument,	NULL,	'b' },
    { "config",		required_argument,	NULL,	'c' },
    { "expand-aliases",	no_argument,		NULL,	'e' },
    { "output-format",	required_argument,	NULL,	'f' },
    { "help",		no_argument,		NULL,	'h' },
    { "input-format",	required_argument,	NULL,	'i' },
    { "increment",	required_argument,	NULL,	'I' },
    { "order-start",	required_argument,	NULL,	'O' },
    { "output",		required_argument,	NULL,	'o' },
    { "version",	no_argument,		NULL,	'V' },
    { NULL,		no_argument,		NULL,	'\0' },
};

__dso_public int main(int argc, char *argv[]);
static void help(void) __attribute__((__noreturn__));
static void usage(int);
static bool convert_sudoers_sudoers(const char *output_file, struct cvtsudoers_config *conf);
static bool parse_sudoers(const char *input_file, struct cvtsudoers_config *conf);
static struct cvtsudoers_config *cvtsudoers_conf_read(const char *conf_file);
static void cvtsudoers_conf_free(struct cvtsudoers_config *conf);

int
main(int argc, char *argv[])
{
    int ch, exitcode = EXIT_FAILURE;
    enum sudoers_formats output_format = format_ldif;
    enum sudoers_formats input_format = format_sudoers;
    struct cvtsudoers_config *conf;
    const char *input_file = "-";
    const char *output_file = "-";
    const char *conf_file = _PATH_CVTSUDOERS_CONF;
    const char *errstr;
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
    bindtextdomain("sudoers", LOCALEDIR);
    textdomain("sudoers");

    /* Read debug and plugin sections of sudo.conf. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG|SUDO_CONF_PLUGINS) == -1)
	goto done;

    /* Initialize the debug subsystem. */
    if (!sudoers_debug_register(getprogname(), sudo_conf_debug_files(getprogname())))
	goto done;

    /* Check for --config option first (no getopt warnings). */
    opterr = 0;
    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	case 'c':
	    conf_file = optarg;
	    break;
	}
    }

    /* Read conf file. */
    conf = cvtsudoers_conf_read(conf_file);

    /*
     * Reset getopt and handle the rest of the arguments.
     */
    opterr = 1;
    optind = 1;
#ifdef HAVE_OPTRESET
    optreset = 1;
#endif
    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	case 'b':
	    free(conf->sudoers_base);
	    conf->sudoers_base = strdup(optarg);
	    if (conf->sudoers_base == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    break;
	case 'c':
	    /* handled above */
	    break;
	case 'e':
	    conf->expand_aliases = true;
	    break;
	case 'f':
	    free(conf->output_format);
	    conf->output_format = strdup(optarg);
	    if (conf->output_format == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    break;
	case 'h':
	    help();
	    break;
	case 'i':
	    free(conf->input_format);
	    conf->input_format = strdup(optarg);
	    if (conf->input_format == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    break;
	case 'I':
	    conf->order_increment = sudo_strtonum(optarg, 1, UINT_MAX, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("order increment: %s: %s"), optarg, U_(errstr));
		usage(1);
	    }
	    break;
	case 'o':
	    output_file = optarg;
	    break;
	case 'O':
	    conf->sudo_order = sudo_strtonum(optarg, 0, UINT_MAX, &errstr);
	    if (errstr != NULL) {
		sudo_warnx(U_("starting order: %s: %s"), optarg, U_(errstr));
		usage(1);
	    }
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

    if (conf->input_format != NULL) {
	if (strcasecmp(conf->input_format, "ldif") == 0) {
	    input_format = format_ldif;
	} else if (strcasecmp(conf->input_format, "sudoers") == 0) {
	    input_format = format_sudoers;
	} else {
	    sudo_warnx(U_("unsupported input format %s"), conf->input_format);
	    usage(1);
	}
    }
    if (conf->output_format != NULL) {
	if (strcasecmp(conf->output_format, "json") == 0) {
	    output_format = format_json;
	    conf->store_options = true;
	} else if (strcasecmp(conf->output_format, "ldif") == 0) {
	    output_format = format_ldif;
	    conf->store_options = true;
	} else if (strcasecmp(conf->output_format, "sudoers") == 0) {
	    output_format = format_sudoers;
	    conf->store_options = false;
	} else {
	    sudo_warnx(U_("unsupported output format %s"), conf->output_format);
	    usage(1);
	}
    }

    /* If no base DN specified, check SUDOERS_BASE. */
    if (conf->sudoers_base == NULL) {
	conf->sudoers_base = getenv("SUDOERS_BASE");
	if (conf->sudoers_base != NULL && *conf->sudoers_base != '\0') {
	    if ((conf->sudoers_base = strdup(conf->sudoers_base)) == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	}
    }

    /* Input file (defaults to stdin). */
    if (argc > 0) {
	if (argc > 1)
	    usage(1);
	input_file = argv[0];
    }

    if (strcmp(input_file, "-") != 0) {
	if (strcmp(input_file, output_file) == 0) {
	    sudo_fatalx(U_("%s: input and output files must be different"),
		input_file);
	}
    }

    /* We may need the hostname to resolve %h escapes in include files. */
    get_hostname();

    /* Setup defaults data structures. */
    if (!init_defaults())
	sudo_fatalx(U_("unable to initialize sudoers default values"));

    switch (input_format) {
    case format_ldif:
	if (!parse_ldif(input_file, conf))
	    goto done;
	break;
    case format_sudoers:
	if (!parse_sudoers(input_file, conf))
	    goto done;
	break;
    default:
	sudo_fatalx("error: unhandled input %d", input_format);
    }

    switch (output_format) {
    case format_json:
	exitcode = !convert_sudoers_json(output_file, conf);
	break;
    case format_ldif:
	exitcode = !convert_sudoers_ldif(output_file, conf);
	break;
    case format_sudoers:
	exitcode = !convert_sudoers_sudoers(output_file, conf);
	break;
    default:
	sudo_fatalx("error: unhandled output format %d", output_format);
    }

done:
    cvtsudoers_conf_free(conf);
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);
    return exitcode;
}

/*
 * cvtsudoers configuration data.
 */
static struct cvtsudoers_config cvtsudoers_config = INITIAL_CONFIG;
static struct cvtsudoers_conf_table cvtsudoers_conf_vars[] = {
    { "order_start", CONF_UINT, &cvtsudoers_config.sudo_order },
    { "order_increment", CONF_UINT, &cvtsudoers_config.order_increment },
    { "sudoers_base", CONF_STR, &cvtsudoers_config.sudoers_base },
    { "input_format", CONF_STR, &cvtsudoers_config.input_format },
    { "output_format", CONF_STR, &cvtsudoers_config.output_format },
    { "expand_aliases", CONF_BOOL, &cvtsudoers_config.expand_aliases }
};

/*
 * Look up keyword in config table.
 * Returns true if found, else false.
 */
static bool
cvtsudoers_parse_keyword(const char *conf_file, const char *keyword,
    const char *value, struct cvtsudoers_conf_table *table)
{
    struct cvtsudoers_conf_table *cur;
    const char *errstr;
    debug_decl(sudo_ldap_parse_keyword, SUDOERS_DEBUG_UTIL)

    /* Look up keyword in config tables */
    for (cur = table; cur->conf_str != NULL; cur++) {
	if (strcasecmp(keyword, cur->conf_str) == 0) {
	    switch (cur->type) {
	    case CONF_BOOL:
		*(bool *)(cur->valp) = sudo_strtobool(value) == true;
		break;
	    case CONF_UINT:
		{
		    unsigned int uval = 
			strtonum(value, 0, UINT_MAX, &errstr);
		    if (errstr != NULL) {
			sudo_warnx(U_("%s: %s: %s: %s"),
			    conf_file, keyword, value, U_(errstr));
			continue;
		    }
		    *(unsigned int *)(cur->valp) = uval;
		}
		break;
	    case CONF_STR:
		{
		    char *cp = strdup(value);
		    if (cp == NULL) {
			sudo_fatalx(U_("%s: %s"), __func__,
			    U_("unable to allocate memory"));
		    }
		    free(*(char **)(cur->valp));
		    *(char **)(cur->valp) = cp;
		    break;
		}
	    }
	    debug_return_bool(true);
	}
    }
    debug_return_bool(false);
}

static struct cvtsudoers_config *
cvtsudoers_conf_read(const char *conf_file)
{
    char *line = NULL;
    size_t linesize = 0;
    FILE *fp;
    debug_decl(cvtsudoers_conf_read, SUDOERS_DEBUG_UTIL)

    if ((fp = fopen(conf_file, "r")) == NULL)
	debug_return_ptr(&cvtsudoers_config);

    while (sudo_parseln(&line, &linesize, NULL, fp, 0) != -1) {
	char *cp, *keyword, *value;

	if (*line == '\0')
	    continue;		/* skip empty line */

	/* Parse keyword = value */
	keyword = line;
	if ((cp = strchr(line, '=')) == NULL)
	    continue;
	value = cp-- + 1;

	/* Trim whitespace after keyword. */
	while (cp != line && isblank((unsigned char)cp[-1]))
	    cp--;
	*cp = '\0';

	/* Trim whitespace before value. */
	while (isblank((unsigned char)*value))
	    value++;

	/* Look up keyword in config tables */
	if (!cvtsudoers_parse_keyword(conf_file, keyword, value, cvtsudoers_conf_vars))
	    sudo_warnx(U_("%s: unknown key word: %s"), conf_file, keyword);
    }
    free(line);
    fclose(fp);

    debug_return_ptr(&cvtsudoers_config);
}

static void
cvtsudoers_conf_free(struct cvtsudoers_config *conf)
{
    debug_decl(cvtsudoers_conf_free, SUDOERS_DEBUG_UTIL)

    free(conf->sudoers_base);
    free(conf->input_format);
    free(conf->output_format);
    conf->sudoers_base = NULL;
    conf->input_format = NULL;
    conf->output_format = NULL;

    debug_return;
}

static bool
parse_sudoers(const char *input_file, struct cvtsudoers_config *conf)
{
    debug_decl(parse_sudoers, SUDOERS_DEBUG_UTIL)

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
	debug_return_bool(false);
    }
    debug_return_bool(true);
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
print_defaults_sudoers(struct sudo_lbuf *lbuf, bool expand_aliases)
{
    struct defaults *def, *next;
    debug_decl(print_defaults_sudoers, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH_SAFE(def, &defaults, entries, next) {
	struct member *m;
	int alias_type;

	/* Print Defaults type and binding (if present) */
	switch (def->type) {
	    case DEFAULTS_HOST:
		sudo_lbuf_append(lbuf, "Defaults@");
		alias_type = HOSTALIAS;
		break;
	    case DEFAULTS_USER:
		sudo_lbuf_append(lbuf, "Defaults:");
		alias_type = expand_aliases ? USERALIAS : UNSPEC;
		break;
	    case DEFAULTS_RUNAS:
		sudo_lbuf_append(lbuf, "Defaults>");
		alias_type = expand_aliases ? RUNASALIAS : UNSPEC;
		break;
	    case DEFAULTS_CMND:
		sudo_lbuf_append(lbuf, "Defaults!");
		alias_type = expand_aliases ? CMNDALIAS : UNSPEC;
		break;
	    default:
		sudo_lbuf_append(lbuf, "Defaults");
		alias_type = UNSPEC;
		break;
	}
	TAILQ_FOREACH(m, def->binding, entries) {
	    if (m != TAILQ_FIRST(def->binding))
		sudo_lbuf_append(lbuf, ", ");
	    sudoers_format_member(lbuf, m, ", ", alias_type);
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
convert_sudoers_sudoers(const char *output_file, struct cvtsudoers_config *conf)
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
    if (!print_defaults_sudoers(&lbuf, conf->expand_aliases))
	goto done;
    if (lbuf.len > 0) {
	sudo_lbuf_print(&lbuf);
	sudo_lbuf_append(&lbuf, "\n");
    }

    /* Print Aliases */
    if (!conf->expand_aliases) {
	if (!print_aliases_sudoers(&lbuf))
	    goto done;
	if (lbuf.len > 1) {
	    sudo_lbuf_print(&lbuf);
	    sudo_lbuf_append(&lbuf, "\n");
	}
    }

    /* Print User_Specs */
    if (!sudoers_format_userspecs(&lbuf, &userspecs, conf->expand_aliases))
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
    (void) fprintf(fatal ? stderr : stdout, "usage: %s [-ehV] [-b dn] "
	"[-c conf_file ] [-f output_format] [-i input_format] [-I increment] "
	"[-o output_file] [-O start_point] [input_file]\n",
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
	"  -b, --base=dn              the base DN for sudo LDAP queries\n"
	"  -e, --expand-aliases       expand aliases when converting\n"
	"  -f, --output-format=format set output format: JSON, LDIF or sudoers\n"
	"  -I, --increment=num        amount to increase each sudoOrder by\n"
	"  -i, --input-format=format  set input format: LDIF or sudoers\n"
	"  -h, --help                 display help message and exit\n"
	"  -O, --order-start=num      starting point for first sudoOrder\n"
	"  -o, --output=output_file   write converted sudoers to output_file\n"
	"  -V, --version              display version information and exit"));
    exit(0);
}
