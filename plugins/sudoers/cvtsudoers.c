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
#include <pwd.h>
#include <unistd.h>

#include "sudoers.h"
#include "parse.h"
#include "sudoers_version.h"
#include "sudo_conf.h"
#include "sudo_lbuf.h"
#include "redblack.h"
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
struct cvtsudoers_filter *filters;
struct sudo_user sudo_user;
struct passwd *list_pw;
static const char short_opts[] =  "b:c:d:ef:hi:I:m:Mo:O:s:V";
static struct option long_opts[] = {
    { "base",		required_argument,	NULL,	'b' },
    { "config",		required_argument,	NULL,	'c' },
    { "defaults",	required_argument,	NULL,	'd' },
    { "expand-aliases",	no_argument,		NULL,	'e' },
    { "output-format",	required_argument,	NULL,	'f' },
    { "help",		no_argument,		NULL,	'h' },
    { "input-format",	required_argument,	NULL,	'i' },
    { "increment",	required_argument,	NULL,	'I' },
    { "match",		required_argument,	NULL,	'm' },
    { "match-local",	no_argument,		NULL,	'M' },
    { "order-start",	required_argument,	NULL,	'O' },
    { "output",		required_argument,	NULL,	'o' },
    { "suppress",	required_argument,	NULL,	's' },
    { "version",	no_argument,		NULL,	'V' },
    { NULL,		no_argument,		NULL,	'\0' },
};

__dso_public int main(int argc, char *argv[]);
static void help(void) __attribute__((__noreturn__));
static void usage(int);
static bool convert_sudoers_sudoers(const char *output_file, struct cvtsudoers_config *conf);
static bool parse_sudoers(const char *input_file, struct cvtsudoers_config *conf);
static bool cvtsudoers_parse_filter(char *expression);
static bool alias_remove_unused(void);
static struct cvtsudoers_config *cvtsudoers_conf_read(const char *conf_file);
static void cvtsudoers_conf_free(struct cvtsudoers_config *conf);
static int cvtsudoers_parse_defaults(char *expression);
static int cvtsudoers_parse_suppression(char *expression);
static void filter_userspecs(void);
static void filter_defaults(struct cvtsudoers_config *conf);

int
main(int argc, char *argv[])
{
    int ch, exitcode = EXIT_FAILURE;
    enum sudoers_formats output_format = format_ldif;
    enum sudoers_formats input_format = format_sudoers;
    struct cvtsudoers_config *conf = NULL;
    bool match_local = false;
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
	case 'd':
	    conf->defaults = cvtsudoers_parse_defaults(optarg);
	    if (conf->defaults == -1)
		usage(1);
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
	case 'm':
	    conf->filter = optarg;
	    break;
	case 'M':
	    match_local = true;
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
	case 's':
	    conf->suppress = cvtsudoers_parse_suppression(optarg);
	    if (conf->suppress == -1)
		usage(1);
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
    if (conf->filter != NULL) {
	/* We always expand aliases when filtering (may change in future). */
	if (!cvtsudoers_parse_filter(conf->filter))
	    usage(1);
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

    /* Set pwutil backend to use the filter data. */
    if (conf->filter != NULL && !match_local) {
	sudo_pwutil_set_backend(cvtsudoers_make_pwitem, cvtsudoers_make_gritem,
	    cvtsudoers_make_gidlist_item, cvtsudoers_make_grlist_item);
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

    /* Apply filters. */
    filter_userspecs();
    filter_defaults(conf);
    if (filters != NULL || conf->defaults != CVT_DEFAULTS_ALL)
	alias_remove_unused();

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
    { "match", CONF_STR, &cvtsudoers_config.filter },
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

    if (conf != NULL) {
	free(conf->sudoers_base);
	free(conf->input_format);
	free(conf->output_format);
	conf->sudoers_base = NULL;
	conf->input_format = NULL;
	conf->output_format = NULL;
    }

    debug_return;
}

static int
cvtsudoers_parse_defaults(char *expression)
{
    char *last = NULL, *cp = expression;
    int flags = 0;
    debug_decl(cvtsudoers_parse_defaults, SUDOERS_DEBUG_UTIL)

    for ((cp = strtok_r(cp, ",", &last)); cp != NULL; (cp = strtok_r(NULL, ",", &last))) {
	if (strcasecmp(cp, "global") == 0) {
	    SET(flags, CVT_DEFAULTS_GLOBAL);
	} else if (strcasecmp(cp, "user") == 0) {
	    SET(flags, CVT_DEFAULTS_USER);
	} else if (strcasecmp(cp, "runas") == 0) {
	    SET(flags, CVT_DEFAULTS_RUNAS);
	} else if (strcasecmp(cp, "host") == 0) {
	    SET(flags, CVT_DEFAULTS_HOST);
	} else if (strcasecmp(cp, "command") == 0) {
	    SET(flags, CVT_DEFAULTS_CMND);
	} else {
	    sudo_warnx(U_("invalid defaults type: %s"), cp);
	    debug_return_int(-1);
	}
    }

    debug_return_int(flags);
}

static int
cvtsudoers_parse_suppression(char *expression)
{
    char *last = NULL, *cp = expression;
    int flags = 0;
    debug_decl(cvtsudoers_parse_suppression, SUDOERS_DEBUG_UTIL)

    for ((cp = strtok_r(cp, ",", &last)); cp != NULL; (cp = strtok_r(NULL, ",", &last))) {
	if (strcasecmp(cp, "defaults") == 0) {
	    SET(flags, SUPPRESS_DEFAULTS);
	} else if (strcasecmp(cp, "aliases") == 0) {
	    SET(flags, SUPPRESS_ALIASES);
	} else if (strcasecmp(cp, "privileges") == 0 || strcasecmp(cp, "privs") == 0) {
	    SET(flags, SUPPRESS_PRIVS);
	} else {
	    sudo_warnx(U_("invalid suppression type: %s"), cp);
	    debug_return_int(-1);
	}
    }

    debug_return_int(flags);
}

static bool
cvtsudoers_parse_filter(char *expression)
{
    char *last = NULL, *cp = expression;
    debug_decl(cvtsudoers_parse_filter, SUDOERS_DEBUG_UTIL)

    if (filters == NULL) {
	if ((filters = malloc(sizeof(*filters))) == NULL) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	STAILQ_INIT(&filters->users);
	STAILQ_INIT(&filters->groups);
	STAILQ_INIT(&filters->hosts);
    }

    for ((cp = strtok_r(cp, ",", &last)); cp != NULL; (cp = strtok_r(NULL, ",", &last))) {
	/*
	 * Filter expression:
	 *	user=foo,group=bar,host=baz
	 */
	char *keyword;
	struct cvtsudoers_string *s;

	if ((s = malloc(sizeof(*s))) == NULL) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}

	/* Parse keyword = value */
	keyword = cp;
	if ((cp = strchr(cp, '=')) == NULL) {
	    sudo_warnx(U_("invalid filter: %s"), keyword);;
	    free(s);
	    debug_return_bool(false);
	}
	*cp++ = '\0';
	s->str = cp;

	if (strcmp(keyword, "user") == 0 ){
	    STAILQ_INSERT_TAIL(&filters->users, s, entries);
	} else if (strcmp(keyword, "group") == 0 ){
	    STAILQ_INSERT_TAIL(&filters->groups, s, entries);
	} else if (strcmp(keyword, "host") == 0 ){
	    STAILQ_INSERT_TAIL(&filters->hosts, s, entries);
	} else {
	    sudo_warnx(U_("invalid filter: %s"), keyword);;
	    free(s);
	    debug_return_bool(false);
	}
    }

    debug_return_bool(true);
}

struct cvtsudoers_string *
cvtsudoers_string_alloc(const char *s)
{
    struct cvtsudoers_string *ls;
    debug_decl(cvtsudoers_string_alloc, SUDOERS_DEBUG_UTIL)

    if ((ls = malloc(sizeof(*ls))) != NULL) {
	if ((ls->str = strdup(s)) == NULL) {
	    free(ls);
	    ls = NULL;
	}
    }

    debug_return_ptr(ls);
}

void
cvtsudoers_string_free(struct cvtsudoers_string *ls)
{
    free(ls->str);
    free(ls);
}

struct cvtsudoers_str_list *
str_list_alloc(void)
{
    struct cvtsudoers_str_list *strlist;
    debug_decl(str_list_alloc, SUDOERS_DEBUG_UTIL)

    strlist = malloc(sizeof(*strlist));
    STAILQ_INIT(strlist);
    strlist->refcnt = 1;

    debug_return_ptr(strlist);
}

void
str_list_free(void *v)
{
    struct cvtsudoers_str_list *strlist = v;
    struct cvtsudoers_string *first;
    debug_decl(str_list_free, SUDOERS_DEBUG_UTIL)

    if (--strlist->refcnt == 0) {
	while ((first = STAILQ_FIRST(strlist)) != NULL) {
	    STAILQ_REMOVE_HEAD(strlist, entries);
	    cvtsudoers_string_free(first);
	}
	free(strlist);
    }
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

static bool
userlist_matches_filter(struct member_list *userlist)
{
    struct cvtsudoers_string *s;
    bool matches = false;
    debug_decl(userlist_matches_filter, SUDOERS_DEBUG_UTIL)

    if (filters == NULL ||
	(STAILQ_EMPTY(&filters->users) && STAILQ_EMPTY(&filters->groups)))
	debug_return_bool(true);

    if (STAILQ_EMPTY(&filters->users)) {
	struct passwd pw;

	/*
	 * Only groups in filter, make a dummy user so userlist_matches()
	 * can do its thing.
	 */
	memset(&pw, 0, sizeof(pw));
	pw.pw_name = "_nobody";
	pw.pw_uid = (uid_t)-1;
	pw.pw_gid = (gid_t)-1;
	if (userlist_matches(&pw, userlist) == true)
	    matches = true;
    }

    STAILQ_FOREACH(s, &filters->users, entries) {
	struct passwd *pw = NULL;
        if (s->str[0] == '#') {
	    const char *errstr;
            uid_t uid = sudo_strtoid(s->str + 1, NULL, NULL, &errstr);
            if (errstr == NULL)
                pw = sudo_getpwuid(uid);
	}
	if (pw == NULL)
	    pw = sudo_getpwnam(s->str);
	if (pw == NULL)
	    continue;
	if (userlist_matches(pw, userlist) == true)
	    matches = true;
	sudo_pw_delref(pw);
	if (matches)
	    break;
    }

    debug_return_bool(matches);
}

static bool
hostlist_matches_filter(struct member_list *hostlist)
{
    struct cvtsudoers_string *s;
    bool matches = false;
    debug_decl(hostlist_matches_filter, SUDOERS_DEBUG_UTIL)

    if (filters == NULL || STAILQ_EMPTY(&filters->hosts))
	debug_return_bool(true);

    STAILQ_FOREACH(s, &filters->hosts, entries) {
	user_runhost = s->str;
	if ((user_srunhost = strchr(user_runhost, '.')) != NULL) {
	    user_srunhost = strndup(user_runhost,
		(size_t)(user_srunhost - user_runhost));
	    if (user_srunhost == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	} else {
	    user_srunhost = user_runhost;
	}
	/* XXX - can't use netgroup_tuple with NULL pw */
	if (hostlist_matches(NULL, hostlist) == true)
	    matches = true;
	if (user_srunhost != user_runhost)
	    free(user_srunhost);
	user_runhost = user_host;
	user_srunhost = user_shost;
	if (matches)
	    break;
    }
    debug_return_bool(matches);
}

/*
 * Display Defaults entries
 */
static bool
print_defaults_sudoers(struct sudo_lbuf *lbuf, bool expand_aliases)
{
    struct defaults *def, *next;
    debug_decl(print_defaults_sudoers, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH_SAFE(def, &defaults, entries, next)
	sudoers_format_default_line(lbuf, def, &next, expand_aliases);

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
 * Apply filters to userspecs, removing non-matching entries.
 */
static void
filter_userspecs(void)
{
    struct userspec *us, *next_us;
    struct privilege *priv, *next_priv;
    debug_decl(filter_userspecs, SUDOERS_DEBUG_UTIL)

    if (filters == NULL)
	debug_return;

    /*
     * Does not currently prune out non-matching entries in the user or
     * host lists.  It acts more like a grep than a true filter.
     * In the future, we may want to add a prune option.
     */
    TAILQ_FOREACH_SAFE(us, &userspecs, entries, next_us) {
	if (!userlist_matches_filter(&us->users)) {
	    TAILQ_REMOVE(&userspecs, us, entries);
	    free_userspec(us);
	    continue;
	}
	TAILQ_FOREACH_SAFE(priv, &us->privileges, entries, next_priv) {
	    if (!hostlist_matches_filter(&priv->hostlist)) {
		TAILQ_REMOVE(&us->privileges, priv, entries);
		free_privilege(priv);
	    }
	}
	if (TAILQ_EMPTY(&us->privileges)) {
	    TAILQ_REMOVE(&userspecs, us, entries);
	    free_userspec(us);
	    continue;
	}
    }
    debug_return;
}

/*
 * Apply filters to host/user-based Defaults, removing non-matching entries.
 */
static void
filter_defaults(struct cvtsudoers_config *conf)
{
    struct defaults *def, *next;
    struct member_list *prev_binding = NULL;
    debug_decl(filter_defaults, SUDOERS_DEBUG_DEFAULTS)

    if (filters == NULL && conf->defaults == CVT_DEFAULTS_ALL)
	debug_return;

    TAILQ_FOREACH_SAFE(def, &defaults, entries, next) {
	bool keep = true;

	switch (def->type) {
	case DEFAULTS:
	    if (!ISSET(conf->defaults, CVT_DEFAULTS_GLOBAL))
		keep = false;
	    break;
	case DEFAULTS_USER:
	    if (!ISSET(conf->defaults, CVT_DEFAULTS_USER) ||
		!userlist_matches_filter(def->binding))
		keep = false;
	    break;
	case DEFAULTS_RUNAS:
	    if (!ISSET(conf->defaults, CVT_DEFAULTS_RUNAS))
		keep = false;
	    break;
	case DEFAULTS_HOST:
	    if (!ISSET(conf->defaults, CVT_DEFAULTS_HOST) ||
		!hostlist_matches_filter(def->binding))
		keep = false;
	    break;
	case DEFAULTS_CMND:
	    if (!ISSET(conf->defaults, CVT_DEFAULTS_RUNAS))
		keep = false;
	    break;
	default:
	    sudo_fatalx_nodebug("unexpected defaults type %d", def->type);
	    break;
	}

	if (!keep) {
	    TAILQ_REMOVE(&defaults, def, entries);
	    free_default(def, &prev_binding);
	} else {
	    prev_binding = def->binding;
	}
    }
    debug_return;
}

/*
 * Remove the alias of the specified type as well as any other aliases
 * referenced by that alias.
 * XXX - share with visudo
 */
static bool
alias_remove_recursive(char *name, int type, struct rbtree *freelist)
{
    struct member *m;
    struct alias *a;
    bool ret = true;
    debug_decl(alias_remove_recursive, SUDOERS_DEBUG_ALIAS)

    if ((a = alias_remove(name, type)) != NULL) {
	TAILQ_FOREACH(m, &a->members, entries) {
	    if (m->type == ALIAS) {
		if (!alias_remove_recursive(m->name, type, freelist))
		    ret = false;
	    }
	}
	if (rbinsert(freelist, a, NULL) != 0)
	    ret = false;
    }
    debug_return_bool(ret);
}

/*
 * Remove unreferenced aliases.
 * XXX - share with visudo
 */
static bool
alias_remove_unused(void)
{
    struct cmndspec *cs;
    struct member *m;
    struct privilege *priv;
    struct userspec *us;
    struct defaults *d;
    int atype, errors = 0;
    struct rbtree *used_aliases;
    struct rbtree *unused_aliases;
    debug_decl(alias_remove_unused, SUDOERS_DEBUG_ALIAS)

    used_aliases = rbcreate(alias_compare);
    if (used_aliases == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }

    /* Move referenced aliases to used_aliases. */
    TAILQ_FOREACH(us, &userspecs, entries) {
	TAILQ_FOREACH(m, &us->users, entries) {
	    if (m->type == ALIAS) {
		if (!alias_remove_recursive(m->name, USERALIAS, used_aliases))
		    errors++;
	    }
	}
	TAILQ_FOREACH(priv, &us->privileges, entries) {
	    TAILQ_FOREACH(m, &priv->hostlist, entries) {
		if (m->type == ALIAS) {
		    if (!alias_remove_recursive(m->name, HOSTALIAS, used_aliases))
			errors++;
		}
	    }
	    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m->type == ALIAS) {
			    if (!alias_remove_recursive(m->name, RUNASALIAS, used_aliases))
				errors++;
			}
		    }
		}
		if (cs->runasgrouplist != NULL) {
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m->type == ALIAS) {
			    if (!alias_remove_recursive(m->name, RUNASALIAS, used_aliases))
				errors++;
			}
		    }
		}
		if ((m = cs->cmnd)->type == ALIAS) {
		    if (!alias_remove_recursive(m->name, CMNDALIAS, used_aliases))
			errors++;
		}
	    }
	}
    }
    TAILQ_FOREACH(d, &defaults, entries) {
	switch (d->type) {
	    case DEFAULTS_HOST:
		atype = HOSTALIAS;
		break;
	    case DEFAULTS_USER:
		atype = USERALIAS;
		break;
	    case DEFAULTS_RUNAS:
		atype = RUNASALIAS;
		break;
	    case DEFAULTS_CMND:
		atype = CMNDALIAS;
		break;
	    default:
		continue; /* not an alias */
	}
	TAILQ_FOREACH(m, d->binding, entries) {
	    if (m->type == ALIAS) {
		if (!alias_remove_recursive(m->name, atype, used_aliases))
		    errors++;
	    }
	}
    }
    unused_aliases = replace_aliases(used_aliases);
    rbdestroy(unused_aliases, alias_free);

    debug_return_int(errors ? false : true);
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
    if (!ISSET(conf->suppress, SUPPRESS_DEFAULTS)) {
	if (!print_defaults_sudoers(&lbuf, conf->expand_aliases))
	    goto done;
	if (lbuf.len > 0) {
	    sudo_lbuf_print(&lbuf);
	    sudo_lbuf_append(&lbuf, "\n");
	}
    }

    /* Print Aliases */
    if (!conf->expand_aliases && !ISSET(conf->suppress, SUPPRESS_ALIASES)) {
	if (!print_aliases_sudoers(&lbuf))
	    goto done;
	if (lbuf.len > 1) {
	    sudo_lbuf_print(&lbuf);
	    sudo_lbuf_append(&lbuf, "\n");
	}
    }

    /* Print User_Specs, separated by blank lines. */
    if (!ISSET(conf->suppress, SUPPRESS_PRIVS)) {
	if (!sudoers_format_userspecs(&lbuf, &userspecs, "\n",
	    conf->expand_aliases, true)) {
	    goto done;
	}
	if (lbuf.len > 1) {
	    sudo_lbuf_print(&lbuf);
	}
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
    (void) fprintf(fatal ? stderr : stdout, "usage: %s [-ehMV] [-b dn] "
	"[-c conf_file ] [-d deftypes] [-f output_format] [-i input_format] "
	"[-I increment] [-m filter] [-o output_file] [-O start_point] "
	"[-s sections] [input_file]\n", getprogname());
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
	"  -d, --defaults=deftypes    only convert Defaults of the specified types\n"
	"  -e, --expand-aliases       expand aliases when converting\n"
	"  -f, --output-format=format set output format: JSON, LDIF or sudoers\n"
	"  -i, --input-format=format  set input format: LDIF or sudoers\n"
	"  -I, --increment=num        amount to increase each sudoOrder by\n"
	"  -h, --help                 display help message and exit\n"
	"  -m, --match=filter         only convert entries that match the filter\n"
	"  -M, --match-local          match filter uses passwd and group databases\n"
	"  -o, --output=output_file   write converted sudoers to output_file\n"
	"  -O, --order-start=num      starting point for first sudoOrder\n"
	"  -s, --suppress=sections    suppress output of certain sections\n"
	"  -V, --version              display version information and exit"));
    exit(0);
}
