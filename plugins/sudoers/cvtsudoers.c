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
 * Write the contents of a struct member to lbuf
 */
static bool
print_member_sudoers(struct sudo_lbuf *lbuf, struct member *m)
{
    struct sudo_command *c;
    debug_decl(print_member_sudoers, SUDOERS_DEBUG_UTIL)

    switch (m->type) {
	case ALL:
	    sudo_lbuf_append(lbuf, "%sALL", m->negated ? "!" : "");
	    break;
	case MYSELF:
	    /* nothing to print */
	    break;
	case COMMAND:
	    c = (struct sudo_command *)m->name;
	    if (m->negated)
		sudo_lbuf_append(lbuf, "!");
	    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED" \t", "%s", c->cmnd);
	    if (c->args) {
		sudo_lbuf_append(lbuf, " ");
		sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", c->args);
	    }
	    break;
	default:
	    /* Do not quote UID/GID, all others get quoted. */
	    if (m->name[0] == '#' &&
		m->name[strspn(m->name + 1, "0123456789") + 1] == '\0') {
		sudo_lbuf_append(lbuf, "%s%s", m->negated ? "!" : "", m->name);
	    } else {
		if (strpbrk(m->name, " \t") != NULL) {
		    sudo_lbuf_append(lbuf, "%s\"", m->negated ? "!" : "");
		    sudo_lbuf_append_quoted(lbuf, "\"", "%s", m->name);
		    sudo_lbuf_append(lbuf, "\"");
		} else {
		    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s%s",
			m->negated ? "!" : "", m->name);
		}
	    }
	    break;
    }
    debug_return_bool(!sudo_lbuf_error(lbuf));
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
	    print_member_sudoers(lbuf, m);
	}

	/* Print Defaults with the same binding, there may be multiple. */
	for (;;) {
	    next = TAILQ_NEXT(def, entries);
	    if (def->val != NULL) {
		sudo_lbuf_append(lbuf, " %s%s", def->var,
		    def->op == '+' ? "+=" : def->op == '-' ? "-=" : "=");
		if (strpbrk(def->val, " \t") != NULL) {
		    sudo_lbuf_append(lbuf, "\"");
		    sudo_lbuf_append_quoted(lbuf, "\"", "%s", def->val);
		    sudo_lbuf_append(lbuf, "\"");
		} else
		    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", def->val);
	    } else {
		sudo_lbuf_append(lbuf, " %s%s",
		    def->op == false ? "!" : "", def->var);
	    }
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
	print_member_sudoers(lbuf, m);
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

#define	TAG_CHANGED(ocs, ncs, tt) \
	(TAG_SET((ncs)->tags.tt) && \
	    ((ocs) == NULL || (ncs)->tags.tt != (ocs)->tags.tt))

/*
 * XXX - same as parse.c:sudo_file_append_cmnd()
 */
static bool
print_cmndspec_sudoers(struct cmndspec *cs, struct cmndspec *prev_cs,
    struct sudo_lbuf *lbuf)
{
    debug_decl(print_cmndspec_sudoers, SUDOERS_DEBUG_UTIL)

#ifdef HAVE_PRIV_SET
    if (cs->privs != NULL && cs->privs != prev_cs->privs)
	sudo_lbuf_append(lbuf, "PRIVS=\"%s\" ", cs->privs);
    if (cs->limitprivs != NULL && cs->limitprivs != prev_cs->limitprivs)
	sudo_lbuf_append(lbuf, "LIMITPRIVS=\"%s\" ", cs->limitprivs);
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
    if (cs->role != NULL && cs->role != prev_cs->role)
	sudo_lbuf_append(lbuf, "ROLE=%s ", cs->role);
    if (cs->type != NULL && cs->type != prev_cs->type)
	sudo_lbuf_append(lbuf, "TYPE=%s ", cs->type);
#endif /* HAVE_SELINUX */
    if (cs->timeout > 0 && cs->timeout != prev_cs->timeout) {
	char numbuf[(((sizeof(int) * 8) + 2) / 3) + 2];
	snprintf(numbuf, sizeof(numbuf), "%d", cs->timeout);
	sudo_lbuf_append(lbuf, "TIMEOUT=%s ", numbuf);
    }
    if (cs->notbefore != UNSPEC && cs->notbefore != prev_cs->notbefore) {
	char buf[sizeof("CCYYMMDDHHMMSSZ")];
	struct tm *tm = gmtime(&cs->notbefore);
	snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02dZ",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec);
	sudo_lbuf_append(lbuf, "NOTBEFORE=%s ", buf);
    }
    if (cs->notafter != UNSPEC && cs->notafter != prev_cs->notafter) {
	char buf[sizeof("CCYYMMDDHHMMSSZ")];
	struct tm *tm = gmtime(&cs->notafter);
	snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02dZ",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec);
	sudo_lbuf_append(lbuf, "NOTAFTER=%s ", buf);
    }
    if (TAG_CHANGED(prev_cs, cs, setenv))
	sudo_lbuf_append(lbuf, cs->tags.setenv ? "SETENV: " : "NOSETENV: ");
    if (TAG_CHANGED(prev_cs, cs, noexec))
	sudo_lbuf_append(lbuf, cs->tags.noexec ? "NOEXEC: " : "EXEC: ");
    if (TAG_CHANGED(prev_cs, cs, nopasswd))
	sudo_lbuf_append(lbuf, cs->tags.nopasswd ? "NOPASSWD: " : "PASSWD: ");
    if (TAG_CHANGED(prev_cs, cs, log_input))
	sudo_lbuf_append(lbuf, cs->tags.log_input ? "LOG_INPUT: " : "NOLOG_INPUT: ");
    if (TAG_CHANGED(prev_cs, cs, log_output))
	sudo_lbuf_append(lbuf, cs->tags.log_output ? "LOG_OUTPUT: " : "NOLOG_OUTPUT: ");
    if (TAG_CHANGED(prev_cs, cs, send_mail))
	sudo_lbuf_append(lbuf, cs->tags.send_mail ? "MAIL: " : "NOMAIL: ");
    if (TAG_CHANGED(prev_cs, cs, follow))
	sudo_lbuf_append(lbuf, cs->tags.follow ? "FOLLOW: " : "NOFOLLOW: ");
    print_member_sudoers(lbuf, cs->cmnd);
    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Derived from parse.c:sudo_file_display_priv_short()
 */
static bool
print_userspec_sudoers(struct sudo_lbuf *lbuf, struct userspec *us)
{
    struct cmndspec *cs, *prev_cs;
    struct privilege *priv;
    struct member *m;
    debug_decl(print_userspec_sudoers, SUDOERS_DEBUG_UTIL)

    /* Print users list. */
    TAILQ_FOREACH(m, &us->users, entries) {
	if (m != TAILQ_FIRST(&us->users))
	    sudo_lbuf_append(lbuf, ", ");
	print_member_sudoers(lbuf, m);
    }

    TAILQ_FOREACH(priv, &us->privileges, entries) {
	/* Print hosts list. */
	if (priv != TAILQ_FIRST(&us->privileges))
	    sudo_lbuf_append(lbuf, " : ");
	else
	    sudo_lbuf_append(lbuf, " ");
	TAILQ_FOREACH(m, &priv->hostlist, entries) {
	    if (m != TAILQ_FIRST(&priv->hostlist))
		sudo_lbuf_append(lbuf, ", ");
	    print_member_sudoers(lbuf, m);
	}

	/* Print commands. */
	sudo_lbuf_append(lbuf, " = ");
	prev_cs = NULL;
	TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	    if (prev_cs == NULL || RUNAS_CHANGED(cs, prev_cs)) {
		if (cs != TAILQ_FIRST(&priv->cmndlist))
		    sudo_lbuf_append(lbuf, ", ");
		if (cs->runasuserlist != NULL || cs->runasgrouplist != NULL)
		    sudo_lbuf_append(lbuf, "(");
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m != TAILQ_FIRST(cs->runasuserlist))
			    sudo_lbuf_append(lbuf, ", ");
			print_member_sudoers(lbuf, m);
		    }
		}
		if (cs->runasgrouplist != NULL) {
		    sudo_lbuf_append(lbuf, " : ");
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m != TAILQ_FIRST(cs->runasgrouplist))
			    sudo_lbuf_append(lbuf, ", ");
			print_member_sudoers(lbuf, m);
		    }
		}
		if (cs->runasuserlist != NULL || cs->runasgrouplist != NULL)
		    sudo_lbuf_append(lbuf, ") ");
	    } else if (cs != TAILQ_FIRST(&priv->cmndlist)) {
		sudo_lbuf_append(lbuf, ", ");
	    }
	    print_cmndspec_sudoers(cs, prev_cs, lbuf);
	    prev_cs = cs;
	}
    }
    sudo_lbuf_append(lbuf, "\n");

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Display User_Specs
 */
static bool
print_userspecs_sudoers(struct sudo_lbuf *lbuf)
{
    struct userspec *us;
    debug_decl(print_userspecs_sudoers, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH(us, &userspecs, entries) {
	if (!print_userspec_sudoers(lbuf, us))
	    break;
    }

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
    if (!print_userspecs_sudoers(&lbuf))
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
