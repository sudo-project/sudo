/*
 * Copyright (c) 1996, 1998-2005, 2007-2012
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#define _SUDO_MAIN

#include <config.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
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
#ifdef HAVE_FNMATCH
# include <fnmatch.h>
#endif /* HAVE_FNMATCH */
#ifdef HAVE_NETGROUP_H
# include <netgroup.h>
#endif /* HAVE_NETGROUP_H */
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SUDO_ERROR_WRAP 0 /* XXX */

#include "tsgetgrpw.h"
#include "sudoers.h"
#include "interfaces.h"
#include "parse.h"
#include <gram.h>

#ifndef HAVE_FNMATCH
# include "compat/fnmatch.h"
#endif /* HAVE_FNMATCH */

/*
 * Function Prototypes
 */
int  print_alias(void *, void *);
void dump_sudoers(void);
void print_defaults(void);
void print_privilege(struct privilege *);
void print_userspecs(void);
void usage(void) __attribute__((__noreturn__));
void cleanup(int);
static void set_runaspw(const char *);
static void set_runasgr(const char *);
static int cb_runas_default(const char *);
static int testsudoers_printf(int msg_type, const char *fmt, ...);
static int testsudoers_print(const char *msg);

extern void setgrfile(const char *);
extern void setgrent(void);
extern void endgrent(void);
extern struct group *getgrent(void);
extern struct group *getgrnam(const char *);
extern struct group *getgrgid(gid_t);
extern void setpwfile(const char *);
extern void setpwent(void);
extern void endpwent(void);
extern struct passwd *getpwent(void);
extern struct passwd *getpwnam(const char *);
extern struct passwd *getpwuid(uid_t);

extern int (*trace_print)(const char *msg);

/*
 * Globals
 */
struct interface *interfaces;
struct sudo_user sudo_user;
struct passwd *list_pw;
static char *runas_group, *runas_user;
extern int errorlineno;
extern bool parse_error;
extern char *errorfile;
sudo_printf_t sudo_printf = testsudoers_printf;
sudo_conv_t sudo_conv;	/* NULL in non-plugin */

/* For getopt(3) */
extern char *optarg;
extern int optind;

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
extern char *malloc_options;
#endif
#ifdef YYDEBUG
extern int yydebug;
#endif

int
main(int argc, char *argv[])
{
    struct cmndspec *cs;
    struct privilege *priv;
    struct userspec *us;
    char *p, *grfile, *pwfile;
    char hbuf[MAXHOSTNAMELEN + 1];
    int match, host_match, runas_match, cmnd_match;
    int ch, dflag;

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    malloc_options = "AFGJPR";
#endif
#ifdef YYDEBUG
    yydebug = 1;
#endif

#if !defined(HAVE_GETPROGNAME) && !defined(HAVE___PROGNAME)
    setprogname(argc > 0 ? argv[0] : "testsudoers");
#endif

    dflag = 0;
    grfile = pwfile = NULL;
    while ((ch = getopt(argc, argv, "dg:G:h:p:tu:")) != -1) {
	switch (ch) {
	    case 'd':
		dflag = 1;
		break;
	    case 'h':
		user_host = optarg;
		break;
	    case 'G':
		grfile = optarg;
		break;
	    case 'g':
		runas_group = optarg;
		break;
	    case 'p':
		pwfile = optarg;
		break;
	    case 't':
		trace_print = testsudoers_print;
		break;
	    case 'u':
		runas_user = optarg;
		break;
	    default:
		usage();
		break;
	}
    }
    argc -= optind;
    argv += optind;

    /* Set group/passwd file and init the cache. */
    if (grfile)
	setgrfile(grfile);
    if (pwfile)
	setpwfile(pwfile);
    sudo_setpwent();
    sudo_setgrent();

    if (argc < 2) {
	if (!dflag)
	    usage();
	user_name = argc ? *argv++ : "root";
	user_cmnd = user_base = "true";
	argc = 0;
    } else {
	user_name = *argv++;
	user_cmnd = *argv++;
	if ((p = strrchr(user_cmnd, '/')) != NULL)
	    user_base = p + 1;
	else
	    user_base = user_cmnd;
	argc -= 2;
    }
    if ((sudo_user.pw = sudo_getpwnam(user_name)) == NULL)
	errorx(1, _("unknown user: %s"), user_name);

    if (user_host == NULL) {
	if (gethostname(hbuf, sizeof(hbuf)) != 0)
	    error(1, "gethostname");
	hbuf[sizeof(hbuf) - 1] = '\0';
	user_host = hbuf;
    }
    if ((p = strchr(user_host, '.'))) {
	*p = '\0';
	user_shost = estrdup(user_host);
	*p = '.';
    } else {
	user_shost = user_host;
    }

    /* Fill in user_args from argv. */
    if (argc > 0) {
	char *to, **from;
	size_t size, n;

	for (size = 0, from = argv; *from; from++)
	    size += strlen(*from) + 1;

	user_args = (char *) emalloc(size);
	for (to = user_args, from = argv; *from; from++) {
	    n = strlcpy(to, *from, size - (to - user_args));
	    if (n >= size - (to - user_args))
		    errorx(1, _("internal error, init_vars() overflow"));
	    to += n;
	    *to++ = ' ';
	}
	*--to = '\0';
    }

    /* Initialize default values. */
    init_defaults();

    /* Set runas callback. */
    sudo_defs_table[I_RUNAS_DEFAULT].callback = cb_runas_default;

    /* Load ip addr/mask for each interface. */
    if (get_net_ifs(&p) > 0)
	set_interfaces(p);

    /* Allocate space for data structures in the parser. */
    init_parser("sudoers", 0);

    if (yyparse() != 0 || parse_error) {
	parse_error = true;
	if (errorlineno != -1)
	    (void) printf("Parse error in %s near line %d",
		errorfile, errorlineno);
	else
	    (void) printf("Parse error in %s", errorfile);
    } else {
	(void) fputs("Parses OK", stdout);
    }

    if (!update_defaults(SETDEF_ALL))
	(void) fputs(" (problem with defaults entries)", stdout);
    puts(".");

    if (def_group_plugin && group_plugin_load(def_group_plugin) != true)
	def_group_plugin = NULL;

    /*
     * Set runas passwd/group entries based on command line or sudoers.
     * Note that if runas_group was specified without runas_user we
     * defer setting runas_pw so the match routines know to ignore it.
     */
    if (runas_group != NULL) {
        set_runasgr(runas_group);
        if (runas_user != NULL)
            set_runaspw(runas_user);
    } else
        set_runaspw(runas_user ? runas_user : def_runas_default);

    if (dflag) {
	(void) putchar('\n');
	dump_sudoers();
	if (argc < 2)
	    exit(parse_error ? 1 : 0);
    }

    /* This loop must match the one in sudo_file_lookup() */
    printf("\nEntries for user %s:\n", user_name);
    match = UNSPEC;
    tq_foreach_rev(&userspecs, us) {
	if (userlist_matches(sudo_user.pw, &us->users) != ALLOW)
	    continue;
	tq_foreach_rev(&us->privileges, priv) {
	    putchar('\n');
	    print_privilege(priv); /* XXX */
	    putchar('\n');
	    host_match = hostlist_matches(&priv->hostlist);
	    if (host_match == ALLOW) {
		puts("\thost  matched");
		tq_foreach_rev(&priv->cmndlist, cs) {
		    runas_match = runaslist_matches(&cs->runasuserlist,
			&cs->runasgrouplist);
		    if (runas_match == ALLOW) {
			puts("\trunas matched");
			cmnd_match = cmnd_matches(cs->cmnd);
			if (cmnd_match != UNSPEC)
			    match = cmnd_match;
			printf("\tcmnd  %s\n", match == ALLOW ? "allowed" :
			    match == DENY ? "denied" : "unmatched");
		    }
		}
	    } else
		puts(_("\thost  unmatched"));
	}
    }
    puts(match == ALLOW ? _("\nCommand allowed") :
	match == DENY ?  _("\nCommand denied") :  _("\nCommand unmatched"));

    /*
     * Exit codes:
     *	0 - parsed OK and command matched.
     *	1 - parse error
     *	2 - command not matched
     *	3 - command denied
     */
    if (parse_error)
	exit(1);
    exit(match == ALLOW ? 0 : match + 3);
}

static void
set_runaspw(const char *user)
{
    if (runas_pw != NULL)
	pw_delref(runas_pw);
    if (*user == '#') {
	if ((runas_pw = sudo_getpwuid(atoi(user + 1))) == NULL)
	    runas_pw = sudo_fakepwnam(user, runas_gr ? runas_gr->gr_gid : 0);
    } else {
	if ((runas_pw = sudo_getpwnam(user)) == NULL)
	    errorx(1, _("unknown user: %s"), user);
    }
}

static void
set_runasgr(const char *group)
{
    if (runas_gr != NULL)
	gr_delref(runas_gr);
    if (*group == '#') {
	if ((runas_gr = sudo_getgrgid(atoi(group + 1))) == NULL)
	    runas_gr = sudo_fakegrnam(group);
    } else {
	if ((runas_gr = sudo_getgrnam(group)) == NULL)
	    errorx(1, _("unknown group: %s"), group);
    }
}

/* 
 * Callback for runas_default sudoers setting.
 */
static int
cb_runas_default(const char *user)
{
    /* Only reset runaspw if user didn't specify one. */
    if (!runas_user && !runas_group)
        set_runaspw(user);
    return true;
}

void
sudo_setspent(void)
{
    return;
}

void
sudo_endspent(void)
{
    return;
}

void
set_fqdn(void)
{
    return;
}

FILE *
open_sudoers(const char *path, bool doedit, bool *keepopen)
{
    return fopen(path, "r");
}

void
init_envtables(void)
{
    return;
}

int
set_perms(int perm)
{
    return 1;
}

void
restore_perms(void)
{
}

void
cleanup(int gotsignal)
{
    if (!gotsignal) {
	sudo_endpwent();
	sudo_endgrent();
    }
}

void
print_member(struct member *m)
{
    struct sudo_command *c;

    if (m->negated)
	putchar('!');
    if (m->name == NULL)
	fputs("ALL", stdout);
    else if (m->type != COMMAND)
	fputs(m->name, stdout);
    else {
	c = (struct sudo_command *) m->name;
	printf("%s%s%s", c->cmnd, c->args ? " " : "",
	    c->args ? c->args : "");
    }
}

void
print_defaults(void)
{
    struct defaults *d;
    struct member *m;

    tq_foreach_fwd(&defaults, d) {
	(void) fputs("Defaults", stdout);
	switch (d->type) {
	    case DEFAULTS_HOST:
		putchar('@');
		break;
	    case DEFAULTS_USER:
		putchar(':');
		break;
	    case DEFAULTS_RUNAS:
		putchar('>');
		break;
	    case DEFAULTS_CMND:
		putchar('!');
		break;
	}
	tq_foreach_fwd(&d->binding, m) {
	    if (m != tq_first(&d->binding))
		putchar(',');
	    print_member(m);
	}
	printf("\t%s%s", d->op == false ? "!" : "", d->var);
	if (d->val != NULL) {
	    printf("%c%s", d->op == true ? '=' : d->op, d->val);
	}
	putchar('\n');
    }
}

int
print_alias(void *v1, void *v2)
{
    struct alias *a = (struct alias *)v1;
    struct member *m;
    struct sudo_command *c;

    switch (a->type) {
	case HOSTALIAS:
	    (void) printf("Host_Alias\t%s = ", a->name);
	    break;
	case CMNDALIAS:
	    (void) printf("Cmnd_Alias\t%s = ", a->name);
	    break;
	case USERALIAS:
	    (void) printf("User_Alias\t%s = ", a->name);
	    break;
	case RUNASALIAS:
	    (void) printf("Runas_Alias\t%s = ", a->name);
	    break;
    }
    tq_foreach_fwd(&a->members, m) {
	if (m != tq_first(&a->members))
	    fputs(", ", stdout);
	if (m->type == COMMAND) {
	    c = (struct sudo_command *) m->name;
	    printf("%s%s%s", c->cmnd, c->args ? " " : "",
		c->args ? c->args : "");
	} else if (m->type == ALL) {
	    fputs("ALL", stdout);
	} else {
	    fputs(m->name, stdout);
	}
    }
    putchar('\n');
    return 0;
}

void
print_privilege(struct privilege *priv)
{
    struct cmndspec *cs;
    struct member *m;
    struct privilege *p;
    struct cmndtag tags;

    for (p = priv; p != NULL; p = p->next) {
	if (p != priv)
	    fputs(" : ", stdout);
	tq_foreach_fwd(&p->hostlist, m) {
	    if (m != tq_first(&p->hostlist))
		fputs(", ", stdout);
	    print_member(m);
	}
	fputs(" = ", stdout);
	tags.nopasswd = tags.noexec = UNSPEC;
	tq_foreach_fwd(&p->cmndlist, cs) {
	    if (cs != tq_first(&p->cmndlist))
		fputs(", ", stdout);
	    if (!tq_empty(&cs->runasuserlist) || !tq_empty(&cs->runasgrouplist)) {
		fputs("(", stdout);
		if (!tq_empty(&cs->runasuserlist)) {
		    tq_foreach_fwd(&cs->runasuserlist, m) {
			if (m != tq_first(&cs->runasuserlist))
			    fputs(", ", stdout);
			print_member(m);
		    }  
		} else if (tq_empty(&cs->runasgrouplist)) {
		    fputs(def_runas_default, stdout);
		} else {
		    fputs(sudo_user.pw->pw_name, stdout);
		}
		if (!tq_empty(&cs->runasgrouplist)) {
		    fputs(" : ", stdout);
		    tq_foreach_fwd(&cs->runasgrouplist, m) {
			if (m != tq_first(&cs->runasgrouplist))
			    fputs(", ", stdout);
			print_member(m);
		    }
		}
		fputs(") ", stdout);
	    }
#ifdef HAVE_SELINUX
	    if (cs->role)
		printf("ROLE=%s ", cs->role);
	    if (cs->type)
		printf("TYPE=%s ", cs->type);
#endif /* HAVE_SELINUX */
	    if (cs->tags.nopasswd != UNSPEC && cs->tags.nopasswd != tags.nopasswd)
		printf("%sPASSWD: ", cs->tags.nopasswd ? "NO" : "");
	    if (cs->tags.noexec != UNSPEC && cs->tags.noexec != tags.noexec)
		printf("%sEXEC: ", cs->tags.noexec ? "NO" : "");
	    print_member(cs->cmnd);
	    memcpy(&tags, &cs->tags, sizeof(tags));
	}
    }
}

void
print_userspecs(void)
{
    struct member *m;
    struct userspec *us;

    tq_foreach_fwd(&userspecs, us) {
	tq_foreach_fwd(&us->users, m) {
	    if (m != tq_first(&us->users))
		fputs(", ", stdout);
	    print_member(m);
	}
	putchar('\t');
	print_privilege(us->privileges.first); /* XXX */
	putchar('\n');
    }
}

static int
testsudoers_printf(int msg_type, const char *fmt, ...)
{
    va_list ap;
    FILE *fp;
            
    switch (msg_type) {
    case SUDO_CONV_INFO_MSG:
	fp = stdout;
	break;
    case SUDO_CONV_ERROR_MSG:
	fp = stderr;
	break;
    default:
	errno = EINVAL;
	return -1;
    }
   
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
   
    return 0;
}

void
dump_sudoers(void)
{
    print_defaults();

    putchar('\n');
    alias_apply(print_alias, NULL);

    putchar('\n');
    print_userspecs();
}

static int testsudoers_print(const char *msg)
{
    return fputs(msg, stderr);
}

void
usage(void)
{
    (void) fprintf(stderr, "usage: %s [-dt] [-G grfile] [-g group] [-h host] [-p pwfile] [-u user] <user> <command> [args]\n", getprogname());
    exit(1);
}
