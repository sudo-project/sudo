/*
 * Copyright (c) 1996, 1998-2005, 2007-2016
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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#ifdef HAVE_NETGROUP_H
# include <netgroup.h>
#endif /* HAVE_NETGROUP_H */
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "tsgetgrpw.h"
#include "sudoers.h"
#include "interfaces.h"
#include "parse.h"
#include "sudo_conf.h"
#include <gram.h>

#ifdef HAVE_FNMATCH
# include <fnmatch.h>
#else
# include "compat/fnmatch.h"
#endif /* HAVE_FNMATCH */

#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/*
 * Function Prototypes
 */
int  print_alias(void *, void *);
void dump_sudoers(void);
void print_defaults(void);
void print_privilege(struct privilege *);
void print_userspecs(void);
void usage(void) __attribute__((__noreturn__));
static void set_runaspw(const char *);
static void set_runasgr(const char *);
static bool cb_runas_default(const char *);
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
struct sudo_user sudo_user;
struct passwd *list_pw;
static char *runas_group, *runas_user;

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
extern char *malloc_options;
#endif
#if YYDEBUG
extern int sudoersdebug;
#endif

__dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    struct cmndspec *cs;
    struct privilege *priv;
    struct userspec *us;
    char *p, *grfile, *pwfile;
    const char *errstr;
    int match, host_match, runas_match, cmnd_match;
    int ch, dflag, exitcode = 0;
    debug_decl(main, SUDOERS_DEBUG_MAIN)

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    malloc_options = "AFGJPR";
#endif
#if YYDEBUG
    sudoersdebug = 1;
#endif

    initprogname(argc > 0 ? argv[0] : "testsudoers");

    if (!sudoers_initlocale(setlocale(LC_ALL, ""), def_sudoers_locale))
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    bindtextdomain("sudoers", LOCALEDIR); /* XXX - should have own domain */
    textdomain("sudoers");

    /* Initialize the debug subsystem. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
	exit(EXIT_FAILURE);
    sudoers_debug_register(getprogname(), sudo_conf_debug_files(getprogname()));

    dflag = 0;
    grfile = pwfile = NULL;
    while ((ch = getopt(argc, argv, "dg:G:h:P:p:tu:U:")) != -1) {
	switch (ch) {
	    case 'd':
		dflag = 1;
		break;
	    case 'h':
		user_host = optarg;
		break;
	    case 'G':
		sudoers_gid = (gid_t)sudo_strtoid(optarg, NULL, NULL, &errstr);
		if (errstr != NULL)
		    sudo_fatalx("group ID %s: %s", optarg, errstr);
		break;
	    case 'g':
		runas_group = optarg;
		break;
	    case 'p':
		pwfile = optarg;
		break;
	    case 'P':
		grfile = optarg;
		break;
	    case 't':
		trace_print = testsudoers_print;
		break;
	    case 'U':
		sudoers_uid = (uid_t)sudo_strtoid(optarg, NULL, NULL, &errstr);
		if (errstr != NULL)
		    sudo_fatalx("user ID %s: %s", optarg, errstr);
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
	sudo_fatalx(U_("unknown user: %s"), user_name);

    if (user_host == NULL) {
	if ((user_host = sudo_gethostname()) == NULL)
	    sudo_fatal("gethostname");
    }
    if ((p = strchr(user_host, '.'))) {
	*p = '\0';
	if ((user_shost = strdup(user_host)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	*p = '.';
    } else {
	user_shost = user_host;
    }
    user_runhost = user_host;
    user_srunhost = user_shost;

    /* Fill in user_args from argv. */
    if (argc > 0) {
	char *to, **from;
	size_t size, n;

	for (size = 0, from = argv; *from; from++)
	    size += strlen(*from) + 1;

	if ((user_args = malloc(size)) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	for (to = user_args, from = argv; *from; from++) {
	    n = strlcpy(to, *from, size - (to - user_args));
	    if (n >= size - (to - user_args))
		sudo_fatalx(U_("internal error, %s overflow"), getprogname());
	    to += n;
	    *to++ = ' ';
	}
	*--to = '\0';
    }

    /* Initialize default values. */
    if (!init_defaults())
	sudo_fatalx(U_("unable to initialize sudoers default values"));

    /* Set runas callback. */
    sudo_defs_table[I_RUNAS_DEFAULT].callback = cb_runas_default;

    /* Load ip addr/mask for each interface. */
    if (get_net_ifs(&p) > 0) {
	if (!set_interfaces(p))
	    sudo_fatal(U_("unable to parse network address list"));
    }

    /* Allocate space for data structures in the parser. */
    init_parser("sudoers", false);

    if (sudoersparse() != 0 || parse_error) {
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
	if (argc < 2) {
	    exitcode = parse_error ? 1 : 0;
	    goto done;
	}
    }

    /* This loop must match the one in sudo_file_lookup() */
    printf("\nEntries for user %s:\n", user_name);
    match = UNSPEC;
    TAILQ_FOREACH_REVERSE(us, &userspecs, userspec_list, entries) {
	if (userlist_matches(sudo_user.pw, &us->users) != ALLOW)
	    continue;
	TAILQ_FOREACH_REVERSE(priv, &us->privileges, privilege_list, entries) {
	    putchar('\n');
	    print_privilege(priv);
	    putchar('\n');
	    host_match = hostlist_matches(sudo_user.pw, &priv->hostlist);
	    if (host_match == ALLOW) {
		puts("\thost  matched");
		TAILQ_FOREACH_REVERSE(cs, &priv->cmndlist, cmndspec_list, entries) {
		    runas_match = runaslist_matches(cs->runasuserlist,
			cs->runasgrouplist, NULL, NULL);
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
    exitcode = parse_error ? 1 : (match == ALLOW ? 0 : match + 3);
done:
    sudo_freepwcache();
    sudo_freegrcache();
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);
    exit(exitcode);
}

static void
set_runaspw(const char *user)
{
    struct passwd *pw = NULL;
    debug_decl(set_runaspw, SUDOERS_DEBUG_UTIL)

    if (*user == '#') {
	const char *errstr;
	uid_t uid = sudo_strtoid(user + 1, NULL, NULL, &errstr);
	if (errstr == NULL) {
	    if ((pw = sudo_getpwuid(uid)) == NULL)
		pw = sudo_fakepwnam(user, user_gid);
	}
    }
    if (pw == NULL) {
	if ((pw = sudo_getpwnam(user)) == NULL)
	    sudo_fatalx(U_("unknown user: %s"), user);
    }
    if (runas_pw != NULL)
	sudo_pw_delref(runas_pw);
    runas_pw = pw;
    debug_return;
}

static void
set_runasgr(const char *group)
{
    struct group *gr = NULL;
    debug_decl(set_runasgr, SUDOERS_DEBUG_UTIL)

    if (*group == '#') {
	const char *errstr;
	gid_t gid = sudo_strtoid(group + 1, NULL, NULL, &errstr);
	if (errstr == NULL) {
	    if ((gr = sudo_getgrgid(gid)) == NULL)
		gr = sudo_fakegrnam(group);
	}
    }
    if (gr == NULL) {
	if ((gr = sudo_getgrnam(group)) == NULL)
	    sudo_fatalx(U_("unknown group: %s"), group);
    }
    if (runas_gr != NULL)
	sudo_gr_delref(runas_gr);
    runas_gr = gr;
    debug_return;
}

/* 
 * Callback for runas_default sudoers setting.
 */
static bool
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

FILE *
open_sudoers(const char *sudoers, bool doedit, bool *keepopen)
{
    struct stat sb;
    FILE *fp = NULL;
    char *sudoers_base;
    debug_decl(open_sudoers, SUDOERS_DEBUG_UTIL)

    sudoers_base = strrchr(sudoers, '/');
    if (sudoers_base != NULL)
	sudoers_base++;

    switch (sudo_secure_file(sudoers, sudoers_uid, sudoers_gid, &sb)) {
	case SUDO_PATH_SECURE:
	    fp = fopen(sudoers, "r");
	    break;
	case SUDO_PATH_MISSING:
	    sudo_warn("unable to stat %s", sudoers_base);
	    break;
	case SUDO_PATH_BAD_TYPE:
	    sudo_warnx("%s is not a regular file", sudoers_base);
	    break;
	case SUDO_PATH_WRONG_OWNER:
	    sudo_warnx("%s should be owned by uid %u",
		sudoers_base, (unsigned int) sudoers_uid);
	    break;
	case SUDO_PATH_WORLD_WRITABLE:
	    sudo_warnx("%s is world writable", sudoers_base);
	    break;
	case SUDO_PATH_GROUP_WRITABLE:
	    sudo_warnx("%s should be owned by gid %u",
		sudoers_base, (unsigned int) sudoers_gid);
	    break;
	default:
	    /* NOTREACHED */
	    break;
    }

    debug_return_ptr(fp);
}

bool
init_envtables(void)
{
    return(true);
}

bool
set_perms(int perm)
{
    return true;
}

bool
restore_perms(void)
{
    return true;
}

void
print_member(struct member *m)
{
    struct sudo_command *c;
    debug_decl(print_member, SUDOERS_DEBUG_UTIL)

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

    debug_return;
}

void
print_defaults(void)
{
    struct defaults *d;
    struct member *m;
    debug_decl(print_defaults, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH(d, &defaults, entries) {
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
	TAILQ_FOREACH(m, d->binding, entries) {
	    if (m != TAILQ_FIRST(d->binding))
		putchar(',');
	    print_member(m);
	}
	printf("\t%s%s", d->op == false ? "!" : "", d->var);
	if (d->val != NULL) {
	    printf("%c%s", d->op == true ? '=' : d->op, d->val);
	}
	putchar('\n');
    }

    debug_return;
}

int
print_alias(void *v1, void *v2)
{
    struct alias *a = (struct alias *)v1;
    struct member *m;
    struct sudo_command *c;
    debug_decl(print_alias, SUDOERS_DEBUG_UTIL)

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
    TAILQ_FOREACH(m, &a->members, entries) {
	if (m != TAILQ_FIRST(&a->members))
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
    debug_return_int(0);
}

#define TAG_SET(tt) \
    ((tt) != UNSPEC && (tt) != IMPLIED)

#define TAG_CHANGED(t) \
    (TAG_SET(cs->tags.t) && cs->tags.t != tags.t)

void
print_privilege(struct privilege *priv)
{
    struct cmndspec *cs;
    struct member *m;
    struct cmndtag tags;
    debug_decl(print_privilege, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH(m, &priv->hostlist, entries) {
	if (m != TAILQ_FIRST(&priv->hostlist))
	    fputs(", ", stdout);
	print_member(m);
    }
    fputs(" = ", stdout);
    TAGS_INIT(tags);
    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	if (cs != TAILQ_FIRST(&priv->cmndlist))
	    fputs(", ", stdout);
	if (cs->runasuserlist != NULL || cs->runasgrouplist != NULL) {
	    fputs("(", stdout);
	    if (cs->runasuserlist != NULL) {
		TAILQ_FOREACH(m, cs->runasuserlist, entries) {
		    if (m != TAILQ_FIRST(cs->runasuserlist))
			fputs(", ", stdout);
		    print_member(m);
		}  
	    } else if (cs->runasgrouplist == NULL) {
		fputs(def_runas_default, stdout);
	    } else {
		fputs(sudo_user.pw->pw_name, stdout);
	    }
	    if (cs->runasgrouplist != NULL) {
		fputs(" : ", stdout);
		TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
		    if (m != TAILQ_FIRST(cs->runasgrouplist))
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
#ifdef HAVE_PRIV_SET
	if (cs->privs)
	    printf("PRIVS=%s ", cs->privs);
	if (cs->limitprivs)
	    printf("LIMITPRIVS=%s ", cs->limitprivs);
#endif /* HAVE_PRIV_SET */
	if (TAG_CHANGED(follow))
	    printf("%sFOLLOW: ", cs->tags.follow ? "" : "NO");
	if (TAG_CHANGED(log_input))
	    printf("%sLOG_INPUT: ", cs->tags.log_input ? "" : "NO");
	if (TAG_CHANGED(log_output))
	    printf("%sLOG_OUTPUT: ", cs->tags.log_output ? "" : "NO");
	if (TAG_CHANGED(noexec))
	    printf("%sEXEC: ", cs->tags.noexec ? "NO" : "");
	if (TAG_CHANGED(nopasswd))
	    printf("%sPASSWD: ", cs->tags.nopasswd ? "NO" : "");
	if (TAG_CHANGED(send_mail))
	    printf("%sMAIL: ", cs->tags.send_mail ? "" : "NO");
	if (TAG_CHANGED(setenv))
	    printf("%sSETENV: ", cs->tags.setenv ? "" : "NO");
	print_member(cs->cmnd);
	memcpy(&tags, &cs->tags, sizeof(tags));
    }
    debug_return;
}

void
print_userspecs(void)
{
    struct member *m;
    struct userspec *us;
    struct privilege *priv;
    debug_decl(print_userspecs, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH(us, &userspecs, entries) {
	TAILQ_FOREACH(m, &us->users, entries) {
	    if (m != TAILQ_FIRST(&us->users))
		fputs(", ", stdout);
	    print_member(m);
	}
	putchar('\t');
	TAILQ_FOREACH(priv, &us->privileges, entries) {
	    if (priv != TAILQ_FIRST(&us->privileges))
		fputs(" : ", stdout);
	    print_privilege(priv);
	}
	putchar('\n');
    }
    debug_return;
}

void
dump_sudoers(void)
{
    debug_decl(dump_sudoers, SUDOERS_DEBUG_UTIL)

    print_defaults();

    putchar('\n');
    alias_apply(print_alias, NULL);

    putchar('\n');
    print_userspecs();

    debug_return;
}

static int testsudoers_print(const char *msg)
{
    return fputs(msg, stderr);
}

void
usage(void)
{
    (void) fprintf(stderr, "usage: %s [-dt] [-G sudoers_gid] [-g group] [-h host] [-P grfile] [-p pwfile] [-U sudoers_uid] [-u user] <user> <command> [args]\n", getprogname());
    exit(1);
}
