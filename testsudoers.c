/*
 * Copyright (c) 1996, 1998-2004 Todd C. Miller <Todd.Miller@courtesan.com>
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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
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
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "sudo.h"
#include "interfaces.h"
#include "parse.h"
#include <gram.h>

#ifndef HAVE_FNMATCH
# include "emul/fnmatch.h"
#endif /* HAVE_FNMATCH */

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */


/*
 * Globals
 */
int  Argc, NewArgc;
char **Argv, **NewArgv;
int num_interfaces;
struct interface *interfaces;
struct sudo_user sudo_user;
extern int parse_error;

/* For getopt(3) */
extern char *optarg;
extern int optind;

extern struct defaults *defaults;
extern struct userspec *userspecs;

int  print_alias __P((VOID *, VOID *));
void dump_sudoers __P((void));
void print_defaults __P((void));
void print_privilege __P((struct privilege *));
void print_userspecs __P((void));
void usage __P((void)) __attribute__((__noreturn__));

int
main(argc, argv)
    int argc;
    char **argv;
{
    struct cmndspec *cs;
    struct passwd pw, rpw;
    struct member *runas;
    struct privilege *priv;
    struct userspec *us;
    char *p, hbuf[MAXHOSTNAMELEN];
    int ch, dflag, rval, matched;
#ifdef	YYDEBUG
    extern int yydebug;
    yydebug = 1;
#endif

    Argv = argv;
    Argc = argc;

    memset(&pw, 0, sizeof(pw));
    sudo_user.pw = &pw;
    memset(&rpw, 0, sizeof(rpw));
    runas_pw = &rpw;

    dflag = 0;
    while ((ch = getopt(argc, argv, "dh:u:")) != -1) {
	switch (ch) {
	    case 'd':
		dflag = 1;
		break;
	    case 'h':
		user_host = optarg;
		break;
	    case 'u':
		user_runas = &optarg;
		break;
	    default:
		usage();
		break;
	}
    }
    argc -= optind;
    argv += optind;
    NewArgc = argc;
    NewArgv = argv;
    if (argc < 2) {
	if (!dflag)
	    usage();
	user_name = "nobody";
	user_cmnd = user_base = "true";
    } else {
	user_name = *argv++;
	user_cmnd = *argv;
	if ((p = strrchr(user_cmnd, '/')) != NULL)
	    user_base = p + 1;
	else
	    user_base = user_cmnd;
	NewArgc -= 2;
    }

    if (user_host == NULL) {
	if (gethostname(hbuf, sizeof(hbuf)) != 0)
	    error(1, "gethostname");
	user_host = hbuf;
    }
    if ((p = strchr(user_host, '.'))) {
	*p = '\0';
	user_shost = estrdup(user_host);
	*p = '.';
    } else {
	user_shost = user_host;
    }

    /* Fill in user_args from NewArgv. */
    if (NewArgc > 1) {
	char *to, **from;
	size_t size, n;

	size = (size_t) (NewArgv[NewArgc-1] - NewArgv[1]) +
		strlen(NewArgv[NewArgc-1]) + 1;
	user_args = (char *) emalloc(size);
	for (to = user_args, from = NewArgv + 1; *from; from++) {
	    n = strlcpy(to, *from, size - (to - user_args));
	    if (n >= size - (to - user_args))
		    errorx(1, "internal error, init_vars() overflow");
	    to += n;
	    *to++ = ' ';
	}
	*--to = '\0';
    }

    /* Initialize default values. */
    init_defaults();
    runas_pw->pw_name = *user_runas;

    /* Load ip addr/mask for each interface. */
    load_interfaces();

    /* Allocate space for data structures in the parser. */
    init_parser("sudoers", 0);

    if (yyparse() != 0 || parse_error)
	(void) fputs("Does not parse", stdout);
    else
	(void) fputs("Parses OK", stdout);

    if (!update_defaults(SET_ALL))
	(void) fputs(" (problem with defaults entries)", stdout);
    puts(".");

    if (dflag) {
	(void) putchar('\n');
	dump_sudoers();
	if (argc < 2)
	    exit(0);
    }

    /* This loop must match the one in sudoers_lookup() */
    printf("\nEntries for user %s:\n", user_name);
    matched = UNSPEC;
    for (us = userspecs; us != NULL; us = us->next) {
	if (user_matches(sudo_user.pw, us->user) == TRUE) {
	    for (priv = us->privileges; priv != NULL; priv = priv->next) {
		putchar('\n');
		print_privilege(priv);
		putchar('\n');
		if (host_matches(priv->hostlist) == TRUE) {
		    puts("\thost  matched");
		    runas = NULL;
		    for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
			if (cs->runaslist != NULL)
			    runas = cs->runaslist;
			if (runas_matches(runas) == TRUE) {
			    puts("\trunas matched");
			    rval = cmnd_matches(cs->cmnd);
			    if (rval != UNSPEC)
				matched = rval;
			    printf("\tcmnd  %s\n", rval == ALLOW ? "allowed" :
				rval == DENY ? "denied" : "unmatched");
			}
		    }
		} else
		    puts("\thost  unmatched");
	    }
	}
    }
    printf("\nCommand %s\n", matched == TRUE ? "allowed" :
	matched == FALSE ? "denied" : "unmatched");

    exit(0);
}

void
set_fqdn()
{
    return;
}

int
set_runaspw(user)
    char *user;
{
    return(TRUE);
}

FILE *
open_sudoers(path, keepopen)
    const char *path;
    int *keepopen;
{
    return(fopen(path, "r"));
}

void
init_envtables()
{
    return;
}

void
set_perms(perm)
    int perm;
{
    return;
}

struct passwd *
sudo_getpwuid(uid)
    uid_t uid;
{
    return(getpwuid(uid));
}

struct passwd *
sudo_getpwnam(name)
    const char *name;
{ 
    return(getpwnam(name));
}

struct group *
sudo_getgrgid(gid)
    gid_t gid;
{
    return(getgrgid(gid));
}

struct group *
sudo_getgrnam(name)
    const char *name;
{
    return(getgrnam(name));
}

void
cleanup()
{
    return;
}

void
print_member(m)    
    struct member *m;
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
print_defaults()
{
    struct defaults *d;
    struct member *m;

    for (d = defaults; d != NULL; d = d->next) {
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
	for (m = d->binding; m != NULL; m = m->next) {
	    if (m != d->binding)
		putchar(',');
	    print_member(m);
	}
	printf("\t%s%s", d->op == FALSE ? "!" : "", d->var);
	if (d->val != NULL) {
	    printf("%c%s", d->op == TRUE ? '=' : d->op, d->val);
	}
	putchar('\n');
    }
}

int
print_alias(v1, v2)
    VOID *v1, *v2;
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
    for (m = a->first_member; m != NULL; m = m->next) {
	if (m != a->first_member)
	    fputs(", ", stdout);
	if (m->type == COMMAND) {
	    c = (struct sudo_command *) m->name;
	    printf("%s%s%s", c->cmnd, c->args ? " " : "",
		c->args ? c->args : "");
	} else
	    fputs(m->name, stdout);
    }
    putchar('\n');
    return(0);
}

void
print_privilege(priv)
    struct privilege *priv;
{
    struct cmndspec *cs;
    struct member *m;
    struct privilege *p;
    struct cmndtag tags;

    for (p = priv; p != NULL; p = p->next) {
	if (p != priv)
	    fputs(" : ", stdout);
	for (m = p->hostlist; m != NULL; m = m->next) {
	    if (m != p->hostlist)
		fputs(", ", stdout);
	    print_member(m);
	}
	fputs(" = ", stdout);
	tags.nopasswd = tags.noexec = tags.monitor = UNSPEC;
	for (cs = p->cmndlist; cs != NULL; cs = cs->next) {
	    if (cs != p->cmndlist)
		fputs(", ", stdout);
	    if (cs->runaslist) {
		fputs("(", stdout);
		for (m = cs->runaslist; m != NULL; m = m->next) {
		    if (m != cs->runaslist)
			fputs(", ", stdout);
		    print_member(m);
		}
		fputs(") ", stdout);
	    }
	    if (cs->tags.nopasswd != UNSPEC && cs->tags.nopasswd != tags.nopasswd)
		printf("%sPASSWD: ", cs->tags.nopasswd ? "NO" : "");
	    if (cs->tags.noexec != UNSPEC && cs->tags.noexec != tags.noexec)
		printf("%sEXEC: ", cs->tags.noexec ? "NO" : "");
	    if (cs->tags.monitor != UNSPEC && cs->tags.monitor != tags.monitor)
		printf("%sMONITOR: ", cs->tags.monitor ? "" : "NO");
	    print_member(cs->cmnd);
	    memcpy(&tags, &cs->tags, sizeof(tags));
	}
    }
}

void
print_userspecs()
{
    struct member *m;
    struct userspec *us;

    for (us = userspecs; us != NULL; us = us->next) {
	for (m = us->user; m != NULL; m = m->next) {
	    if (m != us->user)
		fputs(", ", stdout);
	    print_member(m);
	}
	putchar('\t');
	print_privilege(us->privileges);
	putchar('\n');
    }
}

void
dump_sudoers()
{
    print_defaults();

    putchar('\n');
    alias_apply(print_alias, NULL);

    putchar('\n');
    print_userspecs();
}

void
usage()
{
    (void) fprintf(stderr,
	"usage: %s [-h host] [-u user] <user> <command> [args]\n",
	    getprogname());
    exit(1);
}
