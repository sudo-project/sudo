%{
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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#if defined(YYBISON) && defined(HAVE_ALLOCA_H) && !defined(__GNUC__)
# include <alloca.h>
#endif /* YYBISON && HAVE_ALLOCA_H && !__GNUC__ */

#include "sudo.h"
#include "parse.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Globals
 */
extern int sudolineno;
extern char *sudoers;
int parse_error;
int pedantic = FALSE;
int verbose = FALSE;
int errorlineno = -1;
char *errorfile = NULL;

struct defaults *defaults;
struct userspec *userspecs;

/*
 * Local protoypes
 */
static void  add_defaults	__P((int, struct member *, struct defaults *));
static void  add_userspec	__P((struct member *, struct privilege *));
       void  yyerror		__P((const char *));

void
yyerror(s)
    const char *s;
{
    /* Save the line the first error occurred on. */
    if (errorlineno == -1) {
	errorlineno = sudolineno ? sudolineno - 1 : 0;
	errorfile = estrdup(sudoers);
    }
    if (verbose && s != NULL) {
#ifndef TRACELEXER
	(void) fprintf(stderr, ">>> %s: %s near line %d <<<\n", sudoers, s,
	    sudolineno ? sudolineno - 1 : 0);
#else
	(void) fprintf(stderr, "<*> ");
#endif
    }
    parse_error = TRUE;
}
%}

%union {
    struct cmndspec *cmndspec;
    struct defaults *defaults;
    struct member *member;
    struct privilege *privilege;
    struct sudo_command command;
    struct cmndtag tag;
    char *string;
    int tok;
}

%start file				/* special start symbol */
%token <command> COMMAND		/* absolute pathname w/ optional args */
%token <string>  ALIAS			/* an UPPERCASE alias name */
%token <string>	 DEFVAR			/* a Defaults variable name */
%token <string>  NTWKADDR		/* w.x.y.z */
%token <string>  NETGROUP		/* a netgroup (+NAME) */
%token <string>  USERGROUP		/* a usergroup (%NAME) */
%token <string>  WORD			/* a word */
%token <tok>	 DEFAULTS		/* Defaults entry */
%token <tok>	 DEFAULTS_HOST		/* Host-specific defaults entry */
%token <tok>	 DEFAULTS_USER		/* User-specific defaults entry */
%token <tok>	 DEFAULTS_RUNAS		/* Runas-specific defaults entry */
%token <tok> 	 RUNAS			/* ( runas_list ) */
%token <tok> 	 NOPASSWD		/* no passwd req for command */
%token <tok> 	 PASSWD			/* passwd req for command (default) */
%token <tok> 	 NOEXEC			/* preload dummy execve() for cmnd */
%token <tok> 	 EXEC			/* don't preload dummy execve() */
%token <tok> 	 MONITOR		/* monitor children of cmnd */
%token <tok> 	 NOMONITOR		/* disable monitoring of children */
%token <tok>	 ALL			/* ALL keyword */
%token <tok>	 COMMENT		/* comment and/or carriage return */
%token <tok>	 HOSTALIAS		/* Host_Alias keyword */
%token <tok>	 CMNDALIAS		/* Cmnd_Alias keyword */
%token <tok>	 USERALIAS		/* User_Alias keyword */
%token <tok>	 RUNASALIAS		/* Runas_Alias keyword */
%token <tok>	 ':' '=' ',' '!' '+' '-' /* union member tokens */
%token <tok>	 ERROR

%type <cmndspec>  cmndspec
%type <cmndspec>  cmndspeclist
%type <defaults>  defaults_entry
%type <defaults>  defaults_list
%type <member>	  cmnd
%type <member>	  opcmnd
%type <member>	  cmndlist
%type <member>	  host
%type <member>	  hostlist
%type <member>	  ophost
%type <member>	  oprunasuser
%type <member>	  opuser
%type <member>	  runaslist
%type <member>	  runasspec
%type <member>	  runasuser
%type <member>	  user
%type <member>	  userlist
%type <privilege> privilege
%type <privilege> privileges
%type <tag>	  cmndtag

%%

file		:	{ ; }
		|	line
		;

line		:	entry
		|	line entry
		;

entry		:	COMMENT {
			    ;
			}
                |       error COMMENT {
			    yyerrok;
			}
		|	userlist privileges {
			    add_userspec($1, $2);
			}
		|	USERALIAS useraliases {
			    ;
			}
		|	HOSTALIAS hostaliases {
			    ;
			}
		|	CMNDALIAS cmndaliases {
			    ;
			}
		|	RUNASALIAS runasaliases {
			    ;
			}
		|	DEFAULTS defaults_list {
			    add_defaults(DEFAULTS, NULL, $2);
			}
		|	DEFAULTS_USER userlist defaults_list {
			    add_defaults(DEFAULTS_USER, $2, $3);
			}
		|	DEFAULTS_RUNAS runaslist defaults_list {
			    add_defaults(DEFAULTS_RUNAS, $2, $3);
			}
		|	DEFAULTS_HOST hostlist defaults_list {
			    add_defaults(DEFAULTS_HOST, $2, $3);
			}
		;

defaults_list	:	defaults_entry
		|	defaults_list ',' defaults_entry {
			    LIST_APPEND($1, $3);
			    $$ = $1;
			}
		;

defaults_entry	:	DEFVAR {
			    NEW_DEFAULT($$, $1, NULL, TRUE);
			}
		|	'!' DEFVAR {
			    NEW_DEFAULT($$, $2, NULL, FALSE);
			}
		|	DEFVAR '=' WORD {
			    NEW_DEFAULT($$, $1, $3, TRUE);
			}
		|	DEFVAR '+' WORD {
			    NEW_DEFAULT($$, $1, $3, '+');
			}
		|	DEFVAR '-' WORD {
			    NEW_DEFAULT($$, $1, $3, '-');
			}
		;

privileges	:	privilege
		|	privileges ':' privilege {
			    LIST_APPEND($1, $3);
			    $$ = $1;
			}
		;

privilege	:	hostlist '=' cmndspeclist {
			    struct cmndtag tags;
			    struct privilege *p = emalloc(sizeof(*p));
			    struct cmndspec *cs;
			    p->hostlist = $1;
			    p->cmndlist = $3;
			    tags.nopasswd = tags.noexec = tags.monitor = UNSPEC;
			    /* propagate tags */
			    for (cs = $3; cs != NULL; cs = cs->next) {
				if (cs->tags.nopasswd == UNSPEC)
				    cs->tags.nopasswd = tags.nopasswd;
				if (cs->tags.noexec == UNSPEC)
				    cs->tags.noexec = tags.noexec;
				if (cs->tags.monitor == UNSPEC)
				    cs->tags.monitor = tags.monitor;
				memcpy(&tags, &cs->tags, sizeof(tags));
			    }
			    p->last = NULL;
			    p->next = NULL;
			    $$ = p;
			}
		;

ophost		:	host {
			    $$ = $1;
			    $$->negated = FALSE;
			}
		|	'!' host {
			    $$ = $2;
			    $$->negated = TRUE;
			}
		;

host		:	ALIAS {
			    NEW_MEMBER($$, $1, ALIAS);
			}
		|	ALL {
			    NEW_MEMBER($$, NULL, ALL);
			}
		|	NETGROUP {
			    NEW_MEMBER($$, $1, NETGROUP);
			}
		|	NTWKADDR {
			    NEW_MEMBER($$, $1, NTWKADDR);
			}
		|	WORD {
			    NEW_MEMBER($$, $1, WORD);
			}
		;

cmndspeclist	:	cmndspec
		|	cmndspeclist ',' cmndspec {
			    LIST_APPEND($1, $3);
			    $$ = $1;
			}
		;

cmndspec	:	runasspec cmndtag opcmnd {
			    struct cmndspec *cs = emalloc(sizeof(*cs));
			    cs->runaslist = $1;
			    cs->tags = $2;
			    cs->cmnd = $3;
			    cs->last = NULL;
			    cs->next = NULL;
			    $$ = cs;
			}
		;

opcmnd		:	cmnd {
			    $$ = $1;
			    $$->negated = FALSE;
			}
		|	'!' cmnd {
			    $$ = $2;
			    $$->negated = TRUE;
			}
		;

runasspec	:	/* empty */ {
			    $$ = NULL;
			}
		|	RUNAS runaslist {
			    $$ = $2;
			}
		;

runaslist	:	oprunasuser
		|	runaslist ',' oprunasuser {
			    LIST_APPEND($1, $3);
			    $$ = $1;
			}
		;

oprunasuser	:	runasuser {
			    $$ = $1;
			    $$->negated = FALSE;
			}
		|	'!' runasuser {
			    $$ = $2;
			    $$->negated = TRUE;
			}
		;

runasuser	:	ALIAS {
			    NEW_MEMBER($$, $1, ALIAS);
			}
		|	ALL {
			    NEW_MEMBER($$, NULL, ALL);
			}
		|	NETGROUP {
			    NEW_MEMBER($$, $1, NETGROUP);
			}
		|	USERGROUP {
			    NEW_MEMBER($$, $1, USERGROUP);
			}
		|	WORD {
			    NEW_MEMBER($$, $1, WORD);
			}
		;

cmndtag		:	/* empty */ {
			    $$.nopasswd = $$.noexec = $$.monitor = UNSPEC;
			}
		|	cmndtag NOPASSWD {
			    $$.nopasswd = TRUE;
			}
		|	cmndtag PASSWD {
			    $$.nopasswd = FALSE;
			}
		|	cmndtag NOEXEC {
			    $$.noexec = TRUE;
			}
		|	cmndtag EXEC {
			    $$.noexec = FALSE;
			}
		|	cmndtag MONITOR {
			    $$.monitor = TRUE;
			}
		|	cmndtag NOMONITOR {
			    $$.monitor = FALSE;
			}
		;

cmnd		:	ALL {
			    NEW_MEMBER($$, NULL, ALL);
			    if (safe_cmnd)
				free(safe_cmnd);
			    safe_cmnd = estrdup(user_cmnd);
			}
		|	ALIAS {
			    NEW_MEMBER($$, $1, ALIAS);
			}
		|	COMMAND {
			    struct sudo_command *c = emalloc(sizeof(*c));
			    c->cmnd = $1.cmnd;
			    c->args = $1.args;
			    NEW_MEMBER($$, (char *)c, COMMAND);
			}
		;

hostaliases	:	hostalias
		|	hostaliases ':' hostalias
		;

hostalias	:	ALIAS '=' hostlist {
			    char *s;
			    if ((s = alias_add($1, HOSTALIAS, $3)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
		;

hostlist	:	ophost
		|	hostlist ',' ophost {
			    LIST_APPEND($1, $3);
			    $$ = $1;
			}
		;

cmndaliases	:	cmndalias
		|	cmndaliases ':' cmndalias
		;

cmndalias	:	ALIAS '=' cmndlist {
			    char *s;
			    if ((s = alias_add($1, CMNDALIAS, $3)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
		;

cmndlist	:	opcmnd
		|	cmndlist ',' opcmnd {
			    LIST_APPEND($1, $3);
			    $$ = $1;
			}
		;

runasaliases	:	runasalias
		|	runasaliases ':' runasalias
		;

runasalias	:	ALIAS '=' runaslist {
			    char *s;
			    if ((s = alias_add($1, RUNASALIAS, $3)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
		;

useraliases	:	useralias
		|	useraliases ':' useralias
		;

useralias	:	ALIAS '=' userlist {
			    char *s;
			    if ((s = alias_add($1, USERALIAS, $3)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
		;

userlist	:	opuser
		|	userlist ',' opuser {
			    LIST_APPEND($1, $3);
			    $$ = $1;
			}
		;

opuser		:	user {
			    $$ = $1;
			    $$->negated = FALSE;
			}
		|	'!' user {
			    $$ = $2;
			    $$->negated = TRUE;
			}
		;

user		:	ALIAS {
			    NEW_MEMBER($$, $1, ALIAS);
			}
		|	ALL {
			    NEW_MEMBER($$, NULL, ALL);
			}
		|	NETGROUP {
			    NEW_MEMBER($$, $1, NETGROUP);
			}
		|	USERGROUP {
			    NEW_MEMBER($$, $1, USERGROUP);
			}
		|	WORD {
			    NEW_MEMBER($$, $1, WORD);
			}
		;

%%
/*
 * Add a list of defaults structures to the defaults list.
 * The binding, if non-NULL, specifies a list of hosts, users, or
 * runas users the entries apply to (specified by the type).
 */
static void
add_defaults(type, binding, defs)
    int type;
    struct member *binding;
    struct defaults *defs;
{
    struct defaults *d;

    /*
     * Set type and binding (who it applies to) for new entries.
     */
    for (d = defs; d != NULL; d = d->next) {
	d->type = type;
	d->binding = binding;
    }
    if (defaults == NULL)
	defaults = defs;
    else
	LIST_APPEND(defaults, defs);
}

/*
 * Allocate a new struct userspec, populate it, and insert it at the
 * and of the userspecs list.
 */
static void
add_userspec(members, privs)
    struct member *members;
    struct privilege *privs;
{
    struct userspec *u;

    u = emalloc(sizeof(*u));
    u->user = members;
    u->privileges = privs;
    u->last = NULL;
    u->next = NULL;
    if (userspecs == NULL)
	userspecs = u;
    else
	LIST_APPEND(userspecs, u);
}

/*
 * Free up space used by data structures from a previous parser run and sets
 * the current sudoers file to path.
 */
void
init_parser(path, quiet)
    char *path;
    int quiet;
{
    struct defaults *d;
    struct member *m, *lastbinding;
    struct userspec *us;
    struct privilege *priv;
    struct cmndspec *cs;
    VOID *next;

    for (us = userspecs; us != NULL; us = next) {
	for (m = us->user; m != NULL; m = next) {
	    next = m->next;
	    if (m->name != NULL)
		free(m->name);
	    free(m);
	}
	for (priv = us->privileges; priv != NULL; priv = next) {
	    for (m = priv->hostlist; m != NULL; m = next) {
		next = m->next;
		if (m->name != NULL)
		    free(m->name);
		free(m);
	    }
	    for (cs = priv->cmndlist; cs != NULL; cs = next) {
		for (m = cs->runaslist; m != NULL; m = next) {
		    next = m->next;
		    if (m->name != NULL)
			free(m->name);
		    free(m);
		}
		if (cs->cmnd->name != NULL)
		    free(cs->cmnd->name);
		free(cs->cmnd);
		next = cs->next;
		free(cs);
	    }
	    next = priv->next;
	    free(priv);
	}
	next = us->next;
	free(us);
    }
    userspecs = NULL;

    lastbinding = NULL;
    for (d = defaults; d != NULL; d = next) {
	if (d->binding != lastbinding) {
	    for (m = d->binding; m != NULL; m = next) {
		next = m->next;
		if (m->name != NULL)
		    free(m->name);
		free(m);
	    }
	    lastbinding = d->binding;
	}
	next = d->next;
	free(d->var);
	if (d->val != NULL)
	    free(d->val);
	free(d);
    }
    defaults = NULL;

    init_aliases();

    if (sudoers != NULL)
	free(sudoers);
    sudoers = estrdup(path);

    parse_error = FALSE;
    errorlineno = -1;
    sudolineno = 1;
    verbose = !quiet;
}
