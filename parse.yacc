%{
/*
 *  CU sudo version 1.3.1
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  Please send bugs, changes, problems to sudo-bugs@cs.colorado.edu
 *
 *******************************************************************
 *
 * parse.yacc -- yacc parser and alias manipulation routines for sudo.
 *
 * Chris Jepeway <jepeway@cs.utk.edu>
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"
#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_LSEARCH
#include <search.h>
#endif /* HAVE_LSEARCH */

#include "sudo.h"
#include "options.h"

#ifndef HAVE_LSEARCH
#include "search.h"
#endif /* HAVE_LSEARCH */

extern int sudolineno, parse_error;
int errorlineno = -1;

/*
 * Alias types
 */
#define HOST			 1
#define CMND			 2
#define USER			 3

/*
 * the matching stack
 */
#define MATCHSTACKSIZE (40)
struct matchstack match[MATCHSTACKSIZE];
int top = 0;

#define push \
    if (top > MATCHSTACKSIZE) \
	yyerror("matching stack overflow\n"); \
    else {\
	match[top].user = -1; \
	match[top].cmnd = -1; \
	match[top].host = -1; \
	top++; \
    }
#define pop \
    if (top == 0) \
	yyerror("matching stack underflow\n"); \
    else \
	top--;

extern int path_matches		__P((char *, char *));
extern int addr_matches		__P((char *));
static int find_alias		__P((char *, int));
static int add_alias		__P((char *, int));
static int more_aliases		__P((size_t));

int yyerror(s)
char *s;
{
    /* save the line the first error occured on */
    if (errorlineno == -1)
	errorlineno = sudolineno;
#ifndef TRACELEXER
    fprintf(stderr, ">>> sudoers file: %s, line %d <<<\n", s, sudolineno);
#else
    fprintf(stderr, "<*> ");
#endif
    parse_error = TRUE;
}
%}

%union {
    char string[MAXCOMMANDLENGTH+1];
    int tok;
}


%start file				/* special start symbol */
%token <string>	ALIAS			/* an UPPERCASE alias name */
%token <string> NTWKADDR		/* w.x.y.z */
%token <string> PATH			/* an absolute pathname */
%token <string> NAME			/* a mixed-case name */
%token <tok>	COMMENT			/* comment and/or carriage return */
%token <tok>	ALL			/* ALL keyword */
%token <tok>	HOSTALIAS		/* Host_Alias keyword */
%token <tok>	CMNDALIAS		/* Cmnd_Alias keyword */
%token <tok>	USERALIAS		/* User_Alias keyword */
%token <tok>	':' '=' ',' '!' '.'	/* union member tokens */
%token <tok>	ERROR

%type <string>	fqdn cmnd

%%

file		:	entry
		|	file entry
		;

entry		:	COMMENT
			{ ; }
                |       error COMMENT
			{ yyerrok; }
		|	NAME {
			    push;
			    user_matches = strcmp(user, $1) == 0;
			} privileges
		|	ALIAS {
			    push;
			    user_matches = find_alias($1, USER) != 0;
			} privileges
		|	ALL {
			    push;
			    user_matches = TRUE;
			} privileges
		|	USERALIAS useraliases
			{ ; }
		|	HOSTALIAS hostaliases
			{ ; }
		|	CMNDALIAS cmndaliases
			{ ; }
		;
		

privileges	:	privilege
		|	privileges ':' privilege
		;

privilege	:	hostspec '=' opcmndlist {
			    if (!user_matches)
				pop;
			    else {
				push;
				user_matches = TRUE;
			    }
			}
		;

hostspec	:	ALL {
			    host_matches = TRUE;
			}
		|	NTWKADDR {
			    if (addr_matches($1))
				host_matches = TRUE;
			}
		|	NAME {
			    if (strcmp(host, $1) == 0)
				host_matches = TRUE;
			}
		|	ALIAS {
			    if (find_alias($1, HOST))
				host_matches = TRUE;
			}
		|	fqdn {
#ifdef HAVE_STRCASECMP
			    if (strcasecmp($1, host) == 0)
				host_matches = TRUE;
#else
			    if (strcmp($1, host) == 0)
				host_matches = TRUE;
#endif /* HAVE_STRCASECMP */
		}
		;

fqdn		:	NAME '.' NAME {
			    strcpy($$, $1);
			    strcat($$, ".");
			    strcat($$, $3);
			}
		|	fqdn '.' NAME {
			    strcpy($$, $1);
			    strcat($$, ".");
			    strcat($$, $3);
			}
		;

opcmndlist	:	opcmnd
		|	opcmndlist ',' opcmnd
		;

opcmnd		:	cmnd
			{ ; }
		|	'!' { push; } opcmnd {
			    int cmnd_matched = cmnd_matches;
			    pop;
			    if (cmnd_matched == TRUE)
				cmnd_matches = FALSE;
			    else if (cmnd_matched == FALSE)
				cmnd_matches = TRUE;
			}
		;

cmnd		:	ALL {
			    cmnd_matches = TRUE;
			}
		|	ALIAS {
			    if (find_alias($1, CMND))
				cmnd_matches = TRUE;
			}
		|	PATH {
			    if (path_matches(cmnd, $1))
				cmnd_matches = TRUE;
			}
		;

hostaliases	:	hostalias
		|	hostaliases ':' hostalias
		;

hostalias	:	ALIAS { push; } '=' hostlist {
			    if (host_matches == TRUE && !add_alias($1, HOST))
				YYERROR;
			    pop;
			}
		;

hostlist	:	hostspec
		|	hostlist ',' hostspec
		;

cmndaliases	:	cmndalias
		|	cmndaliases ':' cmndalias
		;

cmndalias	:	ALIAS { push; }	'=' cmndlist {
			    if (cmnd_matches == TRUE && !add_alias($1, CMND))
				YYERROR;
			    pop;
			}
		;

cmndlist	:	cmnd
			{ ; }
		|	cmndlist ',' cmnd
		;

useraliases	:	useralias
		|	useraliases ':' useralias
		;

useralias	:	ALIAS { push; }	'=' userlist {
			    if (user_matches == TRUE && !add_alias($1, USER))
				YYERROR;
			    pop;
			}
		;

userlist	:	user
			{ ; }
		|	userlist ',' user
		;

user		:	NAME {
			    if (strcmp($1, user) == 0)
				user_matches = TRUE;
			}
		|	ALL {
			    user_matches = TRUE;
			}
		;

%%


typedef struct {
    int type;
    char name[BUFSIZ];
} aliasinfo;

#define MOREALIASES (32)
aliasinfo *aliases;
size_t naliases = 0;
size_t nslots = 0;

static int
aliascmp(a1, a2)
const VOID *a1, *a2;
{
    int r;
    aliasinfo *ai1, *ai2;

    ai1 = (aliasinfo *) a1;
    ai2 = (aliasinfo *) a2;
    r = strcmp(ai1->name, ai2->name);
    if (r == 0)
	r = ai1->type - ai2->type;

    return(r);
}

static int
add_alias(alias, type)
char *alias;
int type;
{
    aliasinfo ai, *aip;
    char s[512];
    int ok;

    ok = FALSE;			/* assume failure */
    ai.type = type;
    strcpy(ai.name, alias);
    if (lfind((const VOID *)&ai, (VOID *)aliases, &naliases, sizeof(ai), aliascmp) != NULL) {
	sprintf(s, "Alias `%s' already defined", alias);
	yyerror(s);
    } else {
	if (naliases == nslots && !more_aliases(nslots)) {
	    (void) sprintf(s, "Out of memory defining alias `%s'", alias);
	    yyerror(s);
	}

	aip = (aliasinfo *) lsearch((const VOID *)&ai, (VOID *)aliases, &naliases, sizeof(ai),
	    aliascmp);

	if (aip != NULL) {
	    ok = TRUE;
	} else {
	    (void) sprintf(s, "Aliases corrupted defining alias `%s'", alias);
	    yyerror(s);
	}
    }

    return(ok);
}

static int
find_alias(alias, type)
char *alias;
int type;
{
    aliasinfo ai;

    strcpy(ai.name, alias);
    ai.type = type;

    return(lfind((const VOID *)&ai, (VOID *)aliases, &naliases, sizeof(ai), aliascmp) != NULL);
}

static int
more_aliases(nslots)
size_t nslots;
{
    aliasinfo *aip;
    if (nslots == 0)
	aip = (aliasinfo *) malloc(MOREALIASES * sizeof(*aip));
    else
	aip = (aliasinfo *) realloc(aliases,
				    (nslots + MOREALIASES) * sizeof(*aip));

    if (aip != NULL) {
	aliases = aip;
	nslots += MOREALIASES;
    }

    return(aip != NULL);
}

int
dumpaliases()
{
    size_t n;

    for (n = 0; n < naliases; n++)
	printf("%s\t%s\n", aliases[n].type == HOST ? "HOST" : "CMND",
                           aliases[n].name);

}

void
reset_aliases()
{
    (void) free(aliases);
    naliases = nslots = 0;
}
