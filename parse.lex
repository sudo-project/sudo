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
 * parse.lex -- lexigraphical analyzer for sudo.
 *
 * Chris Jepeway <jepeway@cs.utk.edu>
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include "sudo.h"
#include "options.h"
#include "y.tab.h"

#undef yywrap		/* guard against a yywrap macro */

extern YYSTYPE yylval;
extern int clearaliases;
int sudolineno = 1;
static int string_len = 0;
static int string_size = 0;
static int sawspace = 0;

static void fill		__P((char *, int));
static void append		__P((char *, int, int));
extern void reset_aliases	__P((void));

/* realloc() to size + COMMANDARGINC to make room for command args */
#define COMMANDARGINC	256

#ifdef TRACELEXER
#define LEXTRACE(msg)	fputs(msg, stderr)
#else
#define LEXTRACE(msg)
#endif
%}

N			[0-9][0-9]?[0-9]?

%e	4000
%p	6000
%k	3500

%s	GOTCMND

%%
[ \t]+			{			/* throw away space/tabs */
			    sawspace = TRUE;	/* but remember for append */
			}

\\\n			{ 
			    sawspace = TRUE;	/* remember for append */
			    ++sudolineno;
			    LEXTRACE("\n\t");
			}			/* throw away EOL after \ */

<GOTCMND>\\[:\,=\\]	{
			    LEXTRACE("QUOTEDCHAR ");
			    append(yytext + 1, 1, sawspace);
			    sawspace = FALSE;
			}

<GOTCMND>[:\,=\n]	{
			    BEGIN 0;
			    unput(*yytext);
			    return(COMMAND);
			}			/* end of command line args */

\n			{ 
			    ++sudolineno; 
			    LEXTRACE("\n");
			    return(COMMENT);
			}			/* return newline */

#.*\n			{
			    ++sudolineno;
			    LEXTRACE("\n");
			    return(COMMENT);
			}			/* return comments */

<GOTCMND>[^\,:=\\ \t\n#]+ {
			    LEXTRACE("ARG ");
			    append(yytext, yyleng, sawspace);
			    sawspace = FALSE;
			  }			/* a command line arg */

\,			{
			    LEXTRACE(", ");
			    return(',');
			}			/* return ',' */

\!			{
			    return('!');		/* return '!' */
			}

=			{
			    LEXTRACE("= ");
			    return('=');
			}			/* return '=' */

:			{
			    LEXTRACE(": ");
			    return(':');
			}			/* return ':' */

\.			{
			    return('.');
			}

\+[a-zA-Z][a-zA-Z0-9_-]* {
			    fill(yytext, yyleng);
			    return(NETGROUP);
			 }

{N}\.{N}\.{N}\.{N}	{
			    fill(yytext, yyleng);
			    return(NTWKADDR);
			}

\/[^\,:=\\ \t\n#]+	{
			    /* directories can't have args... */
			    if (yytext[yyleng - 1] == '/') {
				LEXTRACE("COMMAND ");
				fill(yytext, yyleng);
				return(COMMAND);
			    } else {
				BEGIN GOTCMND;
				LEXTRACE("COMMAND ");
				fill(yytext, yyleng);
			    }
			}			/* a pathname */

[A-Z][A-Z0-9_]*		{
			    fill(yytext, yyleng);
			    if (strcmp(yytext, "ALL") == 0) {
				LEXTRACE("ALL ");
				return(ALL);
			    }
			    LEXTRACE("ALIAS ");
			    return(ALIAS);
			}

[a-zA-Z][a-zA-Z0-9_-]*	{
			    int l;

			    fill(yytext, yyleng);
			    if (strcmp(yytext, "Host_Alias") == 0) {
				LEXTRACE("HOSTALIAS ");
				return(HOSTALIAS);
			    }
			    if (strcmp(yytext, "Cmnd_Alias") == 0) {
				LEXTRACE("CMNDALIAS ");
				return(CMNDALIAS);
			    }
			    if (strcmp(yytext, "User_Alias") == 0) {
				LEXTRACE("USERALIAS ");
				return(USERALIAS);
			    }

			    l = yyleng - 1;
			    if (isalpha(yytext[l]) || isdigit(yytext[l])) {
				/* NAME is what RFC1034 calls a label */
				LEXTRACE("NAME ");
				return(NAME);
			    }

			    return(ERROR);
			}

.			{
			    return(ERROR);
			}	/* parse error */

%%
static void fill(s, len)
    char *s;
    int len;
{

    string_len = len;		/* length of copied string */
    string_size = len + 1;	/* leave room for the NULL */

    yylval.string = (char *) malloc(string_size);
    if (yylval.string == NULL)
	yyerror("unable to allocate memory");
    (void) strcpy(yylval.string, s);
}


static void append(s, len, addspace)
    char *s;
    int len;
    int addspace;
{
    char *p;
    int new_len;

    new_len = string_len + len + addspace;

    /*
     * If we don't have enough space realloc() some more
     */
    if (new_len >= string_size) {
	/* Allocate more space than we need for subsequent args */
	while (new_len >= (string_size += COMMANDARGINC))
	    ;

	yylval.string = (char *) realloc(yylval.string, string_size);
	if (yylval.string == NULL )
	    yyerror("unable to allocate memory");
    }

    /* Efficiently append the arg (with a leading space) */
    p = yylval.string + string_len;
    if (addspace)
	*p++ = ' ';
    (void) strcpy(p, s);
    string_len = new_len;
}


int yywrap()
{
#ifdef YY_NEW_FILE
    YY_NEW_FILE;
#endif /* YY_NEW_FILE */

    /* don't reset the aliases if called by testsudoers */
    if (clearaliases)
	reset_aliases();

    return(TRUE);
}
