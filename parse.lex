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

static void fill		__P((void));
static void append		__P((void));
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
[ \t]+			{ ; }			/* throw away space/tabs */

\\\n			{ 
			  ++sudolineno;
			  LEXTRACE("\n\t");
			}			/* throw away EOL after \ */

<GOTCMND>[:,=\n]	{
			  BEGIN 0;
			  unput(yytext[0]);
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

<GOTCMND>((\\[\,:=\\])|([^\,:=\\ \t\n#]))+ {
			    LEXTRACE("ARG ");
			    append();
			  }			/* a command line arg */

\,			{
			  LEXTRACE(", ");
			  return(',');
			}			/* return ',' */

\!			{ return('!'); }		/* return '!' */

=			{
			  LEXTRACE("= ");
			  return('=');
			}			/* return '=' */

:			{
			  LEXTRACE(": ");
			  return(':');
			}			/* return ':' */

\.			{ return('.'); }

\+[a-zA-Z][a-zA-Z0-9_-]* {
			  fill();
			  return(NETGROUP);
			 }

{N}\.{N}\.{N}\.{N}	{
			  fill();
			  return(NTWKADDR);
			}

\/[^\,:=\\ \t\n#]+\/	{
			  LEXTRACE("COMMAND ");
			  fill();
			  return(COMMAND);
			}			/* a directory */

\/[^\,:=\\ \t\n#]+	{
			  BEGIN GOTCMND;
			  LEXTRACE("COMMAND ");
			  fill();
			}			/* a pathname */

[A-Z][A-Z0-9_]*		{
			  fill();
			  if (strcmp(yytext, "ALL") == 0) {
			      LEXTRACE("ALL ");
			      return(ALL);
			  }
			  LEXTRACE("ALIAS ");
			  return(ALIAS);
			}

[a-zA-Z][a-zA-Z0-9_-]*	{
			  int l;

			  fill();
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

.			{ return(ERROR); }	/* return error */

%%
static void fill() {

    string_len = yyleng;	/* length of copied string */
    string_size = yyleng + 1;	/* leave room for the NULL */

    yylval.string = (char *) malloc(string_size);
    if (yylval.string == NULL)
	yyerror("unable to allocate memory");
    (void) strcpy(yylval.string, yytext);
}


static void append() {
    char *s;
    int new_len;

    new_len = string_len + yyleng + 1;

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

    /* Effeciently append the arg (with a leading space) */
    s = yylval.string + string_len;
    *s++ = ' ';
    (void) strcpy(s, yytext);
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
