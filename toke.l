%{
/*
 * Copyright (c) 1996, 1998-2005 Todd C. Miller <Todd.Miller@courtesan.com>
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
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
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
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <ctype.h>
#include "sudo.h"
#include "parse.h"
#include <gram.h>

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

extern YYSTYPE yylval;
int sudolineno = 1;
char *sudoers;
static int sawspace = 0;
static int arg_len = 0;
static int arg_size = 0;

static int fill			__P((char *, int));
static int fill_cmnd		__P((char *, int));
static int fill_args		__P((char *, int, int));
static int switch_buffer	__P((char *));
extern void yyerror		__P((const char *));

#define	push_include(_p)	(switch_buffer((_p)))
#define	pop_include()		(switch_buffer(NULL))

/* realloc() to size + COMMANDARGINC to make room for command args */
#define COMMANDARGINC	64

#ifdef TRACELEXER
#define LEXTRACE(msg)	fputs(msg, stderr)
#else
#define LEXTRACE(msg)
#endif
%}

OCTET			(1?[0-9]{1,2})|(2[0-4][0-9])|(25[0-5])
DOTTEDQUAD		{OCTET}(\.{OCTET}){3}
HOSTNAME		[[:alnum:]_-]+
WORD			([^#>!=:,\(\) \t\n\\]|\\[^\n])+
PATH			\/(\\[\,:= \t#]|[^\,:=\\ \t\n#])+
ENVAR			([^#!=, \t\n\\]|\\[^\n])([^#=, \t\n\\]|\\[^\n])*
DEFVAR			[a-z_]+

%option nounput
%option noyywrap

/* XXX - convert GOTRUNAS to exclusive state (GOTDEFS cannot be) */
%s	GOTRUNAS
%s	GOTDEFS
%x	GOTCMND
%x	STARTDEFS
%x	INDEFS

%%
<GOTDEFS>[[:blank:]]+	BEGIN STARTDEFS;

<STARTDEFS>{DEFVAR}	{
			    BEGIN INDEFS;
			    LEXTRACE("DEFVAR ");
			    if (!fill(yytext, yyleng))
				yyterminate();
			    return(DEFVAR);
			}

<INDEFS>{
    ,			{
			    BEGIN STARTDEFS;
			    LEXTRACE(", ");
			    return(',');
			}			/* return ',' */

    =			{
			    LEXTRACE("= ");
			    return('=');
			}			/* return '=' */

    \+=			{
			    LEXTRACE("+= ");
			    return('+');
			}			/* return '+' */

    -=			{
			    LEXTRACE("-= ");
			    return('-');
			}			/* return '-' */

    \"([^\"]|\\\")+\"	{
			    LEXTRACE("WORD(1) ");
			    if (!fill(yytext + 1, yyleng - 2))
				yyterminate();
			    return(WORD);
			}

    {ENVAR}		{
			    LEXTRACE("WORD(2) ");
			    if (!fill(yytext, yyleng))
				yyterminate();
			    return(WORD);
			}
}

<GOTCMND>{
    \\[\*\?\[\]\!]	{
			    /* quoted fnmatch glob char, pass verbatim */
			    LEXTRACE("QUOTEDCHAR ");
			    if (!fill_args(yytext, 2, sawspace))
				yyterminate();
			    sawspace = FALSE;
			}

    \\[:\\,= \t#]	{
			    /* quoted sudoers special char, strip backslash */
			    LEXTRACE("QUOTEDCHAR ");
			    if (!fill_args(yytext + 1, 1, sawspace))
				yyterminate();
			    sawspace = FALSE;
			}

    [#:\,=\n]		{
			    BEGIN INITIAL;
			    yyless(0);
			    return(COMMAND);
			}			/* end of command line args */

    [^\\:, \t\n]+ 	{
			    LEXTRACE("ARG ");
			    if (!fill_args(yytext, yyleng, sawspace))
				yyterminate();
			    sawspace = FALSE;
			}			/* a command line arg */
}

<INITIAL>^#include[[:blank:]]+\/.*\n {
			    char *cp, *ep;
			    ++sudolineno;
			    /* pull out path from #include line */
			    cp = yytext + 9;
			    while (isblank((unsigned char) *cp))
				cp++;
			    ep = cp;
			    while (*ep != '\0' && !isspace((unsigned char) *ep))
				ep++;
			    *ep = '\0';
			    /* push current buffer and switch to include file */
			    if (!push_include(cp))
				yyterminate();
			    LEXTRACE("INCLUDE\n");
			    return(COMMENT);
			}

<INITIAL>^Defaults([:@>\!]{WORD})? {
			    BEGIN GOTDEFS;
			    switch (yytext[8]) {
				case ':':
				    yyless(9);
				    LEXTRACE("DEFAULTS_USER ");
				    return(DEFAULTS_USER);
				case '>':
				    yyless(9);
				    LEXTRACE("DEFAULTS_RUNAS ");
				    return(DEFAULTS_RUNAS);
				case '@':
				    yyless(9);
				    LEXTRACE("DEFAULTS_HOST ");
				    return(DEFAULTS_HOST);
				case '!':
				    yyless(9);
				    LEXTRACE("DEFAULTS_CMND ");
				    return(DEFAULTS_CMND);
				default:
				    LEXTRACE("DEFAULTS ");
				    return(DEFAULTS);
			    }
			}

<INITIAL>^(Host|Cmnd|User|Runas)_Alias	{
			    if (!fill(yytext, yyleng))
				yyterminate();
			    switch (*yytext) {
				case 'H':
				    LEXTRACE("HOSTALIAS ");
				    return(HOSTALIAS);
				case 'C':
				    LEXTRACE("CMNDALIAS ");
				    return(CMNDALIAS);
				case 'U':
				    LEXTRACE("USERALIAS ");
				    return(USERALIAS);
				case 'R':
				    LEXTRACE("RUNASALIAS ");
				    BEGIN GOTRUNAS;
				    return(RUNASALIAS);
			    }
			}

NOPASSWD[[:blank:]]*:	{
				/* cmnd does not require passwd for this user */
			    	LEXTRACE("NOPASSWD ");
			    	return(NOPASSWD);
			}

PASSWD[[:blank:]]*:	{
				/* cmnd requires passwd for this user */
			    	LEXTRACE("PASSWD ");
			    	return(PASSWD);
			}

NOEXEC[[:blank:]]*:	{
			    	LEXTRACE("NOEXEC ");
			    	return(NOEXEC);
			}

EXEC[[:blank:]]*:	{
			    	LEXTRACE("EXEC ");
			    	return(EXEC);
			}

NOMONITOR[[:blank:]]*:	{
			    	LEXTRACE("NOMONITOR ");
			    	return(NOMONITOR);
			}

MONITOR[[:blank:]]*:	{
			    	LEXTRACE("MONITOR ");
			    	return(MONITOR);
			}

\+{WORD}		{
			    /* netgroup */
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("NETGROUP ");
			    return(NETGROUP);
			}

\%{WORD}		{
			    /* UN*X group */
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("USERGROUP ");
			    return(USERGROUP);
			}

{DOTTEDQUAD}(\/{DOTTEDQUAD})? {
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    return(NTWKADDR);
			}

{DOTTEDQUAD}\/([12][0-9]*|3[0-2]*) {
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    return(NTWKADDR);
			}

<INITIAL>\(		{
				BEGIN GOTRUNAS;
				LEXTRACE("RUNAS ");
				return (RUNAS);
			}

[[:upper:]][[:upper:][:digit:]_]* {
			    if (strcmp(yytext, "ALL") == 0) {
				LEXTRACE("ALL ");
				return(ALL);
			    } else {
				if (!fill(yytext, yyleng))
				    yyterminate();
				LEXTRACE("ALIAS ");
				return(ALIAS);
			    }
			}

<GOTRUNAS>(#[0-9-]+|{WORD}) {
			    /* username/uid that user can run command as */
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("WORD(3) ");
			    return(WORD);
			}

<GOTRUNAS>\)		{
			    BEGIN INITIAL;
			}

<GOTDEFS>({PATH}|sudoedit) {
			    /* no command args allowed for Defaults!/path */
			    if (!fill_cmnd(yytext, yyleng))
				yyterminate();
			    LEXTRACE("COMMAND ");
			    return(COMMAND);
			}

sudoedit		{
			    BEGIN GOTCMND;
			    LEXTRACE("COMMAND ");
			    if (!fill_cmnd(yytext, yyleng))
				yyterminate();
			}			/* sudo -e */

{PATH}			{
			    /* directories can't have args... */
			    if (yytext[yyleng - 1] == '/') {
				LEXTRACE("COMMAND ");
				if (!fill_cmnd(yytext, yyleng))
				    yyterminate();
				return(COMMAND);
			    } else {
				BEGIN GOTCMND;
				LEXTRACE("COMMAND ");
				if (!fill_cmnd(yytext, yyleng))
				    yyterminate();
			    }
			}			/* a pathname */

<INITIAL,GOTDEFS>{WORD} {
			    /* a word */
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("WORD(4) ");
			    return(WORD);
			}

,			{
			    LEXTRACE(", ");
			    return(',');
			}			/* return ',' */

=			{
			    LEXTRACE("= ");
			    return('=');
			}			/* return '=' */

:			{
			    LEXTRACE(": ");
			    return(':');
			}			/* return ':' */

<*>!+			{
			    if (yyleng % 2 == 1)
				return('!');	/* return '!' */
			}

<*>\n			{
			    BEGIN INITIAL;
			    ++sudolineno;
			    LEXTRACE("\n");
			    return(COMMENT);
			}			/* return newline */

<*>[[:blank:]]+		{			/* throw away space/tabs */
			    sawspace = TRUE;	/* but remember for fill_args */
			}

<*>\\[[:blank:]]*\n	{
			    sawspace = TRUE;	/* remember for fill_args */
			    ++sudolineno;
			    LEXTRACE("\n\t");
			}			/* throw away EOL after \ */

<INITIAL,STARTDEFS,INDEFS>#.*\n	{
			    BEGIN INITIAL;
			    ++sudolineno;
			    LEXTRACE("\n");
			    return(COMMENT);
			}			/* return comments */

<*>.			{
			    LEXTRACE("ERROR ");
			    return(ERROR);
			}	/* parse error */

<*><<EOF>>		{
			    if (YY_START != INITIAL) {
			    	BEGIN INITIAL;
				LEXTRACE("ERROR ");
				return(ERROR);
			    }
			    if (!pop_include())
				yyterminate();
			}

%%
static int
fill(s, len)
    char *s;
    int len;
{
    int i, j;

    yylval.string = (char *) malloc(len + 1);
    if (yylval.string == NULL) {
	yyerror("unable to allocate memory");
	return(FALSE);
    }

    /* Copy the string and collapse any escaped characters. */
    for (i = 0, j = 0; i < len; i++, j++) {
	if (s[i] == '\\' && i != len - 1)
	    yylval.string[j] = s[++i];
	else
	    yylval.string[j] = s[i];
    }
    yylval.string[j] = '\0';
    return(TRUE);
}

static int
fill_cmnd(s, len)
    char *s;
    int len;
{
    arg_len = arg_size = 0;

    yylval.command.cmnd = (char *) malloc(++len);
    if (yylval.command.cmnd == NULL) {
	yyerror("unable to allocate memory");
	return(FALSE);
    }

    /* copy the string and NULL-terminate it (escapes handled by fnmatch) */
    (void) strlcpy(yylval.command.cmnd, s, len);

    yylval.command.args = NULL;
    return(TRUE);
}

static int
fill_args(s, len, addspace)
    char *s;
    int len;
    int addspace;
{
    int new_len;
    char *p;

    if (yylval.command.args == NULL) {
	addspace = 0;
	new_len = len;
    } else
	new_len = arg_len + len + addspace;

    if (new_len >= arg_size) {
	/* Allocate more space than we need for subsequent args */
	while (new_len >= (arg_size += COMMANDARGINC))
	    ;

	p = yylval.command.args ?
	    (char *) realloc(yylval.command.args, arg_size) :
	    (char *) malloc(arg_size);
	if (p == NULL) {
	    if (yylval.command.args != NULL)
		free(yylval.command.args);
	    yyerror("unable to allocate memory");
	    return(FALSE);
	} else
	    yylval.command.args = p;
    }

    /* Efficiently append the arg (with a leading space if needed). */
    p = yylval.command.args + arg_len;
    if (addspace)
	*p++ = ' ';
    if (strlcpy(p, s, arg_size - (p - yylval.command.args)) != len) {
	yyerror("fill_args: buffer overflow");	/* paranoia */
	return(FALSE);
    }
    arg_len = new_len;
    return(TRUE);
}

struct sudoers_state {
    YY_BUFFER_STATE bs;
    char *path;
    int lineno;
};

#define MAX_SUDOERS_DEPTH	128
#define SUDOERS_STACK_INCREMENT	16

static int
switch_buffer(path)
    char *path;
{
    static size_t stacksize, depth;
    static struct sudoers_state *state;
    static int keepopen;
    FILE *fp;

    if (path != NULL) {
	/* push current state */
	if ((path = strdup(path)) == NULL) {
	    yyerror("unable to allocate memory");
	    return(FALSE);
	}
	if (depth >= stacksize) {
	    if (depth > MAX_SUDOERS_DEPTH) {
		yyerror("too many levels of includes");
		return(FALSE);
	    }
	    stacksize += SUDOERS_STACK_INCREMENT;
	    state = (struct sudoers_state *) realloc(state,
		sizeof(state) * stacksize);
	    if (state == NULL) {
		yyerror("unable to allocate memory");
		return(FALSE);
	    }
	}
	if ((fp = open_sudoers(path, &keepopen)) == NULL) {
	    yyerror(path);
	    return(FALSE);
	}
	state[depth].bs = YY_CURRENT_BUFFER;
	state[depth].path = sudoers;
	state[depth].lineno = sudolineno;
	depth++;
	sudolineno = 1;
	sudoers = path;
	yy_switch_to_buffer(yy_create_buffer(fp, YY_BUF_SIZE));
    } else {
	/* pop */
	if (depth == 0)
	    return(FALSE);
	depth--;
	if (!keepopen)
	    fclose(YY_CURRENT_BUFFER->yy_input_file);
	yy_delete_buffer(YY_CURRENT_BUFFER);
	yy_switch_to_buffer(state[depth].bs);
	free(sudoers);
	sudoers = state[depth].path;
	sudolineno = state[depth].lineno;
	keepopen = FALSE;
    }
    return(TRUE);
}
