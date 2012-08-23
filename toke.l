%{
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
#include <sys/stat.h>
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
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
#include <errno.h>
#include <ctype.h>
#include "sudo.h"
#include "parse.h"
#include "toke.h"
#include <gram.h>
#include "secure_path.h"

extern YYSTYPE yylval;
extern int parse_error;
extern int sudoers_warnings;
int sudolineno;
int last_token;
char *sudoers;

static int continued, prev_state, sawspace;

#define ECHO	ignore_result(fwrite(yytext, yyleng, 1, yyout))

static int _push_include	__P((char *, int));
static int pop_include		__P((void));
static char *parse_include	__P((char *));

#define fill(a, b)		fill_txt(a, b, 0)

#define LEXRETURN(n)	do {	\
	last_token = (n);	\
	return (n);		\
} while (0)

#define	push_include(_p)	(_push_include((_p), FALSE))
#define	push_includedir(_p)	(_push_include((_p), TRUE))

#ifdef TRACELEXER
#define LEXTRACE(msg)	fputs(msg, stderr)
#else
#define LEXTRACE(msg)
#endif
%}

HEX16			[0-9A-Fa-f]{1,4}
OCTET			(1?[0-9]{1,2})|(2[0-4][0-9])|(25[0-5])
IPV4ADDR		{OCTET}(\.{OCTET}){3}
IPV6ADDR		({HEX16}?:){2,7}{HEX16}?|({HEX16}?:){2,6}:{IPV4ADDR}

HOSTNAME		[[:alnum:]_-]+
WORD			([^#>!=:,\(\) \t\n\\\"]|\\[^\n])+
ID			#-?[0-9]+
PATH			\/(\\[\,:= \t#]|[^\,:=\\ \t\n#])+
ENVAR			([^#!=, \t\n\\\"]|\\[^\n])([^#=, \t\n\\\"]|\\[^\n])*
DEFVAR			[a-z_]+

%option noinput
%option nounput
%option noyywrap

%s	GOTDEFS
%x	GOTCMND
%x	STARTDEFS
%x	INDEFS
%x	INSTR

%%
<GOTDEFS>[[:blank:]]*,[[:blank:]]* {
			    LEXTRACE(", ");
			    LEXRETURN(',');
			}			/* return ',' */

<GOTDEFS>[[:blank:]]+	BEGIN STARTDEFS;

<STARTDEFS>{DEFVAR}	{
			    BEGIN INDEFS;
			    LEXTRACE("DEFVAR ");
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXRETURN(DEFVAR);
			}

<INDEFS>{
    ,			{
			    BEGIN STARTDEFS;
			    LEXTRACE(", ");
			    LEXRETURN(',');
			}			/* return ',' */

    =			{
			    LEXTRACE("= ");
			    LEXRETURN('=');
			}			/* return '=' */

    \+=			{
			    LEXTRACE("+= ");
			    LEXRETURN('+');
			}			/* return '+' */

    -=			{
			    LEXTRACE("-= ");
			    LEXRETURN('-');
			}			/* return '-' */

    \"			{
			    LEXTRACE("BEGINSTR ");
			    yylval.string = NULL;
			    prev_state = YY_START;
			    BEGIN INSTR;
			}

    {ENVAR}		{
			    LEXTRACE("WORD(2) ");
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXRETURN(WORD);
			}
}

<INSTR>{
    \\[[:blank:]]*\n[[:blank:]]*	{
			    /* Line continuation char followed by newline. */
			    sudolineno++;
			    continued = TRUE;
			}

    \"			{
			    LEXTRACE("ENDSTR ");
			    BEGIN prev_state;

			    if (yylval.string == NULL) {
				LEXTRACE("ERROR "); /* empty string */
				LEXRETURN(ERROR);
			    }
			    if (prev_state == INITIAL) {
				switch (yylval.string[0]) {
				case '%':
				    if (yylval.string[1] == '\0' ||
					(yylval.string[1] == ':' &&
					yylval.string[2] == '\0')) {
					LEXTRACE("ERROR "); /* empty group */
					LEXRETURN(ERROR);
				    }
				    LEXTRACE("USERGROUP ");
				    LEXRETURN(USERGROUP);
				case '+':
				    if (yylval.string[1] == '\0') {
					LEXTRACE("ERROR "); /* empty netgroup */
					LEXRETURN(ERROR);
				    }
				    LEXTRACE("NETGROUP ");
				    LEXRETURN(NETGROUP);
				}
			    }
			    LEXTRACE("WORD(4) ");
			    LEXRETURN(WORD);
			}

    \\			{
			    LEXTRACE("BACKSLASH ");
			    if (!append(yytext, yyleng))
				yyterminate();
			}

    ([^\"\n\\]|\\\")+	{
			    LEXTRACE("STRBODY ");
			    if (!append(yytext, yyleng))
				yyterminate();
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
			    LEXRETURN(COMMAND);
			}			/* end of command line args */

    [^#\\:, \t\n]+ 	{
			    LEXTRACE("ARG ");
			    if (!fill_args(yytext, yyleng, sawspace))
				yyterminate();
			    sawspace = FALSE;
			}			/* a command line arg */
}

<INITIAL>^#include[[:blank:]]+.*\n {
			    char *path;

			    if (continued) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }

			    if ((path = parse_include(yytext)) == NULL)
				yyterminate();

			    LEXTRACE("INCLUDE\n");

			    /* Push current buffer and switch to include file */
			    if (!push_include(path))
				yyterminate();
			}

<INITIAL>^#includedir[[:blank:]]+.*\n {
			    char *path;

			    if (continued) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }

			    if ((path = parse_include(yytext)) == NULL)
				yyterminate();

			    LEXTRACE("INCLUDEDIR\n");

			    /*
			     * Push current buffer and switch to include file.
			     * We simply ignore empty directories.
			     */
			    if (!push_includedir(path) && parse_error)
				yyterminate();
			}

<INITIAL>^[[:blank:]]*Defaults([:@>\!][[:blank:]]*\!*\"?({ID}|{WORD}))? {
			    char deftype;
			    int n;

			    if (continued) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }

			    for (n = 0; isblank((unsigned char)yytext[n]); n++)
				continue;
			    n += sizeof("Defaults") - 1;
			    if ((deftype = yytext[n++]) != '\0') {
				while (isblank((unsigned char)yytext[n]))
				    n++;
			    }
			    BEGIN GOTDEFS;
			    switch (deftype) {
				case ':':
				    yyless(n);
				    LEXTRACE("DEFAULTS_USER ");
				    LEXRETURN(DEFAULTS_USER);
				case '>':
				    yyless(n);
				    LEXTRACE("DEFAULTS_RUNAS ");
				    LEXRETURN(DEFAULTS_RUNAS);
				case '@':
				    yyless(n);
				    LEXTRACE("DEFAULTS_HOST ");
				    LEXRETURN(DEFAULTS_HOST);
				case '!':
				    yyless(n);
				    LEXTRACE("DEFAULTS_CMND ");
				    LEXRETURN(DEFAULTS_CMND);
				default:
				    LEXTRACE("DEFAULTS ");
				    LEXRETURN(DEFAULTS);
			    }
			}

<INITIAL>^[[:blank:]]*(Host|Cmnd|User|Runas)_Alias	{
			    int n;

			    if (continued) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }

			    for (n = 0; isblank((unsigned char)yytext[n]); n++)
				continue;
			    switch (yytext[n]) {
				case 'H':
				    LEXTRACE("HOSTALIAS ");
				    LEXRETURN(HOSTALIAS);
				case 'C':
				    LEXTRACE("CMNDALIAS ");
				    LEXRETURN(CMNDALIAS);
				case 'U':
				    LEXTRACE("USERALIAS ");
				    LEXRETURN(USERALIAS);
				case 'R':
				    LEXTRACE("RUNASALIAS ");
				    LEXRETURN(RUNASALIAS);
			    }
			}

NOPASSWD[[:blank:]]*:	{
				/* cmnd does not require passwd for this user */
			    	LEXTRACE("NOPASSWD ");
			    	LEXRETURN(NOPASSWD);
			}

PASSWD[[:blank:]]*:	{
				/* cmnd requires passwd for this user */
			    	LEXTRACE("PASSWD ");
			    	LEXRETURN(PASSWD);
			}

NOEXEC[[:blank:]]*:	{
			    	LEXTRACE("NOEXEC ");
			    	LEXRETURN(NOEXEC);
			}

EXEC[[:blank:]]*:	{
			    	LEXTRACE("EXEC ");
			    	LEXRETURN(EXEC);
			}

SETENV[[:blank:]]*:	{
			    	LEXTRACE("SETENV ");
			    	LEXRETURN(SETENV);
			}

NOSETENV[[:blank:]]*:	{
			    	LEXTRACE("NOSETENV ");
			    	LEXRETURN(NOSETENV);
			}

LOG_OUTPUT[[:blank:]]*:	{
			    	LEXTRACE("LOG_OUTPUT ");
			    	LEXRETURN(LOG_OUTPUT);
			}

NOLOG_OUTPUT[[:blank:]]*:	{
			    	LEXTRACE("NOLOG_OUTPUT ");
			    	LEXRETURN(NOLOG_OUTPUT);
			}

LOG_INPUT[[:blank:]]*:	{
			    	LEXTRACE("LOG_INPUT ");
			    	LEXRETURN(LOG_INPUT);
			}

NOLOG_INPUT[[:blank:]]*:	{
			    	LEXTRACE("NOLOG_INPUT ");
			    	LEXRETURN(NOLOG_INPUT);
			}

<INITIAL,GOTDEFS>(\+|\%|\%:) {
			    /* empty group or netgroup */
			    LEXTRACE("ERROR ");
			    LEXRETURN(ERROR);
			}

\+{WORD}		{
			    /* netgroup */
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("NETGROUP ");
			    LEXRETURN(NETGROUP);
			}

\%:?({WORD}|{ID})	{
			    /* group */
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("USERGROUP ");
			    LEXRETURN(USERGROUP);
			}

{IPV4ADDR}(\/{IPV4ADDR})? {
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    LEXRETURN(NTWKADDR);
			}

{IPV4ADDR}\/([12]?[0-9]|3[0-2]) {
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    LEXRETURN(NTWKADDR);
			}

{IPV6ADDR}(\/{IPV6ADDR})? {
			    if (!ipv6_valid(yytext)) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    LEXRETURN(NTWKADDR);
			}

{IPV6ADDR}\/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]) {
			    if (!ipv6_valid(yytext)) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    LEXRETURN(NTWKADDR);
			}

ALL {
			    LEXTRACE("ALL ");
			    LEXRETURN(ALL);

			}

<INITIAL>ROLE {
#ifdef HAVE_SELINUX
			    LEXTRACE("ROLE ");
			    LEXRETURN(ROLE);
#else
			    goto got_alias;
#endif
			}

<INITIAL>TYPE {
#ifdef HAVE_SELINUX
			    LEXTRACE("TYPE ");
			    LEXRETURN(TYPE);
#else
			    goto got_alias;
#endif
			}

[[:upper:]][[:upper:][:digit:]_]* {
#ifndef HAVE_SELINUX
			got_alias:
#endif
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("ALIAS ");
			    LEXRETURN(ALIAS);
			}

<GOTDEFS>({PATH}|sudoedit) {
			    /* no command args allowed for Defaults!/path */
			    if (!fill_cmnd(yytext, yyleng))
				yyterminate();
			    LEXTRACE("COMMAND ");
			    LEXRETURN(COMMAND);
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
				LEXRETURN(COMMAND);
			    } else {
				BEGIN GOTCMND;
				LEXTRACE("COMMAND ");
				if (!fill_cmnd(yytext, yyleng))
				    yyterminate();
			    }
			}			/* a pathname */

<INITIAL,GOTDEFS>\" {
			    LEXTRACE("BEGINSTR ");
			    yylval.string = NULL;
			    prev_state = YY_START;
			    BEGIN INSTR;
			}

<INITIAL,GOTDEFS>({ID}|{WORD}) {
			    /* a word */
			    if (!fill(yytext, yyleng))
				yyterminate();
			    LEXTRACE("WORD(5) ");
			    LEXRETURN(WORD);
			}

\(			{
			    LEXTRACE("( ");
			    LEXRETURN('(');
			}

\)			{
			    LEXTRACE(") ");
			    LEXRETURN(')');
			}

,			{
			    LEXTRACE(", ");
			    LEXRETURN(',');
			}			/* return ',' */

=			{
			    LEXTRACE("= ");
			    LEXRETURN('=');
			}			/* return '=' */

:			{
			    LEXTRACE(": ");
			    LEXRETURN(':');
			}			/* return ':' */

<*>!+			{
			    if (yyleng & 1) {
				LEXTRACE("!");
				LEXRETURN('!');	/* return '!' */
			    }
			}

<*>\n			{
			    if (YY_START == INSTR) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);	/* line break in string */
			    }
			    BEGIN INITIAL;
			    sudolineno++;
			    continued = FALSE;
			    LEXTRACE("\n");
			    LEXRETURN(COMMENT);
			}			/* return newline */

<*>[[:blank:]]+		{			/* throw away space/tabs */
			    sawspace = TRUE;	/* but remember for fill_args */
			}

<*>\\[[:blank:]]*\n	{
			    sawspace = TRUE;	/* remember for fill_args */
			    sudolineno++;
			    continued = TRUE;
			}			/* throw away EOL after \ */

<INITIAL,STARTDEFS,INDEFS>#(-[^\n0-9].*|[^\n0-9-].*)?\n	{
			    BEGIN INITIAL;
			    sudolineno++;
			    continued = FALSE;
			    LEXTRACE("#\n");
			    LEXRETURN(COMMENT);
			}			/* comment, not uid/gid */

<*>.			{
			    LEXTRACE("ERROR ");
			    LEXRETURN(ERROR);
			}	/* parse error */

<*><<EOF>>		{
			    if (YY_START != INITIAL) {
			    	BEGIN INITIAL;
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }
			    if (!pop_include())
				yyterminate();
			}

%%
struct path_list {
    char *path;
    struct path_list *next;
};

struct include_stack {
    YY_BUFFER_STATE bs;
    char *path;
    struct path_list *more; /* more files in case of includedir */
    int lineno;
    int keepopen;
};

static int
pl_compare(v1, v2)
    const void *v1;
    const void *v2;
{
    const struct path_list * const *p1 = v1;
    const struct path_list * const *p2 = v2;

    return strcmp((*p1)->path, (*p2)->path);
}

static char *
switch_dir(stack, dirpath)
    struct include_stack *stack;
    char *dirpath;
{
    DIR *dir;
    int i, count = 0;
    char *path = NULL;
    struct dirent *dent;
    struct stat sb;
    struct path_list *pl, *first = NULL;
    struct path_list **sorted = NULL;

    if (!(dir = opendir(dirpath))) {
	if (errno != ENOENT) {
	    char *errbuf;
	    if (asprintf(&errbuf, "%s: %s", dirpath, strerror(errno)) != -1) {
		yyerror(errbuf);
		free(errbuf);
	    } else {
		yyerror("unable to allocate memory");
	    }
	}
	goto done;
    }
    while ((dent = readdir(dir))) {
	/* Ignore files that end in '~' or have a '.' in them. */
	if (dent->d_name[0] == '\0' || dent->d_name[NAMLEN(dent) - 1] == '~'
	    || strchr(dent->d_name, '.') != NULL) {
	    continue;
	}
	if (asprintf(&path, "%s/%s", dirpath, dent->d_name) == -1) {
	    closedir(dir);
	    goto bad;
	}
	if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) {
	    efree(path);
	    path = NULL;
	    continue;
	}
	pl = malloc(sizeof(*pl));
	if (pl == NULL)
	    goto bad;
	pl->path = path;
	pl->next = first;
	first = pl;
	count++;
    }
    closedir(dir);

    if (count == 0)
	goto done;

    /* Sort the list as an array. */
    sorted = malloc(sizeof(*sorted) * count);
    if (sorted == NULL)
	goto bad;
    pl = first;
    for (i = 0; i < count; i++) {
	sorted[i] = pl;
	pl = pl->next;
    }
    qsort(sorted, count, sizeof(*sorted), pl_compare);

    /* Apply sorting to the list. */
    first = sorted[0];
    sorted[count - 1]->next = NULL;
    for (i = 1; i < count; i++)
	sorted[i - 1]->next = sorted[i];
    efree(sorted);

    /* Pull out the first element for parsing, leave the rest for later. */
    if (count) {
	path = first->path;
	pl = first->next;
	efree(first);
	stack->more = pl;
    } else {
	path = NULL;
    }
done:
    efree(dirpath);
    return path;
bad:
    while (first != NULL) {
	pl = first;
	first = pl->next;
	free(pl->path);
	free(pl);
    }
    efree(sorted);
    efree(dirpath);
    efree(path);
    return NULL;
}

#define MAX_SUDOERS_DEPTH	128
#define SUDOERS_STACK_INCREMENT	16

static size_t istacksize, idepth;
static struct include_stack *istack;
static int keepopen;

void
init_lexer()
{
    struct path_list *pl;

    while (idepth) {
	idepth--;
	while ((pl = istack[idepth].more) != NULL) {
	    istack[idepth].more = pl->next;
	    efree(pl->path);
	    efree(pl);
	}
	efree(istack[idepth].path);
	if (idepth && !istack[idepth].keepopen)
	    fclose(istack[idepth].bs->yy_input_file);
	yy_delete_buffer(istack[idepth].bs);
    }
    efree(istack);
    istack = NULL;
    istacksize = idepth = 0;
    sudolineno = 1;
    keepopen = FALSE;
    sawspace = FALSE;
    continued = FALSE;
    prev_state = INITIAL;
}

static int
_push_include(path, isdir)
    char *path;
    int isdir;
{
    struct path_list *pl;
    FILE *fp;

    /* push current state onto stack */
    if (idepth >= istacksize) {
	if (idepth > MAX_SUDOERS_DEPTH) {
	    yyerror("too many levels of includes");
	    return FALSE;
	}
	istacksize += SUDOERS_STACK_INCREMENT;
	istack = (struct include_stack *) realloc(istack,
	    sizeof(*istack) * istacksize);
	if (istack == NULL) {
	    yyerror("unable to allocate memory");
	    return FALSE;
	}
    }
    if (isdir) {
	struct stat sb;
	switch (sudo_secure_dir(path, SUDOERS_UID, SUDOERS_GID, &sb)) {
	    case SUDO_PATH_SECURE:
		break;
	    case SUDO_PATH_MISSING:
		return FALSE;
	    case SUDO_PATH_BAD_TYPE:
		errno = ENOTDIR;
		if (sudoers_warnings) {
		    warning(path);
		}
		return FALSE;
	    case SUDO_PATH_WRONG_OWNER:
		if (sudoers_warnings) {
		    warningx("%s is owned by uid %u, should be %u",
			path, (unsigned int) sb.st_uid,
			(unsigned int) SUDOERS_UID);
		}
		return FALSE;
	    case SUDO_PATH_WORLD_WRITABLE:
		if (sudoers_warnings) {
		    warningx("%s is world writable", path);
		}
		return FALSE;
	    case SUDO_PATH_GROUP_WRITABLE:
		if (sudoers_warnings) {
		    warningx("%s is owned by gid %u, should be %u",
			path, (unsigned int) sb.st_gid,
			(unsigned int) SUDOERS_GID);
		}
		return FALSE;
	    default:
		/* NOTREACHED */
		return FALSE;
	}
	if (!(path = switch_dir(&istack[idepth], path))) {
	    /* switch_dir() called yyerror() for us */
	    return FALSE;
	}
	while ((fp = open_sudoers(path, FALSE, &keepopen)) == NULL) {
	    /* Unable to open path in includedir, go to next one, if any. */
	    efree(path);
	    if ((pl = istack[idepth].more) == NULL)
		return FALSE;
	    path = pl->path;
	    istack[idepth].more = pl->next;
	    efree(pl);
	}
    } else {
	if ((fp = open_sudoers(path, TRUE, &keepopen)) == NULL) {
	    /* The error was already printed by open_sudoers() */
	    yyerror(NULL);
	    return FALSE;
	}
	istack[idepth].more = NULL;
    }
    /* Push the old (current) file and open the new one. */
    istack[idepth].path = sudoers; /* push old path */
    istack[idepth].bs = YY_CURRENT_BUFFER;
    istack[idepth].lineno = sudolineno;
    istack[idepth].keepopen = keepopen;
    idepth++;
    sudolineno = 1;
    sudoers = path;
    yy_switch_to_buffer(yy_create_buffer(fp, YY_BUF_SIZE));

    return TRUE;
}

static int
pop_include()
{
    struct path_list *pl;
    FILE *fp;

    if (idepth == 0)
	return FALSE;

    if (!keepopen)
	fclose(YY_CURRENT_BUFFER->yy_input_file);
    yy_delete_buffer(YY_CURRENT_BUFFER);
    /* If we are in an include dir, move to the next file. */
    while ((pl = istack[idepth - 1].more) != NULL) {
	fp = open_sudoers(pl->path, FALSE, &keepopen);
	if (fp != NULL) {
	    istack[idepth - 1].more = pl->next;
	    efree(sudoers);
	    sudoers = pl->path;
	    sudolineno = 1;
	    yy_switch_to_buffer(yy_create_buffer(fp, YY_BUF_SIZE));
	    efree(pl);
	    break;
	}
	/* Unable to open path in include dir, go to next one. */
	istack[idepth - 1].more = pl->next;
	efree(pl->path);
	efree(pl);
    }
    /* If no path list, just pop the last dir on the stack. */
    if (pl == NULL) {
	idepth--;
	yy_switch_to_buffer(istack[idepth].bs);
	efree(sudoers);
	sudoers = istack[idepth].path;
	sudolineno = istack[idepth].lineno;
	keepopen = istack[idepth].keepopen;
    }
    return TRUE;
}

static char *
parse_include(base)
    char *base;
{
    char *cp, *ep, *path, *pp;
    int dirlen = 0, len = 0, subst = 0;
    size_t shost_len = 0;

    /* Pull out path from #include line. */
    cp = base + sizeof("#include");
    if (*cp == 'i')
	cp += 3; /* includedir */
    while (isblank((unsigned char) *cp))
	cp++;
    ep = cp;
    while (*ep != '\0' && !isspace((unsigned char) *ep)) {
	if (ep[0] == '%' && ep[1] == 'h') {
	    shost_len = strlen(user_shost);
	    len += shost_len - 2;
	    subst = 1;
	}
	ep++;
    }

    /* Relative paths are located in the same dir as the sudoers file. */
    if (*cp != '/') {
	char *dirend = strrchr(sudoers, '/');
	if (dirend != NULL)
	    dirlen = (int)(dirend - sudoers) + 1;
    }

    /* Make a copy of the fully-qualified path and return it. */
    len += (int)(ep - cp);
    path = pp = malloc(len + dirlen + 1);
    if (path == NULL) {
	yyerror("unable to allocate memory");
	return NULL;
    }
    if (dirlen) {
	memcpy(path, sudoers, dirlen);
	pp += dirlen;
    }
    if (subst) {
	/* substitute for %h */
	while (cp < ep) {
	    if (cp[0] == '%' && cp[1] == 'h') {
		memcpy(pp, user_shost, shost_len);
		pp += shost_len;
		cp += 2;
		continue;
	    }
	    *pp++ = *cp++;
	}
	*pp = '\0';
    } else {
	memcpy(pp, cp, len);
	pp[len] = '\0';
    }

    /* Push any excess characters (e.g. comment, newline) back to the lexer */
    if (*ep != '\0')
	yyless((int)(ep - base));

    return path;
}
