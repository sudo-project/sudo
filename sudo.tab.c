#ifndef lint
/*static char yysccsid[] = "from: @(#)yaccpar	1.9 (Berkeley) 02/21/93";*/
static char yyrcsid[]
#if __GNUC__ >= 2
  __attribute__ ((unused))
#endif /* __GNUC__ >= 2 */
  = "$OpenBSD: skeleton.c,v 1.29 2008/07/08 15:06:50 otto Exp $";
#endif
#include <stdlib.h>
#include <string.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define YYPREFIX "yy"
#line 2 "parse.yacc"
/*
 * Copyright (c) 1996, 1998-2004, 2007
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

/*
 * XXX - the whole opFOO naming thing is somewhat bogus.
 *
 * XXX - the way things are stored for printmatches is stupid,
 *       they should be stored as elements in an array and then
 *       list_matches() can format things the way it wants.
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
#include <pwd.h>
#if defined(YYBISON) && defined(HAVE_ALLOCA_H) && !defined(__GNUC__)
# include <alloca.h>
#endif /* YYBISON && HAVE_ALLOCA_H && !__GNUC__ */
#ifdef HAVE_LSEARCH
# include <search.h>
#endif /* HAVE_LSEARCH */
#include <limits.h>

#include "sudo.h"
#include "parse.h"

#ifndef HAVE_LSEARCH
#include "emul/search.h"
#endif /* HAVE_LSEARCH */

/*
 * We must define SIZE_MAX for yacc's skeleton.c.
 * If there is no SIZE_MAX or SIZE_T_MAX we have to assume that size_t
 * could be signed (as it is on SunOS 4.x).
 */
#ifndef SIZE_MAX
# ifdef SIZE_T_MAX
#  define SIZE_MAX	SIZE_T_MAX
# else
#  define SIZE_MAX	INT_MAX
# endif /* SIZE_T_MAX */
#endif /* SIZE_MAX */

/*
 * Globals
 */
extern int sudolineno, parse_error;
int errorlineno = -1;
int clearaliases = TRUE;
int printmatches = FALSE;
int pedantic = FALSE;
int keepall = FALSE;
int quiet = FALSE;
int used_runas = FALSE;

/*
 * Alias types
 */
#define HOST_ALIAS		 1
#define CMND_ALIAS		 2
#define USER_ALIAS		 3
#define RUNAS_ALIAS		 4

#define SETMATCH(_var, _val)	do { \
	if ((_var) == UNSPEC || (_val) != NOMATCH) \
	    (_var) = (_val); \
} while (0)

#define SETNMATCH(_var, _val)	do { \
	if ((_val) != NOMATCH) \
	    (_var) = ! (_val); \
	else if ((_var) == UNSPEC) \
	    (_var) = NOMATCH; \
} while (0)

#define	SETENV_RESET \
	if (setenv_ok == IMPLIED) setenv_ok = def_setenv ? TRUE : UNSPEC

/*
 * The matching stack, initial space allocated in init_parser().
 */
struct matchstack *match;
int top = 0, stacksize = 0;

#define push \
    do { \
	if (top >= stacksize) { \
	    while ((stacksize += STACKINCREMENT) < top); \
	    match = (struct matchstack *) erealloc3(match, stacksize, sizeof(struct matchstack)); \
	} \
	match[top].user   = UNSPEC; \
	match[top].cmnd   = UNSPEC; \
	match[top].host   = UNSPEC; \
	match[top].runas  = UNSPEC; \
	match[top].nopass = def_authenticate ? UNSPEC : TRUE; \
	match[top].noexec = def_noexec ? TRUE : UNSPEC; \
	match[top].setenv = def_setenv ? TRUE : UNSPEC; \
	match[top].role = NULL; \
	match[top].type = NULL; \
	top++; \
    } while (0)

#define pushcp \
    do { \
	if (top >= stacksize) { \
	    while ((stacksize += STACKINCREMENT) < top); \
	    match = (struct matchstack *) erealloc3(match, stacksize, sizeof(struct matchstack)); \
	} \
	match[top].user   = match[top-1].user; \
	match[top].cmnd   = match[top-1].cmnd; \
	match[top].host   = match[top-1].host; \
	match[top].runas  = match[top-1].runas; \
	match[top].nopass = match[top-1].nopass; \
	match[top].noexec = match[top-1].noexec; \
	match[top].setenv = match[top-1].setenv; \
	match[top].role   = estrdup(match[top-1].role); \
	match[top].type   = estrdup(match[top-1].type); \
	top++; \
    } while (0)

#define pop \
    do { \
	if (top == 0) \
	    yyerror("matching stack underflow"); \
	else { \
	    efree(match[top-1].role); \
	    efree(match[top-1].type); \
	    top--; \
	} \
    } while (0)


/*
 * For testing if foo_matches variable was set to TRUE or FALSE
 */
#define	MATCHED(_v)	((_v) >= 0)

/*
 * Shortcuts for append()
 */
#define append_cmnd(s, p) append(s, &cm_list[cm_list_len].cmnd, \
	&cm_list[cm_list_len].cmnd_len, &cm_list[cm_list_len].cmnd_size, p)

#define append_runas(s, p) append(s, &cm_list[cm_list_len].runas, \
	&cm_list[cm_list_len].runas_len, &cm_list[cm_list_len].runas_size, p)

#define append_role(s, p) append(s, &cm_list[cm_list_len].role, \
	&cm_list[cm_list_len].role_len, &cm_list[cm_list_len].role_size, p)

#define append_type(s, p) append(s, &cm_list[cm_list_len].type, \
	&cm_list[cm_list_len].type_len, &cm_list[cm_list_len].type_size, p)

#define append_entries(s, p) append(s, &ga_list[ga_list_len-1].entries, \
	&ga_list[ga_list_len-1].entries_len, \
	&ga_list[ga_list_len-1].entries_size, p)

/*
 * The stack for printmatches.  A list of allowed commands for the user.
 */
static struct command_match *cm_list = NULL;
static size_t cm_list_len = 0, cm_list_size = 0;

/*
 * List of Cmnd_Aliases and expansions for `sudo -l'
 */
static int in_alias = FALSE;
static size_t ga_list_len = 0, ga_list_size = 0;
static struct generic_alias *ga_list = NULL;

/*
 * Does this Defaults list pertain to this user?
 */
static int defaults_matches = FALSE;

/*
 * Local protoypes
 */
static int  add_alias		__P((char *, int, int));
static void append		__P((char *, char **, size_t *, size_t *, char *));
static void expand_ga_list	__P((void));
static void expand_match_list	__P((void));
static aliasinfo *find_alias	__P((char *, int));
static void more_aliases	__P((void));
       void init_parser		__P((void));
       void yyerror		__P((char *));

void
yyerror(s)
    char *s;
{
    /* Save the line the first error occurred on. */
    if (errorlineno == -1)
	errorlineno = sudolineno ? sudolineno - 1 : 0;
    if (s && !quiet) {
#ifndef TRACELEXER
	(void) fprintf(stderr, ">>> sudoers file: %s, line %d <<<\n", s,
	    sudolineno ? sudolineno - 1 : 0);
#else
	(void) fprintf(stderr, "<*> ");
#endif
    }
    parse_error = TRUE;
}
#line 251 "parse.yacc"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
    struct selinux_info seinfo;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 280 "sudo.tab.c"
#define COMMAND 257
#define ALIAS 258
#define DEFVAR 259
#define NTWKADDR 260
#define NETGROUP 261
#define USERGROUP 262
#define WORD 263
#define DEFAULTS 264
#define DEFAULTS_HOST 265
#define DEFAULTS_USER 266
#define DEFAULTS_RUNAS 267
#define RUNAS 268
#define NOPASSWD 269
#define PASSWD 270
#define NOEXEC 271
#define EXEC 272
#define SETENV 273
#define NOSETENV 274
#define ALL 275
#define COMMENT 276
#define HOSTALIAS 277
#define CMNDALIAS 278
#define USERALIAS 279
#define RUNASALIAS 280
#define ERROR 281
#define TYPE 282
#define ROLE 283
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short yylhs[] =
#else
short yylhs[] =
#endif
	{                                        -1,
    0,    0,   10,   10,   12,   10,   10,   10,   10,   10,
   10,   18,   19,   21,   19,   22,   19,   24,   19,   20,
   20,   25,   25,   25,   25,   25,   13,   13,   26,   28,
   28,    2,    2,    2,    2,    2,   27,   27,   31,   29,
   33,   34,   33,    8,    9,    7,    7,    7,    7,    7,
   30,   30,    5,    5,    4,   35,    4,    3,    3,    3,
    3,    3,   32,   32,   32,   32,   32,   32,   32,    1,
    1,    1,   15,   15,   37,   36,   23,   23,   16,   16,
   39,   38,   40,   40,   17,   17,   42,   41,   14,   14,
   44,   43,   11,   11,   45,   45,    6,    6,    6,    6,
    6,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yylen[] =
#else
short yylen[] =
#endif
	{                                         2,
    1,    2,    1,    2,    0,    3,    2,    2,    2,    2,
    1,    2,    1,    0,    3,    0,    3,    0,    3,    1,
    3,    1,    2,    3,    3,    3,    1,    3,    3,    1,
    2,    1,    1,    1,    1,    1,    1,    3,    0,    5,
    1,    0,    3,    3,    3,    0,    1,    1,    2,    2,
    0,    2,    1,    3,    1,    0,    3,    1,    1,    1,
    1,    1,    0,    2,    2,    2,    2,    2,    2,    1,
    1,    1,    1,    3,    0,    4,    1,    3,    1,    3,
    0,    4,    1,    3,    1,    3,    0,    4,    1,    3,
    0,    4,    1,    3,    1,    2,    1,    1,    1,    1,
    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydefred[] =
#else
short yydefred[] =
#endif
	{                                      0,
    0,   13,   18,   14,   16,    3,    0,    0,    0,    0,
    0,    1,    0,   11,    0,    4,    0,    0,    0,   75,
    0,   73,   81,    0,   79,   91,    0,   89,   87,    0,
   85,    2,  100,   99,   98,   97,  101,    0,   95,    0,
   93,    0,    0,   12,    0,   36,   33,   34,   35,   32,
    0,   30,    0,   77,    0,   61,   60,   59,   58,   62,
   56,   55,   53,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   96,    0,    0,    0,   27,    0,    0,    0,
   23,    0,   31,    0,    0,    0,    0,   74,    0,   80,
    0,   90,    0,   86,   94,    0,   39,   24,   25,   26,
   21,   78,   57,   54,    0,   72,   71,   70,   42,   41,
   83,    0,    0,    0,   28,    0,   37,    0,    0,    0,
   39,    0,    0,   43,   84,   38,    0,    0,    0,   63,
    0,    0,    0,    0,    0,   49,   50,   45,   44,   64,
   65,   66,   67,   68,   69,   40,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydgoto[] =
#else
short yydgoto[] =
#endif
	{                                      11,
  110,   52,   62,   63,   64,   39,  130,  131,  132,   12,
   40,   13,   75,   27,   21,   24,   30,   14,   15,   44,
   18,   19,   76,   17,   45,   77,  116,   54,  117,  123,
  118,  135,  111,  119,   85,   22,   65,   25,   67,  112,
   31,   71,   28,   69,   41,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yysindex[] =
#else
short yysindex[] =
#endif
	{                                   -247,
 -248,    0,    0,    0,    0,    0, -211, -210, -205, -201,
 -247,    0,   62,    0,  -33,    0,   89,   62,  114,    0,
    2,    0,    0,    3,    0,    0,    4,    0,    0,    6,
    0,    0,    0,    0,    0,    0,    0, -251,    0,  -28,
    0,  -18, -194,    0,   14,    0,    0,    0,    0,    0,
 -219,    0,   22,    0,   23,    0,    0,    0,    0,    0,
    0,    0,    0,   24,    8, -211,    9, -210,   10, -205,
   11, -201,    0,   62,   16,  -23,    0, -187, -186, -184,
    0,  -33,    0,   89, -212,  114,   89,    0,  -20,    0,
   62,    0,  114,    0,    0,   89,    0,    0,    0,    0,
    0,    0,    0,    0,   22,    0,    0,    0,    0,    0,
    0,   36,   23,   24,    0,   37,    0, -185, -221,  -20,
    0,  114, -268,    0,    0,    0,   24,   21,   25,    0,
 -195, -193, -175, -174,  274,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yyrindex[] =
#else
short yyrindex[] =
#endif
	{                                    141,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  141,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  156,    0,    0,  181,    0,    0,  206,    0,    0,  236,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    1,    0,    0,  261,    0,    0,    0,    0,    0,
    0,    0,  -25,    0,  -11,    0,    0,    0,    0,    0,
    0,    0,    0,  -10,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  300,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   26,    0,    0,    0,    0,    0,
    0,   52,   78,  104,    0,  130,    0,  -29,    0,    0,
    0,    0,  340,    0,    0,    0,  313,    0,    0,    0,
  365,  391,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yygindex[] =
#else
short yygindex[] =
#endif
	{                                      0,
  -27,   40,   12,    7,  -87,   56,    0,  -36,  -32,   87,
  -16,    0,    0,    0,    0,    0,    0,    0,    0,   18,
    0,    0,  -14,    0,    0,    5,    0,   19,  -19,    0,
    0,    0,  -80,    0,    0,   39,    0,   38,    0,    0,
   35,    0,   42,    0,   34,
};
#define YYTABLESIZE 666
#if defined(__cplusplus) || defined(__STDC__)
const short yytable[] =
#else
short yytable[] =
#endif
	{                                      43,
   22,   55,   53,   51,   51,  114,   33,   19,    1,   34,
   35,   36,  109,  128,  129,   74,    2,    3,    4,    5,
   84,   15,   17,   37,   79,   76,   80,   16,    6,    7,
    8,    9,   10,   22,  127,  106,  107,   97,   46,  125,
   47,   48,   78,   49,   22,   56,   20,   23,   57,   58,
   59,   82,   26,  108,  146,   50,   29,   82,   76,   66,
   68,   70,   60,   72,   81,   84,   74,   86,   87,   89,
   91,   93,  105,   96,  113,   98,   99,   92,  100,  120,
  121,  133,  122,   76,   82,  134,  128,  138,  139,  129,
   83,  124,  104,   73,   38,  137,  103,   32,  136,  101,
  115,  126,  102,   88,   88,   90,   94,   95,    0,   82,
   92,   92,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   51,    0,    0,    0,    0,    0,    0,    0,   29,
    0,    0,    0,    0,    0,   92,   88,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   61,    0,    0,    0,
    0,    0,    0,    0,    0,    8,    0,    0,    0,    0,
    0,   88,   29,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    5,    0,    0,    0,    0,    0,    0,
    9,    0,    0,    0,    0,    0,    0,   29,    8,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    7,    0,    0,    0,    0,
    0,    0,    0,    9,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   42,    0,   51,   51,   46,
    0,   47,   48,   19,   49,   10,  106,  107,    7,   51,
   51,   51,   51,   51,   51,   51,   50,   15,   17,    0,
    0,    0,   51,   51,  108,    0,   22,    0,   22,    0,
   20,   22,   22,   22,   22,   22,   22,   22,   10,    0,
    0,    0,    0,    0,    0,   22,   22,   22,   22,   22,
   22,   76,    0,   76,    0,    0,   76,   76,   76,   76,
   76,   76,   76,   20,    0,    0,    0,    0,    0,    6,
   76,   76,   76,   76,   76,   76,  109,   82,    0,   82,
    0,    0,   82,   82,   82,   82,   82,   82,   82,   33,
    0,    0,   34,   35,   36,    0,   82,   82,   82,   82,
   82,   82,    6,   92,    0,   92,   37,    0,   92,   92,
   92,   92,   92,   92,   92,   52,   46,    0,   47,   48,
    0,   49,   92,   92,   92,   92,   92,   92,    0,   88,
    0,   88,    0,   50,   88,   88,   88,   88,   88,   88,
   88,   56,   46,    0,   57,   58,   59,    0,   88,   88,
   88,   88,   88,   88,    0,   29,    0,   29,   60,    0,
   29,   29,   29,   29,   29,   29,   29,   47,    5,    0,
    0,    5,    5,    5,   29,   29,   29,   29,   29,   29,
    0,    8,    0,    8,    0,    5,    8,    8,    8,    8,
    8,    8,    8,   48,    0,    0,    0,    0,    0,    0,
    8,    8,    8,    8,    8,    8,    9,    0,    9,    0,
    0,    9,    9,    9,    9,    9,    9,    9,    0,    0,
    0,    0,    0,    0,    0,    9,    9,    9,    9,    9,
    9,    7,    0,    7,    0,    0,    7,    7,    7,    7,
    7,    7,    7,    0,    0,    0,    0,    0,    0,    0,
    7,    7,    7,    7,    7,    7,    0,    0,    0,    0,
    0,   10,    0,   10,    0,    0,   10,   10,   10,   10,
   10,   10,   10,    0,    0,    0,    0,    0,    0,    0,
   10,   10,   10,   10,   10,   10,   20,    0,   20,    0,
    0,   20,   20,   20,   20,   20,   20,   20,    0,    0,
  106,  107,    0,    0,    0,   20,   20,   20,   20,   20,
   20,    0,  140,  141,  142,  143,  144,  145,  108,    0,
    0,    0,    0,    0,    0,    6,    0,    6,    0,    0,
    6,    6,    6,    6,    6,    6,    6,    0,    0,   52,
   52,    0,    0,    0,    6,    6,    6,    6,    6,    6,
    0,   52,   52,   52,   52,   52,   52,   52,    0,    0,
    0,    0,    0,    0,   52,   52,   46,   46,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   46,   46,
   46,   46,   46,   46,   46,    0,    0,    0,    0,    0,
    0,   47,   47,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   47,   47,   47,   47,   47,   47,   47,
    0,    0,    0,    0,    0,    0,    0,   48,   48,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   48,
   48,   48,   48,   48,   48,   48,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yycheck[] =
#else
short yycheck[] =
#endif
	{                                      33,
    0,   18,   17,   33,   33,   93,  258,   33,  256,  261,
  262,  263,   33,  282,  283,   44,  264,  265,  266,  267,
   44,   33,   33,  275,   43,    0,   45,  276,  276,  277,
  278,  279,  280,   33,  122,  257,  258,   61,  258,  120,
  260,  261,   61,  263,   44,  258,  258,  258,  261,  262,
  263,    0,  258,  275,  135,  275,  258,   44,   33,   58,
   58,   58,  275,   58,  259,   44,   44,   44,   61,   61,
   61,   61,   87,   58,   91,  263,  263,    0,  263,   44,
   44,   61,  268,   58,   33,   61,  282,  263,  263,  283,
   51,  119,   86,   38,   33,  132,   85,   11,  131,   82,
   96,  121,   84,    0,   66,   68,   72,   74,   -1,   58,
   33,   70,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,    0,
   -1,   -1,   -1,   -1,   -1,   58,   33,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   33,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   58,   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   58,   33,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  259,   -1,  257,  258,  258,
   -1,  260,  261,  259,  263,    0,  257,  258,   33,  269,
  270,  271,  272,  273,  274,  275,  275,  259,  259,   -1,
   -1,   -1,  282,  283,  275,   -1,  256,   -1,  258,   -1,
    0,  261,  262,  263,  264,  265,  266,  267,   33,   -1,
   -1,   -1,   -1,   -1,   -1,  275,  276,  277,  278,  279,
  280,  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,   33,   -1,   -1,   -1,   -1,   -1,    0,
  275,  276,  277,  278,  279,  280,   33,  256,   -1,  258,
   -1,   -1,  261,  262,  263,  264,  265,  266,  267,  258,
   -1,   -1,  261,  262,  263,   -1,  275,  276,  277,  278,
  279,  280,   33,  256,   -1,  258,  275,   -1,  261,  262,
  263,  264,  265,  266,  267,   33,  258,   -1,  260,  261,
   -1,  263,  275,  276,  277,  278,  279,  280,   -1,  256,
   -1,  258,   -1,  275,  261,  262,  263,  264,  265,  266,
  267,  258,   33,   -1,  261,  262,  263,   -1,  275,  276,
  277,  278,  279,  280,   -1,  256,   -1,  258,  275,   -1,
  261,  262,  263,  264,  265,  266,  267,   33,  258,   -1,
   -1,  261,  262,  263,  275,  276,  277,  278,  279,  280,
   -1,  256,   -1,  258,   -1,  275,  261,  262,  263,  264,
  265,  266,  267,   33,   -1,   -1,   -1,   -1,   -1,   -1,
  275,  276,  277,  278,  279,  280,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,  267,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  275,  276,  277,  278,  279,
  280,  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  275,  276,  277,  278,  279,  280,   -1,   -1,   -1,   -1,
   -1,  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  275,  276,  277,  278,  279,  280,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,  267,   -1,   -1,
  257,  258,   -1,   -1,   -1,  275,  276,  277,  278,  279,
  280,   -1,  269,  270,  271,  272,  273,  274,  275,   -1,
   -1,   -1,   -1,   -1,   -1,  256,   -1,  258,   -1,   -1,
  261,  262,  263,  264,  265,  266,  267,   -1,   -1,  257,
  258,   -1,   -1,   -1,  275,  276,  277,  278,  279,  280,
   -1,  269,  270,  271,  272,  273,  274,  275,   -1,   -1,
   -1,   -1,   -1,   -1,  282,  283,  257,  258,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  269,  270,
  271,  272,  273,  274,  275,   -1,   -1,   -1,   -1,   -1,
   -1,  257,  258,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  269,  270,  271,  272,  273,  274,  275,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  257,  258,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  269,
  270,  271,  272,  273,  274,  275,
};
#define YYFINAL 11
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 283
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyname[] =
#else
char *yyname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,0,0,0,0,0,"'+'","','","'-'",0,0,0,0,0,0,0,0,0,0,0,0,"':'",0,0,
"'='",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"COMMAND","ALIAS","DEFVAR","NTWKADDR","NETGROUP","USERGROUP","WORD","DEFAULTS",
"DEFAULTS_HOST","DEFAULTS_USER","DEFAULTS_RUNAS","RUNAS","NOPASSWD","PASSWD",
"NOEXEC","EXEC","SETENV","NOSETENV","ALL","COMMENT","HOSTALIAS","CMNDALIAS",
"USERALIAS","RUNASALIAS","ERROR","TYPE","ROLE",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyrule[] =
#else
char *yyrule[] =
#endif
	{"$accept : file",
"file : entry",
"file : file entry",
"entry : COMMENT",
"entry : error COMMENT",
"$$1 :",
"entry : $$1 userlist privileges",
"entry : USERALIAS useraliases",
"entry : HOSTALIAS hostaliases",
"entry : CMNDALIAS cmndaliases",
"entry : RUNASALIAS runasaliases",
"entry : defaults_line",
"defaults_line : defaults_type defaults_list",
"defaults_type : DEFAULTS",
"$$2 :",
"defaults_type : DEFAULTS_USER $$2 userlist",
"$$3 :",
"defaults_type : DEFAULTS_RUNAS $$3 runaslist",
"$$4 :",
"defaults_type : DEFAULTS_HOST $$4 hostlist",
"defaults_list : defaults_entry",
"defaults_list : defaults_entry ',' defaults_list",
"defaults_entry : DEFVAR",
"defaults_entry : '!' DEFVAR",
"defaults_entry : DEFVAR '=' WORD",
"defaults_entry : DEFVAR '+' WORD",
"defaults_entry : DEFVAR '-' WORD",
"privileges : privilege",
"privileges : privileges ':' privilege",
"privilege : hostlist '=' cmndspeclist",
"ophost : host",
"ophost : '!' host",
"host : ALL",
"host : NTWKADDR",
"host : NETGROUP",
"host : WORD",
"host : ALIAS",
"cmndspeclist : cmndspec",
"cmndspeclist : cmndspeclist ',' cmndspec",
"$$5 :",
"cmndspec : $$5 runasspec selinux cmndtag opcmnd",
"opcmnd : cmnd",
"$$6 :",
"opcmnd : '!' $$6 cmnd",
"rolespec : ROLE '=' WORD",
"typespec : TYPE '=' WORD",
"selinux :",
"selinux : rolespec",
"selinux : typespec",
"selinux : rolespec typespec",
"selinux : typespec rolespec",
"runasspec :",
"runasspec : RUNAS runaslist",
"runaslist : oprunasuser",
"runaslist : runaslist ',' oprunasuser",
"oprunasuser : runasuser",
"$$7 :",
"oprunasuser : '!' $$7 runasuser",
"runasuser : WORD",
"runasuser : USERGROUP",
"runasuser : NETGROUP",
"runasuser : ALIAS",
"runasuser : ALL",
"cmndtag :",
"cmndtag : cmndtag NOPASSWD",
"cmndtag : cmndtag PASSWD",
"cmndtag : cmndtag NOEXEC",
"cmndtag : cmndtag EXEC",
"cmndtag : cmndtag SETENV",
"cmndtag : cmndtag NOSETENV",
"cmnd : ALL",
"cmnd : ALIAS",
"cmnd : COMMAND",
"hostaliases : hostalias",
"hostaliases : hostaliases ':' hostalias",
"$$8 :",
"hostalias : ALIAS $$8 '=' hostlist",
"hostlist : ophost",
"hostlist : hostlist ',' ophost",
"cmndaliases : cmndalias",
"cmndaliases : cmndaliases ':' cmndalias",
"$$9 :",
"cmndalias : ALIAS $$9 '=' cmndlist",
"cmndlist : opcmnd",
"cmndlist : cmndlist ',' opcmnd",
"runasaliases : runasalias",
"runasaliases : runasaliases ':' runasalias",
"$$10 :",
"runasalias : ALIAS $$10 '=' runaslist",
"useraliases : useralias",
"useraliases : useraliases ':' useralias",
"$$11 :",
"useralias : ALIAS $$11 '=' userlist",
"userlist : opuser",
"userlist : userlist ',' opuser",
"opuser : user",
"opuser : '!' user",
"user : WORD",
"user : USERGROUP",
"user : NETGROUP",
"user : ALIAS",
"user : ALL",
};
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
/* LINTUSED */
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
#line 1061 "parse.yacc"

#define MOREALIASES (32)
aliasinfo *aliases = NULL;
size_t naliases = 0;
size_t nslots = 0;


/*
 * Compare two aliasinfo structures, strcmp() style.
 * Note that we do *not* compare their values.
 */
static int
aliascmp(a1, a2)
    const VOID *a1, *a2;
{
    int r;
    aliasinfo *ai1, *ai2;

    ai1 = (aliasinfo *) a1;
    ai2 = (aliasinfo *) a2;
    if ((r = strcmp(ai1->name, ai2->name)) == 0)
	r = ai1->type - ai2->type;

    return(r);
}

/*
 * Compare two generic_alias structures, strcmp() style.
 */
static int
genaliascmp(entry, key)
    const VOID *entry, *key;
{
    int r;
    struct generic_alias *ga1, *ga2;

    ga1 = (struct generic_alias *) key;
    ga2 = (struct generic_alias *) entry;
    if ((r = strcmp(ga1->alias, ga2->alias)) == 0)
	r = ga1->type - ga2->type;

    return(r);
}


/*
 * Adds the named alias of the specified type to the aliases list.
 */
static int
add_alias(alias, type, val)
    char *alias;
    int type;
    int val;
{
    aliasinfo ai, *aip;
    size_t onaliases;
    char s[512];

    if (naliases >= nslots)
	more_aliases();

    ai.type = type;
    ai.val = val;
    ai.name = estrdup(alias);
    onaliases = naliases;

    aip = (aliasinfo *) lsearch((VOID *)&ai, (VOID *)aliases, &naliases,
				sizeof(ai), aliascmp);
    if (aip == NULL) {
	(void) snprintf(s, sizeof(s), "Aliases corrupted defining alias `%s'",
			alias);
	yyerror(s);
	return(FALSE);
    }
    if (onaliases == naliases) {
	(void) snprintf(s, sizeof(s), "Alias `%s' already defined", alias);
	yyerror(s);
	return(FALSE);
    }

    return(TRUE);
}

/*
 * Searches for the named alias of the specified type.
 */
static aliasinfo *
find_alias(alias, type)
    char *alias;
    int type;
{
    aliasinfo ai;

    ai.name = alias;
    ai.type = type;

    return((aliasinfo *) lfind((VOID *)&ai, (VOID *)aliases, &naliases,
		 sizeof(ai), aliascmp));
}

/*
 * Allocates more space for the aliases list.
 */
static void
more_aliases()
{

    nslots += MOREALIASES;
    aliases = (aliasinfo *) erealloc3(aliases, nslots, sizeof(aliasinfo));
}

/*
 * Lists the contents of the aliases list.
 */
void
dumpaliases()
{
    size_t n;

    for (n = 0; n < naliases; n++) {
	if (aliases[n].val == -1)
	    continue;

	switch (aliases[n].type) {
	case HOST_ALIAS:
	    (void) puts("HOST_ALIAS");
	    break;

	case CMND_ALIAS:
	    (void) puts("CMND_ALIAS");
	    break;

	case USER_ALIAS:
	    (void) puts("USER_ALIAS");
	    break;

	case RUNAS_ALIAS:
	    (void) puts("RUNAS_ALIAS");
	    break;
	}
	(void) printf("\t%s: %d\n", aliases[n].name, aliases[n].val);
    }
}

/*
 * Lists the contents of cm_list and ga_list for `sudo -l'.
 */
void
list_matches()
{
    size_t count;
    char *p;
    struct generic_alias *ga, key;

    (void) printf("User %s may run the following commands on this host:\n",
	user_name);
    for (count = 0; count < cm_list_len; count++) {

	/* Print the runas list. */
	(void) fputs("    ", stdout);
	if (cm_list[count].runas) {
	    (void) putchar('(');
	    p = strtok(cm_list[count].runas, ", ");
	    do {
		if (p != cm_list[count].runas)
		    (void) fputs(", ", stdout);

		key.alias = p;
		key.type = RUNAS_ALIAS;
		if ((ga = (struct generic_alias *) lfind((VOID *) &key,
		    (VOID *) &ga_list[0], &ga_list_len, sizeof(key), genaliascmp)))
		    (void) fputs(ga->entries, stdout);
		else
		    (void) fputs(p, stdout);
	    } while ((p = strtok(NULL, ", ")));
	    (void) fputs(") ", stdout);
	} else {
	    (void) printf("(%s) ", def_runas_default);
	}

#ifdef HAVE_SELINUX
	/* SELinux role and type */
	if (cm_list[count].role != NULL)
	    (void) printf("ROLE=%s ", cm_list[count].role);
	if (cm_list[count].type != NULL)
	    (void) printf("TYPE=%s ", cm_list[count].type);
#endif

	/* Is execve(2) disabled? */
	if (cm_list[count].noexecve == TRUE && !def_noexec)
	    (void) fputs("NOEXEC: ", stdout);
	else if (cm_list[count].noexecve == FALSE && def_noexec)
	    (void) fputs("EXEC: ", stdout);

	/* Is a password required? */
	if (cm_list[count].nopasswd == TRUE && def_authenticate)
	    (void) fputs("NOPASSWD: ", stdout);
	else if (cm_list[count].nopasswd == FALSE && !def_authenticate)
	    (void) fputs("PASSWD: ", stdout);

	/* Is setenv enabled? */
	if (cm_list[count].setenv == TRUE && !def_setenv)
	    (void) fputs("SETENV: ", stdout);
	else if (cm_list[count].setenv == FALSE && def_setenv)
	    (void) fputs("NOSETENV: ", stdout);

	/* Print the actual command or expanded Cmnd_Alias. */
	key.alias = cm_list[count].cmnd;
	key.type = CMND_ALIAS;
	if ((ga = (struct generic_alias *) lfind((VOID *) &key,
	    (VOID *) &ga_list[0], &ga_list_len, sizeof(key), genaliascmp)))
	    (void) puts(ga->entries);
	else
	    (void) puts(cm_list[count].cmnd);
    }

    /* Be nice and free up space now that we are done. */
    for (count = 0; count < ga_list_len; count++) {
	efree(ga_list[count].alias);
	efree(ga_list[count].entries);
    }
    efree(ga_list);
    ga_list = NULL;

    for (count = 0; count < cm_list_len; count++) {
	efree(cm_list[count].runas);
	efree(cm_list[count].cmnd);
	efree(cm_list[count].role);
	efree(cm_list[count].type);
    }
    efree(cm_list);
    cm_list = NULL;
    cm_list_len = 0;
    cm_list_size = 0;
}

/*
 * Appends a source string to the destination, optionally prefixing a separator.
 */
static void
append(src, dstp, dst_len, dst_size, separator)
    char *src, **dstp;
    size_t *dst_len, *dst_size;
    char *separator;
{
    size_t src_len = strlen(src);
    char *dst = *dstp;

    /*
     * Only add the separator if there is something to separate from.
     * If the last char is a '!', don't apply the separator (XXX).
     */
    if (separator && dst && dst[*dst_len - 1] != '!')
	src_len += strlen(separator);
    else
	separator = NULL;

    /* Assumes dst will be NULL if not set. */
    if (dst == NULL) {
	dst = (char *) emalloc(BUFSIZ);
	*dst = '\0';
	*dst_size = BUFSIZ;
	*dst_len = 0;
	*dstp = dst;
    }

    /* Allocate more space if necessary. */
    if (*dst_size <= *dst_len + src_len) {
	while (*dst_size <= *dst_len + src_len)
	    *dst_size += BUFSIZ;

	dst = (char *) erealloc(dst, *dst_size);
	*dstp = dst;
    }

    /* Copy src -> dst adding a separator if appropriate and adjust len. */
    if (separator)
	(void) strlcat(dst, separator, *dst_size);
    (void) strlcat(dst, src, *dst_size);
    *dst_len += src_len;
}

/*
 * Frees up space used by the aliases list and resets the associated counters.
 */
void
reset_aliases()
{
    size_t n;

    if (aliases) {
	for (n = 0; n < naliases; n++)
	    efree(aliases[n].name);
	efree(aliases);
	aliases = NULL;
    }
    naliases = nslots = 0;
}

/*
 * Increments ga_list_len, allocating more space as necessary.
 */
static void
expand_ga_list()
{

    if (++ga_list_len >= ga_list_size) {
	while ((ga_list_size += STACKINCREMENT) < ga_list_len)
	    ;
	ga_list = (struct generic_alias *)
	    erealloc3(ga_list, ga_list_size, sizeof(struct generic_alias));
    }

    ga_list[ga_list_len - 1].entries = NULL;
}

/*
 * Increments cm_list_len, allocating more space as necessary.
 */
static void
expand_match_list()
{

    if (++cm_list_len >= cm_list_size) {
	while ((cm_list_size += STACKINCREMENT) < cm_list_len)
	    ;
	if (cm_list == NULL)
	    cm_list_len = 0;		/* start at 0 since it is a subscript */
	cm_list = (struct command_match *)
	    erealloc3(cm_list, cm_list_size, sizeof(struct command_match));
    }

    cm_list[cm_list_len].runas = cm_list[cm_list_len].cmnd = NULL;
    cm_list[cm_list_len].type = cm_list[cm_list_len].role = NULL;
    cm_list[cm_list_len].nopasswd = FALSE;
    cm_list[cm_list_len].noexecve = FALSE;
    cm_list[cm_list_len].setenv = FALSE;
}

/*
 * Frees up spaced used by a previous parser run and allocates new space
 * for various data structures.
 */
void
init_parser()
{

    /* Free up old data structures if we run the parser more than once. */
    if (match) {
	efree(match);
	match = NULL;
	top = 0;
	parse_error = FALSE;
	used_runas = FALSE;
	errorlineno = -1;
	sudolineno = 1;
    }

    /* Allocate space for the matching stack. */
    stacksize = STACKINCREMENT;
    match = (struct matchstack *) emalloc2(stacksize, sizeof(struct matchstack));

    /* Allocate space for the match list (for `sudo -l'). */
    if (printmatches == TRUE)
	expand_match_list();
}
#line 1055 "sudo.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
#if defined(__cplusplus) || defined(__STDC__)
static int yygrowstack(void)
#else
static int yygrowstack()
#endif
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#define YY_SIZE_MAX 0xffffffffU
#endif
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + i;
    if (newsize && YY_SIZE_MAX / newsize < sizeof *newvs)
        goto bail;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return -1;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
#if defined(__cplusplus) || defined(__STDC__)
yyparse(void)
#else
yyparse()
#endif
{
    int yym, yyn, yystate;
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
    const char *yys;
#else /* !(defined(__cplusplus) || defined(__STDC__)) */
    char *yys;
#endif /* !(defined(__cplusplus) || defined(__STDC__)) */

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif /* YYDEBUG */

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 3:
#line 313 "parse.yacc"
{ ; }
break;
case 4:
#line 315 "parse.yacc"
{ yyerrok; }
break;
case 5:
#line 316 "parse.yacc"
{ push; }
break;
case 6:
#line 316 "parse.yacc"
{
			    while (top && user_matches != TRUE)
				pop;
			}
break;
case 7:
#line 321 "parse.yacc"
{ ; }
break;
case 8:
#line 323 "parse.yacc"
{ ; }
break;
case 9:
#line 325 "parse.yacc"
{ ; }
break;
case 10:
#line 327 "parse.yacc"
{ ; }
break;
case 11:
#line 329 "parse.yacc"
{ ; }
break;
case 13:
#line 335 "parse.yacc"
{
			    defaults_matches = TRUE;
			}
break;
case 14:
#line 338 "parse.yacc"
{ push; }
break;
case 15:
#line 338 "parse.yacc"
{
			    defaults_matches = user_matches;
			    pop;
			}
break;
case 16:
#line 342 "parse.yacc"
{ push; }
break;
case 17:
#line 342 "parse.yacc"
{
			    defaults_matches = yyvsp[0].BOOLEAN == TRUE;
			    pop;
			}
break;
case 18:
#line 346 "parse.yacc"
{ push; }
break;
case 19:
#line 346 "parse.yacc"
{
			    defaults_matches = host_matches;
			    pop;
			}
break;
case 22:
#line 356 "parse.yacc"
{
			    if (defaults_matches == TRUE &&
				!set_default(yyvsp[0].string, NULL, TRUE)) {
				yyerror(NULL);
				YYERROR;
			    }
			    efree(yyvsp[0].string);
			}
break;
case 23:
#line 364 "parse.yacc"
{
			    if (defaults_matches == TRUE &&
				!set_default(yyvsp[0].string, NULL, FALSE)) {
				yyerror(NULL);
				YYERROR;
			    }
			    efree(yyvsp[0].string);
			}
break;
case 24:
#line 372 "parse.yacc"
{
			    if (defaults_matches == TRUE &&
				!set_default(yyvsp[-2].string, yyvsp[0].string, TRUE)) {
				yyerror(NULL);
				YYERROR;
			    }
			    efree(yyvsp[-2].string);
			    efree(yyvsp[0].string);
			}
break;
case 25:
#line 381 "parse.yacc"
{
			    if (defaults_matches == TRUE &&
				!set_default(yyvsp[-2].string, yyvsp[0].string, '+')) {
				yyerror(NULL);
				YYERROR;
			    }
			    efree(yyvsp[-2].string);
			    efree(yyvsp[0].string);
			}
break;
case 26:
#line 390 "parse.yacc"
{
			    if (defaults_matches == TRUE &&
				!set_default(yyvsp[-2].string, yyvsp[0].string, '-')) {
				yyerror(NULL);
				YYERROR;
			    }
			    efree(yyvsp[-2].string);
			    efree(yyvsp[0].string);
			}
break;
case 29:
#line 405 "parse.yacc"
{
			    /*
			     * We already did a push if necessary in
			     * cmndspec so just reset some values so
			     * the next 'privilege' gets a clean slate.
			     */
			    host_matches = UNSPEC;
			    runas_matches = UNSPEC;
			    no_passwd = def_authenticate ? UNSPEC : TRUE;
			    no_execve = def_noexec ? TRUE : UNSPEC;
			    setenv_ok = def_setenv ? TRUE : UNSPEC;
#ifdef HAVE_SELINUX
			    efree(match[top-1].role);
			    match[top-1].role = NULL;
			    efree(match[top-1].type);
			    match[top-1].type = NULL;
#endif
			}
break;
case 30:
#line 425 "parse.yacc"
{
			    SETMATCH(host_matches, yyvsp[0].BOOLEAN);
			}
break;
case 31:
#line 428 "parse.yacc"
{
			    SETNMATCH(host_matches, yyvsp[0].BOOLEAN);
			}
break;
case 32:
#line 433 "parse.yacc"
{
			    yyval.BOOLEAN = TRUE;
			}
break;
case 33:
#line 436 "parse.yacc"
{
			    if (addr_matches(yyvsp[0].string))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;
			    efree(yyvsp[0].string);
			}
break;
case 34:
#line 443 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, user_host, user_shost, NULL))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;
			    efree(yyvsp[0].string);
			}
break;
case 35:
#line 450 "parse.yacc"
{
			    if (hostname_matches(user_shost, user_host, yyvsp[0].string) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;
			    efree(yyvsp[0].string);
			}
break;
case 36:
#line 457 "parse.yacc"
{
			    aliasinfo *aip = find_alias(yyvsp[0].string, HOST_ALIAS);

			    /* could be an all-caps hostname */
			    if (aip)
				yyval.BOOLEAN = aip->val;
			    else if (strcasecmp(user_shost, yyvsp[0].string) == 0)
				yyval.BOOLEAN = TRUE;
			    else {
				if (pedantic) {
				    (void) fprintf(stderr,
					"%s: undeclared Host_Alias `%s' referenced near line %d\n",
					(pedantic == 1) ? "Warning" : "Error", yyvsp[0].string, sudolineno);
				    if (pedantic > 1) {
					yyerror(NULL);
					YYERROR;
				    }
				}
				yyval.BOOLEAN = NOMATCH;
			    }
			    efree(yyvsp[0].string);
			}
break;
case 39:
#line 485 "parse.yacc"
{ SETENV_RESET; }
break;
case 40:
#line 485 "parse.yacc"
{
#ifdef HAVE_SELINUX
			    /* Replace inherited role/type as needed. */
			    if (yyvsp[-2].seinfo.role != NULL) {
				efree(match[top-1].role);
				match[top-1].role = yyvsp[-2].seinfo.role;
			    }
			    if (yyvsp[-2].seinfo.type != NULL) {
				efree(match[top-1].type);
				match[top-1].type = yyvsp[-2].seinfo.type;
			    }
#endif
			    /*
			     * Push the entry onto the stack if it is worth
			     * saving and reset cmnd_matches for next cmnd.
			     *
			     * We need to save at least one entry on
			     * the stack so sudoers_lookup() can tell that
			     * the user was listed in sudoers.  Also, we
			     * need to be able to tell whether or not a
			     * user was listed for this specific host.
			     *
			     * If keepall is set and the user matches then
			     * we need to keep entries around too...
			     */
			    if (MATCHED(user_matches) &&
				MATCHED(host_matches) &&
				MATCHED(cmnd_matches) &&
				MATCHED(runas_matches))
				pushcp;
			    else if (MATCHED(user_matches) && (top == 1 ||
				(top == 2 && MATCHED(host_matches) &&
				!MATCHED(match[0].host))))
				pushcp;
			    else if (user_matches == TRUE && keepall)
				pushcp;

			    cmnd_matches = UNSPEC;
			}
break;
case 41:
#line 526 "parse.yacc"
{
			    SETMATCH(cmnd_matches, yyvsp[0].BOOLEAN);
			}
break;
case 42:
#line 529 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("!", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_cmnd("!", NULL);
			    }
			}
break;
case 43:
#line 537 "parse.yacc"
{
			    SETNMATCH(cmnd_matches, yyvsp[0].BOOLEAN);
			}
break;
case 44:
#line 542 "parse.yacc"
{
#ifdef HAVE_SELINUX
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE && runas_matches == TRUE)
				append_role(yyvsp[0].string, NULL);
			    yyval.string = yyvsp[0].string;
#else
			    free(yyvsp[0].string);
			    yyval.string = NULL;
#endif /* HAVE_SELINUX */
			}
break;
case 45:
#line 555 "parse.yacc"
{
#ifdef HAVE_SELINUX
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE && runas_matches == TRUE)
				append_type(yyvsp[0].string, NULL);
			    yyval.string = yyvsp[0].string;
#else
			    free(yyvsp[0].string);
			    yyval.string = NULL;
#endif /* HAVE_SELINUX */
			}
break;
case 46:
#line 568 "parse.yacc"
{
#ifdef HAVE_SELINUX
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE && runas_matches == TRUE) {
				if (match[top-1].role != NULL) {
				    /* Inherit role. */
				    cm_list[cm_list_len].role =
					estrdup(cm_list[cm_list_len-1].role);
				    cm_list[cm_list_len].role_len =
					cm_list[cm_list_len-1].role_len;
				    cm_list[cm_list_len].role_size =
					cm_list[cm_list_len-1].role_len + 1;
				}
				if (match[top-1].type != NULL) {
				    /* Inherit type. */
				    cm_list[cm_list_len].type =
					estrdup(cm_list[cm_list_len-1].type);
				    cm_list[cm_list_len].type_len =
					cm_list[cm_list_len-1].type_len;
				    cm_list[cm_list_len].type_size =
					cm_list[cm_list_len-1].type_len + 1;
				}
			    }
#endif /* HAVE_SELINUX */
			    yyval.seinfo.role = NULL;
			    yyval.seinfo.type = NULL;
			}
break;
case 47:
#line 595 "parse.yacc"
{
#ifdef HAVE_SELINUX
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE && runas_matches == TRUE) {
				if (match[top-1].type != NULL) {
				    /* Inherit type. */
				    cm_list[cm_list_len].type =
					estrdup(cm_list[cm_list_len-1].type);
				    cm_list[cm_list_len].type_len =
					cm_list[cm_list_len-1].type_len;
				    cm_list[cm_list_len].type_size =
					cm_list[cm_list_len-1].type_len + 1;
				}
			    }
#endif /* HAVE_SELINUX */
			    yyval.seinfo.role = yyvsp[0].string;
			    yyval.seinfo.type = NULL;
			}
break;
case 48:
#line 613 "parse.yacc"
{
#ifdef HAVE_SELINUX
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE && runas_matches == TRUE) {
				if (match[top-1].role != NULL) {
				    /* Inherit role. */
				    cm_list[cm_list_len].role =
					estrdup(cm_list[cm_list_len-1].role);
				    cm_list[cm_list_len].role_len =
					cm_list[cm_list_len-1].role_len;
				    cm_list[cm_list_len].role_size =
					cm_list[cm_list_len-1].role_len + 1;
				}
			    }
#endif /* HAVE_SELINUX */
			    yyval.seinfo.type = yyvsp[0].string;
			    yyval.seinfo.role = NULL;
			}
break;
case 49:
#line 631 "parse.yacc"
{
			    yyval.seinfo.role = yyvsp[-1].string;
			    yyval.seinfo.type = yyvsp[0].string;
			}
break;
case 50:
#line 635 "parse.yacc"
{
			    yyval.seinfo.type = yyvsp[-1].string;
			    yyval.seinfo.role = yyvsp[0].string;
			}
break;
case 51:
#line 641 "parse.yacc"
{
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				if (runas_matches == UNSPEC) {
				    cm_list[cm_list_len].runas_len = 0;
				} else {
				    /* Inherit runas data. */
				    cm_list[cm_list_len].runas =
					estrdup(cm_list[cm_list_len-1].runas);
				    cm_list[cm_list_len].runas_len =
					cm_list[cm_list_len-1].runas_len;
				    cm_list[cm_list_len].runas_size =
					cm_list[cm_list_len-1].runas_len + 1;
				}
			    }
			    /*
			     * If this is the first entry in a command list
			     * then check against default runas user.
			     */
			    if (runas_matches == UNSPEC) {
				runas_matches = userpw_matches(def_runas_default,
				    *user_runas, runas_pw) ? TRUE : NOMATCH;
			    }
			}
break;
case 52:
#line 665 "parse.yacc"
{
			    runas_matches = yyvsp[0].BOOLEAN;
			}
break;
case 53:
#line 670 "parse.yacc"
{ ; }
break;
case 54:
#line 671 "parse.yacc"
{
			    /* Later entries override earlier ones. */
			    if (yyvsp[0].BOOLEAN != NOMATCH)
				yyval.BOOLEAN = yyvsp[0].BOOLEAN;
			    else
				yyval.BOOLEAN = yyvsp[-2].BOOLEAN;
			}
break;
case 55:
#line 680 "parse.yacc"
{ ; }
break;
case 56:
#line 681 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("!", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas("!", ", ");
			    }
			}
break;
case 57:
#line 689 "parse.yacc"
{
			    /* Set $$ to the negation of runasuser */
			    yyval.BOOLEAN = (yyvsp[0].BOOLEAN == NOMATCH ? NOMATCH : ! yyvsp[0].BOOLEAN);
			}
break;
case 58:
#line 695 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    if (userpw_matches(yyvsp[0].string, *user_runas, runas_pw))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;
			    efree(yyvsp[0].string);
			    used_runas = TRUE;
			}
break;
case 59:
#line 710 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    if (usergr_matches(yyvsp[0].string, *user_runas, runas_pw))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;
			    efree(yyvsp[0].string);
			    used_runas = TRUE;
			}
break;
case 60:
#line 725 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    if (netgr_matches(yyvsp[0].string, NULL, NULL, *user_runas))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;
			    efree(yyvsp[0].string);
			    used_runas = TRUE;
			}
break;
case 61:
#line 740 "parse.yacc"
{
			    aliasinfo *aip = find_alias(yyvsp[0].string, RUNAS_ALIAS);

			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    /* could be an all-caps username */
			    if (aip)
				yyval.BOOLEAN = aip->val;
			    else if (strcmp(yyvsp[0].string, *user_runas) == 0)
				yyval.BOOLEAN = TRUE;
			    else {
				if (pedantic) {
				    (void) fprintf(stderr,
					"%s: undeclared Runas_Alias `%s' referenced near line %d\n",
					(pedantic == 1) ? "Warning" : "Error", yyvsp[0].string, sudolineno);
				    if (pedantic > 1) {
					yyerror(NULL);
					YYERROR;
				    }
				}
				yyval.BOOLEAN = NOMATCH;
			    }
			    efree(yyvsp[0].string);
			    used_runas = TRUE;
			}
break;
case 62:
#line 770 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("ALL", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas("ALL", ", ");
			    }
			    yyval.BOOLEAN = TRUE;
			}
break;
case 63:
#line 782 "parse.yacc"
{
			    /* Inherit {NO,}{PASSWD,EXEC,SETENV} status. */
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				if (no_passwd == TRUE)
				    cm_list[cm_list_len].nopasswd = TRUE;
				else
				    cm_list[cm_list_len].nopasswd = FALSE;
				if (no_execve == TRUE)
				    cm_list[cm_list_len].noexecve = TRUE;
				else
				    cm_list[cm_list_len].noexecve = FALSE;
				if (setenv_ok == TRUE)
				    cm_list[cm_list_len].setenv = TRUE;
				else
				    cm_list[cm_list_len].setenv = FALSE;
			    }
			}
break;
case 64:
#line 800 "parse.yacc"
{
			    no_passwd = TRUE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = TRUE;
			}
break;
case 65:
#line 806 "parse.yacc"
{
			    no_passwd = FALSE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = FALSE;
			}
break;
case 66:
#line 812 "parse.yacc"
{
			    no_execve = TRUE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].noexecve = TRUE;
			}
break;
case 67:
#line 818 "parse.yacc"
{
			    no_execve = FALSE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].noexecve = FALSE;
			}
break;
case 68:
#line 824 "parse.yacc"
{
			    setenv_ok = TRUE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].setenv = TRUE;
			}
break;
case 69:
#line 830 "parse.yacc"
{
			    setenv_ok = FALSE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].setenv = FALSE;
			}
break;
case 70:
#line 838 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("ALL", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE) {
				    append_cmnd("ALL", NULL);
				    expand_match_list();
				}
			    }
			    /* sudo "ALL" implies the SETENV tag */
			    if (setenv_ok == UNSPEC)
				setenv_ok = IMPLIED;

			    efree(safe_cmnd);
			    safe_cmnd = NULL;
			    yyval.BOOLEAN = TRUE;
			}
break;
case 71:
#line 856 "parse.yacc"
{
			    aliasinfo *aip;

			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE) {
				    append_cmnd(yyvsp[0].string, NULL);
				    expand_match_list();
				}
			    }

			    if ((aip = find_alias(yyvsp[0].string, CMND_ALIAS)))
				yyval.BOOLEAN = aip->val;
			    else {
				if (pedantic) {
				    (void) fprintf(stderr,
					"%s: undeclared Cmnd_Alias `%s' referenced near line %d\n",
					(pedantic == 1) ? "Warning" : "Error", yyvsp[0].string, sudolineno);
				    if (pedantic > 1) {
					yyerror(NULL);
					YYERROR;
				    }
				}
				yyval.BOOLEAN = NOMATCH;
			    }
			    efree(yyvsp[0].string);
			}
break;
case 72:
#line 885 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE) {
				    append_entries(yyvsp[0].command.cmnd, ", ");
				    if (yyvsp[0].command.args)
					append_entries(yyvsp[0].command.args, " ");
				}
				if (host_matches == TRUE &&
				    user_matches == TRUE)  {
				    append_cmnd(yyvsp[0].command.cmnd, NULL);
				    if (yyvsp[0].command.args)
					append_cmnd(yyvsp[0].command.args, " ");
				    expand_match_list();
				}
			    }

			    if (command_matches(yyvsp[0].command.cmnd, yyvsp[0].command.args))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;

			    efree(yyvsp[0].command.cmnd);
			    efree(yyvsp[0].command.args);
			}
break;
case 75:
#line 915 "parse.yacc"
{ push; }
break;
case 76:
#line 915 "parse.yacc"
{
			    if ((MATCHED(host_matches) || pedantic) &&
				!add_alias(yyvsp[-3].string, HOST_ALIAS, host_matches)) {
				yyerror(NULL);
				YYERROR;
			    }
			    pop;
			}
break;
case 81:
#line 933 "parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necessary. */
				expand_ga_list();
				ga_list[ga_list_len-1].type = CMND_ALIAS;
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			     }
			}
break;
case 82:
#line 942 "parse.yacc"
{
			    if ((MATCHED(cmnd_matches) || pedantic) &&
				!add_alias(yyvsp[-3].string, CMND_ALIAS, cmnd_matches)) {
				yyerror(NULL);
				YYERROR;
			    }
			    pop;
			    efree(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			}
break;
case 83:
#line 956 "parse.yacc"
{ ; }
break;
case 87:
#line 964 "parse.yacc"
{
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necessary. */
				expand_ga_list();
				ga_list[ga_list_len-1].type = RUNAS_ALIAS;
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			    }
			}
break;
case 88:
#line 972 "parse.yacc"
{
			    if ((yyvsp[0].BOOLEAN != NOMATCH || pedantic) &&
				!add_alias(yyvsp[-3].string, RUNAS_ALIAS, yyvsp[0].BOOLEAN)) {
				yyerror(NULL);
				YYERROR;
			    }
			    efree(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			}
break;
case 91:
#line 989 "parse.yacc"
{ push; }
break;
case 92:
#line 989 "parse.yacc"
{
			    if ((MATCHED(user_matches) || pedantic) &&
				!add_alias(yyvsp[-3].string, USER_ALIAS, user_matches)) {
				yyerror(NULL);
				YYERROR;
			    }
			    pop;
			    efree(yyvsp[-3].string);
			}
break;
case 95:
#line 1004 "parse.yacc"
{
			    SETMATCH(user_matches, yyvsp[0].BOOLEAN);
			}
break;
case 96:
#line 1007 "parse.yacc"
{
			    SETNMATCH(user_matches, yyvsp[0].BOOLEAN);
			}
break;
case 97:
#line 1012 "parse.yacc"
{
			    if (userpw_matches(yyvsp[0].string, user_name, sudo_user.pw))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;
			    efree(yyvsp[0].string);
			}
break;
case 98:
#line 1019 "parse.yacc"
{
			    if (usergr_matches(yyvsp[0].string, user_name, sudo_user.pw))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;
			    efree(yyvsp[0].string);
			}
break;
case 99:
#line 1026 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, NULL, NULL, user_name))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = NOMATCH;
			    efree(yyvsp[0].string);
			}
break;
case 100:
#line 1033 "parse.yacc"
{
			    aliasinfo *aip = find_alias(yyvsp[0].string, USER_ALIAS);

			    /* could be an all-caps username */
			    if (aip)
				yyval.BOOLEAN = aip->val;
			    else if (strcmp(yyvsp[0].string, user_name) == 0)
				yyval.BOOLEAN = TRUE;
			    else {
				if (pedantic) {
				    (void) fprintf(stderr,
					"%s: undeclared User_Alias `%s' referenced near line %d\n",
					(pedantic == 1) ? "Warning" : "Error", yyvsp[0].string, sudolineno);
				    if (pedantic > 1) {
					yyerror(NULL);
					YYERROR;
				    }
				}
				yyval.BOOLEAN = NOMATCH;
			    }
			    efree(yyvsp[0].string);
			}
break;
case 101:
#line 1055 "parse.yacc"
{
			    yyval.BOOLEAN = TRUE;
			}
break;
#line 2161 "sudo.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    if (yyss)
            free(yyss);
    if (yyvs)
            free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
