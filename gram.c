#ifndef lint
/*static char yysccsid[] = "from: @(#)yaccpar	1.9 (Berkeley) 02/21/93";*/
static char yyrcsid[]
#if __GNUC__ >= 2
  __attribute__ ((unused))
#endif /* __GNUC__ >= 2 */
  = "$OpenBSD: skeleton.c,v 1.23 2004/03/12 13:39:50 henning Exp $";
#endif
#include <stdlib.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define YYPREFIX "yy"
#line 2 "gram.y"
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

#include "config.h"

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
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
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

struct alias *aliases;	/* XXX - use RB or binary search tree */
struct defaults *defaults;
struct userspec *userspecs;

/*
 * Local protoypes
 */
static void add_alias		__P((struct alias *));
static void add_defaults	__P((int, struct member *, struct defaults *));
static void add_userspec	__P((struct member *, struct privilege *));
       void yyerror		__P((const char *));

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
#line 106 "gram.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
    struct alias *alias;
    struct cmndspec *cmndspec;
    struct defaults *defaults;
    struct member *member;
    struct privilege *privilege;
    struct sudo_command command;
    struct cmndtag tag;
    char *string;
    int tok;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 138 "gram.c"
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
#define MONITOR 273
#define NOMONITOR 274
#define ALL 275
#define COMMENT 276
#define HOSTALIAS 277
#define CMNDALIAS 278
#define USERALIAS 279
#define RUNASALIAS 280
#define ERROR 281
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short yylhs[] =
#else
short yylhs[] =
#endif
	{                                        -1,
    0,    0,   29,   29,   30,   30,   30,   30,   30,   30,
   30,   30,   30,   30,   30,   12,   12,   11,   11,   11,
   11,   11,   27,   27,   26,   18,   18,   16,   16,   16,
   16,   16,   10,   10,    9,   14,   14,   22,   22,   21,
   21,   19,   19,   23,   23,   23,   23,   23,   28,   28,
   28,   28,   28,   28,   28,   13,   13,   13,    4,    4,
    3,   17,   17,    2,    2,    1,   15,   15,    6,    6,
    5,    8,    8,    7,   25,   25,   20,   20,   24,   24,
   24,   24,   24,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yylen[] =
#else
short yylen[] =
#endif
	{                                         2,
    0,    1,    1,    2,    1,    2,    2,    2,    2,    2,
    2,    2,    3,    3,    3,    1,    3,    1,    2,    3,
    3,    3,    1,    3,    3,    1,    2,    1,    1,    1,
    1,    1,    1,    3,    3,    1,    2,    0,    2,    1,
    3,    1,    2,    1,    1,    1,    1,    1,    0,    2,
    2,    2,    2,    2,    2,    1,    1,    1,    1,    3,
    3,    1,    3,    1,    3,    3,    1,    3,    1,    3,
    3,    1,    3,    3,    1,    3,    1,    2,    1,    1,
    1,    1,    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydefred[] =
#else
short yydefred[] =
#endif
	{                                      0,
    0,   79,   81,   82,   83,    0,    0,    0,    0,   80,
    5,    0,    0,    0,    0,    0,    0,   75,   77,    0,
    0,    3,    6,    0,    0,   16,    0,   28,   31,   30,
   32,   29,    0,   26,    0,   62,    0,   44,   46,   47,
   48,   45,    0,   40,    0,   42,    0,   59,    0,    0,
   64,    0,    0,   72,    0,    0,   69,    0,   78,    0,
    0,   23,    0,    4,    0,    0,    0,   19,    0,   27,
    0,    0,    0,   43,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   76,    0,    0,   20,   21,   22,
   17,   63,   41,    0,   60,   58,   57,   56,    0,   36,
   67,    0,   65,    0,   73,    0,   70,    0,   33,    0,
   49,   24,   37,    0,    0,    0,    0,   68,   34,   50,
   51,   52,   53,   54,   55,   35,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydgoto[] =
#else
short yydgoto[] =
#endif
	{                                      17,
   51,   52,   48,   49,   57,   58,   54,   55,  109,  110,
   26,   27,  100,  101,  102,   34,   61,   36,   44,   18,
   45,  111,   46,   19,   20,   62,   63,  117,   21,   22,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yysindex[] =
#else
short yysindex[] =
#endif
	{                                    -33,
 -270,    0,    0,    0,    0,   11,   88,  114,  140,    0,
    0, -237, -234, -231, -226, -244,    0,    0,    0,   62,
  -33,    0,    0,  -38, -224,    0,   -8,    0,    0,    0,
    0,    0, -221,    0,  -24,    0,  -11,    0,    0,    0,
    0,    0, -215,    0,   -3,    0,  -23,    0,   -9,   -5,
    0,   -1,    2,    0,    4,    3,    0,    7,    0,  114,
  -36,    0,    8,    0, -213, -208, -205,    0,   11,    0,
   88,   -8,   -8,    0,  140,   -8,   88, -237,  -17, -234,
  114, -231,  140, -226,    0, -201,   88,    0,    0,    0,
    0,    0,    0,   24,    0,    0,    0,    0, -247,    0,
    0,   25,    0,   27,    0,   28,    0,  140,    0,   30,
    0,    0,    0,  -17,   28, -201,  -20,    0,    0,    0,
    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yyrindex[] =
#else
short yyrindex[] =
#endif
	{                                     70,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   76,    0,    0,    1,    0,    0,  156,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  181,    0,
    0,  206,    0,    0,  236,    0,    0,  261,    0,    0,
    0,    0,  300,    0,    0,    0,    0,    0,    0,    0,
    0,  326,  352,    0,    0,  378,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  274,    0,    0,    0,    0,
    0,    0,    0,   26,    0,    0,    0,    0,    0,    0,
    0,   52,    0,   78,    0,  104,    0,    0,    0,  130,
    0,    0,    0,    0,  391,  274,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yygindex[] =
#else
short yygindex[] =
#endif
	{                                      0,
    6,    0,    5,    0,   -7,    0,   -2,    0,  -37,    0,
   12,   16,  -12, -102,    0,   49,   -4,   17,   14,   31,
  -79,    0,   47,   77,   -6,    9,    0,    0,    0,   71,
};
#define YYTABLESIZE 666
#if defined(__cplusplus) || defined(__STDC__)
const short yytable[] =
#else
short yytable[] =
#endif
	{                                      16,
   18,   37,   35,  106,   66,   23,   67,   71,   25,   96,
   97,  118,   99,    2,  126,   99,    3,    4,    5,   71,
   47,   25,   65,   50,   86,   61,   53,   98,  115,   25,
   10,   56,   60,   18,   68,   69,   28,   77,   29,   30,
   75,   31,   38,   25,   18,   39,   40,   41,   78,   88,
   72,   66,   73,   32,   89,   79,   80,   90,   61,   42,
   76,   82,   81,   83,   84,   87,  108,   71,  114,    1,
   60,   75,   94,  116,  104,    2,  107,   74,  119,  105,
   91,   70,   95,   61,   66,  103,  113,   92,   93,   74,
   85,   64,   59,    0,   33,  112,    0,    0,    0,    0,
    0,    0,    0,   71,    0,   60,    0,    0,    0,   66,
   74,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   33,    0,    0,    0,    0,    0,    0,    0,    0,   25,
    0,    0,    0,    0,    0,   74,   71,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   16,    0,    0,    0,
    0,    0,    0,    0,    0,   12,    0,    0,    0,    0,
    0,   71,   25,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   43,    0,    0,    0,    0,    0,    0,    0,
    9,    0,    0,    0,    0,    0,    0,   25,   12,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   10,    0,    0,    0,    0,
    0,    0,    0,    9,    0,    0,    0,    0,    0,    0,
    0,    0,    1,    0,    2,    0,    0,    3,    4,    5,
    6,    7,    8,    9,   24,    8,   96,   97,   10,   96,
   97,   10,   11,   12,   13,   14,   15,   24,  120,  121,
  122,  123,  124,  125,   98,   24,   18,   98,   18,    0,
   11,   18,   18,   18,   18,   18,   18,   18,    8,   24,
    0,    0,    0,    0,    0,   18,   18,   18,   18,   18,
   18,   61,    0,   61,    0,    0,   61,   61,   61,   61,
   61,   61,   61,   11,    0,    0,    0,    0,    0,    7,
   61,   61,   61,   61,   61,   61,   38,   66,    0,   66,
    0,    0,   66,   66,   66,   66,   66,   66,   66,   28,
    0,   29,   30,    0,   31,   15,   66,   66,   66,   66,
   66,   66,    7,   74,    0,   74,   32,    0,   74,   74,
   74,   74,   74,   74,   74,   28,    0,   29,   30,    0,
   31,   13,   74,   74,   74,   74,   74,   74,   15,   71,
    0,   71,   32,    0,   71,   71,   71,   71,   71,   71,
   71,    2,    0,    0,    3,    4,    5,   14,   71,   71,
   71,   71,   71,   71,   13,   25,    0,   25,   10,    0,
   25,   25,   25,   25,   25,   25,   25,   38,    0,    0,
   39,   40,   41,    0,   25,   25,   25,   25,   25,   25,
   14,   12,    0,   12,   42,    0,   12,   12,   12,   12,
   12,   12,   12,   39,    0,    0,    0,    0,    0,    0,
   12,   12,   12,   12,   12,   12,    9,    0,    9,    0,
    0,    9,    9,    9,    9,    9,    9,    9,    0,    0,
    0,    0,    0,    0,    0,    9,    9,    9,    9,    9,
    9,   10,    0,   10,    0,    0,   10,   10,   10,   10,
   10,   10,   10,    0,    0,    0,    0,    0,    0,    0,
   10,   10,   10,   10,   10,   10,    0,    0,    0,    0,
    0,    8,    0,    8,    0,    0,    8,    8,    8,    8,
    8,    8,    8,    0,    0,    0,    0,    0,    0,    0,
    8,    8,    8,    8,    8,    8,   11,    0,   11,    0,
    0,   11,   11,   11,   11,   11,   11,   11,    0,    0,
   38,   38,    0,    0,    0,   11,   11,   11,   11,   11,
   11,    0,   38,   38,   38,   38,   38,   38,   38,    0,
    0,    0,    0,    0,    0,    7,    0,    7,    0,    0,
    7,    7,    7,    7,    7,    7,    7,    0,    0,    0,
    0,    0,    0,    0,    7,    7,    7,    7,    7,    7,
    0,   15,    0,   15,    0,    0,   15,   15,   15,   15,
   15,   15,   15,    0,    0,    0,    0,    0,    0,    0,
   15,   15,   15,   15,   15,   15,    0,   13,    0,   13,
    0,    0,   13,   13,   13,   13,   13,   13,   13,    0,
    0,    0,    0,    0,    0,    0,   13,   13,   13,   13,
   13,   13,    0,   14,    0,   14,    0,    0,   14,   14,
   14,   14,   14,   14,   14,    0,    0,   39,   39,    0,
    0,    0,   14,   14,   14,   14,   14,   14,    0,   39,
   39,   39,   39,   39,   39,   39,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yycheck[] =
#else
short yycheck[] =
#endif
	{                                      33,
    0,    8,    7,   83,   43,  276,   45,   44,   33,  257,
  258,  114,   33,  258,  117,   33,  261,  262,  263,   44,
  258,   33,   61,  258,   61,    0,  258,  275,  108,   33,
  275,  258,   44,   33,  259,   44,  258,   61,  260,  261,
   44,  263,  258,   33,   44,  261,  262,  263,   58,  263,
   35,    0,   37,  275,  263,   61,   58,  263,   33,  275,
   45,   58,   61,   61,   58,   58,  268,   44,   44,    0,
   44,   44,   77,   44,   81,    0,   84,    0,  116,   82,
   69,   33,   78,   58,   33,   80,   99,   71,   75,   43,
   60,   21,   16,   -1,   33,   87,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,    0,   -1,   44,   -1,   -1,   -1,   58,
   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,    0,
   -1,   -1,   -1,   -1,   -1,   58,   33,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   33,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   58,   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   58,   33,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  256,   -1,  258,   -1,   -1,  261,  262,  263,
  264,  265,  266,  267,  259,    0,  257,  258,   33,  257,
  258,  275,  276,  277,  278,  279,  280,  259,  269,  270,
  271,  272,  273,  274,  275,  259,  256,  275,  258,   -1,
    0,  261,  262,  263,  264,  265,  266,  267,   33,  259,
   -1,   -1,   -1,   -1,   -1,  275,  276,  277,  278,  279,
  280,  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,   33,   -1,   -1,   -1,   -1,   -1,    0,
  275,  276,  277,  278,  279,  280,   33,  256,   -1,  258,
   -1,   -1,  261,  262,  263,  264,  265,  266,  267,  258,
   -1,  260,  261,   -1,  263,    0,  275,  276,  277,  278,
  279,  280,   33,  256,   -1,  258,  275,   -1,  261,  262,
  263,  264,  265,  266,  267,  258,   -1,  260,  261,   -1,
  263,    0,  275,  276,  277,  278,  279,  280,   33,  256,
   -1,  258,  275,   -1,  261,  262,  263,  264,  265,  266,
  267,  258,   -1,   -1,  261,  262,  263,    0,  275,  276,
  277,  278,  279,  280,   33,  256,   -1,  258,  275,   -1,
  261,  262,  263,  264,  265,  266,  267,  258,   -1,   -1,
  261,  262,  263,   -1,  275,  276,  277,  278,  279,  280,
   33,  256,   -1,  258,  275,   -1,  261,  262,  263,  264,
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
  261,  262,  263,  264,  265,  266,  267,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  275,  276,  277,  278,  279,  280,
   -1,  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  275,  276,  277,  278,  279,  280,   -1,  256,   -1,  258,
   -1,   -1,  261,  262,  263,  264,  265,  266,  267,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  275,  276,  277,  278,
  279,  280,   -1,  256,   -1,  258,   -1,   -1,  261,  262,
  263,  264,  265,  266,  267,   -1,   -1,  257,  258,   -1,
   -1,   -1,  275,  276,  277,  278,  279,  280,   -1,  269,
  270,  271,  272,  273,  274,  275,
};
#define YYFINAL 17
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 281
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
"NOEXEC","EXEC","MONITOR","NOMONITOR","ALL","COMMENT","HOSTALIAS","CMNDALIAS",
"USERALIAS","RUNASALIAS","ERROR",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const yyrule[] =
#else
char *yyrule[] =
#endif
	{"$accept : file",
"file :",
"file : line",
"line : entry",
"line : line entry",
"entry : COMMENT",
"entry : error COMMENT",
"entry : userlist privileges",
"entry : USERALIAS useraliases",
"entry : HOSTALIAS hostaliases",
"entry : CMNDALIAS cmndaliases",
"entry : RUNASALIAS runasaliases",
"entry : DEFAULTS defaults_list",
"entry : DEFAULTS_USER userlist defaults_list",
"entry : DEFAULTS_RUNAS runaslist defaults_list",
"entry : DEFAULTS_HOST hostlist defaults_list",
"defaults_list : defaults_entry",
"defaults_list : defaults_list ',' defaults_entry",
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
"host : ALIAS",
"host : ALL",
"host : NETGROUP",
"host : NTWKADDR",
"host : WORD",
"cmndspeclist : cmndspec",
"cmndspeclist : cmndspeclist ',' cmndspec",
"cmndspec : runasspec cmndtag opcmnd",
"opcmnd : cmnd",
"opcmnd : '!' cmnd",
"runasspec :",
"runasspec : RUNAS runaslist",
"runaslist : oprunasuser",
"runaslist : runaslist ',' oprunasuser",
"oprunasuser : runasuser",
"oprunasuser : '!' runasuser",
"runasuser : ALIAS",
"runasuser : ALL",
"runasuser : NETGROUP",
"runasuser : USERGROUP",
"runasuser : WORD",
"cmndtag :",
"cmndtag : cmndtag NOPASSWD",
"cmndtag : cmndtag PASSWD",
"cmndtag : cmndtag NOEXEC",
"cmndtag : cmndtag EXEC",
"cmndtag : cmndtag MONITOR",
"cmndtag : cmndtag NOMONITOR",
"cmnd : ALL",
"cmnd : ALIAS",
"cmnd : COMMAND",
"hostaliases : hostalias",
"hostaliases : hostaliases ':' hostalias",
"hostalias : ALIAS '=' hostlist",
"hostlist : ophost",
"hostlist : hostlist ',' ophost",
"cmndaliases : cmndalias",
"cmndaliases : cmndaliases ':' cmndalias",
"cmndalias : ALIAS '=' cmndlist",
"cmndlist : opcmnd",
"cmndlist : cmndlist ',' opcmnd",
"runasaliases : runasalias",
"runasaliases : runasaliases ':' runasalias",
"runasalias : ALIAS '=' runaslist",
"useraliases : useralias",
"useraliases : useraliases ':' useralias",
"useralias : ALIAS '=' userlist",
"userlist : opuser",
"userlist : userlist ',' opuser",
"opuser : user",
"opuser : '!' user",
"user : ALIAS",
"user : ALL",
"user : NETGROUP",
"user : USERGROUP",
"user : WORD",
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
#line 508 "gram.y"

/*
 * Add a list of aliases to the end of the global aliases list.
 */
static void
add_alias(a)
    struct alias *a;
{
    if (aliases == NULL)
	aliases = a;
    else {
	if (aliases->last != NULL)
	    aliases->last->next = a;
	else /* if (aliases->next == NULL) */
	    aliases->next = a;
	aliases->last = a->last ? a->last : a;
    }
}

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
    else {
	if (defaults->last != NULL)
	    defaults->last->next = defs;
	else /* if (defaults->next == NULL) */
	    defaults->next = defs;
	defaults->last = defs->last ? defs->last : defs;
    }
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
    else {
	if (userspecs->last != NULL)
	    userspecs->last->next = u;
	else /* if (userspecs->next == NULL) */
	    userspecs->next = u;
	userspecs->last = u;
    }
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
    struct alias *a;
    struct defaults *d;
    struct member *m, *lastbinding;
    struct userspec *us;
    struct privilege *priv;
    struct cmndspec *cs;
    VOID *next;

    for (a = aliases ; a != NULL; a = a->next) {
	for (m = a->first_member; m != NULL; m = next) {
	    next = m->next;
	    if (m->name != NULL)
		free(m->name);
	    free(m);
	}
    }
    aliases = NULL;

    for (us = userspecs ; us != NULL; us = next) {
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
    for (d = defaults ; d != NULL; d = next) {
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

    if (sudoers != NULL)
	free(sudoers);
    sudoers = estrdup(path);

    parse_error = FALSE;
    errorlineno = -1;
    sudolineno = 1;
    verbose = !quiet;
}
#line 679 "gram.c"
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
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss);
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + i;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs);
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
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 1:
#line 177 "gram.y"
{ ; }
break;
case 5:
#line 185 "gram.y"
{
			    ;
			}
break;
case 6:
#line 188 "gram.y"
{
			    yyerrok;
			}
break;
case 7:
#line 191 "gram.y"
{
			    add_userspec(yyvsp[-1].member, yyvsp[0].privilege);
			}
break;
case 8:
#line 194 "gram.y"
{
			    add_alias(yyvsp[0].alias);
			}
break;
case 9:
#line 197 "gram.y"
{
			    add_alias(yyvsp[0].alias);
			}
break;
case 10:
#line 200 "gram.y"
{
			    add_alias(yyvsp[0].alias);
			}
break;
case 11:
#line 203 "gram.y"
{
			    add_alias(yyvsp[0].alias);
			}
break;
case 12:
#line 206 "gram.y"
{
			    add_defaults(DEFAULTS, NULL, yyvsp[0].defaults);
			}
break;
case 13:
#line 209 "gram.y"
{
			    add_defaults(DEFAULTS_USER, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 14:
#line 212 "gram.y"
{
			    add_defaults(DEFAULTS_RUNAS, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 15:
#line 215 "gram.y"
{
			    add_defaults(DEFAULTS_HOST, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 17:
#line 221 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].defaults, yyvsp[0].defaults);
			    yyval.defaults = yyvsp[-2].defaults;
			}
break;
case 18:
#line 227 "gram.y"
{
			    NEW_DEFAULT(yyval.defaults, yyvsp[0].string, NULL, TRUE);
			}
break;
case 19:
#line 230 "gram.y"
{
			    NEW_DEFAULT(yyval.defaults, yyvsp[0].string, NULL, FALSE);
			}
break;
case 20:
#line 233 "gram.y"
{
			    NEW_DEFAULT(yyval.defaults, yyvsp[-2].string, yyvsp[0].string, TRUE);
			}
break;
case 21:
#line 236 "gram.y"
{
			    NEW_DEFAULT(yyval.defaults, yyvsp[-2].string, yyvsp[0].string, '+');
			}
break;
case 22:
#line 239 "gram.y"
{
			    NEW_DEFAULT(yyval.defaults, yyvsp[-2].string, yyvsp[0].string, '-');
			}
break;
case 24:
#line 245 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].privilege, yyvsp[0].privilege);
			    yyval.privilege = yyvsp[-2].privilege;
			}
break;
case 25:
#line 251 "gram.y"
{
			    struct cmndtag tags;
			    struct privilege *p = emalloc(sizeof(*p));
			    struct cmndspec *cs;
			    p->hostlist = yyvsp[-2].member;
			    p->cmndlist = yyvsp[0].cmndspec;
			    tags.nopasswd = tags.noexec = tags.monitor = UNSPEC;
			    /* propagate tags */
			    for (cs = yyvsp[0].cmndspec; cs != NULL; cs = cs->next) {
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
			    yyval.privilege = p;
			}
break;
case 26:
#line 274 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 27:
#line 278 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 28:
#line 284 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, HOSTALIAS);
			}
break;
case 29:
#line 287 "gram.y"
{
			    NEW_MEMBER(yyval.member, NULL, ALL);
			}
break;
case 30:
#line 290 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, NETGROUP);
			}
break;
case 31:
#line 293 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, NTWKADDR);
			}
break;
case 32:
#line 296 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, WORD);
			}
break;
case 34:
#line 302 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].cmndspec, yyvsp[0].cmndspec);
			    yyval.cmndspec = yyvsp[-2].cmndspec;
			}
break;
case 35:
#line 308 "gram.y"
{
			    struct cmndspec *cs = emalloc(sizeof(*cs));
			    cs->runaslist = yyvsp[-2].member;
			    cs->tags = yyvsp[-1].tag;
			    cs->cmnd = yyvsp[0].member;
			    cs->last = NULL;
			    cs->next = NULL;
			    yyval.cmndspec = cs;
			}
break;
case 36:
#line 319 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 37:
#line 323 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 38:
#line 329 "gram.y"
{
			    yyval.member = NULL;
			}
break;
case 39:
#line 332 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			}
break;
case 41:
#line 338 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 42:
#line 344 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 43:
#line 348 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 44:
#line 354 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, RUNASALIAS);
			}
break;
case 45:
#line 357 "gram.y"
{
			    NEW_MEMBER(yyval.member, NULL, ALL);
			}
break;
case 46:
#line 360 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, NETGROUP);
			}
break;
case 47:
#line 363 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, USERGROUP);
			}
break;
case 48:
#line 366 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, WORD);
			}
break;
case 49:
#line 371 "gram.y"
{
			    yyval.tag.nopasswd = yyval.tag.noexec = yyval.tag.monitor = UNSPEC;
			}
break;
case 50:
#line 374 "gram.y"
{
			    yyval.tag.nopasswd = TRUE;
			}
break;
case 51:
#line 377 "gram.y"
{
			    yyval.tag.nopasswd = FALSE;
			}
break;
case 52:
#line 380 "gram.y"
{
			    yyval.tag.noexec = TRUE;
			}
break;
case 53:
#line 383 "gram.y"
{
			    yyval.tag.noexec = FALSE;
			}
break;
case 54:
#line 386 "gram.y"
{
			    yyval.tag.monitor = TRUE;
			}
break;
case 55:
#line 389 "gram.y"
{
			    yyval.tag.monitor = FALSE;
			}
break;
case 56:
#line 394 "gram.y"
{
			    NEW_MEMBER(yyval.member, NULL, ALL);
			    if (safe_cmnd)
				free(safe_cmnd);
			    safe_cmnd = estrdup(user_cmnd);
			}
break;
case 57:
#line 400 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, CMNDALIAS);
			}
break;
case 58:
#line 403 "gram.y"
{
			    struct sudo_command *c = emalloc(sizeof(*c));
			    c->cmnd = yyvsp[0].command.cmnd;
			    c->args = yyvsp[0].command.args;
			    NEW_MEMBER(yyval.member, (char *)c, COMMAND);
			}
break;
case 60:
#line 412 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].alias, yyvsp[0].alias);
			    yyval.alias = yyvsp[-2].alias;
			}
break;
case 61:
#line 418 "gram.y"
{
			    NEW_ALIAS(yyval.alias, yyvsp[-2].string, HOSTALIAS, yyvsp[0].member);
			}
break;
case 63:
#line 424 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 65:
#line 431 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].alias, yyvsp[0].alias);
			    yyval.alias = yyvsp[-2].alias;
			}
break;
case 66:
#line 437 "gram.y"
{
			    NEW_ALIAS(yyval.alias, yyvsp[-2].string, CMNDALIAS, yyvsp[0].member);
			}
break;
case 68:
#line 443 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 70:
#line 450 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].alias, yyvsp[0].alias);
			    yyval.alias = yyvsp[-2].alias;
			}
break;
case 71:
#line 456 "gram.y"
{
			    NEW_ALIAS(yyval.alias, yyvsp[-2].string, RUNASALIAS, yyvsp[0].member);
			}
break;
case 73:
#line 462 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].alias, yyvsp[0].alias);
			    yyval.alias = yyvsp[-2].alias;
			}
break;
case 74:
#line 468 "gram.y"
{
			    NEW_ALIAS(yyval.alias, yyvsp[-2].string, USERALIAS, yyvsp[0].member);
			}
break;
case 76:
#line 474 "gram.y"
{
			    LIST_APPEND(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 77:
#line 480 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 78:
#line 484 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 79:
#line 490 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, USERALIAS);
			}
break;
case 80:
#line 493 "gram.y"
{
			    NEW_MEMBER(yyval.member, NULL, ALL);
			}
break;
case 81:
#line 496 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, NETGROUP);
			}
break;
case 82:
#line 499 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, USERGROUP);
			}
break;
case 83:
#line 502 "gram.y"
{
			    NEW_MEMBER(yyval.member, yyvsp[0].string, WORD);
			}
break;
#line 1333 "gram.c"
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
