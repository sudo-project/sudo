#ifndef lint
/*static char yysccsid[] = "from: @(#)yaccpar	1.9 (Berkeley) 02/21/93";*/
static char yyrcsid[]
#if __GNUC__ >= 2
  __attribute__ ((unused))
#endif /* __GNUC__ >= 2 */
  = "$OpenBSD: skeleton.c,v 1.28 2007/09/03 21:14:58 deraadt Exp $";
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
 * Copyright (c) 1996, 1998-2005, 2007
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
__unused static const char rcsid[] = "$Sudo$";
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

struct defaults_list defaults;
struct userspec_list userspecs;

/*
 * Local protoypes
 */
static void  add_defaults	__P((int, struct member *, struct defaults *));
static void  add_userspec	__P((struct member *, struct privilege *));
static struct defaults *new_default __P((char *, char *, int));
static struct member *new_member __P((char *, int));
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
#line 103 "gram.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
    struct cmndspec *cmndspec;
    struct defaults *defaults;
    struct member *member;
    struct runascontainer *runas;
    struct privilege *privilege;
    struct sudo_command command;
    struct cmndtag tag;
    char *string;
    int tok;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 135 "y.tab.c"
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
#define DEFAULTS_CMND 268
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
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short yylhs[] =
#else
short yylhs[] =
#endif
	{                                        -1,
    0,    0,   22,   22,   23,   23,   23,   23,   23,   23,
   23,   23,   23,   23,   23,   23,    4,    4,    3,    3,
    3,    3,    3,   20,   20,   19,   10,   10,    8,    8,
    8,    8,    8,    2,    2,    1,    6,    6,   17,   17,
   18,   18,   18,   21,   21,   21,   21,   21,   21,   21,
    5,    5,    5,   25,   25,   28,    9,    9,   26,   26,
   29,    7,    7,   27,   27,   30,   24,   24,   31,   13,
   13,   11,   11,   12,   12,   12,   12,   12,   16,   16,
   14,   14,   15,   15,   15,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yylen[] =
#else
short yylen[] =
#endif
	{                                         2,
    0,    1,    1,    2,    1,    2,    2,    2,    2,    2,
    2,    2,    3,    3,    3,    3,    1,    3,    1,    2,
    3,    3,    3,    1,    3,    3,    1,    2,    1,    1,
    1,    1,    1,    1,    3,    3,    1,    2,    0,    3,
    1,    3,    2,    0,    2,    2,    2,    2,    2,    2,
    1,    1,    1,    1,    3,    3,    1,    3,    1,    3,
    3,    1,    3,    1,    3,    3,    1,    3,    3,    1,
    3,    1,    2,    1,    1,    1,    1,    1,    1,    3,
    1,    2,    1,    1,    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydefred[] =
#else
short yydefred[] =
#endif
	{                                      0,
    0,   74,   76,   77,   78,    0,    0,    0,    0,    0,
   75,    5,    0,    0,    0,    0,    0,    0,   70,   72,
    0,    0,    3,    6,    0,    0,   17,    0,   29,   32,
   31,   33,   30,    0,   27,    0,   57,    0,    0,   53,
   52,   51,    0,   37,   62,    0,    0,    0,   54,    0,
    0,   59,    0,    0,   67,    0,    0,   64,   73,    0,
    0,   24,    0,    4,    0,    0,    0,   20,    0,   28,
    0,    0,    0,    0,   38,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   71,    0,    0,   21,   22,
   23,   18,   58,   63,    0,   55,    0,   60,    0,   68,
    0,   65,    0,   34,    0,   44,   25,    0,    0,    0,
    0,    0,   83,   85,   84,    0,   79,   81,    0,    0,
   40,   35,   45,   46,   47,   48,   49,   50,   36,   82,
    0,    0,   80,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydgoto[] =
#else
short yydgoto[] =
#endif
	{                                      18,
  104,  105,   27,   28,   44,   45,   46,   35,   61,   37,
   19,   20,   21,  117,  118,  119,  106,  110,   62,   63,
  112,   22,   23,   54,   48,   51,   57,   49,   52,   58,
   55,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yysindex[] =
#else
short yysindex[] =
#endif
	{                                    -33,
 -269,    0,    0,    0,    0,   -8,  454,  458,  458,  -17,
    0,    0, -249, -247, -241, -231, -243,    0,    0,    0,
  141,  -33,    0,    0,  -37, -216,    0,  -16,    0,    0,
    0,    0,    0, -221,    0,  -23,    0,  -21,  -21,    0,
    0,    0, -244,    0,    0,  -11,  -14,   -1,    0,   -6,
    2,    0,    3,    4,    0,    5,    7,    0,    0,  458,
  -15,    0,    9,    0, -219, -207, -202,    0,   -8,    0,
  454,  -16,  -16,  -16,    0,  -17,  -16,  454, -249,  -17,
 -247,  458, -241,  458, -231,    0,   23,  454,    0,    0,
    0,    0,    0,    0,   24,    0,   25,    0,   27,    0,
   27,    0,  217,    0,   28,    0,    0,   -3,   -9,   29,
   23,  250,    0,    0,    0, -222,    0,    0,   30,   -3,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   -3,   30,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yyrindex[] =
#else
short yyrindex[] =
#endif
	{                                     73,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   75,    0,    0,    1,    0,    0,  156,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  181,    0,    0,
  206,    0,    0,  237,    0,    0,  274,    0,    0,    0,
    0,    0,  300,    0,    0,    0,    0,    0,    0,    0,
    0,  326,  352,  378,    0,    0,  430,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  392,    0,    0,    0,
    0,    0,    0,    0,   26,    0,   52,    0,   78,    0,
  104,    0,    0,    0,  130,    0,    0,    0,   39,    0,
  392,    0,    0,    0,    0,    0,    0,    0,   40,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   41,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yygindex[] =
#else
short yygindex[] =
#endif
	{                                      0,
  -28,    0,   17,   12,   44,  -74,    8,   55,   -2,   19,
   31,   76,   -5,  -39,  -22,  -25,    0,    0,   11,    0,
    0,    0,   74,    0,    0,    0,    0,   18,   20,   15,
   22,
};
#define YYTABLESIZE 733
#if defined(__cplusplus) || defined(__STDC__)
const short yytable[] =
#else
short yytable[] =
#endif
	{                                      17,
   19,   94,   38,   39,   36,   66,   24,   67,   47,   26,
   50,   26,   40,   41,    2,   43,   53,    3,    4,    5,
   71,   26,   60,   65,   26,   56,   56,   69,   71,  116,
   42,   11,   76,   19,   60,  113,   29,  129,   30,   31,
  114,   32,   68,   89,   19,   87,   78,   72,  120,   73,
   74,   61,  115,   33,   80,   90,   79,   77,   56,   81,
   91,   83,  103,   82,   85,   84,   88,   71,   76,  121,
   60,  111,    1,  131,    2,   95,   99,   69,  101,   41,
   43,   42,  122,   56,   61,   92,   75,   97,   70,   93,
   86,  133,   59,  130,  132,   64,   96,  109,  107,  102,
   98,    0,    0,   66,  100,    0,    0,    0,    0,   61,
   69,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   26,
    0,    0,    0,    0,    0,   69,   66,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   12,    0,    0,    0,    0,
    0,   66,   26,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   34,    0,    0,    0,    0,    0,    0,
    9,    0,    0,    0,   60,    0,    0,   26,   12,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   10,    0,    0,    0,    0,
    0,    0,    0,    9,    0,    0,    0,    0,    0,    0,
    0,    0,    1,    0,    2,    0,    0,    3,    4,    5,
    6,    7,    8,    9,   10,   25,    8,   25,   10,   40,
   41,   11,   12,   13,   14,   15,   16,   25,    0,   17,
   25,    0,    0,    0,  113,    0,   19,   42,   19,  114,
    0,   19,   19,   19,   19,   19,   19,   19,   19,    8,
    0,  115,    0,   11,  108,   19,   19,   19,   19,   19,
   19,   56,   43,   56,    0,    0,   56,   56,   56,   56,
   56,   56,   56,   56,    0,    0,    0,    0,    0,    7,
   56,   56,   56,   56,   56,   56,   11,   61,    0,   61,
    0,    0,   61,   61,   61,   61,   61,   61,   61,   61,
    0,    0,    0,    0,    0,   15,   61,   61,   61,   61,
   61,   61,    7,   69,    0,   69,    0,    0,   69,   69,
   69,   69,   69,   69,   69,   69,    0,    0,    0,    0,
    0,   13,   69,   69,   69,   69,   69,   69,   15,   66,
    0,   66,    0,    0,   66,   66,   66,   66,   66,   66,
   66,   66,    0,    0,    0,    0,    0,   14,   66,   66,
   66,   66,   66,   66,   13,   26,    0,   26,    0,    0,
   26,   26,   26,   26,   26,   26,   26,   26,   29,    0,
   30,   31,    0,   32,   26,   26,   26,   26,   26,   26,
   14,   12,    0,   12,    0,   33,   12,   12,   12,   12,
   12,   12,   12,   12,   39,    0,    0,    0,    0,   16,
   12,   12,   12,   12,   12,   12,    9,    0,    9,    0,
    0,    9,    9,    9,    9,    9,    9,    9,    9,    0,
    0,    0,    0,    0,    0,    9,    9,    9,    9,    9,
    9,   10,   16,   10,    0,    0,   10,   10,   10,   10,
   10,   10,   10,   10,    2,    0,    0,    3,    4,    5,
   10,   10,   10,   10,   10,   10,   34,    0,    0,    0,
   17,   11,    8,    0,    8,    0,    0,    8,    8,    8,
    8,    8,    8,    8,    8,    0,   40,   41,    0,    0,
    0,    8,    8,    8,    8,    8,    8,    0,  123,  124,
  125,  126,  127,  128,   42,    0,    0,    0,    0,   11,
    0,   11,    0,    0,   11,   11,   11,   11,   11,   11,
   11,   11,    0,    0,    0,    0,    0,    0,   11,   11,
   11,   11,   11,   11,    0,    7,    0,    7,    0,    0,
    7,    7,    7,    7,    7,    7,    7,    7,    0,    0,
    0,    0,    0,    0,    7,    7,    7,    7,    7,    7,
    0,   15,    0,   15,    0,    0,   15,   15,   15,   15,
   15,   15,   15,   15,    0,    0,    0,    0,    0,    0,
   15,   15,   15,   15,   15,   15,    0,   13,    0,   13,
    0,    0,   13,   13,   13,   13,   13,   13,   13,   13,
    0,    0,    0,    0,    0,    0,   13,   13,   13,   13,
   13,   13,    0,   14,    0,   14,    0,    0,   14,   14,
   14,   14,   14,   14,   14,   14,    0,    0,   39,   39,
    0,    0,   14,   14,   14,   14,   14,   14,    0,    0,
   39,   39,   39,   39,   39,   39,   39,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   16,    0,   16,    0,    0,
   16,   16,   16,   16,   16,   16,   16,   16,    0,    0,
    0,    0,    0,    0,   16,   16,   16,   16,   16,   16,
    0,   29,    0,   30,   31,    2,   32,    0,    3,    4,
    5,    0,    0,    0,    0,    0,    0,    0,   33,    0,
    0,    0,   11,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yycheck[] =
#else
short yycheck[] =
#endif
	{                                      33,
    0,   76,    8,    9,    7,   43,  276,   45,  258,   33,
  258,   33,  257,  258,  258,   33,  258,  261,  262,  263,
   44,   33,   44,   61,   33,    0,  258,   44,   44,   33,
  275,  275,   44,   33,   44,  258,  258,  112,  260,  261,
  263,  263,  259,  263,   44,   61,   61,   36,   58,   38,
   39,    0,  275,  275,   61,  263,   58,   46,   33,   58,
  263,   58,   40,   61,   58,   61,   58,   44,   44,   41,
   44,   44,    0,   44,    0,   78,   82,    0,   84,   41,
   41,   41,  111,   58,   33,   69,   43,   80,   34,   71,
   60,  131,   17,  116,  120,   22,   79,  103,   88,   85,
   81,   -1,   -1,    0,   83,   -1,   -1,   -1,   -1,   58,
   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,    0,
   -1,   -1,   -1,   -1,   -1,   58,   33,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   58,   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
    0,   -1,   -1,   -1,   44,   -1,   -1,   58,   33,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  256,   -1,  258,   -1,   -1,  261,  262,  263,
  264,  265,  266,  267,  268,  259,    0,  259,   33,  257,
  258,  275,  276,  277,  278,  279,  280,  259,   -1,   33,
  259,   -1,   -1,   -1,  258,   -1,  256,  275,  258,  263,
   -1,  261,  262,  263,  264,  265,  266,  267,  268,   33,
   -1,  275,   -1,    0,   58,  275,  276,  277,  278,  279,
  280,  256,   33,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,  268,   -1,   -1,   -1,   -1,   -1,    0,
  275,  276,  277,  278,  279,  280,   33,  256,   -1,  258,
   -1,   -1,  261,  262,  263,  264,  265,  266,  267,  268,
   -1,   -1,   -1,   -1,   -1,    0,  275,  276,  277,  278,
  279,  280,   33,  256,   -1,  258,   -1,   -1,  261,  262,
  263,  264,  265,  266,  267,  268,   -1,   -1,   -1,   -1,
   -1,    0,  275,  276,  277,  278,  279,  280,   33,  256,
   -1,  258,   -1,   -1,  261,  262,  263,  264,  265,  266,
  267,  268,   -1,   -1,   -1,   -1,   -1,    0,  275,  276,
  277,  278,  279,  280,   33,  256,   -1,  258,   -1,   -1,
  261,  262,  263,  264,  265,  266,  267,  268,  258,   -1,
  260,  261,   -1,  263,  275,  276,  277,  278,  279,  280,
   33,  256,   -1,  258,   -1,  275,  261,  262,  263,  264,
  265,  266,  267,  268,   33,   -1,   -1,   -1,   -1,    0,
  275,  276,  277,  278,  279,  280,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,  267,  268,   -1,
   -1,   -1,   -1,   -1,   -1,  275,  276,  277,  278,  279,
  280,  256,   33,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,  268,  258,   -1,   -1,  261,  262,  263,
  275,  276,  277,  278,  279,  280,   33,   -1,   -1,   -1,
   33,  275,  256,   -1,  258,   -1,   -1,  261,  262,  263,
  264,  265,  266,  267,  268,   -1,  257,  258,   -1,   -1,
   -1,  275,  276,  277,  278,  279,  280,   -1,  269,  270,
  271,  272,  273,  274,  275,   -1,   -1,   -1,   -1,  256,
   -1,  258,   -1,   -1,  261,  262,  263,  264,  265,  266,
  267,  268,   -1,   -1,   -1,   -1,   -1,   -1,  275,  276,
  277,  278,  279,  280,   -1,  256,   -1,  258,   -1,   -1,
  261,  262,  263,  264,  265,  266,  267,  268,   -1,   -1,
   -1,   -1,   -1,   -1,  275,  276,  277,  278,  279,  280,
   -1,  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,  268,   -1,   -1,   -1,   -1,   -1,   -1,
  275,  276,  277,  278,  279,  280,   -1,  256,   -1,  258,
   -1,   -1,  261,  262,  263,  264,  265,  266,  267,  268,
   -1,   -1,   -1,   -1,   -1,   -1,  275,  276,  277,  278,
  279,  280,   -1,  256,   -1,  258,   -1,   -1,  261,  262,
  263,  264,  265,  266,  267,  268,   -1,   -1,  257,  258,
   -1,   -1,  275,  276,  277,  278,  279,  280,   -1,   -1,
  269,  270,  271,  272,  273,  274,  275,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  256,   -1,  258,   -1,   -1,
  261,  262,  263,  264,  265,  266,  267,  268,   -1,   -1,
   -1,   -1,   -1,   -1,  275,  276,  277,  278,  279,  280,
   -1,  258,   -1,  260,  261,  258,  263,   -1,  261,  262,
  263,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  275,   -1,
   -1,   -1,  275,
};
#define YYFINAL 18
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
"'!'",0,0,0,0,0,0,"'('","')'",0,"'+'","','","'-'",0,0,0,0,0,0,0,0,0,0,0,0,"':'",
0,0,"'='",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"COMMAND","ALIAS","DEFVAR","NTWKADDR","NETGROUP","USERGROUP","WORD","DEFAULTS",
"DEFAULTS_HOST","DEFAULTS_USER","DEFAULTS_RUNAS","DEFAULTS_CMND","NOPASSWD",
"PASSWD","NOEXEC","EXEC","SETENV","NOSETENV","ALL","COMMENT","HOSTALIAS",
"CMNDALIAS","USERALIAS","RUNASALIAS","ERROR",
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
"entry : DEFAULTS_RUNAS userlist defaults_list",
"entry : DEFAULTS_HOST hostlist defaults_list",
"entry : DEFAULTS_CMND cmndlist defaults_list",
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
"runasspec : '(' runaslist ')'",
"runaslist : userlist",
"runaslist : userlist ':' grouplist",
"runaslist : ':' grouplist",
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
"runasalias : ALIAS '=' userlist",
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
"grouplist : opgroup",
"grouplist : grouplist ',' opgroup",
"opgroup : group",
"opgroup : '!' group",
"group : ALIAS",
"group : ALL",
"group : WORD",
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
#line 527 "gram.y"
static struct defaults *
new_default(var, val, op)
    char *var;
    char *val;
    int op;
{
    struct defaults *d;

    d = emalloc(sizeof(struct defaults));
    d->var = var;
    d->val = val;
    tq_init(&d->binding);
    d->type = 0;
    d->op = op;
    d->prev = d;
    d->next = NULL;

    return(d);
}

static struct member *
new_member(name, type)
    char *name;
    int type;
{
    struct member *m;

    m = emalloc(sizeof(struct member));
    m->name = name;
    m->type = type;
    m->prev = m;
    m->next = NULL;

    return(m);
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
	list2tq(&d->binding, binding);
    }
    tq_append(&defaults, defs);
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
    list2tq(&u->users, members);
    list2tq(&u->privileges, privs);
    u->prev = u;
    u->next = NULL;
    tq_append(&userspecs, u);
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
    struct member *m, *binding;
    struct userspec *us;
    struct privilege *priv;
    struct cmndspec *cs;

    while ((us = tq_pop(&userspecs)) != NULL) {
	while ((m = tq_pop(&us->users)) != NULL) {
	    efree(m->name);
	    efree(m);
	}
	while ((priv = tq_pop(&us->privileges)) != NULL) {
	    struct member *runasuser = NULL, *runasgroup = NULL;

	    while ((m = tq_pop(&priv->hostlist)) != NULL) {
		efree(m->name);
		efree(m);
	    }
	    while ((cs = tq_pop(&priv->cmndlist)) != NULL) {
		if (tq_last(&cs->runasuserlist) != runasuser) {
		    runasuser = tq_last(&cs->runasuserlist);
		    while ((m = tq_pop(&cs->runasuserlist)) != NULL) {
			efree(m->name);
			efree(m);
		    }
		}
		if (tq_last(&cs->runasgrouplist) != runasgroup) {
		    runasgroup = tq_last(&cs->runasgrouplist);
		    while ((m = tq_pop(&cs->runasgrouplist)) != NULL) {
			efree(m->name);
			efree(m);
		    }
		}
		efree(cs->cmnd->name);
		efree(cs->cmnd);
		efree(cs);
	    }
	    efree(priv);
	}
    }
    tq_init(&userspecs);

    binding = NULL;
    while ((d = tq_pop(&defaults)) != NULL) {
	if (tq_last(&d->binding) != binding) {
	    binding = tq_last(&d->binding);
	    while ((m = tq_pop(&d->binding)) != NULL) {
		efree(m->name);
		efree(m);
	    }
	}
	efree(d->var);
	efree(d->val);
	efree(d);
    }
    tq_init(&defaults);

    init_aliases();

    efree(sudoers);
    sudoers = estrdup(path);

    parse_error = FALSE;
    errorlineno = -1;
    sudolineno = 1;
    verbose = !quiet;
}
#line 685 "y.tab.c"
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
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 1:
#line 168 "gram.y"
{ ; }
break;
case 5:
#line 176 "gram.y"
{
			    ;
			}
break;
case 6:
#line 179 "gram.y"
{
			    yyerrok;
			}
break;
case 7:
#line 182 "gram.y"
{
			    add_userspec(yyvsp[-1].member, yyvsp[0].privilege);
			}
break;
case 8:
#line 185 "gram.y"
{
			    ;
			}
break;
case 9:
#line 188 "gram.y"
{
			    ;
			}
break;
case 10:
#line 191 "gram.y"
{
			    ;
			}
break;
case 11:
#line 194 "gram.y"
{
			    ;
			}
break;
case 12:
#line 197 "gram.y"
{
			    add_defaults(DEFAULTS, NULL, yyvsp[0].defaults);
			}
break;
case 13:
#line 200 "gram.y"
{
			    add_defaults(DEFAULTS_USER, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 14:
#line 203 "gram.y"
{
			    add_defaults(DEFAULTS_RUNAS, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 15:
#line 206 "gram.y"
{
			    add_defaults(DEFAULTS_HOST, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 16:
#line 209 "gram.y"
{
			    add_defaults(DEFAULTS_CMND, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 18:
#line 215 "gram.y"
{
			    list_append(yyvsp[-2].defaults, yyvsp[0].defaults);
			    yyval.defaults = yyvsp[-2].defaults;
			}
break;
case 19:
#line 221 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, TRUE);
			}
break;
case 20:
#line 224 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, FALSE);
			}
break;
case 21:
#line 227 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, TRUE);
			}
break;
case 22:
#line 230 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '+');
			}
break;
case 23:
#line 233 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '-');
			}
break;
case 25:
#line 239 "gram.y"
{
			    list_append(yyvsp[-2].privilege, yyvsp[0].privilege);
			    yyval.privilege = yyvsp[-2].privilege;
			}
break;
case 26:
#line 245 "gram.y"
{
			    struct privilege *p = emalloc(sizeof(*p));
			    list2tq(&p->hostlist, yyvsp[-2].member);
			    list2tq(&p->cmndlist, yyvsp[0].cmndspec);
			    p->prev = p;
			    p->next = NULL;
			    yyval.privilege = p;
			}
break;
case 27:
#line 255 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 28:
#line 259 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 29:
#line 265 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 30:
#line 268 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 31:
#line 271 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			}
break;
case 32:
#line 274 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NTWKADDR);
			}
break;
case 33:
#line 277 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
case 35:
#line 283 "gram.y"
{
			    list_append(yyvsp[-2].cmndspec, yyvsp[0].cmndspec);
			    /* propagate tags and runas list */
			    if (yyvsp[0].cmndspec->tags.nopasswd == UNSPEC)
				yyvsp[0].cmndspec->tags.nopasswd = yyvsp[0].cmndspec->prev->tags.nopasswd;
			    if (yyvsp[0].cmndspec->tags.noexec == UNSPEC)
				yyvsp[0].cmndspec->tags.noexec = yyvsp[0].cmndspec->prev->tags.noexec;
			    if (yyvsp[0].cmndspec->tags.setenv == UNSPEC &&
				yyvsp[0].cmndspec->prev->tags.setenv != IMPLIED)
				yyvsp[0].cmndspec->tags.setenv = yyvsp[0].cmndspec->prev->tags.setenv;
			    if ((tq_empty(&yyvsp[0].cmndspec->runasuserlist) &&
				 tq_empty(&yyvsp[0].cmndspec->runasgrouplist)) &&
				(!tq_empty(&yyvsp[0].cmndspec->prev->runasuserlist) ||
				 !tq_empty(&yyvsp[0].cmndspec->prev->runasgrouplist))) {
				yyvsp[0].cmndspec->runasuserlist = yyvsp[0].cmndspec->prev->runasuserlist;
				yyvsp[0].cmndspec->runasgrouplist = yyvsp[0].cmndspec->prev->runasgrouplist;
			    }
			    yyval.cmndspec = yyvsp[-2].cmndspec;
			}
break;
case 36:
#line 304 "gram.y"
{
			    struct cmndspec *cs = emalloc(sizeof(*cs));
			    if (yyvsp[-2].runas != NULL) {
				list2tq(&cs->runasuserlist, yyvsp[-2].runas->runasusers);
				list2tq(&cs->runasgrouplist, yyvsp[-2].runas->runasgroups);
				efree(yyvsp[-2].runas);
			    } else {
				tq_init(&cs->runasuserlist);
				tq_init(&cs->runasgrouplist);
			    }
			    cs->tags = yyvsp[-1].tag;
			    cs->cmnd = yyvsp[0].member;
			    cs->prev = cs;
			    cs->next = NULL;
			    /* sudo "ALL" implies the SETENV tag */
			    if (cs->cmnd->type == ALL && !cs->cmnd->negated &&
				cs->tags.setenv == UNSPEC)
				cs->tags.setenv = IMPLIED;
			    yyval.cmndspec = cs;
			}
break;
case 37:
#line 326 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 38:
#line 330 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 39:
#line 336 "gram.y"
{
			    yyval.runas = NULL;
			}
break;
case 40:
#line 339 "gram.y"
{
			    yyval.runas = yyvsp[-1].runas;
			}
break;
case 41:
#line 344 "gram.y"
{
			    yyval.runas = emalloc(sizeof(struct runascontainer));
			    yyval.runas->runasusers = yyvsp[0].member;
			    yyval.runas->runasgroups = NULL;
			}
break;
case 42:
#line 349 "gram.y"
{
			    yyval.runas = emalloc(sizeof(struct runascontainer));
			    yyval.runas->runasusers = yyvsp[-2].member;
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 43:
#line 354 "gram.y"
{
			    yyval.runas = emalloc(sizeof(struct runascontainer));
			    yyval.runas->runasusers = NULL;
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 44:
#line 361 "gram.y"
{
			    yyval.tag.nopasswd = yyval.tag.noexec = yyval.tag.setenv = UNSPEC;
			}
break;
case 45:
#line 364 "gram.y"
{
			    yyval.tag.nopasswd = TRUE;
			}
break;
case 46:
#line 367 "gram.y"
{
			    yyval.tag.nopasswd = FALSE;
			}
break;
case 47:
#line 370 "gram.y"
{
			    yyval.tag.noexec = TRUE;
			}
break;
case 48:
#line 373 "gram.y"
{
			    yyval.tag.noexec = FALSE;
			}
break;
case 49:
#line 376 "gram.y"
{
			    yyval.tag.setenv = TRUE;
			}
break;
case 50:
#line 379 "gram.y"
{
			    yyval.tag.setenv = FALSE;
			}
break;
case 51:
#line 384 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 52:
#line 387 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 53:
#line 390 "gram.y"
{
			    struct sudo_command *c = emalloc(sizeof(*c));
			    c->cmnd = yyvsp[0].command.cmnd;
			    c->args = yyvsp[0].command.args;
			    yyval.member = new_member((char *)c, COMMAND);
			}
break;
case 56:
#line 402 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, HOSTALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 58:
#line 412 "gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 61:
#line 422 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, CMNDALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 63:
#line 432 "gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 66:
#line 442 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, RUNASALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 69:
#line 455 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, USERALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 71:
#line 465 "gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 72:
#line 471 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 73:
#line 475 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 74:
#line 481 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 75:
#line 484 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 76:
#line 487 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			}
break;
case 77:
#line 490 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, USERGROUP);
			}
break;
case 78:
#line 493 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
case 80:
#line 499 "gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 81:
#line 505 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 82:
#line 509 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 83:
#line 515 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 84:
#line 518 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 85:
#line 521 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
#line 1364 "y.tab.c"
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
