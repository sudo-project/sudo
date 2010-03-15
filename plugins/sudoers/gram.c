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
#line 2 "./gram.y"
/*
 * Copyright (c) 1996, 1998-2005, 2007-2009
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
#include <limits.h>

#include "sudoers.h" /* XXX */
#include "parse.h"

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
	warningx(">>> %s: %s near line %d <<<", sudoers, s,
	    sudolineno ? sudolineno - 1 : 0);
#else
	fputs("<*> ", stderr);
#endif
    }
    parse_error = TRUE;
}
#line 113 "./gram.y"
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
    struct selinux_info seinfo;
    char *string;
    int tok;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 139 "y.tab.c"
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
#define TRANSCRIPT 275
#define NOTRANSCRIPT 276
#define ALL 277
#define COMMENT 278
#define HOSTALIAS 279
#define CMNDALIAS 280
#define USERALIAS 281
#define RUNASALIAS 282
#define ERROR 283
#define TYPE 284
#define ROLE 285
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short yylhs[] =
#else
short yylhs[] =
#endif
	{                                        -1,
    0,    0,   25,   25,   26,   26,   26,   26,   26,   26,
   26,   26,   26,   26,   26,   26,    4,    4,    3,    3,
    3,    3,    3,   20,   20,   19,   10,   10,    8,    8,
    8,    8,    8,    2,    2,    1,    6,    6,   23,   24,
   22,   22,   22,   22,   22,   17,   17,   18,   18,   18,
   21,   21,   21,   21,   21,   21,   21,   21,   21,    5,
    5,    5,   28,   28,   31,    9,    9,   29,   29,   32,
    7,    7,   30,   30,   33,   27,   27,   34,   13,   13,
   11,   11,   12,   12,   12,   12,   12,   16,   16,   14,
   14,   15,   15,   15,
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
    1,    1,    1,    1,    3,    4,    1,    2,    3,    3,
    0,    1,    1,    2,    2,    0,    3,    1,    3,    2,
    0,    2,    2,    2,    2,    2,    2,    2,    2,    1,
    1,    1,    1,    3,    3,    1,    3,    1,    3,    3,
    1,    3,    1,    3,    3,    1,    3,    3,    1,    3,
    1,    2,    1,    1,    1,    1,    1,    1,    3,    1,
    2,    1,    1,    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydefred[] =
#else
short yydefred[] =
#endif
	{                                      0,
    0,   83,   85,   86,   87,    0,    0,    0,    0,    0,
   84,    5,    0,    0,    0,    0,    0,    0,   79,   81,
    0,    0,    3,    6,    0,    0,   17,    0,   29,   32,
   31,   33,   30,    0,   27,    0,   66,    0,    0,   62,
   61,   60,    0,   37,   71,    0,    0,    0,   63,    0,
    0,   68,    0,    0,   76,    0,    0,   73,   82,    0,
    0,   24,    0,    4,    0,    0,    0,   20,    0,   28,
    0,    0,    0,    0,   38,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   80,    0,    0,   21,   22,
   23,   18,   67,   72,    0,   64,    0,   69,    0,   77,
    0,   74,    0,   34,    0,    0,   25,    0,    0,    0,
    0,    0,    0,   51,    0,    0,   92,   94,   93,    0,
   88,   90,    0,    0,   47,   35,    0,    0,    0,   44,
   45,   91,    0,    0,   40,   39,   52,   53,   54,   55,
   56,   57,   58,   59,   36,   89,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydgoto[] =
#else
short yydgoto[] =
#endif
	{                                      18,
  104,  105,   27,   28,   44,   45,   46,   35,   61,   37,
   19,   20,   21,  121,  122,  123,  106,  110,   62,   63,
  129,  114,  115,  116,   22,   23,   54,   48,   51,   57,
   49,   52,   58,   55,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yysindex[] =
#else
short yysindex[] =
#endif
	{                                    -26,
 -272,    0,    0,    0,    0,  -16,  481,  485,  485,  -31,
    0,    0, -237, -232, -228, -227, -238,    0,    0,    0,
  417,  -26,    0,    0,   -2, -217,    0,    7,    0,    0,
    0,    0,    0, -223,    0,  -28,    0,  -25,  -25,    0,
    0,    0, -248,    0,    0,  -11,  -14,   -6,    0,   -3,
   -5,    0,   -1,    4,    0,    2,    6,    0,    0,  485,
  -17,    0,    8,    0, -198, -196, -195,    0,  -16,    0,
  481,    7,    7,    7,    0,  -31,    7,  481, -237,  -31,
 -232,  485, -228,  485, -227,    0,   29,  481,    0,    0,
    0,    0,    0,    0,   26,    0,   30,    0,   31,    0,
   31,    0,  457,    0,   32, -270,    0,  -30,   -8,   36,
   29,   11,   12,    0, -206, -205,    0,    0,    0, -245,
    0,    0,   35,  -30,    0,    0, -182, -180,  453,    0,
    0,    0,  -30,   35,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yyrindex[] =
#else
short yyrindex[] =
#endif
	{                                     84,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   89,    0,    0,    1,    0,    0,  163,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  190,    0,    0,
  217,    0,    0,  244,    0,    0,  271,    0,    0,    0,
    0,    0,  298,    0,    0,    0,    0,    0,    0,    0,
    0,  325,  352,  379,    0,    0,  406,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  432,    0,    0,    0,
    0,    0,    0,    0,   28,    0,   55,    0,   82,    0,
  109,    0,    0,    0,  136,  480,    0,    0,   49,    0,
  432,    0,    0,    0,  507,  534,    0,    0,    0,    0,
    0,    0,   50,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   51,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yygindex[] =
#else
short yygindex[] =
#endif
	{                                      0,
  -18,    0,   25,   10,   52,  -72,   16,   63,   -7,   27,
   39,   83,    3,  -32,  -15,  -22,    0,    0,   15,    0,
    0,    0,  -12,   -4,    0,   85,    0,    0,    0,    0,
   33,   37,   23,   34,
};
#define YYTABLESIZE 811
#if defined(__cplusplus) || defined(__STDC__)
const short yytable[] =
#else
short yytable[] =
#endif
	{                                      36,
   19,   43,  120,   94,   26,   24,   17,   26,   40,   41,
   38,   39,  117,  112,  113,   71,   26,  118,   60,    2,
   47,   26,    3,    4,    5,   50,   71,   65,   42,   53,
   56,  119,   76,   19,   29,   60,   30,   31,   11,   32,
   66,   68,   67,   87,   19,   72,   78,   73,   74,  124,
   69,   79,   81,   33,   70,   77,  145,   80,   65,   82,
   65,   83,   84,   85,   89,   88,   90,   91,  103,   71,
   95,  127,  128,   76,   60,  111,  125,  112,  133,  113,
  135,   78,  136,    1,   99,   65,  101,   70,    2,   48,
   50,   49,  126,   92,   75,   97,   70,   93,   86,   59,
  146,  134,  107,  131,  132,  109,   64,  102,   75,    0,
  130,   96,   70,    0,   78,    0,  100,   98,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   26,    0,    0,    0,   78,
    0,   75,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   12,    0,    0,    0,   75,    0,   26,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    9,
    0,    0,    0,   26,    0,   12,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   10,    0,    0,    0,
    0,    0,    9,    0,    0,   40,   41,  117,    0,    1,
   25,    2,  118,   25,    3,    4,    5,    6,    7,    8,
    9,   10,   25,    8,    0,   42,  119,   25,    0,   10,
   11,   12,   13,   14,   15,   16,   19,    0,   19,    0,
    0,   19,   19,   19,   19,   19,   19,   19,   19,    0,
   11,    0,    0,    0,    0,    0,    8,   19,   19,   19,
   19,   19,   19,   65,    0,   65,    0,    0,   65,   65,
   65,   65,   65,   65,   65,   65,    0,    7,    0,    0,
    0,    0,    0,   11,   65,   65,   65,   65,   65,   65,
   70,    0,   70,    0,    0,   70,   70,   70,   70,   70,
   70,   70,   70,    0,   15,    0,    0,    0,    0,    0,
    7,   70,   70,   70,   70,   70,   70,   78,    0,   78,
    0,    0,   78,   78,   78,   78,   78,   78,   78,   78,
    0,   13,    0,    0,    0,    0,    0,   15,   78,   78,
   78,   78,   78,   78,   75,    0,   75,    0,    0,   75,
   75,   75,   75,   75,   75,   75,   75,    0,   14,    0,
    0,    0,    0,    0,   13,   75,   75,   75,   75,   75,
   75,   26,    0,   26,    0,    0,   26,   26,   26,   26,
   26,   26,   26,   26,    0,   16,    0,    0,    0,    0,
    0,   14,   26,   26,   26,   26,   26,   26,   12,    0,
   12,    0,    0,   12,   12,   12,   12,   12,   12,   12,
   12,    0,    0,    0,    0,    0,    0,    0,   16,   12,
   12,   12,   12,   12,   12,    9,    0,    9,    0,   34,
    9,    9,    9,    9,    9,    9,    9,    9,    0,    0,
   60,    0,    0,    0,   46,    0,    9,    9,    9,    9,
    9,    9,   10,    0,   10,    0,    0,   10,   10,   10,
   10,   10,   10,   10,   10,   43,    0,    0,    0,   17,
    0,    0,    0,   10,   10,   10,   10,   10,   10,    8,
    0,    8,    0,    0,    8,    8,    8,    8,    8,    8,
    8,    8,   41,   34,  108,    0,    0,   17,    0,    0,
    8,    8,    8,    8,    8,    8,   11,    0,   11,    0,
    0,   11,   11,   11,   11,   11,   11,   11,   11,   42,
    0,    0,    0,    0,    0,    0,    0,   11,   11,   11,
   11,   11,   11,    7,    0,    7,    0,    0,    7,    7,
    7,    7,    7,    7,    7,    7,   43,    0,    0,    0,
    0,    0,    0,    0,    7,    7,    7,    7,    7,    7,
   15,    0,   15,    0,    0,   15,   15,   15,   15,   15,
   15,   15,   15,    0,    0,    0,    0,    0,    0,    0,
    0,   15,   15,   15,   15,   15,   15,   13,    0,   13,
    0,    0,   13,   13,   13,   13,   13,   13,   13,   13,
    0,    0,    0,    0,    0,    0,    0,    0,   13,   13,
   13,   13,   13,   13,   14,    0,   14,    0,    0,   14,
   14,   14,   14,   14,   14,   14,   14,    0,    0,    0,
    0,    0,    0,    0,    0,   14,   14,   14,   14,   14,
   14,   16,    0,   16,    0,    0,   16,   16,   16,   16,
   16,   16,   16,   16,   29,    0,   30,   31,    0,   32,
    0,    0,   16,   16,   16,   16,   16,   16,   46,   46,
    0,    0,    0,   33,    0,    0,    0,    0,    0,    0,
   46,   46,   46,   46,   46,   46,   46,   46,   46,   40,
   41,    0,    0,    0,    2,   46,   46,    3,    4,    5,
    0,  137,  138,  139,  140,  141,  142,  143,  144,   42,
    0,    0,    0,   11,    0,    0,   41,   41,   29,    0,
   30,   31,    2,   32,    0,    3,    4,    5,   41,   41,
   41,   41,   41,   41,   41,   41,   41,   33,    0,    0,
    0,   11,    0,   42,   42,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   42,   42,   42,   42,   42,
   42,   42,   42,   42,    0,    0,    0,    0,    0,    0,
   43,   43,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   43,   43,   43,   43,   43,   43,   43,   43,
   43,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yycheck[] =
#else
short yycheck[] =
#endif
	{                                       7,
    0,   33,   33,   76,   33,  278,   33,   33,  257,  258,
    8,    9,  258,  284,  285,   44,   33,  263,   44,  258,
  258,   33,  261,  262,  263,  258,   44,    0,  277,  258,
  258,  277,   44,   33,  258,   44,  260,  261,  277,  263,
   43,  259,   45,   61,   44,   36,   61,   38,   39,   58,
   44,   58,   58,  277,    0,   46,  129,   61,   61,   61,
   33,   58,   61,   58,  263,   58,  263,  263,   40,   44,
   78,   61,   61,   44,   44,   44,   41,  284,   44,  285,
  263,    0,  263,    0,   82,   58,   84,   33,    0,   41,
   41,   41,  111,   69,   43,   80,   34,   71,   60,   17,
  133,  124,   88,  116,  120,  103,   22,   85,    0,   -1,
  115,   79,   58,   -1,   33,   -1,   83,   81,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   58,
   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,    0,   -1,   -1,   -1,   58,   -1,   33,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,    0,
   -1,   -1,   -1,   58,   -1,   33,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,
   -1,   -1,   33,   -1,   -1,  257,  258,  258,   -1,  256,
  259,  258,  263,  259,  261,  262,  263,  264,  265,  266,
  267,  268,  259,    0,   -1,  277,  277,  259,   -1,   33,
  277,  278,  279,  280,  281,  282,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,  267,  268,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   33,  277,  278,  279,
  280,  281,  282,  256,   -1,  258,   -1,   -1,  261,  262,
  263,  264,  265,  266,  267,  268,   -1,    0,   -1,   -1,
   -1,   -1,   -1,   33,  277,  278,  279,  280,  281,  282,
  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,  265,
  266,  267,  268,   -1,    0,   -1,   -1,   -1,   -1,   -1,
   33,  277,  278,  279,  280,  281,  282,  256,   -1,  258,
   -1,   -1,  261,  262,  263,  264,  265,  266,  267,  268,
   -1,    0,   -1,   -1,   -1,   -1,   -1,   33,  277,  278,
  279,  280,  281,  282,  256,   -1,  258,   -1,   -1,  261,
  262,  263,  264,  265,  266,  267,  268,   -1,    0,   -1,
   -1,   -1,   -1,   -1,   33,  277,  278,  279,  280,  281,
  282,  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,  268,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   33,  277,  278,  279,  280,  281,  282,  256,   -1,
  258,   -1,   -1,  261,  262,  263,  264,  265,  266,  267,
  268,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   33,  277,
  278,  279,  280,  281,  282,  256,   -1,  258,   -1,   33,
  261,  262,  263,  264,  265,  266,  267,  268,   -1,   -1,
   44,   -1,   -1,   -1,   33,   -1,  277,  278,  279,  280,
  281,  282,  256,   -1,  258,   -1,   -1,  261,  262,  263,
  264,  265,  266,  267,  268,   33,   -1,   -1,   -1,   33,
   -1,   -1,   -1,  277,  278,  279,  280,  281,  282,  256,
   -1,  258,   -1,   -1,  261,  262,  263,  264,  265,  266,
  267,  268,   33,   33,   58,   -1,   -1,   33,   -1,   -1,
  277,  278,  279,  280,  281,  282,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,  267,  268,   33,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,  277,  278,  279,
  280,  281,  282,  256,   -1,  258,   -1,   -1,  261,  262,
  263,  264,  265,  266,  267,  268,   33,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  277,  278,  279,  280,  281,  282,
  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,  265,
  266,  267,  268,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  277,  278,  279,  280,  281,  282,  256,   -1,  258,
   -1,   -1,  261,  262,  263,  264,  265,  266,  267,  268,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  277,  278,
  279,  280,  281,  282,  256,   -1,  258,   -1,   -1,  261,
  262,  263,  264,  265,  266,  267,  268,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  277,  278,  279,  280,  281,
  282,  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,  268,  258,   -1,  260,  261,   -1,  263,
   -1,   -1,  277,  278,  279,  280,  281,  282,  257,  258,
   -1,   -1,   -1,  277,   -1,   -1,   -1,   -1,   -1,   -1,
  269,  270,  271,  272,  273,  274,  275,  276,  277,  257,
  258,   -1,   -1,   -1,  258,  284,  285,  261,  262,  263,
   -1,  269,  270,  271,  272,  273,  274,  275,  276,  277,
   -1,   -1,   -1,  277,   -1,   -1,  257,  258,  258,   -1,
  260,  261,  258,  263,   -1,  261,  262,  263,  269,  270,
  271,  272,  273,  274,  275,  276,  277,  277,   -1,   -1,
   -1,  277,   -1,  257,  258,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  269,  270,  271,  272,  273,
  274,  275,  276,  277,   -1,   -1,   -1,   -1,   -1,   -1,
  257,  258,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  269,  270,  271,  272,  273,  274,  275,  276,
  277,
};
#define YYFINAL 18
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 285
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
"PASSWD","NOEXEC","EXEC","SETENV","NOSETENV","TRANSCRIPT","NOTRANSCRIPT","ALL",
"COMMENT","HOSTALIAS","CMNDALIAS","USERALIAS","RUNASALIAS","ERROR","TYPE",
"ROLE",
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
"cmndspec : runasspec selinux cmndtag opcmnd",
"opcmnd : cmnd",
"opcmnd : '!' cmnd",
"rolespec : ROLE '=' WORD",
"typespec : TYPE '=' WORD",
"selinux :",
"selinux : rolespec",
"selinux : typespec",
"selinux : rolespec typespec",
"selinux : typespec rolespec",
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
"cmndtag : cmndtag TRANSCRIPT",
"cmndtag : cmndtag NOTRANSCRIPT",
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
#line 596 "./gram.y"
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
add_defaults(type, bmem, defs)
    int type;
    struct member *bmem;
    struct defaults *defs;
{
    struct defaults *d;
    struct member_list binding;

    /*
     * We can only call list2tq once on bmem as it will zero
     * out the prev pointer when it consumes bmem.
     */
    list2tq(&binding, bmem);

    /*
     * Set type and binding (who it applies to) for new entries.
     */
    for (d = defs; d != NULL; d = d->next) {
	d->type = type;
	d->binding = binding;
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
    struct sudo_command *c;

    while ((us = tq_pop(&userspecs)) != NULL) {
	while ((m = tq_pop(&us->users)) != NULL) {
	    efree(m->name);
	    efree(m);
	}
	while ((priv = tq_pop(&us->privileges)) != NULL) {
	    struct member *runasuser = NULL, *runasgroup = NULL;
#ifdef HAVE_SELINUX
	    char *role = NULL, *type = NULL;
#endif /* HAVE_SELINUX */

	    while ((m = tq_pop(&priv->hostlist)) != NULL) {
		efree(m->name);
		efree(m);
	    }
	    while ((cs = tq_pop(&priv->cmndlist)) != NULL) {
#ifdef HAVE_SELINUX
		/* Only free the first instance of a role/type. */
		if (cs->role != role) {
		    role = cs->role;
		    efree(cs->role);
		}
		if (cs->type != type) {
		    type = cs->type;
		    efree(cs->type);
		}
#endif /* HAVE_SELINUX */
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
		if (cs->cmnd->type == COMMAND) {
			c = (struct sudo_command *) cs->cmnd->name;
			efree(c->cmnd);
			efree(c->args);
		}
		efree(cs->cmnd->name);
		efree(cs->cmnd);
		efree(cs);
	    }
	    efree(priv);
	}
	efree(us);
    }
    tq_init(&userspecs);

    binding = NULL;
    while ((d = tq_pop(&defaults)) != NULL) {
	if (tq_last(&d->binding) != binding) {
	    binding = tq_last(&d->binding);
	    while ((m = tq_pop(&d->binding)) != NULL) {
		if (m->type == COMMAND) {
			c = (struct sudo_command *) m->name;
			efree(c->cmnd);
			efree(c->args);
		}
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

    init_lexer();

    efree(sudoers);
    sudoers = path ? estrdup(path) : NULL;

    parse_error = FALSE;
    errorlineno = -1;
    errorfile = NULL;
    sudolineno = 1;
    verbose = !quiet;
}
#line 760 "y.tab.c"
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
#define YY_SIZE_MAX 0x7fffffff
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
case 1:
#line 186 "./gram.y"
{ ; }
break;
case 5:
#line 194 "./gram.y"
{
			    ;
			}
break;
case 6:
#line 197 "./gram.y"
{
			    yyerrok;
			}
break;
case 7:
#line 200 "./gram.y"
{
			    add_userspec(yyvsp[-1].member, yyvsp[0].privilege);
			}
break;
case 8:
#line 203 "./gram.y"
{
			    ;
			}
break;
case 9:
#line 206 "./gram.y"
{
			    ;
			}
break;
case 10:
#line 209 "./gram.y"
{
			    ;
			}
break;
case 11:
#line 212 "./gram.y"
{
			    ;
			}
break;
case 12:
#line 215 "./gram.y"
{
			    add_defaults(DEFAULTS, NULL, yyvsp[0].defaults);
			}
break;
case 13:
#line 218 "./gram.y"
{
			    add_defaults(DEFAULTS_USER, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 14:
#line 221 "./gram.y"
{
			    add_defaults(DEFAULTS_RUNAS, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 15:
#line 224 "./gram.y"
{
			    add_defaults(DEFAULTS_HOST, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 16:
#line 227 "./gram.y"
{
			    add_defaults(DEFAULTS_CMND, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 18:
#line 233 "./gram.y"
{
			    list_append(yyvsp[-2].defaults, yyvsp[0].defaults);
			    yyval.defaults = yyvsp[-2].defaults;
			}
break;
case 19:
#line 239 "./gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, TRUE);
			}
break;
case 20:
#line 242 "./gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, FALSE);
			}
break;
case 21:
#line 245 "./gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, TRUE);
			}
break;
case 22:
#line 248 "./gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '+');
			}
break;
case 23:
#line 251 "./gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '-');
			}
break;
case 25:
#line 257 "./gram.y"
{
			    list_append(yyvsp[-2].privilege, yyvsp[0].privilege);
			    yyval.privilege = yyvsp[-2].privilege;
			}
break;
case 26:
#line 263 "./gram.y"
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
#line 273 "./gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 28:
#line 277 "./gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 29:
#line 283 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 30:
#line 286 "./gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 31:
#line 289 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			}
break;
case 32:
#line 292 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NTWKADDR);
			}
break;
case 33:
#line 295 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
case 35:
#line 301 "./gram.y"
{
			    list_append(yyvsp[-2].cmndspec, yyvsp[0].cmndspec);
#ifdef HAVE_SELINUX
			    /* propagate role and type */
			    if (yyvsp[0].cmndspec->role == NULL)
				yyvsp[0].cmndspec->role = yyvsp[0].cmndspec->prev->role;
			    if (yyvsp[0].cmndspec->type == NULL)
				yyvsp[0].cmndspec->type = yyvsp[0].cmndspec->prev->type;
#endif /* HAVE_SELINUX */
			    /* propagate tags and runas list */
			    if (yyvsp[0].cmndspec->tags.nopasswd == UNSPEC)
				yyvsp[0].cmndspec->tags.nopasswd = yyvsp[0].cmndspec->prev->tags.nopasswd;
			    if (yyvsp[0].cmndspec->tags.noexec == UNSPEC)
				yyvsp[0].cmndspec->tags.noexec = yyvsp[0].cmndspec->prev->tags.noexec;
			    if (yyvsp[0].cmndspec->tags.setenv == UNSPEC &&
				yyvsp[0].cmndspec->prev->tags.setenv != IMPLIED)
				yyvsp[0].cmndspec->tags.setenv = yyvsp[0].cmndspec->prev->tags.setenv;
			    if (yyvsp[0].cmndspec->tags.transcript == UNSPEC)
				yyvsp[0].cmndspec->tags.transcript = yyvsp[0].cmndspec->prev->tags.transcript;
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
#line 331 "./gram.y"
{
			    struct cmndspec *cs = emalloc(sizeof(*cs));
			    if (yyvsp[-3].runas != NULL) {
				list2tq(&cs->runasuserlist, yyvsp[-3].runas->runasusers);
				list2tq(&cs->runasgrouplist, yyvsp[-3].runas->runasgroups);
				efree(yyvsp[-3].runas);
			    } else {
				tq_init(&cs->runasuserlist);
				tq_init(&cs->runasgrouplist);
			    }
#ifdef HAVE_SELINUX
			    cs->role = yyvsp[-2].seinfo.role;
			    cs->type = yyvsp[-2].seinfo.type;
#endif
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
#line 357 "./gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 38:
#line 361 "./gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 39:
#line 367 "./gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 40:
#line 372 "./gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 41:
#line 377 "./gram.y"
{
			    yyval.seinfo.role = NULL;
			    yyval.seinfo.type = NULL;
			}
break;
case 42:
#line 381 "./gram.y"
{
			    yyval.seinfo.role = yyvsp[0].string;
			    yyval.seinfo.type = NULL;
			}
break;
case 43:
#line 385 "./gram.y"
{
			    yyval.seinfo.type = yyvsp[0].string;
			    yyval.seinfo.role = NULL;
			}
break;
case 44:
#line 389 "./gram.y"
{
			    yyval.seinfo.role = yyvsp[-1].string;
			    yyval.seinfo.type = yyvsp[0].string;
			}
break;
case 45:
#line 393 "./gram.y"
{
			    yyval.seinfo.type = yyvsp[-1].string;
			    yyval.seinfo.role = yyvsp[0].string;
			}
break;
case 46:
#line 399 "./gram.y"
{
			    yyval.runas = NULL;
			}
break;
case 47:
#line 402 "./gram.y"
{
			    yyval.runas = yyvsp[-1].runas;
			}
break;
case 48:
#line 407 "./gram.y"
{
			    yyval.runas = emalloc(sizeof(struct runascontainer));
			    yyval.runas->runasusers = yyvsp[0].member;
			    yyval.runas->runasgroups = NULL;
			}
break;
case 49:
#line 412 "./gram.y"
{
			    yyval.runas = emalloc(sizeof(struct runascontainer));
			    yyval.runas->runasusers = yyvsp[-2].member;
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 50:
#line 417 "./gram.y"
{
			    yyval.runas = emalloc(sizeof(struct runascontainer));
			    yyval.runas->runasusers = NULL;
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 51:
#line 424 "./gram.y"
{
			    yyval.tag.nopasswd = yyval.tag.noexec = yyval.tag.setenv = yyval.tag.transcript = UNSPEC;
			}
break;
case 52:
#line 427 "./gram.y"
{
			    yyval.tag.nopasswd = TRUE;
			}
break;
case 53:
#line 430 "./gram.y"
{
			    yyval.tag.nopasswd = FALSE;
			}
break;
case 54:
#line 433 "./gram.y"
{
			    yyval.tag.noexec = TRUE;
			}
break;
case 55:
#line 436 "./gram.y"
{
			    yyval.tag.noexec = FALSE;
			}
break;
case 56:
#line 439 "./gram.y"
{
			    yyval.tag.setenv = TRUE;
			}
break;
case 57:
#line 442 "./gram.y"
{
			    yyval.tag.setenv = FALSE;
			}
break;
case 58:
#line 445 "./gram.y"
{
			    yyval.tag.transcript = TRUE;
			}
break;
case 59:
#line 448 "./gram.y"
{
			    yyval.tag.transcript = FALSE;
			}
break;
case 60:
#line 453 "./gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 61:
#line 456 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 62:
#line 459 "./gram.y"
{
			    struct sudo_command *c = emalloc(sizeof(*c));
			    c->cmnd = yyvsp[0].command.cmnd;
			    c->args = yyvsp[0].command.args;
			    yyval.member = new_member((char *)c, COMMAND);
			}
break;
case 65:
#line 471 "./gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, HOSTALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 67:
#line 481 "./gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 70:
#line 491 "./gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, CMNDALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 72:
#line 501 "./gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 75:
#line 511 "./gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, RUNASALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 78:
#line 524 "./gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, USERALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 80:
#line 534 "./gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 81:
#line 540 "./gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 82:
#line 544 "./gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 83:
#line 550 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 84:
#line 553 "./gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 85:
#line 556 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			}
break;
case 86:
#line 559 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, USERGROUP);
			}
break;
case 87:
#line 562 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
case 89:
#line 568 "./gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 90:
#line 574 "./gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = FALSE;
			}
break;
case 91:
#line 578 "./gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = TRUE;
			}
break;
case 92:
#line 584 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 93:
#line 587 "./gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 94:
#line 590 "./gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
#line 1514 "y.tab.c"
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
