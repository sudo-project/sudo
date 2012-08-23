#include <config.h>
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
#line 2 "gram.y"
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
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_INTTYPES_H
# include <inttypes.h>
#endif
#if defined(YYBISON) && defined(HAVE_ALLOCA_H) && !defined(__GNUC__)
# include <alloca.h>
#endif /* YYBISON && HAVE_ALLOCA_H && !__GNUC__ */
#include <limits.h>

#include "sudoers.h" /* XXX */
#include "parse.h"
#include "toke.h"
#include "gram.h"

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
extern int last_token;
extern char *sudoers;
bool sudoers_warnings = true;
bool parse_error = false;
int errorlineno = -1;
char *errorfile = NULL;

struct defaults_list defaults;
struct userspec_list userspecs;

/*
 * Local protoypes
 */
static void  add_defaults(int, struct member *, struct defaults *);
static void  add_userspec(struct member *, struct privilege *);
static struct defaults *new_default(char *, char *, int);
static struct member *new_member(char *, int);
       void  yyerror(const char *);

void
yyerror(const char *s)
{
    debug_decl(yyerror, SUDO_DEBUG_PARSER)

    /* If we last saw a newline the error is on the preceding line. */
    if (last_token == COMMENT)
	sudolineno--;

    /* Save the line the first error occurred on. */
    if (errorlineno == -1) {
	errorlineno = sudolineno;
	errorfile = estrdup(sudoers);
    }
    if (sudoers_warnings && s != NULL) {
	LEXTRACE("<*> ");
#ifndef TRACELEXER
	if (trace_print == NULL || trace_print == sudoers_trace_print)
	    warningx(_(">>> %s: %s near line %d <<<"), sudoers, s, sudolineno);
#endif
    }
    parse_error = true;
    debug_return;
}
#line 122 "gram.y"
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
    struct solaris_privs_info privinfo;
    char *string;
    int tok;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 149 "gram.c"
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
#define LOG_INPUT 275
#define NOLOG_INPUT 276
#define LOG_OUTPUT 277
#define NOLOG_OUTPUT 278
#define ALL 279
#define COMMENT 280
#define HOSTALIAS 281
#define CMNDALIAS 282
#define USERALIAS 283
#define RUNASALIAS 284
#define ERROR 285
#define TYPE 286
#define ROLE 287
#define PRIVS 288
#define LIMITPRIVS 289
#define MYSELF 290
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short yylhs[] =
#else
short yylhs[] =
#endif
	{                                        -1,
    0,    0,   28,   28,   29,   29,   29,   29,   29,   29,
   29,   29,   29,   29,   29,   29,    4,    4,    3,    3,
    3,    3,    3,   20,   20,   19,   10,   10,    8,    8,
    8,    8,    8,    2,    2,    1,    6,    6,   23,   24,
   22,   22,   22,   22,   22,   26,   27,   25,   25,   25,
   25,   25,   17,   17,   18,   18,   18,   18,   18,   21,
   21,   21,   21,   21,   21,   21,   21,   21,   21,   21,
    5,    5,    5,   31,   31,   34,    9,    9,   32,   32,
   35,    7,    7,   33,   33,   36,   30,   30,   37,   13,
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
    1,    1,    1,    1,    3,    5,    1,    2,    3,    3,
    0,    1,    1,    2,    2,    3,    3,    0,    1,    1,
    2,    2,    0,    3,    0,    1,    3,    2,    1,    0,
    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,
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
    0,   94,   96,   97,   98,    0,    0,    0,    0,    0,
   95,    5,    0,    0,    0,    0,    0,    0,   90,   92,
    0,    0,    3,    6,    0,    0,   17,    0,   29,   32,
   31,   33,   30,    0,   27,    0,   77,    0,    0,   73,
   72,   71,    0,   37,   82,    0,    0,    0,   74,    0,
    0,   79,    0,    0,   87,    0,    0,   84,   93,    0,
    0,   24,    0,    4,    0,    0,    0,   20,    0,   28,
    0,    0,    0,    0,   38,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   91,    0,    0,   21,   22,
   23,   18,   78,   83,    0,   75,    0,   80,    0,   88,
    0,   85,    0,   34,    0,    0,   25,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  103,  105,  104,    0,
   99,  101,    0,    0,   54,   35,    0,    0,    0,    0,
   60,    0,    0,   44,   45,  102,    0,    0,   40,   39,
    0,    0,    0,   51,   52,  100,   46,   47,   61,   62,
   63,   64,   65,   66,   67,   68,   69,   70,   36,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yydgoto[] =
#else
short yydgoto[] =
#endif
	{                                      18,
  104,  105,   27,   28,   44,   45,   46,   35,   61,   37,
   19,   20,   21,  121,  122,  123,  106,  110,   62,   63,
  143,  114,  115,  116,  131,  132,  133,   22,   23,   54,
   48,   51,   57,   49,   52,   58,   55,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yysindex[] =
#else
short yysindex[] =
#endif
	{                                    541,
 -270,    0,    0,    0,    0,  -21,   -5,  553,  553,   20,
    0,    0, -242, -229, -216, -214, -240,    0,    0,    0,
  -27,  541,    0,    0,  -18, -227,    0,    2,    0,    0,
    0,    0,    0, -223,    0,  -33,    0,  -31,  -31,    0,
    0,    0, -243,    0,    0,  -24,  -12,   -6,    0,    3,
    4,    0,    5,    7,    0,    6,   10,    0,    0,  553,
  -20,    0,   11,    0, -206, -193, -191,    0,  -21,    0,
   -5,    2,    2,    2,    0,   20,    2,   -5, -242,   20,
 -229,  553, -216,  553, -214,    0,   33,   -5,    0,    0,
    0,    0,    0,    0,   31,    0,   32,    0,   34,    0,
   34,    0,  513,    0,   35, -226,    0,   86,  -25,   36,
   33,   19,   21, -234, -202, -201,    0,    0,    0, -232,
    0,    0,   41,   86,    0,    0, -176, -173,   37,   38,
    0, -198, -195,    0,    0,    0,   86,   41,    0,    0,
 -169, -168,  569,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yyrindex[] =
#else
short yyrindex[] =
#endif
	{                                     96,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   97,    0,    0,    1,    0,    0,  177,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  207,    0,    0,
  237,    0,    0,  271,    0,    0,  300,    0,    0,    0,
    0,    0,  329,    0,    0,    0,    0,    0,    0,    0,
    0,  358,  387,  417,    0,    0,  446,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  463,    0,    0,    0,
    0,    0,    0,    0,   30,    0,   59,    0,   89,    0,
  118,    0,   60,    0,  148,  -28,    0,   62,   63,    0,
  463,    0,    0,  594,  489,  512,    0,    0,    0,    0,
    0,    0,   64,    0,    0,    0,    0,    0,    0,    0,
    0,  623,  653,    0,    0,    0,    0,   65,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short yygindex[] =
#else
short yygindex[] =
#endif
	{                                      0,
  -11,    0,   39,   12,   66,  -72,   27,   76,   -4,   40,
   52,   98,   -1,  -23,   -7,   -8,    0,    0,   42,    0,
    0,    0,    8,   13,    0,  -13,   -9,    0,   99,    0,
    0,    0,    0,   46,   45,   44,   48,
};
#define YYTABLESIZE 932
#if defined(__cplusplus) || defined(__STDC__)
const short yytable[] =
#else
short yytable[] =
#endif
	{                                      26,
   19,   26,   36,   94,   41,   34,   38,   39,   26,   24,
   71,   26,   60,   40,   41,   47,   60,    2,   60,   76,
    3,    4,    5,   71,   66,  117,   67,   34,   50,   76,
  118,   68,  124,   19,   29,   42,   30,   31,   11,   32,
   87,   53,   65,   56,   19,   69,  119,   72,   78,   73,
   74,   79,   43,  129,  130,   33,   89,   77,   81,  112,
  113,   81,   76,   80,   83,   82,   84,   85,   88,   90,
  159,   91,  103,   95,   71,   76,  125,   60,  111,  127,
   99,  128,  101,  112,  137,  113,  139,   76,   89,  140,
  130,   81,  129,  147,  148,    1,    2,  141,  142,  126,
   55,  109,   59,   56,   58,   57,   97,   92,   75,   70,
   93,   86,  136,  146,   59,  138,   81,   86,  120,  145,
   64,   89,  144,  135,   96,   98,    0,  134,  102,  107,
  100,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   89,   26,    0,    0,
   86,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   86,   12,    0,    0,    0,
   26,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   26,    9,    0,    0,   12,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   25,    0,   25,   41,   41,
   29,    0,   30,   31,   25,   32,   10,   25,    0,    9,
   41,   41,   41,   41,   41,   41,   41,   41,   41,   41,
   41,   33,   29,    0,   30,   31,   19,   32,   19,   41,
   41,   19,   19,   19,   19,   19,   19,   19,   19,   10,
    8,    0,    0,   33,    0,    0,   40,   41,    0,   19,
   19,   19,   19,   19,   19,   76,    0,   76,    0,    0,
   76,   76,   76,   76,   76,   76,   76,   76,   42,   11,
    0,    0,    0,    8,    0,    0,    0,    0,   76,   76,
   76,   76,   76,   76,   81,    0,   81,    0,    0,   81,
   81,   81,   81,   81,   81,   81,   81,    0,    7,    0,
    0,    0,   11,    0,    0,    0,    0,   81,   81,   81,
   81,   81,   81,  117,   89,    0,   89,    0,  118,   89,
   89,   89,   89,   89,   89,   89,   89,   15,    0,    0,
    0,    7,    0,    0,  119,    0,    0,   89,   89,   89,
   89,   89,   89,   86,    0,   86,    0,    0,   86,   86,
   86,   86,   86,   86,   86,   86,   13,    0,    0,    0,
   15,    0,    0,    0,    0,    0,   86,   86,   86,   86,
   86,   86,    0,   26,    0,   26,    0,    0,   26,   26,
   26,   26,   26,   26,   26,   26,   14,    0,    0,   13,
    0,    0,    0,    0,    0,    0,   26,   26,   26,   26,
   26,   26,   12,    0,   12,    0,    0,   12,   12,   12,
   12,   12,   12,   12,   12,   16,    0,    0,    0,   14,
    0,    0,    0,    0,    0,   12,   12,   12,   12,   12,
   12,    0,    9,    0,    9,    0,    0,    9,    9,    9,
    9,    9,    9,    9,    9,    0,    0,    0,   16,    0,
    0,    0,    0,    0,    0,    9,    9,    9,    9,    9,
    9,    0,   10,    0,   10,   53,    0,   10,   10,   10,
   10,   10,   10,   10,   10,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   10,   10,   10,   10,   10,
   10,   42,    0,    0,    0,    0,    8,    0,    8,    0,
    0,    8,    8,    8,    8,    8,    8,    8,    8,    0,
    0,    0,    0,    0,   43,   17,    0,    0,    0,    8,
    8,    8,    8,    8,    8,   11,    0,   11,    0,    0,
   11,   11,   11,   11,   11,   11,   11,   11,    0,    0,
  108,    0,    0,   17,    0,    0,    0,    0,   11,   11,
   11,   11,   11,   11,    7,   17,    7,    0,    0,    7,
    7,    7,    7,    7,    7,    7,    7,    0,    0,    0,
    0,   43,    0,    0,    0,    0,    0,    7,    7,    7,
    7,    7,    7,   15,    0,   15,    0,    0,   15,   15,
   15,   15,   15,   15,   15,   15,   48,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   15,   15,   15,   15,
   15,   15,   13,    0,   13,    0,    0,   13,   13,   13,
   13,   13,   13,   13,   13,   49,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   13,   13,   13,   13,   13,
   13,    0,   14,    0,   14,    0,    0,   14,   14,   14,
   14,   14,   14,   14,   14,   50,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   14,   14,   14,   14,   14,
   14,   16,    0,   16,    0,    0,   16,   16,   16,   16,
   16,   16,   16,   16,    0,    0,    0,    0,    0,   53,
   53,    0,    0,    0,   16,   16,   16,   16,   16,   16,
    0,   53,   53,   53,   53,   53,   53,   53,   53,   53,
   53,   53,    0,    0,    0,   42,   42,    0,   53,   53,
   53,   53,    0,    0,    0,    0,    0,   42,   42,   42,
   42,   42,   42,   42,   42,   42,   42,   42,   43,   43,
    2,    0,    0,    3,    4,    5,   42,   42,    0,    0,
   43,   43,   43,   43,   43,   43,   43,   43,   43,   43,
   43,   11,    0,    0,    0,    0,    1,    0,    2,   43,
   43,    3,    4,    5,    6,    7,    8,    9,   10,    0,
    2,    0,    0,    3,    4,    5,    0,    0,    0,   11,
   12,   13,   14,   15,   16,   40,   41,    0,    0,    0,
    0,   11,    0,    0,    0,    0,    0,  149,  150,  151,
  152,  153,  154,  155,  156,  157,  158,   42,    0,    0,
   48,   48,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   48,   48,   48,   48,   48,   48,   48,   48,
   48,   48,   48,    0,    0,    0,    0,    0,    0,   49,
   49,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   49,   49,   49,   49,   49,   49,   49,   49,   49,
   49,   49,    0,    0,    0,    0,    0,    0,    0,   50,
   50,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   50,   50,   50,   50,   50,   50,   50,   50,   50,
   50,   50,
};
#if defined(__cplusplus) || defined(__STDC__)
const short yycheck[] =
#else
short yycheck[] =
#endif
	{                                      33,
    0,   33,    7,   76,   33,   33,    8,    9,   33,  280,
   44,   33,   44,  257,  258,  258,   44,  258,   44,   44,
  261,  262,  263,   44,   43,  258,   45,   33,  258,    0,
  263,  259,   58,   33,  258,  279,  260,  261,  279,  263,
   61,  258,   61,  258,   44,   44,  279,   36,   61,   38,
   39,   58,   33,  288,  289,  279,  263,   46,    0,  286,
  287,   58,   33,   61,   58,   61,   61,   58,   58,  263,
  143,  263,   40,   78,   44,   44,   41,   44,   44,   61,
   82,   61,   84,  286,   44,  287,  263,   58,    0,  263,
  289,   33,  288,  263,  263,    0,    0,   61,   61,  111,
   41,  103,   41,   41,   41,   41,   80,   69,   43,   34,
   71,   60,  120,  137,   17,  124,   58,    0,   33,  133,
   22,   33,  132,  116,   79,   81,   -1,  115,   85,   88,
   83,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   58,    0,   -1,   -1,
   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   58,    0,   -1,   -1,   -1,
   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   58,    0,   -1,   -1,   33,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  259,   -1,  259,  257,  258,
  258,   -1,  260,  261,  259,  263,    0,  259,   -1,   33,
  269,  270,  271,  272,  273,  274,  275,  276,  277,  278,
  279,  279,  258,   -1,  260,  261,  256,  263,  258,  288,
  289,  261,  262,  263,  264,  265,  266,  267,  268,   33,
    0,   -1,   -1,  279,   -1,   -1,  257,  258,   -1,  279,
  280,  281,  282,  283,  284,  256,   -1,  258,   -1,   -1,
  261,  262,  263,  264,  265,  266,  267,  268,  279,    0,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,  279,  280,
  281,  282,  283,  284,  256,   -1,  258,   -1,   -1,  261,
  262,  263,  264,  265,  266,  267,  268,   -1,    0,   -1,
   -1,   -1,   33,   -1,   -1,   -1,   -1,  279,  280,  281,
  282,  283,  284,  258,  256,   -1,  258,   -1,  263,  261,
  262,  263,  264,  265,  266,  267,  268,    0,   -1,   -1,
   -1,   33,   -1,   -1,  279,   -1,   -1,  279,  280,  281,
  282,  283,  284,  256,   -1,  258,   -1,   -1,  261,  262,
  263,  264,  265,  266,  267,  268,    0,   -1,   -1,   -1,
   33,   -1,   -1,   -1,   -1,   -1,  279,  280,  281,  282,
  283,  284,   -1,  256,   -1,  258,   -1,   -1,  261,  262,
  263,  264,  265,  266,  267,  268,    0,   -1,   -1,   33,
   -1,   -1,   -1,   -1,   -1,   -1,  279,  280,  281,  282,
  283,  284,  256,   -1,  258,   -1,   -1,  261,  262,  263,
  264,  265,  266,  267,  268,    0,   -1,   -1,   -1,   33,
   -1,   -1,   -1,   -1,   -1,  279,  280,  281,  282,  283,
  284,   -1,  256,   -1,  258,   -1,   -1,  261,  262,  263,
  264,  265,  266,  267,  268,   -1,   -1,   -1,   33,   -1,
   -1,   -1,   -1,   -1,   -1,  279,  280,  281,  282,  283,
  284,   -1,  256,   -1,  258,   33,   -1,  261,  262,  263,
  264,  265,  266,  267,  268,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  279,  280,  281,  282,  283,
  284,   33,   -1,   -1,   -1,   -1,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,  267,  268,   -1,
   -1,   -1,   -1,   -1,   33,   33,   -1,   -1,   -1,  279,
  280,  281,  282,  283,  284,  256,   -1,  258,   -1,   -1,
  261,  262,  263,  264,  265,  266,  267,  268,   -1,   -1,
   58,   -1,   -1,   33,   -1,   -1,   -1,   -1,  279,  280,
  281,  282,  283,  284,  256,   33,  258,   -1,   -1,  261,
  262,  263,  264,  265,  266,  267,  268,   -1,   -1,   -1,
   -1,   33,   -1,   -1,   -1,   -1,   -1,  279,  280,  281,
  282,  283,  284,  256,   -1,  258,   -1,   -1,  261,  262,
  263,  264,  265,  266,  267,  268,   33,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  279,  280,  281,  282,
  283,  284,  256,   -1,  258,   -1,   -1,  261,  262,  263,
  264,  265,  266,  267,  268,   33,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  279,  280,  281,  282,  283,
  284,   -1,  256,   -1,  258,   -1,   -1,  261,  262,  263,
  264,  265,  266,  267,  268,   33,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  279,  280,  281,  282,  283,
  284,  256,   -1,  258,   -1,   -1,  261,  262,  263,  264,
  265,  266,  267,  268,   -1,   -1,   -1,   -1,   -1,  257,
  258,   -1,   -1,   -1,  279,  280,  281,  282,  283,  284,
   -1,  269,  270,  271,  272,  273,  274,  275,  276,  277,
  278,  279,   -1,   -1,   -1,  257,  258,   -1,  286,  287,
  288,  289,   -1,   -1,   -1,   -1,   -1,  269,  270,  271,
  272,  273,  274,  275,  276,  277,  278,  279,  257,  258,
  258,   -1,   -1,  261,  262,  263,  288,  289,   -1,   -1,
  269,  270,  271,  272,  273,  274,  275,  276,  277,  278,
  279,  279,   -1,   -1,   -1,   -1,  256,   -1,  258,  288,
  289,  261,  262,  263,  264,  265,  266,  267,  268,   -1,
  258,   -1,   -1,  261,  262,  263,   -1,   -1,   -1,  279,
  280,  281,  282,  283,  284,  257,  258,   -1,   -1,   -1,
   -1,  279,   -1,   -1,   -1,   -1,   -1,  269,  270,  271,
  272,  273,  274,  275,  276,  277,  278,  279,   -1,   -1,
  257,  258,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  269,  270,  271,  272,  273,  274,  275,  276,
  277,  278,  279,   -1,   -1,   -1,   -1,   -1,   -1,  257,
  258,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  269,  270,  271,  272,  273,  274,  275,  276,  277,
  278,  279,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  257,
  258,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  269,  270,  271,  272,  273,  274,  275,  276,  277,
  278,  279,
};
#define YYFINAL 18
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 290
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
"PASSWD","NOEXEC","EXEC","SETENV","NOSETENV","LOG_INPUT","NOLOG_INPUT",
"LOG_OUTPUT","NOLOG_OUTPUT","ALL","COMMENT","HOSTALIAS","CMNDALIAS","USERALIAS",
"RUNASALIAS","ERROR","TYPE","ROLE","PRIVS","LIMITPRIVS","MYSELF",
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
"cmndspec : runasspec selinux solarisprivs cmndtag opcmnd",
"opcmnd : cmnd",
"opcmnd : '!' cmnd",
"rolespec : ROLE '=' WORD",
"typespec : TYPE '=' WORD",
"selinux :",
"selinux : rolespec",
"selinux : typespec",
"selinux : rolespec typespec",
"selinux : typespec rolespec",
"privsspec : PRIVS '=' WORD",
"limitprivsspec : LIMITPRIVS '=' WORD",
"solarisprivs :",
"solarisprivs : privsspec",
"solarisprivs : limitprivsspec",
"solarisprivs : privsspec limitprivsspec",
"solarisprivs : limitprivsspec privsspec",
"runasspec :",
"runasspec : '(' runaslist ')'",
"runaslist :",
"runaslist : userlist",
"runaslist : userlist ':' grouplist",
"runaslist : ':' grouplist",
"runaslist : ':'",
"cmndtag :",
"cmndtag : cmndtag NOPASSWD",
"cmndtag : cmndtag PASSWD",
"cmndtag : cmndtag NOEXEC",
"cmndtag : cmndtag EXEC",
"cmndtag : cmndtag SETENV",
"cmndtag : cmndtag NOSETENV",
"cmndtag : cmndtag LOG_INPUT",
"cmndtag : cmndtag NOLOG_INPUT",
"cmndtag : cmndtag LOG_OUTPUT",
"cmndtag : cmndtag NOLOG_OUTPUT",
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
#line 674 "gram.y"
static struct defaults *
new_default(char *var, char *val, int op)
{
    struct defaults *d;
    debug_decl(new_default, SUDO_DEBUG_PARSER)

    d = ecalloc(1, sizeof(struct defaults));
    d->var = var;
    d->val = val;
    tq_init(&d->binding);
    /* d->type = 0; */
    d->op = op;
    d->prev = d;
    /* d->next = NULL; */

    debug_return_ptr(d);
}

static struct member *
new_member(char *name, int type)
{
    struct member *m;
    debug_decl(new_member, SUDO_DEBUG_PARSER)

    m = ecalloc(1, sizeof(struct member));
    m->name = name;
    m->type = type;
    m->prev = m;
    /* m->next = NULL; */

    debug_return_ptr(m);
}

/*
 * Add a list of defaults structures to the defaults list.
 * The binding, if non-NULL, specifies a list of hosts, users, or
 * runas users the entries apply to (specified by the type).
 */
static void
add_defaults(int type, struct member *bmem, struct defaults *defs)
{
    struct defaults *d;
    struct member_list binding;
    debug_decl(add_defaults, SUDO_DEBUG_PARSER)

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

    debug_return;
}

/*
 * Allocate a new struct userspec, populate it, and insert it at the
 * and of the userspecs list.
 */
static void
add_userspec(struct member *members, struct privilege *privs)
{
    struct userspec *u;
    debug_decl(add_userspec, SUDO_DEBUG_PARSER)

    u = ecalloc(1, sizeof(*u));
    list2tq(&u->users, members);
    list2tq(&u->privileges, privs);
    u->prev = u;
    /* u->next = NULL; */
    tq_append(&userspecs, u);

    debug_return;
}

/*
 * Free up space used by data structures from a previous parser run and sets
 * the current sudoers file to path.
 */
void
init_parser(const char *path, bool quiet)
{
    struct defaults *d;
    struct member *m, *binding;
    struct userspec *us;
    struct privilege *priv;
    struct cmndspec *cs;
    struct sudo_command *c;
    debug_decl(init_parser, SUDO_DEBUG_PARSER)

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
#ifdef HAVE_PRIV_SET
	    char *privs = NULL, *limitprivs = NULL;
#endif /* HAVE_PRIV_SET */

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
#ifdef HAVE_PRIV_SET
		/* Only free the first instance of privs/limitprivs. */
		if (cs->privs != privs) {
		    privs = cs->privs;
		    efree(cs->privs);
		}
		if (cs->limitprivs != limitprivs) {
		    limitprivs = cs->limitprivs;
		    efree(cs->limitprivs);
		}
#endif /* HAVE_PRIV_SET */
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

    parse_error = false;
    errorlineno = -1;
    errorfile = sudoers;
    sudoers_warnings = !quiet;

    debug_return;
}
#line 827 "gram.c"
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

    newsize = yystacksize ? yystacksize : YYINITSTACKSIZE;
    if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#define YY_SIZE_MAX 0x7fffffff
#endif
    if (YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    i = yyssp - yyss;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + i;
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
#line 204 "gram.y"
{ ; }
break;
case 5:
#line 212 "gram.y"
{
			    ;
			}
break;
case 6:
#line 215 "gram.y"
{
			    yyerrok;
			}
break;
case 7:
#line 218 "gram.y"
{
			    add_userspec(yyvsp[-1].member, yyvsp[0].privilege);
			}
break;
case 8:
#line 221 "gram.y"
{
			    ;
			}
break;
case 9:
#line 224 "gram.y"
{
			    ;
			}
break;
case 10:
#line 227 "gram.y"
{
			    ;
			}
break;
case 11:
#line 230 "gram.y"
{
			    ;
			}
break;
case 12:
#line 233 "gram.y"
{
			    add_defaults(DEFAULTS, NULL, yyvsp[0].defaults);
			}
break;
case 13:
#line 236 "gram.y"
{
			    add_defaults(DEFAULTS_USER, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 14:
#line 239 "gram.y"
{
			    add_defaults(DEFAULTS_RUNAS, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 15:
#line 242 "gram.y"
{
			    add_defaults(DEFAULTS_HOST, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 16:
#line 245 "gram.y"
{
			    add_defaults(DEFAULTS_CMND, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 18:
#line 251 "gram.y"
{
			    list_append(yyvsp[-2].defaults, yyvsp[0].defaults);
			    yyval.defaults = yyvsp[-2].defaults;
			}
break;
case 19:
#line 257 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, true);
			}
break;
case 20:
#line 260 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, false);
			}
break;
case 21:
#line 263 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, true);
			}
break;
case 22:
#line 266 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '+');
			}
break;
case 23:
#line 269 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '-');
			}
break;
case 25:
#line 275 "gram.y"
{
			    list_append(yyvsp[-2].privilege, yyvsp[0].privilege);
			    yyval.privilege = yyvsp[-2].privilege;
			}
break;
case 26:
#line 281 "gram.y"
{
			    struct privilege *p = ecalloc(1, sizeof(*p));
			    list2tq(&p->hostlist, yyvsp[-2].member);
			    list2tq(&p->cmndlist, yyvsp[0].cmndspec);
			    p->prev = p;
			    /* p->next = NULL; */
			    yyval.privilege = p;
			}
break;
case 27:
#line 291 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 28:
#line 295 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 29:
#line 301 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 30:
#line 304 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 31:
#line 307 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			}
break;
case 32:
#line 310 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NTWKADDR);
			}
break;
case 33:
#line 313 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
case 35:
#line 319 "gram.y"
{
			    list_append(yyvsp[-2].cmndspec, yyvsp[0].cmndspec);
#ifdef HAVE_SELINUX
			    /* propagate role and type */
			    if (yyvsp[0].cmndspec->role == NULL)
				yyvsp[0].cmndspec->role = yyvsp[0].cmndspec->prev->role;
			    if (yyvsp[0].cmndspec->type == NULL)
				yyvsp[0].cmndspec->type = yyvsp[0].cmndspec->prev->type;
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
			    /* propagate privs & limitprivs */
			    if (yyvsp[0].cmndspec->privs == NULL)
			        yyvsp[0].cmndspec->privs = yyvsp[0].cmndspec->prev->privs;
			    if (yyvsp[0].cmndspec->limitprivs == NULL)
			        yyvsp[0].cmndspec->limitprivs = yyvsp[0].cmndspec->prev->limitprivs;
#endif /* HAVE_PRIV_SET */
			    /* propagate tags and runas list */
			    if (yyvsp[0].cmndspec->tags.nopasswd == UNSPEC)
				yyvsp[0].cmndspec->tags.nopasswd = yyvsp[0].cmndspec->prev->tags.nopasswd;
			    if (yyvsp[0].cmndspec->tags.noexec == UNSPEC)
				yyvsp[0].cmndspec->tags.noexec = yyvsp[0].cmndspec->prev->tags.noexec;
			    if (yyvsp[0].cmndspec->tags.setenv == UNSPEC &&
				yyvsp[0].cmndspec->prev->tags.setenv != IMPLIED)
				yyvsp[0].cmndspec->tags.setenv = yyvsp[0].cmndspec->prev->tags.setenv;
			    if (yyvsp[0].cmndspec->tags.log_input == UNSPEC)
				yyvsp[0].cmndspec->tags.log_input = yyvsp[0].cmndspec->prev->tags.log_input;
			    if (yyvsp[0].cmndspec->tags.log_output == UNSPEC)
				yyvsp[0].cmndspec->tags.log_output = yyvsp[0].cmndspec->prev->tags.log_output;
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
#line 358 "gram.y"
{
			    struct cmndspec *cs = ecalloc(1, sizeof(*cs));
			    if (yyvsp[-4].runas != NULL) {
				list2tq(&cs->runasuserlist, yyvsp[-4].runas->runasusers);
				list2tq(&cs->runasgrouplist, yyvsp[-4].runas->runasgroups);
				efree(yyvsp[-4].runas);
			    } else {
				tq_init(&cs->runasuserlist);
				tq_init(&cs->runasgrouplist);
			    }
#ifdef HAVE_SELINUX
			    cs->role = yyvsp[-3].seinfo.role;
			    cs->type = yyvsp[-3].seinfo.type;
#endif
#ifdef HAVE_PRIV_SET
			    cs->privs = yyvsp[-2].privinfo.privs;
			    cs->limitprivs = yyvsp[-2].privinfo.limitprivs;
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
#line 388 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 38:
#line 392 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 39:
#line 398 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 40:
#line 403 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 41:
#line 408 "gram.y"
{
			    yyval.seinfo.role = NULL;
			    yyval.seinfo.type = NULL;
			}
break;
case 42:
#line 412 "gram.y"
{
			    yyval.seinfo.role = yyvsp[0].string;
			    yyval.seinfo.type = NULL;
			}
break;
case 43:
#line 416 "gram.y"
{
			    yyval.seinfo.type = yyvsp[0].string;
			    yyval.seinfo.role = NULL;
			}
break;
case 44:
#line 420 "gram.y"
{
			    yyval.seinfo.role = yyvsp[-1].string;
			    yyval.seinfo.type = yyvsp[0].string;
			}
break;
case 45:
#line 424 "gram.y"
{
			    yyval.seinfo.type = yyvsp[-1].string;
			    yyval.seinfo.role = yyvsp[0].string;
			}
break;
case 46:
#line 430 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 47:
#line 434 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 48:
#line 439 "gram.y"
{
			    yyval.privinfo.privs = NULL;
			    yyval.privinfo.limitprivs = NULL;
			}
break;
case 49:
#line 443 "gram.y"
{
			    yyval.privinfo.privs = yyvsp[0].string;
			    yyval.privinfo.limitprivs = NULL;
			}
break;
case 50:
#line 447 "gram.y"
{
			    yyval.privinfo.privs = NULL;
			    yyval.privinfo.limitprivs = yyvsp[0].string;
			}
break;
case 51:
#line 451 "gram.y"
{
			    yyval.privinfo.privs = yyvsp[-1].string;
			    yyval.privinfo.limitprivs = yyvsp[0].string;
			}
break;
case 52:
#line 455 "gram.y"
{
			    yyval.privinfo.limitprivs = yyvsp[-1].string;
			    yyval.privinfo.privs = yyvsp[0].string;
			}
break;
case 53:
#line 460 "gram.y"
{
			    yyval.runas = NULL;
			}
break;
case 54:
#line 463 "gram.y"
{
			    yyval.runas = yyvsp[-1].runas;
			}
break;
case 55:
#line 468 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    yyval.runas->runasusers = new_member(NULL, MYSELF);
			    /* $$->runasgroups = NULL; */
			}
break;
case 56:
#line 473 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    yyval.runas->runasusers = yyvsp[0].member;
			    /* $$->runasgroups = NULL; */
			}
break;
case 57:
#line 478 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    yyval.runas->runasusers = yyvsp[-2].member;
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 58:
#line 483 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    /* $$->runasusers = NULL; */
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 59:
#line 488 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    yyval.runas->runasusers = new_member(NULL, MYSELF);
			    /* $$->runasgroups = NULL; */
			}
break;
case 60:
#line 495 "gram.y"
{
			    yyval.tag.nopasswd = yyval.tag.noexec = yyval.tag.setenv =
				yyval.tag.log_input = yyval.tag.log_output = UNSPEC;
			}
break;
case 61:
#line 499 "gram.y"
{
			    yyval.tag.nopasswd = true;
			}
break;
case 62:
#line 502 "gram.y"
{
			    yyval.tag.nopasswd = false;
			}
break;
case 63:
#line 505 "gram.y"
{
			    yyval.tag.noexec = true;
			}
break;
case 64:
#line 508 "gram.y"
{
			    yyval.tag.noexec = false;
			}
break;
case 65:
#line 511 "gram.y"
{
			    yyval.tag.setenv = true;
			}
break;
case 66:
#line 514 "gram.y"
{
			    yyval.tag.setenv = false;
			}
break;
case 67:
#line 517 "gram.y"
{
			    yyval.tag.log_input = true;
			}
break;
case 68:
#line 520 "gram.y"
{
			    yyval.tag.log_input = false;
			}
break;
case 69:
#line 523 "gram.y"
{
			    yyval.tag.log_output = true;
			}
break;
case 70:
#line 526 "gram.y"
{
			    yyval.tag.log_output = false;
			}
break;
case 71:
#line 531 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 72:
#line 534 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 73:
#line 537 "gram.y"
{
			    struct sudo_command *c = ecalloc(1, sizeof(*c));
			    c->cmnd = yyvsp[0].command.cmnd;
			    c->args = yyvsp[0].command.args;
			    yyval.member = new_member((char *)c, COMMAND);
			}
break;
case 76:
#line 549 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, HOSTALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 78:
#line 559 "gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 81:
#line 569 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, CMNDALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 83:
#line 579 "gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 86:
#line 589 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, RUNASALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 89:
#line 602 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, USERALIAS, yyvsp[0].member)) != NULL) {
				yyerror(s);
				YYERROR;
			    }
			}
break;
case 91:
#line 612 "gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 92:
#line 618 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 93:
#line 622 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 94:
#line 628 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 95:
#line 631 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 96:
#line 634 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			}
break;
case 97:
#line 637 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, USERGROUP);
			}
break;
case 98:
#line 640 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
case 100:
#line 646 "gram.y"
{
			    list_append(yyvsp[-2].member, yyvsp[0].member);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 101:
#line 652 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 102:
#line 656 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 103:
#line 662 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 104:
#line 665 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 105:
#line 668 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
#line 1667 "gram.c"
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
