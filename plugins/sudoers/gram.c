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
#define yyparse sudoersparse
#define yylex sudoerslex
#define yyerror sudoerserror
#define yychar sudoerschar
#define yyval sudoersval
#define yylval sudoerslval
#define yydebug sudoersdebug
#define yynerrs sudoersnerrs
#define yyerrflag sudoerserrflag
#define yyss sudoersss
#define yysslim sudoerssslim
#define yyssp sudoersssp
#define yyvs sudoersvs
#define yyvsp sudoersvsp
#define yystacksize sudoersstacksize
#define yylhs sudoerslhs
#define yylen sudoerslen
#define yydefred sudoersdefred
#define yydgoto sudoersdgoto
#define yysindex sudoerssindex
#define yyrindex sudoersrindex
#define yygindex sudoersgindex
#define yytable sudoerstable
#define yycheck sudoerscheck
#define yyname sudoersname
#define yyrule sudoersrule
#define YYPREFIX "sudoers"
#line 2 "gram.y"
/*
 * Copyright (c) 1996, 1998-2005, 2007-2013
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
bool sudoers_warnings = true;
bool parse_error = false;
int errorlineno = -1;
const char *errorfile = NULL;

struct defaults_list defaults = TAILQ_HEAD_INITIALIZER(defaults);
struct userspec_list userspecs = TAILQ_HEAD_INITIALIZER(userspecs);

/*
 * Local protoypes
 */
static void  add_defaults(int, struct member *, struct defaults *);
static void  add_userspec(struct member *, struct privilege *);
static struct defaults *new_default(char *, char *, int);
static struct member *new_member(char *, int);
static struct sudo_digest *new_digest(int, const char *);
#line 92 "gram.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
    struct cmndspec *cmndspec;
    struct defaults *defaults;
    struct member *member;
    struct runascontainer *runas;
    struct privilege *privilege;
    struct sudo_digest *digest;
    struct sudo_command command;
    struct cmndtag tag;
    struct selinux_info seinfo;
    struct solaris_privs_info privinfo;
    char *string;
    int tok;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 146 "gram.c"
#define COMMAND 257
#define ALIAS 258
#define DEFVAR 259
#define NTWKADDR 260
#define NETGROUP 261
#define USERGROUP 262
#define WORD 263
#define DIGEST 264
#define DEFAULTS 265
#define DEFAULTS_HOST 266
#define DEFAULTS_USER 267
#define DEFAULTS_RUNAS 268
#define DEFAULTS_CMND 269
#define NOPASSWD 270
#define PASSWD 271
#define NOEXEC 272
#define EXEC 273
#define SETENV 274
#define NOSETENV 275
#define LOG_INPUT 276
#define NOLOG_INPUT 277
#define LOG_OUTPUT 278
#define NOLOG_OUTPUT 279
#define ALL 280
#define COMMENT 281
#define HOSTALIAS 282
#define CMNDALIAS 283
#define USERALIAS 284
#define RUNASALIAS 285
#define ERROR 286
#define TYPE 287
#define ROLE 288
#define PRIVS 289
#define LIMITPRIVS 290
#define MYSELF 291
#define SHA224 292
#define SHA256 293
#define SHA384 294
#define SHA512 295
#define YYERRCODE 256
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerslhs[] =
#else
short sudoerslhs[] =
#endif
	{                                        -1,
    0,    0,   30,   30,   31,   31,   31,   31,   31,   31,
   31,   31,   31,   31,   31,   31,    4,    4,    3,    3,
    3,    3,    3,   21,   21,   20,   11,   11,    9,    9,
    9,    9,    9,    2,    2,    1,   29,   29,   29,   29,
    7,    7,    6,    6,   24,   25,   23,   23,   23,   23,
   23,   27,   28,   26,   26,   26,   26,   26,   18,   18,
   19,   19,   19,   19,   19,   22,   22,   22,   22,   22,
   22,   22,   22,   22,   22,   22,    5,    5,    5,   33,
   33,   36,   10,   10,   34,   34,   37,    8,    8,   35,
   35,   38,   32,   32,   39,   14,   14,   12,   12,   13,
   13,   13,   13,   13,   17,   17,   15,   15,   16,   16,
   16,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerslen[] =
#else
short sudoerslen[] =
#endif
	{                                         2,
    0,    1,    1,    2,    1,    2,    2,    2,    2,    2,
    2,    2,    3,    3,    3,    3,    1,    3,    1,    2,
    3,    3,    3,    1,    3,    3,    1,    2,    1,    1,
    1,    1,    1,    1,    3,    5,    3,    3,    3,    3,
    1,    2,    1,    2,    3,    3,    0,    1,    1,    2,
    2,    3,    3,    0,    1,    1,    2,    2,    0,    3,
    0,    1,    3,    2,    1,    0,    2,    2,    2,    2,
    2,    2,    2,    2,    2,    2,    1,    1,    1,    1,
    3,    3,    1,    3,    1,    3,    3,    1,    3,    1,
    3,    3,    1,    3,    3,    1,    3,    1,    2,    1,
    1,    1,    1,    1,    1,    3,    1,    2,    1,    1,
    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersdefred[] =
#else
short sudoersdefred[] =
#endif
	{                                      0,
    0,  100,  102,  103,  104,    0,    0,    0,    0,    0,
  101,    5,    0,    0,    0,    0,    0,    0,   96,   98,
    0,    0,    3,    6,    0,    0,   17,    0,   29,   32,
   31,   33,   30,    0,   27,    0,   83,    0,    0,   79,
   78,   77,    0,    0,    0,    0,    0,   43,   41,   88,
    0,    0,    0,    0,   80,    0,    0,   85,    0,    0,
   93,    0,    0,   90,   99,    0,    0,   24,    0,    4,
    0,    0,    0,   20,    0,   28,    0,    0,    0,    0,
   44,    0,    0,    0,    0,    0,    0,   42,    0,    0,
    0,    0,    0,    0,    0,    0,   97,    0,    0,   21,
   22,   23,   18,   84,   37,   38,   39,   40,   89,    0,
   81,    0,   86,    0,   94,    0,   91,    0,   34,    0,
    0,   25,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  109,  111,  110,    0,  105,  107,    0,    0,   60,
   35,    0,    0,    0,    0,   66,    0,    0,   50,   51,
  108,    0,    0,   46,   45,    0,    0,    0,   57,   58,
  106,   52,   53,   67,   68,   69,   70,   71,   72,   73,
   74,   75,   76,   36,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersdgoto[] =
#else
short sudoersdgoto[] =
#endif
	{                                      18,
  119,  120,   27,   28,   48,   49,   50,   51,   35,   67,
   37,   19,   20,   21,  136,  137,  138,  121,  125,   68,
   69,  158,  129,  130,  131,  146,  147,  148,   52,   22,
   23,   60,   54,   57,   63,   55,   58,   64,   61,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerssindex[] =
#else
short sudoerssindex[] =
#endif
	{                                    -33,
 -277,    0,    0,    0,    0,  -13,   75,  105,  105,  -15,
    0,    0, -246, -241, -217, -210, -226,    0,    0,    0,
   -5,  -33,    0,    0,   -3, -244,    0,    5,    0,    0,
    0,    0,    0, -237,    0,  -28,    0,  -19,  -19,    0,
    0,    0, -251,   -7,   -1,    4,    7,    0,    0,    0,
  -14,  -20,   -2,    8,    0,    6,   11,    0,    9,   13,
    0,   12,   14,    0,    0,  105,  -11,    0,   18,    0,
 -203, -200, -188,    0,  -13,    0,   75,    5,    5,    5,
    0, -187, -185, -184, -183,  -15,    5,    0,   75, -246,
  -15, -241,  105, -217,  105, -210,    0,   42,   75,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   39,
    0,   40,    0,   43,    0,   43,    0,   45,    0,   44,
 -279,    0,  135,   -6,   49,   42,   25,   32, -243, -195,
 -192,    0,    0,    0, -236,    0,    0,   54,  135,    0,
    0, -164, -163,   41,   46,    0, -189, -180,    0,    0,
    0,  135,   54,    0,    0, -159, -158,  585,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersrindex[] =
#else
short sudoersrindex[] =
#endif
	{                                    106,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  110,    0,    0,    1,    0,    0,  181,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  211,    0,    0,  241,    0,    0,  271,
    0,    0,  301,    0,    0,    0,    0,    0,  331,    0,
    0,    0,    0,    0,    0,    0,    0,  361,  391,  421,
    0,    0,    0,    0,    0,    0,  451,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  467,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   31,
    0,   61,    0,   91,    0,  121,    0,   70,    0,  151,
  495,    0,   71,   72,    0,  467,    0,    0,  615,  525,
  555,    0,    0,    0,    0,    0,    0,   73,    0,    0,
    0,    0,    0,    0,    0,    0,  645,  675,    0,    0,
    0,    0,   74,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersgindex[] =
#else
short sudoersgindex[] =
#endif
	{                                      0,
  -10,    0,   47,   17,   80,   65,  -84,   27,   92,   -4,
   48,   62,  112,    2,  -25,   10,   -9,    0,    0,   33,
    0,    0,    0,    3,   16,    0,  -17,  -12,    0,    0,
  111,    0,    0,    0,    0,   50,   51,   52,   53,
};
#define YYTABLESIZE 970
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerstable[] =
#else
short sudoerstable[] =
#endif
	{                                      17,
   19,  109,   36,   24,   26,   40,   41,  127,  128,   38,
   39,   53,   43,   26,   74,   77,   56,   43,   26,   26,
   29,  132,   30,   31,   66,   32,  133,   34,   42,   86,
   82,    2,   77,   19,    3,    4,    5,   66,   66,   72,
   59,   73,   33,  134,   19,  144,  145,   62,   75,   98,
   82,  139,   78,   11,   79,   80,   83,   71,   89,  100,
   87,   84,  101,   82,   85,   90,   91,   87,   92,   93,
   94,   96,   95,  174,  102,   99,  105,   17,  106,  107,
  108,  118,   77,   86,  110,  142,   66,  126,   82,  140,
   95,  127,  143,   87,  114,  128,  116,  152,  154,  155,
  145,  156,  123,  162,  163,    1,  157,   34,  144,    2,
   61,   65,   62,   64,   63,  141,   88,  112,   87,  124,
   92,  103,   81,   95,  104,   76,  161,   97,   65,  153,
  160,  122,   70,  150,  159,    0,    0,   17,    0,  111,
    0,    0,  113,    0,  151,  149,  115,  117,   95,    0,
   26,    0,    0,   92,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  135,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   92,    0,
   12,    0,    0,   26,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   26,    0,
    9,    0,    0,   12,    0,    0,    0,    0,    0,    0,
    0,    0,    1,    0,    2,    0,    0,    3,    4,    5,
   25,    6,    7,    8,    9,   10,   40,   41,    0,   25,
   10,   40,   41,    9,   25,   25,   11,   12,   13,   14,
   15,   16,   29,    0,   30,   31,   19,   32,   19,   42,
    0,   19,   19,   19,   42,   19,   19,   19,   19,   19,
    8,    0,    0,   10,   33,    0,   44,   45,   46,   47,
   19,   19,   19,   19,   19,   19,   82,    0,   82,    0,
    0,   82,   82,   82,    0,   82,   82,   82,   82,   82,
   11,    0,    2,    8,    0,    3,    4,    5,    0,    0,
   82,   82,   82,   82,   82,   82,   87,    0,   87,    0,
    0,   87,   87,   87,   11,   87,   87,   87,   87,   87,
    7,    0,   29,   11,   30,   31,    0,   32,    0,    0,
   87,   87,   87,   87,   87,   87,   95,    0,   95,    0,
    0,   95,   95,   95,   33,   95,   95,   95,   95,   95,
   15,    0,    2,    7,    0,    3,    4,    5,    0,    0,
   95,   95,   95,   95,   95,   95,   92,    0,   92,    0,
    0,   92,   92,   92,   11,   92,   92,   92,   92,   92,
   13,    0,  132,   15,    0,    0,    0,  133,    0,    0,
   92,   92,   92,   92,   92,   92,   26,    0,   26,    0,
    0,   26,   26,   26,  134,   26,   26,   26,   26,   26,
   14,    0,    0,   13,    0,    0,    0,    0,    0,    0,
   26,   26,   26,   26,   26,   26,   12,    0,   12,    0,
    0,   12,   12,   12,    0,   12,   12,   12,   12,   12,
   16,    0,    0,   14,    0,    0,    0,    0,    0,    0,
   12,   12,   12,   12,   12,   12,    9,    0,    9,    0,
    0,    9,    9,    9,    0,    9,    9,    9,    9,    9,
    0,    0,    0,   16,    0,    0,    0,    0,    0,    0,
    9,    9,    9,    9,    9,    9,   10,    0,   10,   59,
    0,   10,   10,   10,    0,   10,   10,   10,   10,   10,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   10,   10,   10,   10,   10,   10,    8,   47,    8,    0,
    0,    8,    8,    8,    0,    8,    8,    8,    8,    8,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    8,    8,    8,    8,    8,    8,   11,   48,   11,    0,
    0,   11,   11,   11,    0,   11,   11,   11,   11,   11,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   11,   11,   11,   11,   11,   11,    7,   49,    7,    0,
    0,    7,    7,    7,    0,    7,    7,    7,    7,    7,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    7,    7,    7,    7,    7,    7,   15,   43,   15,    0,
    0,   15,   15,   15,    0,   15,   15,   15,   15,   15,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   15,   15,   15,   15,   15,   15,   13,   54,   13,    0,
    0,   13,   13,   13,    0,   13,   13,   13,   13,   13,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   13,   13,   13,   13,   13,   13,   14,   55,   14,    0,
    0,   14,   14,   14,    0,   14,   14,   14,   14,   14,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   14,   14,   14,   14,   14,   14,   16,   56,   16,    0,
    0,   16,   16,   16,    0,   16,   16,   16,   16,   16,
    0,    0,    0,   59,   59,    0,    0,    0,    0,    0,
   16,   16,   16,   16,   16,   16,   59,   59,   59,   59,
   59,   59,   59,   59,   59,   59,   59,    0,    0,    0,
    0,   47,   47,   59,   59,   59,   59,    0,   59,   59,
   59,   59,    0,    0,   47,   47,   47,   47,   47,   47,
   47,   47,   47,   47,   47,    0,    0,    0,    0,    0,
    0,   48,   48,   47,   47,    0,   47,   47,   47,   47,
    0,    0,    0,    0,   48,   48,   48,   48,   48,   48,
   48,   48,   48,   48,   48,    0,    0,    0,    0,    0,
    0,   49,   49,   48,   48,    0,   48,   48,   48,   48,
    0,    0,    0,    0,   49,   49,   49,   49,   49,   49,
   49,   49,   49,   49,   49,    0,    0,    0,    0,    0,
    0,   40,   41,   49,   49,    0,   49,   49,   49,   49,
    0,    0,    0,    0,  164,  165,  166,  167,  168,  169,
  170,  171,  172,  173,   42,    0,    0,    0,    0,    0,
    0,   54,   54,    0,    0,    0,   44,   45,   46,   47,
    0,    0,    0,    0,   54,   54,   54,   54,   54,   54,
   54,   54,   54,   54,   54,    0,    0,    0,    0,    0,
    0,   55,   55,    0,    0,    0,   54,   54,   54,   54,
    0,    0,    0,    0,   55,   55,   55,   55,   55,   55,
   55,   55,   55,   55,   55,    0,    0,    0,    0,    0,
    0,   56,   56,    0,    0,    0,   55,   55,   55,   55,
    0,    0,    0,    0,   56,   56,   56,   56,   56,   56,
   56,   56,   56,   56,   56,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   56,   56,   56,   56,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerscheck[] =
#else
short sudoerscheck[] =
#endif
	{                                      33,
    0,   86,    7,  281,   33,  257,  258,  287,  288,    8,
    9,  258,   33,   33,  259,   44,  258,   33,   33,   33,
  258,  258,  260,  261,   44,  263,  263,   33,  280,   44,
    0,  258,   44,   33,  261,  262,  263,   44,   44,   43,
  258,   45,  280,  280,   44,  289,  290,  258,   44,   61,
   58,   58,   36,  280,   38,   39,   58,   61,   61,  263,
    0,   58,  263,   33,   58,   58,   61,   51,   58,   61,
   58,   58,   61,  158,  263,   58,  264,   33,  264,  264,
  264,   40,   44,   44,   89,   61,   44,   44,   58,   41,
    0,  287,   61,   33,   93,  288,   95,   44,  263,  263,
  290,   61,   58,  263,  263,    0,   61,   33,  289,    0,
   41,   41,   41,   41,   41,  126,   52,   91,   58,  118,
    0,   75,   43,   33,   77,   34,  152,   66,   17,  139,
  148,   99,   22,  131,  147,   -1,   -1,   33,   -1,   90,
   -1,   -1,   92,   -1,  135,  130,   94,   96,   58,   -1,
    0,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   33,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   58,   -1,
    0,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   58,   -1,
    0,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  256,   -1,  258,   -1,   -1,  261,  262,  263,
  259,  265,  266,  267,  268,  269,  257,  258,   -1,  259,
    0,  257,  258,   33,  259,  259,  280,  281,  282,  283,
  284,  285,  258,   -1,  260,  261,  256,  263,  258,  280,
   -1,  261,  262,  263,  280,  265,  266,  267,  268,  269,
    0,   -1,   -1,   33,  280,   -1,  292,  293,  294,  295,
  280,  281,  282,  283,  284,  285,  256,   -1,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
    0,   -1,  258,   33,   -1,  261,  262,  263,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  280,  265,  266,  267,  268,  269,
    0,   -1,  258,   33,  260,  261,   -1,  263,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  280,  265,  266,  267,  268,  269,
    0,   -1,  258,   33,   -1,  261,  262,  263,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  280,  265,  266,  267,  268,  269,
    0,   -1,  258,   33,   -1,   -1,   -1,  263,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  280,  265,  266,  267,  268,  269,
    0,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   -1,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
    0,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   -1,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   -1,  258,   33,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   33,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   33,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   33,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   33,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   33,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   33,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  256,   33,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
   -1,   -1,   -1,  257,  258,   -1,   -1,   -1,   -1,   -1,
  280,  281,  282,  283,  284,  285,  270,  271,  272,  273,
  274,  275,  276,  277,  278,  279,  280,   -1,   -1,   -1,
   -1,  257,  258,  287,  288,  289,  290,   -1,  292,  293,
  294,  295,   -1,   -1,  270,  271,  272,  273,  274,  275,
  276,  277,  278,  279,  280,   -1,   -1,   -1,   -1,   -1,
   -1,  257,  258,  289,  290,   -1,  292,  293,  294,  295,
   -1,   -1,   -1,   -1,  270,  271,  272,  273,  274,  275,
  276,  277,  278,  279,  280,   -1,   -1,   -1,   -1,   -1,
   -1,  257,  258,  289,  290,   -1,  292,  293,  294,  295,
   -1,   -1,   -1,   -1,  270,  271,  272,  273,  274,  275,
  276,  277,  278,  279,  280,   -1,   -1,   -1,   -1,   -1,
   -1,  257,  258,  289,  290,   -1,  292,  293,  294,  295,
   -1,   -1,   -1,   -1,  270,  271,  272,  273,  274,  275,
  276,  277,  278,  279,  280,   -1,   -1,   -1,   -1,   -1,
   -1,  257,  258,   -1,   -1,   -1,  292,  293,  294,  295,
   -1,   -1,   -1,   -1,  270,  271,  272,  273,  274,  275,
  276,  277,  278,  279,  280,   -1,   -1,   -1,   -1,   -1,
   -1,  257,  258,   -1,   -1,   -1,  292,  293,  294,  295,
   -1,   -1,   -1,   -1,  270,  271,  272,  273,  274,  275,
  276,  277,  278,  279,  280,   -1,   -1,   -1,   -1,   -1,
   -1,  257,  258,   -1,   -1,   -1,  292,  293,  294,  295,
   -1,   -1,   -1,   -1,  270,  271,  272,  273,  274,  275,
  276,  277,  278,  279,  280,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  292,  293,  294,  295,
};
#define YYFINAL 18
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 295
#if YYDEBUG
#if defined(__cplusplus) || defined(__STDC__)
const char * const sudoersname[] =
#else
char *sudoersname[] =
#endif
	{
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,0,0,"'('","')'",0,"'+'","','","'-'",0,0,0,0,0,0,0,0,0,0,0,0,"':'",
0,0,"'='",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"COMMAND","ALIAS","DEFVAR","NTWKADDR","NETGROUP","USERGROUP","WORD","DIGEST",
"DEFAULTS","DEFAULTS_HOST","DEFAULTS_USER","DEFAULTS_RUNAS","DEFAULTS_CMND",
"NOPASSWD","PASSWD","NOEXEC","EXEC","SETENV","NOSETENV","LOG_INPUT",
"NOLOG_INPUT","LOG_OUTPUT","NOLOG_OUTPUT","ALL","COMMENT","HOSTALIAS",
"CMNDALIAS","USERALIAS","RUNASALIAS","ERROR","TYPE","ROLE","PRIVS","LIMITPRIVS",
"MYSELF","SHA224","SHA256","SHA384","SHA512",
};
#if defined(__cplusplus) || defined(__STDC__)
const char * const sudoersrule[] =
#else
char *sudoersrule[] =
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
"cmndspec : runasspec selinux solarisprivs cmndtag digcmnd",
"digest : SHA224 ':' DIGEST",
"digest : SHA256 ':' DIGEST",
"digest : SHA384 ':' DIGEST",
"digest : SHA512 ':' DIGEST",
"digcmnd : opcmnd",
"digcmnd : digest opcmnd",
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
"cmndlist : digcmnd",
"cmndlist : cmndlist ',' digcmnd",
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
unsigned int yystacksize;
#line 685 "gram.y"
void
sudoerserror(const char *s)
{
    debug_decl(sudoerserror, SUDO_DEBUG_PARSER)

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
	if (trace_print == NULL || trace_print == sudoers_trace_print) {
	    const char fmt[] = ">>> %s: %s near line %d <<<\n";
	    int oldlocale;

	    /* Warnings are displayed in the user's locale. */
	    sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);
	    sudo_printf(SUDO_CONV_ERROR_MSG, _(fmt), sudoers, _(s), sudolineno);
	    sudoers_setlocale(oldlocale, NULL);
	}
#endif
    }
    parse_error = true;
    debug_return;
}

static struct defaults *
new_default(char *var, char *val, int op)
{
    struct defaults *d;
    debug_decl(new_default, SUDO_DEBUG_PARSER)

    d = ecalloc(1, sizeof(struct defaults));
    d->var = var;
    d->val = val;
    /* d->type = 0; */
    d->op = op;
    /* d->binding = NULL */
    HLTQ_INIT(d, entries);

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
    HLTQ_INIT(m, entries);

    debug_return_ptr(m);
}

struct sudo_digest *
new_digest(int digest_type, const char *digest_str)
{
    struct sudo_digest *dig;
    debug_decl(new_digest, SUDO_DEBUG_PARSER)

    dig = emalloc(sizeof(*dig));
    dig->digest_type = digest_type;
    dig->digest_str = estrdup(digest_str);

    debug_return_ptr(dig);
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
    struct member_list *binding;
    debug_decl(add_defaults, SUDO_DEBUG_PARSER)

    if (defs != NULL) {
	/*
	 * We use a single binding for each entry in defs.
	 */
	binding = emalloc(sizeof(*binding));
	if (bmem != NULL)
	    HLTQ_TO_TAILQ(binding, bmem, entries);
	else
	    TAILQ_INIT(binding);

	/*
	 * Set type and binding (who it applies to) for new entries.
	 * Then add to the global defaults list.
	 */
	HLTQ_FOREACH(d, defs, entries) {
	    d->type = type;
	    d->binding = binding;
	}
	TAILQ_CONCAT_HLTQ(&defaults, defs, entries);
    }

    debug_return;
}

/*
 * Allocate a new struct userspec, populate it, and insert it at the
 * end of the userspecs list.
 */
static void
add_userspec(struct member *members, struct privilege *privs)
{
    struct userspec *u;
    debug_decl(add_userspec, SUDO_DEBUG_PARSER)

    u = ecalloc(1, sizeof(*u));
    HLTQ_TO_TAILQ(&u->users, members, entries);
    HLTQ_TO_TAILQ(&u->privileges, privs, entries);
    TAILQ_INSERT_TAIL(&userspecs, u, entries);

    debug_return;
}

/*
 * Free up space used by data structures from a previous parser run and sets
 * the current sudoers file to path.
 */
void
init_parser(const char *path, bool quiet)
{
    struct member_list *binding;
    struct defaults *d, *d_next;
    struct userspec *us, *us_next;
    debug_decl(init_parser, SUDO_DEBUG_PARSER)

    TAILQ_FOREACH_SAFE(us, &userspecs, entries, us_next) {
	struct member *m, *m_next;
	struct privilege *priv, *priv_next;

	TAILQ_FOREACH_SAFE(m, &us->users, entries, m_next) {
	    efree(m->name);
	    efree(m);
	}
	TAILQ_FOREACH_SAFE(priv, &us->privileges, entries, priv_next) {
	    struct member_list *runasuserlist = NULL, *runasgrouplist = NULL;
	    struct cmndspec *cs, *cs_next;
#ifdef HAVE_SELINUX
	    char *role = NULL, *type = NULL;
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
	    char *privs = NULL, *limitprivs = NULL;
#endif /* HAVE_PRIV_SET */

	    TAILQ_FOREACH_SAFE(m, &priv->hostlist, entries, m_next) {
		efree(m->name);
		efree(m);
	    }
	    TAILQ_FOREACH_SAFE(cs, &priv->cmndlist, entries, cs_next) {
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
		/* Only free the first instance of runas user/group lists. */
		if (cs->runasuserlist && cs->runasuserlist != runasuserlist) {
		    runasuserlist = cs->runasuserlist;
		    TAILQ_FOREACH_SAFE(m, runasuserlist, entries, m_next) {
			efree(m->name);
			efree(m);
		    }
		    efree(runasuserlist);
		}
		if (cs->runasgrouplist && cs->runasgrouplist != runasgrouplist) {
		    runasgrouplist = cs->runasgrouplist;
		    TAILQ_FOREACH_SAFE(m, runasgrouplist, entries, m_next) {
			efree(m->name);
			efree(m);
		    }
		    efree(runasgrouplist);
		}
		if (cs->cmnd->type == COMMAND) {
			struct sudo_command *c =
			    (struct sudo_command *) cs->cmnd->name;
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
    TAILQ_INIT(&userspecs);

    binding = NULL;
    TAILQ_FOREACH_SAFE(d, &defaults, entries, d_next) {
	if (d->binding != binding) {
	    struct member *m, *m_next;

	    binding = d->binding;
	    TAILQ_FOREACH_SAFE(m, d->binding, entries, m_next) {
		if (m->type == COMMAND) {
			struct sudo_command *c =
			    (struct sudo_command *) m->name;
			efree(c->cmnd);
			efree(c->args);
		}
		efree(m->name);
		efree(m);
	    }
	    efree(d->binding);
	}
	efree(d->var);
	efree(d->val);
	efree(d);
    }
    TAILQ_INIT(&defaults);

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
#line 906 "gram.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
#if defined(__cplusplus) || defined(__STDC__)
static int yygrowstack(void)
#else
static int yygrowstack()
#endif
{
    unsigned int newsize;
    long sslen;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
#ifdef SIZE_MAX
#define YY_SIZE_MAX SIZE_MAX
#else
#ifdef __STDC__
#define YY_SIZE_MAX 0xffffffffU
#else
#define YY_SIZE_MAX (unsigned int)0xffffffff
#endif
#endif
    if (YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    sslen = yyssp - yyss;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + sslen;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + sslen;
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
#line 182 "gram.y"
{ ; }
break;
case 5:
#line 190 "gram.y"
{
			    ;
			}
break;
case 6:
#line 193 "gram.y"
{
			    yyerrok;
			}
break;
case 7:
#line 196 "gram.y"
{
			    add_userspec(yyvsp[-1].member, yyvsp[0].privilege);
			}
break;
case 8:
#line 199 "gram.y"
{
			    ;
			}
break;
case 9:
#line 202 "gram.y"
{
			    ;
			}
break;
case 10:
#line 205 "gram.y"
{
			    ;
			}
break;
case 11:
#line 208 "gram.y"
{
			    ;
			}
break;
case 12:
#line 211 "gram.y"
{
			    add_defaults(DEFAULTS, NULL, yyvsp[0].defaults);
			}
break;
case 13:
#line 214 "gram.y"
{
			    add_defaults(DEFAULTS_USER, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 14:
#line 217 "gram.y"
{
			    add_defaults(DEFAULTS_RUNAS, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 15:
#line 220 "gram.y"
{
			    add_defaults(DEFAULTS_HOST, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 16:
#line 223 "gram.y"
{
			    add_defaults(DEFAULTS_CMND, yyvsp[-1].member, yyvsp[0].defaults);
			}
break;
case 18:
#line 229 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].defaults, yyvsp[0].defaults, entries);
			    yyval.defaults = yyvsp[-2].defaults;
			}
break;
case 19:
#line 235 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, true);
			}
break;
case 20:
#line 238 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, false);
			}
break;
case 21:
#line 241 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, true);
			}
break;
case 22:
#line 244 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '+');
			}
break;
case 23:
#line 247 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '-');
			}
break;
case 25:
#line 253 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].privilege, yyvsp[0].privilege, entries);
			    yyval.privilege = yyvsp[-2].privilege;
			}
break;
case 26:
#line 259 "gram.y"
{
			    struct privilege *p = ecalloc(1, sizeof(*p));
			    HLTQ_TO_TAILQ(&p->hostlist, yyvsp[-2].member, entries);
			    HLTQ_TO_TAILQ(&p->cmndlist, yyvsp[0].cmndspec, entries);
			    HLTQ_INIT(p, entries);
			    yyval.privilege = p;
			}
break;
case 27:
#line 268 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 28:
#line 272 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 29:
#line 278 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 30:
#line 281 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 31:
#line 284 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			}
break;
case 32:
#line 287 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NTWKADDR);
			}
break;
case 33:
#line 290 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
case 35:
#line 296 "gram.y"
{
			    struct cmndspec *prev;
			    prev = HLTQ_LAST(yyvsp[-2].cmndspec, cmndspec, entries);
			    HLTQ_CONCAT(yyvsp[-2].cmndspec, yyvsp[0].cmndspec, entries);
#ifdef HAVE_SELINUX
			    /* propagate role and type */
			    if (yyvsp[0].cmndspec->role == NULL)
				yyvsp[0].cmndspec->role = prev->role;
			    if (yyvsp[0].cmndspec->type == NULL)
				yyvsp[0].cmndspec->type = prev->type;
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
			    /* propagate privs & limitprivs */
			    if (yyvsp[0].cmndspec->privs == NULL)
			        yyvsp[0].cmndspec->privs = prev->privs;
			    if (yyvsp[0].cmndspec->limitprivs == NULL)
			        yyvsp[0].cmndspec->limitprivs = prev->limitprivs;
#endif /* HAVE_PRIV_SET */
			    /* propagate tags and runas list */
			    if (yyvsp[0].cmndspec->tags.nopasswd == UNSPEC)
				yyvsp[0].cmndspec->tags.nopasswd = prev->tags.nopasswd;
			    if (yyvsp[0].cmndspec->tags.noexec == UNSPEC)
				yyvsp[0].cmndspec->tags.noexec = prev->tags.noexec;
			    if (yyvsp[0].cmndspec->tags.setenv == UNSPEC &&
				prev->tags.setenv != IMPLIED)
				yyvsp[0].cmndspec->tags.setenv = prev->tags.setenv;
			    if (yyvsp[0].cmndspec->tags.log_input == UNSPEC)
				yyvsp[0].cmndspec->tags.log_input = prev->tags.log_input;
			    if (yyvsp[0].cmndspec->tags.log_output == UNSPEC)
				yyvsp[0].cmndspec->tags.log_output = prev->tags.log_output;
			    if ((yyvsp[0].cmndspec->runasuserlist == NULL &&
				 yyvsp[0].cmndspec->runasgrouplist == NULL) &&
				(prev->runasuserlist != NULL ||
				 prev->runasgrouplist != NULL)) {
				yyvsp[0].cmndspec->runasuserlist = prev->runasuserlist;
				yyvsp[0].cmndspec->runasgrouplist = prev->runasgrouplist;
			    }
			    yyval.cmndspec = yyvsp[-2].cmndspec;
			}
break;
case 36:
#line 337 "gram.y"
{
			    struct cmndspec *cs = ecalloc(1, sizeof(*cs));
			    if (yyvsp[-4].runas != NULL) {
				if (yyvsp[-4].runas->runasusers != NULL) {
				    cs->runasuserlist =
					emalloc(sizeof(*cs->runasuserlist));
				    HLTQ_TO_TAILQ(cs->runasuserlist,
					yyvsp[-4].runas->runasusers, entries);
				}
				if (yyvsp[-4].runas->runasgroups != NULL) {
				    cs->runasgrouplist =
					emalloc(sizeof(*cs->runasgrouplist));
				    HLTQ_TO_TAILQ(cs->runasgrouplist,
					yyvsp[-4].runas->runasgroups, entries);
				}
				efree(yyvsp[-4].runas);
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
			    HLTQ_INIT(cs, entries);
			    /* sudo "ALL" implies the SETENV tag */
			    if (cs->cmnd->type == ALL && !cs->cmnd->negated &&
				cs->tags.setenv == UNSPEC)
				cs->tags.setenv = IMPLIED;
			    yyval.cmndspec = cs;
			}
break;
case 37:
#line 373 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA224, yyvsp[0].string);
			}
break;
case 38:
#line 376 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA256, yyvsp[0].string);
			}
break;
case 39:
#line 379 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA384, yyvsp[0].string);
			}
break;
case 40:
#line 382 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA512, yyvsp[0].string);
			}
break;
case 41:
#line 387 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			}
break;
case 42:
#line 390 "gram.y"
{
			    /* XXX - yuck */
			    struct sudo_command *c = (struct sudo_command *)(yyvsp[0].member->name);
			    c->digest = yyvsp[-1].digest;
			    yyval.member = yyvsp[0].member;
			}
break;
case 43:
#line 398 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 44:
#line 402 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 45:
#line 408 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 46:
#line 413 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 47:
#line 418 "gram.y"
{
			    yyval.seinfo.role = NULL;
			    yyval.seinfo.type = NULL;
			}
break;
case 48:
#line 422 "gram.y"
{
			    yyval.seinfo.role = yyvsp[0].string;
			    yyval.seinfo.type = NULL;
			}
break;
case 49:
#line 426 "gram.y"
{
			    yyval.seinfo.type = yyvsp[0].string;
			    yyval.seinfo.role = NULL;
			}
break;
case 50:
#line 430 "gram.y"
{
			    yyval.seinfo.role = yyvsp[-1].string;
			    yyval.seinfo.type = yyvsp[0].string;
			}
break;
case 51:
#line 434 "gram.y"
{
			    yyval.seinfo.type = yyvsp[-1].string;
			    yyval.seinfo.role = yyvsp[0].string;
			}
break;
case 52:
#line 440 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 53:
#line 444 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 54:
#line 449 "gram.y"
{
			    yyval.privinfo.privs = NULL;
			    yyval.privinfo.limitprivs = NULL;
			}
break;
case 55:
#line 453 "gram.y"
{
			    yyval.privinfo.privs = yyvsp[0].string;
			    yyval.privinfo.limitprivs = NULL;
			}
break;
case 56:
#line 457 "gram.y"
{
			    yyval.privinfo.privs = NULL;
			    yyval.privinfo.limitprivs = yyvsp[0].string;
			}
break;
case 57:
#line 461 "gram.y"
{
			    yyval.privinfo.privs = yyvsp[-1].string;
			    yyval.privinfo.limitprivs = yyvsp[0].string;
			}
break;
case 58:
#line 465 "gram.y"
{
			    yyval.privinfo.limitprivs = yyvsp[-1].string;
			    yyval.privinfo.privs = yyvsp[0].string;
			}
break;
case 59:
#line 471 "gram.y"
{
			    yyval.runas = NULL;
			}
break;
case 60:
#line 474 "gram.y"
{
			    yyval.runas = yyvsp[-1].runas;
			}
break;
case 61:
#line 479 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    yyval.runas->runasusers = new_member(NULL, MYSELF);
			    /* $$->runasgroups = NULL; */
			}
break;
case 62:
#line 484 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    yyval.runas->runasusers = yyvsp[0].member;
			    /* $$->runasgroups = NULL; */
			}
break;
case 63:
#line 489 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    yyval.runas->runasusers = yyvsp[-2].member;
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 64:
#line 494 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    /* $$->runasusers = NULL; */
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 65:
#line 499 "gram.y"
{
			    yyval.runas = ecalloc(1, sizeof(struct runascontainer));
			    yyval.runas->runasusers = new_member(NULL, MYSELF);
			    /* $$->runasgroups = NULL; */
			}
break;
case 66:
#line 506 "gram.y"
{
			    yyval.tag.nopasswd = yyval.tag.noexec = yyval.tag.setenv =
				yyval.tag.log_input = yyval.tag.log_output = UNSPEC;
			}
break;
case 67:
#line 510 "gram.y"
{
			    yyval.tag.nopasswd = true;
			}
break;
case 68:
#line 513 "gram.y"
{
			    yyval.tag.nopasswd = false;
			}
break;
case 69:
#line 516 "gram.y"
{
			    yyval.tag.noexec = true;
			}
break;
case 70:
#line 519 "gram.y"
{
			    yyval.tag.noexec = false;
			}
break;
case 71:
#line 522 "gram.y"
{
			    yyval.tag.setenv = true;
			}
break;
case 72:
#line 525 "gram.y"
{
			    yyval.tag.setenv = false;
			}
break;
case 73:
#line 528 "gram.y"
{
			    yyval.tag.log_input = true;
			}
break;
case 74:
#line 531 "gram.y"
{
			    yyval.tag.log_input = false;
			}
break;
case 75:
#line 534 "gram.y"
{
			    yyval.tag.log_output = true;
			}
break;
case 76:
#line 537 "gram.y"
{
			    yyval.tag.log_output = false;
			}
break;
case 77:
#line 542 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 78:
#line 545 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 79:
#line 548 "gram.y"
{
			    struct sudo_command *c = ecalloc(1, sizeof(*c));
			    c->cmnd = yyvsp[0].command.cmnd;
			    c->args = yyvsp[0].command.args;
			    yyval.member = new_member((char *)c, COMMAND);
			}
break;
case 82:
#line 560 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, HOSTALIAS, yyvsp[0].member)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 84:
#line 570 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 87:
#line 580 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, CMNDALIAS, yyvsp[0].member)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 89:
#line 590 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 92:
#line 600 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, RUNASALIAS, yyvsp[0].member)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 95:
#line 613 "gram.y"
{
			    char *s;
			    if ((s = alias_add(yyvsp[-2].string, USERALIAS, yyvsp[0].member)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 97:
#line 623 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 98:
#line 629 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 99:
#line 633 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 100:
#line 639 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 101:
#line 642 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 102:
#line 645 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			}
break;
case 103:
#line 648 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, USERGROUP);
			}
break;
case 104:
#line 651 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
case 106:
#line 657 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 107:
#line 663 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 108:
#line 667 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 109:
#line 673 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			}
break;
case 110:
#line 676 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			}
break;
case 111:
#line 679 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			}
break;
#line 1798 "gram.c"
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
