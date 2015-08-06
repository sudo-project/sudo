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
 * Copyright (c) 1996, 1998-2005, 2007-2013, 2014-2015
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
#include <stdlib.h>
#include <stddef.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
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
static bool add_defaults(int, struct member *, struct defaults *);
static bool add_userspec(struct member *, struct privilege *);
static struct defaults *new_default(char *, char *, int);
static struct member *new_member(char *, int);
static struct sudo_digest *new_digest(int, const char *);
#line 73 "gram.y"
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
#line 127 "gram.c"
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
#define MAIL 280
#define NOMAIL 281
#define FOLLOW 282
#define NOFOLLOW 283
#define ALL 284
#define COMMENT 285
#define HOSTALIAS 286
#define CMNDALIAS 287
#define USERALIAS 288
#define RUNASALIAS 289
#define ERROR 290
#define TYPE 291
#define ROLE 292
#define PRIVS 293
#define LIMITPRIVS 294
#define MYSELF 295
#define SHA224_TOK 296
#define SHA256_TOK 297
#define SHA384_TOK 298
#define SHA512_TOK 299
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
   22,   22,   22,   22,   22,   22,   22,   22,   22,   22,
    5,    5,    5,   33,   33,   36,   10,   10,   34,   34,
   37,    8,    8,   35,   35,   38,   32,   32,   39,   14,
   14,   12,   12,   13,   13,   13,   13,   13,   17,   17,
   15,   15,   16,   16,   16,
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
    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,
    1,    1,    1,    1,    3,    3,    1,    3,    1,    3,
    3,    1,    3,    1,    3,    3,    1,    3,    3,    1,
    3,    1,    2,    1,    1,    1,    1,    1,    1,    3,
    1,    2,    1,    1,    1,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersdefred[] =
#else
short sudoersdefred[] =
#endif
	{                                      0,
    0,  104,  106,  107,  108,    0,    0,    0,    0,    0,
  105,    5,    0,    0,    0,    0,    0,    0,  100,  102,
    0,    0,    3,    6,    0,    0,   17,    0,   29,   32,
   31,   33,   30,    0,   27,    0,   87,    0,    0,   83,
   82,   81,    0,    0,    0,    0,    0,   43,   41,   92,
    0,    0,    0,    0,   84,    0,    0,   89,    0,    0,
   97,    0,    0,   94,  103,    0,    0,   24,    0,    4,
    0,    0,    0,   20,    0,   28,    0,    0,    0,    0,
   44,    0,    0,    0,    0,    0,    0,   42,    0,    0,
    0,    0,    0,    0,    0,    0,  101,    0,    0,   21,
   22,   23,   18,   88,   37,   38,   39,   40,   93,    0,
   85,    0,   90,    0,   98,    0,   95,    0,   34,    0,
    0,   25,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  113,  115,  114,    0,  109,  111,    0,    0,   60,
   35,    0,    0,    0,    0,   66,    0,    0,   50,   51,
  112,    0,    0,   46,   45,    0,    0,    0,   57,   58,
  110,   52,   53,   67,   68,   69,   70,   71,   72,   73,
   74,   75,   76,   79,   80,   77,   78,   36,
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
	{                                    686,
 -272,    0,    0,    0,    0,  -23,  227,  -19,  -19,   -5,
    0,    0, -239, -236, -234, -232, -231,    0,    0,    0,
  -33,  686,    0,    0,   -3, -220,    0,    3,    0,    0,
    0,    0,    0, -225,    0,  -28,    0,  -24,  -24,    0,
    0,    0, -240,  -15,   -8,    2,    8,    0,    0,    0,
  -21,  -12,   -9,   10,    0,    9,   13,    0,   11,   16,
    0,   14,   19,    0,    0,  -19,  -36,    0,   20,    0,
 -208, -187, -183,    0,  -23,    0,  227,    3,    3,    3,
    0, -181, -180, -179, -178,   -5,    3,    0,  227, -239,
   -5, -236,  -19, -234,  -19, -232,    0,   41,  227,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   46,
    0,   47,    0,   48,    0,   48,    0,  -29,    0,   50,
 -230,    0,  289,   -7,   52,   41,   34,   37, -229, -192,
 -191,    0,    0,    0, -217,    0,    0,   56,  289,    0,
    0, -161, -160,   43,   44,    0, -188, -185,    0,    0,
    0,  289,   56,    0,    0, -154, -153,  533,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersrindex[] =
#else
short sudoersrindex[] =
#endif
	{                                    113,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  114,    0,    0,    1,    0,    0,  145,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  159,    0,    0,  193,    0,    0,  207,
    0,    0,  241,    0,    0,    0,    0,    0,  275,    0,
    0,    0,    0,    0,    0,    0,    0,  309,  323,  357,
    0,    0,    0,    0,    0,    0,  371,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  404,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   15,
    0,   49,    0,   63,    0,   97,    0,   74,    0,  111,
  434,    0,   75,   76,    0,  404,    0,    0,  566,  465,
  499,    0,    0,    0,    0,    0,    0,   77,    0,    0,
    0,    0,    0,    0,    0,    0,  597,  630,    0,    0,
    0,    0,   78,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoersgindex[] =
#else
short sudoersgindex[] =
#endif
	{                                      0,
   -4,    0,   45,   18,   80,   72,  -79,   35,   91,   -1,
   51,   61,  112,   -6,  -20,   -2,    4,    0,    0,   32,
    0,    0,    0,    5,    7,    0,  -14,    6,    0,    0,
  116,    0,    0,    0,    0,   57,   54,   39,   55,
};
#define YYTABLESIZE 975
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerstable[] =
#else
short sudoerstable[] =
#endif
	{                                      34,
   19,   38,   39,   17,   26,   36,  109,   77,   26,   26,
   66,   26,   24,   17,   86,   77,   40,   41,   53,   66,
   43,   56,   86,   59,   98,   62,    2,   43,  123,    3,
    4,    5,   29,   19,   30,   31,   66,   32,   74,   72,
  132,   73,   82,   42,   19,  133,   75,   86,   91,   83,
  139,   89,   11,   78,  100,   79,   80,   71,   33,   84,
  127,  128,   99,  144,  145,   85,  134,   90,   87,   91,
   92,   93,   86,   94,   95,  101,   96,   99,  178,  102,
  118,   91,  105,  106,  107,  108,  114,  110,  116,   77,
   86,   66,  140,  126,  142,   99,   96,  143,  127,  152,
  128,  154,  155,  156,  157,  145,   91,  144,  162,  163,
   26,  124,    1,    2,   61,   65,   62,   64,   63,  103,
   99,  141,   81,   88,   76,  112,   97,  104,   65,   96,
  122,  161,  151,  160,  117,  150,  149,   70,    0,    0,
    0,    0,  153,   26,   12,  113,  111,    0,  115,    0,
    0,    0,  159,    0,   96,    0,    0,    0,    9,    0,
    0,    0,    0,    0,    0,    0,    0,    0,   26,    0,
    0,    0,    0,    0,    0,    0,    0,   12,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    9,   10,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    8,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   29,   10,   30,   31,    2,   32,
   25,    3,    4,    5,   25,   25,    0,   25,    2,    8,
   11,    3,    4,    5,   40,   41,    0,    0,    0,    0,
   33,   40,   41,    0,   11,    0,   19,    0,   19,   34,
    0,   19,   19,   19,   11,   19,   19,   19,   19,   19,
   86,   42,   86,   11,    7,   86,   86,   86,   42,   86,
   86,   86,   86,   86,   19,   19,   19,   19,   19,   19,
   44,   45,   46,   47,    0,    0,    0,    0,   86,   86,
   86,   86,   86,   86,   91,    0,   91,    7,   15,   91,
   91,   91,    0,   91,   91,   91,   91,   91,   99,    0,
   99,  135,   13,   99,   99,   99,    0,   99,   99,   99,
   99,   99,   91,   91,   91,   91,   91,   91,    0,    0,
    0,   15,    0,    0,    0,    0,   99,   99,   99,   99,
   99,   99,   96,    0,   96,   13,   14,   96,   96,   96,
    0,   96,   96,   96,   96,   96,   26,    0,   26,    0,
   16,   26,   26,   26,    0,   26,   26,   26,   26,   26,
   96,   96,   96,   96,   96,   96,    0,    0,    0,   14,
    0,    0,    0,    0,   26,   26,   26,   26,   26,   26,
   12,    0,   12,   16,    0,   12,   12,   12,    0,   12,
   12,   12,   12,   12,    9,    0,    9,    0,    0,    9,
    9,    9,    0,    9,    9,    9,    9,    9,   12,   12,
   12,   12,   12,   12,    0,    0,   59,    0,    0,    0,
    0,    0,    9,    9,    9,    9,    9,    9,   10,    0,
   10,    0,    0,   10,   10,   10,    0,   10,   10,   10,
   10,   10,    8,    0,    8,    0,   47,    8,    8,    8,
    0,    8,    8,    8,    8,    8,   10,   10,   10,   10,
   10,   10,    0,    0,   29,    0,   30,   31,    0,   32,
    8,    8,    8,    8,    8,    8,   11,   48,   11,    0,
    0,   11,   11,   11,    0,   11,   11,   11,   11,   11,
   33,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   11,   11,   11,   11,   11,   11,
    7,   49,    7,    0,    0,    7,    7,    7,    0,    7,
    7,    7,    7,    7,    0,    0,  132,    0,    0,    0,
    0,  133,    0,    0,    0,    0,    0,    0,    7,    7,
    7,    7,    7,    7,   15,   43,   15,    0,    0,   15,
   15,   15,  134,   15,   15,   15,   15,   15,   13,    0,
   13,    0,    0,   13,   13,   13,    0,   13,   13,   13,
   13,   13,   15,   15,   15,   15,   15,   15,   54,    0,
    0,    0,    0,    0,    0,    0,   13,   13,   13,   13,
   13,   13,   14,    0,   14,    0,    0,   14,   14,   14,
    0,   14,   14,   14,   14,   14,   16,    0,   16,   55,
    0,   16,   16,   16,    0,   16,   16,   16,   16,   16,
   14,   14,   14,   14,   14,   14,    0,    0,    0,    0,
    0,    0,    0,    0,   16,   16,   16,   16,   16,   16,
   59,   59,   56,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   59,   59,   59,   59,   59,   59,   59,
   59,   59,   59,   59,   59,   59,   59,   59,    0,    0,
   47,   47,    0,    0,   59,   59,   59,   59,    0,   59,
   59,   59,   59,   47,   47,   47,   47,   47,   47,   47,
   47,   47,   47,   47,   47,   47,   47,   47,   17,    0,
    0,   48,   48,    0,    0,    0,   47,   47,    0,   47,
   47,   47,   47,    0,   48,   48,   48,   48,   48,   48,
   48,   48,   48,   48,   48,   48,   48,   48,   48,    0,
    0,    0,    0,    0,    0,   49,   49,   48,   48,    0,
   48,   48,   48,   48,    0,    0,    0,    0,   49,   49,
   49,   49,   49,   49,   49,   49,   49,   49,   49,   49,
   49,   49,   49,    0,    0,    0,    0,    0,    0,   40,
   41,   49,   49,    0,   49,   49,   49,   49,    0,    0,
    0,    0,  164,  165,  166,  167,  168,  169,  170,  171,
  172,  173,  174,  175,  176,  177,   42,    0,    0,    0,
    0,    0,   54,   54,    0,    0,    0,    0,   44,   45,
   46,   47,    0,    0,    0,   54,   54,   54,   54,   54,
   54,   54,   54,   54,   54,   54,   54,   54,   54,   54,
    0,    0,    0,   55,   55,    0,    0,    0,    0,    0,
    0,   54,   54,   54,   54,    0,   55,   55,   55,   55,
   55,   55,   55,   55,   55,   55,   55,   55,   55,   55,
   55,    0,    0,    0,    0,    0,   56,   56,    0,    0,
    0,    0,   55,   55,   55,   55,    0,    0,    0,   56,
   56,   56,   56,   56,   56,   56,   56,   56,   56,   56,
   56,   56,   56,   56,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   56,   56,   56,   56,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    1,    0,    2,    0,    0,    3,    4,    5,    0,
    6,    7,    8,    9,   10,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,   11,
   12,   13,   14,   15,   16,
};
#if defined(__cplusplus) || defined(__STDC__)
const short sudoerscheck[] =
#else
short sudoerscheck[] =
#endif
	{                                      33,
    0,    8,    9,   33,   33,    7,   86,   44,   33,   33,
   44,   33,  285,   33,    0,   44,  257,  258,  258,   44,
   33,  258,   44,  258,   61,  258,  258,   33,   58,  261,
  262,  263,  258,   33,  260,  261,   44,  263,  259,   43,
  258,   45,   58,  284,   44,  263,   44,   33,    0,   58,
   58,   61,  284,   36,  263,   38,   39,   61,  284,   58,
  291,  292,    0,  293,  294,   58,  284,   58,   51,   61,
   58,   61,   58,   58,   61,  263,   58,   58,  158,  263,
   40,   33,  264,  264,  264,  264,   93,   89,   95,   44,
   44,   44,   41,   44,   61,   33,    0,   61,  291,   44,
  292,  263,  263,   61,   61,  294,   58,  293,  263,  263,
    0,  118,    0,    0,   41,   41,   41,   41,   41,   75,
   58,  126,   43,   52,   34,   91,   66,   77,   17,   33,
   99,  152,  135,  148,   96,  131,  130,   22,   -1,   -1,
   -1,   -1,  139,   33,    0,   92,   90,   -1,   94,   -1,
   -1,   -1,  147,   -1,   58,   -1,   -1,   -1,    0,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   58,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   33,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   33,    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  258,   33,  260,  261,  258,  263,
  259,  261,  262,  263,  259,  259,   -1,  259,  258,   33,
    0,  261,  262,  263,  257,  258,   -1,   -1,   -1,   -1,
  284,  257,  258,   -1,  284,   -1,  256,   -1,  258,   33,
   -1,  261,  262,  263,  284,  265,  266,  267,  268,  269,
  256,  284,  258,   33,    0,  261,  262,  263,  284,  265,
  266,  267,  268,  269,  284,  285,  286,  287,  288,  289,
  296,  297,  298,  299,   -1,   -1,   -1,   -1,  284,  285,
  286,  287,  288,  289,  256,   -1,  258,   33,    0,  261,
  262,  263,   -1,  265,  266,  267,  268,  269,  256,   -1,
  258,   33,    0,  261,  262,  263,   -1,  265,  266,  267,
  268,  269,  284,  285,  286,  287,  288,  289,   -1,   -1,
   -1,   33,   -1,   -1,   -1,   -1,  284,  285,  286,  287,
  288,  289,  256,   -1,  258,   33,    0,  261,  262,  263,
   -1,  265,  266,  267,  268,  269,  256,   -1,  258,   -1,
    0,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
  284,  285,  286,  287,  288,  289,   -1,   -1,   -1,   33,
   -1,   -1,   -1,   -1,  284,  285,  286,  287,  288,  289,
  256,   -1,  258,   33,   -1,  261,  262,  263,   -1,  265,
  266,  267,  268,  269,  256,   -1,  258,   -1,   -1,  261,
  262,  263,   -1,  265,  266,  267,  268,  269,  284,  285,
  286,  287,  288,  289,   -1,   -1,   33,   -1,   -1,   -1,
   -1,   -1,  284,  285,  286,  287,  288,  289,  256,   -1,
  258,   -1,   -1,  261,  262,  263,   -1,  265,  266,  267,
  268,  269,  256,   -1,  258,   -1,   33,  261,  262,  263,
   -1,  265,  266,  267,  268,  269,  284,  285,  286,  287,
  288,  289,   -1,   -1,  258,   -1,  260,  261,   -1,  263,
  284,  285,  286,  287,  288,  289,  256,   33,  258,   -1,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
  284,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  284,  285,  286,  287,  288,  289,
  256,   33,  258,   -1,   -1,  261,  262,  263,   -1,  265,
  266,  267,  268,  269,   -1,   -1,  258,   -1,   -1,   -1,
   -1,  263,   -1,   -1,   -1,   -1,   -1,   -1,  284,  285,
  286,  287,  288,  289,  256,   33,  258,   -1,   -1,  261,
  262,  263,  284,  265,  266,  267,  268,  269,  256,   -1,
  258,   -1,   -1,  261,  262,  263,   -1,  265,  266,  267,
  268,  269,  284,  285,  286,  287,  288,  289,   33,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  284,  285,  286,  287,
  288,  289,  256,   -1,  258,   -1,   -1,  261,  262,  263,
   -1,  265,  266,  267,  268,  269,  256,   -1,  258,   33,
   -1,  261,  262,  263,   -1,  265,  266,  267,  268,  269,
  284,  285,  286,  287,  288,  289,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  284,  285,  286,  287,  288,  289,
  257,  258,   33,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  270,  271,  272,  273,  274,  275,  276,
  277,  278,  279,  280,  281,  282,  283,  284,   -1,   -1,
  257,  258,   -1,   -1,  291,  292,  293,  294,   -1,  296,
  297,  298,  299,  270,  271,  272,  273,  274,  275,  276,
  277,  278,  279,  280,  281,  282,  283,  284,   33,   -1,
   -1,  257,  258,   -1,   -1,   -1,  293,  294,   -1,  296,
  297,  298,  299,   -1,  270,  271,  272,  273,  274,  275,
  276,  277,  278,  279,  280,  281,  282,  283,  284,   -1,
   -1,   -1,   -1,   -1,   -1,  257,  258,  293,  294,   -1,
  296,  297,  298,  299,   -1,   -1,   -1,   -1,  270,  271,
  272,  273,  274,  275,  276,  277,  278,  279,  280,  281,
  282,  283,  284,   -1,   -1,   -1,   -1,   -1,   -1,  257,
  258,  293,  294,   -1,  296,  297,  298,  299,   -1,   -1,
   -1,   -1,  270,  271,  272,  273,  274,  275,  276,  277,
  278,  279,  280,  281,  282,  283,  284,   -1,   -1,   -1,
   -1,   -1,  257,  258,   -1,   -1,   -1,   -1,  296,  297,
  298,  299,   -1,   -1,   -1,  270,  271,  272,  273,  274,
  275,  276,  277,  278,  279,  280,  281,  282,  283,  284,
   -1,   -1,   -1,  257,  258,   -1,   -1,   -1,   -1,   -1,
   -1,  296,  297,  298,  299,   -1,  270,  271,  272,  273,
  274,  275,  276,  277,  278,  279,  280,  281,  282,  283,
  284,   -1,   -1,   -1,   -1,   -1,  257,  258,   -1,   -1,
   -1,   -1,  296,  297,  298,  299,   -1,   -1,   -1,  270,
  271,  272,  273,  274,  275,  276,  277,  278,  279,  280,
  281,  282,  283,  284,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,  296,  297,  298,  299,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  256,   -1,  258,   -1,   -1,  261,  262,  263,   -1,
  265,  266,  267,  268,  269,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,  284,
  285,  286,  287,  288,  289,
};
#define YYFINAL 18
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 299
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
"NOLOG_INPUT","LOG_OUTPUT","NOLOG_OUTPUT","MAIL","NOMAIL","FOLLOW","NOFOLLOW",
"ALL","COMMENT","HOSTALIAS","CMNDALIAS","USERALIAS","RUNASALIAS","ERROR","TYPE",
"ROLE","PRIVS","LIMITPRIVS","MYSELF","SHA224_TOK","SHA256_TOK","SHA384_TOK",
"SHA512_TOK",
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
"digest : SHA224_TOK ':' DIGEST",
"digest : SHA256_TOK ':' DIGEST",
"digest : SHA384_TOK ':' DIGEST",
"digest : SHA512_TOK ':' DIGEST",
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
"cmndtag : cmndtag FOLLOW",
"cmndtag : cmndtag NOFOLLOW",
"cmndtag : cmndtag MAIL",
"cmndtag : cmndtag NOMAIL",
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
#line 859 "gram.y"
void
sudoerserror(const char *s)
{
    debug_decl(sudoerserror, SUDOERS_DEBUG_PARSER)

    /* If we last saw a newline the error is on the preceding line. */
    if (last_token == COMMENT)
	sudolineno--;

    /* Save the line the first error occurred on. */
    if (errorlineno == -1) {
	errorlineno = sudolineno;
	errorfile = sudoers;
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
    debug_decl(new_default, SUDOERS_DEBUG_PARSER)

    if ((d = calloc(1, sizeof(struct defaults))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

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
    debug_decl(new_member, SUDOERS_DEBUG_PARSER)

    if ((m = calloc(1, sizeof(struct member))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    m->name = name;
    m->type = type;
    HLTQ_INIT(m, entries);

    debug_return_ptr(m);
}

struct sudo_digest *
new_digest(int digest_type, const char *digest_str)
{
    struct sudo_digest *dig;
    debug_decl(new_digest, SUDOERS_DEBUG_PARSER)

    if ((dig = malloc(sizeof(*dig))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    dig->digest_type = digest_type;
    dig->digest_str = strdup(digest_str);
    if (dig->digest_str == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	free(dig);
	dig = NULL;
    }

    debug_return_ptr(dig);
}

/*
 * Add a list of defaults structures to the defaults list.
 * The binding, if non-NULL, specifies a list of hosts, users, or
 * runas users the entries apply to (specified by the type).
 */
static bool
add_defaults(int type, struct member *bmem, struct defaults *defs)
{
    struct defaults *d;
    struct member_list *binding;
    debug_decl(add_defaults, SUDOERS_DEBUG_PARSER)

    if (defs != NULL) {
	/*
	 * We use a single binding for each entry in defs.
	 */
	if ((binding = malloc(sizeof(*binding))) == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to allocate memory");
	    debug_return_bool(false);
	}
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

    debug_return_bool(true);
}

/*
 * Allocate a new struct userspec, populate it, and insert it at the
 * end of the userspecs list.
 */
static bool
add_userspec(struct member *members, struct privilege *privs)
{
    struct userspec *u;
    debug_decl(add_userspec, SUDOERS_DEBUG_PARSER)

    if ((u = calloc(1, sizeof(*u))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_bool(false);
    }
    HLTQ_TO_TAILQ(&u->users, members, entries);
    HLTQ_TO_TAILQ(&u->privileges, privs, entries);
    TAILQ_INSERT_TAIL(&userspecs, u, entries);

    debug_return_bool(true);
}

/*
 * Free up space used by data structures from a previous parser run and sets
 * the current sudoers file to path.
 */
bool
init_parser(const char *path, bool quiet)
{
    struct member_list *binding;
    struct defaults *d, *d_next;
    struct userspec *us, *us_next;
    bool rval = true;
    debug_decl(init_parser, SUDOERS_DEBUG_PARSER)

    TAILQ_FOREACH_SAFE(us, &userspecs, entries, us_next) {
	struct member *m, *m_next;
	struct privilege *priv, *priv_next;

	TAILQ_FOREACH_SAFE(m, &us->users, entries, m_next) {
	    free(m->name);
	    free(m);
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
		free(m->name);
		free(m);
	    }
	    TAILQ_FOREACH_SAFE(cs, &priv->cmndlist, entries, cs_next) {
#ifdef HAVE_SELINUX
		/* Only free the first instance of a role/type. */
		if (cs->role != role) {
		    role = cs->role;
		    free(cs->role);
		}
		if (cs->type != type) {
		    type = cs->type;
		    free(cs->type);
		}
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
		/* Only free the first instance of privs/limitprivs. */
		if (cs->privs != privs) {
		    privs = cs->privs;
		    free(cs->privs);
		}
		if (cs->limitprivs != limitprivs) {
		    limitprivs = cs->limitprivs;
		    free(cs->limitprivs);
		}
#endif /* HAVE_PRIV_SET */
		/* Only free the first instance of runas user/group lists. */
		if (cs->runasuserlist && cs->runasuserlist != runasuserlist) {
		    runasuserlist = cs->runasuserlist;
		    TAILQ_FOREACH_SAFE(m, runasuserlist, entries, m_next) {
			free(m->name);
			free(m);
		    }
		    free(runasuserlist);
		}
		if (cs->runasgrouplist && cs->runasgrouplist != runasgrouplist) {
		    runasgrouplist = cs->runasgrouplist;
		    TAILQ_FOREACH_SAFE(m, runasgrouplist, entries, m_next) {
			free(m->name);
			free(m);
		    }
		    free(runasgrouplist);
		}
		if (cs->cmnd->type == COMMAND) {
			struct sudo_command *c =
			    (struct sudo_command *) cs->cmnd->name;
			free(c->cmnd);
			free(c->args);
		}
		free(cs->cmnd->name);
		free(cs->cmnd);
		free(cs);
	    }
	    free(priv);
	}
	free(us);
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
			free(c->cmnd);
			free(c->args);
		}
		free(m->name);
		free(m);
	    }
	    free(d->binding);
	}
	free(d->var);
	free(d->val);
	free(d);
    }
    TAILQ_INIT(&defaults);

    init_lexer();

    if (!init_aliases()) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	rval = false;
    }

    free(sudoers);
    if (path != NULL) {
	if ((sudoers = strdup(path)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    rval = false;
	}
    } else {
	sudoers = NULL;
    }

    parse_error = false;
    errorlineno = -1;
    errorfile = sudoers;
    sudoers_warnings = !quiet;

    debug_return_bool(rval);
}
#line 938 "gram.c"
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
#if defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(__GNUC__)
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
#line 167 "gram.y"
{ ; }
break;
case 5:
#line 175 "gram.y"
{
			    ;
			}
break;
case 6:
#line 178 "gram.y"
{
			    yyerrok;
			}
break;
case 7:
#line 181 "gram.y"
{
			    if (!add_userspec(yyvsp[-1].member, yyvsp[0].privilege)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 8:
#line 187 "gram.y"
{
			    ;
			}
break;
case 9:
#line 190 "gram.y"
{
			    ;
			}
break;
case 10:
#line 193 "gram.y"
{
			    ;
			}
break;
case 11:
#line 196 "gram.y"
{
			    ;
			}
break;
case 12:
#line 199 "gram.y"
{
			    if (!add_defaults(DEFAULTS, NULL, yyvsp[0].defaults)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 13:
#line 205 "gram.y"
{
			    if (!add_defaults(DEFAULTS_USER, yyvsp[-1].member, yyvsp[0].defaults)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 14:
#line 211 "gram.y"
{
			    if (!add_defaults(DEFAULTS_RUNAS, yyvsp[-1].member, yyvsp[0].defaults)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 15:
#line 217 "gram.y"
{
			    if (!add_defaults(DEFAULTS_HOST, yyvsp[-1].member, yyvsp[0].defaults)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 16:
#line 223 "gram.y"
{
			    if (!add_defaults(DEFAULTS_CMND, yyvsp[-1].member, yyvsp[0].defaults)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 18:
#line 232 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].defaults, yyvsp[0].defaults, entries);
			    yyval.defaults = yyvsp[-2].defaults;
			}
break;
case 19:
#line 238 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, true);
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 20:
#line 245 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, false);
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 21:
#line 252 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, true);
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 22:
#line 259 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '+');
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 23:
#line 266 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '-');
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 25:
#line 276 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].privilege, yyvsp[0].privilege, entries);
			    yyval.privilege = yyvsp[-2].privilege;
			}
break;
case 26:
#line 282 "gram.y"
{
			    struct privilege *p = calloc(1, sizeof(*p));
			    if (p == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    HLTQ_TO_TAILQ(&p->hostlist, yyvsp[-2].member, entries);
			    HLTQ_TO_TAILQ(&p->cmndlist, yyvsp[0].cmndspec, entries);
			    HLTQ_INIT(p, entries);
			    yyval.privilege = p;
			}
break;
case 27:
#line 295 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 28:
#line 299 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 29:
#line 305 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 30:
#line 312 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 31:
#line 319 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 32:
#line 326 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NTWKADDR);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 33:
#line 333 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 35:
#line 343 "gram.y"
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
			    if (yyvsp[0].cmndspec->tags.send_mail == UNSPEC)
				yyvsp[0].cmndspec->tags.send_mail = prev->tags.send_mail;
			    if (yyvsp[0].cmndspec->tags.follow == UNSPEC)
				yyvsp[0].cmndspec->tags.follow = prev->tags.follow;
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
#line 388 "gram.y"
{
			    struct cmndspec *cs = calloc(1, sizeof(*cs));
			    if (cs == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    if (yyvsp[-4].runas != NULL) {
				if (yyvsp[-4].runas->runasusers != NULL) {
				    cs->runasuserlist =
					malloc(sizeof(*cs->runasuserlist));
				    if (cs->runasuserlist == NULL) {
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasuserlist,
					yyvsp[-4].runas->runasusers, entries);
				}
				if (yyvsp[-4].runas->runasgroups != NULL) {
				    cs->runasgrouplist =
					malloc(sizeof(*cs->runasgrouplist));
				    if (cs->runasgrouplist == NULL) {
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasgrouplist,
					yyvsp[-4].runas->runasgroups, entries);
				}
				free(yyvsp[-4].runas);
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
#line 436 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA224, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 38:
#line 443 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA256, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 39:
#line 450 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA384, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 40:
#line 457 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA512, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 41:
#line 466 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			}
break;
case 42:
#line 469 "gram.y"
{
			    if (yyvsp[0].member->type != COMMAND) {
				sudoerserror(N_("a digest requires a path name"));
				YYERROR;
			    }
			    /* XXX - yuck */
			    ((struct sudo_command *) yyvsp[0].member->name)->digest = yyvsp[-1].digest;
			    yyval.member = yyvsp[0].member;
			}
break;
case 43:
#line 480 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 44:
#line 484 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 45:
#line 490 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 46:
#line 495 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 47:
#line 500 "gram.y"
{
			    yyval.seinfo.role = NULL;
			    yyval.seinfo.type = NULL;
			}
break;
case 48:
#line 504 "gram.y"
{
			    yyval.seinfo.role = yyvsp[0].string;
			    yyval.seinfo.type = NULL;
			}
break;
case 49:
#line 508 "gram.y"
{
			    yyval.seinfo.type = yyvsp[0].string;
			    yyval.seinfo.role = NULL;
			}
break;
case 50:
#line 512 "gram.y"
{
			    yyval.seinfo.role = yyvsp[-1].string;
			    yyval.seinfo.type = yyvsp[0].string;
			}
break;
case 51:
#line 516 "gram.y"
{
			    yyval.seinfo.type = yyvsp[-1].string;
			    yyval.seinfo.role = yyvsp[0].string;
			}
break;
case 52:
#line 522 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 53:
#line 526 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 54:
#line 531 "gram.y"
{
			    yyval.privinfo.privs = NULL;
			    yyval.privinfo.limitprivs = NULL;
			}
break;
case 55:
#line 535 "gram.y"
{
			    yyval.privinfo.privs = yyvsp[0].string;
			    yyval.privinfo.limitprivs = NULL;
			}
break;
case 56:
#line 539 "gram.y"
{
			    yyval.privinfo.privs = NULL;
			    yyval.privinfo.limitprivs = yyvsp[0].string;
			}
break;
case 57:
#line 543 "gram.y"
{
			    yyval.privinfo.privs = yyvsp[-1].string;
			    yyval.privinfo.limitprivs = yyvsp[0].string;
			}
break;
case 58:
#line 547 "gram.y"
{
			    yyval.privinfo.limitprivs = yyvsp[-1].string;
			    yyval.privinfo.privs = yyvsp[0].string;
			}
break;
case 59:
#line 553 "gram.y"
{
			    yyval.runas = NULL;
			}
break;
case 60:
#line 556 "gram.y"
{
			    yyval.runas = yyvsp[-1].runas;
			}
break;
case 61:
#line 561 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas != NULL) {
				yyval.runas->runasusers = new_member(NULL, MYSELF);
				/* $$->runasgroups = NULL; */
				if (yyval.runas->runasusers == NULL) {
				    free(yyval.runas);
				    yyval.runas = NULL;
				}
			    }
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 62:
#line 576 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    yyval.runas->runasusers = yyvsp[0].member;
			    /* $$->runasgroups = NULL; */
			}
break;
case 63:
#line 585 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    yyval.runas->runasusers = yyvsp[-2].member;
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 64:
#line 594 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    /* $$->runasusers = NULL; */
			    yyval.runas->runasgroups = yyvsp[0].member;
			}
break;
case 65:
#line 603 "gram.y"
{
			    yyval.runas = calloc(1, sizeof(struct runascontainer));
			    if (yyval.runas != NULL) {
				yyval.runas->runasusers = new_member(NULL, MYSELF);
				/* $$->runasgroups = NULL; */
				if (yyval.runas->runasusers == NULL) {
				    free(yyval.runas);
				    yyval.runas = NULL;
				}
			    }
			    if (yyval.runas == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 66:
#line 620 "gram.y"
{
			    TAGS_INIT(yyval.tag);
			}
break;
case 67:
#line 623 "gram.y"
{
			    yyval.tag.nopasswd = true;
			}
break;
case 68:
#line 626 "gram.y"
{
			    yyval.tag.nopasswd = false;
			}
break;
case 69:
#line 629 "gram.y"
{
			    yyval.tag.noexec = true;
			}
break;
case 70:
#line 632 "gram.y"
{
			    yyval.tag.noexec = false;
			}
break;
case 71:
#line 635 "gram.y"
{
			    yyval.tag.setenv = true;
			}
break;
case 72:
#line 638 "gram.y"
{
			    yyval.tag.setenv = false;
			}
break;
case 73:
#line 641 "gram.y"
{
			    yyval.tag.log_input = true;
			}
break;
case 74:
#line 644 "gram.y"
{
			    yyval.tag.log_input = false;
			}
break;
case 75:
#line 647 "gram.y"
{
			    yyval.tag.log_output = true;
			}
break;
case 76:
#line 650 "gram.y"
{
			    yyval.tag.log_output = false;
			}
break;
case 77:
#line 653 "gram.y"
{
			    yyval.tag.follow = true;
			}
break;
case 78:
#line 656 "gram.y"
{
			    yyval.tag.follow = false;
			}
break;
case 79:
#line 659 "gram.y"
{
			    yyval.tag.send_mail = true;
			}
break;
case 80:
#line 662 "gram.y"
{
			    yyval.tag.send_mail = false;
			}
break;
case 81:
#line 667 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 82:
#line 674 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 83:
#line 681 "gram.y"
{
			    struct sudo_command *c = calloc(1, sizeof(*c));
			    if (c == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    c->cmnd = yyvsp[0].command.cmnd;
			    c->args = yyvsp[0].command.args;
			    yyval.member = new_member((char *)c, COMMAND);
			    if (yyval.member == NULL) {
				free(c);
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 86:
#line 702 "gram.y"
{
			    const char *s;
			    if ((s = alias_add(yyvsp[-2].string, HOSTALIAS, yyvsp[0].member)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 88:
#line 712 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 91:
#line 722 "gram.y"
{
			    const char *s;
			    if ((s = alias_add(yyvsp[-2].string, CMNDALIAS, yyvsp[0].member)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 93:
#line 732 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 96:
#line 742 "gram.y"
{
			    const char *s;
			    if ((s = alias_add(yyvsp[-2].string, RUNASALIAS, yyvsp[0].member)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 99:
#line 755 "gram.y"
{
			    const char *s;
			    if ((s = alias_add(yyvsp[-2].string, USERALIAS, yyvsp[0].member)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 101:
#line 765 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 102:
#line 771 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 103:
#line 775 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 104:
#line 781 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 105:
#line 788 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 106:
#line 795 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 107:
#line 802 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, USERGROUP);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 108:
#line 809 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 110:
#line 819 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 111:
#line 825 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 112:
#line 829 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 113:
#line 835 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 114:
#line 842 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 115:
#line 849 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
#line 2031 "gram.c"
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
