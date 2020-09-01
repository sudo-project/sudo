/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

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
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1996, 1998-2005, 2007-2013, 2014-2020
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#if defined(YYBISON) && defined(HAVE_ALLOCA_H) && !defined(__GNUC__)
# include <alloca.h>
#endif /* YYBISON && HAVE_ALLOCA_H && !__GNUC__ */
#include <errno.h>

#include "sudoers.h"
#include "sudo_digest.h"
#include "toke.h"

#ifdef YYBISON
# define YYERROR_VERBOSE
#endif

/* If we last saw a newline the entry is on the preceding line. */
#define this_lineno	(last_token == '\n' ? sudolineno - 1 : sudolineno)

/*
 * Globals
 */
bool sudoers_warnings = true;
bool sudoers_strict = false;
bool parse_error = false;
int errorlineno = -1;
char *errorfile = NULL;

struct sudoers_parse_tree parsed_policy = {
    TAILQ_HEAD_INITIALIZER(parsed_policy.userspecs),
    TAILQ_HEAD_INITIALIZER(parsed_policy.defaults),
    NULL, /* aliases */
    NULL, /* lhost */
    NULL /* shost */
};

/*
 * Local prototypes
 */
static void init_options(struct command_options *opts);
static bool add_defaults(int, struct member *, struct defaults *);
static bool add_userspec(struct member *, struct privilege *);
static struct defaults *new_default(char *, char *, short);
static struct member *new_member(char *, int);
static struct sudo_command *new_command(char *, char *);
static struct command_digest *new_digest(int, char *);
#line 77 "gram.y"
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
    struct cmndspec *cmndspec;
    struct defaults *defaults;
    struct member *member;
    struct runascontainer *runas;
    struct privilege *privilege;
    struct command_digest *digest;
    struct sudo_command command;
    struct command_options options;
    struct cmndtag tag;
    char *string;
    int tok;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
#line 130 "gram.c"
#define END 0
#define COMMAND 257
#define ALIAS 258
#define DEFVAR 259
#define NTWKADDR 260
#define NETGROUP 261
#define USERGROUP 262
#define WORD 263
#define DIGEST 264
#define INCLUDE 265
#define INCLUDEDIR 266
#define DEFAULTS 267
#define DEFAULTS_HOST 268
#define DEFAULTS_USER 269
#define DEFAULTS_RUNAS 270
#define DEFAULTS_CMND 271
#define NOPASSWD 272
#define PASSWD 273
#define NOEXEC 274
#define EXEC 275
#define SETENV 276
#define NOSETENV 277
#define LOG_INPUT 278
#define NOLOG_INPUT 279
#define LOG_OUTPUT 280
#define NOLOG_OUTPUT 281
#define MAIL 282
#define NOMAIL 283
#define FOLLOWLNK 284
#define NOFOLLOWLNK 285
#define ALL 286
#define HOSTALIAS 287
#define CMNDALIAS 288
#define USERALIAS 289
#define RUNASALIAS 290
#define ERROR 291
#define NOMATCH 292
#define CHROOT 293
#define CWD 294
#define TYPE 295
#define ROLE 296
#define PRIVS 297
#define LIMITPRIVS 298
#define CMND_TIMEOUT 299
#define NOTBEFORE 300
#define NOTAFTER 301
#define MYSELF 302
#define SHA224_TOK 303
#define SHA256_TOK 304
#define SHA384_TOK 305
#define SHA512_TOK 306
#define YYERRCODE 256
const short sudoerslhs[] =
	{                                        -1,
    0,    0,   37,   37,   38,   38,   38,   38,   38,   38,
   38,   38,   38,   38,   38,   38,   38,   38,   33,   33,
   34,   34,    4,    4,    3,    3,    3,    3,    3,   21,
   21,   21,   20,   11,   11,    9,    9,    9,    9,    9,
    2,    2,    1,   35,   35,   35,   35,   36,   36,    7,
    7,    6,    6,   24,   25,   30,   31,   32,   26,   27,
   28,   29,   18,   18,   19,   19,   19,   19,   19,   23,
   23,   23,   23,   23,   23,   23,   23,   23,   23,   22,
   22,   22,   22,   22,   22,   22,   22,   22,   22,   22,
   22,   22,   22,   22,    5,    5,    5,   41,   41,   44,
   10,   10,   42,   42,   45,    8,    8,   43,   43,   46,
   40,   40,   47,   14,   14,   12,   12,   13,   13,   13,
   13,   13,   17,   17,   15,   15,   16,   16,   16,   39,
   39,
};
const short sudoerslen[] =
	{                                         2,
    0,    1,    1,    2,    1,    2,    1,    1,    3,    3,
    3,    3,    3,    3,    4,    4,    4,    4,    3,    4,
    3,    4,    1,    3,    1,    2,    3,    3,    3,    1,
    3,    4,    3,    1,    2,    1,    1,    1,    1,    1,
    1,    3,    4,    3,    3,    3,    3,    1,    3,    1,
    2,    1,    2,    3,    3,    3,    3,    3,    3,    3,
    3,    3,    0,    3,    0,    1,    3,    2,    1,    0,
    2,    2,    2,    2,    2,    2,    2,    2,    2,    0,
    2,    2,    2,    2,    2,    2,    2,    2,    2,    2,
    2,    2,    2,    2,    1,    1,    1,    1,    3,    3,
    1,    3,    1,    3,    3,    1,    3,    1,    3,    3,
    1,    3,    3,    1,    3,    1,    2,    1,    1,    1,
    1,    1,    1,    3,    1,    2,    1,    1,    1,    1,
    1,
};
const short sudoersdefred[] =
	{                                      0,
    0,  118,  120,  121,  122,    0,    0,    0,    0,    0,
    0,    0,  119,    0,    0,    0,    0,    0,    5,    0,
  114,  116,    0,    7,    8,    0,    3,  131,  130,    6,
    0,    0,    0,    0,   23,    0,   36,   39,   38,   40,
   37,    0,   34,    0,  101,    0,    0,   97,   96,   95,
    0,    0,    0,    0,    0,   52,   50,  106,    0,   48,
    0,    0,    0,   98,    0,    0,  103,    0,    0,  111,
    0,    0,  108,  117,    0,    0,   30,    0,    4,    0,
   19,    0,   21,    0,    0,    0,   26,    0,   14,   35,
    0,    0,    0,    0,   53,    0,    0,    0,    0,    0,
    0,    0,   51,    0,    0,   11,    0,    0,   12,    0,
    0,   10,    0,    0,   13,  115,    0,    0,    9,   20,
   22,   27,   28,   29,   24,  102,   17,   15,   16,   44,
   45,   46,   47,  107,   18,   49,    0,   99,    0,  104,
    0,  112,    0,  109,    0,   41,    0,   70,    0,   31,
    0,    0,    0,    0,    0,   32,  127,  129,  128,    0,
  123,  125,    0,    0,   64,   42,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   71,   72,   76,   77,
   78,   79,   75,   73,   74,  126,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   81,   82,   83,
   84,   85,   86,   87,   88,   89,   90,   93,   94,   91,
   92,   43,  124,   55,   54,   60,   59,   61,   62,   56,
   57,   58,
};
const short sudoersdgoto[] =
	{                                      20,
  146,  147,   35,   36,   56,   57,   58,   59,   43,   76,
   45,   21,   22,   23,  161,  162,  163,  148,  153,   77,
   78,  176,  155,  177,  178,  179,  180,  181,  182,  183,
  184,  185,   24,   25,   60,   61,   26,   27,   30,   69,
   63,   66,   72,   64,   67,   73,   70,
};
const short sudoerssindex[] =
	{                                    -10,
   48,    0,    0,    0,    0, -245, -233,  -29,   38,   95,
   95,  -32,    0, -205, -197, -195, -191, -144,    0,    0,
    0,    0,  -22,    0,    0,  -10,    0,    0,    0,    0,
    6,    7,   32, -189,    0,   50,    0,    0,    0,    0,
    0, -138,    0,  -31,    0,  -30,  -30,    0,    0,    0,
 -220,   15,   22,   27,   43,    0,    0,    0,  -25,    0,
   69,   35,   21,    0,   49,   24,    0,   55,   25,    0,
   60,   26,    0,    0,   95,    8,    0,   29,    0,   48,
    0,   48,    0, -157, -156, -155,    0,  -29,    0,    0,
   38,   50,   50,   50,    0, -153, -140, -135, -134,  -32,
   50, -168,    0,   38, -205,    0,  -32, -197,    0,   95,
 -195,    0,   95, -191,    0,    0,   86,   62,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   88,    0,   96,    0,
   97,    0,   97,    0,  -18,    0,   99,    0,   48,    0,
  -21,   42,   98,   86, -143,    0,    0,    0,    0, -214,
    0,    0,  103,  -21,    0,    0,  100,  101,  102,  104,
  105,  106,  107,  108,  109,   59,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  -21,  103, -114, -104,
 -103,  -99,  -92,  -91,  -90,  -89,  -88,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,};
const short sudoersrindex[] =
	{                                    176,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  177,    0,    0,    0,    0,
    0,    0,   54,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    9,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   33,    0,   41,    0,
   45,    0,   46,    0,  137,    0,   47,    0,    0,    0,
  138,  139,    0,    9,   94,    0,    0,    0,    0,    0,
    0,    0,  140,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  141,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,};
const short sudoersgindex[] =
	{                                      0,
   30,    0,  110,   87,  132,  124,  -95,   79,  145,   11,
  111,  113,  171,   -1,    3,   31,   28,    0,    0,   75,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   92,    0,    0,  169,   -4,    0,
    0,    0,    0,   91,   89,   85,   90,
};
#define YYTABLESIZE 400
const short sudoerstable[] =
	{                                      19,
   51,   34,   34,   34,  134,   28,   28,   34,   46,   47,
   42,  160,   91,   75,   18,   29,   29,   31,  100,   44,
   28,   75,   18,   28,   28,   28,   81,   83,   28,   32,
   29,   89,  100,   29,   29,   29,   48,   49,   29,  151,
  105,   63,  100,  157,  113,  110,   33,   28,  158,   28,
  105,   91,   62,   25,  113,  110,   33,   29,  106,   29,
   65,  109,   68,   25,  112,   50,   71,  115,  117,   87,
   42,  159,   96,  119,   85,  120,   86,  121,  105,   97,
  212,  108,  111,  114,   98,   75,  118,  127,  128,  129,
  100,   51,   84,   88,   42,  104,  135,   25,  105,  164,
   99,   51,  113,  110,   33,  122,  123,  124,  141,  107,
  130,  143,  102,    2,  137,  110,    3,    4,    5,   37,
  113,   38,   39,  131,   40,  145,   80,   18,  132,  133,
   92,   91,   93,   94,   52,   53,   54,   55,  165,  100,
   75,   13,  154,  152,  156,  101,  187,   41,  214,  167,
  168,  169,  170,  171,  172,  173,  174,  175,  215,  216,
  189,  190,  191,  217,  192,  193,  194,  195,  196,  197,
  218,  219,  220,  221,  222,    1,    2,   65,   69,   66,
   68,   67,   95,  166,  103,  139,   90,  116,   74,  213,
  186,  188,  150,  136,   79,  138,  140,  125,  144,    0,
  142,  126,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   48,   49,    0,   33,   33,   33,
    0,    0,    0,   33,    0,   37,  157,   38,   39,    2,
   40,  158,    3,    4,    5,    1,    0,    2,    0,    0,
    3,    4,    5,   50,    6,    7,    8,    9,   10,   11,
   12,   80,   82,   41,  159,   63,   63,   13,    0,    0,
   52,   53,   54,   55,    0,   13,   14,   15,   16,   17,
   63,   63,   63,   63,   63,   63,   63,   63,   63,   63,
   63,   63,   63,   63,   63,   37,    0,   38,   39,    0,
   40,   63,   63,   63,   63,   63,   63,   63,   63,   63,
    0,   63,   63,   63,   63,   48,   49,  149,    0,   37,
    0,   38,   39,   41,   40,   48,   49,    0,    0,    0,
  198,  199,  200,  201,  202,  203,  204,  205,  206,  207,
  208,  209,  210,  211,   50,    0,    0,   41,    0,    0,
   80,   80,    2,    0,   50,    3,    4,    5,    0,    0,
    0,   52,   53,   54,   55,   80,   80,   80,   80,   80,
   80,   80,   80,   80,   80,   80,   80,   80,   80,   80,
   13,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   80,   80,   80,   80,
};
const short sudoerscheck[] =
	{                                      10,
   33,   33,   33,   33,  100,    0,    0,   33,   10,   11,
   33,   33,   44,   44,   33,   10,   10,  263,   44,    9,
    0,   44,   33,    0,    0,    0,   31,   32,    0,  263,
   10,   36,    0,   10,   10,   10,  257,  258,   10,   58,
    0,   33,   10,  258,    0,    0,    0,    0,  263,    0,
   10,   44,  258,    0,   10,   10,   10,   10,   63,   10,
  258,   66,  258,   10,   69,  286,  258,   72,   61,  259,
   33,  286,   58,   78,   43,   80,   45,   82,   58,   58,
  176,   58,   58,   58,   58,   44,   58,   92,   93,   94,
   58,   33,   61,   44,   33,   61,  101,   44,   58,   58,
   58,   33,   58,   58,   58,  263,  263,  263,  110,   61,
  264,  113,   44,  258,  104,   61,  261,  262,  263,  258,
   61,  260,  261,  264,  263,   40,   33,   33,  264,  264,
   44,   44,   46,   47,  303,  304,  305,  306,   41,   44,
   44,  286,   44,  145,  149,   59,   44,  286,  263,  293,
  294,  295,  296,  297,  298,  299,  300,  301,  263,  263,
   61,   61,   61,  263,   61,   61,   61,   61,   61,   61,
  263,  263,  263,  263,  263,    0,    0,   41,   41,   41,
   41,   41,   51,  154,   61,  107,   42,   75,   18,  187,
  160,  164,  118,  102,   26,  105,  108,   88,  114,   -1,
  111,   91,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  257,  258,   -1,  259,  259,  259,
   -1,   -1,   -1,  259,   -1,  258,  258,  260,  261,  258,
  263,  263,  261,  262,  263,  256,   -1,  258,   -1,   -1,
  261,  262,  263,  286,  265,  266,  267,  268,  269,  270,
  271,  256,  256,  286,  286,  257,  258,  286,   -1,   -1,
  303,  304,  305,  306,   -1,  286,  287,  288,  289,  290,
  272,  273,  274,  275,  276,  277,  278,  279,  280,  281,
  282,  283,  284,  285,  286,  258,   -1,  260,  261,   -1,
  263,  293,  294,  295,  296,  297,  298,  299,  300,  301,
   -1,  303,  304,  305,  306,  257,  258,  256,   -1,  258,
   -1,  260,  261,  286,  263,  257,  258,   -1,   -1,   -1,
  272,  273,  274,  275,  276,  277,  278,  279,  280,  281,
  282,  283,  284,  285,  286,   -1,   -1,  286,   -1,   -1,
  257,  258,  258,   -1,  286,  261,  262,  263,   -1,   -1,
   -1,  303,  304,  305,  306,  272,  273,  274,  275,  276,
  277,  278,  279,  280,  281,  282,  283,  284,  285,  286,
  286,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  303,  304,  305,  306,
};
#define YYFINAL 20
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 306
#if YYDEBUG
const char * const sudoersname[] =
	{
"end-of-file",0,0,0,0,0,0,0,0,0,"'\\n'",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,"'!'",0,0,0,0,0,0,"'('","')'",0,"'+'","','","'-'",0,0,0,0,0,0,0,0,0,0,0,0,
"':'",0,0,"'='",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,"COMMAND","ALIAS","DEFVAR","NTWKADDR","NETGROUP","USERGROUP","WORD",
"DIGEST","INCLUDE","INCLUDEDIR","DEFAULTS","DEFAULTS_HOST","DEFAULTS_USER",
"DEFAULTS_RUNAS","DEFAULTS_CMND","NOPASSWD","PASSWD","NOEXEC","EXEC","SETENV",
"NOSETENV","LOG_INPUT","NOLOG_INPUT","LOG_OUTPUT","NOLOG_OUTPUT","MAIL",
"NOMAIL","FOLLOWLNK","NOFOLLOWLNK","ALL","HOSTALIAS","CMNDALIAS","USERALIAS",
"RUNASALIAS","ERROR","NOMATCH","CHROOT","CWD","TYPE","ROLE","PRIVS",
"LIMITPRIVS","CMND_TIMEOUT","NOTBEFORE","NOTAFTER","MYSELF","SHA224_TOK",
"SHA256_TOK","SHA384_TOK","SHA512_TOK",
};
const char * const sudoersrule[] =
	{"$accept : file",
"file :",
"file : line",
"line : entry",
"line : line entry",
"entry : '\\n'",
"entry : error eol",
"entry : include",
"entry : includedir",
"entry : userlist privileges eol",
"entry : USERALIAS useraliases eol",
"entry : HOSTALIAS hostaliases eol",
"entry : CMNDALIAS cmndaliases eol",
"entry : RUNASALIAS runasaliases eol",
"entry : DEFAULTS defaults_list eol",
"entry : DEFAULTS_USER userlist defaults_list eol",
"entry : DEFAULTS_RUNAS userlist defaults_list eol",
"entry : DEFAULTS_HOST hostlist defaults_list eol",
"entry : DEFAULTS_CMND cmndlist defaults_list eol",
"include : INCLUDE WORD eol",
"include : INCLUDE WORD error eol",
"includedir : INCLUDEDIR WORD eol",
"includedir : INCLUDEDIR WORD error eol",
"defaults_list : defaults_entry",
"defaults_list : defaults_list ',' defaults_entry",
"defaults_entry : DEFVAR",
"defaults_entry : '!' DEFVAR",
"defaults_entry : DEFVAR '=' WORD",
"defaults_entry : DEFVAR '+' WORD",
"defaults_entry : DEFVAR '-' WORD",
"privileges : privilege",
"privileges : privileges ':' privilege",
"privileges : privileges ':' error eol",
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
"cmndspec : runasspec options cmndtag digcmnd",
"digestspec : SHA224_TOK ':' DIGEST",
"digestspec : SHA256_TOK ':' DIGEST",
"digestspec : SHA384_TOK ':' DIGEST",
"digestspec : SHA512_TOK ':' DIGEST",
"digestlist : digestspec",
"digestlist : digestlist ',' digestspec",
"digcmnd : opcmnd",
"digcmnd : digestlist opcmnd",
"opcmnd : cmnd",
"opcmnd : '!' cmnd",
"chdirspec : CWD '=' WORD",
"chrootspec : CHROOT '=' WORD",
"timeoutspec : CMND_TIMEOUT '=' WORD",
"notbeforespec : NOTBEFORE '=' WORD",
"notafterspec : NOTAFTER '=' WORD",
"rolespec : ROLE '=' WORD",
"typespec : TYPE '=' WORD",
"privsspec : PRIVS '=' WORD",
"limitprivsspec : LIMITPRIVS '=' WORD",
"runasspec :",
"runasspec : '(' runaslist ')'",
"runaslist :",
"runaslist : userlist",
"runaslist : userlist ':' grouplist",
"runaslist : ':' grouplist",
"runaslist : ':'",
"options :",
"options : options chdirspec",
"options : options chrootspec",
"options : options notbeforespec",
"options : options notafterspec",
"options : options timeoutspec",
"options : options rolespec",
"options : options typespec",
"options : options privsspec",
"options : options limitprivsspec",
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
"cmndtag : cmndtag FOLLOWLNK",
"cmndtag : cmndtag NOFOLLOWLNK",
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
"eol : '\\n'",
"eol : END",
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
int yyparse(void);
#line 1018 "gram.y"
void
sudoerserror(const char *s)
{
    debug_decl(sudoerserror, SUDOERS_DEBUG_PARSER);

    /* The lexer displays more detailed messages for ERROR tokens. */
    if (last_token == ERROR)
	debug_return;

    /* Save the line the first error occurred on. */
    if (errorlineno == -1) {
	errorlineno = this_lineno;
	rcstr_delref(errorfile);
	errorfile = rcstr_addref(sudoers);
    }
    if (sudoers_warnings && s != NULL) {
	LEXTRACE("<*> ");
#ifndef TRACELEXER
	if (trace_print == NULL || trace_print == sudoers_trace_print) {
	    int oldlocale;

	    /* Warnings are displayed in the user's locale. */
	    sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("%s:%d: %s\n"), sudoers,
		this_lineno, _(s));
	    sudoers_setlocale(oldlocale, NULL);

	    /* Display the offending line and token if possible. */
	    if (sudolinebuf.len != 0) {
		char tildes[128];
		size_t tlen = 0;

		sudo_printf(SUDO_CONV_ERROR_MSG, "%s%s", sudolinebuf.buf,
		    sudolinebuf.buf[sudolinebuf.len - 1] == '\n' ? "" : "\n");
		if (sudolinebuf.toke_end > sudolinebuf.toke_start) {
		    tlen = sudolinebuf.toke_end - sudolinebuf.toke_start - 1;
		    if (tlen >= sizeof(tildes))
			tlen = sizeof(tildes) - 1;
		    memset(tildes, '~', tlen);
		}
		tildes[tlen] = '\0';
		sudo_printf(SUDO_CONV_ERROR_MSG, "%*s^%s\n",
		    (int)sudolinebuf.toke_start, "", tildes);
	    }
	}
#endif
    }
    parse_error = true;
    debug_return;
}

static struct defaults *
new_default(char *var, char *val, short op)
{
    struct defaults *d;
    debug_decl(new_default, SUDOERS_DEBUG_PARSER);

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
    d->lineno = this_lineno;
    d->file = rcstr_addref(sudoers);
    HLTQ_INIT(d, entries);

    debug_return_ptr(d);
}

static struct member *
new_member(char *name, int type)
{
    struct member *m;
    debug_decl(new_member, SUDOERS_DEBUG_PARSER);

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

static struct sudo_command *
new_command(char *cmnd, char *args)
{
    struct sudo_command *c;
    debug_decl(new_command, SUDOERS_DEBUG_PARSER);

    if ((c = calloc(1, sizeof(*c))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    c->cmnd = cmnd;
    c->args = args;
    TAILQ_INIT(&c->digests);

    debug_return_ptr(c);
}

static struct command_digest *
new_digest(int digest_type, char *digest_str)
{
    struct command_digest *digest;
    debug_decl(new_digest, SUDOERS_DEBUG_PARSER);

    if ((digest = malloc(sizeof(*digest))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    HLTQ_INIT(digest, entries);
    digest->digest_type = digest_type;
    digest->digest_str = digest_str;
    if (digest->digest_str == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	free(digest);
	digest = NULL;
    }

    debug_return_ptr(digest);
}

/*
 * Add a list of defaults structures to the defaults list.
 * The binding, if non-NULL, specifies a list of hosts, users, or
 * runas users the entries apply to (specified by the type).
 */
static bool
add_defaults(int type, struct member *bmem, struct defaults *defs)
{
    struct defaults *d, *next;
    struct member_list *binding;
    bool ret = true;
    debug_decl(add_defaults, SUDOERS_DEBUG_PARSER);

    if (defs != NULL) {
	/*
	 * We use a single binding for each entry in defs.
	 */
	if ((binding = malloc(sizeof(*binding))) == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to allocate memory");
	    sudoerserror(N_("unable to allocate memory"));
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
	HLTQ_FOREACH_SAFE(d, defs, entries, next) {
	    d->type = type;
	    d->binding = binding;
	    TAILQ_INSERT_TAIL(&parsed_policy.defaults, d, entries);
	}
    }

    debug_return_bool(ret);
}

/*
 * Allocate a new struct userspec, populate it, and insert it at the
 * end of the userspecs list.
 */
static bool
add_userspec(struct member *members, struct privilege *privs)
{
    struct userspec *u;
    debug_decl(add_userspec, SUDOERS_DEBUG_PARSER);

    if ((u = calloc(1, sizeof(*u))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_bool(false);
    }
    u->lineno = this_lineno;
    u->file = rcstr_addref(sudoers);
    HLTQ_TO_TAILQ(&u->users, members, entries);
    HLTQ_TO_TAILQ(&u->privileges, privs, entries);
    STAILQ_INIT(&u->comments);
    TAILQ_INSERT_TAIL(&parsed_policy.userspecs, u, entries);

    debug_return_bool(true);
}

/*
 * Free a member struct and its contents.
 */
void
free_member(struct member *m)
{
    debug_decl(free_member, SUDOERS_DEBUG_PARSER);

    if (m->type == COMMAND || (m->type == ALL && m->name != NULL)) {
	struct command_digest *digest;
	struct sudo_command *c = (struct sudo_command *)m->name;
	free(c->cmnd);
	free(c->args);
	while ((digest = TAILQ_FIRST(&c->digests)) != NULL) {
	    TAILQ_REMOVE(&c->digests, digest, entries);
	    free(digest->digest_str);
	    free(digest);
	}
    }
    free(m->name);
    free(m);

    debug_return;
}

/*
 * Free a tailq of members but not the struct member_list container itself.
 */
void
free_members(struct member_list *members)
{
    struct member *m;
    debug_decl(free_members, SUDOERS_DEBUG_PARSER);

    while ((m = TAILQ_FIRST(members)) != NULL) {
	TAILQ_REMOVE(members, m, entries);
	free_member(m);
    }

    debug_return;
}

void
free_defaults(struct defaults_list *defs)
{
    struct member_list *prev_binding = NULL;
    struct defaults *def;
    debug_decl(free_defaults, SUDOERS_DEBUG_PARSER);

    while ((def = TAILQ_FIRST(defs)) != NULL) {
	TAILQ_REMOVE(defs, def, entries);
	free_default(def, &prev_binding);
    }

    debug_return;
}

void
free_default(struct defaults *def, struct member_list **binding)
{
    debug_decl(free_default, SUDOERS_DEBUG_PARSER);

    if (def->binding != *binding) {
	*binding = def->binding;
	if (def->binding != NULL) {
	    free_members(def->binding);
	    free(def->binding);
	}
    }
    rcstr_delref(def->file);
    free(def->var);
    free(def->val);
    free(def);

    debug_return;
}

void
free_privilege(struct privilege *priv)
{
    struct member_list *runasuserlist = NULL, *runasgrouplist = NULL;
    struct member_list *prev_binding = NULL;
    struct cmndspec *cs;
    struct defaults *def;
    char *runcwd = NULL, *runchroot = NULL;
#ifdef HAVE_SELINUX
    char *role = NULL, *type = NULL;
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
    char *privs = NULL, *limitprivs = NULL;
#endif /* HAVE_PRIV_SET */
    debug_decl(free_privilege, SUDOERS_DEBUG_PARSER);

    free(priv->ldap_role);
    free_members(&priv->hostlist);
    while ((cs = TAILQ_FIRST(&priv->cmndlist)) != NULL) {
	TAILQ_REMOVE(&priv->cmndlist, cs, entries);
	/* Only free the first instance of runcwd/runchroot. */
	if (cs->runcwd != runcwd) {
	    runcwd = cs->runcwd;
	    free(cs->runcwd);
	}
	if (cs->runchroot != runchroot) {
	    runcwd = cs->runchroot;
	    free(cs->runchroot);
	}
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
	    free_members(runasuserlist);
	    free(runasuserlist);
	}
	if (cs->runasgrouplist && cs->runasgrouplist != runasgrouplist) {
	    runasgrouplist = cs->runasgrouplist;
	    free_members(runasgrouplist);
	    free(runasgrouplist);
	}
	free_member(cs->cmnd);
	free(cs);
    }
    while ((def = TAILQ_FIRST(&priv->defaults)) != NULL) {
	TAILQ_REMOVE(&priv->defaults, def, entries);
	free_default(def, &prev_binding);
    }
    free(priv);

    debug_return;
}

void
free_userspecs(struct userspec_list *usl)
{
    struct userspec *us;
    debug_decl(free_userspecs, SUDOERS_DEBUG_PARSER);

    while ((us = TAILQ_FIRST(usl)) != NULL) {
	TAILQ_REMOVE(usl, us, entries);
	free_userspec(us);
    }

    debug_return;
}

void
free_userspec(struct userspec *us)
{
    struct privilege *priv;
    struct sudoers_comment *comment;
    debug_decl(free_userspec, SUDOERS_DEBUG_PARSER);

    free_members(&us->users);
    while ((priv = TAILQ_FIRST(&us->privileges)) != NULL) {
	TAILQ_REMOVE(&us->privileges, priv, entries);
	free_privilege(priv);
    }
    while ((comment = STAILQ_FIRST(&us->comments)) != NULL) {
	STAILQ_REMOVE_HEAD(&us->comments, entries);
	free(comment->str);
	free(comment);
    }
    rcstr_delref(us->file);
    free(us);

    debug_return;
}

/*
 * Initialized a sudoers parse tree.
 */
void
init_parse_tree(struct sudoers_parse_tree *parse_tree, const char *lhost,
    const char *shost)
{
    TAILQ_INIT(&parse_tree->userspecs);
    TAILQ_INIT(&parse_tree->defaults);
    parse_tree->aliases = NULL;
    parse_tree->shost = shost;
    parse_tree->lhost = lhost;
}

/*
 * Move the contents of parsed_policy to new_tree.
 */
void
reparent_parse_tree(struct sudoers_parse_tree *new_tree)
{
    TAILQ_CONCAT(&new_tree->userspecs, &parsed_policy.userspecs, entries);
    TAILQ_CONCAT(&new_tree->defaults, &parsed_policy.defaults, entries);
    new_tree->aliases = parsed_policy.aliases;
    parsed_policy.aliases = NULL;
}

/*
 * Free the contents of a sudoers parse tree and initialize it.
 */
void
free_parse_tree(struct sudoers_parse_tree *parse_tree)
{
    free_userspecs(&parse_tree->userspecs);
    free_defaults(&parse_tree->defaults);
    free_aliases(parse_tree->aliases);
    parse_tree->aliases = NULL;
}

/*
 * Free up space used by data structures from a previous parser run and sets
 * the current sudoers file to path.
 */
bool
init_parser(const char *path, bool quiet, bool strict)
{
    bool ret = true;
    debug_decl(init_parser, SUDOERS_DEBUG_PARSER);

    free_parse_tree(&parsed_policy);
    init_lexer();

    rcstr_delref(sudoers);
    if (path != NULL) {
	if ((sudoers = rcstr_dup(path)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    ret = false;
	}
    } else {
	sudoers = NULL;
    }

    parse_error = false;
    errorlineno = -1;
    rcstr_delref(errorfile);
    errorfile = NULL;
    sudoers_warnings = !quiet;
    sudoers_strict = strict;

    debug_return_bool(ret);
}

/*
 * Initialize all options in a cmndspec.
 */
static void
init_options(struct command_options *opts)
{
    opts->notbefore = UNSPEC;
    opts->notafter = UNSPEC;
    opts->timeout = UNSPEC;
#ifdef HAVE_SELINUX
    opts->role = NULL;
    opts->type = NULL;
#endif
#ifdef HAVE_PRIV_SET
    opts->privs = NULL;
    opts->limitprivs = NULL;
#endif
}
#line 1056 "gram.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(void)
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
#define YY_SIZE_MAX 0xffffffffU
#endif
    if (YY_SIZE_MAX / newsize < sizeof *newss)
        goto bail;
    sslen = yyssp - yyss;
    newss = yyss ? realloc(yyss, newsize * sizeof *newss) :
      malloc(newsize * sizeof *newss); /* overflow check above */
    if (newss == NULL)
        goto bail;
    yyss = newss;
    yyssp = newss + sslen;
    newvs = yyvs ? realloc(yyvs, newsize * sizeof *newvs) :
      malloc(newsize * sizeof *newvs); /* overflow check above */
    if (newvs == NULL)
        goto bail;
    yyvs = newvs;
    yyvsp = newvs + sslen;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
bail:
    free(yyss);
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
yyparse(void)
{
    int yym, yyn, yystate;
#if YYDEBUG
    const char *yys;

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
#line 186 "gram.y"
{
			    ; /* empty file */
			}
break;
case 5:
#line 196 "gram.y"
{
			    ; /* blank line */
			}
break;
case 6:
#line 199 "gram.y"
{
			    yyerrok;
			}
break;
case 7:
#line 202 "gram.y"
{
			    if (!push_include(yyvsp[0].string, false)) {
				free(yyvsp[0].string);
				YYERROR;
			    }
			    free(yyvsp[0].string);
			}
break;
case 8:
#line 209 "gram.y"
{
			    if (!push_include(yyvsp[0].string, true)) {
				free(yyvsp[0].string);
				YYERROR;
			    }
			    free(yyvsp[0].string);
			}
break;
case 9:
#line 216 "gram.y"
{
			    if (!add_userspec(yyvsp[-2].member, yyvsp[-1].privilege)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 10:
#line 222 "gram.y"
{
			    ;
			}
break;
case 11:
#line 225 "gram.y"
{
			    ;
			}
break;
case 12:
#line 228 "gram.y"
{
			    ;
			}
break;
case 13:
#line 231 "gram.y"
{
			    ;
			}
break;
case 14:
#line 234 "gram.y"
{
			    if (!add_defaults(DEFAULTS, NULL, yyvsp[-1].defaults))
				YYERROR;
			}
break;
case 15:
#line 238 "gram.y"
{
			    if (!add_defaults(DEFAULTS_USER, yyvsp[-2].member, yyvsp[-1].defaults))
				YYERROR;
			}
break;
case 16:
#line 242 "gram.y"
{
			    if (!add_defaults(DEFAULTS_RUNAS, yyvsp[-2].member, yyvsp[-1].defaults))
				YYERROR;
			}
break;
case 17:
#line 246 "gram.y"
{
			    if (!add_defaults(DEFAULTS_HOST, yyvsp[-2].member, yyvsp[-1].defaults))
				YYERROR;
			}
break;
case 18:
#line 250 "gram.y"
{
			    if (!add_defaults(DEFAULTS_CMND, yyvsp[-2].member, yyvsp[-1].defaults))
				YYERROR;
			}
break;
case 19:
#line 256 "gram.y"
{
			    yyval.string = yyvsp[-1].string;
			}
break;
case 20:
#line 259 "gram.y"
{
			    yyerrok;
			    yyval.string = yyvsp[-2].string;
			}
break;
case 21:
#line 265 "gram.y"
{
			    yyval.string = yyvsp[-1].string;
			}
break;
case 22:
#line 268 "gram.y"
{
			    yyerrok;
			    yyval.string = yyvsp[-2].string;
			}
break;
case 24:
#line 275 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].defaults, yyvsp[0].defaults, entries);
			    yyval.defaults = yyvsp[-2].defaults;
			}
break;
case 25:
#line 281 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, true);
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 26:
#line 288 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[0].string, NULL, false);
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 27:
#line 295 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, true);
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 28:
#line 302 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '+');
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 29:
#line 309 "gram.y"
{
			    yyval.defaults = new_default(yyvsp[-2].string, yyvsp[0].string, '-');
			    if (yyval.defaults == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 31:
#line 319 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].privilege, yyvsp[0].privilege, entries);
			    yyval.privilege = yyvsp[-2].privilege;
			}
break;
case 32:
#line 323 "gram.y"
{
			    yyerrok;
			    yyval.privilege = yyvsp[-3].privilege;
			}
break;
case 33:
#line 329 "gram.y"
{
			    struct privilege *p = calloc(1, sizeof(*p));
			    if (p == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    TAILQ_INIT(&p->defaults);
			    HLTQ_TO_TAILQ(&p->hostlist, yyvsp[-2].member, entries);
			    HLTQ_TO_TAILQ(&p->cmndlist, yyvsp[0].cmndspec, entries);
			    HLTQ_INIT(p, entries);
			    yyval.privilege = p;
			}
break;
case 34:
#line 343 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 35:
#line 347 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 36:
#line 353 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 37:
#line 360 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 38:
#line 367 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 39:
#line 374 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NTWKADDR);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 40:
#line 381 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 42:
#line 391 "gram.y"
{
			    struct cmndspec *prev;
			    prev = HLTQ_LAST(yyvsp[-2].cmndspec, cmndspec, entries);
			    HLTQ_CONCAT(yyvsp[-2].cmndspec, yyvsp[0].cmndspec, entries);

			    /* propagate runcwd and runchroot */
			    if (yyvsp[0].cmndspec->runcwd == NULL)
				yyvsp[0].cmndspec->runcwd = prev->runcwd;
			    if (yyvsp[0].cmndspec->runchroot == NULL)
				yyvsp[0].cmndspec->runchroot = prev->runchroot;
#ifdef HAVE_SELINUX
			    /* propagate role and type */
			    if (yyvsp[0].cmndspec->role == NULL && yyvsp[0].cmndspec->type == NULL) {
				yyvsp[0].cmndspec->role = prev->role;
				yyvsp[0].cmndspec->type = prev->type;
			    }
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
			    /* propagate privs & limitprivs */
			    if (yyvsp[0].cmndspec->privs == NULL && yyvsp[0].cmndspec->limitprivs == NULL) {
			        yyvsp[0].cmndspec->privs = prev->privs;
			        yyvsp[0].cmndspec->limitprivs = prev->limitprivs;
			    }
#endif /* HAVE_PRIV_SET */
			    /* propagate command time restrictions */
			    if (yyvsp[0].cmndspec->notbefore == UNSPEC)
				yyvsp[0].cmndspec->notbefore = prev->notbefore;
			    if (yyvsp[0].cmndspec->notafter == UNSPEC)
				yyvsp[0].cmndspec->notafter = prev->notafter;
			    /* propagate command timeout */
			    if (yyvsp[0].cmndspec->timeout == UNSPEC)
				yyvsp[0].cmndspec->timeout = prev->timeout;
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
case 43:
#line 450 "gram.y"
{
			    struct cmndspec *cs = calloc(1, sizeof(*cs));
			    if (cs == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    if (yyvsp[-3].runas != NULL) {
				if (yyvsp[-3].runas->runasusers != NULL) {
				    cs->runasuserlist =
					malloc(sizeof(*cs->runasuserlist));
				    if (cs->runasuserlist == NULL) {
					free(cs);
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasuserlist,
					yyvsp[-3].runas->runasusers, entries);
				}
				if (yyvsp[-3].runas->runasgroups != NULL) {
				    cs->runasgrouplist =
					malloc(sizeof(*cs->runasgrouplist));
				    if (cs->runasgrouplist == NULL) {
					free(cs);
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasgrouplist,
					yyvsp[-3].runas->runasgroups, entries);
				}
				free(yyvsp[-3].runas);
			    }
#ifdef HAVE_SELINUX
			    cs->role = yyvsp[-2].options.role;
			    cs->type = yyvsp[-2].options.type;
#endif
#ifdef HAVE_PRIV_SET
			    cs->privs = yyvsp[-2].options.privs;
			    cs->limitprivs = yyvsp[-2].options.limitprivs;
#endif
			    cs->notbefore = yyvsp[-2].options.notbefore;
			    cs->notafter = yyvsp[-2].options.notafter;
			    cs->timeout = yyvsp[-2].options.timeout;
			    cs->runcwd = yyvsp[-2].options.runcwd;
			    cs->runchroot = yyvsp[-2].options.runchroot;
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
case 44:
#line 505 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA224, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 45:
#line 512 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA256, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 46:
#line 519 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA384, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 47:
#line 526 "gram.y"
{
			    yyval.digest = new_digest(SUDO_DIGEST_SHA512, yyvsp[0].string);
			    if (yyval.digest == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 49:
#line 536 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].digest, yyvsp[0].digest, entries);
			    yyval.digest = yyvsp[-2].digest;
			}
break;
case 50:
#line 542 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			}
break;
case 51:
#line 545 "gram.y"
{
			    struct sudo_command *c =
				(struct sudo_command *) yyvsp[0].member->name;

			    if (yyvsp[0].member->type != COMMAND && yyvsp[0].member->type != ALL) {
				sudoerserror(N_("a digest requires a path name"));
				YYERROR;
			    }
			    if (c == NULL) {
				/* lazy-allocate sudo_command for ALL */
				if ((c = new_command(NULL, NULL)) == NULL) {
				    sudoerserror(N_("unable to allocate memory"));
				    YYERROR;
				}
				yyvsp[0].member->name = (char *)c;
			    }
			    HLTQ_TO_TAILQ(&c->digests, yyvsp[-1].digest, entries);
			    yyval.member = yyvsp[0].member;
			}
break;
case 52:
#line 566 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 53:
#line 570 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 54:
#line 576 "gram.y"
{
			    if (yyvsp[0].string[0] != '/' && yyvsp[0].string[0] != '~') {
				if (strcmp(yyvsp[0].string, "*") != 0) {
				    sudoerserror(N_("values for \"CWD\" must"
					" start with a '/', '~', or '*'"));
				    YYERROR;
				}
			    }
			    yyval.string = yyvsp[0].string;
			}
break;
case 55:
#line 588 "gram.y"
{
			    if (yyvsp[0].string[0] != '/' && yyvsp[0].string[0] != '~') {
				if (strcmp(yyvsp[0].string, "*") != 0) {
				    sudoerserror(N_("values for \"CHROOT\" must"
					" start with a '/', '~', or '*'"));
				    YYERROR;
				}
			    }
			    yyval.string = yyvsp[0].string;
			}
break;
case 56:
#line 600 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 57:
#line 605 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 58:
#line 609 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 59:
#line 614 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 60:
#line 619 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 61:
#line 624 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 62:
#line 628 "gram.y"
{
			    yyval.string = yyvsp[0].string;
			}
break;
case 63:
#line 633 "gram.y"
{
			    yyval.runas = NULL;
			}
break;
case 64:
#line 636 "gram.y"
{
			    yyval.runas = yyvsp[-1].runas;
			}
break;
case 65:
#line 641 "gram.y"
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
#line 656 "gram.y"
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
case 67:
#line 665 "gram.y"
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
case 68:
#line 674 "gram.y"
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
case 69:
#line 683 "gram.y"
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
case 70:
#line 700 "gram.y"
{
			    init_options(&yyval.options);
			}
break;
case 71:
#line 703 "gram.y"
{
			    free(yyval.options.runcwd);
			    yyval.options.runcwd = yyvsp[0].string;
			}
break;
case 72:
#line 707 "gram.y"
{
			    free(yyval.options.runchroot);
			    yyval.options.runchroot = yyvsp[0].string;
			}
break;
case 73:
#line 711 "gram.y"
{
			    yyval.options.notbefore = parse_gentime(yyvsp[0].string);
			    free(yyvsp[0].string);
			    if (yyval.options.notbefore == -1) {
				sudoerserror(N_("invalid notbefore value"));
				YYERROR;
			    }
			}
break;
case 74:
#line 719 "gram.y"
{
			    yyval.options.notafter = parse_gentime(yyvsp[0].string);
			    free(yyvsp[0].string);
			    if (yyval.options.notafter == -1) {
				sudoerserror(N_("invalid notafter value"));
				YYERROR;
			    }
			}
break;
case 75:
#line 727 "gram.y"
{
			    yyval.options.timeout = parse_timeout(yyvsp[0].string);
			    free(yyvsp[0].string);
			    if (yyval.options.timeout == -1) {
				if (errno == ERANGE)
				    sudoerserror(N_("timeout value too large"));
				else
				    sudoerserror(N_("invalid timeout value"));
				YYERROR;
			    }
			}
break;
case 76:
#line 738 "gram.y"
{
#ifdef HAVE_SELINUX
			    free(yyval.options.role);
			    yyval.options.role = yyvsp[0].string;
#endif
			}
break;
case 77:
#line 744 "gram.y"
{
#ifdef HAVE_SELINUX
			    free(yyval.options.type);
			    yyval.options.type = yyvsp[0].string;
#endif
			}
break;
case 78:
#line 750 "gram.y"
{
#ifdef HAVE_PRIV_SET
			    free(yyval.options.privs);
			    yyval.options.privs = yyvsp[0].string;
#endif
			}
break;
case 79:
#line 756 "gram.y"
{
#ifdef HAVE_PRIV_SET
			    free(yyval.options.limitprivs);
			    yyval.options.limitprivs = yyvsp[0].string;
#endif
			}
break;
case 80:
#line 764 "gram.y"
{
			    TAGS_INIT(yyval.tag);
			}
break;
case 81:
#line 767 "gram.y"
{
			    yyval.tag.nopasswd = true;
			}
break;
case 82:
#line 770 "gram.y"
{
			    yyval.tag.nopasswd = false;
			}
break;
case 83:
#line 773 "gram.y"
{
			    yyval.tag.noexec = true;
			}
break;
case 84:
#line 776 "gram.y"
{
			    yyval.tag.noexec = false;
			}
break;
case 85:
#line 779 "gram.y"
{
			    yyval.tag.setenv = true;
			}
break;
case 86:
#line 782 "gram.y"
{
			    yyval.tag.setenv = false;
			}
break;
case 87:
#line 785 "gram.y"
{
			    yyval.tag.log_input = true;
			}
break;
case 88:
#line 788 "gram.y"
{
			    yyval.tag.log_input = false;
			}
break;
case 89:
#line 791 "gram.y"
{
			    yyval.tag.log_output = true;
			}
break;
case 90:
#line 794 "gram.y"
{
			    yyval.tag.log_output = false;
			}
break;
case 91:
#line 797 "gram.y"
{
			    yyval.tag.follow = true;
			}
break;
case 92:
#line 800 "gram.y"
{
			    yyval.tag.follow = false;
			}
break;
case 93:
#line 803 "gram.y"
{
			    yyval.tag.send_mail = true;
			}
break;
case 94:
#line 806 "gram.y"
{
			    yyval.tag.send_mail = false;
			}
break;
case 95:
#line 811 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 96:
#line 818 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 97:
#line 825 "gram.y"
{
			    struct sudo_command *c;

			    if ((c = new_command(yyvsp[0].command.cmnd, yyvsp[0].command.args)) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    yyval.member = new_member((char *)c, COMMAND);
			    if (yyval.member == NULL) {
				free(c);
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 100:
#line 845 "gram.y"
{
			    const char *s;
			    s = alias_add(&parsed_policy, yyvsp[-2].string, HOSTALIAS,
				sudoers, this_lineno, yyvsp[0].member);
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 102:
#line 857 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 105:
#line 867 "gram.y"
{
			    const char *s;
			    s = alias_add(&parsed_policy, yyvsp[-2].string, CMNDALIAS,
				sudoers, this_lineno, yyvsp[0].member);
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 107:
#line 879 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 110:
#line 889 "gram.y"
{
			    const char *s;
			    s = alias_add(&parsed_policy, yyvsp[-2].string, RUNASALIAS,
				sudoers, this_lineno, yyvsp[0].member);
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 113:
#line 904 "gram.y"
{
			    const char *s;
			    s = alias_add(&parsed_policy, yyvsp[-2].string, USERALIAS,
				sudoers, this_lineno, yyvsp[0].member);
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
break;
case 115:
#line 916 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 116:
#line 922 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 117:
#line 926 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 118:
#line 932 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 119:
#line 939 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 120:
#line 946 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, NETGROUP);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 121:
#line 953 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, USERGROUP);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 122:
#line 960 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 124:
#line 970 "gram.y"
{
			    HLTQ_CONCAT(yyvsp[-2].member, yyvsp[0].member, entries);
			    yyval.member = yyvsp[-2].member;
			}
break;
case 125:
#line 976 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = false;
			}
break;
case 126:
#line 980 "gram.y"
{
			    yyval.member = yyvsp[0].member;
			    yyval.member->negated = true;
			}
break;
case 127:
#line 986 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, ALIAS);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 128:
#line 993 "gram.y"
{
			    yyval.member = new_member(NULL, ALL);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 129:
#line 1000 "gram.y"
{
			    yyval.member = new_member(yyvsp[0].string, WORD);
			    if (yyval.member == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
break;
case 130:
#line 1009 "gram.y"
{
			    ;
			}
break;
case 131:
#line 1012 "gram.y"
{
			    ; /* EOF */
			}
break;
#line 2300 "gram.c"
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
    free(yyss);
    free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (1);
yyaccept:
    free(yyss);
    free(yyvs);
    yyss = yyssp = NULL;
    yyvs = yyvsp = NULL;
    yystacksize = 0;
    return (0);
}
