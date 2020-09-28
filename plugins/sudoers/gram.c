/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>
/* A Bison parser, made by GNU Bison 3.3.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2019 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.3.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         sudoersparse
#define yylex           sudoerslex
#define yyerror         sudoerserror
#define yydebug         sudoersdebug
#define yynerrs         sudoersnerrs

#define yylval          sudoerslval
#define yychar          sudoerschar

/* First part of user prologue.  */
#line 1 "gram.y" /* yacc.c:337  */

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
#define this_lineno	(sudoerschar == '\n' ? sudolineno - 1 : sudolineno)

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

#line 154 "gram.c" /* yacc.c:337  */
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_SUDOERS_Y_TAB_H_INCLUDED
# define YY_SUDOERS_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int sudoersdebug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    COMMAND = 258,
    ALIAS = 259,
    DEFVAR = 260,
    NTWKADDR = 261,
    NETGROUP = 262,
    USERGROUP = 263,
    WORD = 264,
    DIGEST = 265,
    INCLUDE = 266,
    INCLUDEDIR = 267,
    DEFAULTS = 268,
    DEFAULTS_HOST = 269,
    DEFAULTS_USER = 270,
    DEFAULTS_RUNAS = 271,
    DEFAULTS_CMND = 272,
    NOPASSWD = 273,
    PASSWD = 274,
    NOEXEC = 275,
    EXEC = 276,
    SETENV = 277,
    NOSETENV = 278,
    LOG_INPUT = 279,
    NOLOG_INPUT = 280,
    LOG_OUTPUT = 281,
    NOLOG_OUTPUT = 282,
    MAIL = 283,
    NOMAIL = 284,
    FOLLOWLNK = 285,
    NOFOLLOWLNK = 286,
    ALL = 287,
    HOSTALIAS = 288,
    CMNDALIAS = 289,
    USERALIAS = 290,
    RUNASALIAS = 291,
    ERROR = 292,
    NOMATCH = 293,
    CHROOT = 294,
    CWD = 295,
    TYPE = 296,
    ROLE = 297,
    PRIVS = 298,
    LIMITPRIVS = 299,
    CMND_TIMEOUT = 300,
    NOTBEFORE = 301,
    NOTAFTER = 302,
    MYSELF = 303,
    SHA224_TOK = 304,
    SHA256_TOK = 305,
    SHA384_TOK = 306,
    SHA512_TOK = 307
  };
#endif
/* Tokens.  */
#define COMMAND 258
#define ALIAS 259
#define DEFVAR 260
#define NTWKADDR 261
#define NETGROUP 262
#define USERGROUP 263
#define WORD 264
#define DIGEST 265
#define INCLUDE 266
#define INCLUDEDIR 267
#define DEFAULTS 268
#define DEFAULTS_HOST 269
#define DEFAULTS_USER 270
#define DEFAULTS_RUNAS 271
#define DEFAULTS_CMND 272
#define NOPASSWD 273
#define PASSWD 274
#define NOEXEC 275
#define EXEC 276
#define SETENV 277
#define NOSETENV 278
#define LOG_INPUT 279
#define NOLOG_INPUT 280
#define LOG_OUTPUT 281
#define NOLOG_OUTPUT 282
#define MAIL 283
#define NOMAIL 284
#define FOLLOWLNK 285
#define NOFOLLOWLNK 286
#define ALL 287
#define HOSTALIAS 288
#define CMNDALIAS 289
#define USERALIAS 290
#define RUNASALIAS 291
#define ERROR 292
#define NOMATCH 293
#define CHROOT 294
#define CWD 295
#define TYPE 296
#define ROLE 297
#define PRIVS 298
#define LIMITPRIVS 299
#define CMND_TIMEOUT 300
#define NOTBEFORE 301
#define NOTAFTER 302
#define MYSELF 303
#define SHA224_TOK 304
#define SHA256_TOK 305
#define SHA384_TOK 306
#define SHA512_TOK 307

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 77 "gram.y" /* yacc.c:352  */

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

#line 315 "gram.c" /* yacc.c:352  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE sudoerslval;

int sudoersparse (void);

#endif /* !YY_SUDOERS_Y_TAB_H_INCLUDED  */



#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  88
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   319

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  62
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  50
/* YYNRULES -- Number of rules.  */
#define YYNRULES  145
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  244

#define YYUNDEFTOK  2
#define YYMAXUTOK   307

/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                                \
  ((unsigned) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      45,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    40,     2,     2,     2,     2,     2,     2,
      43,    44,     2,    41,    39,    42,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    37,     2,
       2,    38,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    46,    47,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    61
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   185,   185,   188,   191,   192,   195,   198,   201,   208,
     215,   221,   224,   227,   230,   233,   237,   241,   245,   249,
     255,   258,   264,   267,   273,   274,   280,   287,   294,   301,
     308,   317,   318,   322,   328,   342,   346,   352,   359,   366,
     373,   380,   389,   390,   449,   504,   511,   518,   525,   534,
     535,   541,   544,   565,   569,   575,   587,   599,   604,   608,
     613,   618,   623,   627,   632,   635,   640,   655,   664,   673,
     682,   699,   700,   701,   702,   703,   704,   705,   706,   707,
     708,   711,   717,   720,   724,   728,   736,   744,   755,   761,
     767,   773,   781,   784,   787,   790,   793,   796,   799,   802,
     805,   808,   811,   814,   817,   820,   823,   828,   835,   842,
     858,   859,   862,   871,   874,   875,   881,   882,   885,   894,
     897,   898,   904,   905,   908,   917,   920,   921,   924,   933,
     936,   937,   943,   947,   953,   960,   967,   974,   981,   990,
     991,   997,  1001,  1007,  1014,  1021
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || 0
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "COMMAND", "ALIAS", "DEFVAR", "NTWKADDR",
  "NETGROUP", "USERGROUP", "WORD", "DIGEST", "INCLUDE", "INCLUDEDIR",
  "DEFAULTS", "DEFAULTS_HOST", "DEFAULTS_USER", "DEFAULTS_RUNAS",
  "DEFAULTS_CMND", "NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV",
  "NOSETENV", "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT",
  "MAIL", "NOMAIL", "FOLLOWLNK", "NOFOLLOWLNK", "ALL", "HOSTALIAS",
  "CMNDALIAS", "USERALIAS", "RUNASALIAS", "':'", "'='", "','", "'!'",
  "'+'", "'-'", "'('", "')'", "'\\n'", "ERROR", "NOMATCH", "CHROOT", "CWD",
  "TYPE", "ROLE", "PRIVS", "LIMITPRIVS", "CMND_TIMEOUT", "NOTBEFORE",
  "NOTAFTER", "MYSELF", "SHA224_TOK", "SHA256_TOK", "SHA384_TOK",
  "SHA512_TOK", "$accept", "file", "line", "entry", "include",
  "includedir", "defaults_list", "defaults_entry", "privileges",
  "privilege", "ophost", "host", "cmndspeclist", "cmndspec", "digestspec",
  "digestlist", "digcmnd", "opcmnd", "chdirspec", "chrootspec",
  "timeoutspec", "notbeforespec", "notafterspec", "rolespec", "typespec",
  "privsspec", "limitprivsspec", "runasspec", "runaslist", "reserved_word",
  "reserved_alias", "options", "cmndtag", "cmnd", "hostaliases",
  "hostalias", "hostlist", "cmndaliases", "cmndalias", "cmndlist",
  "runasaliases", "runasalias", "useraliases", "useralias", "userlist",
  "opuser", "user", "grouplist", "opgroup", "group", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,    58,    61,    44,
      33,    43,    45,    40,    41,    10,   292,   293,   294,   295,
     296,   297,   298,   299,   300,   301,   302,   303,   304,   305,
     306,   307
};
# endif

#define YYPACT_NINF -112

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-112)))

#define YYTABLE_NINF -4

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     160,   -37,  -112,  -112,  -112,  -112,     6,     9,    35,   222,
     236,   236,     7,  -112,    37,    48,    77,   102,   175,  -112,
      44,   202,  -112,  -112,  -112,    10,  -112,  -112,  -112,     8,
      11,   124,    43,    69,  -112,  -112,  -112,  -112,  -112,  -112,
     131,  -112,  -112,    15,    31,    31,  -112,  -112,  -112,    75,
      57,    99,   106,   149,  -112,    73,  -112,  -112,  -112,    33,
      72,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,
    -112,  -112,   159,     0,  -112,   163,   174,   104,  -112,   194,
     201,   154,  -112,   213,   217,   185,  -112,  -112,  -112,  -112,
     236,   196,  -112,    45,   153,  -112,   212,  -112,   249,   250,
     251,  -112,    35,  -112,  -112,   222,    79,   142,   182,  -112,
     253,   254,   255,   256,    -1,  -112,     7,   207,   222,   222,
      37,  -112,     7,     7,    48,  -112,   236,   236,    77,  -112,
     236,   236,   102,  -112,  -112,   138,  -112,   218,  -112,  -112,
    -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,
    -112,  -112,  -112,  -112,  -112,   228,   228,  -112,   230,   230,
    -112,   231,   231,  -112,   231,   231,  -112,  -112,  -112,   216,
     232,  -112,  -112,    42,   242,   109,   218,   229,  -112,  -112,
    -112,   176,   233,  -112,  -112,  -112,    42,  -112,   235,   237,
     252,   257,   258,   259,   260,   261,   262,  -112,  -112,  -112,
    -112,  -112,  -112,  -112,  -112,  -112,     3,  -112,    42,   233,
     265,   278,   279,   280,   282,   283,   284,   285,   292,  -112,
    -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,
    -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,
    -112,  -112,  -112,  -112
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     0,   134,   136,   137,   138,     0,     0,     0,     0,
       0,     0,     0,   135,     0,     0,     0,     0,     0,     6,
       0,     0,     4,     8,     9,     0,   130,   132,     7,     0,
       0,    26,     0,     0,    24,    37,    40,    39,    41,    38,
       0,   114,    35,     0,     0,     0,   109,   108,   107,     0,
       0,     0,     0,     0,    49,     0,   120,    51,    53,     0,
       0,    71,    72,    73,    78,    77,    79,    80,    74,    75,
      76,    81,     0,     0,   110,     0,     0,     0,   116,     0,
       0,     0,   126,     0,     0,     0,   122,   133,     1,     5,
       0,     0,    31,     0,     0,    20,     0,    22,     0,     0,
       0,    27,     0,    15,    36,     0,     0,     0,     0,    54,
       0,     0,     0,     0,     0,    52,     0,     0,     0,     0,
       0,    12,     0,     0,     0,    13,     0,     0,     0,    11,
       0,     0,     0,    14,   131,     0,    10,    64,    21,    23,
      28,    29,    30,    25,   115,    18,    16,    17,    45,    46,
      47,    48,    50,   121,    19,   112,   113,   111,   118,   119,
     117,   128,   129,   127,   124,   125,   123,    33,    32,    66,
      34,    42,    82,    70,     0,    67,    64,    92,   143,   145,
     144,     0,    69,   139,   141,    65,     0,    43,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    83,    84,    87,
      85,    86,    88,    89,    90,    91,     0,   142,     0,    68,
       0,     0,     0,     0,     0,     0,     0,     0,     0,    93,
      94,    95,    96,    97,    98,    99,   100,   101,   102,   105,
     106,   103,   104,    44,   140,    56,    55,    61,    60,    62,
      63,    57,    58,    59
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -112,  -112,  -112,   281,  -112,  -112,   145,   203,  -112,   168,
     199,   266,  -112,   132,   193,  -112,  -111,   263,  -112,  -112,
    -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,
     -13,  -112,  -112,   264,  -112,   189,     4,  -112,   186,   127,
    -112,   179,  -112,   184,   -10,   224,   297,   130,   111,   136
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,    20,    21,    22,    23,    24,    33,    34,    91,    92,
      41,    42,   170,   171,    54,    55,    56,    57,   197,   198,
     199,   200,   201,   202,   203,   204,   205,   172,   174,    71,
      72,   177,   206,    58,    73,    74,    93,    77,    78,    59,
      85,    86,    81,    82,    25,    26,    27,   182,   183,   184
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      44,    45,    76,    80,    84,   153,    46,    47,    28,    94,
      46,    47,    96,    43,    35,    29,    36,    37,    30,    38,
      31,   219,   220,   221,   222,   223,   224,   225,   226,   227,
     228,   229,   230,   231,   232,    48,    31,   120,    31,    48,
      31,    60,    39,    49,    88,   121,   178,    49,   101,    90,
      40,   179,    75,    95,   105,    32,    97,    50,    51,    52,
      53,    50,    51,    52,    53,    50,    51,    52,    53,    61,
      90,    32,   116,    32,   180,    32,    46,    47,    46,    47,
      61,    79,   181,   137,   105,    62,    63,    64,    65,    66,
      67,    68,    69,    70,   110,   233,    62,    63,    64,    65,
      66,    67,    68,    69,    70,    48,    83,    48,   102,    61,
     118,    76,   114,    49,   103,    80,   161,   162,   102,    84,
     164,   165,   155,   156,   145,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    61,    35,   111,    36,    37,   167,
      38,   124,    35,   112,    36,    37,   186,    38,    90,   125,
      62,    63,    64,    65,    66,    67,    68,    69,    70,   175,
      -2,     1,    98,    39,     2,    99,   100,     3,     4,     5,
      39,     6,     7,     8,     9,    10,    11,    12,    40,     2,
     178,   102,     3,     4,     5,   179,   113,   146,   106,   107,
     108,   128,    13,    14,    15,    16,    17,   119,   138,   129,
      18,   122,    -3,     1,   117,    19,     2,    13,   180,     3,
       4,     5,   123,     6,     7,     8,     9,    10,    11,    12,
       2,   102,   132,     3,     4,     5,    35,   147,    36,    37,
     133,    38,   126,   135,    13,    14,    15,    16,    17,   127,
       2,   136,    18,     3,     4,     5,   102,    19,    13,   158,
     159,   130,   154,   173,    39,   131,    18,   139,   140,   141,
     142,   169,    40,   148,   149,   150,   151,   105,    13,   116,
      90,   176,   208,   210,   235,   211,    18,   188,   189,   190,
     191,   192,   193,   194,   195,   196,   185,   236,   237,   238,
     212,   239,   240,   241,   242,   213,   214,   215,   216,   217,
     218,   243,    89,   168,   144,   143,   104,   152,   187,   157,
     160,   166,   163,   109,   134,    87,   209,   207,   115,   234
};

static const yytype_uint8 yycheck[] =
{
      10,    11,    15,    16,    17,   116,     3,     4,    45,     1,
       3,     4,     1,     9,     4,     9,     6,     7,     9,     9,
       5,    18,    19,    20,    21,    22,    23,    24,    25,    26,
      27,    28,    29,    30,    31,    32,     5,    37,     5,    32,
       5,     4,    32,    40,     0,    45,     4,    40,     5,    39,
      40,     9,     4,    45,    39,    40,    45,    58,    59,    60,
      61,    58,    59,    60,    61,    58,    59,    60,    61,    32,
      39,    40,    39,    40,    32,    40,     3,     4,     3,     4,
      32,     4,    40,    38,    39,    48,    49,    50,    51,    52,
      53,    54,    55,    56,    37,   206,    48,    49,    50,    51,
      52,    53,    54,    55,    56,    32,     4,    32,    39,    32,
      38,   124,    39,    40,    45,   128,   126,   127,    39,   132,
     130,   131,   118,   119,    45,    48,    49,    50,    51,    52,
      53,    54,    55,    56,    32,     4,    37,     6,     7,     1,
       9,    37,     4,    37,     6,     7,    37,     9,    39,    45,
      48,    49,    50,    51,    52,    53,    54,    55,    56,   169,
       0,     1,    38,    32,     4,    41,    42,     7,     8,     9,
      32,    11,    12,    13,    14,    15,    16,    17,    40,     4,
       4,    39,     7,     8,     9,     9,    37,    45,    43,    44,
      45,    37,    32,    33,    34,    35,    36,    38,    45,    45,
      40,    38,     0,     1,    59,    45,     4,    32,    32,     7,
       8,     9,    38,    11,    12,    13,    14,    15,    16,    17,
       4,    39,    37,     7,     8,     9,     4,    45,     6,     7,
      45,     9,    38,    37,    32,    33,    34,    35,    36,    38,
       4,    45,    40,     7,     8,     9,    39,    45,    32,   122,
     123,    38,    45,    37,    32,    38,    40,    45,     9,     9,
       9,    43,    40,    10,    10,    10,    10,    39,    32,    39,
      39,    39,    39,    38,     9,    38,    40,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    44,     9,     9,     9,
      38,     9,     9,     9,     9,    38,    38,    38,    38,    38,
      38,     9,    21,   135,   105,   102,    40,   114,   176,   120,
     124,   132,   128,    49,    90,    18,   186,   181,    55,   208
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     1,     4,     7,     8,     9,    11,    12,    13,    14,
      15,    16,    17,    32,    33,    34,    35,    36,    40,    45,
      63,    64,    65,    66,    67,   106,   107,   108,    45,     9,
       9,     5,    40,    68,    69,     4,     6,     7,     9,    32,
      40,    72,    73,    98,   106,   106,     3,     4,    32,    40,
      58,    59,    60,    61,    76,    77,    78,    79,    95,   101,
       4,    32,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    91,    92,    96,    97,     4,    92,    99,   100,     4,
      92,   104,   105,     4,    92,   102,   103,   108,     0,    65,
      39,    70,    71,    98,     1,    45,     1,    45,    38,    41,
      42,     5,    39,    45,    73,    39,    68,    68,    68,    95,
      37,    37,    37,    37,    39,    79,    39,    68,    38,    38,
      37,    45,    38,    38,    37,    45,    38,    38,    37,    45,
      38,    38,    37,    45,   107,    37,    45,    38,    45,    45,
       9,     9,     9,    69,    72,    45,    45,    45,    10,    10,
      10,    10,    76,    78,    45,    98,    98,    97,   101,   101,
     100,   106,   106,   105,   106,   106,   103,     1,    71,    43,
      74,    75,    89,    37,    90,   106,    39,    93,     4,     9,
      32,    40,   109,   110,   111,    44,    37,    75,    48,    49,
      50,    51,    52,    53,    54,    55,    56,    80,    81,    82,
      83,    84,    85,    86,    87,    88,    94,   111,    39,   109,
      38,    38,    38,    38,    38,    38,    38,    38,    38,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    78,   110,     9,     9,     9,     9,     9,
       9,     9,     9,     9
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    62,    63,    63,    64,    64,    65,    65,    65,    65,
      65,    65,    65,    65,    65,    65,    65,    65,    65,    65,
      66,    66,    67,    67,    68,    68,    69,    69,    69,    69,
      69,    70,    70,    70,    71,    72,    72,    73,    73,    73,
      73,    73,    74,    74,    75,    76,    76,    76,    76,    77,
      77,    78,    78,    79,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    89,    90,    90,    90,    90,
      90,    91,    91,    91,    91,    91,    91,    91,    91,    91,
      91,    92,    93,    93,    93,    93,    93,    93,    93,    93,
      93,    93,    94,    94,    94,    94,    94,    94,    94,    94,
      94,    94,    94,    94,    94,    94,    94,    95,    95,    95,
      96,    96,    97,    97,    98,    98,    99,    99,   100,   100,
     101,   101,   102,   102,   103,   103,   104,   104,   105,   105,
     106,   106,   107,   107,   108,   108,   108,   108,   108,   109,
     109,   110,   110,   111,   111,   111
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     1,     1,     2,     1,     2,     1,     1,
       3,     3,     3,     3,     3,     3,     4,     4,     4,     4,
       3,     4,     3,     4,     1,     3,     1,     2,     3,     3,
       3,     1,     3,     3,     3,     1,     2,     1,     1,     1,
       1,     1,     1,     3,     4,     3,     3,     3,     3,     1,
       3,     1,     2,     1,     2,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     0,     3,     0,     1,     3,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     0,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     0,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     1,     1,     1,
       1,     3,     3,     3,     1,     3,     1,     3,     3,     3,
       1,     3,     1,     3,     3,     3,     1,     3,     3,     3,
       1,     3,     1,     2,     1,     1,     1,     1,     1,     1,
       3,     1,     2,     1,     1,     1
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256



/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)

/* This macro is provided for backward compatibility. */
#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YYUSE (yyoutput);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo, int yytype, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  yy_symbol_value_print (yyo, yytype, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, int yyrule)
{
  unsigned long yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &yyvsp[(yyi + 1) - (yynrhs)]
                                              );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return (YYSIZE_T) (yystpcpy (yyres, yystr) - yyres);
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
                    yysize = yysize1;
                  else
                    return 2;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
      yysize = yysize1;
    else
      return 2;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;
/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

int
yyparse (void)
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yynewstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  *yyssp = (yytype_int16) yystate;

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = (YYSIZE_T) (yyssp - yyss + 1);

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
# undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 185 "gram.y" /* yacc.c:1652  */
    {
			    ; /* empty file */
			}
#line 1610 "gram.c" /* yacc.c:1652  */
    break;

  case 6:
#line 195 "gram.y" /* yacc.c:1652  */
    {
			    ; /* blank line */
			}
#line 1618 "gram.c" /* yacc.c:1652  */
    break;

  case 7:
#line 198 "gram.y" /* yacc.c:1652  */
    {
			    yyerrok;
			}
#line 1626 "gram.c" /* yacc.c:1652  */
    break;

  case 8:
#line 201 "gram.y" /* yacc.c:1652  */
    {
			    if (!push_include((yyvsp[0].string), false)) {
				free((yyvsp[0].string));
				YYERROR;
			    }
			    free((yyvsp[0].string));
			}
#line 1638 "gram.c" /* yacc.c:1652  */
    break;

  case 9:
#line 208 "gram.y" /* yacc.c:1652  */
    {
			    if (!push_include((yyvsp[0].string), true)) {
				free((yyvsp[0].string));
				YYERROR;
			    }
			    free((yyvsp[0].string));
			}
#line 1650 "gram.c" /* yacc.c:1652  */
    break;

  case 10:
#line 215 "gram.y" /* yacc.c:1652  */
    {
			    if (!add_userspec((yyvsp[-2].member), (yyvsp[-1].privilege))) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1661 "gram.c" /* yacc.c:1652  */
    break;

  case 11:
#line 221 "gram.y" /* yacc.c:1652  */
    {
			    ;
			}
#line 1669 "gram.c" /* yacc.c:1652  */
    break;

  case 12:
#line 224 "gram.y" /* yacc.c:1652  */
    {
			    ;
			}
#line 1677 "gram.c" /* yacc.c:1652  */
    break;

  case 13:
#line 227 "gram.y" /* yacc.c:1652  */
    {
			    ;
			}
#line 1685 "gram.c" /* yacc.c:1652  */
    break;

  case 14:
#line 230 "gram.y" /* yacc.c:1652  */
    {
			    ;
			}
#line 1693 "gram.c" /* yacc.c:1652  */
    break;

  case 15:
#line 233 "gram.y" /* yacc.c:1652  */
    {
			    if (!add_defaults(DEFAULTS, NULL, (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1702 "gram.c" /* yacc.c:1652  */
    break;

  case 16:
#line 237 "gram.y" /* yacc.c:1652  */
    {
			    if (!add_defaults(DEFAULTS_USER, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1711 "gram.c" /* yacc.c:1652  */
    break;

  case 17:
#line 241 "gram.y" /* yacc.c:1652  */
    {
			    if (!add_defaults(DEFAULTS_RUNAS, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1720 "gram.c" /* yacc.c:1652  */
    break;

  case 18:
#line 245 "gram.y" /* yacc.c:1652  */
    {
			    if (!add_defaults(DEFAULTS_HOST, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1729 "gram.c" /* yacc.c:1652  */
    break;

  case 19:
#line 249 "gram.y" /* yacc.c:1652  */
    {
			    if (!add_defaults(DEFAULTS_CMND, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1738 "gram.c" /* yacc.c:1652  */
    break;

  case 20:
#line 255 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.string) = (yyvsp[-1].string);
			}
#line 1746 "gram.c" /* yacc.c:1652  */
    break;

  case 21:
#line 258 "gram.y" /* yacc.c:1652  */
    {
			    yyerrok;
			    (yyval.string) = (yyvsp[-2].string);
			}
#line 1755 "gram.c" /* yacc.c:1652  */
    break;

  case 22:
#line 264 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.string) = (yyvsp[-1].string);
			}
#line 1763 "gram.c" /* yacc.c:1652  */
    break;

  case 23:
#line 267 "gram.y" /* yacc.c:1652  */
    {
			    yyerrok;
			    (yyval.string) = (yyvsp[-2].string);
			}
#line 1772 "gram.c" /* yacc.c:1652  */
    break;

  case 25:
#line 274 "gram.y" /* yacc.c:1652  */
    {
			    HLTQ_CONCAT((yyvsp[-2].defaults), (yyvsp[0].defaults), entries);
			    (yyval.defaults) = (yyvsp[-2].defaults);
			}
#line 1781 "gram.c" /* yacc.c:1652  */
    break;

  case 26:
#line 280 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.defaults) = new_default((yyvsp[0].string), NULL, true);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1793 "gram.c" /* yacc.c:1652  */
    break;

  case 27:
#line 287 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.defaults) = new_default((yyvsp[0].string), NULL, false);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1805 "gram.c" /* yacc.c:1652  */
    break;

  case 28:
#line 294 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.defaults) = new_default((yyvsp[-2].string), (yyvsp[0].string), true);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1817 "gram.c" /* yacc.c:1652  */
    break;

  case 29:
#line 301 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.defaults) = new_default((yyvsp[-2].string), (yyvsp[0].string), '+');
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1829 "gram.c" /* yacc.c:1652  */
    break;

  case 30:
#line 308 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.defaults) = new_default((yyvsp[-2].string), (yyvsp[0].string), '-');
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1841 "gram.c" /* yacc.c:1652  */
    break;

  case 32:
#line 318 "gram.y" /* yacc.c:1652  */
    {
			    HLTQ_CONCAT((yyvsp[-2].privilege), (yyvsp[0].privilege), entries);
			    (yyval.privilege) = (yyvsp[-2].privilege);
			}
#line 1850 "gram.c" /* yacc.c:1652  */
    break;

  case 33:
#line 322 "gram.y" /* yacc.c:1652  */
    {
			    yyerrok;
			    (yyval.privilege) = (yyvsp[-2].privilege);
			}
#line 1859 "gram.c" /* yacc.c:1652  */
    break;

  case 34:
#line 328 "gram.y" /* yacc.c:1652  */
    {
			    struct privilege *p = calloc(1, sizeof(*p));
			    if (p == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    TAILQ_INIT(&p->defaults);
			    HLTQ_TO_TAILQ(&p->hostlist, (yyvsp[-2].member), entries);
			    HLTQ_TO_TAILQ(&p->cmndlist, (yyvsp[0].cmndspec), entries);
			    HLTQ_INIT(p, entries);
			    (yyval.privilege) = p;
			}
#line 1876 "gram.c" /* yacc.c:1652  */
    break;

  case 35:
#line 342 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 1885 "gram.c" /* yacc.c:1652  */
    break;

  case 36:
#line 346 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 1894 "gram.c" /* yacc.c:1652  */
    break;

  case 37:
#line 352 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1906 "gram.c" /* yacc.c:1652  */
    break;

  case 38:
#line 359 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1918 "gram.c" /* yacc.c:1652  */
    break;

  case 39:
#line 366 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), NETGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1930 "gram.c" /* yacc.c:1652  */
    break;

  case 40:
#line 373 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), NTWKADDR);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1942 "gram.c" /* yacc.c:1652  */
    break;

  case 41:
#line 380 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1954 "gram.c" /* yacc.c:1652  */
    break;

  case 43:
#line 390 "gram.y" /* yacc.c:1652  */
    {
			    struct cmndspec *prev;
			    prev = HLTQ_LAST((yyvsp[-2].cmndspec), cmndspec, entries);
			    HLTQ_CONCAT((yyvsp[-2].cmndspec), (yyvsp[0].cmndspec), entries);

			    /* propagate runcwd and runchroot */
			    if ((yyvsp[0].cmndspec)->runcwd == NULL)
				(yyvsp[0].cmndspec)->runcwd = prev->runcwd;
			    if ((yyvsp[0].cmndspec)->runchroot == NULL)
				(yyvsp[0].cmndspec)->runchroot = prev->runchroot;
#ifdef HAVE_SELINUX
			    /* propagate role and type */
			    if ((yyvsp[0].cmndspec)->role == NULL && (yyvsp[0].cmndspec)->type == NULL) {
				(yyvsp[0].cmndspec)->role = prev->role;
				(yyvsp[0].cmndspec)->type = prev->type;
			    }
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
			    /* propagate privs & limitprivs */
			    if ((yyvsp[0].cmndspec)->privs == NULL && (yyvsp[0].cmndspec)->limitprivs == NULL) {
			        (yyvsp[0].cmndspec)->privs = prev->privs;
			        (yyvsp[0].cmndspec)->limitprivs = prev->limitprivs;
			    }
#endif /* HAVE_PRIV_SET */
			    /* propagate command time restrictions */
			    if ((yyvsp[0].cmndspec)->notbefore == UNSPEC)
				(yyvsp[0].cmndspec)->notbefore = prev->notbefore;
			    if ((yyvsp[0].cmndspec)->notafter == UNSPEC)
				(yyvsp[0].cmndspec)->notafter = prev->notafter;
			    /* propagate command timeout */
			    if ((yyvsp[0].cmndspec)->timeout == UNSPEC)
				(yyvsp[0].cmndspec)->timeout = prev->timeout;
			    /* propagate tags and runas list */
			    if ((yyvsp[0].cmndspec)->tags.nopasswd == UNSPEC)
				(yyvsp[0].cmndspec)->tags.nopasswd = prev->tags.nopasswd;
			    if ((yyvsp[0].cmndspec)->tags.noexec == UNSPEC)
				(yyvsp[0].cmndspec)->tags.noexec = prev->tags.noexec;
			    if ((yyvsp[0].cmndspec)->tags.setenv == UNSPEC &&
				prev->tags.setenv != IMPLIED)
				(yyvsp[0].cmndspec)->tags.setenv = prev->tags.setenv;
			    if ((yyvsp[0].cmndspec)->tags.log_input == UNSPEC)
				(yyvsp[0].cmndspec)->tags.log_input = prev->tags.log_input;
			    if ((yyvsp[0].cmndspec)->tags.log_output == UNSPEC)
				(yyvsp[0].cmndspec)->tags.log_output = prev->tags.log_output;
			    if ((yyvsp[0].cmndspec)->tags.send_mail == UNSPEC)
				(yyvsp[0].cmndspec)->tags.send_mail = prev->tags.send_mail;
			    if ((yyvsp[0].cmndspec)->tags.follow == UNSPEC)
				(yyvsp[0].cmndspec)->tags.follow = prev->tags.follow;
			    if (((yyvsp[0].cmndspec)->runasuserlist == NULL &&
				 (yyvsp[0].cmndspec)->runasgrouplist == NULL) &&
				(prev->runasuserlist != NULL ||
				 prev->runasgrouplist != NULL)) {
				(yyvsp[0].cmndspec)->runasuserlist = prev->runasuserlist;
				(yyvsp[0].cmndspec)->runasgrouplist = prev->runasgrouplist;
			    }
			    (yyval.cmndspec) = (yyvsp[-2].cmndspec);
			}
#line 2016 "gram.c" /* yacc.c:1652  */
    break;

  case 44:
#line 449 "gram.y" /* yacc.c:1652  */
    {
			    struct cmndspec *cs = calloc(1, sizeof(*cs));
			    if (cs == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    if ((yyvsp[-3].runas) != NULL) {
				if ((yyvsp[-3].runas)->runasusers != NULL) {
				    cs->runasuserlist =
					malloc(sizeof(*cs->runasuserlist));
				    if (cs->runasuserlist == NULL) {
					free(cs);
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasuserlist,
					(yyvsp[-3].runas)->runasusers, entries);
				}
				if ((yyvsp[-3].runas)->runasgroups != NULL) {
				    cs->runasgrouplist =
					malloc(sizeof(*cs->runasgrouplist));
				    if (cs->runasgrouplist == NULL) {
					free(cs);
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasgrouplist,
					(yyvsp[-3].runas)->runasgroups, entries);
				}
				free((yyvsp[-3].runas));
			    }
#ifdef HAVE_SELINUX
			    cs->role = (yyvsp[-2].options).role;
			    cs->type = (yyvsp[-2].options).type;
#endif
#ifdef HAVE_PRIV_SET
			    cs->privs = (yyvsp[-2].options).privs;
			    cs->limitprivs = (yyvsp[-2].options).limitprivs;
#endif
			    cs->notbefore = (yyvsp[-2].options).notbefore;
			    cs->notafter = (yyvsp[-2].options).notafter;
			    cs->timeout = (yyvsp[-2].options).timeout;
			    cs->runcwd = (yyvsp[-2].options).runcwd;
			    cs->runchroot = (yyvsp[-2].options).runchroot;
			    cs->tags = (yyvsp[-1].tag);
			    cs->cmnd = (yyvsp[0].member);
			    HLTQ_INIT(cs, entries);
			    /* sudo "ALL" implies the SETENV tag */
			    if (cs->cmnd->type == ALL && !cs->cmnd->negated &&
				cs->tags.setenv == UNSPEC)
				cs->tags.setenv = IMPLIED;
			    (yyval.cmndspec) = cs;
			}
#line 2074 "gram.c" /* yacc.c:1652  */
    break;

  case 45:
#line 504 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA224, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2086 "gram.c" /* yacc.c:1652  */
    break;

  case 46:
#line 511 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA256, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2098 "gram.c" /* yacc.c:1652  */
    break;

  case 47:
#line 518 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA384, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2110 "gram.c" /* yacc.c:1652  */
    break;

  case 48:
#line 525 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA512, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2122 "gram.c" /* yacc.c:1652  */
    break;

  case 50:
#line 535 "gram.y" /* yacc.c:1652  */
    {
			    HLTQ_CONCAT((yyvsp[-2].digest), (yyvsp[0].digest), entries);
			    (yyval.digest) = (yyvsp[-2].digest);
			}
#line 2131 "gram.c" /* yacc.c:1652  */
    break;

  case 51:
#line 541 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = (yyvsp[0].member);
			}
#line 2139 "gram.c" /* yacc.c:1652  */
    break;

  case 52:
#line 544 "gram.y" /* yacc.c:1652  */
    {
			    struct sudo_command *c =
				(struct sudo_command *) (yyvsp[0].member)->name;

			    if ((yyvsp[0].member)->type != COMMAND && (yyvsp[0].member)->type != ALL) {
				sudoerserror(N_("a digest requires a path name"));
				YYERROR;
			    }
			    if (c == NULL) {
				/* lazy-allocate sudo_command for ALL */
				if ((c = new_command(NULL, NULL)) == NULL) {
				    sudoerserror(N_("unable to allocate memory"));
				    YYERROR;
				}
				(yyvsp[0].member)->name = (char *)c;
			    }
			    HLTQ_TO_TAILQ(&c->digests, (yyvsp[-1].digest), entries);
			    (yyval.member) = (yyvsp[0].member);
			}
#line 2163 "gram.c" /* yacc.c:1652  */
    break;

  case 53:
#line 565 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 2172 "gram.c" /* yacc.c:1652  */
    break;

  case 54:
#line 569 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 2181 "gram.c" /* yacc.c:1652  */
    break;

  case 55:
#line 575 "gram.y" /* yacc.c:1652  */
    {
			    if ((yyvsp[0].string)[0] != '/' && (yyvsp[0].string)[0] != '~') {
				if (strcmp((yyvsp[0].string), "*") != 0) {
				    sudoerserror(N_("values for \"CWD\" must"
					" start with a '/', '~', or '*'"));
				    YYERROR;
				}
			    }
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2196 "gram.c" /* yacc.c:1652  */
    break;

  case 56:
#line 587 "gram.y" /* yacc.c:1652  */
    {
			    if ((yyvsp[0].string)[0] != '/' && (yyvsp[0].string)[0] != '~') {
				if (strcmp((yyvsp[0].string), "*") != 0) {
				    sudoerserror(N_("values for \"CHROOT\" must"
					" start with a '/', '~', or '*'"));
				    YYERROR;
				}
			    }
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2211 "gram.c" /* yacc.c:1652  */
    break;

  case 57:
#line 599 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2219 "gram.c" /* yacc.c:1652  */
    break;

  case 58:
#line 604 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2227 "gram.c" /* yacc.c:1652  */
    break;

  case 59:
#line 608 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2235 "gram.c" /* yacc.c:1652  */
    break;

  case 60:
#line 613 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2243 "gram.c" /* yacc.c:1652  */
    break;

  case 61:
#line 618 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2251 "gram.c" /* yacc.c:1652  */
    break;

  case 62:
#line 623 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2259 "gram.c" /* yacc.c:1652  */
    break;

  case 63:
#line 627 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2267 "gram.c" /* yacc.c:1652  */
    break;

  case 64:
#line 632 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.runas) = NULL;
			}
#line 2275 "gram.c" /* yacc.c:1652  */
    break;

  case 65:
#line 635 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.runas) = (yyvsp[-1].runas);
			}
#line 2283 "gram.c" /* yacc.c:1652  */
    break;

  case 66:
#line 640 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) != NULL) {
				(yyval.runas)->runasusers = new_member(NULL, MYSELF);
				/* $$->runasgroups = NULL; */
				if ((yyval.runas)->runasusers == NULL) {
				    free((yyval.runas));
				    (yyval.runas) = NULL;
				}
			    }
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2303 "gram.c" /* yacc.c:1652  */
    break;

  case 67:
#line 655 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    (yyval.runas)->runasusers = (yyvsp[0].member);
			    /* $$->runasgroups = NULL; */
			}
#line 2317 "gram.c" /* yacc.c:1652  */
    break;

  case 68:
#line 664 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    (yyval.runas)->runasusers = (yyvsp[-2].member);
			    (yyval.runas)->runasgroups = (yyvsp[0].member);
			}
#line 2331 "gram.c" /* yacc.c:1652  */
    break;

  case 69:
#line 673 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    /* $$->runasusers = NULL; */
			    (yyval.runas)->runasgroups = (yyvsp[0].member);
			}
#line 2345 "gram.c" /* yacc.c:1652  */
    break;

  case 70:
#line 682 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) != NULL) {
				(yyval.runas)->runasusers = new_member(NULL, MYSELF);
				/* $$->runasgroups = NULL; */
				if ((yyval.runas)->runasusers == NULL) {
				    free((yyval.runas));
				    (yyval.runas) = NULL;
				}
			    }
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2365 "gram.c" /* yacc.c:1652  */
    break;

  case 81:
#line 711 "gram.y" /* yacc.c:1652  */
    {
			    sudoerserror(N_("syntax error, reserved word used as an alias name"));
			    YYERROR;
			}
#line 2374 "gram.c" /* yacc.c:1652  */
    break;

  case 82:
#line 717 "gram.y" /* yacc.c:1652  */
    {
			    init_options(&(yyval.options));
			}
#line 2382 "gram.c" /* yacc.c:1652  */
    break;

  case 83:
#line 720 "gram.y" /* yacc.c:1652  */
    {
			    free((yyval.options).runcwd);
			    (yyval.options).runcwd = (yyvsp[0].string);
			}
#line 2391 "gram.c" /* yacc.c:1652  */
    break;

  case 84:
#line 724 "gram.y" /* yacc.c:1652  */
    {
			    free((yyval.options).runchroot);
			    (yyval.options).runchroot = (yyvsp[0].string);
			}
#line 2400 "gram.c" /* yacc.c:1652  */
    break;

  case 85:
#line 728 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.options).notbefore = parse_gentime((yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).notbefore == -1) {
				sudoerserror(N_("invalid notbefore value"));
				YYERROR;
			    }
			}
#line 2413 "gram.c" /* yacc.c:1652  */
    break;

  case 86:
#line 736 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.options).notafter = parse_gentime((yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).notafter == -1) {
				sudoerserror(N_("invalid notafter value"));
				YYERROR;
			    }
			}
#line 2426 "gram.c" /* yacc.c:1652  */
    break;

  case 87:
#line 744 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.options).timeout = parse_timeout((yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).timeout == -1) {
				if (errno == ERANGE)
				    sudoerserror(N_("timeout value too large"));
				else
				    sudoerserror(N_("invalid timeout value"));
				YYERROR;
			    }
			}
#line 2442 "gram.c" /* yacc.c:1652  */
    break;

  case 88:
#line 755 "gram.y" /* yacc.c:1652  */
    {
#ifdef HAVE_SELINUX
			    free((yyval.options).role);
			    (yyval.options).role = (yyvsp[0].string);
#endif
			}
#line 2453 "gram.c" /* yacc.c:1652  */
    break;

  case 89:
#line 761 "gram.y" /* yacc.c:1652  */
    {
#ifdef HAVE_SELINUX
			    free((yyval.options).type);
			    (yyval.options).type = (yyvsp[0].string);
#endif
			}
#line 2464 "gram.c" /* yacc.c:1652  */
    break;

  case 90:
#line 767 "gram.y" /* yacc.c:1652  */
    {
#ifdef HAVE_PRIV_SET
			    free((yyval.options).privs);
			    (yyval.options).privs = (yyvsp[0].string);
#endif
			}
#line 2475 "gram.c" /* yacc.c:1652  */
    break;

  case 91:
#line 773 "gram.y" /* yacc.c:1652  */
    {
#ifdef HAVE_PRIV_SET
			    free((yyval.options).limitprivs);
			    (yyval.options).limitprivs = (yyvsp[0].string);
#endif
			}
#line 2486 "gram.c" /* yacc.c:1652  */
    break;

  case 92:
#line 781 "gram.y" /* yacc.c:1652  */
    {
			    TAGS_INIT((yyval.tag));
			}
#line 2494 "gram.c" /* yacc.c:1652  */
    break;

  case 93:
#line 784 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).nopasswd = true;
			}
#line 2502 "gram.c" /* yacc.c:1652  */
    break;

  case 94:
#line 787 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).nopasswd = false;
			}
#line 2510 "gram.c" /* yacc.c:1652  */
    break;

  case 95:
#line 790 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).noexec = true;
			}
#line 2518 "gram.c" /* yacc.c:1652  */
    break;

  case 96:
#line 793 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).noexec = false;
			}
#line 2526 "gram.c" /* yacc.c:1652  */
    break;

  case 97:
#line 796 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).setenv = true;
			}
#line 2534 "gram.c" /* yacc.c:1652  */
    break;

  case 98:
#line 799 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).setenv = false;
			}
#line 2542 "gram.c" /* yacc.c:1652  */
    break;

  case 99:
#line 802 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).log_input = true;
			}
#line 2550 "gram.c" /* yacc.c:1652  */
    break;

  case 100:
#line 805 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).log_input = false;
			}
#line 2558 "gram.c" /* yacc.c:1652  */
    break;

  case 101:
#line 808 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).log_output = true;
			}
#line 2566 "gram.c" /* yacc.c:1652  */
    break;

  case 102:
#line 811 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).log_output = false;
			}
#line 2574 "gram.c" /* yacc.c:1652  */
    break;

  case 103:
#line 814 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).follow = true;
			}
#line 2582 "gram.c" /* yacc.c:1652  */
    break;

  case 104:
#line 817 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).follow = false;
			}
#line 2590 "gram.c" /* yacc.c:1652  */
    break;

  case 105:
#line 820 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).send_mail = true;
			}
#line 2598 "gram.c" /* yacc.c:1652  */
    break;

  case 106:
#line 823 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.tag).send_mail = false;
			}
#line 2606 "gram.c" /* yacc.c:1652  */
    break;

  case 107:
#line 828 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2618 "gram.c" /* yacc.c:1652  */
    break;

  case 108:
#line 835 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2630 "gram.c" /* yacc.c:1652  */
    break;

  case 109:
#line 842 "gram.y" /* yacc.c:1652  */
    {
			    struct sudo_command *c;

			    if ((c = new_command((yyvsp[0].command).cmnd, (yyvsp[0].command).args)) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    (yyval.member) = new_member((char *)c, COMMAND);
			    if ((yyval.member) == NULL) {
				free(c);
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2649 "gram.c" /* yacc.c:1652  */
    break;

  case 112:
#line 862 "gram.y" /* yacc.c:1652  */
    {
			    const char *s;
			    s = alias_add(&parsed_policy, (yyvsp[-2].string), HOSTALIAS,
				sudoers, this_lineno, (yyvsp[0].member));
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
#line 2663 "gram.c" /* yacc.c:1652  */
    break;

  case 115:
#line 875 "gram.y" /* yacc.c:1652  */
    {
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2672 "gram.c" /* yacc.c:1652  */
    break;

  case 118:
#line 885 "gram.y" /* yacc.c:1652  */
    {
			    const char *s;
			    s = alias_add(&parsed_policy, (yyvsp[-2].string), CMNDALIAS,
				sudoers, this_lineno, (yyvsp[0].member));
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
#line 2686 "gram.c" /* yacc.c:1652  */
    break;

  case 121:
#line 898 "gram.y" /* yacc.c:1652  */
    {
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2695 "gram.c" /* yacc.c:1652  */
    break;

  case 124:
#line 908 "gram.y" /* yacc.c:1652  */
    {
			    const char *s;
			    s = alias_add(&parsed_policy, (yyvsp[-2].string), RUNASALIAS,
				sudoers, this_lineno, (yyvsp[0].member));
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
#line 2709 "gram.c" /* yacc.c:1652  */
    break;

  case 128:
#line 924 "gram.y" /* yacc.c:1652  */
    {
			    const char *s;
			    s = alias_add(&parsed_policy, (yyvsp[-2].string), USERALIAS,
				sudoers, this_lineno, (yyvsp[0].member));
			    if (s != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
#line 2723 "gram.c" /* yacc.c:1652  */
    break;

  case 131:
#line 937 "gram.y" /* yacc.c:1652  */
    {
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2732 "gram.c" /* yacc.c:1652  */
    break;

  case 132:
#line 943 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 2741 "gram.c" /* yacc.c:1652  */
    break;

  case 133:
#line 947 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 2750 "gram.c" /* yacc.c:1652  */
    break;

  case 134:
#line 953 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2762 "gram.c" /* yacc.c:1652  */
    break;

  case 135:
#line 960 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2774 "gram.c" /* yacc.c:1652  */
    break;

  case 136:
#line 967 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), NETGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2786 "gram.c" /* yacc.c:1652  */
    break;

  case 137:
#line 974 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), USERGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2798 "gram.c" /* yacc.c:1652  */
    break;

  case 138:
#line 981 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2810 "gram.c" /* yacc.c:1652  */
    break;

  case 140:
#line 991 "gram.y" /* yacc.c:1652  */
    {
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2819 "gram.c" /* yacc.c:1652  */
    break;

  case 141:
#line 997 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 2828 "gram.c" /* yacc.c:1652  */
    break;

  case 142:
#line 1001 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 2837 "gram.c" /* yacc.c:1652  */
    break;

  case 143:
#line 1007 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2849 "gram.c" /* yacc.c:1652  */
    break;

  case 144:
#line 1014 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2861 "gram.c" /* yacc.c:1652  */
    break;

  case 145:
#line 1021 "gram.y" /* yacc.c:1652  */
    {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2873 "gram.c" /* yacc.c:1652  */
    break;


#line 2877 "gram.c" /* yacc.c:1652  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;


#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif


/*-----------------------------------------------------.
| yyreturn -- parsing is finished, return the result.  |
`-----------------------------------------------------*/
yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 1029 "gram.y" /* yacc.c:1918  */

void
sudoerserror(const char *s)
{
    debug_decl(sudoerserror, SUDOERS_DEBUG_PARSER);

    /* The lexer displays more detailed messages for ERROR tokens. */
    if (sudoerschar == ERROR)
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
	    runchroot = cs->runchroot;
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
    opts->runchroot = NULL;
    opts->runcwd = NULL;
#ifdef HAVE_SELINUX
    opts->role = NULL;
    opts->type = NULL;
#endif
#ifdef HAVE_PRIV_SET
    opts->privs = NULL;
    opts->limitprivs = NULL;
#endif
}
