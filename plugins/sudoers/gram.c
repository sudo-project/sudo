/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>
/* A Bison parser, made by GNU Bison 3.7.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2020 Free Software Foundation,
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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30704

/* Bison version string.  */
#define YYBISON_VERSION "3.7.4"

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
#line 1 "gram.y"

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

// PVS Studio suppression
// -V::1037, 1042

/*
 * Globals
 */
bool sudoers_warnings = true;
bool sudoers_strict = false;
bool parse_error = false;
int errorlineno = -1;
char *errorfile = NULL;

static int alias_line, alias_column;

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
static void alias_error(const char *name, int errnum);

#line 160 "gram.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
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

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_SUDOERS_Y_TAB_H_INCLUDED
# define YY_SUDOERS_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int sudoersdebug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    COMMAND = 258,                 /* COMMAND  */
    ALIAS = 259,                   /* ALIAS  */
    DEFVAR = 260,                  /* DEFVAR  */
    NTWKADDR = 261,                /* NTWKADDR  */
    NETGROUP = 262,                /* NETGROUP  */
    USERGROUP = 263,               /* USERGROUP  */
    WORD = 264,                    /* WORD  */
    DIGEST = 265,                  /* DIGEST  */
    INCLUDE = 266,                 /* INCLUDE  */
    INCLUDEDIR = 267,              /* INCLUDEDIR  */
    DEFAULTS = 268,                /* DEFAULTS  */
    DEFAULTS_HOST = 269,           /* DEFAULTS_HOST  */
    DEFAULTS_USER = 270,           /* DEFAULTS_USER  */
    DEFAULTS_RUNAS = 271,          /* DEFAULTS_RUNAS  */
    DEFAULTS_CMND = 272,           /* DEFAULTS_CMND  */
    NOPASSWD = 273,                /* NOPASSWD  */
    PASSWD = 274,                  /* PASSWD  */
    NOEXEC = 275,                  /* NOEXEC  */
    EXEC = 276,                    /* EXEC  */
    SETENV = 277,                  /* SETENV  */
    NOSETENV = 278,                /* NOSETENV  */
    LOG_INPUT = 279,               /* LOG_INPUT  */
    NOLOG_INPUT = 280,             /* NOLOG_INPUT  */
    LOG_OUTPUT = 281,              /* LOG_OUTPUT  */
    NOLOG_OUTPUT = 282,            /* NOLOG_OUTPUT  */
    MAIL = 283,                    /* MAIL  */
    NOMAIL = 284,                  /* NOMAIL  */
    FOLLOWLNK = 285,               /* FOLLOWLNK  */
    NOFOLLOWLNK = 286,             /* NOFOLLOWLNK  */
    ALL = 287,                     /* ALL  */
    HOSTALIAS = 288,               /* HOSTALIAS  */
    CMNDALIAS = 289,               /* CMNDALIAS  */
    USERALIAS = 290,               /* USERALIAS  */
    RUNASALIAS = 291,              /* RUNASALIAS  */
    ERROR = 292,                   /* ERROR  */
    NOMATCH = 293,                 /* NOMATCH  */
    CHROOT = 294,                  /* CHROOT  */
    CWD = 295,                     /* CWD  */
    TYPE = 296,                    /* TYPE  */
    ROLE = 297,                    /* ROLE  */
    PRIVS = 298,                   /* PRIVS  */
    LIMITPRIVS = 299,              /* LIMITPRIVS  */
    CMND_TIMEOUT = 300,            /* CMND_TIMEOUT  */
    NOTBEFORE = 301,               /* NOTBEFORE  */
    NOTAFTER = 302,                /* NOTAFTER  */
    MYSELF = 303,                  /* MYSELF  */
    SHA224_TOK = 304,              /* SHA224_TOK  */
    SHA256_TOK = 305,              /* SHA256_TOK  */
    SHA384_TOK = 306,              /* SHA384_TOK  */
    SHA512_TOK = 307               /* SHA512_TOK  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
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
#line 83 "gram.y"

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

#line 331 "gram.c"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE sudoerslval;

int sudoersparse (void);

#endif /* !YY_SUDOERS_Y_TAB_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_COMMAND = 3,                    /* COMMAND  */
  YYSYMBOL_ALIAS = 4,                      /* ALIAS  */
  YYSYMBOL_DEFVAR = 5,                     /* DEFVAR  */
  YYSYMBOL_NTWKADDR = 6,                   /* NTWKADDR  */
  YYSYMBOL_NETGROUP = 7,                   /* NETGROUP  */
  YYSYMBOL_USERGROUP = 8,                  /* USERGROUP  */
  YYSYMBOL_WORD = 9,                       /* WORD  */
  YYSYMBOL_DIGEST = 10,                    /* DIGEST  */
  YYSYMBOL_INCLUDE = 11,                   /* INCLUDE  */
  YYSYMBOL_INCLUDEDIR = 12,                /* INCLUDEDIR  */
  YYSYMBOL_DEFAULTS = 13,                  /* DEFAULTS  */
  YYSYMBOL_DEFAULTS_HOST = 14,             /* DEFAULTS_HOST  */
  YYSYMBOL_DEFAULTS_USER = 15,             /* DEFAULTS_USER  */
  YYSYMBOL_DEFAULTS_RUNAS = 16,            /* DEFAULTS_RUNAS  */
  YYSYMBOL_DEFAULTS_CMND = 17,             /* DEFAULTS_CMND  */
  YYSYMBOL_NOPASSWD = 18,                  /* NOPASSWD  */
  YYSYMBOL_PASSWD = 19,                    /* PASSWD  */
  YYSYMBOL_NOEXEC = 20,                    /* NOEXEC  */
  YYSYMBOL_EXEC = 21,                      /* EXEC  */
  YYSYMBOL_SETENV = 22,                    /* SETENV  */
  YYSYMBOL_NOSETENV = 23,                  /* NOSETENV  */
  YYSYMBOL_LOG_INPUT = 24,                 /* LOG_INPUT  */
  YYSYMBOL_NOLOG_INPUT = 25,               /* NOLOG_INPUT  */
  YYSYMBOL_LOG_OUTPUT = 26,                /* LOG_OUTPUT  */
  YYSYMBOL_NOLOG_OUTPUT = 27,              /* NOLOG_OUTPUT  */
  YYSYMBOL_MAIL = 28,                      /* MAIL  */
  YYSYMBOL_NOMAIL = 29,                    /* NOMAIL  */
  YYSYMBOL_FOLLOWLNK = 30,                 /* FOLLOWLNK  */
  YYSYMBOL_NOFOLLOWLNK = 31,               /* NOFOLLOWLNK  */
  YYSYMBOL_ALL = 32,                       /* ALL  */
  YYSYMBOL_HOSTALIAS = 33,                 /* HOSTALIAS  */
  YYSYMBOL_CMNDALIAS = 34,                 /* CMNDALIAS  */
  YYSYMBOL_USERALIAS = 35,                 /* USERALIAS  */
  YYSYMBOL_RUNASALIAS = 36,                /* RUNASALIAS  */
  YYSYMBOL_37_ = 37,                       /* ':'  */
  YYSYMBOL_38_ = 38,                       /* '='  */
  YYSYMBOL_39_ = 39,                       /* ','  */
  YYSYMBOL_40_ = 40,                       /* '!'  */
  YYSYMBOL_41_ = 41,                       /* '+'  */
  YYSYMBOL_42_ = 42,                       /* '-'  */
  YYSYMBOL_43_ = 43,                       /* '('  */
  YYSYMBOL_44_ = 44,                       /* ')'  */
  YYSYMBOL_45_n_ = 45,                     /* '\n'  */
  YYSYMBOL_ERROR = 46,                     /* ERROR  */
  YYSYMBOL_NOMATCH = 47,                   /* NOMATCH  */
  YYSYMBOL_CHROOT = 48,                    /* CHROOT  */
  YYSYMBOL_CWD = 49,                       /* CWD  */
  YYSYMBOL_TYPE = 50,                      /* TYPE  */
  YYSYMBOL_ROLE = 51,                      /* ROLE  */
  YYSYMBOL_PRIVS = 52,                     /* PRIVS  */
  YYSYMBOL_LIMITPRIVS = 53,                /* LIMITPRIVS  */
  YYSYMBOL_CMND_TIMEOUT = 54,              /* CMND_TIMEOUT  */
  YYSYMBOL_NOTBEFORE = 55,                 /* NOTBEFORE  */
  YYSYMBOL_NOTAFTER = 56,                  /* NOTAFTER  */
  YYSYMBOL_MYSELF = 57,                    /* MYSELF  */
  YYSYMBOL_SHA224_TOK = 58,                /* SHA224_TOK  */
  YYSYMBOL_SHA256_TOK = 59,                /* SHA256_TOK  */
  YYSYMBOL_SHA384_TOK = 60,                /* SHA384_TOK  */
  YYSYMBOL_SHA512_TOK = 61,                /* SHA512_TOK  */
  YYSYMBOL_YYACCEPT = 62,                  /* $accept  */
  YYSYMBOL_file = 63,                      /* file  */
  YYSYMBOL_line = 64,                      /* line  */
  YYSYMBOL_entry = 65,                     /* entry  */
  YYSYMBOL_include = 66,                   /* include  */
  YYSYMBOL_includedir = 67,                /* includedir  */
  YYSYMBOL_defaults_list = 68,             /* defaults_list  */
  YYSYMBOL_defaults_entry = 69,            /* defaults_entry  */
  YYSYMBOL_privileges = 70,                /* privileges  */
  YYSYMBOL_privilege = 71,                 /* privilege  */
  YYSYMBOL_ophost = 72,                    /* ophost  */
  YYSYMBOL_host = 73,                      /* host  */
  YYSYMBOL_cmndspeclist = 74,              /* cmndspeclist  */
  YYSYMBOL_cmndspec = 75,                  /* cmndspec  */
  YYSYMBOL_digestspec = 76,                /* digestspec  */
  YYSYMBOL_digestlist = 77,                /* digestlist  */
  YYSYMBOL_digcmnd = 78,                   /* digcmnd  */
  YYSYMBOL_opcmnd = 79,                    /* opcmnd  */
  YYSYMBOL_chdirspec = 80,                 /* chdirspec  */
  YYSYMBOL_chrootspec = 81,                /* chrootspec  */
  YYSYMBOL_timeoutspec = 82,               /* timeoutspec  */
  YYSYMBOL_notbeforespec = 83,             /* notbeforespec  */
  YYSYMBOL_notafterspec = 84,              /* notafterspec  */
  YYSYMBOL_rolespec = 85,                  /* rolespec  */
  YYSYMBOL_typespec = 86,                  /* typespec  */
  YYSYMBOL_privsspec = 87,                 /* privsspec  */
  YYSYMBOL_limitprivsspec = 88,            /* limitprivsspec  */
  YYSYMBOL_runasspec = 89,                 /* runasspec  */
  YYSYMBOL_runaslist = 90,                 /* runaslist  */
  YYSYMBOL_reserved_word = 91,             /* reserved_word  */
  YYSYMBOL_reserved_alias = 92,            /* reserved_alias  */
  YYSYMBOL_options = 93,                   /* options  */
  YYSYMBOL_cmndtag = 94,                   /* cmndtag  */
  YYSYMBOL_cmnd = 95,                      /* cmnd  */
  YYSYMBOL_hostaliases = 96,               /* hostaliases  */
  YYSYMBOL_hostalias = 97,                 /* hostalias  */
  YYSYMBOL_98_1 = 98,                      /* $@1  */
  YYSYMBOL_hostlist = 99,                  /* hostlist  */
  YYSYMBOL_cmndaliases = 100,              /* cmndaliases  */
  YYSYMBOL_cmndalias = 101,                /* cmndalias  */
  YYSYMBOL_102_2 = 102,                    /* $@2  */
  YYSYMBOL_cmndlist = 103,                 /* cmndlist  */
  YYSYMBOL_runasaliases = 104,             /* runasaliases  */
  YYSYMBOL_runasalias = 105,               /* runasalias  */
  YYSYMBOL_106_3 = 106,                    /* $@3  */
  YYSYMBOL_useraliases = 107,              /* useraliases  */
  YYSYMBOL_useralias = 108,                /* useralias  */
  YYSYMBOL_109_4 = 109,                    /* $@4  */
  YYSYMBOL_userlist = 110,                 /* userlist  */
  YYSYMBOL_opuser = 111,                   /* opuser  */
  YYSYMBOL_user = 112,                     /* user  */
  YYSYMBOL_grouplist = 113,                /* grouplist  */
  YYSYMBOL_opgroup = 114,                  /* opgroup  */
  YYSYMBOL_group = 115                     /* group  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_uint8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

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


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && ! defined __ICC && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                            \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
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

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if !defined yyoverflow

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
#endif /* !defined yyoverflow */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
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
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
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
#define YYLAST   320

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  62
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  54
/* YYNRULES -- Number of rules.  */
#define YYNRULES  149
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  248

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   307


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
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
static const yytype_int16 yyrline[] =
{
       0,   192,   192,   195,   198,   199,   202,   205,   208,   215,
     222,   228,   231,   234,   237,   240,   244,   248,   252,   256,
     262,   265,   271,   274,   280,   281,   287,   294,   301,   308,
     315,   324,   325,   329,   335,   349,   353,   359,   366,   373,
     380,   387,   396,   397,   456,   511,   518,   525,   532,   541,
     542,   548,   551,   572,   576,   582,   594,   606,   611,   615,
     620,   625,   630,   634,   639,   642,   647,   662,   671,   680,
     689,   706,   707,   708,   709,   710,   711,   712,   713,   714,
     715,   718,   724,   727,   731,   735,   743,   751,   762,   768,
     774,   780,   788,   791,   794,   797,   800,   803,   806,   809,
     812,   815,   818,   821,   824,   827,   830,   835,   842,   849,
     865,   866,   869,   869,   879,   882,   883,   889,   890,   893,
     893,   903,   906,   907,   913,   914,   917,   917,   927,   930,
     931,   934,   934,   944,   947,   948,   954,   958,   964,   971,
     978,   985,   992,  1001,  1002,  1008,  1012,  1018,  1025,  1032
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if YYDEBUG || 0
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "COMMAND", "ALIAS",
  "DEFVAR", "NTWKADDR", "NETGROUP", "USERGROUP", "WORD", "DIGEST",
  "INCLUDE", "INCLUDEDIR", "DEFAULTS", "DEFAULTS_HOST", "DEFAULTS_USER",
  "DEFAULTS_RUNAS", "DEFAULTS_CMND", "NOPASSWD", "PASSWD", "NOEXEC",
  "EXEC", "SETENV", "NOSETENV", "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT",
  "NOLOG_OUTPUT", "MAIL", "NOMAIL", "FOLLOWLNK", "NOFOLLOWLNK", "ALL",
  "HOSTALIAS", "CMNDALIAS", "USERALIAS", "RUNASALIAS", "':'", "'='", "','",
  "'!'", "'+'", "'-'", "'('", "')'", "'\\n'", "ERROR", "NOMATCH", "CHROOT",
  "CWD", "TYPE", "ROLE", "PRIVS", "LIMITPRIVS", "CMND_TIMEOUT",
  "NOTBEFORE", "NOTAFTER", "MYSELF", "SHA224_TOK", "SHA256_TOK",
  "SHA384_TOK", "SHA512_TOK", "$accept", "file", "line", "entry",
  "include", "includedir", "defaults_list", "defaults_entry", "privileges",
  "privilege", "ophost", "host", "cmndspeclist", "cmndspec", "digestspec",
  "digestlist", "digcmnd", "opcmnd", "chdirspec", "chrootspec",
  "timeoutspec", "notbeforespec", "notafterspec", "rolespec", "typespec",
  "privsspec", "limitprivsspec", "runasspec", "runaslist", "reserved_word",
  "reserved_alias", "options", "cmndtag", "cmnd", "hostaliases",
  "hostalias", "$@1", "hostlist", "cmndaliases", "cmndalias", "$@2",
  "cmndlist", "runasaliases", "runasalias", "$@3", "useraliases",
  "useralias", "$@4", "userlist", "opuser", "user", "grouplist", "opgroup",
  "group", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_int16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,    58,    61,    44,
      33,    43,    45,    40,    41,    10,   292,   293,   294,   295,
     296,   297,   298,   299,   300,   301,   302,   303,   304,   305,
     306,   307
};
#endif

#define YYPACT_NINF (-114)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-4)

#define yytable_value_is_error(Yyn) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     178,   -11,  -114,  -114,  -114,  -114,    27,    44,     9,   240,
     148,   148,     6,  -114,    31,    40,   112,   121,   193,  -114,
      75,   220,  -114,  -114,  -114,    95,  -114,  -114,  -114,    10,
      11,    16,    73,    32,  -114,  -114,  -114,  -114,  -114,  -114,
     255,  -114,  -114,     8,    12,    12,  -114,  -114,  -114,   106,
      63,    70,    74,    89,  -114,    66,  -114,  -114,  -114,    34,
    -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
    -114,  -114,   107,    77,  -114,  -114,   120,    83,  -114,  -114,
     143,    87,  -114,  -114,   158,    92,  -114,  -114,  -114,  -114,
     148,   105,  -114,   145,    88,  -114,   102,  -114,   189,   190,
     197,  -114,     9,  -114,  -114,   240,    91,   101,   104,  -114,
     198,   206,   207,   212,   209,  -114,     6,   170,   169,   240,
      31,  -114,   188,     6,    40,  -114,   192,   148,   112,  -114,
     201,   148,   121,  -114,  -114,    36,  -114,   202,  -114,  -114,
    -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
    -114,  -114,  -114,  -114,  -114,   240,   211,  -114,     6,   218,
    -114,   148,   219,  -114,   148,   219,  -114,  -114,  -114,   234,
     224,  -114,  -114,   211,   218,   219,   219,    99,   196,   -21,
     202,   241,  -114,  -114,  -114,   109,   236,  -114,  -114,  -114,
      99,  -114,   210,   213,   235,   238,   239,   243,   244,   245,
     246,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
       1,  -114,    99,   236,   269,   270,   276,   277,   279,   289,
     290,   291,   292,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
    -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
    -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     0,   138,   140,   141,   142,     0,     0,     0,     0,
       0,     0,     0,   139,     0,     0,     0,     0,     0,     6,
       0,     0,     4,     8,     9,     0,   134,   136,     7,     0,
       0,    26,     0,     0,    24,    37,    40,    39,    41,    38,
       0,   115,    35,     0,     0,     0,   109,   108,   107,     0,
       0,     0,     0,     0,    49,     0,   122,    51,    53,     0,
     112,    71,    72,    73,    78,    77,    79,    80,    74,    75,
      76,    81,     0,     0,   110,   119,     0,     0,   117,   131,
       0,     0,   129,   126,     0,     0,   124,   137,     1,     5,
       0,     0,    31,     0,     0,    20,     0,    22,     0,     0,
       0,    27,     0,    15,    36,     0,     0,     0,     0,    54,
       0,     0,     0,     0,     0,    52,     0,     0,     0,     0,
       0,    12,     0,     0,     0,    13,     0,     0,     0,    11,
       0,     0,     0,    14,   135,     0,    10,    64,    21,    23,
      28,    29,    30,    25,   116,    18,    16,    17,    45,    46,
      47,    48,    50,   123,    19,     0,   114,   111,     0,   121,
     118,     0,   133,   130,     0,   128,   125,    33,    32,    66,
      34,    42,    82,   113,   120,   132,   127,    70,     0,    67,
      64,    92,   147,   149,   148,     0,    69,   143,   145,    65,
       0,    43,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    83,    84,    87,    85,    86,    88,    89,    90,    91,
       0,   146,     0,    68,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    93,    94,    95,    96,    97,    98,    99,
     100,   101,   102,   105,   106,   103,   104,    44,   144,    56,
      55,    61,    60,    62,    63,    57,    58,    59
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -114,  -114,  -114,   281,  -114,  -114,   160,   203,  -114,   168,
     199,   266,  -114,   127,   194,  -114,  -113,   254,  -114,  -114,
    -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
      -9,  -114,  -114,   261,  -114,   191,  -114,    -7,  -114,   195,
    -114,  -108,  -114,   180,  -114,  -114,   185,  -114,   -10,   225,
     296,   126,   108,   132
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,    20,    21,    22,    23,    24,    33,    34,    91,    92,
      41,    42,   170,   171,    54,    55,    56,    57,   201,   202,
     203,   204,   205,   206,   207,   208,   209,   172,   178,    71,
      72,   181,   210,    58,    73,    74,   118,    93,    77,    78,
     122,    59,    85,    86,   130,    81,    82,   126,    25,    26,
      27,   186,   187,   188
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      44,    45,    43,   153,    46,    47,    76,    80,    84,    46,
      47,    94,    96,    31,    31,   159,   190,    31,    90,   223,
     224,   225,   226,   227,   228,   229,   230,   231,   232,   233,
     234,   235,   236,    48,    28,    60,    29,   167,    48,    31,
      35,    49,    36,    37,    75,    38,    49,   105,    32,    32,
     174,    90,    32,    30,    98,    95,    97,    99,   100,    50,
      51,    52,    53,    61,    50,    51,    52,    53,    39,    46,
      47,   102,    61,   116,    32,    88,    40,   103,   101,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    62,    63,
      64,    65,    66,    67,    68,    69,    70,   237,    48,    35,
     110,    36,    37,   182,    38,   114,    49,   111,   183,    46,
      47,   112,   156,   182,   120,    76,    79,   162,   183,    80,
     124,   165,   121,    84,   128,    83,   113,    39,   125,   132,
     102,   184,   129,   138,    90,    40,   145,   133,    48,   185,
     102,   184,   135,   102,    61,   119,   146,   139,   173,   147,
     136,   175,     2,    61,   176,     3,     4,     5,   123,   179,
      62,    63,    64,    65,    66,    67,    68,    69,    70,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    -2,     1,
      13,   127,     2,   137,   105,     3,     4,     5,    18,     6,
       7,     8,     9,    10,    11,    12,   131,     2,   140,   141,
       3,     4,     5,   106,   107,   108,   142,   155,   148,   102,
      13,    14,    15,    16,    17,   154,   149,   150,    18,   117,
      -3,     1,   151,    19,     2,    13,   158,     3,     4,     5,
     161,     6,     7,     8,     9,    10,    11,    12,     2,   164,
     189,     3,     4,     5,    35,   169,    36,    37,   214,    38,
     105,   215,    13,    14,    15,    16,    17,   116,    90,    35,
      18,    36,    37,   180,    38,    19,    13,    50,    51,    52,
      53,   177,    39,   216,    18,   212,   217,   218,   239,   240,
      40,   219,   220,   221,   222,   241,   242,    39,   243,   192,
     193,   194,   195,   196,   197,   198,   199,   200,   244,   245,
     246,   247,    89,   168,   144,   143,   104,   191,   152,   115,
     109,   157,   166,   163,    87,   134,   213,   211,     0,   160,
     238
};

static const yytype_int16 yycheck[] =
{
      10,    11,     9,   116,     3,     4,    15,    16,    17,     3,
       4,     1,     1,     5,     5,   123,    37,     5,    39,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    45,     4,     9,     1,    32,     5,
       4,    40,     6,     7,     4,     9,    40,    39,    40,    40,
     158,    39,    40,     9,    38,    45,    45,    41,    42,    58,
      59,    60,    61,    32,    58,    59,    60,    61,    32,     3,
       4,    39,    32,    39,    40,     0,    40,    45,     5,    48,
      49,    50,    51,    52,    53,    54,    55,    56,    48,    49,
      50,    51,    52,    53,    54,    55,    56,   210,    32,     4,
      37,     6,     7,     4,     9,    39,    40,    37,     9,     3,
       4,    37,   119,     4,    37,   124,     4,   127,     9,   128,
      37,   131,    45,   132,    37,     4,    37,    32,    45,    37,
      39,    32,    45,    45,    39,    40,    45,    45,    32,    40,
      39,    32,    37,    39,    32,    38,    45,    45,   155,    45,
      45,   161,     4,    32,   164,     7,     8,     9,    38,   169,
      48,    49,    50,    51,    52,    53,    54,    55,    56,    48,
      49,    50,    51,    52,    53,    54,    55,    56,     0,     1,
      32,    38,     4,    38,    39,     7,     8,     9,    40,    11,
      12,    13,    14,    15,    16,    17,    38,     4,     9,     9,
       7,     8,     9,    43,    44,    45,     9,    38,    10,    39,
      32,    33,    34,    35,    36,    45,    10,    10,    40,    59,
       0,     1,    10,    45,     4,    32,    38,     7,     8,     9,
      38,    11,    12,    13,    14,    15,    16,    17,     4,    38,
      44,     7,     8,     9,     4,    43,     6,     7,    38,     9,
      39,    38,    32,    33,    34,    35,    36,    39,    39,     4,
      40,     6,     7,    39,     9,    45,    32,    58,    59,    60,
      61,    37,    32,    38,    40,    39,    38,    38,     9,     9,
      40,    38,    38,    38,    38,     9,     9,    32,     9,    48,
      49,    50,    51,    52,    53,    54,    55,    56,     9,     9,
       9,     9,    21,   135,   105,   102,    40,   180,   114,    55,
      49,   120,   132,   128,    18,    90,   190,   185,    -1,   124,
     212
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     1,     4,     7,     8,     9,    11,    12,    13,    14,
      15,    16,    17,    32,    33,    34,    35,    36,    40,    45,
      63,    64,    65,    66,    67,   110,   111,   112,    45,     9,
       9,     5,    40,    68,    69,     4,     6,     7,     9,    32,
      40,    72,    73,    99,   110,   110,     3,     4,    32,    40,
      58,    59,    60,    61,    76,    77,    78,    79,    95,   103,
       4,    32,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    91,    92,    96,    97,     4,    92,   100,   101,     4,
      92,   107,   108,     4,    92,   104,   105,   112,     0,    65,
      39,    70,    71,    99,     1,    45,     1,    45,    38,    41,
      42,     5,    39,    45,    73,    39,    68,    68,    68,    95,
      37,    37,    37,    37,    39,    79,    39,    68,    98,    38,
      37,    45,   102,    38,    37,    45,   109,    38,    37,    45,
     106,    38,    37,    45,   111,    37,    45,    38,    45,    45,
       9,     9,     9,    69,    72,    45,    45,    45,    10,    10,
      10,    10,    76,    78,    45,    38,    99,    97,    38,   103,
     101,    38,   110,   108,    38,   110,   105,     1,    71,    43,
      74,    75,    89,    99,   103,   110,   110,    37,    90,   110,
      39,    93,     4,     9,    32,    40,   113,   114,   115,    44,
      37,    75,    48,    49,    50,    51,    52,    53,    54,    55,
      56,    80,    81,    82,    83,    84,    85,    86,    87,    88,
      94,   115,    39,   113,    38,    38,    38,    38,    38,    38,
      38,    38,    38,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    78,   114,     9,
       9,     9,     9,     9,     9,     9,     9,     9
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int8 yyr1[] =
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
      96,    96,    98,    97,    97,    99,    99,   100,   100,   102,
     101,   101,   103,   103,   104,   104,   106,   105,   105,   107,
     107,   109,   108,   108,   110,   110,   111,   111,   112,   112,
     112,   112,   112,   113,   113,   114,   114,   115,   115,   115
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_int8 yyr2[] =
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
       1,     3,     0,     4,     3,     1,     3,     1,     3,     0,
       4,     3,     1,     3,     1,     3,     0,     4,     3,     1,
       3,     0,     4,     3,     1,     3,     1,     2,     1,     1,
       1,     1,     1,     1,     3,     1,     2,     1,     1,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

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

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


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
# ifndef YY_LOCATION_PRINT
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif


# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  FILE *yyoutput = yyo;
  YYUSE (yyoutput);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yykind < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yykind], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
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
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)]);
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
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
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






/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep)
{
  YYUSE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/* Lookahead token kind.  */
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
    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

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
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    goto yyexhaustedlab;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
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
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */

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

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex ();
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
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
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
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
  case 2: /* file: %empty  */
#line 192 "gram.y"
                        {
			    ; /* empty file */
			}
#line 1624 "gram.c"
    break;

  case 6: /* entry: '\n'  */
#line 202 "gram.y"
                             {
			    ; /* blank line */
			}
#line 1632 "gram.c"
    break;

  case 7: /* entry: error '\n'  */
#line 205 "gram.y"
                                   {
			    yyerrok;
			}
#line 1640 "gram.c"
    break;

  case 8: /* entry: include  */
#line 208 "gram.y"
                                {
			    if (!push_include((yyvsp[0].string), false)) {
				free((yyvsp[0].string));
				YYERROR;
			    }
			    free((yyvsp[0].string));
			}
#line 1652 "gram.c"
    break;

  case 9: /* entry: includedir  */
#line 215 "gram.y"
                                   {
			    if (!push_include((yyvsp[0].string), true)) {
				free((yyvsp[0].string));
				YYERROR;
			    }
			    free((yyvsp[0].string));
			}
#line 1664 "gram.c"
    break;

  case 10: /* entry: userlist privileges '\n'  */
#line 222 "gram.y"
                                                 {
			    if (!add_userspec((yyvsp[-2].member), (yyvsp[-1].privilege))) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1675 "gram.c"
    break;

  case 11: /* entry: USERALIAS useraliases '\n'  */
#line 228 "gram.y"
                                                   {
			    ;
			}
#line 1683 "gram.c"
    break;

  case 12: /* entry: HOSTALIAS hostaliases '\n'  */
#line 231 "gram.y"
                                                   {
			    ;
			}
#line 1691 "gram.c"
    break;

  case 13: /* entry: CMNDALIAS cmndaliases '\n'  */
#line 234 "gram.y"
                                                   {
			    ;
			}
#line 1699 "gram.c"
    break;

  case 14: /* entry: RUNASALIAS runasaliases '\n'  */
#line 237 "gram.y"
                                                     {
			    ;
			}
#line 1707 "gram.c"
    break;

  case 15: /* entry: DEFAULTS defaults_list '\n'  */
#line 240 "gram.y"
                                                    {
			    if (!add_defaults(DEFAULTS, NULL, (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1716 "gram.c"
    break;

  case 16: /* entry: DEFAULTS_USER userlist defaults_list '\n'  */
#line 244 "gram.y"
                                                                  {
			    if (!add_defaults(DEFAULTS_USER, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1725 "gram.c"
    break;

  case 17: /* entry: DEFAULTS_RUNAS userlist defaults_list '\n'  */
#line 248 "gram.y"
                                                                   {
			    if (!add_defaults(DEFAULTS_RUNAS, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1734 "gram.c"
    break;

  case 18: /* entry: DEFAULTS_HOST hostlist defaults_list '\n'  */
#line 252 "gram.y"
                                                                  {
			    if (!add_defaults(DEFAULTS_HOST, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1743 "gram.c"
    break;

  case 19: /* entry: DEFAULTS_CMND cmndlist defaults_list '\n'  */
#line 256 "gram.y"
                                                                  {
			    if (!add_defaults(DEFAULTS_CMND, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1752 "gram.c"
    break;

  case 20: /* include: INCLUDE WORD '\n'  */
#line 262 "gram.y"
                                          {
			    (yyval.string) = (yyvsp[-1].string);
			}
#line 1760 "gram.c"
    break;

  case 21: /* include: INCLUDE WORD error '\n'  */
#line 265 "gram.y"
                                                {
			    yyerrok;
			    (yyval.string) = (yyvsp[-2].string);
			}
#line 1769 "gram.c"
    break;

  case 22: /* includedir: INCLUDEDIR WORD '\n'  */
#line 271 "gram.y"
                                             {
			    (yyval.string) = (yyvsp[-1].string);
			}
#line 1777 "gram.c"
    break;

  case 23: /* includedir: INCLUDEDIR WORD error '\n'  */
#line 274 "gram.y"
                                                   {
			    yyerrok;
			    (yyval.string) = (yyvsp[-2].string);
			}
#line 1786 "gram.c"
    break;

  case 25: /* defaults_list: defaults_list ',' defaults_entry  */
#line 281 "gram.y"
                                                         {
			    HLTQ_CONCAT((yyvsp[-2].defaults), (yyvsp[0].defaults), entries);
			    (yyval.defaults) = (yyvsp[-2].defaults);
			}
#line 1795 "gram.c"
    break;

  case 26: /* defaults_entry: DEFVAR  */
#line 287 "gram.y"
                               {
			    (yyval.defaults) = new_default((yyvsp[0].string), NULL, true);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1807 "gram.c"
    break;

  case 27: /* defaults_entry: '!' DEFVAR  */
#line 294 "gram.y"
                                   {
			    (yyval.defaults) = new_default((yyvsp[0].string), NULL, false);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1819 "gram.c"
    break;

  case 28: /* defaults_entry: DEFVAR '=' WORD  */
#line 301 "gram.y"
                                        {
			    (yyval.defaults) = new_default((yyvsp[-2].string), (yyvsp[0].string), true);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1831 "gram.c"
    break;

  case 29: /* defaults_entry: DEFVAR '+' WORD  */
#line 308 "gram.y"
                                        {
			    (yyval.defaults) = new_default((yyvsp[-2].string), (yyvsp[0].string), '+');
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1843 "gram.c"
    break;

  case 30: /* defaults_entry: DEFVAR '-' WORD  */
#line 315 "gram.y"
                                        {
			    (yyval.defaults) = new_default((yyvsp[-2].string), (yyvsp[0].string), '-');
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1855 "gram.c"
    break;

  case 32: /* privileges: privileges ':' privilege  */
#line 325 "gram.y"
                                                 {
			    HLTQ_CONCAT((yyvsp[-2].privilege), (yyvsp[0].privilege), entries);
			    (yyval.privilege) = (yyvsp[-2].privilege);
			}
#line 1864 "gram.c"
    break;

  case 33: /* privileges: privileges ':' error  */
#line 329 "gram.y"
                                             {
			    yyerrok;
			    (yyval.privilege) = (yyvsp[-2].privilege);
			}
#line 1873 "gram.c"
    break;

  case 34: /* privilege: hostlist '=' cmndspeclist  */
#line 335 "gram.y"
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
#line 1890 "gram.c"
    break;

  case 35: /* ophost: host  */
#line 349 "gram.y"
                             {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 1899 "gram.c"
    break;

  case 36: /* ophost: '!' host  */
#line 353 "gram.y"
                                 {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 1908 "gram.c"
    break;

  case 37: /* host: ALIAS  */
#line 359 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1920 "gram.c"
    break;

  case 38: /* host: ALL  */
#line 366 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1932 "gram.c"
    break;

  case 39: /* host: NETGROUP  */
#line 373 "gram.y"
                                 {
			    (yyval.member) = new_member((yyvsp[0].string), NETGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1944 "gram.c"
    break;

  case 40: /* host: NTWKADDR  */
#line 380 "gram.y"
                                 {
			    (yyval.member) = new_member((yyvsp[0].string), NTWKADDR);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1956 "gram.c"
    break;

  case 41: /* host: WORD  */
#line 387 "gram.y"
                             {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1968 "gram.c"
    break;

  case 43: /* cmndspeclist: cmndspeclist ',' cmndspec  */
#line 397 "gram.y"
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
#line 2030 "gram.c"
    break;

  case 44: /* cmndspec: runasspec options cmndtag digcmnd  */
#line 456 "gram.y"
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
#line 2088 "gram.c"
    break;

  case 45: /* digestspec: SHA224_TOK ':' DIGEST  */
#line 511 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA224, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2100 "gram.c"
    break;

  case 46: /* digestspec: SHA256_TOK ':' DIGEST  */
#line 518 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA256, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2112 "gram.c"
    break;

  case 47: /* digestspec: SHA384_TOK ':' DIGEST  */
#line 525 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA384, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2124 "gram.c"
    break;

  case 48: /* digestspec: SHA512_TOK ':' DIGEST  */
#line 532 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA512, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2136 "gram.c"
    break;

  case 50: /* digestlist: digestlist ',' digestspec  */
#line 542 "gram.y"
                                                  {
			    HLTQ_CONCAT((yyvsp[-2].digest), (yyvsp[0].digest), entries);
			    (yyval.digest) = (yyvsp[-2].digest);
			}
#line 2145 "gram.c"
    break;

  case 51: /* digcmnd: opcmnd  */
#line 548 "gram.y"
                               {
			    (yyval.member) = (yyvsp[0].member);
			}
#line 2153 "gram.c"
    break;

  case 52: /* digcmnd: digestlist opcmnd  */
#line 551 "gram.y"
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
#line 2177 "gram.c"
    break;

  case 53: /* opcmnd: cmnd  */
#line 572 "gram.y"
                             {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 2186 "gram.c"
    break;

  case 54: /* opcmnd: '!' cmnd  */
#line 576 "gram.y"
                                 {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 2195 "gram.c"
    break;

  case 55: /* chdirspec: CWD '=' WORD  */
#line 582 "gram.y"
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
#line 2210 "gram.c"
    break;

  case 56: /* chrootspec: CHROOT '=' WORD  */
#line 594 "gram.y"
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
#line 2225 "gram.c"
    break;

  case 57: /* timeoutspec: CMND_TIMEOUT '=' WORD  */
#line 606 "gram.y"
                                              {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2233 "gram.c"
    break;

  case 58: /* notbeforespec: NOTBEFORE '=' WORD  */
#line 611 "gram.y"
                                           {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2241 "gram.c"
    break;

  case 59: /* notafterspec: NOTAFTER '=' WORD  */
#line 615 "gram.y"
                                          {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2249 "gram.c"
    break;

  case 60: /* rolespec: ROLE '=' WORD  */
#line 620 "gram.y"
                                      {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2257 "gram.c"
    break;

  case 61: /* typespec: TYPE '=' WORD  */
#line 625 "gram.y"
                                      {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2265 "gram.c"
    break;

  case 62: /* privsspec: PRIVS '=' WORD  */
#line 630 "gram.y"
                                       {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2273 "gram.c"
    break;

  case 63: /* limitprivsspec: LIMITPRIVS '=' WORD  */
#line 634 "gram.y"
                                            {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2281 "gram.c"
    break;

  case 64: /* runasspec: %empty  */
#line 639 "gram.y"
                                    {
			    (yyval.runas) = NULL;
			}
#line 2289 "gram.c"
    break;

  case 65: /* runasspec: '(' runaslist ')'  */
#line 642 "gram.y"
                                          {
			    (yyval.runas) = (yyvsp[-1].runas);
			}
#line 2297 "gram.c"
    break;

  case 66: /* runaslist: %empty  */
#line 647 "gram.y"
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
#line 2317 "gram.c"
    break;

  case 67: /* runaslist: userlist  */
#line 662 "gram.y"
                                 {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    (yyval.runas)->runasusers = (yyvsp[0].member);
			    /* $$->runasgroups = NULL; */
			}
#line 2331 "gram.c"
    break;

  case 68: /* runaslist: userlist ':' grouplist  */
#line 671 "gram.y"
                                               {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    (yyval.runas)->runasusers = (yyvsp[-2].member);
			    (yyval.runas)->runasgroups = (yyvsp[0].member);
			}
#line 2345 "gram.c"
    break;

  case 69: /* runaslist: ':' grouplist  */
#line 680 "gram.y"
                                      {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    /* $$->runasusers = NULL; */
			    (yyval.runas)->runasgroups = (yyvsp[0].member);
			}
#line 2359 "gram.c"
    break;

  case 70: /* runaslist: ':'  */
#line 689 "gram.y"
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
#line 2379 "gram.c"
    break;

  case 71: /* reserved_word: ALL  */
#line 706 "gram.y"
                                        { (yyval.string) = "ALL"; }
#line 2385 "gram.c"
    break;

  case 72: /* reserved_word: CHROOT  */
#line 707 "gram.y"
                                        { (yyval.string) = "CHROOT"; }
#line 2391 "gram.c"
    break;

  case 73: /* reserved_word: CWD  */
#line 708 "gram.y"
                                        { (yyval.string) = "CWD"; }
#line 2397 "gram.c"
    break;

  case 74: /* reserved_word: CMND_TIMEOUT  */
#line 709 "gram.y"
                                        { (yyval.string) = "CMND_TIMEOUT"; }
#line 2403 "gram.c"
    break;

  case 75: /* reserved_word: NOTBEFORE  */
#line 710 "gram.y"
                                        { (yyval.string) = "NOTBEFORE"; }
#line 2409 "gram.c"
    break;

  case 76: /* reserved_word: NOTAFTER  */
#line 711 "gram.y"
                                        { (yyval.string) = "NOTAFTER"; }
#line 2415 "gram.c"
    break;

  case 77: /* reserved_word: ROLE  */
#line 712 "gram.y"
                                        { (yyval.string) = "ROLE"; }
#line 2421 "gram.c"
    break;

  case 78: /* reserved_word: TYPE  */
#line 713 "gram.y"
                                        { (yyval.string) = "TYPE"; }
#line 2427 "gram.c"
    break;

  case 79: /* reserved_word: PRIVS  */
#line 714 "gram.y"
                                        { (yyval.string) = "PRIVS"; }
#line 2433 "gram.c"
    break;

  case 80: /* reserved_word: LIMITPRIVS  */
#line 715 "gram.y"
                                        { (yyval.string) = "LIMITPRIVS"; }
#line 2439 "gram.c"
    break;

  case 81: /* reserved_alias: reserved_word  */
#line 718 "gram.y"
                                      {
			    sudoerserrorf(U_("syntax error, reserved word %s used as an alias name"), (yyvsp[0].string));
			    YYERROR;
			}
#line 2448 "gram.c"
    break;

  case 82: /* options: %empty  */
#line 724 "gram.y"
                                    {
			    init_options(&(yyval.options));
			}
#line 2456 "gram.c"
    break;

  case 83: /* options: options chdirspec  */
#line 727 "gram.y"
                                          {
			    free((yyval.options).runcwd);
			    (yyval.options).runcwd = (yyvsp[0].string);
			}
#line 2465 "gram.c"
    break;

  case 84: /* options: options chrootspec  */
#line 731 "gram.y"
                                           {
			    free((yyval.options).runchroot);
			    (yyval.options).runchroot = (yyvsp[0].string);
			}
#line 2474 "gram.c"
    break;

  case 85: /* options: options notbeforespec  */
#line 735 "gram.y"
                                              {
			    (yyval.options).notbefore = parse_gentime((yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).notbefore == -1) {
				sudoerserror(N_("invalid notbefore value"));
				YYERROR;
			    }
			}
#line 2487 "gram.c"
    break;

  case 86: /* options: options notafterspec  */
#line 743 "gram.y"
                                             {
			    (yyval.options).notafter = parse_gentime((yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).notafter == -1) {
				sudoerserror(N_("invalid notafter value"));
				YYERROR;
			    }
			}
#line 2500 "gram.c"
    break;

  case 87: /* options: options timeoutspec  */
#line 751 "gram.y"
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
#line 2516 "gram.c"
    break;

  case 88: /* options: options rolespec  */
#line 762 "gram.y"
                                         {
#ifdef HAVE_SELINUX
			    free((yyval.options).role);
			    (yyval.options).role = (yyvsp[0].string);
#endif
			}
#line 2527 "gram.c"
    break;

  case 89: /* options: options typespec  */
#line 768 "gram.y"
                                         {
#ifdef HAVE_SELINUX
			    free((yyval.options).type);
			    (yyval.options).type = (yyvsp[0].string);
#endif
			}
#line 2538 "gram.c"
    break;

  case 90: /* options: options privsspec  */
#line 774 "gram.y"
                                          {
#ifdef HAVE_PRIV_SET
			    free((yyval.options).privs);
			    (yyval.options).privs = (yyvsp[0].string);
#endif
			}
#line 2549 "gram.c"
    break;

  case 91: /* options: options limitprivsspec  */
#line 780 "gram.y"
                                               {
#ifdef HAVE_PRIV_SET
			    free((yyval.options).limitprivs);
			    (yyval.options).limitprivs = (yyvsp[0].string);
#endif
			}
#line 2560 "gram.c"
    break;

  case 92: /* cmndtag: %empty  */
#line 788 "gram.y"
                                    {
			    TAGS_INIT(&(yyval.tag));
			}
#line 2568 "gram.c"
    break;

  case 93: /* cmndtag: cmndtag NOPASSWD  */
#line 791 "gram.y"
                                         {
			    (yyval.tag).nopasswd = true;
			}
#line 2576 "gram.c"
    break;

  case 94: /* cmndtag: cmndtag PASSWD  */
#line 794 "gram.y"
                                       {
			    (yyval.tag).nopasswd = false;
			}
#line 2584 "gram.c"
    break;

  case 95: /* cmndtag: cmndtag NOEXEC  */
#line 797 "gram.y"
                                       {
			    (yyval.tag).noexec = true;
			}
#line 2592 "gram.c"
    break;

  case 96: /* cmndtag: cmndtag EXEC  */
#line 800 "gram.y"
                                     {
			    (yyval.tag).noexec = false;
			}
#line 2600 "gram.c"
    break;

  case 97: /* cmndtag: cmndtag SETENV  */
#line 803 "gram.y"
                                       {
			    (yyval.tag).setenv = true;
			}
#line 2608 "gram.c"
    break;

  case 98: /* cmndtag: cmndtag NOSETENV  */
#line 806 "gram.y"
                                         {
			    (yyval.tag).setenv = false;
			}
#line 2616 "gram.c"
    break;

  case 99: /* cmndtag: cmndtag LOG_INPUT  */
#line 809 "gram.y"
                                          {
			    (yyval.tag).log_input = true;
			}
#line 2624 "gram.c"
    break;

  case 100: /* cmndtag: cmndtag NOLOG_INPUT  */
#line 812 "gram.y"
                                            {
			    (yyval.tag).log_input = false;
			}
#line 2632 "gram.c"
    break;

  case 101: /* cmndtag: cmndtag LOG_OUTPUT  */
#line 815 "gram.y"
                                           {
			    (yyval.tag).log_output = true;
			}
#line 2640 "gram.c"
    break;

  case 102: /* cmndtag: cmndtag NOLOG_OUTPUT  */
#line 818 "gram.y"
                                             {
			    (yyval.tag).log_output = false;
			}
#line 2648 "gram.c"
    break;

  case 103: /* cmndtag: cmndtag FOLLOWLNK  */
#line 821 "gram.y"
                                          {
			    (yyval.tag).follow = true;
			}
#line 2656 "gram.c"
    break;

  case 104: /* cmndtag: cmndtag NOFOLLOWLNK  */
#line 824 "gram.y"
                                            {
			    (yyval.tag).follow = false;
			}
#line 2664 "gram.c"
    break;

  case 105: /* cmndtag: cmndtag MAIL  */
#line 827 "gram.y"
                                     {
			    (yyval.tag).send_mail = true;
			}
#line 2672 "gram.c"
    break;

  case 106: /* cmndtag: cmndtag NOMAIL  */
#line 830 "gram.y"
                                       {
			    (yyval.tag).send_mail = false;
			}
#line 2680 "gram.c"
    break;

  case 107: /* cmnd: ALL  */
#line 835 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2692 "gram.c"
    break;

  case 108: /* cmnd: ALIAS  */
#line 842 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2704 "gram.c"
    break;

  case 109: /* cmnd: COMMAND  */
#line 849 "gram.y"
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
#line 2723 "gram.c"
    break;

  case 112: /* $@1: %empty  */
#line 869 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2732 "gram.c"
    break;

  case 113: /* hostalias: ALIAS $@1 '=' hostlist  */
#line 872 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), HOSTALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			}
#line 2744 "gram.c"
    break;

  case 116: /* hostlist: hostlist ',' ophost  */
#line 883 "gram.y"
                                            {
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2753 "gram.c"
    break;

  case 119: /* $@2: %empty  */
#line 893 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2762 "gram.c"
    break;

  case 120: /* cmndalias: ALIAS $@2 '=' cmndlist  */
#line 896 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), CMNDALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			}
#line 2774 "gram.c"
    break;

  case 123: /* cmndlist: cmndlist ',' digcmnd  */
#line 907 "gram.y"
                                             {
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2783 "gram.c"
    break;

  case 126: /* $@3: %empty  */
#line 917 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2792 "gram.c"
    break;

  case 127: /* runasalias: ALIAS $@3 '=' userlist  */
#line 920 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), RUNASALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			}
#line 2804 "gram.c"
    break;

  case 131: /* $@4: %empty  */
#line 934 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2813 "gram.c"
    break;

  case 132: /* useralias: ALIAS $@4 '=' userlist  */
#line 937 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), USERALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			}
#line 2825 "gram.c"
    break;

  case 135: /* userlist: userlist ',' opuser  */
#line 948 "gram.y"
                                            {
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2834 "gram.c"
    break;

  case 136: /* opuser: user  */
#line 954 "gram.y"
                             {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 2843 "gram.c"
    break;

  case 137: /* opuser: '!' user  */
#line 958 "gram.y"
                                 {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 2852 "gram.c"
    break;

  case 138: /* user: ALIAS  */
#line 964 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2864 "gram.c"
    break;

  case 139: /* user: ALL  */
#line 971 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2876 "gram.c"
    break;

  case 140: /* user: NETGROUP  */
#line 978 "gram.y"
                                 {
			    (yyval.member) = new_member((yyvsp[0].string), NETGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2888 "gram.c"
    break;

  case 141: /* user: USERGROUP  */
#line 985 "gram.y"
                                  {
			    (yyval.member) = new_member((yyvsp[0].string), USERGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2900 "gram.c"
    break;

  case 142: /* user: WORD  */
#line 992 "gram.y"
                             {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2912 "gram.c"
    break;

  case 144: /* grouplist: grouplist ',' opgroup  */
#line 1002 "gram.y"
                                              {
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2921 "gram.c"
    break;

  case 145: /* opgroup: group  */
#line 1008 "gram.y"
                              {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 2930 "gram.c"
    break;

  case 146: /* opgroup: '!' group  */
#line 1012 "gram.y"
                                  {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 2939 "gram.c"
    break;

  case 147: /* group: ALIAS  */
#line 1018 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2951 "gram.c"
    break;

  case 148: /* group: ALL  */
#line 1025 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2963 "gram.c"
    break;

  case 149: /* group: WORD  */
#line 1032 "gram.y"
                             {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 2975 "gram.c"
    break;


#line 2979 "gram.c"

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
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

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
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      yyerror (YY_("syntax error"));
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

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
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
                  YY_ACCESSING_SYMBOL (yystate), yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

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


#if !defined yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturn;
#endif


/*-------------------------------------------------------.
| yyreturn -- parsing is finished, clean up and return.  |
`-------------------------------------------------------*/
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
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif

  return yyresult;
}

#line 1040 "gram.y"

/* Like yyerror() but takes a printf-style format string. */
void
sudoerserrorf(const char *fmt, ...)
{
    debug_decl(sudoerserrorf, SUDOERS_DEBUG_PARSER);

    /* The lexer displays more detailed messages for ERROR tokens. */
    if (sudoerschar == ERROR)
	debug_return;

    /* Save the line the first error occurred on. */
    if (errorlineno == -1) {
	errorlineno = this_lineno;
	rcstr_delref(errorfile);
	errorfile = rcstr_addref(sudoers);
    }
    if (sudoers_warnings && fmt != NULL) {
	LEXTRACE("<*> ");
#ifndef TRACELEXER
	if (trace_print == NULL || trace_print == sudoers_trace_print) {
	    char *s, *tofree = NULL;
	    int oldlocale;
	    va_list ap;

	    /* Warnings are displayed in the user's locale. */
	    sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);
	    va_start(ap, fmt);
	    if (strcmp(fmt, "%s") == 0) {
		/* Optimize common case, a single string. */
		s = _(va_arg(ap, char *));
	    } else {
		if (vasprintf(&s, fmt, ap) != -1)
		    tofree = s;
		else
		    s = _("syntax error");
	    }
	    sudo_printf(SUDO_CONV_ERROR_MSG, _("%s:%d:%d: %s\n"), sudoers,
		this_lineno, (int)sudolinebuf.toke_start + 1, s);
	    free(tofree);
	    va_end(ap);
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

void
sudoerserror(const char *s)
{
    // -V:sudoerserror:575, 618
    if (s == NULL)
	sudoerserrorf(NULL);
    else
	sudoerserrorf("%s", s);
}

static void
alias_error(const char *name, int errnum)
{
    if (errnum == EEXIST)
	sudoerserrorf(U_("Alias \"%s\" already defined"), name);
    else
	sudoerserror(N_("unable to allocate memory"));
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
    d->line = this_lineno;
    d->column = sudolinebuf.toke_start + 1;
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

/*
 * Like new_member() but uses ALL for the type.
 * Used by the ldap and sssd back-ends, which don't include gram.h.
 */
struct member *
new_member_all(char *name)
{
    return new_member(name, ALL);
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
    u->line = this_lineno;
    u->column = sudolinebuf.toke_start + 1;
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
