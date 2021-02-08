/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>
/* A Bison parser, made by GNU Bison 3.7.5.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
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
#define YYBISON 30705

/* Bison version string.  */
#define YYBISON_VERSION "3.7.5"

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

#ifdef NO_LEAKS
static struct parser_leak_list parser_leak_list =
    SLIST_HEAD_INITIALIZER(parser_leak_list);
#endif

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

#line 165 "gram.c"

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
    CHROOT = 293,                  /* CHROOT  */
    CWD = 294,                     /* CWD  */
    TYPE = 295,                    /* TYPE  */
    ROLE = 296,                    /* ROLE  */
    PRIVS = 297,                   /* PRIVS  */
    LIMITPRIVS = 298,              /* LIMITPRIVS  */
    CMND_TIMEOUT = 299,            /* CMND_TIMEOUT  */
    NOTBEFORE = 300,               /* NOTBEFORE  */
    NOTAFTER = 301,                /* NOTAFTER  */
    MYSELF = 302,                  /* MYSELF  */
    SHA224_TOK = 303,              /* SHA224_TOK  */
    SHA256_TOK = 304,              /* SHA256_TOK  */
    SHA384_TOK = 305,              /* SHA384_TOK  */
    SHA512_TOK = 306               /* SHA512_TOK  */
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

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 88 "gram.y"

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

#line 334 "gram.c"

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
  YYSYMBOL_CHROOT = 47,                    /* CHROOT  */
  YYSYMBOL_CWD = 48,                       /* CWD  */
  YYSYMBOL_TYPE = 49,                      /* TYPE  */
  YYSYMBOL_ROLE = 50,                      /* ROLE  */
  YYSYMBOL_PRIVS = 51,                     /* PRIVS  */
  YYSYMBOL_LIMITPRIVS = 52,                /* LIMITPRIVS  */
  YYSYMBOL_CMND_TIMEOUT = 53,              /* CMND_TIMEOUT  */
  YYSYMBOL_NOTBEFORE = 54,                 /* NOTBEFORE  */
  YYSYMBOL_NOTAFTER = 55,                  /* NOTAFTER  */
  YYSYMBOL_MYSELF = 56,                    /* MYSELF  */
  YYSYMBOL_SHA224_TOK = 57,                /* SHA224_TOK  */
  YYSYMBOL_SHA256_TOK = 58,                /* SHA256_TOK  */
  YYSYMBOL_SHA384_TOK = 59,                /* SHA384_TOK  */
  YYSYMBOL_SHA512_TOK = 60,                /* SHA512_TOK  */
  YYSYMBOL_YYACCEPT = 61,                  /* $accept  */
  YYSYMBOL_file = 62,                      /* file  */
  YYSYMBOL_line = 63,                      /* line  */
  YYSYMBOL_entry = 64,                     /* entry  */
  YYSYMBOL_include = 65,                   /* include  */
  YYSYMBOL_includedir = 66,                /* includedir  */
  YYSYMBOL_defaults_list = 67,             /* defaults_list  */
  YYSYMBOL_defaults_entry = 68,            /* defaults_entry  */
  YYSYMBOL_privileges = 69,                /* privileges  */
  YYSYMBOL_privilege = 70,                 /* privilege  */
  YYSYMBOL_ophost = 71,                    /* ophost  */
  YYSYMBOL_host = 72,                      /* host  */
  YYSYMBOL_cmndspeclist = 73,              /* cmndspeclist  */
  YYSYMBOL_cmndspec = 74,                  /* cmndspec  */
  YYSYMBOL_digestspec = 75,                /* digestspec  */
  YYSYMBOL_digestlist = 76,                /* digestlist  */
  YYSYMBOL_digcmnd = 77,                   /* digcmnd  */
  YYSYMBOL_opcmnd = 78,                    /* opcmnd  */
  YYSYMBOL_chdirspec = 79,                 /* chdirspec  */
  YYSYMBOL_chrootspec = 80,                /* chrootspec  */
  YYSYMBOL_timeoutspec = 81,               /* timeoutspec  */
  YYSYMBOL_notbeforespec = 82,             /* notbeforespec  */
  YYSYMBOL_notafterspec = 83,              /* notafterspec  */
  YYSYMBOL_rolespec = 84,                  /* rolespec  */
  YYSYMBOL_typespec = 85,                  /* typespec  */
  YYSYMBOL_privsspec = 86,                 /* privsspec  */
  YYSYMBOL_limitprivsspec = 87,            /* limitprivsspec  */
  YYSYMBOL_runasspec = 88,                 /* runasspec  */
  YYSYMBOL_runaslist = 89,                 /* runaslist  */
  YYSYMBOL_reserved_word = 90,             /* reserved_word  */
  YYSYMBOL_reserved_alias = 91,            /* reserved_alias  */
  YYSYMBOL_options = 92,                   /* options  */
  YYSYMBOL_cmndtag = 93,                   /* cmndtag  */
  YYSYMBOL_cmnd = 94,                      /* cmnd  */
  YYSYMBOL_hostaliases = 95,               /* hostaliases  */
  YYSYMBOL_hostalias = 96,                 /* hostalias  */
  YYSYMBOL_97_1 = 97,                      /* $@1  */
  YYSYMBOL_hostlist = 98,                  /* hostlist  */
  YYSYMBOL_cmndaliases = 99,               /* cmndaliases  */
  YYSYMBOL_cmndalias = 100,                /* cmndalias  */
  YYSYMBOL_101_2 = 101,                    /* $@2  */
  YYSYMBOL_cmndlist = 102,                 /* cmndlist  */
  YYSYMBOL_runasaliases = 103,             /* runasaliases  */
  YYSYMBOL_runasalias = 104,               /* runasalias  */
  YYSYMBOL_105_3 = 105,                    /* $@3  */
  YYSYMBOL_useraliases = 106,              /* useraliases  */
  YYSYMBOL_useralias = 107,                /* useralias  */
  YYSYMBOL_108_4 = 108,                    /* $@4  */
  YYSYMBOL_userlist = 109,                 /* userlist  */
  YYSYMBOL_opuser = 110,                   /* opuser  */
  YYSYMBOL_user = 111,                     /* user  */
  YYSYMBOL_grouplist = 112,                /* grouplist  */
  YYSYMBOL_opgroup = 113,                  /* opgroup  */
  YYSYMBOL_group = 114                     /* group  */
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

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
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
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
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
#define YYNTOKENS  61
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  54
/* YYNRULES -- Number of rules.  */
#define YYNRULES  149
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  248

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   306


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
      54,    55,    56,    57,    58,    59,    60
};

#if YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   196,   196,   199,   202,   203,   206,   209,   212,   221,
     230,   236,   239,   242,   245,   248,   252,   256,   260,   264,
     270,   273,   279,   282,   288,   289,   296,   305,   314,   324,
     334,   346,   347,   352,   358,   375,   379,   385,   394,   402,
     411,   420,   431,   432,   492,   558,   567,   576,   585,   596,
     597,   604,   607,   629,   633,   639,   651,   663,   668,   672,
     677,   682,   687,   691,   696,   699,   704,   720,   731,   743,
     754,   772,   773,   774,   775,   776,   777,   778,   779,   780,
     781,   784,   790,   793,   798,   803,   812,   821,   833,   840,
     847,   854,   863,   866,   869,   872,   875,   878,   881,   884,
     887,   890,   893,   896,   899,   902,   905,   910,   918,   927,
     946,   947,   950,   950,   962,   965,   966,   973,   974,   977,
     977,   989,   992,   993,  1000,  1001,  1004,  1004,  1016,  1019,
    1020,  1023,  1023,  1035,  1038,  1039,  1046,  1050,  1056,  1065,
    1073,  1082,  1091,  1102,  1103,  1110,  1114,  1120,  1129,  1137
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
  "'!'", "'+'", "'-'", "'('", "')'", "'\\n'", "ERROR", "CHROOT", "CWD",
  "TYPE", "ROLE", "PRIVS", "LIMITPRIVS", "CMND_TIMEOUT", "NOTBEFORE",
  "NOTAFTER", "MYSELF", "SHA224_TOK", "SHA256_TOK", "SHA384_TOK",
  "SHA512_TOK", "$accept", "file", "line", "entry", "include",
  "includedir", "defaults_list", "defaults_entry", "privileges",
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
     306
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
     174,   -28,  -114,  -114,  -114,  -114,    27,    45,     9,   194,
     231,   231,     6,  -114,    30,    39,    92,   118,   148,  -114,
      57,   216,  -114,  -114,  -114,    95,  -114,  -114,  -114,    10,
      11,   217,    34,    68,  -114,  -114,  -114,  -114,  -114,  -114,
     190,  -114,  -114,     8,    69,    69,  -114,  -114,  -114,   128,
      32,    58,    63,    74,  -114,    12,  -114,  -114,  -114,    98,
    -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
    -114,  -114,    78,     5,  -114,  -114,   111,    81,  -114,  -114,
     126,   139,  -114,  -114,   141,   167,  -114,  -114,  -114,  -114,
     231,   168,  -114,   124,    91,  -114,   132,  -114,   183,   184,
     186,  -114,     9,  -114,  -114,   194,    75,   176,   208,  -114,
     192,   201,   226,   227,   207,  -114,     6,   215,   180,   194,
      30,  -114,   206,     6,    39,  -114,   224,   231,    92,  -114,
     230,   231,   118,  -114,  -114,    66,  -114,   202,  -114,  -114,
    -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
    -114,  -114,  -114,  -114,  -114,   194,   242,  -114,     6,   243,
    -114,   231,   244,  -114,   231,   244,  -114,  -114,  -114,   121,
     245,  -114,  -114,   242,   243,   244,   244,    36,   241,    -2,
     202,   225,  -114,  -114,  -114,   101,   247,  -114,  -114,  -114,
      36,  -114,   232,   249,   250,   251,   252,   253,   254,   255,
     256,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
       1,  -114,    36,   247,   237,   260,   286,   287,   288,   289,
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
    -114,  -114,  -114,   281,  -114,  -114,   198,   203,  -114,   169,
     204,   263,  -114,   127,   196,  -114,  -113,   257,  -114,  -114,
    -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,  -114,
      -9,  -114,  -114,   259,  -114,   191,  -114,    -7,  -114,   182,
    -114,  -105,  -114,   181,  -114,  -114,   187,  -114,   -10,   228,
     296,   129,   104,   135
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,    20,    21,    22,    23,    24,    33,    34,    91,    92,
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
      47,    94,    96,    31,    31,    46,    47,    28,   159,   223,
     224,   225,   226,   227,   228,   229,   230,   231,   232,   233,
     234,   235,   236,    48,    60,   190,    29,    90,    48,   101,
     182,    49,   120,    75,    48,   183,    49,   105,    32,    32,
     121,   114,    49,   174,    30,    95,    97,    88,    50,    51,
      52,    53,    61,    50,    51,    52,    53,   167,   184,   110,
      35,    61,    36,    37,    31,    38,   185,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    62,    63,    64,    65,
      66,    67,    68,    69,    70,   111,    79,   237,    39,    35,
     112,    36,    37,    31,    38,   182,    40,   102,    90,    32,
     183,   113,   156,   103,   102,    76,   119,   162,   124,    80,
     145,   165,    83,    84,    61,     2,   125,    39,     3,     4,
       5,    46,    47,   184,    90,    40,   138,   116,    32,    62,
      63,    64,    65,    66,    67,    68,    69,    70,   173,   123,
      61,   175,     2,    13,   176,     3,     4,     5,   177,   179,
      48,    18,   137,   105,   127,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    -2,     1,   128,   139,     2,   131,
      13,     3,     4,     5,   129,     6,     7,     8,     9,    10,
      11,    12,   140,   141,    35,   142,    36,    37,    35,    38,
      36,    37,   148,    38,   132,   135,    13,    14,    15,    16,
      17,   149,   133,   136,    18,   102,    -3,     1,   155,    19,
       2,   146,    39,     3,     4,     5,    39,     6,     7,     8,
       9,    10,    11,    12,    40,     2,   150,   151,     3,     4,
       5,   106,   107,   108,   158,   169,   239,   102,    13,    14,
      15,    16,    17,   147,   102,    98,    18,   117,    99,   100,
     154,    19,   161,    13,    50,    51,    52,    53,   164,   240,
     214,    18,   192,   193,   194,   195,   196,   197,   198,   199,
     200,   105,   116,    90,   180,   189,   212,   215,   216,   217,
     218,   219,   220,   221,   222,   241,   242,   243,   244,   245,
     246,   247,    89,   104,   168,   143,   160,   191,   109,   144,
     152,   157,   115,   166,    87,   163,   238,     0,   134,   213,
     211
};

static const yytype_int16 yycheck[] =
{
      10,    11,     9,   116,     3,     4,    15,    16,    17,     3,
       4,     1,     1,     5,     5,     3,     4,    45,   123,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,     4,    37,     9,    39,    32,     5,
       4,    40,    37,     4,    32,     9,    40,    39,    40,    40,
      45,    39,    40,   158,     9,    45,    45,     0,    57,    58,
      59,    60,    32,    57,    58,    59,    60,     1,    32,    37,
       4,    32,     6,     7,     5,     9,    40,    47,    48,    49,
      50,    51,    52,    53,    54,    55,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    37,     4,   210,    32,     4,
      37,     6,     7,     5,     9,     4,    40,    39,    39,    40,
       9,    37,   119,    45,    39,   124,    38,   127,    37,   128,
      45,   131,     4,   132,    32,     4,    45,    32,     7,     8,
       9,     3,     4,    32,    39,    40,    45,    39,    40,    47,
      48,    49,    50,    51,    52,    53,    54,    55,   155,    38,
      32,   161,     4,    32,   164,     7,     8,     9,    37,   169,
      32,    40,    38,    39,    38,    47,    48,    49,    50,    51,
      52,    53,    54,    55,     0,     1,    37,    45,     4,    38,
      32,     7,     8,     9,    45,    11,    12,    13,    14,    15,
      16,    17,     9,     9,     4,     9,     6,     7,     4,     9,
       6,     7,    10,     9,    37,    37,    32,    33,    34,    35,
      36,    10,    45,    45,    40,    39,     0,     1,    38,    45,
       4,    45,    32,     7,     8,     9,    32,    11,    12,    13,
      14,    15,    16,    17,    40,     4,    10,    10,     7,     8,
       9,    43,    44,    45,    38,    43,     9,    39,    32,    33,
      34,    35,    36,    45,    39,    38,    40,    59,    41,    42,
      45,    45,    38,    32,    57,    58,    59,    60,    38,     9,
      38,    40,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    39,    39,    39,    39,    44,    39,    38,    38,    38,
      38,    38,    38,    38,    38,     9,     9,     9,     9,     9,
       9,     9,    21,    40,   135,   102,   124,   180,    49,   105,
     114,   120,    55,   132,    18,   128,   212,    -1,    90,   190,
     185
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     1,     4,     7,     8,     9,    11,    12,    13,    14,
      15,    16,    17,    32,    33,    34,    35,    36,    40,    45,
      62,    63,    64,    65,    66,   109,   110,   111,    45,     9,
       9,     5,    40,    67,    68,     4,     6,     7,     9,    32,
      40,    71,    72,    98,   109,   109,     3,     4,    32,    40,
      57,    58,    59,    60,    75,    76,    77,    78,    94,   102,
       4,    32,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    90,    91,    95,    96,     4,    91,    99,   100,     4,
      91,   106,   107,     4,    91,   103,   104,   111,     0,    64,
      39,    69,    70,    98,     1,    45,     1,    45,    38,    41,
      42,     5,    39,    45,    72,    39,    67,    67,    67,    94,
      37,    37,    37,    37,    39,    78,    39,    67,    97,    38,
      37,    45,   101,    38,    37,    45,   108,    38,    37,    45,
     105,    38,    37,    45,   110,    37,    45,    38,    45,    45,
       9,     9,     9,    68,    71,    45,    45,    45,    10,    10,
      10,    10,    75,    77,    45,    38,    98,    96,    38,   102,
     100,    38,   109,   107,    38,   109,   104,     1,    70,    43,
      73,    74,    88,    98,   102,   109,   109,    37,    89,   109,
      39,    92,     4,     9,    32,    40,   112,   113,   114,    44,
      37,    74,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    79,    80,    81,    82,    83,    84,    85,    86,    87,
      93,   114,    39,   112,    38,    38,    38,    38,    38,    38,
      38,    38,    38,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    77,   113,     9,
       9,     9,     9,     9,     9,     9,     9,     9
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_int8 yyr1[] =
{
       0,    61,    62,    62,    63,    63,    64,    64,    64,    64,
      64,    64,    64,    64,    64,    64,    64,    64,    64,    64,
      65,    65,    66,    66,    67,    67,    68,    68,    68,    68,
      68,    69,    69,    69,    70,    71,    71,    72,    72,    72,
      72,    72,    73,    73,    74,    75,    75,    75,    75,    76,
      76,    77,    77,    78,    78,    79,    80,    81,    82,    83,
      84,    85,    86,    87,    88,    88,    89,    89,    89,    89,
      89,    90,    90,    90,    90,    90,    90,    90,    90,    90,
      90,    91,    92,    92,    92,    92,    92,    92,    92,    92,
      92,    92,    93,    93,    93,    93,    93,    93,    93,    93,
      93,    93,    93,    93,    93,    93,    93,    94,    94,    94,
      95,    95,    97,    96,    96,    98,    98,    99,    99,   101,
     100,   100,   102,   102,   103,   103,   105,   104,   104,   106,
     106,   108,   107,   107,   109,   109,   110,   110,   111,   111,
     111,   111,   111,   112,   112,   113,   113,   114,   114,   114
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
  YY_USE (yyoutput);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yykind < YYNTOKENS)
    YYPRINT (yyo, yytoknum[yykind], *yyvaluep);
# endif
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
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
  YY_USE (yyvaluep);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
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
#line 196 "gram.y"
                        {
			    ; /* empty file */
			}
#line 1638 "gram.c"
    break;

  case 6: /* entry: '\n'  */
#line 206 "gram.y"
                             {
			    ; /* blank line */
			}
#line 1646 "gram.c"
    break;

  case 7: /* entry: error '\n'  */
#line 209 "gram.y"
                                   {
			    yyerrok;
			}
#line 1654 "gram.c"
    break;

  case 8: /* entry: include  */
#line 212 "gram.y"
                                {
			    if (!push_include((yyvsp[0].string), false)) {
				parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
				free((yyvsp[0].string));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    free((yyvsp[0].string));
			}
#line 1668 "gram.c"
    break;

  case 9: /* entry: includedir  */
#line 221 "gram.y"
                                   {
			    if (!push_include((yyvsp[0].string), true)) {
				parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
				free((yyvsp[0].string));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    free((yyvsp[0].string));
			}
#line 1682 "gram.c"
    break;

  case 10: /* entry: userlist privileges '\n'  */
#line 230 "gram.y"
                                                 {
			    if (!add_userspec((yyvsp[-2].member), (yyvsp[-1].privilege))) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1693 "gram.c"
    break;

  case 11: /* entry: USERALIAS useraliases '\n'  */
#line 236 "gram.y"
                                                   {
			    ;
			}
#line 1701 "gram.c"
    break;

  case 12: /* entry: HOSTALIAS hostaliases '\n'  */
#line 239 "gram.y"
                                                   {
			    ;
			}
#line 1709 "gram.c"
    break;

  case 13: /* entry: CMNDALIAS cmndaliases '\n'  */
#line 242 "gram.y"
                                                   {
			    ;
			}
#line 1717 "gram.c"
    break;

  case 14: /* entry: RUNASALIAS runasaliases '\n'  */
#line 245 "gram.y"
                                                     {
			    ;
			}
#line 1725 "gram.c"
    break;

  case 15: /* entry: DEFAULTS defaults_list '\n'  */
#line 248 "gram.y"
                                                    {
			    if (!add_defaults(DEFAULTS, NULL, (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1734 "gram.c"
    break;

  case 16: /* entry: DEFAULTS_USER userlist defaults_list '\n'  */
#line 252 "gram.y"
                                                                  {
			    if (!add_defaults(DEFAULTS_USER, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1743 "gram.c"
    break;

  case 17: /* entry: DEFAULTS_RUNAS userlist defaults_list '\n'  */
#line 256 "gram.y"
                                                                   {
			    if (!add_defaults(DEFAULTS_RUNAS, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1752 "gram.c"
    break;

  case 18: /* entry: DEFAULTS_HOST hostlist defaults_list '\n'  */
#line 260 "gram.y"
                                                                  {
			    if (!add_defaults(DEFAULTS_HOST, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1761 "gram.c"
    break;

  case 19: /* entry: DEFAULTS_CMND cmndlist defaults_list '\n'  */
#line 264 "gram.y"
                                                                  {
			    if (!add_defaults(DEFAULTS_CMND, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1770 "gram.c"
    break;

  case 20: /* include: INCLUDE WORD '\n'  */
#line 270 "gram.y"
                                          {
			    (yyval.string) = (yyvsp[-1].string);
			}
#line 1778 "gram.c"
    break;

  case 21: /* include: INCLUDE WORD error '\n'  */
#line 273 "gram.y"
                                                {
			    yyerrok;
			    (yyval.string) = (yyvsp[-2].string);
			}
#line 1787 "gram.c"
    break;

  case 22: /* includedir: INCLUDEDIR WORD '\n'  */
#line 279 "gram.y"
                                             {
			    (yyval.string) = (yyvsp[-1].string);
			}
#line 1795 "gram.c"
    break;

  case 23: /* includedir: INCLUDEDIR WORD error '\n'  */
#line 282 "gram.y"
                                                   {
			    yyerrok;
			    (yyval.string) = (yyvsp[-2].string);
			}
#line 1804 "gram.c"
    break;

  case 25: /* defaults_list: defaults_list ',' defaults_entry  */
#line 289 "gram.y"
                                                         {
			    parser_leak_remove(LEAK_DEFAULTS, (yyvsp[0].defaults));
			    HLTQ_CONCAT((yyvsp[-2].defaults), (yyvsp[0].defaults), entries);
			    (yyval.defaults) = (yyvsp[-2].defaults);
			}
#line 1814 "gram.c"
    break;

  case 26: /* defaults_entry: DEFVAR  */
#line 296 "gram.y"
                               {
			    (yyval.defaults) = new_default((yyvsp[0].string), NULL, true);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DEFAULTS, (yyval.defaults));
			}
#line 1828 "gram.c"
    break;

  case 27: /* defaults_entry: '!' DEFVAR  */
#line 305 "gram.y"
                                   {
			    (yyval.defaults) = new_default((yyvsp[0].string), NULL, false);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DEFAULTS, (yyval.defaults));
			}
#line 1842 "gram.c"
    break;

  case 28: /* defaults_entry: DEFVAR '=' WORD  */
#line 314 "gram.y"
                                        {
			    (yyval.defaults) = new_default((yyvsp[-2].string), (yyvsp[0].string), true);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-2].string));
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DEFAULTS, (yyval.defaults));
			}
#line 1857 "gram.c"
    break;

  case 29: /* defaults_entry: DEFVAR '+' WORD  */
#line 324 "gram.y"
                                        {
			    (yyval.defaults) = new_default((yyvsp[-2].string), (yyvsp[0].string), '+');
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-2].string));
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DEFAULTS, (yyval.defaults));
			}
#line 1872 "gram.c"
    break;

  case 30: /* defaults_entry: DEFVAR '-' WORD  */
#line 334 "gram.y"
                                        {
			    (yyval.defaults) = new_default((yyvsp[-2].string), (yyvsp[0].string), '-');
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-2].string));
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DEFAULTS, (yyval.defaults));
			}
#line 1887 "gram.c"
    break;

  case 32: /* privileges: privileges ':' privilege  */
#line 347 "gram.y"
                                                 {
			    parser_leak_remove(LEAK_PRIVILEGE, (yyvsp[0].privilege));
			    HLTQ_CONCAT((yyvsp[-2].privilege), (yyvsp[0].privilege), entries);
			    (yyval.privilege) = (yyvsp[-2].privilege);
			}
#line 1897 "gram.c"
    break;

  case 33: /* privileges: privileges ':' error  */
#line 352 "gram.y"
                                             {
			    yyerrok;
			    (yyval.privilege) = (yyvsp[-2].privilege);
			}
#line 1906 "gram.c"
    break;

  case 34: /* privilege: hostlist '=' cmndspeclist  */
#line 358 "gram.y"
                                                  {
			    struct privilege *p = calloc(1, sizeof(*p));
			    if (p == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_PRIVILEGE, p);
			    TAILQ_INIT(&p->defaults);
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[-2].member));
			    HLTQ_TO_TAILQ(&p->hostlist, (yyvsp[-2].member), entries);
			    parser_leak_remove(LEAK_CMNDSPEC, (yyvsp[0].cmndspec));
			    HLTQ_TO_TAILQ(&p->cmndlist, (yyvsp[0].cmndspec), entries);
			    HLTQ_INIT(p, entries);
			    (yyval.privilege) = p;
			}
#line 1926 "gram.c"
    break;

  case 35: /* ophost: host  */
#line 375 "gram.y"
                             {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 1935 "gram.c"
    break;

  case 36: /* ophost: '!' host  */
#line 379 "gram.y"
                                 {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 1944 "gram.c"
    break;

  case 37: /* host: ALIAS  */
#line 385 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 1958 "gram.c"
    break;

  case 38: /* host: ALL  */
#line 394 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 1971 "gram.c"
    break;

  case 39: /* host: NETGROUP  */
#line 402 "gram.y"
                                 {
			    (yyval.member) = new_member((yyvsp[0].string), NETGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 1985 "gram.c"
    break;

  case 40: /* host: NTWKADDR  */
#line 411 "gram.y"
                                 {
			    (yyval.member) = new_member((yyvsp[0].string), NTWKADDR);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 1999 "gram.c"
    break;

  case 41: /* host: WORD  */
#line 420 "gram.y"
                             {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2013 "gram.c"
    break;

  case 43: /* cmndspeclist: cmndspeclist ',' cmndspec  */
#line 432 "gram.y"
                                                  {
			    struct cmndspec *prev;
			    prev = HLTQ_LAST((yyvsp[-2].cmndspec), cmndspec, entries);
			    parser_leak_remove(LEAK_CMNDSPEC, (yyvsp[0].cmndspec));
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
#line 2076 "gram.c"
    break;

  case 44: /* cmndspec: runasspec options cmndtag digcmnd  */
#line 492 "gram.y"
                                                          {
			    struct cmndspec *cs = calloc(1, sizeof(*cs));
			    if (cs == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_CMNDSPEC, cs);
			    if ((yyvsp[-3].runas) != NULL) {
				if ((yyvsp[-3].runas)->runasusers != NULL) {
				    cs->runasuserlist =
					malloc(sizeof(*cs->runasuserlist));
				    if (cs->runasuserlist == NULL) {
					free(cs);
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    /* g/c done via runas container */
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
				    /* g/c done via runas container */
				    HLTQ_TO_TAILQ(cs->runasgrouplist,
					(yyvsp[-3].runas)->runasgroups, entries);
				}
				parser_leak_remove(LEAK_RUNAS, (yyvsp[-3].runas));
				free((yyvsp[-3].runas));
			    }
#ifdef HAVE_SELINUX
			    cs->role = (yyvsp[-2].options).role;
			    parser_leak_remove(LEAK_PTR, (yyvsp[-2].options).role);
			    cs->type = (yyvsp[-2].options).type;
			    parser_leak_remove(LEAK_PTR, (yyvsp[-2].options).type);
#endif
#ifdef HAVE_PRIV_SET
			    cs->privs = (yyvsp[-2].options).privs;
			    parser_leak_remove(LEAK_PTR, (yyvsp[-2].options).privs);
			    cs->limitprivs = (yyvsp[-2].options).limitprivs;
			    parser_leak_remove(LEAK_PTR, (yyvsp[-2].options).limitprivs);
#endif
			    cs->notbefore = (yyvsp[-2].options).notbefore;
			    cs->notafter = (yyvsp[-2].options).notafter;
			    cs->timeout = (yyvsp[-2].options).timeout;
			    cs->runcwd = (yyvsp[-2].options).runcwd;
			    parser_leak_remove(LEAK_PTR, (yyvsp[-2].options).runcwd);
			    cs->runchroot = (yyvsp[-2].options).runchroot;
			    parser_leak_remove(LEAK_PTR, (yyvsp[-2].options).runchroot);
			    cs->tags = (yyvsp[-1].tag);
			    cs->cmnd = (yyvsp[0].member);
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    HLTQ_INIT(cs, entries);
			    /* sudo "ALL" implies the SETENV tag */
			    if (cs->cmnd->type == ALL && !cs->cmnd->negated &&
				cs->tags.setenv == UNSPEC)
				cs->tags.setenv = IMPLIED;
			    (yyval.cmndspec) = cs;
			}
#line 2145 "gram.c"
    break;

  case 45: /* digestspec: SHA224_TOK ':' DIGEST  */
#line 558 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA224, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DIGEST, (yyval.digest));
			}
#line 2159 "gram.c"
    break;

  case 46: /* digestspec: SHA256_TOK ':' DIGEST  */
#line 567 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA256, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DIGEST, (yyval.digest));
			}
#line 2173 "gram.c"
    break;

  case 47: /* digestspec: SHA384_TOK ':' DIGEST  */
#line 576 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA384, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DIGEST, (yyval.digest));
			}
#line 2187 "gram.c"
    break;

  case 48: /* digestspec: SHA512_TOK ':' DIGEST  */
#line 585 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA512, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DIGEST, (yyval.digest));
			}
#line 2201 "gram.c"
    break;

  case 50: /* digestlist: digestlist ',' digestspec  */
#line 597 "gram.y"
                                                  {
			    parser_leak_remove(LEAK_DIGEST, (yyvsp[0].digest));
			    HLTQ_CONCAT((yyvsp[-2].digest), (yyvsp[0].digest), entries);
			    (yyval.digest) = (yyvsp[-2].digest);
			}
#line 2211 "gram.c"
    break;

  case 51: /* digcmnd: opcmnd  */
#line 604 "gram.y"
                               {
			    (yyval.member) = (yyvsp[0].member);
			}
#line 2219 "gram.c"
    break;

  case 52: /* digcmnd: digestlist opcmnd  */
#line 607 "gram.y"
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
			    parser_leak_remove(LEAK_DIGEST, (yyvsp[-1].digest));
			    HLTQ_TO_TAILQ(&c->digests, (yyvsp[-1].digest), entries);
			    (yyval.member) = (yyvsp[0].member);
			}
#line 2244 "gram.c"
    break;

  case 53: /* opcmnd: cmnd  */
#line 629 "gram.y"
                             {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 2253 "gram.c"
    break;

  case 54: /* opcmnd: '!' cmnd  */
#line 633 "gram.y"
                                 {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 2262 "gram.c"
    break;

  case 55: /* chdirspec: CWD '=' WORD  */
#line 639 "gram.y"
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
#line 2277 "gram.c"
    break;

  case 56: /* chrootspec: CHROOT '=' WORD  */
#line 651 "gram.y"
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
#line 2292 "gram.c"
    break;

  case 57: /* timeoutspec: CMND_TIMEOUT '=' WORD  */
#line 663 "gram.y"
                                              {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2300 "gram.c"
    break;

  case 58: /* notbeforespec: NOTBEFORE '=' WORD  */
#line 668 "gram.y"
                                           {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2308 "gram.c"
    break;

  case 59: /* notafterspec: NOTAFTER '=' WORD  */
#line 672 "gram.y"
                                          {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2316 "gram.c"
    break;

  case 60: /* rolespec: ROLE '=' WORD  */
#line 677 "gram.y"
                                      {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2324 "gram.c"
    break;

  case 61: /* typespec: TYPE '=' WORD  */
#line 682 "gram.y"
                                      {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2332 "gram.c"
    break;

  case 62: /* privsspec: PRIVS '=' WORD  */
#line 687 "gram.y"
                                       {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2340 "gram.c"
    break;

  case 63: /* limitprivsspec: LIMITPRIVS '=' WORD  */
#line 691 "gram.y"
                                            {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2348 "gram.c"
    break;

  case 64: /* runasspec: %empty  */
#line 696 "gram.y"
                                    {
			    (yyval.runas) = NULL;
			}
#line 2356 "gram.c"
    break;

  case 65: /* runasspec: '(' runaslist ')'  */
#line 699 "gram.y"
                                          {
			    (yyval.runas) = (yyvsp[-1].runas);
			}
#line 2364 "gram.c"
    break;

  case 66: /* runaslist: %empty  */
#line 704 "gram.y"
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
			    parser_leak_add(LEAK_RUNAS, (yyval.runas));
			}
#line 2385 "gram.c"
    break;

  case 67: /* runaslist: userlist  */
#line 720 "gram.y"
                                 {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_RUNAS, (yyval.runas));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    (yyval.runas)->runasusers = (yyvsp[0].member);
			    /* $$->runasgroups = NULL; */
			}
#line 2401 "gram.c"
    break;

  case 68: /* runaslist: userlist ':' grouplist  */
#line 731 "gram.y"
                                               {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_RUNAS, (yyval.runas));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[-2].member));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    (yyval.runas)->runasusers = (yyvsp[-2].member);
			    (yyval.runas)->runasgroups = (yyvsp[0].member);
			}
#line 2418 "gram.c"
    break;

  case 69: /* runaslist: ':' grouplist  */
#line 743 "gram.y"
                                      {
			    (yyval.runas) = calloc(1, sizeof(struct runascontainer));
			    if ((yyval.runas) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_RUNAS, (yyval.runas));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    /* $$->runasusers = NULL; */
			    (yyval.runas)->runasgroups = (yyvsp[0].member);
			}
#line 2434 "gram.c"
    break;

  case 70: /* runaslist: ':'  */
#line 754 "gram.y"
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
			    parser_leak_add(LEAK_RUNAS, (yyval.runas));
			}
#line 2455 "gram.c"
    break;

  case 71: /* reserved_word: ALL  */
#line 772 "gram.y"
                                        { (yyval.string) = "ALL"; }
#line 2461 "gram.c"
    break;

  case 72: /* reserved_word: CHROOT  */
#line 773 "gram.y"
                                        { (yyval.string) = "CHROOT"; }
#line 2467 "gram.c"
    break;

  case 73: /* reserved_word: CWD  */
#line 774 "gram.y"
                                        { (yyval.string) = "CWD"; }
#line 2473 "gram.c"
    break;

  case 74: /* reserved_word: CMND_TIMEOUT  */
#line 775 "gram.y"
                                        { (yyval.string) = "CMND_TIMEOUT"; }
#line 2479 "gram.c"
    break;

  case 75: /* reserved_word: NOTBEFORE  */
#line 776 "gram.y"
                                        { (yyval.string) = "NOTBEFORE"; }
#line 2485 "gram.c"
    break;

  case 76: /* reserved_word: NOTAFTER  */
#line 777 "gram.y"
                                        { (yyval.string) = "NOTAFTER"; }
#line 2491 "gram.c"
    break;

  case 77: /* reserved_word: ROLE  */
#line 778 "gram.y"
                                        { (yyval.string) = "ROLE"; }
#line 2497 "gram.c"
    break;

  case 78: /* reserved_word: TYPE  */
#line 779 "gram.y"
                                        { (yyval.string) = "TYPE"; }
#line 2503 "gram.c"
    break;

  case 79: /* reserved_word: PRIVS  */
#line 780 "gram.y"
                                        { (yyval.string) = "PRIVS"; }
#line 2509 "gram.c"
    break;

  case 80: /* reserved_word: LIMITPRIVS  */
#line 781 "gram.y"
                                        { (yyval.string) = "LIMITPRIVS"; }
#line 2515 "gram.c"
    break;

  case 81: /* reserved_alias: reserved_word  */
#line 784 "gram.y"
                                      {
			    sudoerserrorf(U_("syntax error, reserved word %s used as an alias name"), (yyvsp[0].string));
			    YYERROR;
			}
#line 2524 "gram.c"
    break;

  case 82: /* options: %empty  */
#line 790 "gram.y"
                                    {
			    init_options(&(yyval.options));
			}
#line 2532 "gram.c"
    break;

  case 83: /* options: options chdirspec  */
#line 793 "gram.y"
                                          {
			    parser_leak_remove(LEAK_PTR, (yyval.options).runcwd);
			    free((yyval.options).runcwd);
			    (yyval.options).runcwd = (yyvsp[0].string);
			}
#line 2542 "gram.c"
    break;

  case 84: /* options: options chrootspec  */
#line 798 "gram.y"
                                           {
			    parser_leak_remove(LEAK_PTR, (yyval.options).runchroot);
			    free((yyval.options).runchroot);
			    (yyval.options).runchroot = (yyvsp[0].string);
			}
#line 2552 "gram.c"
    break;

  case 85: /* options: options notbeforespec  */
#line 803 "gram.y"
                                              {
			    (yyval.options).notbefore = parse_gentime((yyvsp[0].string));
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).notbefore == -1) {
				sudoerserror(N_("invalid notbefore value"));
				YYERROR;
			    }
			}
#line 2566 "gram.c"
    break;

  case 86: /* options: options notafterspec  */
#line 812 "gram.y"
                                             {
			    (yyval.options).notafter = parse_gentime((yyvsp[0].string));
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).notafter == -1) {
				sudoerserror(N_("invalid notafter value"));
				YYERROR;
			    }
			}
#line 2580 "gram.c"
    break;

  case 87: /* options: options timeoutspec  */
#line 821 "gram.y"
                                            {
			    (yyval.options).timeout = parse_timeout((yyvsp[0].string));
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).timeout == -1) {
				if (errno == ERANGE)
				    sudoerserror(N_("timeout value too large"));
				else
				    sudoerserror(N_("invalid timeout value"));
				YYERROR;
			    }
			}
#line 2597 "gram.c"
    break;

  case 88: /* options: options rolespec  */
#line 833 "gram.y"
                                         {
#ifdef HAVE_SELINUX
			    parser_leak_remove(LEAK_PTR, (yyval.options).role);
			    free((yyval.options).role);
			    (yyval.options).role = (yyvsp[0].string);
#endif
			}
#line 2609 "gram.c"
    break;

  case 89: /* options: options typespec  */
#line 840 "gram.y"
                                         {
#ifdef HAVE_SELINUX
			    parser_leak_remove(LEAK_PTR, (yyval.options).type);
			    free((yyval.options).type);
			    (yyval.options).type = (yyvsp[0].string);
#endif
			}
#line 2621 "gram.c"
    break;

  case 90: /* options: options privsspec  */
#line 847 "gram.y"
                                          {
#ifdef HAVE_PRIV_SET
			    parser_leak_remove(LEAK_PTR, (yyval.options).privs);
			    free((yyval.options).privs);
			    (yyval.options).privs = (yyvsp[0].string);
#endif
			}
#line 2633 "gram.c"
    break;

  case 91: /* options: options limitprivsspec  */
#line 854 "gram.y"
                                               {
#ifdef HAVE_PRIV_SET
			    parser_leak_remove(LEAK_PTR, (yyval.options).limitprivs);
			    free((yyval.options).limitprivs);
			    (yyval.options).limitprivs = (yyvsp[0].string);
#endif
			}
#line 2645 "gram.c"
    break;

  case 92: /* cmndtag: %empty  */
#line 863 "gram.y"
                                    {
			    TAGS_INIT(&(yyval.tag));
			}
#line 2653 "gram.c"
    break;

  case 93: /* cmndtag: cmndtag NOPASSWD  */
#line 866 "gram.y"
                                         {
			    (yyval.tag).nopasswd = true;
			}
#line 2661 "gram.c"
    break;

  case 94: /* cmndtag: cmndtag PASSWD  */
#line 869 "gram.y"
                                       {
			    (yyval.tag).nopasswd = false;
			}
#line 2669 "gram.c"
    break;

  case 95: /* cmndtag: cmndtag NOEXEC  */
#line 872 "gram.y"
                                       {
			    (yyval.tag).noexec = true;
			}
#line 2677 "gram.c"
    break;

  case 96: /* cmndtag: cmndtag EXEC  */
#line 875 "gram.y"
                                     {
			    (yyval.tag).noexec = false;
			}
#line 2685 "gram.c"
    break;

  case 97: /* cmndtag: cmndtag SETENV  */
#line 878 "gram.y"
                                       {
			    (yyval.tag).setenv = true;
			}
#line 2693 "gram.c"
    break;

  case 98: /* cmndtag: cmndtag NOSETENV  */
#line 881 "gram.y"
                                         {
			    (yyval.tag).setenv = false;
			}
#line 2701 "gram.c"
    break;

  case 99: /* cmndtag: cmndtag LOG_INPUT  */
#line 884 "gram.y"
                                          {
			    (yyval.tag).log_input = true;
			}
#line 2709 "gram.c"
    break;

  case 100: /* cmndtag: cmndtag NOLOG_INPUT  */
#line 887 "gram.y"
                                            {
			    (yyval.tag).log_input = false;
			}
#line 2717 "gram.c"
    break;

  case 101: /* cmndtag: cmndtag LOG_OUTPUT  */
#line 890 "gram.y"
                                           {
			    (yyval.tag).log_output = true;
			}
#line 2725 "gram.c"
    break;

  case 102: /* cmndtag: cmndtag NOLOG_OUTPUT  */
#line 893 "gram.y"
                                             {
			    (yyval.tag).log_output = false;
			}
#line 2733 "gram.c"
    break;

  case 103: /* cmndtag: cmndtag FOLLOWLNK  */
#line 896 "gram.y"
                                          {
			    (yyval.tag).follow = true;
			}
#line 2741 "gram.c"
    break;

  case 104: /* cmndtag: cmndtag NOFOLLOWLNK  */
#line 899 "gram.y"
                                            {
			    (yyval.tag).follow = false;
			}
#line 2749 "gram.c"
    break;

  case 105: /* cmndtag: cmndtag MAIL  */
#line 902 "gram.y"
                                     {
			    (yyval.tag).send_mail = true;
			}
#line 2757 "gram.c"
    break;

  case 106: /* cmndtag: cmndtag NOMAIL  */
#line 905 "gram.y"
                                       {
			    (yyval.tag).send_mail = false;
			}
#line 2765 "gram.c"
    break;

  case 107: /* cmnd: ALL  */
#line 910 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2778 "gram.c"
    break;

  case 108: /* cmnd: ALIAS  */
#line 918 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2792 "gram.c"
    break;

  case 109: /* cmnd: COMMAND  */
#line 927 "gram.y"
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
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].command).cmnd);
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].command).args);
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2814 "gram.c"
    break;

  case 112: /* $@1: %empty  */
#line 950 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2823 "gram.c"
    break;

  case 113: /* hostalias: ALIAS $@1 '=' hostlist  */
#line 953 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), HOSTALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-3].string));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			}
#line 2837 "gram.c"
    break;

  case 116: /* hostlist: hostlist ',' ophost  */
#line 966 "gram.y"
                                            {
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2847 "gram.c"
    break;

  case 119: /* $@2: %empty  */
#line 977 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2856 "gram.c"
    break;

  case 120: /* cmndalias: ALIAS $@2 '=' cmndlist  */
#line 980 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), CMNDALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-3].string));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			}
#line 2870 "gram.c"
    break;

  case 123: /* cmndlist: cmndlist ',' digcmnd  */
#line 993 "gram.y"
                                             {
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2880 "gram.c"
    break;

  case 126: /* $@3: %empty  */
#line 1004 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2889 "gram.c"
    break;

  case 127: /* runasalias: ALIAS $@3 '=' userlist  */
#line 1007 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), RUNASALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-3].string));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			}
#line 2903 "gram.c"
    break;

  case 131: /* $@4: %empty  */
#line 1023 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2912 "gram.c"
    break;

  case 132: /* useralias: ALIAS $@4 '=' userlist  */
#line 1026 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), USERALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-3].string));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			}
#line 2926 "gram.c"
    break;

  case 135: /* userlist: userlist ',' opuser  */
#line 1039 "gram.y"
                                            {
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2936 "gram.c"
    break;

  case 136: /* opuser: user  */
#line 1046 "gram.y"
                             {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 2945 "gram.c"
    break;

  case 137: /* opuser: '!' user  */
#line 1050 "gram.y"
                                 {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 2954 "gram.c"
    break;

  case 138: /* user: ALIAS  */
#line 1056 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2968 "gram.c"
    break;

  case 139: /* user: ALL  */
#line 1065 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2981 "gram.c"
    break;

  case 140: /* user: NETGROUP  */
#line 1073 "gram.y"
                                 {
			    (yyval.member) = new_member((yyvsp[0].string), NETGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2995 "gram.c"
    break;

  case 141: /* user: USERGROUP  */
#line 1082 "gram.y"
                                  {
			    (yyval.member) = new_member((yyvsp[0].string), USERGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3009 "gram.c"
    break;

  case 142: /* user: WORD  */
#line 1091 "gram.y"
                             {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3023 "gram.c"
    break;

  case 144: /* grouplist: grouplist ',' opgroup  */
#line 1103 "gram.y"
                                              {
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 3033 "gram.c"
    break;

  case 145: /* opgroup: group  */
#line 1110 "gram.y"
                              {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 3042 "gram.c"
    break;

  case 146: /* opgroup: '!' group  */
#line 1114 "gram.y"
                                  {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 3051 "gram.c"
    break;

  case 147: /* group: ALIAS  */
#line 1120 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3065 "gram.c"
    break;

  case 148: /* group: ALL  */
#line 1129 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3078 "gram.c"
    break;

  case 149: /* group: WORD  */
#line 1137 "gram.y"
                             {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3092 "gram.c"
    break;


#line 3096 "gram.c"

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

#line 1147 "gram.y"

/* Like yyerror() but takes a printf-style format string. */
void
sudoerserrorf(const char *fmt, ...)
{
    static int last_error_line = -1;
    static char *last_error_file = NULL;
    debug_decl(sudoerserrorf, SUDOERS_DEBUG_PARSER);

    /* Only print the first error found in a line. */
    if (last_error_file == sudoers && last_error_line == this_lineno)
	debug_return;
    last_error_file = sudoers;
    last_error_line = this_lineno;

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
    /* garbage collected as part of struct member */

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
	if (bmem != NULL) {
	    parser_leak_remove(LEAK_MEMBER, bmem);
	    HLTQ_TO_TAILQ(binding, bmem, entries);
	} else {
	    TAILQ_INIT(binding);
	}

	/*
	 * Set type and binding (who it applies to) for new entries.
	 * Then add to the global defaults list.
	 */
	parser_leak_remove(LEAK_DEFAULTS, defs);
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
    parser_leak_remove(LEAK_MEMBER, members);
    HLTQ_TO_TAILQ(&u->users, members, entries);
    parser_leak_remove(LEAK_PRIVILEGE, privs);
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
free_cmndspecs(struct cmndspec_list *csl)
{
    struct member_list *runasuserlist = NULL, *runasgrouplist = NULL;
    char *runcwd = NULL, *runchroot = NULL;
#ifdef HAVE_SELINUX
    char *role = NULL, *type = NULL;
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
    char *privs = NULL, *limitprivs = NULL;
#endif /* HAVE_PRIV_SET */
    struct cmndspec *cs;
    debug_decl(free_cmndspecs, SUDOERS_DEBUG_PARSER);

    while ((cs = TAILQ_FIRST(csl)) != NULL) {
	TAILQ_REMOVE(csl, cs, entries);

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

    debug_return;
}

void
free_privilege(struct privilege *priv)
{
    struct member_list *prev_binding = NULL;
    struct defaults *def;
    debug_decl(free_privilege, SUDOERS_DEBUG_PARSER);

    free(priv->ldap_role);
    free_members(&priv->hostlist);
    free_cmndspecs(&priv->cmndlist);
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
    parser_leak_init();
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

bool
parser_leak_add(enum parser_leak_types type, void *v)
{
#ifdef NO_LEAKS
    struct parser_leak_entry *entry;
    debug_decl(parser_leak_add, SUDOERS_DEBUG_PARSER);

    if (v == NULL)
	debug_return_bool(false);

    entry = calloc(1, sizeof(*entry));
    if (entry == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_bool(false);
    }
    switch (type) {
    case LEAK_PRIVILEGE:
	entry->u.p = v;
	break;
    case LEAK_CMNDSPEC:
	entry->u.cs = v;
	break;
    case LEAK_DEFAULTS:
	entry->u.d = v;
	break;
    case LEAK_MEMBER:
	entry->u.m = v;
	break;
    case LEAK_DIGEST:
	entry->u.dig = v;
	break;
    case LEAK_RUNAS:
	entry->u.rc = v;
	break;
    case LEAK_PTR:
	entry->u.ptr = v;
	break;
    default:
	free(entry);
	sudo_warnx("unexpected leak type %d", type);
	debug_return_bool(false);
    }
    entry->type = type;
    SLIST_INSERT_HEAD(&parser_leak_list, entry, entries);
    debug_return_bool(true);
#else
    return true;
#endif /* NO_LEAKS */
}

bool
parser_leak_remove(enum parser_leak_types type, void *v)
{
#ifdef NO_LEAKS
    struct parser_leak_entry *entry, *prev = NULL;
    debug_decl(parser_leak_remove, SUDOERS_DEBUG_PARSER);

    if (v == NULL)
	debug_return_bool(false);

    SLIST_FOREACH(entry, &parser_leak_list, entries) {
	switch (entry->type) {
	case LEAK_PRIVILEGE:
	    if (entry->u.p == v)
	    	goto found;
	    break;
	case LEAK_CMNDSPEC:
	    if (entry->u.cs == v)
	    	goto found;
	    break;
	case LEAK_DEFAULTS:
	    if (entry->u.d == v)
	    	goto found;
	    break;
	case LEAK_MEMBER:
	    if (entry->u.m == v)
	    	goto found;
	    break;
	case LEAK_DIGEST:
	    if (entry->u.dig == v)
	    	goto found;
	    break;
	case LEAK_RUNAS:
	    if (entry->u.rc == v)
	    	goto found;
	    break;
	case LEAK_PTR:
	    if (entry->u.ptr == v)
	    	goto found;
	    break;
	default:
	    sudo_warnx("unexpected leak type %d in %p", entry->type, entry);
	}
	prev = entry;
    }
    /* If this happens, there is a bug in the leak tracking code. */
    sudo_warnx("%s: unable to find %p, type %d", __func__, v, type);
    debug_return_bool(false);
found:
    if (prev == NULL)
	SLIST_REMOVE_HEAD(&parser_leak_list, entries);
    else
	SLIST_REMOVE_AFTER(prev, entries);
    free(entry);
    debug_return_bool(true);
#else
    return true;
#endif /* NO_LEAKS */
}

void
parser_leak_free(void)
{
#ifdef NO_LEAKS
    struct parser_leak_entry *entry;
    void *next;
    debug_decl(parser_leak_run, SUDOERS_DEBUG_PARSER);

    /* Free the leaks. */
    while ((entry = SLIST_FIRST(&parser_leak_list))) {
	SLIST_REMOVE_HEAD(&parser_leak_list, entries);
	switch (entry->type) {
	case LEAK_PRIVILEGE:
	    {
		struct privilege *priv;

		HLTQ_FOREACH_SAFE(priv, entry->u.p, entries, next)
		    free_privilege(priv);
		free(entry);
	    }
	    break;
	case LEAK_CMNDSPEC:
	    {
		struct cmndspec_list specs;

		HLTQ_TO_TAILQ(&specs, entry->u.cs, entries);
		free_cmndspecs(&specs);
		free(entry);
	    }
	    break;
	case LEAK_DEFAULTS:
	    {
		struct defaults_list defs;

		HLTQ_TO_TAILQ(&defs, entry->u.d, entries);
		free_defaults(&defs);
		free(entry);
	    }
	    break;
	case LEAK_MEMBER:
	    {
		struct member *m;

		HLTQ_FOREACH_SAFE(m, entry->u.m, entries, next)
		    free_member(m);
		free(entry);
	    }
	    break;
	case LEAK_DIGEST:
	    {
		struct command_digest *dig;

		HLTQ_FOREACH_SAFE(dig, entry->u.dig, entries, next) {
		    free(dig->digest_str);
		    free(dig);
		}
		free(entry);
	    }
	    break;
	case LEAK_RUNAS:
	    {
		struct member *m;

		if (entry->u.rc->runasusers != NULL) {
		    HLTQ_FOREACH_SAFE(m, entry->u.rc->runasusers, entries, next)
			free_member(m);
		}
		if (entry->u.rc->runasgroups != NULL) {
		    HLTQ_FOREACH_SAFE(m, entry->u.rc->runasgroups, entries, next)
			free_member(m);
		}
		free(entry->u.rc);
		free(entry);
		break;
	    }
	case LEAK_PTR:
	    free(entry->u.ptr);
	    free(entry);
	    break;
	default:
	    sudo_warnx("unexpected garbage type %d", entry->type);
	}
    }

    debug_return;
#endif /* NO_LEAKS */
}

void
parser_leak_init(void)
{
#ifdef NO_LEAKS
    static bool initialized;
    debug_decl(parser_leak_init, SUDOERS_DEBUG_PARSER);

    if (!initialized) {
	atexit(parser_leak_free);
	initialized = true;
	debug_return;
    }

    /* Already initialized, free existing leaks. */
    parser_leak_free();
    debug_return;
#endif /* NO_LEAKS */
}
