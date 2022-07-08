/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>
/* A Bison parser, made by GNU Bison 3.8.2.  */

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
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

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
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

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
 * Copyright (c) 1996, 1998-2005, 2007-2013, 2014-2022
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
// -V::560, 592, 1037, 1042

/*
 * Globals
 */
bool sudoers_warnings = true;
bool sudoers_strict = false;
bool parse_error = false;

/* Optional logging function for parse errors. */
sudoers_logger_t sudoers_error_hook;

static int alias_line, alias_column;

#ifdef NO_LEAKS
static struct parser_leak_list parser_leak_list =
    SLIST_HEAD_INITIALIZER(parser_leak_list);
#endif

struct sudoers_parse_tree parsed_policy = {
    { NULL, NULL }, /* entries */
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

#line 164 "gram.c"

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
    INTERCEPT = 287,               /* INTERCEPT  */
    NOINTERCEPT = 288,             /* NOINTERCEPT  */
    ALL = 289,                     /* ALL  */
    HOSTALIAS = 290,               /* HOSTALIAS  */
    CMNDALIAS = 291,               /* CMNDALIAS  */
    USERALIAS = 292,               /* USERALIAS  */
    RUNASALIAS = 293,              /* RUNASALIAS  */
    ERROR = 294,                   /* ERROR  */
    NOMATCH = 295,                 /* NOMATCH  */
    CHROOT = 296,                  /* CHROOT  */
    CWD = 297,                     /* CWD  */
    TYPE = 298,                    /* TYPE  */
    ROLE = 299,                    /* ROLE  */
    APPARMOR_PROFILE = 300,        /* APPARMOR_PROFILE  */
    PRIVS = 301,                   /* PRIVS  */
    LIMITPRIVS = 302,              /* LIMITPRIVS  */
    CMND_TIMEOUT = 303,            /* CMND_TIMEOUT  */
    NOTBEFORE = 304,               /* NOTBEFORE  */
    NOTAFTER = 305,                /* NOTAFTER  */
    MYSELF = 306,                  /* MYSELF  */
    SHA224_TOK = 307,              /* SHA224_TOK  */
    SHA256_TOK = 308,              /* SHA256_TOK  */
    SHA384_TOK = 309,              /* SHA384_TOK  */
    SHA512_TOK = 310               /* SHA512_TOK  */
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
#define INTERCEPT 287
#define NOINTERCEPT 288
#define ALL 289
#define HOSTALIAS 290
#define CMNDALIAS 291
#define USERALIAS 292
#define RUNASALIAS 293
#define ERROR 294
#define NOMATCH 295
#define CHROOT 296
#define CWD 297
#define TYPE 298
#define ROLE 299
#define APPARMOR_PROFILE 300
#define PRIVS 301
#define LIMITPRIVS 302
#define CMND_TIMEOUT 303
#define NOTBEFORE 304
#define NOTAFTER 305
#define MYSELF 306
#define SHA224_TOK 307
#define SHA256_TOK 308
#define SHA384_TOK 309
#define SHA512_TOK 310

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 87 "gram.y"

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
    const char *cstring;
    int tok;

#line 342 "gram.c"

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
  YYSYMBOL_INTERCEPT = 32,                 /* INTERCEPT  */
  YYSYMBOL_NOINTERCEPT = 33,               /* NOINTERCEPT  */
  YYSYMBOL_ALL = 34,                       /* ALL  */
  YYSYMBOL_HOSTALIAS = 35,                 /* HOSTALIAS  */
  YYSYMBOL_CMNDALIAS = 36,                 /* CMNDALIAS  */
  YYSYMBOL_USERALIAS = 37,                 /* USERALIAS  */
  YYSYMBOL_RUNASALIAS = 38,                /* RUNASALIAS  */
  YYSYMBOL_39_ = 39,                       /* ':'  */
  YYSYMBOL_40_ = 40,                       /* '='  */
  YYSYMBOL_41_ = 41,                       /* ','  */
  YYSYMBOL_42_ = 42,                       /* '!'  */
  YYSYMBOL_43_ = 43,                       /* '+'  */
  YYSYMBOL_44_ = 44,                       /* '-'  */
  YYSYMBOL_45_ = 45,                       /* '('  */
  YYSYMBOL_46_ = 46,                       /* ')'  */
  YYSYMBOL_47_n_ = 47,                     /* '\n'  */
  YYSYMBOL_ERROR = 48,                     /* ERROR  */
  YYSYMBOL_NOMATCH = 49,                   /* NOMATCH  */
  YYSYMBOL_CHROOT = 50,                    /* CHROOT  */
  YYSYMBOL_CWD = 51,                       /* CWD  */
  YYSYMBOL_TYPE = 52,                      /* TYPE  */
  YYSYMBOL_ROLE = 53,                      /* ROLE  */
  YYSYMBOL_APPARMOR_PROFILE = 54,          /* APPARMOR_PROFILE  */
  YYSYMBOL_PRIVS = 55,                     /* PRIVS  */
  YYSYMBOL_LIMITPRIVS = 56,                /* LIMITPRIVS  */
  YYSYMBOL_CMND_TIMEOUT = 57,              /* CMND_TIMEOUT  */
  YYSYMBOL_NOTBEFORE = 58,                 /* NOTBEFORE  */
  YYSYMBOL_NOTAFTER = 59,                  /* NOTAFTER  */
  YYSYMBOL_MYSELF = 60,                    /* MYSELF  */
  YYSYMBOL_SHA224_TOK = 61,                /* SHA224_TOK  */
  YYSYMBOL_SHA256_TOK = 62,                /* SHA256_TOK  */
  YYSYMBOL_SHA384_TOK = 63,                /* SHA384_TOK  */
  YYSYMBOL_SHA512_TOK = 64,                /* SHA512_TOK  */
  YYSYMBOL_YYACCEPT = 65,                  /* $accept  */
  YYSYMBOL_file = 66,                      /* file  */
  YYSYMBOL_line = 67,                      /* line  */
  YYSYMBOL_entry = 68,                     /* entry  */
  YYSYMBOL_include = 69,                   /* include  */
  YYSYMBOL_includedir = 70,                /* includedir  */
  YYSYMBOL_defaults_list = 71,             /* defaults_list  */
  YYSYMBOL_defaults_entry = 72,            /* defaults_entry  */
  YYSYMBOL_privileges = 73,                /* privileges  */
  YYSYMBOL_privilege = 74,                 /* privilege  */
  YYSYMBOL_ophost = 75,                    /* ophost  */
  YYSYMBOL_host = 76,                      /* host  */
  YYSYMBOL_cmndspeclist = 77,              /* cmndspeclist  */
  YYSYMBOL_cmndspec = 78,                  /* cmndspec  */
  YYSYMBOL_digestspec = 79,                /* digestspec  */
  YYSYMBOL_digestlist = 80,                /* digestlist  */
  YYSYMBOL_digcmnd = 81,                   /* digcmnd  */
  YYSYMBOL_opcmnd = 82,                    /* opcmnd  */
  YYSYMBOL_chdirspec = 83,                 /* chdirspec  */
  YYSYMBOL_chrootspec = 84,                /* chrootspec  */
  YYSYMBOL_timeoutspec = 85,               /* timeoutspec  */
  YYSYMBOL_notbeforespec = 86,             /* notbeforespec  */
  YYSYMBOL_notafterspec = 87,              /* notafterspec  */
  YYSYMBOL_rolespec = 88,                  /* rolespec  */
  YYSYMBOL_typespec = 89,                  /* typespec  */
  YYSYMBOL_apparmor_profilespec = 90,      /* apparmor_profilespec  */
  YYSYMBOL_privsspec = 91,                 /* privsspec  */
  YYSYMBOL_limitprivsspec = 92,            /* limitprivsspec  */
  YYSYMBOL_runasspec = 93,                 /* runasspec  */
  YYSYMBOL_runaslist = 94,                 /* runaslist  */
  YYSYMBOL_reserved_word = 95,             /* reserved_word  */
  YYSYMBOL_reserved_alias = 96,            /* reserved_alias  */
  YYSYMBOL_options = 97,                   /* options  */
  YYSYMBOL_cmndtag = 98,                   /* cmndtag  */
  YYSYMBOL_cmnd = 99,                      /* cmnd  */
  YYSYMBOL_hostaliases = 100,              /* hostaliases  */
  YYSYMBOL_hostalias = 101,                /* hostalias  */
  YYSYMBOL_102_1 = 102,                    /* $@1  */
  YYSYMBOL_hostlist = 103,                 /* hostlist  */
  YYSYMBOL_cmndaliases = 104,              /* cmndaliases  */
  YYSYMBOL_cmndalias = 105,                /* cmndalias  */
  YYSYMBOL_106_2 = 106,                    /* $@2  */
  YYSYMBOL_cmndlist = 107,                 /* cmndlist  */
  YYSYMBOL_runasaliases = 108,             /* runasaliases  */
  YYSYMBOL_runasalias = 109,               /* runasalias  */
  YYSYMBOL_110_3 = 110,                    /* $@3  */
  YYSYMBOL_useraliases = 111,              /* useraliases  */
  YYSYMBOL_useralias = 112,                /* useralias  */
  YYSYMBOL_113_4 = 113,                    /* $@4  */
  YYSYMBOL_userlist = 114,                 /* userlist  */
  YYSYMBOL_opuser = 115,                   /* opuser  */
  YYSYMBOL_user = 116,                     /* user  */
  YYSYMBOL_grouplist = 117,                /* grouplist  */
  YYSYMBOL_opgroup = 118,                  /* opgroup  */
  YYSYMBOL_group = 119                     /* group  */
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
# if defined HAVE_STDINT_H
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

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
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
#define YYFINAL  89
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   332

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  65
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  55
/* YYNRULES -- Number of rules.  */
#define YYNRULES  154
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  255

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   310


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
      47,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    42,     2,     2,     2,     2,     2,     2,
      45,    46,     2,    43,    41,    44,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    39,     2,
       2,    40,     2,     2,     2,     2,     2,     2,     2,     2,
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
      35,    36,    37,    38,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    57,    58,    59,    60,    61,    62,    63,
      64
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   201,   201,   204,   207,   208,   211,   214,   217,   226,
     235,   241,   244,   247,   250,   253,   257,   261,   265,   269,
     275,   278,   284,   287,   293,   294,   301,   310,   319,   329,
     339,   351,   352,   357,   363,   380,   384,   390,   399,   407,
     416,   425,   436,   437,   499,   569,   578,   587,   596,   607,
     608,   615,   618,   632,   636,   642,   658,   674,   679,   683,
     688,   693,   698,   703,   707,   712,   715,   720,   736,   747,
     759,   770,   788,   789,   790,   791,   792,   793,   794,   795,
     796,   797,   798,   801,   807,   810,   815,   820,   829,   838,
     850,   857,   864,   871,   878,   887,   890,   893,   896,   899,
     902,   905,   908,   911,   914,   917,   920,   923,   926,   929,
     932,   935,   940,   954,   963,   986,   987,   990,   990,  1002,
    1005,  1006,  1013,  1014,  1017,  1017,  1029,  1032,  1033,  1040,
    1041,  1044,  1044,  1056,  1059,  1060,  1063,  1063,  1075,  1078,
    1079,  1086,  1090,  1096,  1105,  1113,  1122,  1131,  1142,  1143,
    1150,  1154,  1160,  1169,  1177
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
  "NOLOG_OUTPUT", "MAIL", "NOMAIL", "FOLLOWLNK", "NOFOLLOWLNK",
  "INTERCEPT", "NOINTERCEPT", "ALL", "HOSTALIAS", "CMNDALIAS", "USERALIAS",
  "RUNASALIAS", "':'", "'='", "','", "'!'", "'+'", "'-'", "'('", "')'",
  "'\\n'", "ERROR", "NOMATCH", "CHROOT", "CWD", "TYPE", "ROLE",
  "APPARMOR_PROFILE", "PRIVS", "LIMITPRIVS", "CMND_TIMEOUT", "NOTBEFORE",
  "NOTAFTER", "MYSELF", "SHA224_TOK", "SHA256_TOK", "SHA384_TOK",
  "SHA512_TOK", "$accept", "file", "line", "entry", "include",
  "includedir", "defaults_list", "defaults_entry", "privileges",
  "privilege", "ophost", "host", "cmndspeclist", "cmndspec", "digestspec",
  "digestlist", "digcmnd", "opcmnd", "chdirspec", "chrootspec",
  "timeoutspec", "notbeforespec", "notafterspec", "rolespec", "typespec",
  "apparmor_profilespec", "privsspec", "limitprivsspec", "runasspec",
  "runaslist", "reserved_word", "reserved_alias", "options", "cmndtag",
  "cmnd", "hostaliases", "hostalias", "$@1", "hostlist", "cmndaliases",
  "cmndalias", "$@2", "cmndlist", "runasaliases", "runasalias", "$@3",
  "useraliases", "useralias", "$@4", "userlist", "opuser", "user",
  "grouplist", "opgroup", "group", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-115)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-4)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
     177,   -29,  -115,  -115,  -115,  -115,    46,    47,     9,   241,
     245,   245,     6,  -115,    32,    75,    89,   117,   192,  -115,
      41,   221,  -115,  -115,  -115,    69,  -115,  -115,  -115,    10,
      11,   238,    96,    30,  -115,  -115,  -115,  -115,  -115,  -115,
     258,  -115,  -115,     8,    54,    54,  -115,  -115,  -115,   101,
      21,    35,    42,    80,  -115,    12,  -115,  -115,  -115,    56,
    -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,    68,    53,  -115,  -115,    98,    55,  -115,
    -115,   116,    67,  -115,  -115,   119,   111,  -115,  -115,  -115,
    -115,   245,   114,  -115,    -3,   107,  -115,   133,  -115,   127,
     173,   174,  -115,     9,  -115,  -115,   241,   156,   157,   161,
    -115,   195,   196,   197,   199,   209,  -115,     6,   169,   126,
     241,    32,  -115,   178,     6,    75,  -115,   180,   245,    89,
    -115,   183,   245,   117,  -115,  -115,    38,  -115,   172,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,   241,   186,  -115,     6,
     190,  -115,   245,   200,  -115,   245,   200,  -115,  -115,  -115,
     235,   205,  -115,  -115,   186,   190,   200,   200,   153,   194,
      76,   172,   243,  -115,  -115,  -115,   103,   210,  -115,  -115,
    -115,   153,  -115,   220,   226,   236,   240,   244,   246,   248,
     249,   250,   251,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,     1,  -115,   153,   210,   252,   276,   294,
     295,   296,   297,   298,   299,   300,   301,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,  -115,  -115,  -115,  -115
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     0,   143,   145,   146,   147,     0,     0,     0,     0,
       0,     0,     0,   144,     0,     0,     0,     0,     0,     6,
       0,     0,     4,     8,     9,     0,   139,   141,     7,     0,
       0,    26,     0,     0,    24,    37,    40,    39,    41,    38,
       0,   120,    35,     0,     0,     0,   114,   113,   112,     0,
       0,     0,     0,     0,    49,     0,   127,    51,    53,     0,
     117,    72,    73,    74,    79,    78,    82,    80,    81,    75,
      76,    77,    83,     0,     0,   115,   124,     0,     0,   122,
     136,     0,     0,   134,   131,     0,     0,   129,   142,     1,
       5,     0,     0,    31,     0,     0,    20,     0,    22,     0,
       0,     0,    27,     0,    15,    36,     0,     0,     0,     0,
      54,     0,     0,     0,     0,     0,    52,     0,     0,     0,
       0,     0,    12,     0,     0,     0,    13,     0,     0,     0,
      11,     0,     0,     0,    14,   140,     0,    10,    65,    21,
      23,    28,    29,    30,    25,   121,    18,    16,    17,    45,
      46,    47,    48,    50,   128,    19,     0,   119,   116,     0,
     126,   123,     0,   138,   135,     0,   133,   130,    33,    32,
      67,    34,    42,    84,   118,   125,   137,   132,    71,     0,
      68,    65,    95,   152,   154,   153,     0,    70,   148,   150,
      66,     0,    43,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    85,    86,    89,    87,    88,    90,    91,
      92,    93,    94,     0,   151,     0,    69,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    96,    97,    98,
      99,   102,   103,   104,   105,   106,   107,   110,   111,   108,
     109,   100,   101,    44,   149,    56,    55,    61,    60,    62,
      63,    64,    57,    58,    59
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -115,  -115,  -115,   290,  -115,  -115,   120,   211,  -115,   176,
     207,   275,  -115,   135,   202,  -115,  -114,   263,  -115,  -115,
    -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,  -115,
    -115,    -9,  -115,  -115,   270,  -115,   201,  -115,    -7,  -115,
     198,  -115,  -107,  -115,   187,  -115,  -115,   203,  -115,   -10,
     230,   306,   134,   112,   140
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,    20,    21,    22,    23,    24,    33,    34,    92,    93,
      41,    42,   171,   172,    54,    55,    56,    57,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   173,   179,
      72,    73,   182,   213,    58,    74,    75,   119,    94,    78,
      79,   123,    59,    86,    87,   131,    82,    83,   127,    25,
      26,    27,   187,   188,   189
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      44,    45,    43,   154,    46,    47,    77,    81,    85,    46,
      47,    95,    97,    31,    31,    46,    47,   160,    28,   227,
     228,   229,   230,   231,   232,   233,   234,   235,   236,   237,
     238,   239,   240,   241,   242,    48,    60,   138,   106,   168,
      48,    89,    35,    49,    36,    37,    48,    38,    49,   106,
      32,    32,   175,   115,    49,    29,    30,    96,    98,    31,
     111,    31,    50,    51,    52,    53,    61,    50,    51,    52,
      53,   103,    39,    35,   112,    36,    37,   104,    38,    76,
      40,   113,    62,    63,    64,    65,    66,    67,    68,    69,
      70,    71,   121,    80,   125,    91,    32,   117,    32,   243,
     122,   102,   126,    39,    46,    47,   129,   183,   120,    61,
      91,    40,   184,   157,   130,   191,    77,    91,   163,   114,
      81,    84,   166,    61,    85,    62,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    48,   141,   185,   124,    62,
      63,    64,    65,    66,    67,    68,    69,    70,    71,   174,
     133,    61,   176,   136,   139,   177,   128,   183,   134,   132,
     180,   137,   184,   107,   108,   109,   156,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    -2,     1,   118,
     140,     2,   142,   143,     3,     4,     5,   185,     6,     7,
       8,     9,    10,    11,    12,   186,     2,   103,   103,     3,
       4,     5,   103,   146,   147,   149,   150,   151,   148,   152,
     103,    13,    14,    15,    16,    17,   155,   170,   159,    18,
     162,    -3,     1,   165,    19,     2,    13,   106,     3,     4,
       5,   117,     6,     7,     8,     9,    10,    11,    12,     2,
     190,    91,     3,     4,     5,    35,   181,    36,    37,     2,
      38,   215,     3,     4,     5,    13,    14,    15,    16,    17,
     217,   245,    35,    18,    36,    37,   218,    38,    19,    13,
      50,    51,    52,    53,   178,    39,   219,    18,    99,    13,
     220,   100,   101,    40,   221,   246,   222,    18,   223,   224,
     225,   226,    39,   193,   194,   195,   196,   197,   198,   199,
     200,   201,   202,   247,   248,   249,   250,   251,   252,   253,
     254,    90,   169,   145,   144,   105,   192,   153,   116,   110,
     167,   135,   158,   161,    88,   216,   214,   244,     0,     0,
       0,     0,   164
};

static const yytype_int16 yycheck[] =
{
      10,    11,     9,   117,     3,     4,    15,    16,    17,     3,
       4,     1,     1,     5,     5,     3,     4,   124,    47,    18,
      19,    20,    21,    22,    23,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,     4,    40,    41,     1,
      34,     0,     4,    42,     6,     7,    34,     9,    42,    41,
      42,    42,   159,    41,    42,     9,     9,    47,    47,     5,
      39,     5,    61,    62,    63,    64,    34,    61,    62,    63,
      64,    41,    34,     4,    39,     6,     7,    47,     9,     4,
      42,    39,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    39,     4,    39,    41,    42,    41,    42,   213,
      47,     5,    47,    34,     3,     4,    39,     4,    40,    34,
      41,    42,     9,   120,    47,    39,   125,    41,   128,    39,
     129,     4,   132,    34,   133,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    34,     9,    34,    40,    50,
      51,    52,    53,    54,    55,    56,    57,    58,    59,   156,
      39,    34,   162,    39,    47,   165,    40,     4,    47,    40,
     170,    47,     9,    43,    44,    45,    40,    50,    51,    52,
      53,    54,    55,    56,    57,    58,    59,     0,     1,    59,
      47,     4,     9,     9,     7,     8,     9,    34,    11,    12,
      13,    14,    15,    16,    17,    42,     4,    41,    41,     7,
       8,     9,    41,    47,    47,    10,    10,    10,    47,    10,
      41,    34,    35,    36,    37,    38,    47,    45,    40,    42,
      40,     0,     1,    40,    47,     4,    34,    41,     7,     8,
       9,    41,    11,    12,    13,    14,    15,    16,    17,     4,
      46,    41,     7,     8,     9,     4,    41,     6,     7,     4,
       9,    41,     7,     8,     9,    34,    35,    36,    37,    38,
      40,     9,     4,    42,     6,     7,    40,     9,    47,    34,
      61,    62,    63,    64,    39,    34,    40,    42,    40,    34,
      40,    43,    44,    42,    40,     9,    40,    42,    40,    40,
      40,    40,    34,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,     9,     9,     9,     9,     9,     9,     9,
       9,    21,   136,   106,   103,    40,   181,   115,    55,    49,
     133,    91,   121,   125,    18,   191,   186,   215,    -1,    -1,
      -1,    -1,   129
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     1,     4,     7,     8,     9,    11,    12,    13,    14,
      15,    16,    17,    34,    35,    36,    37,    38,    42,    47,
      66,    67,    68,    69,    70,   114,   115,   116,    47,     9,
       9,     5,    42,    71,    72,     4,     6,     7,     9,    34,
      42,    75,    76,   103,   114,   114,     3,     4,    34,    42,
      61,    62,    63,    64,    79,    80,    81,    82,    99,   107,
       4,    34,    50,    51,    52,    53,    54,    55,    56,    57,
      58,    59,    95,    96,   100,   101,     4,    96,   104,   105,
       4,    96,   111,   112,     4,    96,   108,   109,   116,     0,
      68,    41,    73,    74,   103,     1,    47,     1,    47,    40,
      43,    44,     5,    41,    47,    76,    41,    71,    71,    71,
      99,    39,    39,    39,    39,    41,    82,    41,    71,   102,
      40,    39,    47,   106,    40,    39,    47,   113,    40,    39,
      47,   110,    40,    39,    47,   115,    39,    47,    40,    47,
      47,     9,     9,     9,    72,    75,    47,    47,    47,    10,
      10,    10,    10,    79,    81,    47,    40,   103,   101,    40,
     107,   105,    40,   114,   112,    40,   114,   109,     1,    74,
      45,    77,    78,    93,   103,   107,   114,   114,    39,    94,
     114,    41,    97,     4,     9,    34,    42,   117,   118,   119,
      46,    39,    78,    50,    51,    52,    53,    54,    55,    56,
      57,    58,    59,    83,    84,    85,    86,    87,    88,    89,
      90,    91,    92,    98,   119,    41,   117,    40,    40,    40,
      40,    40,    40,    40,    40,    40,    40,    18,    19,    20,
      21,    22,    23,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    81,   118,     9,     9,     9,     9,     9,
       9,     9,     9,     9,     9
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    65,    66,    66,    67,    67,    68,    68,    68,    68,
      68,    68,    68,    68,    68,    68,    68,    68,    68,    68,
      69,    69,    70,    70,    71,    71,    72,    72,    72,    72,
      72,    73,    73,    73,    74,    75,    75,    76,    76,    76,
      76,    76,    77,    77,    78,    79,    79,    79,    79,    80,
      80,    81,    81,    82,    82,    83,    84,    85,    86,    87,
      88,    89,    90,    91,    92,    93,    93,    94,    94,    94,
      94,    94,    95,    95,    95,    95,    95,    95,    95,    95,
      95,    95,    95,    96,    97,    97,    97,    97,    97,    97,
      97,    97,    97,    97,    97,    98,    98,    98,    98,    98,
      98,    98,    98,    98,    98,    98,    98,    98,    98,    98,
      98,    98,    99,    99,    99,   100,   100,   102,   101,   101,
     103,   103,   104,   104,   106,   105,   105,   107,   107,   108,
     108,   110,   109,   109,   111,   111,   113,   112,   112,   114,
     114,   115,   115,   116,   116,   116,   116,   116,   117,   117,
     118,   118,   119,   119,   119
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     0,     1,     1,     2,     1,     2,     1,     1,
       3,     3,     3,     3,     3,     3,     4,     4,     4,     4,
       3,     4,     3,     4,     1,     3,     1,     2,     3,     3,
       3,     1,     3,     3,     3,     1,     2,     1,     1,     1,
       1,     1,     1,     3,     4,     3,     3,     3,     3,     1,
       3,     1,     2,     1,     2,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     0,     3,     0,     1,     3,
       2,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     0,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     0,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     1,     1,     1,     1,     3,     0,     4,     3,
       1,     3,     1,     3,     0,     4,     3,     1,     3,     1,
       3,     0,     4,     3,     1,     3,     0,     4,     3,     1,
       3,     1,     2,     1,     1,     1,     1,     1,     1,     3,
       1,     2,     1,     1,     1
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


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
    YYNOMEM;
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
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
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
#line 201 "gram.y"
                        {
			    ; /* empty file */
			}
#line 1650 "gram.c"
    break;

  case 6: /* entry: '\n'  */
#line 211 "gram.y"
                             {
			    ; /* blank line */
			}
#line 1658 "gram.c"
    break;

  case 7: /* entry: error '\n'  */
#line 214 "gram.y"
                                   {
			    yyerrok;
			}
#line 1666 "gram.c"
    break;

  case 8: /* entry: include  */
#line 217 "gram.y"
                                {
			    if (!push_include((yyvsp[0].string), false)) {
				parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
				free((yyvsp[0].string));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    free((yyvsp[0].string));
			}
#line 1680 "gram.c"
    break;

  case 9: /* entry: includedir  */
#line 226 "gram.y"
                                   {
			    if (!push_include((yyvsp[0].string), true)) {
				parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
				free((yyvsp[0].string));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    free((yyvsp[0].string));
			}
#line 1694 "gram.c"
    break;

  case 10: /* entry: userlist privileges '\n'  */
#line 235 "gram.y"
                                                 {
			    if (!add_userspec((yyvsp[-2].member), (yyvsp[-1].privilege))) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
#line 1705 "gram.c"
    break;

  case 11: /* entry: USERALIAS useraliases '\n'  */
#line 241 "gram.y"
                                                   {
			    ;
			}
#line 1713 "gram.c"
    break;

  case 12: /* entry: HOSTALIAS hostaliases '\n'  */
#line 244 "gram.y"
                                                   {
			    ;
			}
#line 1721 "gram.c"
    break;

  case 13: /* entry: CMNDALIAS cmndaliases '\n'  */
#line 247 "gram.y"
                                                   {
			    ;
			}
#line 1729 "gram.c"
    break;

  case 14: /* entry: RUNASALIAS runasaliases '\n'  */
#line 250 "gram.y"
                                                     {
			    ;
			}
#line 1737 "gram.c"
    break;

  case 15: /* entry: DEFAULTS defaults_list '\n'  */
#line 253 "gram.y"
                                                    {
			    if (!add_defaults(DEFAULTS, NULL, (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1746 "gram.c"
    break;

  case 16: /* entry: DEFAULTS_USER userlist defaults_list '\n'  */
#line 257 "gram.y"
                                                                  {
			    if (!add_defaults(DEFAULTS_USER, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1755 "gram.c"
    break;

  case 17: /* entry: DEFAULTS_RUNAS userlist defaults_list '\n'  */
#line 261 "gram.y"
                                                                   {
			    if (!add_defaults(DEFAULTS_RUNAS, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1764 "gram.c"
    break;

  case 18: /* entry: DEFAULTS_HOST hostlist defaults_list '\n'  */
#line 265 "gram.y"
                                                                  {
			    if (!add_defaults(DEFAULTS_HOST, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1773 "gram.c"
    break;

  case 19: /* entry: DEFAULTS_CMND cmndlist defaults_list '\n'  */
#line 269 "gram.y"
                                                                  {
			    if (!add_defaults(DEFAULTS_CMND, (yyvsp[-2].member), (yyvsp[-1].defaults)))
				YYERROR;
			}
#line 1782 "gram.c"
    break;

  case 20: /* include: INCLUDE WORD '\n'  */
#line 275 "gram.y"
                                          {
			    (yyval.string) = (yyvsp[-1].string);
			}
#line 1790 "gram.c"
    break;

  case 21: /* include: INCLUDE WORD error '\n'  */
#line 278 "gram.y"
                                                {
			    yyerrok;
			    (yyval.string) = (yyvsp[-2].string);
			}
#line 1799 "gram.c"
    break;

  case 22: /* includedir: INCLUDEDIR WORD '\n'  */
#line 284 "gram.y"
                                             {
			    (yyval.string) = (yyvsp[-1].string);
			}
#line 1807 "gram.c"
    break;

  case 23: /* includedir: INCLUDEDIR WORD error '\n'  */
#line 287 "gram.y"
                                                   {
			    yyerrok;
			    (yyval.string) = (yyvsp[-2].string);
			}
#line 1816 "gram.c"
    break;

  case 25: /* defaults_list: defaults_list ',' defaults_entry  */
#line 294 "gram.y"
                                                         {
			    parser_leak_remove(LEAK_DEFAULTS, (yyvsp[0].defaults));
			    HLTQ_CONCAT((yyvsp[-2].defaults), (yyvsp[0].defaults), entries);
			    (yyval.defaults) = (yyvsp[-2].defaults);
			}
#line 1826 "gram.c"
    break;

  case 26: /* defaults_entry: DEFVAR  */
#line 301 "gram.y"
                               {
			    (yyval.defaults) = new_default((yyvsp[0].string), NULL, true);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DEFAULTS, (yyval.defaults));
			}
#line 1840 "gram.c"
    break;

  case 27: /* defaults_entry: '!' DEFVAR  */
#line 310 "gram.y"
                                   {
			    (yyval.defaults) = new_default((yyvsp[0].string), NULL, false);
			    if ((yyval.defaults) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DEFAULTS, (yyval.defaults));
			}
#line 1854 "gram.c"
    break;

  case 28: /* defaults_entry: DEFVAR '=' WORD  */
#line 319 "gram.y"
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
#line 1869 "gram.c"
    break;

  case 29: /* defaults_entry: DEFVAR '+' WORD  */
#line 329 "gram.y"
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
#line 1884 "gram.c"
    break;

  case 30: /* defaults_entry: DEFVAR '-' WORD  */
#line 339 "gram.y"
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
#line 1899 "gram.c"
    break;

  case 32: /* privileges: privileges ':' privilege  */
#line 352 "gram.y"
                                                 {
			    parser_leak_remove(LEAK_PRIVILEGE, (yyvsp[0].privilege));
			    HLTQ_CONCAT((yyvsp[-2].privilege), (yyvsp[0].privilege), entries);
			    (yyval.privilege) = (yyvsp[-2].privilege);
			}
#line 1909 "gram.c"
    break;

  case 33: /* privileges: privileges ':' error  */
#line 357 "gram.y"
                                             {
			    yyerrok;
			    (yyval.privilege) = (yyvsp[-2].privilege);
			}
#line 1918 "gram.c"
    break;

  case 34: /* privilege: hostlist '=' cmndspeclist  */
#line 363 "gram.y"
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
#line 1938 "gram.c"
    break;

  case 35: /* ophost: host  */
#line 380 "gram.y"
                             {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 1947 "gram.c"
    break;

  case 36: /* ophost: '!' host  */
#line 384 "gram.y"
                                 {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 1956 "gram.c"
    break;

  case 37: /* host: ALIAS  */
#line 390 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 1970 "gram.c"
    break;

  case 38: /* host: ALL  */
#line 399 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 1983 "gram.c"
    break;

  case 39: /* host: NETGROUP  */
#line 407 "gram.y"
                                 {
			    (yyval.member) = new_member((yyvsp[0].string), NETGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 1997 "gram.c"
    break;

  case 40: /* host: NTWKADDR  */
#line 416 "gram.y"
                                 {
			    (yyval.member) = new_member((yyvsp[0].string), NTWKADDR);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2011 "gram.c"
    break;

  case 41: /* host: WORD  */
#line 425 "gram.y"
                             {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2025 "gram.c"
    break;

  case 43: /* cmndspeclist: cmndspeclist ',' cmndspec  */
#line 437 "gram.y"
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
			    if ((yyvsp[0].cmndspec)->tags.intercept == UNSPEC)
				(yyvsp[0].cmndspec)->tags.intercept = prev->tags.intercept;
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
#line 2090 "gram.c"
    break;

  case 44: /* cmndspec: runasspec options cmndtag digcmnd  */
#line 499 "gram.y"
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
#ifdef HAVE_APPARMOR
				cs->apparmor_profile = (yyvsp[-2].options).apparmor_profile;
				parser_leak_remove(LEAK_PTR, (yyvsp[-2].options).apparmor_profile);
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
#line 2163 "gram.c"
    break;

  case 45: /* digestspec: SHA224_TOK ':' DIGEST  */
#line 569 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA224, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DIGEST, (yyval.digest));
			}
#line 2177 "gram.c"
    break;

  case 46: /* digestspec: SHA256_TOK ':' DIGEST  */
#line 578 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA256, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DIGEST, (yyval.digest));
			}
#line 2191 "gram.c"
    break;

  case 47: /* digestspec: SHA384_TOK ':' DIGEST  */
#line 587 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA384, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DIGEST, (yyval.digest));
			}
#line 2205 "gram.c"
    break;

  case 48: /* digestspec: SHA512_TOK ':' DIGEST  */
#line 596 "gram.y"
                                              {
			    (yyval.digest) = new_digest(SUDO_DIGEST_SHA512, (yyvsp[0].string));
			    if ((yyval.digest) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_DIGEST, (yyval.digest));
			}
#line 2219 "gram.c"
    break;

  case 50: /* digestlist: digestlist ',' digestspec  */
#line 608 "gram.y"
                                                  {
			    parser_leak_remove(LEAK_DIGEST, (yyvsp[0].digest));
			    HLTQ_CONCAT((yyvsp[-2].digest), (yyvsp[0].digest), entries);
			    (yyval.digest) = (yyvsp[-2].digest);
			}
#line 2229 "gram.c"
    break;

  case 51: /* digcmnd: opcmnd  */
#line 615 "gram.y"
                               {
			    (yyval.member) = (yyvsp[0].member);
			}
#line 2237 "gram.c"
    break;

  case 52: /* digcmnd: digestlist opcmnd  */
#line 618 "gram.y"
                                          {
			    struct sudo_command *c =
				(struct sudo_command *) (yyvsp[0].member)->name;

			    if ((yyvsp[0].member)->type != COMMAND && (yyvsp[0].member)->type != ALL) {
				sudoerserror(N_("a digest requires a path name"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_DIGEST, (yyvsp[-1].digest));
			    HLTQ_TO_TAILQ(&c->digests, (yyvsp[-1].digest), entries);
			    (yyval.member) = (yyvsp[0].member);
			}
#line 2254 "gram.c"
    break;

  case 53: /* opcmnd: cmnd  */
#line 632 "gram.y"
                             {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 2263 "gram.c"
    break;

  case 54: /* opcmnd: '!' cmnd  */
#line 636 "gram.y"
                                 {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 2272 "gram.c"
    break;

  case 55: /* chdirspec: CWD '=' WORD  */
#line 642 "gram.y"
                                     {
			    if ((yyvsp[0].string)[0] != '/' && (yyvsp[0].string)[0] != '~') {
				if (strcmp((yyvsp[0].string), "*") != 0) {
				    sudoerserror(N_("values for \"CWD\" must"
					" start with a '/', '~', or '*'"));
				    YYERROR;
				}
			    }
			    if (strlen((yyvsp[0].string)) >= PATH_MAX) {
				sudoerserror(N_("\"CWD\" path too long"));
				YYERROR;
			    }
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2291 "gram.c"
    break;

  case 56: /* chrootspec: CHROOT '=' WORD  */
#line 658 "gram.y"
                                        {
			    if ((yyvsp[0].string)[0] != '/' && (yyvsp[0].string)[0] != '~') {
				if (strcmp((yyvsp[0].string), "*") != 0) {
				    sudoerserror(N_("values for \"CHROOT\" must"
					" start with a '/', '~', or '*'"));
				    YYERROR;
				}
			    }
			    if (strlen((yyvsp[0].string)) >= PATH_MAX) {
				sudoerserror(N_("\"CHROOT\" path too long"));
				YYERROR;
			    }
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2310 "gram.c"
    break;

  case 57: /* timeoutspec: CMND_TIMEOUT '=' WORD  */
#line 674 "gram.y"
                                              {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2318 "gram.c"
    break;

  case 58: /* notbeforespec: NOTBEFORE '=' WORD  */
#line 679 "gram.y"
                                           {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2326 "gram.c"
    break;

  case 59: /* notafterspec: NOTAFTER '=' WORD  */
#line 683 "gram.y"
                                          {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2334 "gram.c"
    break;

  case 60: /* rolespec: ROLE '=' WORD  */
#line 688 "gram.y"
                                      {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2342 "gram.c"
    break;

  case 61: /* typespec: TYPE '=' WORD  */
#line 693 "gram.y"
                                      {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2350 "gram.c"
    break;

  case 62: /* apparmor_profilespec: APPARMOR_PROFILE '=' WORD  */
#line 698 "gram.y"
                                                          {
				(yyval.string) = (yyvsp[0].string);
			}
#line 2358 "gram.c"
    break;

  case 63: /* privsspec: PRIVS '=' WORD  */
#line 703 "gram.y"
                                       {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2366 "gram.c"
    break;

  case 64: /* limitprivsspec: LIMITPRIVS '=' WORD  */
#line 707 "gram.y"
                                            {
			    (yyval.string) = (yyvsp[0].string);
			}
#line 2374 "gram.c"
    break;

  case 65: /* runasspec: %empty  */
#line 712 "gram.y"
                                    {
			    (yyval.runas) = NULL;
			}
#line 2382 "gram.c"
    break;

  case 66: /* runasspec: '(' runaslist ')'  */
#line 715 "gram.y"
                                          {
			    (yyval.runas) = (yyvsp[-1].runas);
			}
#line 2390 "gram.c"
    break;

  case 67: /* runaslist: %empty  */
#line 720 "gram.y"
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
#line 2411 "gram.c"
    break;

  case 68: /* runaslist: userlist  */
#line 736 "gram.y"
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
#line 2427 "gram.c"
    break;

  case 69: /* runaslist: userlist ':' grouplist  */
#line 747 "gram.y"
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
#line 2444 "gram.c"
    break;

  case 70: /* runaslist: ':' grouplist  */
#line 759 "gram.y"
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
#line 2460 "gram.c"
    break;

  case 71: /* runaslist: ':'  */
#line 770 "gram.y"
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
#line 2481 "gram.c"
    break;

  case 72: /* reserved_word: ALL  */
#line 788 "gram.y"
                                        { (yyval.cstring) = "ALL"; }
#line 2487 "gram.c"
    break;

  case 73: /* reserved_word: CHROOT  */
#line 789 "gram.y"
                                        { (yyval.cstring) = "CHROOT"; }
#line 2493 "gram.c"
    break;

  case 74: /* reserved_word: CWD  */
#line 790 "gram.y"
                                        { (yyval.cstring) = "CWD"; }
#line 2499 "gram.c"
    break;

  case 75: /* reserved_word: CMND_TIMEOUT  */
#line 791 "gram.y"
                                        { (yyval.cstring) = "CMND_TIMEOUT"; }
#line 2505 "gram.c"
    break;

  case 76: /* reserved_word: NOTBEFORE  */
#line 792 "gram.y"
                                        { (yyval.cstring) = "NOTBEFORE"; }
#line 2511 "gram.c"
    break;

  case 77: /* reserved_word: NOTAFTER  */
#line 793 "gram.y"
                                        { (yyval.cstring) = "NOTAFTER"; }
#line 2517 "gram.c"
    break;

  case 78: /* reserved_word: ROLE  */
#line 794 "gram.y"
                                        { (yyval.cstring) = "ROLE"; }
#line 2523 "gram.c"
    break;

  case 79: /* reserved_word: TYPE  */
#line 795 "gram.y"
                                        { (yyval.cstring) = "TYPE"; }
#line 2529 "gram.c"
    break;

  case 80: /* reserved_word: PRIVS  */
#line 796 "gram.y"
                                        { (yyval.cstring) = "PRIVS"; }
#line 2535 "gram.c"
    break;

  case 81: /* reserved_word: LIMITPRIVS  */
#line 797 "gram.y"
                                        { (yyval.cstring) = "LIMITPRIVS"; }
#line 2541 "gram.c"
    break;

  case 82: /* reserved_word: APPARMOR_PROFILE  */
#line 798 "gram.y"
                                         { (yyval.cstring) = "APPARMOR_PROFILE"; }
#line 2547 "gram.c"
    break;

  case 83: /* reserved_alias: reserved_word  */
#line 801 "gram.y"
                                      {
			    sudoerserrorf(U_("syntax error, reserved word %s used as an alias name"), (yyvsp[0].cstring));
			    YYERROR;
			}
#line 2556 "gram.c"
    break;

  case 84: /* options: %empty  */
#line 807 "gram.y"
                                    {
			    init_options(&(yyval.options));
			}
#line 2564 "gram.c"
    break;

  case 85: /* options: options chdirspec  */
#line 810 "gram.y"
                                          {
			    parser_leak_remove(LEAK_PTR, (yyval.options).runcwd);
			    free((yyval.options).runcwd);
			    (yyval.options).runcwd = (yyvsp[0].string);
			}
#line 2574 "gram.c"
    break;

  case 86: /* options: options chrootspec  */
#line 815 "gram.y"
                                           {
			    parser_leak_remove(LEAK_PTR, (yyval.options).runchroot);
			    free((yyval.options).runchroot);
			    (yyval.options).runchroot = (yyvsp[0].string);
			}
#line 2584 "gram.c"
    break;

  case 87: /* options: options notbeforespec  */
#line 820 "gram.y"
                                              {
			    (yyval.options).notbefore = parse_gentime((yyvsp[0].string));
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).notbefore == -1) {
				sudoerserror(N_("invalid notbefore value"));
				YYERROR;
			    }
			}
#line 2598 "gram.c"
    break;

  case 88: /* options: options notafterspec  */
#line 829 "gram.y"
                                             {
			    (yyval.options).notafter = parse_gentime((yyvsp[0].string));
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    free((yyvsp[0].string));
			    if ((yyval.options).notafter == -1) {
				sudoerserror(N_("invalid notafter value"));
				YYERROR;
			    }
			}
#line 2612 "gram.c"
    break;

  case 89: /* options: options timeoutspec  */
#line 838 "gram.y"
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
#line 2629 "gram.c"
    break;

  case 90: /* options: options rolespec  */
#line 850 "gram.y"
                                         {
#ifdef HAVE_SELINUX
			    parser_leak_remove(LEAK_PTR, (yyval.options).role);
			    free((yyval.options).role);
			    (yyval.options).role = (yyvsp[0].string);
#endif
			}
#line 2641 "gram.c"
    break;

  case 91: /* options: options typespec  */
#line 857 "gram.y"
                                         {
#ifdef HAVE_SELINUX
			    parser_leak_remove(LEAK_PTR, (yyval.options).type);
			    free((yyval.options).type);
			    (yyval.options).type = (yyvsp[0].string);
#endif
			}
#line 2653 "gram.c"
    break;

  case 92: /* options: options apparmor_profilespec  */
#line 864 "gram.y"
                                                     {
#ifdef HAVE_APPARMOR
				parser_leak_remove(LEAK_PTR, (yyval.options).apparmor_profile);
				free((yyval.options).apparmor_profile);
				(yyval.options).apparmor_profile = (yyvsp[0].string);
#endif
			}
#line 2665 "gram.c"
    break;

  case 93: /* options: options privsspec  */
#line 871 "gram.y"
                                          {
#ifdef HAVE_PRIV_SET
			    parser_leak_remove(LEAK_PTR, (yyval.options).privs);
			    free((yyval.options).privs);
			    (yyval.options).privs = (yyvsp[0].string);
#endif
			}
#line 2677 "gram.c"
    break;

  case 94: /* options: options limitprivsspec  */
#line 878 "gram.y"
                                               {
#ifdef HAVE_PRIV_SET
			    parser_leak_remove(LEAK_PTR, (yyval.options).limitprivs);
			    free((yyval.options).limitprivs);
			    (yyval.options).limitprivs = (yyvsp[0].string);
#endif
			}
#line 2689 "gram.c"
    break;

  case 95: /* cmndtag: %empty  */
#line 887 "gram.y"
                                    {
			    TAGS_INIT(&(yyval.tag));
			}
#line 2697 "gram.c"
    break;

  case 96: /* cmndtag: cmndtag NOPASSWD  */
#line 890 "gram.y"
                                         {
			    (yyval.tag).nopasswd = true;
			}
#line 2705 "gram.c"
    break;

  case 97: /* cmndtag: cmndtag PASSWD  */
#line 893 "gram.y"
                                       {
			    (yyval.tag).nopasswd = false;
			}
#line 2713 "gram.c"
    break;

  case 98: /* cmndtag: cmndtag NOEXEC  */
#line 896 "gram.y"
                                       {
			    (yyval.tag).noexec = true;
			}
#line 2721 "gram.c"
    break;

  case 99: /* cmndtag: cmndtag EXEC  */
#line 899 "gram.y"
                                     {
			    (yyval.tag).noexec = false;
			}
#line 2729 "gram.c"
    break;

  case 100: /* cmndtag: cmndtag INTERCEPT  */
#line 902 "gram.y"
                                          {
			    (yyval.tag).intercept = true;
			}
#line 2737 "gram.c"
    break;

  case 101: /* cmndtag: cmndtag NOINTERCEPT  */
#line 905 "gram.y"
                                            {
			    (yyval.tag).intercept = false;
			}
#line 2745 "gram.c"
    break;

  case 102: /* cmndtag: cmndtag SETENV  */
#line 908 "gram.y"
                                       {
			    (yyval.tag).setenv = true;
			}
#line 2753 "gram.c"
    break;

  case 103: /* cmndtag: cmndtag NOSETENV  */
#line 911 "gram.y"
                                         {
			    (yyval.tag).setenv = false;
			}
#line 2761 "gram.c"
    break;

  case 104: /* cmndtag: cmndtag LOG_INPUT  */
#line 914 "gram.y"
                                          {
			    (yyval.tag).log_input = true;
			}
#line 2769 "gram.c"
    break;

  case 105: /* cmndtag: cmndtag NOLOG_INPUT  */
#line 917 "gram.y"
                                            {
			    (yyval.tag).log_input = false;
			}
#line 2777 "gram.c"
    break;

  case 106: /* cmndtag: cmndtag LOG_OUTPUT  */
#line 920 "gram.y"
                                           {
			    (yyval.tag).log_output = true;
			}
#line 2785 "gram.c"
    break;

  case 107: /* cmndtag: cmndtag NOLOG_OUTPUT  */
#line 923 "gram.y"
                                             {
			    (yyval.tag).log_output = false;
			}
#line 2793 "gram.c"
    break;

  case 108: /* cmndtag: cmndtag FOLLOWLNK  */
#line 926 "gram.y"
                                          {
			    (yyval.tag).follow = true;
			}
#line 2801 "gram.c"
    break;

  case 109: /* cmndtag: cmndtag NOFOLLOWLNK  */
#line 929 "gram.y"
                                            {
			    (yyval.tag).follow = false;
			}
#line 2809 "gram.c"
    break;

  case 110: /* cmndtag: cmndtag MAIL  */
#line 932 "gram.y"
                                     {
			    (yyval.tag).send_mail = true;
			}
#line 2817 "gram.c"
    break;

  case 111: /* cmndtag: cmndtag NOMAIL  */
#line 935 "gram.y"
                                       {
			    (yyval.tag).send_mail = false;
			}
#line 2825 "gram.c"
    break;

  case 112: /* cmnd: ALL  */
#line 940 "gram.y"
                            {
			    struct sudo_command *c;

			    if ((c = new_command(NULL, NULL)) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    (yyval.member) = new_member((char *)c, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2844 "gram.c"
    break;

  case 113: /* cmnd: ALIAS  */
#line 954 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 2858 "gram.c"
    break;

  case 114: /* cmnd: COMMAND  */
#line 963 "gram.y"
                                {
			    struct sudo_command *c;

			    if (strlen((yyvsp[0].command).cmnd) >= PATH_MAX) {
				sudoerserror(N_("command too long"));
				YYERROR;
			    }
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
#line 2884 "gram.c"
    break;

  case 117: /* $@1: %empty  */
#line 990 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2893 "gram.c"
    break;

  case 118: /* hostalias: ALIAS $@1 '=' hostlist  */
#line 993 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), HOSTALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-3].string));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			}
#line 2907 "gram.c"
    break;

  case 121: /* hostlist: hostlist ',' ophost  */
#line 1006 "gram.y"
                                            {
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2917 "gram.c"
    break;

  case 124: /* $@2: %empty  */
#line 1017 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2926 "gram.c"
    break;

  case 125: /* cmndalias: ALIAS $@2 '=' cmndlist  */
#line 1020 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), CMNDALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-3].string));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			}
#line 2940 "gram.c"
    break;

  case 128: /* cmndlist: cmndlist ',' digcmnd  */
#line 1033 "gram.y"
                                             {
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 2950 "gram.c"
    break;

  case 131: /* $@3: %empty  */
#line 1044 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2959 "gram.c"
    break;

  case 132: /* runasalias: ALIAS $@3 '=' userlist  */
#line 1047 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), RUNASALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-3].string));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			}
#line 2973 "gram.c"
    break;

  case 136: /* $@4: %empty  */
#line 1063 "gram.y"
                              {
			    alias_line = this_lineno;
			    alias_column = sudolinebuf.toke_start + 1;
			}
#line 2982 "gram.c"
    break;

  case 137: /* useralias: ALIAS $@4 '=' userlist  */
#line 1066 "gram.y"
                                       {
			    if (!alias_add(&parsed_policy, (yyvsp[-3].string), USERALIAS,
				sudoers, alias_line, alias_column, (yyvsp[0].member))) {
				alias_error((yyvsp[-3].string), errno);
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[-3].string));
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			}
#line 2996 "gram.c"
    break;

  case 140: /* userlist: userlist ',' opuser  */
#line 1079 "gram.y"
                                            {
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 3006 "gram.c"
    break;

  case 141: /* opuser: user  */
#line 1086 "gram.y"
                             {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 3015 "gram.c"
    break;

  case 142: /* opuser: '!' user  */
#line 1090 "gram.y"
                                 {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 3024 "gram.c"
    break;

  case 143: /* user: ALIAS  */
#line 1096 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3038 "gram.c"
    break;

  case 144: /* user: ALL  */
#line 1105 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3051 "gram.c"
    break;

  case 145: /* user: NETGROUP  */
#line 1113 "gram.y"
                                 {
			    (yyval.member) = new_member((yyvsp[0].string), NETGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3065 "gram.c"
    break;

  case 146: /* user: USERGROUP  */
#line 1122 "gram.y"
                                  {
			    (yyval.member) = new_member((yyvsp[0].string), USERGROUP);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3079 "gram.c"
    break;

  case 147: /* user: WORD  */
#line 1131 "gram.y"
                             {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3093 "gram.c"
    break;

  case 149: /* grouplist: grouplist ',' opgroup  */
#line 1143 "gram.y"
                                              {
			    parser_leak_remove(LEAK_MEMBER, (yyvsp[0].member));
			    HLTQ_CONCAT((yyvsp[-2].member), (yyvsp[0].member), entries);
			    (yyval.member) = (yyvsp[-2].member);
			}
#line 3103 "gram.c"
    break;

  case 150: /* opgroup: group  */
#line 1150 "gram.y"
                              {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = false;
			}
#line 3112 "gram.c"
    break;

  case 151: /* opgroup: '!' group  */
#line 1154 "gram.y"
                                  {
			    (yyval.member) = (yyvsp[0].member);
			    (yyval.member)->negated = true;
			}
#line 3121 "gram.c"
    break;

  case 152: /* group: ALIAS  */
#line 1160 "gram.y"
                              {
			    (yyval.member) = new_member((yyvsp[0].string), ALIAS);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3135 "gram.c"
    break;

  case 153: /* group: ALL  */
#line 1169 "gram.y"
                            {
			    (yyval.member) = new_member(NULL, ALL);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3148 "gram.c"
    break;

  case 154: /* group: WORD  */
#line 1177 "gram.y"
                             {
			    (yyval.member) = new_member((yyvsp[0].string), WORD);
			    if ((yyval.member) == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    parser_leak_remove(LEAK_PTR, (yyvsp[0].string));
			    parser_leak_add(LEAK_MEMBER, (yyval.member));
			}
#line 3162 "gram.c"
    break;


#line 3166 "gram.c"

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
  ++yynerrs;

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
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
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

#line 1187 "gram.y"

/* Like yyerror() but takes a printf-style format string. */
void
sudoerserrorf(const char *fmt, ...)
{
    const int column = sudolinebuf.toke_start + 1;
    va_list ap;
    debug_decl(sudoerserrorf, SUDOERS_DEBUG_PARSER);

    if (sudoers_error_hook != NULL) {
	va_start(ap, fmt);
	sudoers_error_hook(sudoers, this_lineno, column, fmt, ap);
	va_end(ap);
    }
    if (sudoers_warnings && fmt != NULL) {
	LEXTRACE("<*> ");
#ifndef TRACELEXER
	if (trace_print == NULL || trace_print == sudoers_trace_print) {
	    char *tofree = NULL;
	    const char *s;
	    int oldlocale;

	    /* Warnings are displayed in the user's locale. */
	    sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);

	    va_start(ap, fmt);
	    if (strcmp(fmt, "%s") == 0) {
		/* Optimize common case, a single string. */
		s = _(va_arg(ap, char *));
	    } else {
		if (vasprintf(&tofree, _(fmt), ap) != -1) {
		    s = tofree;
		} else {
		    s = _("syntax error");
		    tofree = NULL;
		}
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
    if (sudoerschar == ERROR) {
	/* Use error string from lexer. */
	s = sudoers_errstr;
	sudoers_errstr = NULL;
    }

#pragma pvs(push)
#pragma pvs(disable: 575, 618)

    if (s == NULL)
	sudoerserrorf(NULL);
    else
	sudoerserrorf("%s", s);

#pragma pvs(pop)
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
    /* d->binding = NULL; */
    d->line = this_lineno;
    d->column = sudolinebuf.toke_start + 1;
    d->file = sudo_rcstr_addref(sudoers);
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

static void
free_defaults_binding(struct defaults_binding *binding)
{
    debug_decl(free_defaults_binding, SUDOERS_DEBUG_PARSER);

    /* Bindings may be shared among multiple Defaults entries. */
    if (binding != NULL) {
	if (--binding->refcnt == 0) {
	    free_members(&binding->members);
	    free(binding);
	}
    }

    debug_return;
}

/*
 * Add a list of defaults structures to the defaults list.
 * The bmem argument, if non-NULL, specifies a list of hosts, users,
 * or runas users the entries apply to (determined by the type).
 */
static bool
add_defaults(int type, struct member *bmem, struct defaults *defs)
{
    struct defaults *d, *next;
    struct defaults_binding *binding;
    bool ret = true;
    debug_decl(add_defaults, SUDOERS_DEBUG_PARSER);

    if (defs == NULL)
	debug_return_bool(false);

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
	HLTQ_TO_TAILQ(&binding->members, bmem, entries);
    } else {
	TAILQ_INIT(&binding->members);
    }
    binding->refcnt = 0;

    /*
     * Set type and binding (who it applies to) for new entries.
     * Then add to the global defaults list.
     */
    parser_leak_remove(LEAK_DEFAULTS, defs);
    HLTQ_FOREACH_SAFE(d, defs, entries, next) {
	d->type = type;
	d->binding = binding;
	binding->refcnt++;
	TAILQ_INSERT_TAIL(&parsed_policy.defaults, d, entries);
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
    /* We already parsed the newline so sudolineno is off by one. */
    u->line = sudolineno - 1;
    u->column = sudolinebuf.toke_start + 1;
    u->file = sudo_rcstr_addref(sudoers);
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
    struct defaults *def;
    debug_decl(free_defaults, SUDOERS_DEBUG_PARSER);

    while ((def = TAILQ_FIRST(defs)) != NULL) {
	TAILQ_REMOVE(defs, def, entries);
	free_default(def);
    }

    debug_return;
}

void
free_default(struct defaults *def)
{
    debug_decl(free_default, SUDOERS_DEBUG_PARSER);

    free_defaults_binding(def->binding);
    sudo_rcstr_delref(def->file);
    free(def->var);
    free(def->val);
    free(def);

    debug_return;
}

void
free_cmndspec(struct cmndspec *cs, struct cmndspec_list *csl)
{
    struct cmndspec *prev, *next;
    debug_decl(free_cmndspec, SUDOERS_DEBUG_PARSER);

    prev = TAILQ_PREV(cs, cmndspec_list, entries);
    next = TAILQ_NEXT(cs, entries);
    TAILQ_REMOVE(csl, cs, entries);

    /* Don't free runcwd/runchroot that are in use by other entries. */
    if ((prev == NULL || cs->runcwd != prev->runcwd) &&
	(next == NULL || cs->runcwd != next->runcwd)) {
	free(cs->runcwd);
    }
    if ((prev == NULL || cs->runchroot != prev->runchroot) &&
	(next == NULL || cs->runchroot != next->runchroot)) {
	free(cs->runchroot);
    }
#ifdef HAVE_SELINUX
    /* Don't free root/type that are in use by other entries. */
    if ((prev == NULL || cs->role != prev->role) &&
	(next == NULL || cs->role != next->role)) {
	free(cs->role);
    }
    if ((prev == NULL || cs->type != prev->type) &&
	(next == NULL || cs->type != next->type)) {
	free(cs->type);
    }
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
    /* Don't free privs/limitprivs that are in use by other entries. */
    if ((prev == NULL || cs->privs != prev->privs) &&
	(next == NULL || cs->privs != next->privs)) {
	free(cs->privs);
    }
    if ((prev == NULL || cs->limitprivs != prev->limitprivs) &&
	(next == NULL || cs->limitprivs != next->limitprivs)) {
	free(cs->limitprivs);
    }
#endif /* HAVE_PRIV_SET */
    /* Don't free user/group lists that are in use by other entries. */
    if (cs->runasuserlist != NULL) {
	if ((prev == NULL || cs->runasuserlist != prev->runasuserlist) &&
	    (next == NULL || cs->runasuserlist != next->runasuserlist)) {
	    free_members(cs->runasuserlist);
	    free(cs->runasuserlist);
	}
    }
    if (cs->runasgrouplist != NULL) {
	if ((prev == NULL || cs->runasgrouplist != prev->runasgrouplist) &&
	    (next == NULL || cs->runasgrouplist != next->runasgrouplist)) {
	    free_members(cs->runasgrouplist);
	    free(cs->runasgrouplist);
	}
    }
    free_member(cs->cmnd);
    free(cs);

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
    struct defaults *def;
    debug_decl(free_privilege, SUDOERS_DEBUG_PARSER);

    free(priv->ldap_role);
    free_members(&priv->hostlist);
    free_cmndspecs(&priv->cmndlist);
    while ((def = TAILQ_FIRST(&priv->defaults)) != NULL) {
	TAILQ_REMOVE(&priv->defaults, def, entries);
	free_default(def);
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
    sudo_rcstr_delref(us->file);
    free(us);

    debug_return;
}

/*
 * Initialized a sudoers parse tree.
 * Takes ownership of lhost and shost.
 */
void
init_parse_tree(struct sudoers_parse_tree *parse_tree, char *lhost, char *shost)
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
    free(parse_tree->lhost);
    if (parse_tree->shost != parse_tree->lhost)
	free(parse_tree->shost);
    parse_tree->lhost = parse_tree->shost = NULL;
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

    sudo_rcstr_delref(sudoers);
    if (path != NULL) {
	if ((sudoers = sudo_rcstr_dup(path)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    ret = false;
	}
    } else {
	sudoers = NULL;
    }

    parse_error = false;
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
#ifdef HAVE_APPARMOR
    opts->apparmor_profile = NULL;
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

#ifdef NO_LEAKS
static void
parser_leak_free(void)
{
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
}
#endif /* NO_LEAKS */

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
