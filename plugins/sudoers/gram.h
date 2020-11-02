/* A Bison parser, made by GNU Bison 3.3.2.  */

/* Bison interface for Yacc-like parsers in C

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

/* Undocumented macros, especially those whose name start with YY_,
   are private implementation details.  Do not rely on them.  */

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
#line 79 "gram.y" /* yacc.c:1921  */

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

#line 176 "y.tab.h" /* yacc.c:1921  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE sudoerslval;

int sudoersparse (void);

#endif /* !YY_SUDOERS_Y_TAB_H_INCLUDED  */
