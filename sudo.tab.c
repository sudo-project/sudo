#ifndef lint
/*static char yysccsid[] = "from: @(#)yaccpar	1.9 (Berkeley) 02/21/93";*/
static char yyrcsid[]
#if __GNUC__ == 2
  __attribute__ ((unused))
#endif /* __GNUC__ == 2 */
  = "$OpenBSD: skeleton.c,v 1.13 1998/11/18 15:45:12 dm Exp $";
#endif
#include <stdlib.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
#define YYPREFIX "yy"
#line 2 "parse.yacc"
/*
 * Copyright (c) 1996, 1998, 1999 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * This code is derived from software contributed by Chris Jepeway
 * <jepeway@cs.utk.edu>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * 4. Products derived from this software may not be called "Sudo" nor
 *    may "Sudo" appear in their names without specific prior written
 *    permission from the author.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * XXX - the whole opFOO naming thing is somewhat bogus.
 *
 * XXX - the way things are stored for printmatches is stupid,
 *       they should be stored as elements in an array and then
 *       list_matches() can format things the way it wants.
 */

#include "config.h"
#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <sys/types.h>
#include <sys/param.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
#include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#if defined(YYBISON) && defined(HAVE_ALLOCA_H) && !defined(__GNUC__)
#include <alloca.h>
#endif /* YYBISON && HAVE_ALLOCA_H && !__GNUC__ */
#ifdef HAVE_LSEARCH
#include <search.h>
#endif /* HAVE_LSEARCH */

#include "sudo.h"
#include "parse.h"

#ifndef HAVE_LSEARCH
#include "emul/search.h"
#endif /* HAVE_LSEARCH */

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Globals
 */
extern int sudolineno, parse_error;
int errorlineno = -1;
int clearaliases = TRUE;
int printmatches = FALSE;
int pedantic = FALSE;

/*
 * Alias types
 */
#define HOST_ALIAS		 1
#define CMND_ALIAS		 2
#define USER_ALIAS		 3
#define RUNAS_ALIAS		 4

/*
 * The matching stack, initial space allocated in init_parser().
 */
struct matchstack *match;
int top = 0, stacksize = 0;

#define push \
    do { \
	if (top >= stacksize) { \
	    while ((stacksize += STACKINCREMENT) < top); \
	    match = (struct matchstack *) erealloc(match, sizeof(struct matchstack) * stacksize); \
	} \
	match[top].user   = -1; \
	match[top].cmnd   = -1; \
	match[top].host   = -1; \
	match[top].runas  = -1; \
	match[top].nopass = def_flag(I_AUTHENTICATE) ? -1 : TRUE; \
	top++; \
    } while (0)

#define pushcp \
    do { \
	if (top >= stacksize) { \
	    while ((stacksize += STACKINCREMENT) < top); \
	    match = (struct matchstack *) erealloc(match, sizeof(struct matchstack) * stacksize); \
	} \
	match[top].user   = match[top-1].user; \
	match[top].cmnd   = match[top-1].cmnd; \
	match[top].host   = match[top-1].host; \
	match[top].runas  = match[top-1].runas; \
	match[top].nopass = match[top-1].nopass; \
	top++; \
    } while (0)

#define pop \
    { \
	if (top == 0) \
	    yyerror("matching stack underflow"); \
	else \
	    top--; \
    }

/*
 * Shortcuts for append()
 */
#define append_cmnd(s, p) append(s, &cm_list[cm_list_len].cmnd, \
	&cm_list[cm_list_len].cmnd_len, &cm_list[cm_list_len].cmnd_size, p)

#define append_runas(s, p) append(s, &cm_list[cm_list_len].runas, \
	&cm_list[cm_list_len].runas_len, &cm_list[cm_list_len].runas_size, p)

#define append_entries(s, p) append(s, &ga_list[ga_list_len-1].entries, \
	&ga_list[ga_list_len-1].entries_len, \
	&ga_list[ga_list_len-1].entries_size, p)

/*
 * The stack for printmatches.  A list of allowed commands for the user.
 */
static struct command_match *cm_list = NULL;
static size_t cm_list_len = 0, cm_list_size = 0;

/*
 * List of Cmnd_Aliases and expansions for `sudo -l'
 */
static int in_alias = FALSE;
static size_t ga_list_len = 0, ga_list_size = 0;
static struct generic_alias *ga_list = NULL;

/*
 * Does this Defaults list pertain to this user?
 */
static int defaults_matches = 0;

/*
 * Local protoypes
 */
static int  add_alias		__P((char *, int, int));
static void append		__P((char *, char **, size_t *, size_t *, char *));
static void expand_ga_list	__P((void));
static void expand_match_list	__P((void));
static aliasinfo *find_alias	__P((char *, int));
static int  more_aliases	__P((void));
       void init_parser		__P((void));
       void yyerror		__P((char *));

void
yyerror(s)
    char *s;
{
    /* Save the line the first error occured on. */
    if (errorlineno == -1)
	errorlineno = sudolineno ? sudolineno - 1 : 0;
    if (s) {
#ifndef TRACELEXER
	(void) fprintf(stderr, ">>> sudoers file: %s, line %d <<<\n", s,
	    sudolineno ? sudolineno - 1 : 0);
#else
	(void) fprintf(stderr, "<*> ");
#endif
    }
    parse_error = TRUE;
}
#line 206 "parse.yacc"
typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
} YYSTYPE;
#line 230 "sudo.tab.c"
#define COMMAND 257
#define ALIAS 258
#define NTWKADDR 259
#define FQHOST 260
#define NETGROUP 261
#define USERGROUP 262
#define WORD 263
#define DEFAULTS 264
#define DEFAULTS_HOST 265
#define DEFAULTS_USER 266
#define RUNAS 267
#define NOPASSWD 268
#define PASSWD 269
#define ALL 270
#define COMMENT 271
#define HOSTALIAS 272
#define CMNDALIAS 273
#define USERALIAS 274
#define RUNASALIAS 275
#define ERROR 276
#define YYERRCODE 256
short yylhs[] = {                                        -1,
    0,    0,    7,    7,    9,    7,    7,    7,    7,    7,
    7,   15,   16,   18,   16,   20,   16,   17,   17,   21,
   21,   21,   10,   10,   22,   24,   24,    2,    2,    2,
    2,    2,    2,   23,   23,   25,   28,   29,   28,   26,
   26,    5,    5,    4,   30,    4,    3,    3,    3,    3,
    3,   27,   27,   27,    1,    1,    1,   12,   12,   32,
   31,   19,   19,   13,   13,   34,   33,   35,   35,   14,
   14,   37,   36,   11,   11,   39,   38,    8,    8,   40,
   40,    6,    6,    6,    6,    6,
};
short yylen[] = {                                         2,
    1,    2,    1,    2,    0,    3,    2,    2,    2,    2,
    1,    2,    1,    0,    3,    0,    3,    1,    3,    1,
    2,    3,    1,    3,    3,    1,    2,    1,    1,    1,
    1,    1,    1,    1,    3,    3,    1,    0,    3,    0,
    2,    1,    3,    1,    0,    3,    1,    1,    1,    1,
    1,    0,    1,    1,    1,    1,    1,    1,    3,    0,
    4,    1,    3,    1,    3,    0,    4,    1,    3,    1,
    3,    0,    4,    1,    3,    0,    4,    1,    3,    1,
    2,    1,    1,    1,    1,    1,
};
short yydefred[] = {                                      0,
    0,   13,   16,   14,    3,    0,    0,    0,    0,    0,
    1,    0,   11,    0,    4,    0,    0,   60,    0,   58,
   66,    0,   64,   76,    0,   74,   72,    0,   70,    2,
   85,   84,   83,   82,   86,    0,   80,    0,   78,    0,
    0,   12,    0,   33,   29,   32,   30,   31,   28,    0,
   26,    0,   62,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   81,    0,    0,    0,   23,    0,   21,    0,
   27,    0,    0,   59,    0,   65,    0,   75,    0,   71,
   79,    0,    0,   22,   19,   63,    0,   57,   56,   55,
   38,   37,   68,    0,    0,   50,   49,   48,   47,   51,
   45,   44,   42,    0,   24,    0,    0,   34,    0,    0,
    0,    0,    0,    0,    0,   53,   54,    0,   39,   69,
   46,   43,   35,   36,
};
short yydgoto[] = {                                      10,
   92,   51,  102,  103,  104,   37,   11,   38,   12,   65,
   25,   19,   22,   28,   13,   14,   42,   17,   66,   16,
   43,   67,  107,   53,  108,  109,  118,   93,  110,  112,
   20,   55,   23,   57,   94,   29,   61,   26,   59,   39,
};
short yysindex[] = {                                   -249,
 -267,    0,    0,    0,    0, -244, -240, -238, -230, -249,
    0,  -14,    0,  -28,    0,  -20,  -14,    0,  -49,    0,
    0,  -10,    0,    0,   -5,    0,    0,    5,    0,    0,
    0,    0,    0,    0,    0, -212,    0,  -33,    0,  -30,
 -220,    0,  -11,    0,    0,    0,    0,    0,    0, -223,
    0,   15,    0,   23,    7, -244,    8, -240,    9, -238,
   10, -230,    0,  -14,   14,  -34,    0, -190,    0,  -28,
    0,  -20,  -20,    0,  -25,    0,  -14,    0,  245,    0,
    0,  -20, -192,    0,    0,    0,   15,    0,    0,    0,
    0,    0,    0,   32,   23,    0,    0,    0,    0,    0,
    0,    0,    0,   33,    0,  245,   34,    0, -203, -228,
  -25, -206,  245,   33, -192,    0,    0,  -25,    0,    0,
    0,    0,    0,    0,
};
short yyrindex[] = {                                    255,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  255,
    0,    0,    0,    0,    0,    0,    0,    0,  121,    0,
    0,  141,    0,    0,  161,    0,    0,  181,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    1,
    0,    0,  201,    0,    0,    0,    0,    0,    0,    0,
    0,  -27,    0,  -21,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  221,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  265,    0,    0,    0,   21,    0,    0,    0,
    0,    0,    0,   41,   61,    0,    0,    0,    0,    0,
    0,    0,    0,   81,    0,    0,  101,    0,   11,    0,
    0,    0,    0,  285,  265,    0,    0,    0,    0,    0,
    0,    0,    0,    0,
};
short yygindex[] = {                                      0,
  -26,   30,  -29,  -31,  -19,   49,   76,  -15,    0,    0,
    0,    0,    0,    0,    0,    0,   18,    0,  -13,    0,
    0,   13,    0,   17,  -24,    0,    0,  -79,    0,    0,
   36,    0,   35,    0,    0,   28,    0,   37,    0,   38,
};
#define YYTABLESIZE 555
short yytable[] = {                                      50,
   20,   54,   52,   15,   41,   17,    1,   91,   56,   72,
   64,   15,   50,   18,    2,    3,    4,   21,   36,   24,
   61,    5,    6,    7,    8,    9,   83,   27,   88,   89,
   68,  120,   70,   20,   44,   45,   46,   47,  124,   48,
   67,   90,   69,   52,   20,   31,   49,   58,   32,   33,
   34,   96,   60,   61,   97,   98,   99,   35,   72,   87,
   77,   95,   62,  100,  116,  117,   64,   73,   75,   77,
   79,   82,   84,   67,  106,  111,  113,  115,   61,   71,
   73,  122,  121,  119,   63,   30,  114,   85,   86,   80,
  123,   74,   76,   77,  105,    0,   78,    0,   67,    0,
   25,   81,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   73,    0,    0,    0,    0,   77,    0,
    8,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   25,    0,    0,    0,    0,   73,    0,
    9,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    8,    0,    0,    0,    0,   25,    0,
    7,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    9,    0,    0,    0,    0,    0,    0,
   10,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    7,    0,    0,    0,    0,    0,    0,
   18,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   10,    0,    0,    0,    0,    0,    0,
    6,    0,    0,    0,   44,   45,   46,   47,    0,   48,
    0,   88,   89,   18,   40,   17,   49,   44,   45,   46,
   47,   15,   48,   31,   90,    0,   32,   33,   34,   49,
    0,    0,    0,    6,    0,   35,   20,    0,   20,    0,
    0,   20,   20,   20,   20,   20,   20,   52,   52,    0,
   20,   20,   20,   20,   20,   20,   61,  101,   61,    0,
   52,   61,   61,   61,   61,   61,   61,    5,    0,    0,
   61,   61,   61,   61,   61,   61,   67,   40,   67,    0,
    0,   67,   67,   67,   67,   67,   67,    0,    0,    0,
   67,   67,   67,   67,   67,   67,   77,   41,   77,    0,
    0,   77,   77,   77,   77,   77,   77,    0,    0,    0,
   77,   77,   77,   77,   77,   77,   73,    0,   73,    0,
    0,   73,   73,   73,   73,   73,   73,    0,    0,    0,
   73,   73,   73,   73,   73,   73,   25,    0,   25,    0,
    0,   25,   25,   25,   25,   25,   25,    0,    0,    0,
   25,   25,   25,   25,   25,   25,    8,    0,    8,    0,
    0,    8,    8,    8,    8,    8,    8,    0,    0,    0,
    8,    8,    8,    8,    8,    8,    9,    0,    9,    0,
    0,    9,    9,    9,    9,    9,    9,    0,    0,    0,
    9,    9,    9,    9,    9,    9,    7,    0,    7,    0,
    0,    7,    7,    7,    7,    7,    7,    0,    0,    0,
    7,    7,    7,    7,    7,    7,   10,    0,   10,    0,
    0,   10,   10,   10,   10,   10,   10,    0,    0,    0,
   10,   10,   10,   10,   10,   10,   18,    0,   18,    0,
    0,   18,   18,   18,   18,   18,   18,    0,    0,    0,
   18,   18,   18,   18,   18,   18,    6,    0,    6,    0,
    0,    6,    6,    6,    6,    6,    6,    0,    0,    0,
    6,    6,    6,    6,    6,    6,    0,    0,    0,    0,
    0,    0,   96,    0,    0,   97,   98,   99,    0,    0,
    0,    0,    5,    0,  100,    5,    5,    5,    0,    0,
    0,   40,   40,    0,    5,    0,    0,    0,    0,    0,
    0,    0,   40,   40,   40,    0,    0,    0,    0,    0,
    0,   41,   41,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   41,   41,   41,
};
short yycheck[] = {                                      33,
    0,   17,   16,  271,   33,   33,  256,   33,   58,   44,
   44,   33,   33,  258,  264,  265,  266,  258,   33,  258,
    0,  271,  272,  273,  274,  275,   61,  258,  257,  258,
   61,  111,   44,   33,  258,  259,  260,  261,  118,  263,
    0,  270,  263,   33,   44,  258,  270,   58,  261,  262,
  263,  258,   58,   33,  261,  262,  263,  270,   44,   73,
    0,   77,   58,  270,  268,  269,   44,   61,   61,   61,
   61,   58,  263,   33,  267,   44,   44,   44,   58,   50,
    0,  113,  112,  110,   36,   10,  106,   70,   72,   62,
  115,   56,   58,   33,   82,   -1,   60,   -1,   58,   -1,
    0,   64,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   58,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   58,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   58,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,   -1,   -1,
    0,   -1,   -1,   -1,  258,  259,  260,  261,   -1,  263,
   -1,  257,  258,   33,  263,  263,  270,  258,  259,  260,
  261,  263,  263,  258,  270,   -1,  261,  262,  263,  270,
   -1,   -1,   -1,   33,   -1,  270,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,  257,  258,   -1,
  270,  271,  272,  273,  274,  275,  256,   33,  258,   -1,
  270,  261,  262,  263,  264,  265,  266,   33,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   33,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   33,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,  256,   -1,  258,   -1,
   -1,  261,  262,  263,  264,  265,  266,   -1,   -1,   -1,
  270,  271,  272,  273,  274,  275,   -1,   -1,   -1,   -1,
   -1,   -1,  258,   -1,   -1,  261,  262,  263,   -1,   -1,
   -1,   -1,  258,   -1,  270,  261,  262,  263,   -1,   -1,
   -1,  257,  258,   -1,  270,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  268,  269,  270,   -1,   -1,   -1,   -1,   -1,
   -1,  257,  258,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,  268,  269,  270,
};
#define YYFINAL 10
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 276
#if YYDEBUG
char *yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,0,0,0,0,0,0,"','",0,0,0,0,0,0,0,0,0,0,0,0,0,"':'",0,0,"'='",0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"COMMAND",
"ALIAS","NTWKADDR","FQHOST","NETGROUP","USERGROUP","WORD","DEFAULTS",
"DEFAULTS_HOST","DEFAULTS_USER","RUNAS","NOPASSWD","PASSWD","ALL","COMMENT",
"HOSTALIAS","CMNDALIAS","USERALIAS","RUNASALIAS","ERROR",
};
char *yyrule[] = {
"$accept : file",
"file : entry",
"file : file entry",
"entry : COMMENT",
"entry : error COMMENT",
"$$1 :",
"entry : $$1 userlist privileges",
"entry : USERALIAS useraliases",
"entry : HOSTALIAS hostaliases",
"entry : CMNDALIAS cmndaliases",
"entry : RUNASALIAS runasaliases",
"entry : defaults_line",
"defaults_line : defaults_type defaults_list",
"defaults_type : DEFAULTS",
"$$2 :",
"defaults_type : DEFAULTS_USER $$2 userlist",
"$$3 :",
"defaults_type : DEFAULTS_HOST $$3 hostlist",
"defaults_list : defaults_entry",
"defaults_list : defaults_entry ',' defaults_list",
"defaults_entry : WORD",
"defaults_entry : '!' WORD",
"defaults_entry : WORD '=' WORD",
"privileges : privilege",
"privileges : privileges ':' privilege",
"privilege : hostlist '=' cmndspeclist",
"ophost : host",
"ophost : '!' host",
"host : ALL",
"host : NTWKADDR",
"host : NETGROUP",
"host : WORD",
"host : FQHOST",
"host : ALIAS",
"cmndspeclist : cmndspec",
"cmndspeclist : cmndspeclist ',' cmndspec",
"cmndspec : runasspec nopasswd opcmnd",
"opcmnd : cmnd",
"$$4 :",
"opcmnd : '!' $$4 cmnd",
"runasspec :",
"runasspec : RUNAS runaslist",
"runaslist : oprunasuser",
"runaslist : runaslist ',' oprunasuser",
"oprunasuser : runasuser",
"$$5 :",
"oprunasuser : '!' $$5 runasuser",
"runasuser : WORD",
"runasuser : USERGROUP",
"runasuser : NETGROUP",
"runasuser : ALIAS",
"runasuser : ALL",
"nopasswd :",
"nopasswd : NOPASSWD",
"nopasswd : PASSWD",
"cmnd : ALL",
"cmnd : ALIAS",
"cmnd : COMMAND",
"hostaliases : hostalias",
"hostaliases : hostaliases ':' hostalias",
"$$6 :",
"hostalias : ALIAS $$6 '=' hostlist",
"hostlist : ophost",
"hostlist : hostlist ',' ophost",
"cmndaliases : cmndalias",
"cmndaliases : cmndaliases ':' cmndalias",
"$$7 :",
"cmndalias : ALIAS $$7 '=' cmndlist",
"cmndlist : opcmnd",
"cmndlist : cmndlist ',' opcmnd",
"runasaliases : runasalias",
"runasaliases : runasaliases ':' runasalias",
"$$8 :",
"runasalias : ALIAS $$8 '=' runaslist",
"useraliases : useralias",
"useraliases : useraliases ':' useralias",
"$$9 :",
"useralias : ALIAS $$9 '=' userlist",
"userlist : opuser",
"userlist : userlist ',' opuser",
"opuser : user",
"opuser : '!' user",
"user : WORD",
"user : USERGROUP",
"user : NETGROUP",
"user : ALIAS",
"user : ALL",
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
#line 818 "parse.yacc"

#define MOREALIASES (32)
aliasinfo *aliases = NULL;
size_t naliases = 0;
size_t nslots = 0;


/*
 * Compare two aliasinfo structures, strcmp() style.
 * Note that we do *not* compare their values.
 */
static int
aliascmp(a1, a2)
    const VOID *a1, *a2;
{
    int r;
    aliasinfo *ai1, *ai2;

    ai1 = (aliasinfo *) a1;
    ai2 = (aliasinfo *) a2;
    if ((r = strcmp(ai1->name, ai2->name)) == 0)
	r = ai1->type - ai2->type;

    return(r);
}

/*
 * Compare two generic_alias structures, strcmp() style.
 */
static int
genaliascmp(entry, key)
    const VOID *entry, *key;
{
    int r;
    struct generic_alias *ga1, *ga2;

    ga1 = (struct generic_alias *) key;
    ga2 = (struct generic_alias *) entry;
    if ((r = strcmp(ga1->alias, ga2->alias)) == 0)
	r = ga1->type - ga2->type;

    return(r);
}


/*
 * Adds the named alias of the specified type to the aliases list.
 */
static int
add_alias(alias, type, val)
    char *alias;
    int type;
    int val;
{
    aliasinfo ai, *aip;
    size_t onaliases;
    char s[512];

    if (naliases >= nslots && !more_aliases()) {
	(void) snprintf(s, sizeof(s), "Out of memory defining alias `%s'",
			alias);
	yyerror(s);
	return(FALSE);
    }

    ai.type = type;
    ai.val = val;
    ai.name = estrdup(alias);
    onaliases = naliases;

    aip = (aliasinfo *) lsearch((VOID *)&ai, (VOID *)aliases, &naliases,
				sizeof(ai), aliascmp);
    if (aip == NULL) {
	(void) snprintf(s, sizeof(s), "Aliases corrupted defining alias `%s'",
			alias);
	yyerror(s);
	return(FALSE);
    }
    if (onaliases == naliases) {
	(void) snprintf(s, sizeof(s), "Alias `%s' already defined", alias);
	yyerror(s);
	return(FALSE);
    }

    return(TRUE);
}

/*
 * Searches for the named alias of the specified type.
 */
static aliasinfo *
find_alias(alias, type)
    char *alias;
    int type;
{
    aliasinfo ai;

    ai.name = alias;
    ai.type = type;

    return((aliasinfo *) lfind((VOID *)&ai, (VOID *)aliases, &naliases,
		 sizeof(ai), aliascmp));
}

/*
 * Allocates more space for the aliases list.
 */
static int
more_aliases()
{

    nslots += MOREALIASES;
    if (nslots == MOREALIASES)
	aliases = (aliasinfo *) malloc(nslots * sizeof(aliasinfo));
    else
	aliases = (aliasinfo *) realloc(aliases, nslots * sizeof(aliasinfo));

    return(aliases != NULL);
}

/*
 * Lists the contents of the aliases list.
 */
void
dumpaliases()
{
    size_t n;

    for (n = 0; n < naliases; n++) {
	if (aliases[n].val == -1)
	    continue;

	switch (aliases[n].type) {
	case HOST_ALIAS:
	    (void) puts("HOST_ALIAS");
	    break;

	case CMND_ALIAS:
	    (void) puts("CMND_ALIAS");
	    break;

	case USER_ALIAS:
	    (void) puts("USER_ALIAS");
	    break;

	case RUNAS_ALIAS:
	    (void) puts("RUNAS_ALIAS");
	    break;
	}
	(void) printf("\t%s: %d\n", aliases[n].name, aliases[n].val);
    }
}

/*
 * Lists the contents of cm_list and ga_list for `sudo -l'.
 */
void
list_matches()
{
    int i; 
    char *p;
    struct generic_alias *ga, key;

    (void) printf("User %s may run the following commands on this host:\n",
	user_name);
    for (i = 0; i < cm_list_len; i++) {

	/* Print the runas list. */
	(void) fputs("    ", stdout);
	if (cm_list[i].runas) {
	    (void) putchar('(');
	    p = strtok(cm_list[i].runas, ", ");
	    do {
		if (p != cm_list[i].runas)
		    (void) fputs(", ", stdout);

		key.alias = p;
		key.type = RUNAS_ALIAS;
		if ((ga = (struct generic_alias *) lfind((VOID *) &key,
		    (VOID *) &ga_list[0], &ga_list_len, sizeof(key), genaliascmp)))
		    (void) fputs(ga->entries, stdout);
		else
		    (void) fputs(p, stdout);
	    } while ((p = strtok(NULL, ", ")));
	    (void) fputs(") ", stdout);
	} else {
	    (void) printf("(%s) ", def_str(I_RUNAS_DEF));
	}

	/* Is a password required? */
	if (cm_list[i].nopasswd == TRUE && def_flag(I_AUTHENTICATE))
	    (void) fputs("NOPASSWD: ", stdout);
	else if (cm_list[i].nopasswd == FALSE && !def_flag(I_AUTHENTICATE))
	    (void) fputs("PASSWD: ", stdout);

	/* Print the actual command or expanded Cmnd_Alias. */
	key.alias = cm_list[i].cmnd;
	key.type = CMND_ALIAS;
	if ((ga = (struct generic_alias *) lfind((VOID *) &key,
	    (VOID *) &ga_list[0], &ga_list_len, sizeof(key), genaliascmp)))
	    (void) puts(ga->entries);
	else
	    (void) puts(cm_list[i].cmnd);
    }

    /* Be nice and free up space now that we are done. */
    for (i = 0; i < ga_list_len; i++) {
	free(ga_list[i].alias);
	free(ga_list[i].entries);
    }
    free(ga_list);
    ga_list = NULL;

    for (i = 0; i < cm_list_len; i++) {
	free(cm_list[i].runas);
	free(cm_list[i].cmnd);
    }
    free(cm_list);
    cm_list = NULL;
    cm_list_len = 0;
    cm_list_size = 0;
}

/*
 * Appends a source string to the destination, optionally prefixing a separator.
 */
static void
append(src, dstp, dst_len, dst_size, separator)
    char *src, **dstp;
    size_t *dst_len, *dst_size;
    char *separator;
{
    size_t src_len = strlen(src);
    char *dst = *dstp;

    /*
     * Only add the separator if there is something to separate from.
     * If the last char is a '!', don't apply the separator (XXX).
     */
    if (separator && dst && dst[*dst_len - 1] != '!')
	src_len += strlen(separator);
    else
	separator = NULL;

    /* Assumes dst will be NULL if not set. */
    if (dst == NULL) {
	dst = (char *) emalloc(BUFSIZ);
	*dst_size = BUFSIZ;
	*dst_len = 0;
	*dstp = dst;
    }

    /* Allocate more space if necessary. */
    if (*dst_size <= *dst_len + src_len) {
	while (*dst_size <= *dst_len + src_len)
	    *dst_size += BUFSIZ;

	dst = (char *) erealloc(dst, *dst_size);
	*dstp = dst;
    }

    /* Copy src -> dst adding a separator if appropriate and adjust len. */
    dst += *dst_len;
    *dst_len += src_len;
    *dst = '\0';
    if (separator)
	(void) strcat(dst, separator);
    (void) strcat(dst, src);
}

/*
 * Frees up space used by the aliases list and resets the associated counters.
 */
void
reset_aliases()
{
    size_t n;

    if (aliases) {
	for (n = 0; n < naliases; n++)
	    free(aliases[n].name);
	free(aliases);
	aliases = NULL;
    }
    naliases = nslots = 0;
}

/*
 * Increments ga_list_len, allocating more space as necessary.
 */
static void
expand_ga_list()
{

    if (++ga_list_len >= ga_list_size) {
	while ((ga_list_size += STACKINCREMENT) < ga_list_len)
	    ;
	ga_list = (struct generic_alias *)
	    erealloc(ga_list, sizeof(struct generic_alias) * ga_list_size);
    }

    ga_list[ga_list_len - 1].entries = NULL;
}

/*
 * Increments cm_list_len, allocating more space as necessary.
 */
static void
expand_match_list()
{

    if (++cm_list_len >= cm_list_size) {
	while ((cm_list_size += STACKINCREMENT) < cm_list_len)
	    ;
	if (cm_list == NULL)
	    cm_list_len = 0;		/* start at 0 since it is a subscript */
	cm_list = (struct command_match *)
	    erealloc(cm_list, sizeof(struct command_match) * cm_list_size);
    }

    cm_list[cm_list_len].runas = cm_list[cm_list_len].cmnd = NULL;
    cm_list[cm_list_len].nopasswd = FALSE;
}

/*
 * Frees up spaced used by a previous parser run and allocates new space
 * for various data structures.
 */
void
init_parser()
{

    /* Free up old data structures if we run the parser more than once. */
    if (match) {
	free(match);
	match = NULL;
	top = 0;
	parse_error = FALSE;
	errorlineno = -1;   
	sudolineno = 1;     
    }

    /* Allocate space for the matching stack. */
    stacksize = STACKINCREMENT;
    match = (struct matchstack *) emalloc(sizeof(struct matchstack) * stacksize);

    /* Allocate space for the match list (for `sudo -l'). */
    if (printmatches == TRUE)
	expand_match_list();
}
#line 931 "sudo.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
#if defined(__cplusplus) || __STDC__
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
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss);
    if (newss == NULL)
        return -1;
    yyss = newss;
    yyssp = newss + i;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs);
    if (newvs == NULL)
        return -1;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
#if defined(__cplusplus) || __STDC__
yyparse(void)
#else
yyparse()
#endif
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

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
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 3:
#line 256 "parse.yacc"
{ ; }
break;
case 4:
#line 258 "parse.yacc"
{ yyerrok; }
break;
case 5:
#line 259 "parse.yacc"
{ push; }
break;
case 6:
#line 259 "parse.yacc"
{
			    while (top && user_matches != TRUE)
				pop;
			}
break;
case 7:
#line 264 "parse.yacc"
{ ; }
break;
case 8:
#line 266 "parse.yacc"
{ ; }
break;
case 9:
#line 268 "parse.yacc"
{ ; }
break;
case 10:
#line 270 "parse.yacc"
{ ; }
break;
case 11:
#line 272 "parse.yacc"
{ ; }
break;
case 13:
#line 277 "parse.yacc"
{
			    defaults_matches = TRUE;
			}
break;
case 14:
#line 280 "parse.yacc"
{ push; }
break;
case 15:
#line 280 "parse.yacc"
{
			    defaults_matches = user_matches;
			    pop;
			}
break;
case 16:
#line 284 "parse.yacc"
{ push; }
break;
case 17:
#line 284 "parse.yacc"
{
			    defaults_matches = host_matches;
			    pop;
			}
break;
case 20:
#line 293 "parse.yacc"
{
			    if (defaults_matches && !set_default(yyvsp[0].string, NULL, 1)) {
				yyerror(NULL);
				YYERROR;
			    }
			    free(yyvsp[0].string);
			}
break;
case 21:
#line 300 "parse.yacc"
{
			    if (defaults_matches && !set_default(yyvsp[0].string, NULL, 0)) {
				yyerror(NULL);
				YYERROR;
			    }
			    free(yyvsp[0].string);
			}
break;
case 22:
#line 307 "parse.yacc"
{
			    /* XXX - need to support quoted values */
			    if (defaults_matches && !set_default(yyvsp[-2].string, yyvsp[0].string, 1)) {
				yyerror(NULL);
				YYERROR;
			    }
			    free(yyvsp[-2].string);
			    free(yyvsp[0].string);
			}
break;
case 25:
#line 321 "parse.yacc"
{
			    /*
			     * We already did a push if necessary in
			     * cmndspec so just reset some values so
			     * the next 'privilege' gets a clean slate.
			     */
			    host_matches = -1;
			    runas_matches = -1;
			    if (def_flag(I_AUTHENTICATE))
				no_passwd = -1;
			    else
				no_passwd = TRUE;
			}
break;
case 26:
#line 336 "parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				host_matches = yyvsp[0].BOOLEAN;
			}
break;
case 27:
#line 340 "parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				host_matches = ! yyvsp[0].BOOLEAN;
			}
break;
case 28:
#line 345 "parse.yacc"
{
			    yyval.BOOLEAN = TRUE;
			}
break;
case 29:
#line 348 "parse.yacc"
{
			    if (addr_matches(yyvsp[0].string))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 30:
#line 355 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, user_host, NULL))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 31:
#line 362 "parse.yacc"
{
			    if (strcasecmp(user_shost, yyvsp[0].string) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 32:
#line 369 "parse.yacc"
{
			    if (strcasecmp(user_host, yyvsp[0].string) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 33:
#line 376 "parse.yacc"
{
			    aliasinfo *aip = find_alias(yyvsp[0].string, HOST_ALIAS);

			    /* could be an all-caps hostname */
			    if (aip)
				yyval.BOOLEAN = aip->val;
			    else if (strcasecmp(user_shost, yyvsp[0].string) == 0)
				yyval.BOOLEAN = TRUE;
			    else {
				if (pedantic) {
				    (void) fprintf(stderr,
					"%s: undeclared Host_Alias `%s' referenced near line %d\n",
					(pedantic == 1) ? "Warning" : "Error", yyvsp[0].string, sudolineno);
				    if (pedantic > 1) {
					yyerror(NULL);
					YYERROR;
				    }
				}
				yyval.BOOLEAN = -1;
			    }
			    free(yyvsp[0].string);
			}
break;
case 36:
#line 404 "parse.yacc"
{
			    /*
			     * Push the entry onto the stack if it is worth
			     * saving and clear cmnd_matches for next cmnd.
			     *
			     * We need to save at least one entry on
			     * the stack so sudoers_lookup() can tell that
			     * the user was listed in sudoers.  Also, we
			     * need to be able to tell whether or not a
			     * user was listed for this specific host.
			     */
			    if (user_matches != -1 && host_matches != -1 &&
				cmnd_matches != -1 && runas_matches != -1)
				pushcp;
			    else if (user_matches != -1 && (top == 1 ||
				(top == 2 && host_matches != -1 &&
				match[0].host == -1)))
				pushcp;
			    cmnd_matches = -1;
			}
break;
case 37:
#line 426 "parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				cmnd_matches = yyvsp[0].BOOLEAN;
			}
break;
case 38:
#line 430 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("!", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_cmnd("!", NULL);
			    }
			}
break;
case 39:
#line 438 "parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				cmnd_matches = ! yyvsp[0].BOOLEAN;
			}
break;
case 40:
#line 444 "parse.yacc"
{
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				if (runas_matches == -1) {
				    cm_list[cm_list_len].runas_len = 0;
				} else {
				    /* Inherit runas data. */
				    cm_list[cm_list_len].runas =
					estrdup(cm_list[cm_list_len-1].runas);
				    cm_list[cm_list_len].runas_len =
					cm_list[cm_list_len-1].runas_len;
				    cm_list[cm_list_len].runas_size =
					cm_list[cm_list_len-1].runas_size;
				}
			    }
			    /*
			     * If this is the first entry in a command list
			     * then check against default runas user.
			     */
			    if (runas_matches == -1)
				runas_matches = (strcmp(*user_runas,
				    def_str(I_RUNAS_DEF)) == 0);
			}
break;
case 41:
#line 467 "parse.yacc"
{
			    runas_matches = (yyvsp[0].BOOLEAN == TRUE ? TRUE : FALSE);
			}
break;
case 42:
#line 472 "parse.yacc"
{ ; }
break;
case 43:
#line 473 "parse.yacc"
{
			    /* Later entries override earlier ones. */
			    if (yyvsp[0].BOOLEAN != -1)
				yyval.BOOLEAN = yyvsp[0].BOOLEAN;
			    else
				yyval.BOOLEAN = yyvsp[-2].BOOLEAN;
			}
break;
case 44:
#line 482 "parse.yacc"
{ ; }
break;
case 45:
#line 483 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("!", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas("!", ", ");
			    }
			}
break;
case 46:
#line 491 "parse.yacc"
{
			    /* Set $$ to the negation of runasuser */
			    yyval.BOOLEAN = (yyvsp[0].BOOLEAN == -1 ? -1 : ! yyvsp[0].BOOLEAN);
			}
break;
case 47:
#line 496 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    if (strcmp(yyvsp[0].string, *user_runas) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 48:
#line 510 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    if (usergr_matches(yyvsp[0].string, *user_runas))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 49:
#line 524 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    if (netgr_matches(yyvsp[0].string, NULL, *user_runas))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 50:
#line 538 "parse.yacc"
{
			    aliasinfo *aip = find_alias(yyvsp[0].string, RUNAS_ALIAS);

			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    /* could be an all-caps username */
			    if (aip)
				yyval.BOOLEAN = aip->val;
			    else if (strcmp(yyvsp[0].string, *user_runas) == 0)
				yyval.BOOLEAN = TRUE;
			    else {
				if (pedantic) {
				    (void) fprintf(stderr,
					"%s: undeclared Runas_Alias `%s' referenced near line %d\n",
					(pedantic == 1) ? "Warning" : "Error", yyvsp[0].string, sudolineno);
				    if (pedantic > 1) {
					yyerror(NULL);
					YYERROR;
				    }
				}
				yyval.BOOLEAN = -1;
			    }
			    free(yyvsp[0].string);
			}
break;
case 51:
#line 567 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("ALL", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas("ALL", ", ");
			    }
			    yyval.BOOLEAN = TRUE;
			}
break;
case 52:
#line 579 "parse.yacc"
{
			    /* Inherit NOPASSWD/PASSWD status. */
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				if (no_passwd == TRUE)
				    cm_list[cm_list_len].nopasswd = TRUE;
				else
				    cm_list[cm_list_len].nopasswd = FALSE;
			    }
			}
break;
case 53:
#line 589 "parse.yacc"
{
			    no_passwd = TRUE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = TRUE;
			}
break;
case 54:
#line 595 "parse.yacc"
{
			    no_passwd = FALSE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = FALSE;
			}
break;
case 55:
#line 603 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("ALL", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE) {
				    append_cmnd("ALL", NULL);
				    expand_match_list();
				}
			    }

			    yyval.BOOLEAN = TRUE;

			    if (safe_cmnd)
				free(safe_cmnd);
			    safe_cmnd = estrdup(user_cmnd);
			}
break;
case 56:
#line 620 "parse.yacc"
{
			    aliasinfo *aip;

			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE) {
				    append_cmnd(yyvsp[0].string, NULL);
				    expand_match_list();
				}
			    }

			    if ((aip = find_alias(yyvsp[0].string, CMND_ALIAS)))
				yyval.BOOLEAN = aip->val;
			    else {
				if (pedantic) {
				    (void) fprintf(stderr,
					"%s: undeclared Cmnd_Alias `%s' referenced near line %d\n",
					(pedantic == 1) ? "Warning" : "Error", yyvsp[0].string, sudolineno);
				    if (pedantic > 1) {
					yyerror(NULL);
					YYERROR;
				    }
				}
				yyval.BOOLEAN = -1;
			    }
			    free(yyvsp[0].string);
			}
break;
case 57:
#line 649 "parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE) {
				    append_entries(yyvsp[0].command.cmnd, ", ");
				    if (yyvsp[0].command.args)
					append_entries(yyvsp[0].command.args, " ");
				}
				if (host_matches == TRUE &&
				    user_matches == TRUE)  {
				    append_cmnd(yyvsp[0].command.cmnd, NULL);
				    if (yyvsp[0].command.args)
					append_cmnd(yyvsp[0].command.args, " ");
				    expand_match_list();
				}
			    }

			    if (command_matches(user_cmnd, user_args,
				yyvsp[0].command.cmnd, yyvsp[0].command.args))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;

			    free(yyvsp[0].command.cmnd);
			    if (yyvsp[0].command.args)
				free(yyvsp[0].command.args);
			}
break;
case 60:
#line 681 "parse.yacc"
{ push; }
break;
case 61:
#line 681 "parse.yacc"
{
			    if ((host_matches != -1 || pedantic) &&
				!add_alias(yyvsp[-3].string, HOST_ALIAS, host_matches))
				YYERROR;
			    pop;
			}
break;
case 66:
#line 697 "parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necessary. */
				expand_ga_list();
				ga_list[ga_list_len-1].type = CMND_ALIAS;
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			     }
			}
break;
case 67:
#line 706 "parse.yacc"
{
			    if ((cmnd_matches != -1 || pedantic) &&
				!add_alias(yyvsp[-3].string, CMND_ALIAS, cmnd_matches))
				YYERROR;
			    pop;
			    free(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			}
break;
case 68:
#line 718 "parse.yacc"
{ ; }
break;
case 72:
#line 726 "parse.yacc"
{
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necessary. */
				expand_ga_list();
				ga_list[ga_list_len-1].type = RUNAS_ALIAS;
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			    }
			}
break;
case 73:
#line 734 "parse.yacc"
{
			    if ((yyvsp[0].BOOLEAN != -1 || pedantic) &&
				!add_alias(yyvsp[-3].string, RUNAS_ALIAS, yyvsp[0].BOOLEAN))
				YYERROR;
			    free(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			}
break;
case 76:
#line 749 "parse.yacc"
{ push; }
break;
case 77:
#line 749 "parse.yacc"
{
			    if ((user_matches != -1 || pedantic) &&
				!add_alias(yyvsp[-3].string, USER_ALIAS, user_matches))
				YYERROR;
			    pop;
			    free(yyvsp[-3].string);
			}
break;
case 80:
#line 762 "parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				user_matches = yyvsp[0].BOOLEAN;
			}
break;
case 81:
#line 766 "parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				user_matches = ! yyvsp[0].BOOLEAN;
			}
break;
case 82:
#line 771 "parse.yacc"
{
			    if (strcmp(yyvsp[0].string, user_name) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 83:
#line 778 "parse.yacc"
{
			    if (usergr_matches(yyvsp[0].string, user_name))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 84:
#line 785 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, NULL, user_name))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			}
break;
case 85:
#line 792 "parse.yacc"
{
			    aliasinfo *aip = find_alias(yyvsp[0].string, USER_ALIAS);

			    /* could be an all-caps username */
			    if (aip)
				yyval.BOOLEAN = aip->val;
			    else if (strcmp(yyvsp[0].string, user_name) == 0)
				yyval.BOOLEAN = TRUE;
			    else {
				if (pedantic) {
				    (void) fprintf(stderr,
					"%s: undeclared User_Alias `%s' referenced near line %d\n",
					(pedantic == 1) ? "Warning" : "Error", yyvsp[0].string, sudolineno);
				    if (pedantic > 1)
					YYERROR;
				}
				yyval.BOOLEAN = -1;
			    }
			    free(yyvsp[0].string);
			}
break;
case 86:
#line 812 "parse.yacc"
{
			    yyval.BOOLEAN = TRUE;
			}
break;
#line 1791 "sudo.tab.c"
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
    return (1);
yyaccept:
    return (0);
}
