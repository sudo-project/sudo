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
 *  CU sudo version 1.6
 *  Copyright (c) 1996, 1998, 1999 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  Please send bugs, changes, problems to sudo-bugs@courtesan.com
 *
 *******************************************************************
 *
 * parse.yacc -- yacc parser and alias manipulation routines for sudo.
 *
 * Chris Jepeway <jepeway@cs.utk.edu>
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
#include <netinet/in.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
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

#ifndef HAVE_LSEARCH
#include "emul/search.h"
#endif /* HAVE_LSEARCH */

#ifndef HAVE_STRCASECMP
#define strcasecmp(a,b)		strcmp(a,b)
#endif /* !HAVE_STRCASECMP */

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Globals
 */
extern int sudolineno, parse_error;
int errorlineno = -1;
int clearaliases = 1;
int printmatches = FALSE;

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
    { \
	if (top >= stacksize) { \
	    while ((stacksize += STACKINCREMENT) < top); \
	    match = (struct matchstack *) erealloc(match, sizeof(struct matchstack) * stacksize); \
	} \
	match[top].user   = -1; \
	match[top].cmnd   = -1; \
	match[top].host   = -1; \
	match[top].runas  = -1; \
	match[top].nopass = -1; \
	top++; \
    }

#define pushcp \
    { \
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
    }

#define pop \
    { \
	if (top == 0) \
	    yyerror("matching stack underflow"); \
	else \
	    top--; \
    }

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
 * Protoypes
 */
extern int  command_matches	__P((char *, char *, char *, char *));
extern int  addr_matches	__P((char *));
extern int  netgr_matches	__P((char *, char *, char *));
extern int  usergr_matches	__P((char *, char *));
static int  find_alias		__P((char *, int));
static int  add_alias		__P((char *, int));
static int  more_aliases	__P((void));
static void append		__P((char *, char **, size_t *, size_t *, int));
static void expand_ga_list	__P((void));
static void expand_match_list	__P((void));
       void init_parser		__P((void));
       void yyerror		__P((char *));

void yyerror(s)
    char *s;
{
    /* save the line the first error occured on */
    if (errorlineno == -1)
	errorlineno = sudolineno ? sudolineno - 1 : 0;
#ifndef TRACELEXER
    (void) fprintf(stderr, ">>> sudoers file: %s, line %d <<<\n", s,
	sudolineno ? sudolineno - 1 : 0);
#else
    (void) fprintf(stderr, "<*> ");
#endif
    parse_error = TRUE;
}
#line 172 "parse.yacc"
typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
} YYSTYPE;
#line 196 "sudo.tab.c"
#define ALIAS 257
#define NTWKADDR 258
#define FQHOST 259
#define NETGROUP 260
#define USERGROUP 261
#define NAME 262
#define RUNAS 263
#define NOPASSWD 264
#define PASSWD 265
#define COMMAND 266
#define COMMENT 267
#define ALL 268
#define HOSTALIAS 269
#define CMNDALIAS 270
#define USERALIAS 271
#define RUNASALIAS 272
#define ERROR 273
#define YYERRCODE 256
short yylhs[] = {                                        -1,
    0,    0,    3,    3,    5,    3,    3,    3,    3,    3,
    6,    6,   11,   14,   15,   14,   12,   12,   12,   12,
   12,   12,   13,   13,   18,   16,    2,   20,    2,   17,
   17,   21,   21,   22,   24,   22,   23,   23,   23,   23,
   23,   19,   19,   19,    1,    1,    1,    8,    8,   26,
   25,   27,   27,    9,    9,   29,   28,   30,   30,   10,
   10,   32,   31,    7,    7,   34,   33,   35,   35,   36,
   37,   36,    4,    4,    4,    4,    4,
};
short yylen[] = {                                         2,
    1,    2,    1,    2,    0,    3,    2,    2,    2,    2,
    1,    3,    3,    1,    0,    3,    1,    1,    1,    1,
    1,    1,    1,    3,    0,    4,    1,    0,    3,    0,
    2,    1,    3,    1,    0,    3,    1,    1,    1,    1,
    1,    0,    1,    1,    1,    1,    1,    1,    3,    0,
    4,    1,    3,    1,    3,    0,    4,    1,    3,    1,
    3,    0,    4,    1,    3,    0,    4,    1,    3,    1,
    0,    3,    1,    1,    1,    1,    1,
};
short yydefred[] = {                                      0,
    0,    3,    0,    0,    0,    0,    0,    1,    0,    4,
   50,    0,   48,   56,    0,   54,   66,    0,   64,   62,
    0,   60,    2,   76,   75,   74,   73,   77,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   22,   18,   21,
   19,   20,   17,    0,   11,    0,    0,   49,    0,   55,
    0,   65,    0,   61,    0,   25,   15,   14,   52,    0,
   46,   47,   45,   28,   27,   58,    0,   71,   70,    0,
   68,   40,   39,   38,   37,   41,   35,    0,   32,   34,
   12,    0,   23,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   25,    0,    0,   16,   53,   29,   59,   72,
   69,   36,   33,   24,    0,   43,   44,    0,   26,
};
short yydgoto[] = {                                       7,
   65,   66,    8,   69,    9,   44,   18,   12,   15,   21,
   45,   58,   82,   59,   85,   83,   95,   84,  108,   87,
   78,   79,   80,   91,   13,   30,   60,   16,   32,   67,
   22,   36,   19,   34,   70,   71,   89,
};
short yysindex[] = {                                   -248,
 -264,    0, -250, -246, -237, -232, -248,    0, -217,    0,
    0,  -31,    0,    0,  -25,    0,    0,  -24,    0,    0,
  -16,    0,    0,    0,    0,    0,    0,    0, -221,  -15,
 -250,  -13, -246,  -12, -237,   -5, -232,    0,    0,    0,
    0,    0,    0,    2,    0,   -4,  -33,    0,   -2,    0,
  -29,    0,  -20,    0, -221,    0,    0,    0,    0,   14,
    0,    0,    0,    0,    0,    0,   19,    0,    0,   20,
    0,    0,    0,    0,    0,    0,    0,   21,    0,    0,
    0,   22,    0, -201,  -33,  -33,   -2,   -2,  -29,  -29,
  -20,  -20,    0,  -20, -255,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   21,    0,    0,   -2,    0,
};
short yyrindex[] = {                                   -207,
    0,    0,    0,    0,    0,    0, -207,    0,    0,    0,
    0,   86,    0,    0,  103,    0,    0,  120,    0,    0,
  137,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  154,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    1,
    0,    0,    0,    0,    0,    0,   18,    0,    0,   35,
    0,    0,    0,    0,    0,    0,    0,   52,    0,    0,
    0,   69,    0,  -21,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,   -1,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  163,    0,    0,    0,    0,
};
short yygindex[] = {                                      0,
    0,  -82,   60,   59,    0,    0,    0,    0,    0,    0,
   15,  -27,    0,  -71,    0,  -22,    0,    0,    0,    0,
  -19,  -75,    0,    0,   41,    0,    0,   40,    0,    0,
   37,    0,   42,    0,    0,  -60,    0,
};
#define YYTABLESIZE 431
short yytable[] = {                                      57,
   51,   46,   10,   68,   98,   99,   11,    1,  106,  107,
   14,   30,   77,   96,   97,  102,  103,   57,    2,   17,
    3,    4,    5,    6,   20,  109,   31,   46,  100,  101,
   64,   42,   33,   35,   67,   38,   39,   40,   41,   24,
   42,   37,   25,   26,   27,   47,   43,   49,   51,    5,
   28,   63,    5,    5,    5,   53,   56,   86,   51,   55,
    5,   94,   88,   90,   92,   93,   23,   29,   13,   81,
  104,   48,   50,   54,  105,   57,   52,    0,    0,    0,
    0,    0,    0,    0,    0,    8,    0,    0,    0,    0,
    0,    0,   67,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    9,    0,    0,    0,    0,    0,    0,   63,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    7,
    0,    0,    0,    0,    0,    0,   13,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   10,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    6,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   31,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   38,   39,   40,   41,   24,   42,    0,
   25,   26,   27,    0,   43,   30,   72,    0,   28,   73,
   74,   75,   30,   30,   30,    0,   30,   76,    0,    0,
    0,    0,    0,    0,   61,   42,   51,   51,    0,    0,
   51,   51,   51,   62,   42,   63,   42,   51,   51,   51,
   51,   51,   51,   57,   57,    0,    0,   57,   57,   57,
    0,    0,    0,    0,   57,   57,   57,   57,   57,   57,
   67,   67,    0,    0,   67,   67,   67,    0,    0,    0,
    0,   67,   67,   67,   67,   67,   67,   63,   63,    0,
    0,   63,   63,   63,    0,    0,    0,    0,   63,   63,
   63,   63,   63,   63,   13,   13,    0,    0,   13,   13,
   13,    0,    0,    0,    0,   13,   13,   13,   13,   13,
   13,    8,    8,    0,    0,    8,    8,    8,    0,    0,
    0,    0,    8,    8,    8,    8,    8,    8,    9,    9,
    0,    0,    9,    9,    9,    0,    0,    0,    0,    9,
    9,    9,    9,    9,    9,    7,    7,    0,    0,    7,
    7,    7,    0,    0,    0,    0,    7,    7,    7,    7,
    7,    7,   10,   10,    0,    0,   10,   10,   10,    0,
    0,    0,    0,   10,   10,   10,   10,   10,   10,    6,
    6,    0,    0,    6,    6,    6,    0,    0,    0,   31,
    6,    6,    6,    6,    6,    6,   31,   31,   31,    0,
   31,
};
short yycheck[] = {                                      33,
    0,   29,  267,   33,   87,   88,  257,  256,  264,  265,
  257,   33,   33,   85,   86,   91,   92,    0,  267,  257,
  269,  270,  271,  272,  257,  108,   58,   55,   89,   90,
   33,   33,   58,   58,    0,  257,  258,  259,  260,  257,
  262,   58,  260,  261,  262,   61,  268,   61,   61,  257,
  268,    0,  260,  261,  262,   61,   61,   44,   58,   58,
  268,  263,   44,   44,   44,   44,    7,    9,    0,   55,
   93,   31,   33,   37,   94,   58,   35,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,
   -1,   -1,   58,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,    0,   -1,   -1,   -1,   -1,   -1,   -1,   58,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,    0,
   -1,   -1,   -1,   -1,   -1,   -1,   58,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   33,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  257,  258,  259,  260,  257,  262,   -1,
  260,  261,  262,   -1,  268,  257,  257,   -1,  268,  260,
  261,  262,  264,  265,  266,   -1,  268,  268,   -1,   -1,
   -1,   -1,   -1,   -1,  257,  257,  256,  257,   -1,   -1,
  260,  261,  262,  266,  266,  268,  268,  267,  268,  269,
  270,  271,  272,  256,  257,   -1,   -1,  260,  261,  262,
   -1,   -1,   -1,   -1,  267,  268,  269,  270,  271,  272,
  256,  257,   -1,   -1,  260,  261,  262,   -1,   -1,   -1,
   -1,  267,  268,  269,  270,  271,  272,  256,  257,   -1,
   -1,  260,  261,  262,   -1,   -1,   -1,   -1,  267,  268,
  269,  270,  271,  272,  256,  257,   -1,   -1,  260,  261,
  262,   -1,   -1,   -1,   -1,  267,  268,  269,  270,  271,
  272,  256,  257,   -1,   -1,  260,  261,  262,   -1,   -1,
   -1,   -1,  267,  268,  269,  270,  271,  272,  256,  257,
   -1,   -1,  260,  261,  262,   -1,   -1,   -1,   -1,  267,
  268,  269,  270,  271,  272,  256,  257,   -1,   -1,  260,
  261,  262,   -1,   -1,   -1,   -1,  267,  268,  269,  270,
  271,  272,  256,  257,   -1,   -1,  260,  261,  262,   -1,
   -1,   -1,   -1,  267,  268,  269,  270,  271,  272,  256,
  257,   -1,   -1,  260,  261,  262,   -1,   -1,   -1,  257,
  267,  268,  269,  270,  271,  272,  264,  265,  266,   -1,
  268,
};
#define YYFINAL 7
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 273
#if YYDEBUG
char *yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,0,0,0,0,0,0,"','",0,"'.'",0,0,0,0,0,0,0,0,0,0,0,"':'",0,0,"'='",0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"ALIAS",
"NTWKADDR","FQHOST","NETGROUP","USERGROUP","NAME","RUNAS","NOPASSWD","PASSWD",
"COMMAND","COMMENT","ALL","HOSTALIAS","CMNDALIAS","USERALIAS","RUNASALIAS",
"ERROR",
};
char *yyrule[] = {
"$accept : file",
"file : entry",
"file : file entry",
"entry : COMMENT",
"entry : error COMMENT",
"$$1 :",
"entry : $$1 user privileges",
"entry : USERALIAS useraliases",
"entry : HOSTALIAS hostaliases",
"entry : CMNDALIAS cmndaliases",
"entry : RUNASALIAS runasaliases",
"privileges : privilege",
"privileges : privileges ':' privilege",
"privilege : hostspec '=' cmndspeclist",
"ophostspec : hostspec",
"$$2 :",
"ophostspec : '!' $$2 ophostspec",
"hostspec : ALL",
"hostspec : NTWKADDR",
"hostspec : NETGROUP",
"hostspec : NAME",
"hostspec : FQHOST",
"hostspec : ALIAS",
"cmndspeclist : cmndspec",
"cmndspeclist : cmndspeclist ',' cmndspec",
"$$3 :",
"cmndspec : $$3 runasspec nopasswd opcmnd",
"opcmnd : cmnd",
"$$4 :",
"opcmnd : '!' $$4 opcmnd",
"runasspec :",
"runasspec : RUNAS runaslist",
"runaslist : oprunasuser",
"runaslist : runaslist ',' oprunasuser",
"oprunasuser : runasuser",
"$$5 :",
"oprunasuser : '!' $$5 oprunasuser",
"runasuser : NAME",
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
"hostlist : ophostspec",
"hostlist : hostlist ',' ophostspec",
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
"$$10 :",
"opuser : '!' $$10 opuser",
"user : NAME",
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
#line 655 "parse.yacc"


typedef struct {
    int type;
    char name[BUFSIZ];
} aliasinfo;

#define MOREALIASES (32)
aliasinfo *aliases = NULL;
size_t naliases = 0;
size_t nslots = 0;


/**********************************************************************
 *
 * aliascmp()
 *
 *  This function compares two aliasinfo structures.
 */

static int aliascmp(a1, a2)
    const VOID *a1, *a2;
{
    int r;
    aliasinfo *ai1, *ai2;

    ai1 = (aliasinfo *) a1;
    ai2 = (aliasinfo *) a2;
    r = strcmp(ai1->name, ai2->name);
    if (r == 0)
	r = ai1->type - ai2->type;

    return(r);
}


/**********************************************************************
 *
 * genaliascmp()
 *
 *  This function compares two generic_alias structures.
 */

static int genaliascmp(entry, key)
    const VOID *entry, *key;
{
    struct generic_alias *ga1 = (struct generic_alias *) key;
    struct generic_alias *ga2 = (struct generic_alias *) entry;

    return(strcmp(ga1->alias, ga2->alias));
}


/**********************************************************************
 *
 * add_alias()
 *
 *  This function adds the named alias of the specified type to the
 *  aliases list.
 */

static int add_alias(alias, type)
    char *alias;
    int type;
{
    aliasinfo ai, *aip;
    char s[512];
    int ok;

    ok = FALSE;			/* assume failure */
    ai.type = type;
    (void) strcpy(ai.name, alias);
    if (lfind((VOID *)&ai, (VOID *)aliases, &naliases, sizeof(ai),
	aliascmp) != NULL) {
	(void) sprintf(s, "Alias `%.*s' already defined", (int) sizeof(s) - 25,
		       alias);
	yyerror(s);
    } else {
	if (naliases >= nslots && !more_aliases()) {
	    (void) sprintf(s, "Out of memory defining alias `%.*s'",
			   (int) sizeof(s) - 32, alias);
	    yyerror(s);
	}

	aip = (aliasinfo *) lsearch((VOID *)&ai, (VOID *)aliases,
				    &naliases, sizeof(ai), aliascmp);

	if (aip != NULL) {
	    ok = TRUE;
	} else {
	    (void) sprintf(s, "Aliases corrupted defining alias `%.*s'",
			   (int) sizeof(s) - 36, alias);
	    yyerror(s);
	}
    }

    return(ok);
}


/**********************************************************************
 *
 * find_alias()
 *
 *  This function searches for the named alias of the specified type.
 */

static int find_alias(alias, type)
    char *alias;
    int type;
{
    aliasinfo ai;

    (void) strcpy(ai.name, alias);
    ai.type = type;

    return(lfind((VOID *)&ai, (VOID *)aliases, &naliases,
		 sizeof(ai), aliascmp) != NULL);
}


/**********************************************************************
 *
 * more_aliases()
 *
 *  This function allocates more space for the aliases list.
 */

static int more_aliases()
{
    nslots += MOREALIASES;
    if (nslots == MOREALIASES)
	aliases = (aliasinfo *) malloc(nslots * sizeof(aliasinfo));
    else
	aliases = (aliasinfo *) realloc(aliases, nslots * sizeof(aliasinfo));

    return(aliases != NULL);
}


/**********************************************************************
 *
 * dumpaliases()
 *
 *  This function lists the contents of the aliases list.
 */

void dumpaliases()
{
    size_t n;

    for (n = 0; n < naliases; n++) {
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
	(void) printf("\t%s\n", aliases[n].name);
    }
}


/**********************************************************************
 *
 * list_matches()
 *
 *  This function lists the contents of cm_list and ga_list for
 *  `sudo -l'.
 */

void list_matches()
{
    int i; 
    char *p;
    struct generic_alias *ga, key;

    (void) puts("You may run the following commands on this host:");
    for (i = 0; i < cm_list_len; i++) {

	/* Print the runas list. */
	(void) fputs("    ", stdout);
	if (cm_list[i].runas) {
	    (void) putchar('(');
	    p = strtok(cm_list[i].runas, ":");
	    do {
		if (p != cm_list[i].runas)
		    (void) fputs(", ", stdout);

		key.alias = p;
		if ((ga = (struct generic_alias *) lfind((VOID *) &key,
		    (VOID *) &ga_list[0], &ga_list_len, sizeof(key), genaliascmp)))
		    (void) fputs(ga->entries, stdout);
		else
		    (void) fputs(p, stdout);
	    } while ((p = strtok(NULL, ":")));
	    (void) fputs(") ", stdout);
	} else {
	    (void) fputs("(root) ", stdout);
	}

	/* Is a password required? */
	if (cm_list[i].nopasswd == TRUE)
	    (void) fputs("NOPASSWD: ", stdout);

	/* Print the actual command or expanded Cmnd_Alias. */
	key.alias = cm_list[i].cmnd;
	if ((ga = (struct generic_alias *) lfind((VOID *) &key,
	    (VOID *) &ga_list[0], &ga_list_len, sizeof(key), genaliascmp)))
	    (void) puts(ga->entries);
	else
	    (void) puts(cm_list[i].cmnd);
    }

    /* Be nice and free up space now that we are done. */
    for (i = 0; i < ga_list_len; i++) {
	(void) free(ga_list[i].alias);
	(void) free(ga_list[i].entries);
    }
    (void) free(ga_list);
    ga_list = NULL;

    for (i = 0; i < cm_list_len; i++) {
	(void) free(cm_list[i].runas);
	(void) free(cm_list[i].cmnd);
    }
    (void) free(cm_list);
    cm_list = NULL;
    cm_list_len = 0;
    cm_list_size = 0;
}


/**********************************************************************
 *
 * append()
 *
 *  This function appends a source string to the destination prefixing
 *  a separator if one is given.
 */

static void append(src, dstp, dst_len, dst_size, separator)
    char *src, **dstp;
    size_t *dst_len, *dst_size;
    int separator;
{
    /* Only add the separator if *dstp is non-NULL. */
    size_t src_len = strlen(src) + ((separator && *dstp) ? 1 : 0);
    char *dst = *dstp;

    /* Assumes dst will be NULL if not set. */
    if (dst == NULL) {
	dst = (char *) emalloc(BUFSIZ);
	*dst_size = BUFSIZ;
	*dst_len = 0;
	*dstp = dst;
    }

    /* Allocate more space if necesary. */
    if (*dst_size <= *dst_len + src_len) {
	while (*dst_size <= *dst_len + src_len)
	    *dst_size += BUFSIZ;

	dst = (char *) erealloc(dst, *dst_size);
	*dstp = dst;
    }

    /* Copy src -> dst adding a separator char if appropriate and adjust len. */
    dst += *dst_len;
    if (separator && *dst_len)
	*dst++ = (char) separator;
    (void) strcpy(dst, src);
    *dst_len += src_len;
}


/**********************************************************************
 *
 * reset_aliases()
 *
 *  This function frees up space used by the aliases list and resets
 *  the associated counters.
 */

void reset_aliases()
{
    if (aliases) {
	(void) free(aliases);
	aliases = NULL;
    }
    naliases = nslots = 0;
}


/**********************************************************************
 *
 * expand_ga_list()
 *
 *  This function increments ga_list_len, allocating more space as necesary.
 */

static void expand_ga_list()
{
    if (++ga_list_len >= ga_list_size) {
	while ((ga_list_size += STACKINCREMENT) < ga_list_len)
	    ;
	ga_list = (struct generic_alias *)
	    erealloc(ga_list, sizeof(struct generic_alias) * ga_list_size);
    }

    ga_list[ga_list_len - 1].entries = NULL;
}


/**********************************************************************
 *
 * expand_match_list()
 *
 *  This function increments cm_list_len, allocating more space as necesary.
 */

static void expand_match_list()
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


/**********************************************************************
 *
 * init_parser()
 *
 *  This function frees up spaced used by a previous parse and
 *  allocates new space for various data structures.
 */

void init_parser()
{
    /* Free up old data structures if we run the parser more than once. */
    if (match) {
	(void) free(match);
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
#line 879 "sudo.tab.c"
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
#line 210 "parse.yacc"
{ ; }
break;
case 4:
#line 212 "parse.yacc"
{ yyerrok; }
break;
case 5:
#line 213 "parse.yacc"
{ push; }
break;
case 6:
#line 213 "parse.yacc"
{
			    while (top && user_matches != TRUE) {
				pop;
			    }
			}
break;
case 7:
#line 219 "parse.yacc"
{ ; }
break;
case 8:
#line 221 "parse.yacc"
{ ; }
break;
case 9:
#line 223 "parse.yacc"
{ ; }
break;
case 10:
#line 225 "parse.yacc"
{ ; }
break;
case 13:
#line 233 "parse.yacc"
{
			    if (user_matches == TRUE) {
				push;
				user_matches = TRUE;
			    } else {
				no_passwd = -1;
				runas_matches = -1;
			    }
			}
break;
case 15:
#line 245 "parse.yacc"
{
			    push;
			}
break;
case 16:
#line 247 "parse.yacc"
{
			    pop;
			    if (host_matched == TRUE)
				host_matches = FALSE;
			    else if (host_matched == FALSE)
				host_matches = TRUE;
			}
break;
case 17:
#line 255 "parse.yacc"
{
			    host_matches = TRUE;
			}
break;
case 18:
#line 258 "parse.yacc"
{
			    if (addr_matches(yyvsp[0].string))
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 19:
#line 263 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, host, NULL))
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 20:
#line 268 "parse.yacc"
{
			    if (strcasecmp(shost, yyvsp[0].string) == 0)
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 21:
#line 273 "parse.yacc"
{
			    if (strcasecmp(host, yyvsp[0].string) == 0)
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 22:
#line 278 "parse.yacc"
{
			    /* could be an all-caps hostname */
			    if (find_alias(yyvsp[0].string, HOST_ALIAS) == TRUE ||
				strcasecmp(shost, yyvsp[0].string) == 0)
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 25:
#line 291 "parse.yacc"
{   /* Push a new entry onto the stack if needed */
			    if (user_matches == TRUE && host_matches == TRUE &&
				cmnd_matches != -1 && runas_matches == TRUE)
				pushcp;
			    cmnd_matches = -1;
			}
break;
case 26:
#line 296 "parse.yacc"
{
			    if (printmatches == TRUE &&
				(runas_matches == -1 || cmnd_matches == -1)) {
				cm_list[cm_list_len].runas_len = 0;
				cm_list[cm_list_len].cmnd_len = 0;
				cm_list[cm_list_len].nopasswd = FALSE;
			    }
			}
break;
case 27:
#line 306 "parse.yacc"
{ ; }
break;
case 28:
#line 307 "parse.yacc"
{
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				append("!", &cm_list[cm_list_len].cmnd,
				       &cm_list[cm_list_len].cmnd_len,
				       &cm_list[cm_list_len].cmnd_size, 0);
				push;
				user_matches = TRUE;
				host_matches = TRUE;
			    } else {
				push;
			    }
			}
break;
case 29:
#line 319 "parse.yacc"
{
			    pop;
			    if (cmnd_matched == TRUE)
				cmnd_matches = FALSE;
			    else if (cmnd_matched == FALSE)
				cmnd_matches = TRUE;
			    yyval.BOOLEAN = cmnd_matches;
			}
break;
case 30:
#line 329 "parse.yacc"
{
			    /*
			     * If this is the first entry in a command list
			     * then check against RUNAS_DEFAULT.
			     */
			    if (runas_matches == -1)
				runas_matches =
				    (strcmp(RUNAS_DEFAULT, runas_user) == 0);
			}
break;
case 31:
#line 338 "parse.yacc"
{ ; }
break;
case 34:
#line 345 "parse.yacc"
{
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				append("", &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, ':');
			}
break;
case 35:
#line 352 "parse.yacc"
{
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				append("!", &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, ':');
				pushcp;
			    } else {
				push;
			    }
			}
break;
case 36:
#line 362 "parse.yacc"
{
			    pop;
			    if (runas_matched == TRUE)
				runas_matches = FALSE;
			    else if (runas_matched == FALSE)
				runas_matches = TRUE;
			}
break;
case 37:
#line 370 "parse.yacc"
{
			    runas_matches = (strcmp(yyvsp[0].string, runas_user) == 0);
			    if (printmatches == TRUE && in_alias == TRUE)
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				append(yyvsp[0].string, &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, 0);
			    (void) free(yyvsp[0].string);
			}
break;
case 38:
#line 383 "parse.yacc"
{
			    runas_matches = usergr_matches(yyvsp[0].string, runas_user);
			    if (printmatches == TRUE && in_alias == TRUE)
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				append(yyvsp[0].string, &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, 0);
			    }
			    (void) free(yyvsp[0].string);
			}
break;
case 39:
#line 397 "parse.yacc"
{
			    runas_matches = netgr_matches(yyvsp[0].string, NULL, runas_user);
			    if (printmatches == TRUE && in_alias == TRUE)
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				append(yyvsp[0].string, &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, 0);
			    }
			    (void) free(yyvsp[0].string);
			}
break;
case 40:
#line 411 "parse.yacc"
{
			    /* could be an all-caps username */
			    if (find_alias(yyvsp[0].string, RUNAS_ALIAS) == TRUE ||
				strcmp(yyvsp[0].string, runas_user) == 0)
				runas_matches = TRUE;
			    else
				runas_matches = FALSE;
			    if (printmatches == TRUE && in_alias == TRUE)
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				append(yyvsp[0].string, &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, 0);
			    (void) free(yyvsp[0].string);
			}
break;
case 41:
#line 429 "parse.yacc"
{
			    runas_matches = TRUE;
			    if (printmatches == TRUE && in_alias == TRUE)
				append("ALL", &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				append("ALL", &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, 0);
			}
break;
case 42:
#line 443 "parse.yacc"
{
			    ;
			}
break;
case 43:
#line 446 "parse.yacc"
{
			    no_passwd = TRUE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = TRUE;
			}
break;
case 44:
#line 452 "parse.yacc"
{
			    no_passwd = FALSE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = FALSE;
			}
break;
case 45:
#line 460 "parse.yacc"
{
			    if (printmatches == TRUE && in_alias == TRUE) {
				append("ALL", &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    }
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				append("ALL", &cm_list[cm_list_len].cmnd,
				       &cm_list[cm_list_len].cmnd_len,
				       &cm_list[cm_list_len].cmnd_size, 0);
				expand_match_list();
			    }

			    cmnd_matches = TRUE;
			    yyval.BOOLEAN = TRUE;
			}
break;
case 46:
#line 477 "parse.yacc"
{
			    if (printmatches == TRUE && in_alias == TRUE) {
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    }
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				append(yyvsp[0].string, &cm_list[cm_list_len].cmnd,
				       &cm_list[cm_list_len].cmnd_len,
				       &cm_list[cm_list_len].cmnd_size, 0);
				expand_match_list();
			    }
			    if (find_alias(yyvsp[0].string, CMND_ALIAS) == TRUE) {
				cmnd_matches = TRUE;
				yyval.BOOLEAN = TRUE;
			    }
			    (void) free(yyvsp[0].string);
			}
break;
case 47:
#line 496 "parse.yacc"
{
			    if (printmatches == TRUE && in_alias == TRUE) {
				append(yyvsp[0].command.cmnd, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
				if (yyvsp[0].command.args)
				    append(yyvsp[0].command.args, &ga_list[ga_list_len-1].entries,
					&ga_list[ga_list_len-1].entries_len,
					&ga_list[ga_list_len-1].entries_size, ' ');
			    }
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)  {
				append(yyvsp[0].command.cmnd, &cm_list[cm_list_len].cmnd,
				       &cm_list[cm_list_len].cmnd_len,
				       &cm_list[cm_list_len].cmnd_size, 0);
				if (yyvsp[0].command.args)
				    append(yyvsp[0].command.args, &cm_list[cm_list_len].cmnd,
					   &cm_list[cm_list_len].cmnd_len,
					   &cm_list[cm_list_len].cmnd_size, ' ');
				expand_match_list();
			    }

			    /* if NewArgc > 1 pass ptr to 1st arg, else NULL */
			    if (command_matches(cmnd, (NewArgc > 1) ?
				    cmnd_args : NULL, yyvsp[0].command.cmnd, yyvsp[0].command.args)) {
				cmnd_matches = TRUE;
				yyval.BOOLEAN = TRUE;
			    }

			    (void) free(yyvsp[0].command.cmnd);
			    if (yyvsp[0].command.args)
				(void) free(yyvsp[0].command.args);
			}
break;
case 50:
#line 535 "parse.yacc"
{ push; }
break;
case 51:
#line 535 "parse.yacc"
{
			    if (host_matches == TRUE &&
				add_alias(yyvsp[-3].string, HOST_ALIAS) == FALSE)
				YYERROR;
			    pop;
			}
break;
case 56:
#line 551 "parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necesary. */
				expand_ga_list();
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			     }
			}
break;
case 57:
#line 559 "parse.yacc"
{
			    if (cmnd_matches == TRUE &&
				add_alias(yyvsp[-3].string, CMND_ALIAS) == FALSE)
				YYERROR;
			    pop;
			    (void) free(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			}
break;
case 58:
#line 571 "parse.yacc"
{ ; }
break;
case 62:
#line 579 "parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necesary. */
				expand_ga_list();
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			    }
			}
break;
case 63:
#line 587 "parse.yacc"
{
			    if (runas_matches > 0 &&
				add_alias(yyvsp[-3].string, RUNAS_ALIAS) == FALSE)
				YYERROR;
			    pop;
			    (void) free(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			}
break;
case 66:
#line 603 "parse.yacc"
{ push; }
break;
case 67:
#line 603 "parse.yacc"
{
			    if (user_matches == TRUE &&
				add_alias(yyvsp[-3].string, USER_ALIAS) == FALSE)
				YYERROR;
			    pop;
			    (void) free(yyvsp[-3].string);
			}
break;
case 68:
#line 612 "parse.yacc"
{ ; }
break;
case 71:
#line 617 "parse.yacc"
{
			    push;
			}
break;
case 72:
#line 619 "parse.yacc"
{
			    pop;
			    if (user_matched == TRUE)
				user_matches = FALSE;
			    else if (user_matched == FALSE)
				user_matches = TRUE;
			}
break;
case 73:
#line 627 "parse.yacc"
{
			    if (strcmp(yyvsp[0].string, user_name) == 0)
				user_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 74:
#line 632 "parse.yacc"
{
			    if (usergr_matches(yyvsp[0].string, user_name))
				user_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 75:
#line 637 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, NULL, user_name))
				user_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 76:
#line 642 "parse.yacc"
{
			    /* could be an all-caps username */
			    if (find_alias(yyvsp[0].string, USER_ALIAS) == TRUE ||
				strcmp(yyvsp[0].string, user_name) == 0)
				user_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 77:
#line 649 "parse.yacc"
{
			    user_matches = TRUE;
			}
break;
#line 1601 "sudo.tab.c"
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
