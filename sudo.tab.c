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
 *  CU sudo version 1.5.8
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
	    match = (struct matchstack *) realloc(match, sizeof(struct matchstack) * stacksize); \
	    if (match == NULL) { \
		(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]); \
		exit(1); \
	    } \
	} \
	match[top].user   = -1; \
	match[top].cmnd   = -1; \
	match[top].host   = -1; \
	match[top].runas  = -1; \
	match[top].nopass = -1; \
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
#line 162 "parse.yacc"
typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
} YYSTYPE;
#line 186 "sudo.tab.c"
#define ALIAS 257
#define NTWKADDR 258
#define FQHOST 259
#define NETGROUP 260
#define USERGROUP 261
#define NAME 262
#define RUNAS 263
#define NOPASSWD 264
#define COMMAND 265
#define COMMENT 266
#define ALL 267
#define HOSTALIAS 268
#define CMNDALIAS 269
#define USERALIAS 270
#define RUNASALIAS 271
#define ERROR 272
#define YYERRCODE 256
short yylhs[] = {                                        -1,
    0,    0,    7,    7,    9,    7,    7,    7,    7,    7,
   10,   10,   15,   16,   16,   16,   16,   16,   16,   17,
   17,   18,    2,   19,    2,    3,    3,    4,    4,    5,
    5,    5,    5,    5,    6,    6,    1,    1,    1,   12,
   12,   21,   20,   22,   22,   13,   13,   24,   23,   25,
   25,   14,   14,   27,   26,   11,   11,   29,   28,   30,
   30,    8,    8,    8,    8,    8,
};
short yylen[] = {                                         2,
    1,    2,    1,    2,    0,    3,    2,    2,    2,    2,
    1,    3,    3,    1,    1,    1,    1,    1,    1,    1,
    3,    3,    1,    0,    3,    0,    2,    1,    3,    1,
    1,    1,    1,    1,    0,    1,    1,    1,    1,    1,
    3,    0,    4,    1,    3,    1,    3,    0,    4,    1,
    3,    1,    3,    0,    4,    1,    3,    0,    4,    1,
    3,    1,    1,    1,    1,    1,
};
short yydefred[] = {                                      0,
    0,    3,    0,    0,    0,    0,    0,    1,    0,    4,
   42,    0,   40,   48,    0,   46,   58,    0,   56,   54,
    0,   52,    2,   65,   64,   63,   62,   66,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   19,   15,   18,
   16,   17,   14,    0,   11,    0,    0,   41,    0,   47,
    0,   57,    0,   53,    0,    0,   44,    0,   38,   39,
   37,   50,    0,   60,    0,   33,   32,   31,   30,   34,
    0,   28,   12,    0,    0,    0,   20,    0,    0,    0,
    0,    0,   36,    0,    0,   45,   51,   61,   29,   24,
   23,   22,   21,    0,   25,
};
short yydgoto[] = {                                       7,
   91,   92,   75,   71,   72,   84,    8,   29,    9,   44,
   18,   12,   15,   21,   45,   46,   76,   77,   94,   13,
   30,   58,   16,   32,   63,   22,   36,   19,   34,   65,
};
short yysindex[] = {                                   -248,
 -259,    0, -247, -246, -245, -244, -248,    0, -220,    0,
    0,  -43,    0,    0,  -42,    0,    0,  -39,    0,    0,
  -34,    0,    0,    0,    0,    0,    0,    0, -231,  -36,
 -247,  -31, -246,  -23, -245,  -22, -244,    0,    0,    0,
    0,    0,    0,  -15,    0,  -17, -231,    0, -211,    0,
 -220,    0, -209,    0, -231, -249,    0,    6,    0,    0,
    0,    0,   11,    0,   19,    0,    0,    0,    0,    0,
   20,    0,    0, -209, -219,   22,    0, -231, -211, -220,
 -209,   20,    0,  -28, -249,    0,    0,    0,    0,    0,
    0,    0,    0,  -28,    0,
};
short yyrindex[] = {                                   -200,
    0,    0,    0,    0,    0,    0, -200,    0,    0,    0,
    0,   81,    0,    0,   97,    0,    0,  113,    0,    0,
  129,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  145,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  -33,    0,    1,    0,    0,
    0,    0,   17,    0,   33,    0,    0,    0,    0,    0,
   49,    0,    0,    0,  -24,   65,    0,    0,    0,    0,
    0,  -29,    0,    0,  -33,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,
};
short yygindex[] = {                                      0,
  -47,  -26,    0,   -5,  -11,    0,   64,  -45,    0,    0,
    0,    0,    0,    0,   18,  -44,    0,  -13,    0,   43,
    0,    0,   44,    0,    0,   39,    0,   45,    0,    0,
};
#define YYTABLESIZE 416
short yytable[] = {                                      26,
   43,   62,   57,   27,   90,   64,   10,    1,   35,   11,
   14,   17,   20,   74,   31,   33,   49,    2,   35,    3,
    4,    5,    6,   37,   47,   38,   39,   40,   41,   49,
   42,   87,   59,   86,   88,   43,   24,   51,   53,   25,
   26,   27,   55,   56,   83,   59,   28,   66,   55,   78,
   67,   68,   69,   60,   79,   61,    5,   70,   43,    5,
    5,    5,   80,   81,   13,   85,    5,   95,   82,   89,
   23,   93,   73,   48,   49,   54,   50,    0,    0,   52,
    8,    0,    0,    0,    0,    0,    0,    0,    0,    0,
   59,    0,    0,    0,    0,    0,    9,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   55,    0,    0,    0,
    0,    0,    7,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   13,    0,    0,    0,    0,    0,   10,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    6,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   26,    0,    0,    0,   27,   59,    0,
   26,   26,   35,   26,   27,   27,   60,   27,   61,    0,
   35,    0,   35,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   43,   43,    0,    0,
   43,   43,   43,    0,    0,    0,   43,   43,   43,   43,
   43,   43,   49,   49,    0,    0,   49,   49,   49,    0,
    0,    0,   49,   49,   49,   49,   49,   49,   59,   59,
    0,    0,   59,   59,   59,    0,    0,    0,   59,   59,
   59,   59,   59,   59,   55,   55,    0,    0,   55,   55,
   55,    0,    0,    0,   55,   55,   55,   55,   55,   55,
   13,   13,    0,    0,   13,   13,   13,    0,    0,    0,
   13,   13,   13,   13,   13,   13,    8,    8,    0,    0,
    8,    8,    8,    0,    0,    0,    8,    8,    8,    8,
    8,    8,    9,    9,    0,    0,    9,    9,    9,    0,
    0,    0,    9,    9,    9,    9,    9,    9,    7,    7,
    0,    0,    7,    7,    7,    0,    0,    0,    7,    7,
    7,    7,    7,    7,   10,   10,    0,    0,   10,   10,
   10,    0,    0,    0,   10,   10,   10,   10,   10,   10,
    6,    6,    0,    0,    6,    6,    6,    0,    0,    0,
    6,    6,    6,    6,    6,    6,
};
short yycheck[] = {                                      33,
    0,   49,   47,   33,   33,   51,  266,  256,   33,  257,
  257,  257,  257,  263,   58,   58,    0,  266,   58,  268,
  269,  270,  271,   58,   61,  257,  258,  259,  260,   61,
  262,   79,    0,   78,   80,  267,  257,   61,   61,  260,
  261,  262,   58,   61,  264,  257,  267,  257,    0,   44,
  260,  261,  262,  265,   44,  267,  257,  267,   58,  260,
  261,  262,   44,   44,    0,   44,  267,   94,   74,   81,
    7,   85,   55,   31,   58,   37,   33,   -1,   -1,   35,
    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   58,   -1,   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   58,   -1,   -1,   -1,
   -1,   -1,    0,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   58,   -1,   -1,   -1,   -1,   -1,    0,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,    0,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  257,   -1,   -1,   -1,  257,  257,   -1,
  264,  265,  257,  267,  264,  265,  265,  267,  267,   -1,
  265,   -1,  267,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,  256,  257,   -1,   -1,
  260,  261,  262,   -1,   -1,   -1,  266,  267,  268,  269,
  270,  271,  256,  257,   -1,   -1,  260,  261,  262,   -1,
   -1,   -1,  266,  267,  268,  269,  270,  271,  256,  257,
   -1,   -1,  260,  261,  262,   -1,   -1,   -1,  266,  267,
  268,  269,  270,  271,  256,  257,   -1,   -1,  260,  261,
  262,   -1,   -1,   -1,  266,  267,  268,  269,  270,  271,
  256,  257,   -1,   -1,  260,  261,  262,   -1,   -1,   -1,
  266,  267,  268,  269,  270,  271,  256,  257,   -1,   -1,
  260,  261,  262,   -1,   -1,   -1,  266,  267,  268,  269,
  270,  271,  256,  257,   -1,   -1,  260,  261,  262,   -1,
   -1,   -1,  266,  267,  268,  269,  270,  271,  256,  257,
   -1,   -1,  260,  261,  262,   -1,   -1,   -1,  266,  267,
  268,  269,  270,  271,  256,  257,   -1,   -1,  260,  261,
  262,   -1,   -1,   -1,  266,  267,  268,  269,  270,  271,
  256,  257,   -1,   -1,  260,  261,  262,   -1,   -1,   -1,
  266,  267,  268,  269,  270,  271,
};
#define YYFINAL 7
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 272
#if YYDEBUG
char *yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
"'!'",0,0,0,0,0,0,0,0,0,0,"','",0,"'.'",0,0,0,0,0,0,0,0,0,0,0,"':'",0,0,"'='",0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"ALIAS",
"NTWKADDR","FQHOST","NETGROUP","USERGROUP","NAME","RUNAS","NOPASSWD","COMMAND",
"COMMENT","ALL","HOSTALIAS","CMNDALIAS","USERALIAS","RUNASALIAS","ERROR",
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
"hostspec : ALL",
"hostspec : NTWKADDR",
"hostspec : NETGROUP",
"hostspec : NAME",
"hostspec : FQHOST",
"hostspec : ALIAS",
"cmndspeclist : cmndspec",
"cmndspeclist : cmndspeclist ',' cmndspec",
"cmndspec : runasspec nopasswd opcmnd",
"opcmnd : cmnd",
"$$2 :",
"opcmnd : '!' $$2 opcmnd",
"runasspec :",
"runasspec : RUNAS runaslist",
"runaslist : runasuser",
"runaslist : runaslist ',' runasuser",
"runasuser : NAME",
"runasuser : USERGROUP",
"runasuser : NETGROUP",
"runasuser : ALIAS",
"runasuser : ALL",
"nopasswd :",
"nopasswd : NOPASSWD",
"cmnd : ALL",
"cmnd : ALIAS",
"cmnd : COMMAND",
"hostaliases : hostalias",
"hostaliases : hostaliases ':' hostalias",
"$$3 :",
"hostalias : ALIAS $$3 '=' hostlist",
"hostlist : hostspec",
"hostlist : hostlist ',' hostspec",
"cmndaliases : cmndalias",
"cmndaliases : cmndaliases ':' cmndalias",
"$$4 :",
"cmndalias : ALIAS $$4 '=' cmndlist",
"cmndlist : cmnd",
"cmndlist : cmndlist ',' cmnd",
"runasaliases : runasalias",
"runasaliases : runasaliases ':' runasalias",
"$$5 :",
"runasalias : ALIAS $$5 '=' runaslist",
"useraliases : useralias",
"useraliases : useraliases ':' useralias",
"$$6 :",
"useralias : ALIAS $$6 '=' userlist",
"userlist : user",
"userlist : userlist ',' user",
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
#line 617 "parse.yacc"


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
	if ((dst = (char *) malloc(BUFSIZ)) == NULL) {
	    (void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	    exit(1);
	}

	*dst_size = BUFSIZ;
	*dst_len = 0;
	*dstp = dst;
    }

    /* Allocate more space if necesary. */
    if (*dst_size <= *dst_len + src_len) {
	while (*dst_size <= *dst_len + src_len)
	    *dst_size += BUFSIZ;

	if (!(dst = (char *) realloc(dst, *dst_size))) {
	    (void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	    exit(1);
	}
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
    if (aliases)
	(void) free(aliases);
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
	while ((ga_list_size += STACKINCREMENT) < ga_list_len);
	if (ga_list == NULL) {
	    if ((ga_list = (struct generic_alias *)
		malloc(sizeof(struct generic_alias) * ga_list_size)) == NULL) {
		(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
		exit(1);
	    }
	} else {
	    if ((ga_list = (struct generic_alias *) realloc(ga_list,
		sizeof(struct generic_alias) * ga_list_size)) == NULL) {
		(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
		exit(1);
	    }
	}
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
	while ((cm_list_size += STACKINCREMENT) < cm_list_len);
	if (cm_list == NULL) {
	    if ((cm_list = (struct command_match *)
		malloc(sizeof(struct command_match) * cm_list_size)) == NULL) {
		(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
		exit(1);
	    }
	    cm_list_len = 0;
	} else {
	    if ((cm_list = (struct command_match *) realloc(cm_list,
		sizeof(struct command_match) * cm_list_size)) == NULL) {
		(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
		exit(1);
	    }
	}
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
    match = (struct matchstack *) malloc(sizeof(struct matchstack) * stacksize);
    if (match == NULL) {
	(void) fprintf(stderr, "%s: cannot allocate memory!\n", Argv[0]);
	exit(1);
    }

    /* Allocate space for the match list (for `sudo -l'). */
    if (printmatches == TRUE)
	expand_match_list();
}
#line 871 "sudo.tab.c"
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
#line 203 "parse.yacc"
{ ; }
break;
case 4:
#line 205 "parse.yacc"
{ yyerrok; }
break;
case 5:
#line 206 "parse.yacc"
{ push; }
break;
case 6:
#line 206 "parse.yacc"
{
			    while (top && user_matches != TRUE) {
				pop;
			    }
			}
break;
case 7:
#line 212 "parse.yacc"
{ ; }
break;
case 8:
#line 214 "parse.yacc"
{ ; }
break;
case 9:
#line 216 "parse.yacc"
{ ; }
break;
case 10:
#line 218 "parse.yacc"
{ ; }
break;
case 13:
#line 226 "parse.yacc"
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
case 14:
#line 237 "parse.yacc"
{
			    host_matches = TRUE;
			}
break;
case 15:
#line 240 "parse.yacc"
{
			    if (addr_matches(yyvsp[0].string))
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 16:
#line 245 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, host, NULL))
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 17:
#line 250 "parse.yacc"
{
			    if (strcasecmp(shost, yyvsp[0].string) == 0)
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 18:
#line 255 "parse.yacc"
{
			    if (strcasecmp(host, yyvsp[0].string) == 0)
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 19:
#line 260 "parse.yacc"
{
			    /* could be an all-caps hostname */
			    if (find_alias(yyvsp[0].string, HOST_ALIAS) == TRUE ||
				strcasecmp(shost, yyvsp[0].string) == 0)
				host_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 22:
#line 273 "parse.yacc"
{
			    if (yyvsp[-2].BOOLEAN > 0 && yyvsp[0].BOOLEAN == TRUE) {
				runas_matches = TRUE;
				if (yyvsp[-1].BOOLEAN == TRUE)
				    no_passwd = TRUE;
				push;
				user_matches = TRUE;
				host_matches = TRUE;
			    } else if (printmatches == TRUE) {
				cm_list[cm_list_len].runas_len = 0;
				cm_list[cm_list_len].cmnd_len = 0;
				cm_list[cm_list_len].nopasswd = FALSE;
			    } else {
				cmnd_matches = -1;
				runas_matches = -1;
				no_passwd = -1;
			    }
			}
break;
case 23:
#line 293 "parse.yacc"
{ ; }
break;
case 24:
#line 294 "parse.yacc"
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
case 25:
#line 306 "parse.yacc"
{
			    int cmnd_matched = cmnd_matches;
			    pop;
			    if (cmnd_matched == TRUE)
				cmnd_matches = FALSE;
			    else if (cmnd_matched == FALSE)
				cmnd_matches = TRUE;
			    yyval.BOOLEAN = cmnd_matches;
			}
break;
case 26:
#line 317 "parse.yacc"
{
			    yyval.BOOLEAN = (strcmp(RUNAS_DEFAULT, runas_user) == 0);
			}
break;
case 27:
#line 320 "parse.yacc"
{
			    yyval.BOOLEAN = yyvsp[0].BOOLEAN;
			}
break;
case 28:
#line 325 "parse.yacc"
{
			    yyval.BOOLEAN = yyvsp[0].BOOLEAN;
			}
break;
case 29:
#line 328 "parse.yacc"
{
			    yyval.BOOLEAN = yyvsp[-2].BOOLEAN + yyvsp[0].BOOLEAN;
			}
break;
case 30:
#line 334 "parse.yacc"
{
			    yyval.BOOLEAN = (strcmp(yyvsp[0].string, runas_user) == 0);
			    if (printmatches == TRUE && in_alias == TRUE)
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				append(yyvsp[0].string, &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, ':');
			    (void) free(yyvsp[0].string);
			}
break;
case 31:
#line 347 "parse.yacc"
{
			    yyval.BOOLEAN = usergr_matches(yyvsp[0].string, runas_user);
			    if (printmatches == TRUE && in_alias == TRUE)
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				append("%", &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, ':');
				append(yyvsp[0].string, &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, 0);
			    }
			    (void) free(yyvsp[0].string);
			}
break;
case 32:
#line 364 "parse.yacc"
{
			    yyval.BOOLEAN = netgr_matches(yyvsp[0].string, NULL, runas_user);
			    if (printmatches == TRUE && in_alias == TRUE)
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				append("+", &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, ':');
				append(yyvsp[0].string, &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, 0);
			    }
			    (void) free(yyvsp[0].string);
			}
break;
case 33:
#line 381 "parse.yacc"
{
			    /* could be an all-caps username */
			    if (find_alias(yyvsp[0].string, RUNAS_ALIAS) == TRUE ||
				strcmp(yyvsp[0].string, runas_user) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = FALSE;
			    if (printmatches == TRUE && in_alias == TRUE)
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				append(yyvsp[0].string, &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, ':');
			    (void) free(yyvsp[0].string);
			}
break;
case 34:
#line 399 "parse.yacc"
{
			    yyval.BOOLEAN = TRUE;
			    if (printmatches == TRUE && in_alias == TRUE)
				append("ALL", &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				append("ALL", &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, ':');
			}
break;
case 35:
#line 413 "parse.yacc"
{
			    yyval.BOOLEAN = FALSE;
			}
break;
case 36:
#line 416 "parse.yacc"
{
			    yyval.BOOLEAN = TRUE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = TRUE;
			}
break;
case 37:
#line 424 "parse.yacc"
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
case 38:
#line 441 "parse.yacc"
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
case 39:
#line 460 "parse.yacc"
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
case 42:
#line 499 "parse.yacc"
{ push; }
break;
case 43:
#line 499 "parse.yacc"
{
			    if (host_matches == TRUE &&
				add_alias(yyvsp[-3].string, HOST_ALIAS) == FALSE)
				YYERROR;
			    pop;
			}
break;
case 48:
#line 515 "parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necesary. */
				expand_ga_list();
				if (!(ga_list[ga_list_len-1].alias = (char *) strdup(yyvsp[0].string))){
				    (void) fprintf(stderr,
				      "%s: cannot allocate memory!\n", Argv[0]);
				    exit(1);
				 }
			     }
			}
break;
case 49:
#line 527 "parse.yacc"
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
case 50:
#line 540 "parse.yacc"
{ ; }
break;
case 54:
#line 548 "parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necesary. */
				expand_ga_list();
				if (!(ga_list[ga_list_len-1].alias = (char *) strdup(yyvsp[0].string))){
				    (void) fprintf(stderr,
				      "%s: cannot allocate memory!\n", Argv[0]);
				    exit(1);
				}
			    }
			}
break;
case 55:
#line 560 "parse.yacc"
{
			    if (yyvsp[0].BOOLEAN > 0 && add_alias(yyvsp[-3].string, RUNAS_ALIAS) == FALSE)
				YYERROR;
			    pop;
			    (void) free(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			}
break;
case 58:
#line 575 "parse.yacc"
{ push; }
break;
case 59:
#line 575 "parse.yacc"
{
			    if (user_matches == TRUE &&
				add_alias(yyvsp[-3].string, USER_ALIAS) == FALSE)
				YYERROR;
			    pop;
			    (void) free(yyvsp[-3].string);
			}
break;
case 60:
#line 585 "parse.yacc"
{ ; }
break;
case 62:
#line 589 "parse.yacc"
{
			    if (strcmp(yyvsp[0].string, user_name) == 0)
				user_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 63:
#line 594 "parse.yacc"
{
			    if (usergr_matches(yyvsp[0].string, user_name))
				user_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 64:
#line 599 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, NULL, user_name))
				user_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 65:
#line 604 "parse.yacc"
{
			    /* could be an all-caps username */
			    if (find_alias(yyvsp[0].string, USER_ALIAS) == TRUE ||
				strcmp(yyvsp[0].string, user_name) == 0)
				user_matches = TRUE;
			    (void) free(yyvsp[0].string);
			}
break;
case 66:
#line 611 "parse.yacc"
{
			    user_matches = TRUE;
			}
break;
#line 1541 "sudo.tab.c"
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
