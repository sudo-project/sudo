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

void
yyerror(s)
    char *s;
{
    /* Save the line the first error occured on. */
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
#line 175 "parse.yacc"
typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
} YYSTYPE;
#line 199 "sudo.tab.c"
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
    6,    6,   11,   14,   16,   14,   15,   15,   15,   15,
   15,   15,   13,   13,   17,    2,   20,    2,   18,   18,
   21,   21,   22,   24,   22,   23,   23,   23,   23,   23,
   19,   19,   19,    1,    1,    1,    8,    8,   26,   25,
   12,   12,    9,    9,   28,   27,   29,   29,   10,   10,
   31,   30,    7,    7,   33,   32,   34,   34,   35,   36,
   35,    4,    4,    4,    4,    4,
};
short yylen[] = {                                         2,
    1,    2,    1,    2,    0,    3,    2,    2,    2,    2,
    1,    3,    3,    1,    0,    3,    1,    1,    1,    1,
    1,    1,    1,    3,    3,    1,    0,    3,    0,    2,
    1,    3,    1,    0,    3,    1,    1,    1,    1,    1,
    0,    1,    1,    1,    1,    1,    1,    3,    0,    4,
    1,    3,    1,    3,    0,    4,    1,    3,    1,    3,
    0,    4,    1,    3,    0,    4,    1,    3,    1,    0,
    3,    1,    1,    1,    1,    1,
};
short yydefred[] = {                                      0,
    0,    3,    0,    0,    0,    0,    0,    1,    0,    4,
   49,    0,   47,   55,    0,   53,   65,    0,   63,   61,
    0,   59,    2,   75,   74,   73,   72,   76,    0,    0,
    0,    0,    0,    0,    0,    0,    0,   22,   18,   21,
   19,   20,   17,   15,    0,   11,    0,   51,   14,    0,
   48,    0,   54,    0,   64,    0,   60,    0,    0,    0,
    0,    0,   45,   46,   44,   27,   26,   57,    0,   70,
   69,    0,   67,   39,   38,   37,   36,   40,   34,    0,
   31,   33,   16,   12,    0,    0,   23,    0,   52,    0,
    0,    0,    0,    0,    0,    0,    0,   42,   43,    0,
   28,   58,   71,   68,   35,   32,   24,   25,
};
short yydgoto[] = {                                       7,
   67,   68,    8,   71,    9,   45,   18,   12,   15,   21,
   46,   47,   86,   48,   49,   58,   87,   88,  100,   90,
   80,   81,   82,   94,   13,   30,   16,   32,   69,   22,
   36,   19,   34,   72,   73,   92,
};
short yysindex[] = {                                   -247,
 -262,    0, -242, -223, -216, -215, -247,    0, -254,    0,
    0,  -37,    0,    0,  -15,    0,    0,  -13,    0,    0,
  -12,    0,    0,    0,    0,    0,    0,    0,  -33,  -14,
 -242,  -11, -223,  -10, -216,   -8, -215,    0,    0,    0,
    0,    0,    0,    0,   -9,    0,  -42,    0,    0,  -33,
    0,   -2,    0,  -29,    0,  -20,    0,  -33,  -33, -209,
  -33,    4,    0,    0,    0,    0,    0,    0,   11,    0,
    0,   12,    0,    0,    0,    0,    0,    0,    0,   13,
    0,    0,    0,    0,  -20,   14,    0, -236,    0,   -2,
   -2,  -29,  -29,  -20,  -20,   13, -209,    0,    0,   -2,
    0,    0,    0,    0,    0,    0,    0,    0,
};
short yyrindex[] = {                                   -224,
    0,    0,    0,    0,    0,    0, -224,    0,    0,    0,
    0,   86,    0,    0,  103,    0,    0,  120,    0,    0,
  137,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  154,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  -21,
    0,    1,    0,    0,    0,    0,    0,    0,   18,    0,
    0,   35,    0,    0,    0,    0,    0,    0,    0,   52,
    0,    0,    0,    0,    0,   69,    0,   -1,    0,    0,
    0,    0,    0,    0,    0,  163,  -21,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,
};
short yygindex[] = {                                      0,
    0,  -74,   53,   54,    0,    0,    0,    0,    0,    0,
    2,   15,    0,  -31,    0,    0,  -35,    0,    0,    0,
  -19,  -84,    0,    0,   33,    0,   34,    0,    0,   31,
    0,   36,    0,    0,  -53,    0,
};
#define YYTABLESIZE 431
short yytable[] = {                                      44,
   50,   61,   24,   70,   10,   25,   26,   27,    1,  105,
  106,   29,   79,   28,   11,  101,  102,   56,   60,    2,
   31,    3,    4,    5,    6,  108,   83,   98,   99,   89,
   66,   41,    5,   14,   66,    5,    5,    5,  103,  104,
   17,   20,   33,    5,   35,   37,   50,   61,   59,   52,
   54,   62,   56,   85,   91,   93,   95,   97,   50,   23,
   84,  107,   29,   51,   62,   96,   53,   57,   13,    0,
   55,    0,    0,    0,    0,   56,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    8,    0,    0,    0,    0,
    0,    0,   66,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    9,    0,    0,    0,    0,    0,    0,   62,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    7,
    0,    0,    0,    0,    0,    0,   13,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   10,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    6,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,   30,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   38,   39,   40,   41,   24,   42,    0,
   25,   26,   27,    0,   43,   29,   74,    0,   28,   75,
   76,   77,   29,   29,   29,    0,   29,   78,    0,    0,
    0,    0,    0,    0,   63,   41,   50,   50,    0,    0,
   50,   50,   50,   64,   41,   65,   41,   50,   50,   50,
   50,   50,   50,   56,   56,    0,    0,   56,   56,   56,
    0,    0,    0,    0,   56,   56,   56,   56,   56,   56,
   66,   66,    0,    0,   66,   66,   66,    0,    0,    0,
    0,   66,   66,   66,   66,   66,   66,   62,   62,    0,
    0,   62,   62,   62,    0,    0,    0,    0,   62,   62,
   62,   62,   62,   62,   13,   13,    0,    0,   13,   13,
   13,    0,    0,    0,    0,   13,   13,   13,   13,   13,
   13,    8,    8,    0,    0,    8,    8,    8,    0,    0,
    0,    0,    8,    8,    8,    8,    8,    8,    9,    9,
    0,    0,    9,    9,    9,    0,    0,    0,    0,    9,
    9,    9,    9,    9,    9,    7,    7,    0,    0,    7,
    7,    7,    0,    0,    0,    0,    7,    7,    7,    7,
    7,    7,   10,   10,    0,    0,   10,   10,   10,    0,
    0,    0,    0,   10,   10,   10,   10,   10,   10,    6,
    6,    0,    0,    6,    6,    6,    0,    0,    0,   30,
    6,    6,    6,    6,    6,    6,   30,   30,   30,    0,
   30,
};
short yycheck[] = {                                      33,
    0,   44,  257,   33,  267,  260,  261,  262,  256,   94,
   95,   33,   33,  268,  257,   90,   91,    0,   61,  267,
   58,  269,  270,  271,  272,  100,   58,  264,  265,   61,
   33,   33,  257,  257,    0,  260,  261,  262,   92,   93,
  257,  257,   58,  268,   58,   58,   61,   44,   58,   61,
   61,    0,   61,  263,   44,   44,   44,   44,   58,    7,
   59,   97,    9,   31,   50,   85,   33,   37,    0,   -1,
   35,   -1,   -1,   -1,   -1,   58,   -1,   -1,   -1,   -1,
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
"privilege : hostlist '=' cmndspeclist",
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
"cmndspec : runasspec nopasswd opcmnd",
"opcmnd : cmnd",
"$$3 :",
"opcmnd : '!' $$3 opcmnd",
"runasspec :",
"runasspec : RUNAS runaslist",
"runaslist : oprunasuser",
"runaslist : runaslist ',' oprunasuser",
"oprunasuser : runasuser",
"$$4 :",
"oprunasuser : '!' $$4 oprunasuser",
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
"$$5 :",
"hostalias : ALIAS $$5 '=' hostlist",
"hostlist : ophostspec",
"hostlist : hostlist ',' ophostspec",
"cmndaliases : cmndalias",
"cmndaliases : cmndaliases ':' cmndalias",
"$$6 :",
"cmndalias : ALIAS $$6 '=' cmndlist",
"cmndlist : opcmnd",
"cmndlist : cmndlist ',' opcmnd",
"runasaliases : runasalias",
"runasaliases : runasaliases ':' runasalias",
"$$7 :",
"runasalias : ALIAS $$7 '=' runaslist",
"useraliases : useralias",
"useraliases : useraliases ':' useralias",
"$$8 :",
"useralias : ALIAS $$8 '=' userlist",
"userlist : opuser",
"userlist : userlist ',' opuser",
"opuser : user",
"$$9 :",
"opuser : '!' $$9 opuser",
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
#line 668 "parse.yacc"

typedef struct {
    int type;
    char name[BUFSIZ];
} aliasinfo;

#define MOREALIASES (32)
aliasinfo *aliases = NULL;
size_t naliases = 0;
size_t nslots = 0;


/*
 * Compare two aliasinfo structures, strcmp() style.
 */
static int
aliascmp(a1, a2)
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

/*
 * Compare two generic_alias structures, strcmp() style.
 */
static int
genaliascmp(entry, key)
    const VOID *entry, *key;
{
    struct generic_alias *ga1 = (struct generic_alias *) key;
    struct generic_alias *ga2 = (struct generic_alias *) entry;

    return(strcmp(ga1->alias, ga2->alias));
}


/*
 * Adds the named alias of the specified type to the aliases list.
 */
static int
add_alias(alias, type)
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

/*
 * Searches for the named alias of the specified type.
 */
static int
find_alias(alias, type)
    char *alias;
    int type;
{
    aliasinfo ai;

    (void) strcpy(ai.name, alias);
    ai.type = type;

    return(lfind((VOID *)&ai, (VOID *)aliases, &naliases,
		 sizeof(ai), aliascmp) != NULL);
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

/*
 * Lists the contents of cm_list and ga_list for `sudo -l'.
 */
void
list_matches()
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

    /* Allocate more space if necessary. */
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

/*
 * Frees up space used by the aliases list and resets the associated counters.
 */
void
reset_aliases()
{

    if (aliases) {
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
#line 835 "sudo.tab.c"
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
#line 212 "parse.yacc"
{ ; }
break;
case 4:
#line 214 "parse.yacc"
{ yyerrok; }
break;
case 5:
#line 215 "parse.yacc"
{ push; }
break;
case 6:
#line 215 "parse.yacc"
{
			    while (top && user_matches != TRUE) {
				pop;
			    }
			}
break;
case 7:
#line 221 "parse.yacc"
{ ; }
break;
case 8:
#line 223 "parse.yacc"
{ ; }
break;
case 9:
#line 225 "parse.yacc"
{ ; }
break;
case 10:
#line 227 "parse.yacc"
{ ; }
break;
case 13:
#line 235 "parse.yacc"
{
			    /*
			     * We already did a push if necessary in
			     * cmndspec so just reset some values so
			     * the next 'privilege' gets a clean slate.
			     */
			    host_matches = -1;
			    runas_matches = -1;
			    no_passwd = -1;
			}
break;
case 15:
#line 248 "parse.yacc"
{
			    push;
			}
break;
case 16:
#line 250 "parse.yacc"
{
			    pop;
			    if (host_matched == TRUE)
				host_matches = FALSE;
			    else if (host_matched == FALSE)
				host_matches = TRUE;
			}
break;
case 17:
#line 258 "parse.yacc"
{
			    host_matches = TRUE;
			}
break;
case 18:
#line 261 "parse.yacc"
{
			    if (addr_matches(yyvsp[0].string))
				host_matches = TRUE;
			    free(yyvsp[0].string);
			}
break;
case 19:
#line 266 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, user_host, NULL))
				host_matches = TRUE;
			    free(yyvsp[0].string);
			}
break;
case 20:
#line 271 "parse.yacc"
{
			    if (strcasecmp(user_shost, yyvsp[0].string) == 0)
				host_matches = TRUE;
			    free(yyvsp[0].string);
			}
break;
case 21:
#line 276 "parse.yacc"
{
			    if (strcasecmp(user_host, yyvsp[0].string) == 0)
				host_matches = TRUE;
			    free(yyvsp[0].string);
			}
break;
case 22:
#line 281 "parse.yacc"
{
			    /* could be an all-caps hostname */
			    if (find_alias(yyvsp[0].string, HOST_ALIAS) == TRUE ||
				strcasecmp(user_shost, yyvsp[0].string) == 0)
				host_matches = TRUE;
			    free(yyvsp[0].string);
			}
break;
case 25:
#line 294 "parse.yacc"
{
			    if (printmatches == TRUE &&
				(runas_matches == -1 || cmnd_matches == -1)) {
				cm_list[cm_list_len].runas_len = 0;
				cm_list[cm_list_len].cmnd_len = 0;
				cm_list[cm_list_len].nopasswd = FALSE;
			    }
			    /*
			     * Push the entry onto the stack if it is worth
			     * saving (or if nothing else is on the stack)
			     * and clear match status.
			     */
			    if (user_matches == TRUE && host_matches == TRUE &&
				((cmnd_matches != -1 && runas_matches != -1) ||
				top == 1))
				pushcp;
			    cmnd_matches = -1;
			}
break;
case 26:
#line 314 "parse.yacc"
{ ; }
break;
case 27:
#line 315 "parse.yacc"
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
case 28:
#line 327 "parse.yacc"
{
			    pop;
			    if (cmnd_matched == TRUE)
				cmnd_matches = FALSE;
			    else if (cmnd_matched == FALSE)
				cmnd_matches = TRUE;
			    yyval.BOOLEAN = cmnd_matches;
			}
break;
case 29:
#line 337 "parse.yacc"
{
			    /*
			     * If this is the first entry in a command list
			     * then check against RUNAS_DEFAULT.
			     */
			    if (runas_matches == -1)
				runas_matches =
				    (strcmp(RUNAS_DEFAULT, user_runas) == 0);
			}
break;
case 30:
#line 346 "parse.yacc"
{ ; }
break;
case 33:
#line 353 "parse.yacc"
{
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				append("", &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, ':');
			}
break;
case 34:
#line 360 "parse.yacc"
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
case 35:
#line 370 "parse.yacc"
{
			    pop;
			    /*
			     * Don't negate FALSE -> TRUE since that would
			     * make !foo match any time the user specified
			     * a runas user (via -u) other than foo.
			     */
			    if (runas_matched == TRUE)
				runas_matches = FALSE;
			}
break;
case 36:
#line 381 "parse.yacc"
{
			    runas_matches = (strcmp(yyvsp[0].string, user_runas) == 0);
			    if (printmatches == TRUE && in_alias == TRUE)
				append(yyvsp[0].string, &ga_list[ga_list_len-1].entries,
				       &ga_list[ga_list_len-1].entries_len,
				       &ga_list[ga_list_len-1].entries_size, ',');
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				append(yyvsp[0].string, &cm_list[cm_list_len].runas,
				       &cm_list[cm_list_len].runas_len,
				       &cm_list[cm_list_len].runas_size, 0);
			    free(yyvsp[0].string);
			}
break;
case 37:
#line 394 "parse.yacc"
{
			    runas_matches = usergr_matches(yyvsp[0].string, user_runas);
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
			    free(yyvsp[0].string);
			}
break;
case 38:
#line 408 "parse.yacc"
{
			    runas_matches = netgr_matches(yyvsp[0].string, NULL, user_runas);
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
			    free(yyvsp[0].string);
			}
break;
case 39:
#line 422 "parse.yacc"
{
			    /* could be an all-caps username */
			    if (find_alias(yyvsp[0].string, RUNAS_ALIAS) == TRUE ||
				strcmp(yyvsp[0].string, user_runas) == 0)
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
			    free(yyvsp[0].string);
			}
break;
case 40:
#line 440 "parse.yacc"
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
case 41:
#line 454 "parse.yacc"
{
			    ;
			}
break;
case 42:
#line 457 "parse.yacc"
{
			    no_passwd = TRUE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = TRUE;
			}
break;
case 43:
#line 463 "parse.yacc"
{
			    no_passwd = FALSE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = FALSE;
			}
break;
case 44:
#line 471 "parse.yacc"
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

			    yyval.BOOLEAN = cmnd_matches = TRUE;
			    if (safe_cmnd)
				free(safe_cmnd);
			    safe_cmnd = estrdup(user_cmnd);
			}
break;
case 45:
#line 490 "parse.yacc"
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
			    free(yyvsp[0].string);
			}
break;
case 46:
#line 509 "parse.yacc"
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
			    if (command_matches(user_cmnd, (NewArgc > 1) ?
				    user_args : NULL, yyvsp[0].command.cmnd, yyvsp[0].command.args)) {
				cmnd_matches = TRUE;
				yyval.BOOLEAN = TRUE;
			    }

			    free(yyvsp[0].command.cmnd);
			    if (yyvsp[0].command.args)
				free(yyvsp[0].command.args);
			}
break;
case 49:
#line 548 "parse.yacc"
{ push; }
break;
case 50:
#line 548 "parse.yacc"
{
			    if (host_matches == TRUE &&
				add_alias(yyvsp[-3].string, HOST_ALIAS) == FALSE)
				YYERROR;
			    pop;
			}
break;
case 55:
#line 564 "parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necessary. */
				expand_ga_list();
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			     }
			}
break;
case 56:
#line 572 "parse.yacc"
{
			    if (cmnd_matches == TRUE &&
				add_alias(yyvsp[-3].string, CMND_ALIAS) == FALSE)
				YYERROR;
			    pop;
			    free(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			}
break;
case 57:
#line 584 "parse.yacc"
{ ; }
break;
case 61:
#line 592 "parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necessary. */
				expand_ga_list();
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			    }
			}
break;
case 62:
#line 600 "parse.yacc"
{
			    if (runas_matches > 0 &&
				add_alias(yyvsp[-3].string, RUNAS_ALIAS) == FALSE)
				YYERROR;
			    pop;
			    free(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			}
break;
case 65:
#line 616 "parse.yacc"
{ push; }
break;
case 66:
#line 616 "parse.yacc"
{
			    if (user_matches == TRUE &&
				add_alias(yyvsp[-3].string, USER_ALIAS) == FALSE)
				YYERROR;
			    pop;
			    free(yyvsp[-3].string);
			}
break;
case 67:
#line 625 "parse.yacc"
{ ; }
break;
case 70:
#line 630 "parse.yacc"
{
			    push;
			}
break;
case 71:
#line 632 "parse.yacc"
{
			    pop;
			    if (user_matched == TRUE)
				user_matches = FALSE;
			    else if (user_matched == FALSE)
				user_matches = TRUE;
			}
break;
case 72:
#line 640 "parse.yacc"
{
			    if (strcmp(yyvsp[0].string, user_name) == 0)
				user_matches = TRUE;
			    free(yyvsp[0].string);
			}
break;
case 73:
#line 645 "parse.yacc"
{
			    if (usergr_matches(yyvsp[0].string, user_name))
				user_matches = TRUE;
			    free(yyvsp[0].string);
			}
break;
case 74:
#line 650 "parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, NULL, user_name))
				user_matches = TRUE;
			    free(yyvsp[0].string);
			}
break;
case 75:
#line 655 "parse.yacc"
{
			    /* could be an all-caps username */
			    if (find_alias(yyvsp[0].string, USER_ALIAS) == TRUE ||
				strcmp(yyvsp[0].string, user_name) == 0)
				user_matches = TRUE;
			    free(yyvsp[0].string);
			}
break;
case 76:
#line 662 "parse.yacc"
{
			    user_matches = TRUE;
			}
break;
#line 1564 "sudo.tab.c"
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
