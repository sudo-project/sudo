
/*  A Bison parser, made from ./parse.yacc
 by  GNU Bison version 1.27
  */

#define YYBISON 1  /* Identify Bison output.  */

#define	COMMAND	257
#define	ALIAS	258
#define	NTWKADDR	259
#define	FQHOST	260
#define	NETGROUP	261
#define	USERGROUP	262
#define	NAME	263
#define	RUNAS	264
#define	NOPASSWD	265
#define	PASSWD	266
#define	ALL	267
#define	COMMENT	268
#define	HOSTALIAS	269
#define	CMNDALIAS	270
#define	USERALIAS	271
#define	RUNASALIAS	272
#define	ERROR	273

#line 1 "./parse.yacc"

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
int clearaliases = TRUE;
int printmatches = FALSE;
int pedantic = FALSE;
#ifdef NO_AUTHENTICATION
int pwdef = TRUE;
#else
int pwdef = -1;
#endif

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
	match[top].nopass = pwdef; \
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
 * Protoypes
 */
extern int  addr_matches	__P((char *));
extern int  command_matches	__P((char *, char *, char *, char *));
extern int  netgr_matches	__P((char *, char *, char *));
extern int  usergr_matches	__P((char *, char *));
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

#line 211 "./parse.yacc"
typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
} YYSTYPE;
#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		108
#define	YYFLAG		-32768
#define	YYNTBASE	24

#define YYTRANSLATE(x) ((unsigned)(x) <= 273 ? yytranslate[x] : 59)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    22,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,    21,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    19,     2,     2,
    20,     2,     2,     2,     2,     2,     2,     2,     2,     2,
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
     2,     2,     2,     2,     2,     1,     3,     4,     5,     6,
     7,     8,     9,    10,    11,    12,    13,    14,    15,    16,
    17,    18,    23
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     2,     5,     7,    10,    11,    15,    18,    21,    24,
    27,    29,    33,    37,    39,    42,    44,    46,    48,    50,
    52,    54,    56,    60,    64,    66,    67,    71,    72,    75,
    77,    81,    83,    84,    88,    90,    92,    94,    96,    98,
    99,   101,   103,   105,   107,   109,   111,   115,   116,   121,
   123,   127,   129,   133,   134,   139,   141,   145,   147,   151,
   152,   157,   159,   163,   164,   169,   171,   175,   177,   180,
   182,   184,   186,   188
};

static const short yyrhs[] = {    25,
     0,    24,    25,     0,    14,     0,     1,    14,     0,     0,
    26,    56,    27,     0,    17,    53,     0,    15,    42,     0,
    16,    46,     0,    18,    50,     0,    28,     0,    27,    19,
    28,     0,    45,    20,    31,     0,    30,     0,    22,    30,
     0,    13,     0,     5,     0,     7,     0,     9,     0,     6,
     0,     4,     0,    32,     0,    31,    21,    32,     0,    35,
    40,    33,     0,    41,     0,     0,    22,    34,    41,     0,
     0,    10,    36,     0,    37,     0,    36,    21,    37,     0,
    39,     0,     0,    22,    38,    39,     0,     9,     0,     8,
     0,     7,     0,     4,     0,    13,     0,     0,    11,     0,
    12,     0,    13,     0,     4,     0,     3,     0,    43,     0,
    42,    19,    43,     0,     0,     4,    44,    20,    45,     0,
    29,     0,    45,    21,    29,     0,    47,     0,    46,    19,
    47,     0,     0,     4,    48,    20,    49,     0,    33,     0,
    49,    21,    33,     0,    51,     0,    50,    19,    51,     0,
     0,     4,    52,    20,    36,     0,    54,     0,    53,    19,
    54,     0,     0,     4,    55,    20,    56,     0,    57,     0,
    56,    21,    57,     0,    58,     0,    22,    58,     0,     9,
     0,     8,     0,     7,     0,     4,     0,    13,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   251,   252,   255,   257,   259,   259,   263,   265,   267,   269,
   274,   275,   278,   290,   294,   299,   302,   309,   316,   323,
   330,   354,   355,   358,   380,   384,   392,   398,   421,   424,
   425,   428,   432,   440,   445,   459,   473,   487,   516,   528,
   538,   544,   552,   569,   598,   626,   627,   630,   630,   638,
   639,   642,   643,   646,   655,   667,   668,   671,   672,   675,
   684,   696,   697,   700,   700,   709,   710,   713,   717,   722,
   729,   736,   743,   763
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","COMMAND",
"ALIAS","NTWKADDR","FQHOST","NETGROUP","USERGROUP","NAME","RUNAS","NOPASSWD",
"PASSWD","ALL","COMMENT","HOSTALIAS","CMNDALIAS","USERALIAS","RUNASALIAS","':'",
"'='","','","'!'","ERROR","file","entry","@1","privileges","privilege","ophost",
"host","cmndspeclist","cmndspec","opcmnd","@2","runasspec","runaslist","oprunasuser",
"@3","runasuser","nopasswd","cmnd","hostaliases","hostalias","@4","hostlist",
"cmndaliases","cmndalias","@5","cmndlist","runasaliases","runasalias","@6","useraliases",
"useralias","@7","userlist","opuser","user", NULL
};
#endif

static const short yyr1[] = {     0,
    24,    24,    25,    25,    26,    25,    25,    25,    25,    25,
    27,    27,    28,    29,    29,    30,    30,    30,    30,    30,
    30,    31,    31,    32,    33,    34,    33,    35,    35,    36,
    36,    37,    38,    37,    39,    39,    39,    39,    39,    40,
    40,    40,    41,    41,    41,    42,    42,    44,    43,    45,
    45,    46,    46,    48,    47,    49,    49,    50,    50,    52,
    51,    53,    53,    55,    54,    56,    56,    57,    57,    58,
    58,    58,    58,    58
};

static const short yyr2[] = {     0,
     1,     2,     1,     2,     0,     3,     2,     2,     2,     2,
     1,     3,     3,     1,     2,     1,     1,     1,     1,     1,
     1,     1,     3,     3,     1,     0,     3,     0,     2,     1,
     3,     1,     0,     3,     1,     1,     1,     1,     1,     0,
     1,     1,     1,     1,     1,     1,     3,     0,     4,     1,
     3,     1,     3,     0,     4,     1,     3,     1,     3,     0,
     4,     1,     3,     0,     4,     1,     3,     1,     2,     1,
     1,     1,     1,     1
};

static const short yydefact[] = {     0,
     0,     3,     0,     0,     0,     0,     0,     1,     0,     4,
    48,     8,    46,    54,     9,    52,    64,     7,    62,    60,
    10,    58,     2,    73,    72,    71,    70,    74,     0,     0,
    66,    68,     0,     0,     0,     0,     0,     0,     0,     0,
    69,    21,    17,    20,    18,    19,    16,     0,     0,     6,
    11,    50,    14,     0,     0,    47,     0,    53,     0,    63,
     0,    59,    67,    15,     0,    28,     0,    49,    45,    44,
    43,    26,    56,    25,    55,    65,    38,    37,    36,    35,
    39,    33,    61,    30,    32,    12,     0,    13,    22,    40,
    51,     0,     0,     0,     0,    29,    28,    41,    42,     0,
    27,    57,    34,    31,    23,    24,     0,     0
};

static const short yydefgoto[] = {     7,
     8,     9,    50,    51,    52,    53,    88,    89,    73,    92,
    90,    83,    84,    94,    85,   100,    74,    12,    13,    33,
    54,    15,    16,    35,    75,    21,    22,    39,    18,    19,
    37,    30,    31,    32
};

static const short yypact[] = {    19,
    -4,-32768,     7,    15,    21,    34,     0,-32768,    58,-32768,
-32768,    27,-32768,-32768,    31,-32768,-32768,    39,-32768,-32768,
    44,-32768,-32768,-32768,-32768,-32768,-32768,-32768,    84,    38,
-32768,-32768,    20,     7,    36,    15,    55,    21,    56,    34,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,    58,    77,    45,
-32768,-32768,-32768,   -15,    48,-32768,    -1,-32768,    58,-32768,
    65,-32768,-32768,-32768,    48,    67,    48,    47,-32768,-32768,
-32768,-32768,-32768,-32768,    64,    68,-32768,-32768,-32768,-32768,
-32768,-32768,    73,-32768,-32768,-32768,    65,    75,-32768,    37,
-32768,    26,    -1,    91,    65,    73,    67,-32768,-32768,    -1,
-32768,-32768,-32768,-32768,-32768,-32768,    79,-32768
};

static const short yypgoto[] = {-32768,
    94,-32768,-32768,    40,    35,    54,-32768,     9,   -69,-32768,
-32768,    22,    12,-32768,    14,-32768,    18,-32768,    78,-32768,
    59,-32768,    80,-32768,-32768,-32768,    71,-32768,-32768,    81,
-32768,    61,    69,    86
};


#define	YYLAST		120


static const short yytable[] = {   107,
     1,    69,    70,    -5,    66,    67,    -5,    -5,    -5,    10,
    11,    71,    -5,     2,     3,     4,     5,     6,    14,     1,
    72,    -5,    -5,   102,    17,    -5,    -5,    -5,    69,    70,
   106,    -5,     2,     3,     4,     5,     6,    20,    71,    55,
    -5,    42,    43,    44,    45,    34,    46,    98,    99,    36,
    47,    42,    43,    44,    45,    57,    46,    38,    48,    49,
    47,    24,    40,    65,    25,    26,    27,    67,    77,    49,
    28,    78,    79,    80,    59,    61,    87,    81,   108,    29,
    42,    43,    44,    45,    93,    46,    82,    24,    48,    47,
    25,    26,    27,    95,    77,    97,    28,    78,    79,    80,
    23,    91,    64,    81,    86,   105,   104,   103,    96,   101,
    62,    56,     0,    68,    41,    58,    63,     0,    60,    76
};

static const short yycheck[] = {     0,
     1,     3,     4,     4,    20,    21,     7,     8,     9,    14,
     4,    13,    13,    14,    15,    16,    17,    18,     4,     1,
    22,    22,     4,    93,     4,     7,     8,     9,     3,     4,
   100,    13,    14,    15,    16,    17,    18,     4,    13,    20,
    22,     4,     5,     6,     7,    19,     9,    11,    12,    19,
    13,     4,     5,     6,     7,    20,     9,    19,    21,    22,
    13,     4,    19,    19,     7,     8,     9,    21,     4,    22,
    13,     7,     8,     9,    20,    20,    10,    13,     0,    22,
     4,     5,     6,     7,    21,     9,    22,     4,    21,    13,
     7,     8,     9,    21,     4,    21,    13,     7,     8,     9,
     7,    67,    49,    13,    65,    97,    95,    94,    87,    92,
    40,    34,    -1,    55,    29,    36,    48,    -1,    38,    59
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/local/share/bison.simple"
/* This file comes from bison-1.27.  */

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

#ifndef YYSTACK_USE_ALLOCA
#ifdef alloca
#define YYSTACK_USE_ALLOCA
#else /* alloca not defined */
#ifdef __GNUC__
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi) || (defined (__sun) && defined (__i386))
#define YYSTACK_USE_ALLOCA
#include <alloca.h>
#else /* not sparc */
/* We think this test detects Watcom and Microsoft C.  */
/* This used to test MSDOS, but that is a bad idea
   since that symbol is in the user namespace.  */
#if (defined (_MSDOS) || defined (_MSDOS_)) && !defined (__TURBOC__)
#if 0 /* No need for malloc.h, which pollutes the namespace;
	 instead, just don't use alloca.  */
#include <malloc.h>
#endif
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
/* I don't know what this was needed for, but it pollutes the namespace.
   So I turned it off.   rms, 2 May 1997.  */
/* #include <malloc.h>  */
 #pragma alloca
#define YYSTACK_USE_ALLOCA
#else /* not MSDOS, or __TURBOC__, or _AIX */
#if 0
#ifdef __hpux /* haible@ilog.fr says this works for HPUX 9.05 and up,
		 and on HPUX 10.  Eventually we can turn this on.  */
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#endif /* __hpux */
#endif
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc */
#endif /* not GNU C */
#endif /* alloca not defined */
#endif /* YYSTACK_USE_ALLOCA not defined */

#ifdef YYSTACK_USE_ALLOCA
#define YYSTACK_ALLOC alloca
#else
#define YYSTACK_ALLOC malloc
#endif

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	yychar;			/*  the lookahead symbol		*/
YYSTYPE	yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Define __yy_memcpy.  Note that the size argument
   should be passed with type unsigned int, because that is what the non-GCC
   definitions require.  With GCC, __builtin_memcpy takes an arg
   of type size_t, but it can handle unsigned int.  */

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(TO,FROM,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (to, from, count)
     char *to;
     char *from;
     unsigned int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (char *to, char *from, unsigned int count)
{
  register char *t = to;
  register char *f = from;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 216 "/usr/local/share/bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#ifdef __cplusplus
#define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else /* not __cplusplus */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#endif /* not __cplusplus */
#else /* not YYPARSE_PARAM */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif /* not YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
#ifdef YYPARSE_PARAM
int yyparse (void *);
#else
int yyparse (void);
#endif
#endif

int
yyparse(YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *yyss = yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  int yystacksize = YYINITDEPTH;
  int yyfree_stacks = 0;

#ifdef YYPURE
  int yychar;
  YYSTYPE yylval;
  int yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE yylloc;
#endif
#endif

  YYSTYPE yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int yylen;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss - 1;
  yyvsp = yyvs;
#ifdef YYLSP_NEEDED
  yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
yynewstate:

  *++yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *yyvs1 = yyvs;
      short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *yyls1 = yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = yyssp - yyss + 1;

#ifdef yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if yyoverflow is a macro.  */
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yyls1, size * sizeof (*yylsp),
		 &yystacksize);
#else
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yystacksize);
#endif

      yyss = yyss1; yyvs = yyvs1;
#ifdef YYLSP_NEEDED
      yyls = yyls1;
#endif
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	{
	  yyerror("parser stack overflow");
	  if (yyfree_stacks)
	    {
	      free (yyss);
	      free (yyvs);
#ifdef YYLSP_NEEDED
	      free (yyls);
#endif
	    }
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
#ifndef YYSTACK_USE_ALLOCA
      yyfree_stacks = 1;
#endif
      yyss = (short *) YYSTACK_ALLOC (yystacksize * sizeof (*yyssp));
      __yy_memcpy ((char *)yyss, (char *)yyss1,
		   size * (unsigned int) sizeof (*yyssp));
      yyvs = (YYSTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yyvsp));
      __yy_memcpy ((char *)yyvs, (char *)yyvs1,
		   size * (unsigned int) sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yylsp));
      __yy_memcpy ((char *)yyls, (char *)yyls1,
		   size * (unsigned int) sizeof (*yylsp));
#endif
#endif /* no yyoverflow */

      yyssp = yyss + size - 1;
      yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
      yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Entering state %d\n", yystate);
#endif

  goto yybackup;
 yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
      if (yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (yyerrstatus) yyerrstatus--;

  yystate = yyn;
  goto yynewstate;

/* Do the default action for the current state.  */
yydefault:

  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
yyreduce:
  yylen = yyr2[yyn];
  if (yylen > 0)
    yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

case 3:
#line 256 "./parse.yacc"
{ ; ;
    break;}
case 4:
#line 258 "./parse.yacc"
{ yyerrok; ;
    break;}
case 5:
#line 259 "./parse.yacc"
{ push; ;
    break;}
case 6:
#line 259 "./parse.yacc"
{
			    while (top && user_matches != TRUE)
				pop;
			;
    break;}
case 7:
#line 264 "./parse.yacc"
{ ; ;
    break;}
case 8:
#line 266 "./parse.yacc"
{ ; ;
    break;}
case 9:
#line 268 "./parse.yacc"
{ ; ;
    break;}
case 10:
#line 270 "./parse.yacc"
{ ; ;
    break;}
case 13:
#line 278 "./parse.yacc"
{
			    /*
			     * We already did a push if necessary in
			     * cmndspec so just reset some values so
			     * the next 'privilege' gets a clean slate.
			     */
			    host_matches = -1;
			    runas_matches = -1;
			    no_passwd = pwdef;
			;
    break;}
case 14:
#line 290 "./parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				host_matches = yyvsp[0].BOOLEAN;
			;
    break;}
case 15:
#line 294 "./parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				host_matches = ! yyvsp[0].BOOLEAN;
			;
    break;}
case 16:
#line 299 "./parse.yacc"
{
			    yyval.BOOLEAN = TRUE;
			;
    break;}
case 17:
#line 302 "./parse.yacc"
{
			    if (addr_matches(yyvsp[0].string))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 18:
#line 309 "./parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, user_host, NULL))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 19:
#line 316 "./parse.yacc"
{
			    if (strcasecmp(user_shost, yyvsp[0].string) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 20:
#line 323 "./parse.yacc"
{
			    if (strcasecmp(user_host, yyvsp[0].string) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 21:
#line 330 "./parse.yacc"
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
			;
    break;}
case 24:
#line 358 "./parse.yacc"
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
			;
    break;}
case 25:
#line 380 "./parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				cmnd_matches = yyvsp[0].BOOLEAN;
			;
    break;}
case 26:
#line 384 "./parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("!", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_cmnd("!", NULL);
			    }
			;
    break;}
case 27:
#line 392 "./parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				cmnd_matches = ! yyvsp[0].BOOLEAN;
			;
    break;}
case 28:
#line 398 "./parse.yacc"
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
			     * then check against RUNAS_DEFAULT.
			     */
			    if (runas_matches == -1)
				runas_matches =
				    (strcmp(RUNAS_DEFAULT, user_runas) == 0);
			;
    break;}
case 29:
#line 421 "./parse.yacc"
{ ; ;
    break;}
case 32:
#line 428 "./parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				runas_matches = yyvsp[0].BOOLEAN;
			;
    break;}
case 33:
#line 432 "./parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("!", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas("!", ", ");
			    }
			;
    break;}
case 34:
#line 440 "./parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				runas_matches = ! yyvsp[0].BOOLEAN;
			;
    break;}
case 35:
#line 445 "./parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    if (strcmp(yyvsp[0].string, user_runas) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 36:
#line 459 "./parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    if (usergr_matches(yyvsp[0].string, user_runas))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 37:
#line 473 "./parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries(yyvsp[0].string, ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas(yyvsp[0].string, ", ");
			    }
			    if (netgr_matches(yyvsp[0].string, NULL, user_runas))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 38:
#line 487 "./parse.yacc"
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
			    else if (strcmp(yyvsp[0].string, user_runas) == 0)
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
			;
    break;}
case 39:
#line 516 "./parse.yacc"
{
			    if (printmatches == TRUE) {
				if (in_alias == TRUE)
				    append_entries("ALL", ", ");
				else if (host_matches == TRUE &&
				    user_matches == TRUE)
				    append_runas("ALL", ", ");
			    }
			    yyval.BOOLEAN = TRUE;
			;
    break;}
case 40:
#line 528 "./parse.yacc"
{
			    /* Inherit NOPASSWD/PASSWD status. */
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE) {
				if (no_passwd == TRUE)
				    cm_list[cm_list_len].nopasswd = TRUE;
				else
				    cm_list[cm_list_len].nopasswd = FALSE;
			    }
			;
    break;}
case 41:
#line 538 "./parse.yacc"
{
			    no_passwd = TRUE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = TRUE;
			;
    break;}
case 42:
#line 544 "./parse.yacc"
{
			    no_passwd = FALSE;
			    if (printmatches == TRUE && host_matches == TRUE &&
				user_matches == TRUE)
				cm_list[cm_list_len].nopasswd = FALSE;
			;
    break;}
case 43:
#line 552 "./parse.yacc"
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
			;
    break;}
case 44:
#line 569 "./parse.yacc"
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
			;
    break;}
case 45:
#line 598 "./parse.yacc"
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
			;
    break;}
case 48:
#line 630 "./parse.yacc"
{ push; ;
    break;}
case 49:
#line 630 "./parse.yacc"
{
			    if ((host_matches != -1 || pedantic) &&
				!add_alias(yyvsp[-3].string, HOST_ALIAS, host_matches))
				YYERROR;
			    pop;
			;
    break;}
case 54:
#line 646 "./parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necessary. */
				expand_ga_list();
				ga_list[ga_list_len-1].type = CMND_ALIAS;
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			     }
			;
    break;}
case 55:
#line 655 "./parse.yacc"
{
			    if ((cmnd_matches != -1 || pedantic) &&
				!add_alias(yyvsp[-3].string, CMND_ALIAS, cmnd_matches))
				YYERROR;
			    pop;
			    free(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			;
    break;}
case 56:
#line 667 "./parse.yacc"
{ ; ;
    break;}
case 60:
#line 675 "./parse.yacc"
{
			    push;
			    if (printmatches == TRUE) {
				in_alias = TRUE;
				/* Allocate space for ga_list if necessary. */
				expand_ga_list();
				ga_list[ga_list_len-1].type = RUNAS_ALIAS;
				ga_list[ga_list_len-1].alias = estrdup(yyvsp[0].string);
			    }
			;
    break;}
case 61:
#line 684 "./parse.yacc"
{
			    if ((runas_matches != -1 || pedantic) &&
				!add_alias(yyvsp[-3].string, RUNAS_ALIAS, runas_matches))
				YYERROR;
			    pop;
			    free(yyvsp[-3].string);

			    if (printmatches == TRUE)
				in_alias = FALSE;
			;
    break;}
case 64:
#line 700 "./parse.yacc"
{ push; ;
    break;}
case 65:
#line 700 "./parse.yacc"
{
			    if ((user_matches != -1 || pedantic) &&
				!add_alias(yyvsp[-3].string, USER_ALIAS, user_matches))
				YYERROR;
			    pop;
			    free(yyvsp[-3].string);
			;
    break;}
case 66:
#line 709 "./parse.yacc"
{ ; ;
    break;}
case 68:
#line 713 "./parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				user_matches = yyvsp[0].BOOLEAN;
			;
    break;}
case 69:
#line 717 "./parse.yacc"
{
			    if (yyvsp[0].BOOLEAN != -1)
				user_matches = ! yyvsp[0].BOOLEAN;
			;
    break;}
case 70:
#line 722 "./parse.yacc"
{
			    if (strcmp(yyvsp[0].string, user_name) == 0)
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 71:
#line 729 "./parse.yacc"
{
			    if (usergr_matches(yyvsp[0].string, user_name))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 72:
#line 736 "./parse.yacc"
{
			    if (netgr_matches(yyvsp[0].string, NULL, user_name))
				yyval.BOOLEAN = TRUE;
			    else
				yyval.BOOLEAN = -1;
			    free(yyvsp[0].string);
			;
    break;}
case 73:
#line 743 "./parse.yacc"
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
			;
    break;}
case 74:
#line 763 "./parse.yacc"
{
			    yyval.BOOLEAN = TRUE;
			;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 542 "/usr/local/share/bison.simple"

  yyvsp -= yylen;
  yyssp -= yylen;
#ifdef YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
  yylsp++;
  if (yylen == 0)
    {
      yylsp->first_line = yylloc.first_line;
      yylsp->first_column = yylloc.first_column;
      yylsp->last_line = (yylsp-1)->last_line;
      yylsp->last_column = (yylsp-1)->last_column;
      yylsp->text = 0;
    }
  else
    {
      yylsp->last_line = (yylsp+yylen-1)->last_line;
      yylsp->last_column = (yylsp+yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;

yyerrlab:   /* here on detecting error */

  if (! yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	  for (x = (yyn < 0 ? -yyn : 0);
	       x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (yyn < 0 ? -yyn : 0);
		       x < (sizeof(yytname) / sizeof(char *)); x++)
		    if (yycheck[x + yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      yyerror(msg);
	      free(msg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror("parse error");
    }

  goto yyerrlab1;
yyerrlab1:   /* here on error raised explicitly by an action */

  if (yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", yychar, yytname[yychar1]);
#endif

      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;

yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  yyn = yydefact[yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (yyn) goto yydefault;
#endif

yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (yyssp == yyss) YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#ifdef YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

yyerrhandle:

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;

 yyacceptlab:
  /* YYACCEPT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 0;

 yyabortlab:
  /* YYABORT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 1;
}
#line 768 "./parse.yacc"


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

    (void) puts("You may run the following commands on this host:");
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
	    (void) printf("(%s) ", RUNAS_DEFAULT);
	}

	/* Is a password required? */
	if (cm_list[i].nopasswd == TRUE && pwdef != TRUE)
	    (void) fputs("NOPASSWD: ", stdout);
	else if (cm_list[i].nopasswd == FALSE && pwdef == TRUE)
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
