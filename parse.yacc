%{
/*
 * CU sudo version 1.3.1 (based on Root Group sudo version 1.1)
 *
 * This software comes with no waranty whatsoever, use at your own risk.
 *
 * Please send bugs, changes, problems to sudo-bugs@cs.colorado.edu
 *
 */

/*
 *  sudo version 1.1 allows users to execute commands as root
 *  Copyright (C) 1991  The Root Group, Inc.
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
 */
/*******************************************************************************
* parse.yacc, sudo project
* David R. Hieb
* March 18, 1991
*
* Yacc Specification file for the sudo project.
*******************************************************************************/

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include "sudo.h"

extern int sudolineno;
extern int parse_error, found_user;

yyerror(s)
char *s;
{
fprintf(stderr, ">>> sudoers file: %s, line %d <<<\n", s, sudolineno);
parse_error = TRUE;
}

yywrap()
{
return(1);
}
%}

%start file				/* special start symbol */
%token <char_val> IDENT1		/* identifier type 1*/
%token <char_val> IDENT2		/* identifier type 2*/
%token <char_val> IDENT3		/* identifier type 3*/
%token <int_val>  COMMENT		/* comment and/or carriage return */
%token <int_val>  ERROR			/* error character(s) */
%token <int_val> ':' '=' ',' '!'	/* union member tokens */
%%
file		:	entry
		|	file entry
		;

entry		:	COMMENT
			{ ; }
                |       error COMMENT
			{ yyerrok; }
		|	IDENT1 access_series COMMENT
			{ if (call_back(TYPE1, ' ', $1) == FOUND_USER) {
				found_user = TRUE;
				return(FOUND_USER);
				}
			  else {
				found_user = FALSE;
				} }
		;

access_series	:	access_group
		|	access_series ':' access_group
		;

access_group	:	IDENT2 '=' cmnd_list
			{ call_back(TYPE2, ' ', $1); }
		;

cmnd_list	:	cmnd_type
		|	cmnd_list ',' cmnd_type
		;

cmnd_type	:	IDENT3
			{ call_back(TYPE3, ' ', $1); }
		|	'!' IDENT3
			{ call_back(TYPE3, '!', $2); }
		|	IDENT2
			{ call_back(TYPE3, ' ', $1); }
		|	'!' IDENT2
			{ call_back(TYPE3, '!', $2); }
		;
%%
