%{
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
 *  If you make modifications to the source, we would be happy to have
 *  them to include in future releases.  Feel free to send them to:
 *      Jeff Nieusma                       nieusma@rootgroup.com
 *      3959 Arbol CT                      (303) 447-8093
 *      Boulder, CO 80301-1752             
 */
/*******************************************************************************
* parse.lex, sudo project
* David R. Hieb
* March 18, 1991
*
* Lex Specification file for the sudo project.
*******************************************************************************/
#include <sys/types.h>
#include <sys/param.h>
#include "sudo.h"
#include "y.tab.h"

#ifdef FLEX_SCANNER
int yylineno = 0;
#endif /* flex */
%}

%%
[ \t]+			{ ; }                     /* throw away space/tabs */
\\\n			{ 
#ifdef FLEX_SCANNER
			++yylineno
#endif /* flex */
			  ; }                     /* throw away EOL after \ */
\,			{ return ','; }           /* return ',' */
\!			{ return '!'; }           /* return '!' */
=			{ return '='; }           /* return '=' */
:			{ return ':'; }           /* return ':' */
\n			{ 
#ifdef FLEX_SCANNER
			++yylineno; 
#endif /* flex */
			  return COMMENT; }       /* return newline */
#.*\n			{ return COMMENT; }       /* return comments */
[@$%^&*()"'`/_+]*	{ return ERROR; }         /* return error */
[?;<>\[\]{}|~.-]*	{ return ERROR; }         /* return error */
^[a-zA-Z0-9_-]+		{ fill(); return IDENT1;} /* user/{Host,Cmnd}_Alias */
[a-zA-Z0-9_.+-]+	{ fill(); return IDENT2;} /* host_type/ALIASES */
(\/[a-zA-Z0-9_.+-]+)+\/? { fill(); return IDENT3;} /* absolute command path */
%%
fill() {
strcpy(yylval.char_val, yytext);
}
