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
 **************************************************************************
 *
 * parse.c, sudo project
 * David R. Hieb
 * March 18, 1991
 *
 * routines to implement and maintain the parsing and list management.
 */

#ifndef lint
static char rcsid[] = "$Id$";
#endif /* lint */

#include "config.h"

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_MALLOC_H 
#include <malloc.h>
#endif /* HAVE_MALLOC_H */ 
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "sudo.h"
#include "options.h"

/*
 * there are 3 main lists (User, Host_Alias, Cmnd_Alias) and 1 extra list
 */
#define NUM_LISTS 3+1

extern FILE *yyin, *yyout;

/*
 * Globals
 */
int user_list_found = FALSE;
int list_num, new_list[NUM_LISTS];
int parse_error = FALSE, found_user = FALSE;
int next_type, num_host_alias = 0, num_cmnd_alias = 0;
LINK tmp_ptr, reset_ptr, save_ptr, list_ptr[NUM_LISTS];


/*
 * Prototypes
 */
static int hostcmp	__P((char *));
static int cmndcmp	__P((char *, char *, char *));
static void print_cmnds	__P((void));


/*
 * inserts a node into list 'list_num' and updates list_ptr[list_num]
 */

void insert_member(list_num, token_type, op_type, data_string)
    int token_type, list_num;
    char op_type;
    char *data_string;
{
    tmp_ptr = (LINK) malloc(sizeof(LIST));
    tmp_ptr -> type = token_type;
    tmp_ptr -> op = op_type;
    tmp_ptr -> data = (char *) malloc(strlen(data_string) + 1);
    strcpy(tmp_ptr -> data, data_string);
    tmp_ptr -> next = (new_list[list_num] == TRUE) ? NULL : list_ptr[list_num];

    list_ptr[list_num] = list_ptr[EXTRA_LIST] = tmp_ptr;
}



/*
 * diagnostic list printing utility that prints list 'list_num'
 */

void print_list(list_num)
    int list_num;
{
    LINK tmptmp_ptr;

    tmptmp_ptr = list_ptr[list_num];

    while (list_ptr[list_num] != NULL) {
	(void) printf("type = %d, op = %c, data = %s\n",
	    list_ptr[list_num] -> type,
	    list_ptr[list_num] -> op, list_ptr[list_num] -> data);
	tmp_ptr = list_ptr[list_num];
	list_ptr[list_num] = tmp_ptr -> next;
    }
    list_ptr[list_num] = tmptmp_ptr;
}



/*
 * delete list utility that deletes list 'list_num'
 */

void delete_list(list_num)
    int list_num;
{
    while (list_ptr[list_num] != NULL) {
	tmp_ptr = list_ptr[list_num];
	list_ptr[list_num] = tmp_ptr -> next;
	/*  free(tmp_ptr);   */
    }
}



/*
 * this routine is what the lex/yacc code calls to build the different lists.
 * once the lists are all built, control eventually returns to validate().
 */

int call_back(token_type, op_type, data_string)
    int token_type;
    char op_type;
    char *data_string;
{
    /*
     * all nodes start out in the extra list since the node name
     * is received last
     */
    list_num = EXTRA_LIST;

    /*
     * if the last received node is TYPE1, then we can classify the list
     * and effectively transfer the extra list to the correct list type.
     */
    if (token_type == TYPE1) {
	/*
	 * we have just build a "Host_Alias" list
	 */
	if (strcmp(data_string, "Host_Alias") == 0) {
	    list_num = HOST_LIST;
	    if (num_host_alias > 0) {
		reset_ptr -> next = list_ptr[HOST_LIST];
	    }
	    num_host_alias++;
	}
	/*
	 * we have just build a "Cmnd_Alias" list
	 */
	else if (strcmp(data_string, "Cmnd_Alias") == 0) {
	    list_num = CMND_LIST;
	    if (num_cmnd_alias > 0) {
		reset_ptr -> next = list_ptr[CMND_LIST];
	    }
	    num_cmnd_alias++;
	}
	/*
	 * we have just build a "User" list
	 */
	else {
	    list_num = USER_LIST;
	    user_list_found = TRUE;
	}
	new_list[EXTRA_LIST] = TRUE;
	new_list[list_num] = FALSE;
	list_ptr[list_num] = list_ptr[EXTRA_LIST];
    }
    /*
     * actually link the new node into list 'list_num'
     */
    insert_member(list_num, token_type, op_type, data_string);

    if (new_list[list_num] == TRUE) {
	reset_ptr = list_ptr[list_num];
	new_list[list_num] = FALSE;
    }
    /*
     * we process one user record at a time from the sudoers file. if we
     * find the user were looking for, we return to lex/yacc declaring 
     * that we have done so. otherwise, we reset the user list, delete the 
     * nodes and start over again looking for the user.
     */
    if (user_list_found == TRUE) {
	if (list_ptr[list_num] -> type == TYPE1 &&
	    strcmp(list_ptr[list_num] -> data, user) == 0) {
	    return (FOUND_USER);
	} else {
	    new_list[list_num] = TRUE;
	    user_list_found = FALSE;
	    delete_list(list_num);
	}
    }
    return (NOT_FOUND_USER);
}



/*
 * this routine is called from cmnd_check() to resolve whether or not
 * a user is permitted to perform a to-yet-be-determined command for
 * a certain host name.
 */

int host_type_ok()
{
    /*
     * check for the reserved keyword 'ALL'. if so, don't check the host name
     */
    if  (strcmp(list_ptr[USER_LIST] -> data, "ALL") == 0) {
	    return (TRUE);
    }
    /*
     * this case is the normal lowercase hostname
     */
    else if (isupper(list_ptr[USER_LIST] -> data[0]) == FALSE) {
	return (hostcmp(list_ptr[USER_LIST] -> data) == 0);
    }
    /*
     * by now we have a Host_Alias that will have to be expanded
     */
    else {
	save_ptr = list_ptr[HOST_LIST];
	while (list_ptr[HOST_LIST] != NULL) {
	    if ((list_ptr[HOST_LIST] -> type == TYPE2) &&
		(strcmp(list_ptr[HOST_LIST] -> data,
			list_ptr[USER_LIST] -> data) == 0)) {
		next_type = list_ptr[HOST_LIST] -> next -> type;
		tmp_ptr = list_ptr[HOST_LIST];
		list_ptr[HOST_LIST] = tmp_ptr -> next;
		while (next_type == TYPE3) {
		    if (hostcmp(list_ptr[HOST_LIST] -> data) == 0) {
			list_ptr[HOST_LIST] = save_ptr;
			return (TRUE);
		    }
		    if (list_ptr[HOST_LIST] -> next != NULL) {
			next_type = list_ptr[HOST_LIST] -> next -> type;
			tmp_ptr = list_ptr[HOST_LIST];
			list_ptr[HOST_LIST] = tmp_ptr -> next;
		    } else {
			next_type = ~TYPE3;
		    }
		}
	    } else {
		tmp_ptr = list_ptr[HOST_LIST];
		list_ptr[HOST_LIST] = tmp_ptr -> next;
	    }
	}
	list_ptr[HOST_LIST] = save_ptr;
	return (FALSE);
    }
}



/*
 * this routine is called from cmnd_check() to resolve whether or not
 * a user is permitted to perform a certain command on the already
 * established host.
 */

int cmnd_type_ok()
{
    /*
     * always return success if the user is running the special
     * command "validate" or the user has the reserved keyword 'ALL'.
     */
    if (!strcmp(cmnd, "validate") || !strcmp(list_ptr[USER_LIST]->data, "ALL"))
	return (MATCH);

    /*
     * if the command has an absolute path, check it out
     */
    if (list_ptr[USER_LIST] -> data[0] == '/') {
	/*
	 * op  |   data   | return value
	 * --------------------------------- 
	 * ' ' | No Match | return(NO_MATCH)
	 * '!' | No Match | return(NO_MATCH)
	 * ' ' |  A Match | return(MATCH)
	 * '!' |  A Match | return(QUIT_NOW) 
	 *
	 * these special cases are important in subtracting from the Universe
	 * of commands in something like:
	 *    user machine=ALL,!/bin/rm,!/etc/named ... 
	 */

	if (cmndcmp(list_ptr[USER_LIST] -> data, cmnd, ocmnd) == 0) {
	    if (list_ptr[USER_LIST] -> op == '!')
		return (QUIT_NOW);
	    else
		return (MATCH);
	} else {
	    return (NO_MATCH);
	}
    }
    /*
     * by now we have a Cmnd_Alias that will have to be expanded
     */
    else {
	save_ptr = list_ptr[CMND_LIST];
	while (list_ptr[CMND_LIST] != NULL) {
	    if ((list_ptr[CMND_LIST] -> type == TYPE2) &&
		(strcmp(list_ptr[CMND_LIST] -> data,
			list_ptr[USER_LIST] -> data) == 0)) {
		next_type = list_ptr[CMND_LIST] -> next -> type;
		tmp_ptr = list_ptr[CMND_LIST];
		list_ptr[CMND_LIST] = tmp_ptr -> next;
		while (next_type == TYPE3) {
		    /*
		     * Match cmnd to the data (directory or file)
		     */
		    if (cmndcmp(list_ptr[CMND_LIST] -> data, cmnd, ocmnd) == 0) {
			if (list_ptr[USER_LIST] -> op == '!') {
			    list_ptr[CMND_LIST] = save_ptr;
			    return (QUIT_NOW);
			} else {
			    list_ptr[CMND_LIST] = save_ptr;
			    return (MATCH);
			}
		    }
		    if (list_ptr[CMND_LIST] -> next != NULL) {
			next_type = list_ptr[CMND_LIST] -> next -> type;
			tmp_ptr = list_ptr[CMND_LIST];
			list_ptr[CMND_LIST] = tmp_ptr -> next;
		    } else {
			next_type = ~TYPE3;
		    }
		}
	    } else {
		tmp_ptr = list_ptr[CMND_LIST];
		list_ptr[CMND_LIST] = tmp_ptr -> next;
	    }
	}
	list_ptr[CMND_LIST] = save_ptr;
	return (NO_MATCH);
    }
}



/*
 * this routine is called from cmnd_list() to print the actual commands
 * that a user is allowed or forbidden to run on the already.
 * established host.
 */

static void print_cmnds()
{
    /*
     * If we have a command or special keyword "ALL", print it out
     */
    if (list_ptr[USER_LIST] -> data[0] == '/' ||
	!strcmp(list_ptr[USER_LIST]->data, "ALL")) {
	/*
	 * print the allowed/forbidden command
	 */
	if (list_ptr[USER_LIST] -> op == '!')
	    (void) printf("forbidden: ");
	else
	    (void) printf("  allowed: ");
	(void) printf("%s\n", list_ptr[USER_LIST] -> data);
    }
    /*
     * by now we have a Cmnd_Alias that will have to be expanded
     */
    else {
	save_ptr = list_ptr[CMND_LIST];
	while (list_ptr[CMND_LIST] != NULL) {
	    if ((list_ptr[CMND_LIST] -> type == TYPE2) &&
		(strcmp(list_ptr[CMND_LIST] -> data,
			list_ptr[USER_LIST] -> data) == 0)) {
		next_type = list_ptr[CMND_LIST] -> next -> type;
		tmp_ptr = list_ptr[CMND_LIST];
		list_ptr[CMND_LIST] = tmp_ptr -> next;
		while (next_type == TYPE3) {
		    /*
		     * print the allowed/forbidden command
		     */
		    if (list_ptr[USER_LIST] -> op == '!')
			(void) printf("forbidden: ");
		    else
			(void) printf("  allowed: ");
		    (void) printf("%s\n", list_ptr[CMND_LIST] -> data);

		    if (list_ptr[CMND_LIST] -> next != NULL) {
			next_type = list_ptr[CMND_LIST] -> next -> type;
			tmp_ptr = list_ptr[CMND_LIST];
			list_ptr[CMND_LIST] = tmp_ptr -> next;
		    } else {
			next_type = ~TYPE3;
		    }
		}
	    } else {
		tmp_ptr = list_ptr[CMND_LIST];
		list_ptr[CMND_LIST] = tmp_ptr -> next;
	    }
	}
	list_ptr[CMND_LIST] = save_ptr;
    }
}



/*
 * this routine is called from validate() after the call_back() routine
 * has built all the possible lists. this routine steps thru the user list
 * calling on host_type_ok() and cmnd_type_ok() trying to resolve whether
 * or not the user will be able to execute the command on the host.
 */

int cmnd_check()
{
    int return_code;

    while (list_ptr[USER_LIST] != NULL) {
	if ((list_ptr[USER_LIST] -> type == TYPE2) && host_type_ok()) {
	    next_type = list_ptr[USER_LIST] -> next -> type;
	    tmp_ptr = list_ptr[USER_LIST];
	    list_ptr[USER_LIST] = tmp_ptr -> next;
	    while (next_type == TYPE3) {
		return_code = cmnd_type_ok();
		if (return_code == MATCH) {
		    return (VALIDATE_OK);
		} else if (return_code == QUIT_NOW) {
		    return (VALIDATE_NOT_OK);
		}
		if (list_ptr[USER_LIST] -> next != NULL) {
		    next_type = list_ptr[USER_LIST] -> next -> type;
		    tmp_ptr = list_ptr[USER_LIST];
		    list_ptr[USER_LIST] = tmp_ptr -> next;
		} else {
		    next_type = ~TYPE3;
		}
	    }
	} else {
	    tmp_ptr = list_ptr[USER_LIST];
	    list_ptr[USER_LIST] = tmp_ptr -> next;
	}
    }
    return (VALIDATE_NOT_OK);
}



/*
 * list commands for a user if got -l
 */

int cmnd_list()
{

    while (list_ptr[USER_LIST] != NULL) {
	if ((list_ptr[USER_LIST] -> type == TYPE2) && host_type_ok()) {
	    next_type = list_ptr[USER_LIST] -> next -> type;
	    tmp_ptr = list_ptr[USER_LIST];
	    list_ptr[USER_LIST] = tmp_ptr -> next;
	    while (next_type == TYPE3) {
		/* print out the available commands */
		print_cmnds();
		if (list_ptr[USER_LIST] -> next != NULL) {
		    next_type = list_ptr[USER_LIST] -> next -> type;
		    tmp_ptr = list_ptr[USER_LIST];
		    list_ptr[USER_LIST] = tmp_ptr -> next;
		} else {
		    next_type = ~TYPE3;
		}
	    }
	} else {
	    tmp_ptr = list_ptr[USER_LIST];
	    list_ptr[USER_LIST] = tmp_ptr -> next;
	}
    }
    return (VALIDATE_NOT_OK);
}



/*
 * this routine is called from the sudo.c module and tries to validate
 * the user, host and command triplet.
 */

int validate()
{
    FILE *sudoers_fp;
    int i, return_code;

    /* become owner of the sudoers file */
    set_perms(PERM_SUDOERS);

    if ((sudoers_fp = fopen(_PATH_SUDO_SUDOERS, "r")) == NULL) {
	perror(_PATH_SUDO_SUDOERS);
	log_error(NO_SUDOERS_FILE);
	exit(1);
    }
    yyin = sudoers_fp;
    yyout = stdout;

    for (i = 0; i < NUM_LISTS; i++)
	new_list[i] = TRUE;

    /*
     * yyparse() returns with one of 3 values: 0) yyparse() worked fine; 
     * 1) yyparse() failed; FOUND_USER) the user was found and yyparse()
     * was returned from prematurely.
     */
    return_code = yyparse();

    /*
     * don't need to keep this open...
     */
    (void) fclose(sudoers_fp);

    /* go back to user perms */
    set_perms(PERM_ROOT);
    set_perms(PERM_USER);

    /*
     * if a parsing error occurred, set return_code accordingly
     */
    if (parse_error == TRUE) {
	return_code = PARSE_ERROR;
    }
    /*
     * if the user was not found, set the return_code accordingly
     */
    if (found_user == FALSE) {
	return_code = NOT_FOUND_USER;
    }
    /*
     * handle the 3 cases individually
     */
    switch (return_code) {
    case FOUND_USER:
	/* do we want to list available commands or check a given command? */
	if (strcmp(cmnd, "list") == 0)
	    return_code = cmnd_list();
	else
	    return_code = cmnd_check();
	delete_list(USER_LIST);
	delete_list(HOST_LIST);
	delete_list(CMND_LIST);
	return (return_code);
	break;
    case NOT_FOUND_USER:
	return (VALIDATE_NO_USER);
	break;
    case PARSE_ERROR:
	return (VALIDATE_ERROR);
	break;
    }
}



/*
 * this routine is called from host_type_ok() and tries to match a host
 * to a host, ip address, or network based on the host and ip_addrs globals.
 */

static int hostcmp(target)
    char *target;			/* target we are matching against */
{

    /* if target an  ip address/network or a hostname? */
    if (interfaces != NULL && isdigit(*target)) {
	struct in_addr target_addr;	/* inet addr version of target */
	int i;				/* loop counter */

	/* convert target to an inet addr */
	target_addr.s_addr = inet_addr(target);

	/* now match against interfaces array. */
	for (i = 0; i < num_interfaces; i++)
	    if (target_addr.s_addr == interfaces[i].addr.s_addr ||
		target_addr.s_addr == ((interfaces[i].addr.s_addr) &
		(interfaces[i].netmask.s_addr)))
		return(0);

	return(1);
    } else {
	return(strcmp(target, host));
    }
}



/*
 * this routine is called from cmnd_type_ok() and tries to match a cmnd
 * or ocmnd to a data entry from the sudoers file.
 */

static int cmndcmp(data, cmnd, ocmnd)
    char *data;				/* data we are checking against */
    char *cmnd;				/* command the user is attempting */
    char *ocmnd;			/* unresolved version of cmnd */
{
    int len = strlen(data);
    int result;

    /*
     * If the data is a directory, match based on len, otherwise
     * do a normal strcmp(3) (must check both cmnd and ocmnd).
     */
    if (*(data + len - 1) == '/') {
	result = strncmp(data, cmnd, len);
	if (result && ocmnd)
	    result = strncmp(data, ocmnd, len);
    } else {
	result = strcmp(data, cmnd);
	if (result && ocmnd)
	    result = strcmp(data, ocmnd);
    }

    return(result);
}
