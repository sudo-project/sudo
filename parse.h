/*
 * Copyright (c) 1996, 1998-2000, 2004, 2007
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
 * $Sudo$
 */

#ifndef _SUDO_PARSE_H
#define _SUDO_PARSE_H

#undef ALLOW
#define ALLOW	1
#undef DENY
#define DENY	0
#undef UNSPEC
#define UNSPEC	-1
/* XXX - use NOTFOUND instead? */

/*
 * A command with args. XXX - merge into struct member.
 */
struct sudo_command {
    char *cmnd;
    char *args;
};

/*
 * Tags associated with a command.
 * Possible valus: TRUE, FALSE, UNSPEC.
 */
struct cmndtag {
    char nopasswd;
    char noexec;
    char setenv;
    char monitor;
    char extra;
};

/*
 * The parses sudoers file is stored as a collection of linked lists,
 * modelled after the yacc grammar.
 *
 * Other than the alias struct, which is stored in a red-black tree,
 * the data structure used is basically a tail queue without a separate
 * head struct--the first entry acts as the head.  This makes it possible
 * to trivally append sub-lists.  Note, however, that the "last" field is
 * only valid in the first entry (the list head).
 */

/*
 * Structure describing a user specification and list thereof.
 */
struct userspec {
    struct member *user;		/* list of users */
    struct privilege *privileges;	/* list of privileges */
    struct userspec *last, *next;
};

/*
 * Structure describing a privilege specification.
 */
struct privilege {
    struct member *hostlist;		/* list of hosts */
    struct cmndspec *cmndlist;		/* list of Cmnd_Specs */
    struct privilege *last, *next;
};

/*
 * Structure describing a linked list of Cmnd_Specs.
 */
struct cmndspec {
    struct member *runaslist;		/* list of runas users */
    struct member *cmnd;		/* command to allow/deny */
    struct cmndtag tags;		/* tag specificaion */
    struct cmndspec *last, *next;
};

/*
 * Generic structure to hold users, hosts, commands.
 */
struct member {
    char *name;				/* member name */
    short type;				/* type (see gram.h) */
    short negated;			/* negated via '!'? */
    struct member *last, *next;
};

/*
 * Generic structure to hold {User,Host,Runas,Cmnd}_Alias
 * Aliases are stored in a red-black tree, sorted by name and type.
 */
struct alias {
    char *name;				/* alias name */
    int type; 				/* {USER,HOST,RUNAS,CMND}ALIAS */
    struct member *first_member;	/* list of alias members */
};

/*
 * Structure describing a Defaults entry and a list thereof.
 */
struct defaults {
    char *var;				/* variable name */
    char *val;				/* variable value */
    struct member *binding;		/* user/host/runas binding */
    int type;				/* DEFAULTS{,_USER,_RUNAS,_HOST} */
    int op;				/* TRUE, FALSE, '+', '-' */
    struct defaults *last, *next;
};

/*
 * Allocate space for a defaults entry and populate it.
 */
#define NEW_DEFAULT(r, v1, v2, o) do {			\
    (r)       = emalloc(sizeof(struct defaults));	\
    (r)->var  = (v1);					\
    (r)->val  = (v2);					\
    (r)->op   = (o);					\
    (r)->last = NULL;					\
    (r)->next = NULL;					\
} while (0)

/*
 * Allocate space for a member and populate it.
 */
#define NEW_MEMBER(r, n, t) do {			\
    (r)       = emalloc(sizeof(struct member));		\
    (r)->name = (n);					\
    (r)->type = (t);					\
    (r)->last = NULL;					\
    (r)->next = NULL;					\
} while (0)

/*
 * Append a list (or single entry) to a tail queue.
 */
#define LIST_APPEND(h, e) do {				\
    if ((h)->last != NULL)				\
	(h)->last->next = (e);				\
    else /* if ((h)->next == NULL) */			\
	(h)->next = (e);				\
    (h)->last = (e);					\
    (h)->last = (e)->last ? (e)->last : (e);		\
} while (0)

/*
 * Prototypes
 */
char *alias_add		__P((char *, int, struct member *));
int addr_matches	__P((char *));
int alias_remove	__P((char *, int));
int cmnd_matches	__P((struct member *));
int command_matches	__P((char *, char *));
int host_matches	__P((struct member *));
int hostname_matches	__P((char *, char *, char *));
int netgr_matches	__P((char *, char *, char *, char *));
int no_aliases		__P((void));
int runas_matches	__P((struct member *));
int user_matches	__P((struct passwd *, struct member *));
int usergr_matches	__P((char *, char *, struct passwd *));
int userpw_matches	__P((char *, char *, struct passwd *));
struct alias *find_alias __P((char *, int));
void alias_apply	__P((int (*)(VOID *, VOID *), VOID *));
void init_aliases	__P((void));
void init_parser	__P((char *, int));

#endif /* _SUDO_PARSE_H */
