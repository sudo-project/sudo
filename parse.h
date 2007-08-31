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
    char extra;
};

/*
 * The parses sudoers file is stored as a collection of linked lists,
 * modelled after the yacc grammar.
 *
 * Other than the alias struct, which is stored in a red-black tree,
 * the data structure used is basically a doubly-linked tail queue without
 * a separate head struct--the first entry acts as the head where the prev
 * pointer does double duty as the tail pointer.  This makes it possible
 * to trivally append sub-lists.  In addition, the prev pointer is always
 * valid (even if it points to itself).  Unlike a circle queue, the next
 * pointer of the last entry is NULL and does not point back to the head.
 */

/*
 * Tail queue list head structure.
 */
struct defaults_list {
    struct defaults *first;
    struct defaults *last;
};

struct userspec_list {
    struct userspec *first;
    struct userspec *last;
};

struct member_list {
    struct member *first;
    struct member *last;
};

struct privilege_list {
    struct privilege *first;
    struct privilege *last;
};

struct cmndspec_list {
    struct cmndspec *first;
    struct cmndspec *last;
};

/*
 * Structure describing a user specification and list thereof.
 */
struct userspec {
    struct member_list users;		/* list of users */
    struct privilege_list privileges;	/* list of privileges */
    struct userspec *prev, *next;
};

/*
 * Structure describing a privilege specification.
 */
struct privilege {
    struct member_list hostlist;	/* list of hosts */
    struct cmndspec_list cmndlist;	/* list of Cmnd_Specs */
    struct privilege *prev, *next;
};

/*
 * Structure describing a linked list of Cmnd_Specs.
 */
struct cmndspec {
    struct member_list runaslist;	/* list of runas users */
    struct member *cmnd;		/* command to allow/deny */
    struct cmndtag tags;		/* tag specificaion */
    struct cmndspec *prev, *next;
};

/*
 * Generic structure to hold users, hosts, commands.
 */
struct member {
    char *name;				/* member name */
    short type;				/* type (see gram.h) */
    short negated;			/* negated via '!'? */
    struct member *prev, *next;
};

/*
 * Generic structure to hold {User,Host,Runas,Cmnd}_Alias
 * Aliases are stored in a red-black tree, sorted by name and type.
 */
struct alias {
    char *name;				/* alias name */
    int type; 				/* {USER,HOST,RUNAS,CMND}ALIAS */
    struct member_list members;		/* list of alias members */
};

/*
 * Structure describing a Defaults entry and a list thereof.
 */
struct defaults {
    char *var;				/* variable name */
    char *val;				/* variable value */
    struct member_list binding;		/* user/host/runas binding */
    int type;				/* DEFAULTS{,_USER,_RUNAS,_HOST} */
    int op;				/* TRUE, FALSE, '+', '-' */
    struct defaults *prev, *next;
};

/*
 * Append one queue (or single entry) to another using the
 * circular properties of the prev pointer to simplify the logic.
 */
#undef LIST_APPEND
#define LIST_APPEND(h, e) do {				\
    void *_tail = (e)->prev;				\
    (h)->prev->next = (e);				\
    (e)->prev = (h)->prev;				\
    (h)->prev = _tail;					\
} while (0)

/*
 * Append the list of entries to the head node and convert
 * e from a semi-circle queue to normal doubly-linked list.
 */
#undef HEAD_APPEND
#define HEAD_APPEND(h, e) do {				\
    void *_tail = (e)->prev;				\
    if ((h).first == NULL)				\
	(h).first = (e);				\
    else						\
	(h).last->next = (e);				\
    (e)->prev = (h).last;				\
    (h).last = _tail;					\
} while (0)

/*
 * Convert from a semi-circle queue to normal doubly-linked list
 * with a head node.
 */
#undef LIST2HEAD
#define LIST2HEAD(h, e) do {				\
    if ((e) != NULL) {					\
	(h).first = (e);				\
	(h).last = (e)->prev;				\
	(e)->prev = NULL;				\
    } else {						\
	(h).first = NULL;				\
	(h).last = NULL;				\
    }							\
} while (0)

#undef LH_FOREACH_FWD
#define LH_FOREACH_FWD(h, v)				\
    for ((v) = (h)->first; (v) != NULL; (v) = (v)->next)

#undef LH_FOREACH_REV
#define LH_FOREACH_REV(h, v)				\
    for ((v) = (h)->last; (v) != NULL; (v) = (v)->prev)

/*
 * Pop the last element off the end of h.
 * XXX - really should return the popped element.
 */
#undef LH_POP
#define LH_POP(h) do {					\
    if (!LH_EMPTY(h)) {					\
	if ((h)->first == (h)->last)			\
	    (h)->first = (h)->last = NULL;		\
	else {						\
	    (h)->last = (h)->last->prev;		\
	    (h)->last->next = NULL;			\
	}						\
    }							\
} while (0)

#undef LH_INIT
#define LH_INIT(h) do {					\
    (h)->first = NULL;					\
    (h)->last = NULL;					\
} while (0)

#undef LH_EMPTY
#define LH_EMPTY(h)	((h)->first == NULL)

#undef LH_FIRST
#define LH_FIRST(h)	((h)->first)

#undef LH_LAST
#define LH_LAST(h)	((h)->last)

#undef LIST_NEXT
#define LIST_NEXT(e)	((e)->next)

#undef LIST_PREV
#define LIST_PREV(e)	((e)->prev)

/*
 * Parsed sudoers info.
 */
extern struct userspec_list userspecs;
extern struct defaults_list defaults;

/*
 * Prototypes
 */
char *alias_add		__P((char *, int, struct member *));
int addr_matches	__P((char *));
int alias_remove	__P((char *, int));
int cmnd_matches	__P((struct member *));
int cmndlist_matches	__P((struct member_list *));
int command_matches	__P((char *, char *));
int hostlist_matches	__P((struct member_list *));
int hostname_matches	__P((char *, char *, char *));
int netgr_matches	__P((char *, char *, char *, char *));
int no_aliases		__P((void));
int runaslist_matches	__P((struct member_list *));
int userlist_matches	__P((struct passwd *, struct member_list *));
int usergr_matches	__P((char *, char *, struct passwd *));
int userpw_matches	__P((char *, char *, struct passwd *));
struct alias *find_alias __P((char *, int));
void alias_apply	__P((int (*)(VOID *, VOID *), VOID *));
void init_aliases	__P((void));
void init_parser	__P((char *, int));

#endif /* _SUDO_PARSE_H */
