/*
 * Copyright (c) 1996, 1998-2000, 2004, 2007-2015
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
 */

#ifndef SUDOERS_PARSE_H
#define SUDOERS_PARSE_H

#undef UNSPEC
#define UNSPEC	-1
#undef DENY
#define DENY	 0
#undef ALLOW
#define ALLOW	 1
#undef IMPLIED
#define IMPLIED	 2

/*
 * Initialize all tags to UNSPEC.
 */
#define TAGS_INIT(t)	do {						       \
    (t).follow = UNSPEC;						       \
    (t).log_input = UNSPEC;						       \
    (t).log_output = UNSPEC;						       \
    (t).noexec = UNSPEC;						       \
    (t).nopasswd = UNSPEC;						       \
    (t).send_mail = UNSPEC;						       \
    (t).setenv = UNSPEC;						       \
} while (0)

/*
 * Returns true if any tag are not UNSPEC, else false.
 */
#define TAGS_SET(t)							       \
    ((t).follow != UNSPEC || (t).log_input != UNSPEC ||			       \
     (t).log_output != UNSPEC || (t).noexec != UNSPEC ||		       \
     (t).nopasswd != UNSPEC || (t).send_mail != UNSPEC ||		       \
     (t).setenv != UNSPEC)

/*
 * Returns true if the specified tag is not UNSPEC or IMPLIED, else false.
 */
#define TAG_SET(tt) \
    ((tt) != UNSPEC && (tt) != IMPLIED)

/*
 * Returns true if any tags set in nt differ between ot and nt, else false.
 */
#define TAGS_CHANGED(ot, nt) \
    ((TAG_SET((nt).follow) && (nt).follow != (ot).follow) || \
    (TAG_SET((nt).log_input) && (nt).log_input != (ot).log_input) || \
    (TAG_SET((nt).log_output) && (nt).log_output != (ot).log_output) || \
    (TAG_SET((nt).noexec) && (nt).noexec != (ot).noexec) || \
    (TAG_SET((nt).nopasswd) && (nt).nopasswd != (ot).nopasswd) || \
    (TAG_SET((nt).setenv) && (nt).setenv != (ot).setenv) || \
    (TAG_SET((nt).send_mail) && (nt).send_mail != (ot).send_mail))

/*
 * Returns true if the runas user and group lists match, else false.
 */
#define RUNAS_CHANGED(cs1, cs2) \
     ((cs1)->runasuserlist != (cs2)->runasuserlist || \
     (cs1)->runasgrouplist != (cs2)->runasgrouplist)

#define SUDO_DIGEST_SHA224	0
#define SUDO_DIGEST_SHA256	1
#define SUDO_DIGEST_SHA384	2
#define SUDO_DIGEST_SHA512	3
#define SUDO_DIGEST_INVALID	4

struct sudo_digest {
    unsigned int digest_type;
    char *digest_str;
};

/*
 * A command with option args and digest.
 * XXX - merge into struct member
 */
struct sudo_command {
    char *cmnd;
    char *args;
    struct sudo_digest *digest;
};

/*
 * Tags associated with a command.
 * Possible values: true, false, IMPLIED, UNSPEC.
 */
struct cmndtag {
    signed int nopasswd: 3;
    signed int noexec: 3;
    signed int setenv: 3;
    signed int log_input: 3;
    signed int log_output: 3;
    signed int send_mail: 3;
    signed int follow: 3;
};

/*
 * SELinux-specific container struct.
 * Currently just contains a role and type.
 */
struct selinux_info {
    char *role;
    char *type;
};

/*
 * Solaris privileges container struct
 * Currently just contains permitted and limit privileges.
 * It could have PFEXEC and PRIV_AWARE flags added in the future.
 */
struct solaris_privs_info {
    char *privs;
    char *limitprivs;
};

/*
 * The parsed sudoers file is stored as a collection of linked lists,
 * modelled after the yacc grammar.
 *
 * Other than the alias struct, which is stored in a red-black tree,
 * the data structure used is a doubly-linked tail queue.  While sudoers
 * is being parsed, a headless tail queue is used where the first entry
 * acts as the head and the prev pointer does double duty as the tail pointer.
 * This makes it possible to trivally append sub-lists.  In addition, the prev
 * pointer is always valid (even if it points to itself).  Unlike a circle
 * queue, the next pointer of the last entry is NULL and does not point back
 * to the head.  When the tail queue is finalized, it is converted to a
 * normal BSD tail queue.
 */

/*
 * Tail queue list head structure.
 */
TAILQ_HEAD(defaults_list, defaults);
TAILQ_HEAD(userspec_list, userspec);
TAILQ_HEAD(member_list, member);
TAILQ_HEAD(privilege_list, privilege);
TAILQ_HEAD(cmndspec_list, cmndspec);

/*
 * Structure describing a user specification and list thereof.
 */
struct userspec {
    TAILQ_ENTRY(userspec) entries;
    struct member_list users;		/* list of users */
    struct privilege_list privileges;	/* list of privileges */
};

/*
 * Structure describing a privilege specification.
 */
struct privilege {
    TAILQ_ENTRY(privilege) entries;
    struct member_list hostlist;	/* list of hosts */
    struct cmndspec_list cmndlist;	/* list of Cmnd_Specs */
};

/*
 * Structure describing a linked list of Cmnd_Specs.
 */
struct cmndspec {
    TAILQ_ENTRY(cmndspec) entries;
    struct member_list *runasuserlist;	/* list of runas users */
    struct member_list *runasgrouplist;	/* list of runas groups */
    struct member *cmnd;		/* command to allow/deny */
    struct cmndtag tags;		/* tag specificaion */
#ifdef HAVE_SELINUX
    char *role, *type;			/* SELinux role and type */
#endif
#ifdef HAVE_PRIV_SET
    char *privs, *limitprivs;		/* Solaris privilege sets */
#endif
};

/*
 * Generic structure to hold users, hosts, commands.
 */
struct member {
    TAILQ_ENTRY(member) entries;
    char *name;				/* member name */
    short type;				/* type (see gram.h) */
    short negated;			/* negated via '!'? */
};

struct runascontainer {
    struct member *runasusers;
    struct member *runasgroups;
};

/*
 * Generic structure to hold {User,Host,Runas,Cmnd}_Alias
 * Aliases are stored in a red-black tree, sorted by name and type.
 */
struct alias {
    char *name;				/* alias name */
    unsigned short type;		/* {USER,HOST,RUNAS,CMND}ALIAS */
    bool used;				/* "used" flag for cycle detection */
    struct member_list members;		/* list of alias members */
};

/*
 * Structure describing a Defaults entry and a list thereof.
 */
struct defaults {
    TAILQ_ENTRY(defaults) entries;
    char *var;				/* variable name */
    char *val;				/* variable value */
    struct member_list *binding;	/* user/host/runas binding */
    int type;				/* DEFAULTS{,_USER,_RUNAS,_HOST} */
    int op;				/* true, false, '+', '-' */
};

/*
 * Parsed sudoers info.
 */
extern struct userspec_list userspecs;
extern struct defaults_list defaults;

/* alias.c */
bool no_aliases(void);
const char *alias_add(char *name, int type, struct member *members);
int alias_compare(const void *a1, const void *a2);
struct alias *alias_get(char *name, int type);
struct alias *alias_remove(char *name, int type);
void alias_apply(int (*func)(void *, void *), void *cookie);
void alias_free(void *a);
void alias_put(struct alias *a);
bool init_aliases(void);

/* gram.c */
bool init_parser(const char *, bool);

/* match_addr.c */
bool addr_matches(char *n);

/* match.c */
bool command_matches(const char *sudoers_cmnd, const char *sudoers_args, const struct sudo_digest *digest);
bool group_matches(const char *sudoers_group, const struct group *gr);
bool hostname_matches(const char *shost, const char *lhost, const char *pattern);
bool netgr_matches(const char *netgr, const char *lhost, const char *shost, const char *user);
bool usergr_matches(const char *group, const char *user, const struct passwd *pw);
bool userpw_matches(const char *sudoers_user, const char *user, const struct passwd *pw);
int cmnd_matches(const struct member *m);
int cmndlist_matches(const struct member_list *list);
int hostlist_matches(const struct passwd *pw, const struct member_list *list);
int runaslist_matches(const struct member_list *user_list, const struct member_list *group_list, struct member **matching_user, struct member **matching_group);
int userlist_matches(const struct passwd *pw, const struct member_list *list);
const char *sudo_getdomainname(void);

/* toke.c */
void init_lexer(void);

/* hexchar.c */
int hexchar(const char *s);

/* base64.c */
size_t base64_decode(const char *str, unsigned char *dst, size_t dsize);

#endif /* SUDOERS_PARSE_H */
