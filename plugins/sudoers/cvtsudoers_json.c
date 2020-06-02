/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>

#include "sudoers.h"
#include "sudo_json.h"
#include "cvtsudoers.h"
#include <gram.h>

/*
 * Closure used to store state when iterating over all aliases.
 */
struct json_alias_closure {
    struct json_container *json;
    const char *title;
    unsigned int count;
    int alias_type;
};

/*
 * Type values used to disambiguate the generic WORD and ALIAS types.
 */
enum word_type {
    TYPE_COMMAND,
    TYPE_HOSTNAME,
    TYPE_RUNASGROUP,
    TYPE_RUNASUSER,
    TYPE_USERNAME
};

/*
 * Print sudo command member in JSON format, with correct indentation.
 */
static void
print_command_json(struct json_container *json, const char *name, bool negated)
{
    struct sudo_command *c = (struct sudo_command *)name;
    struct command_digest *digest;
    struct json_value value;
    char *cmnd = c->cmnd;
    const char *digest_name;
    debug_decl(print_command_json, SUDOERS_DEBUG_UTIL);

    /* Print command with optional command line args. */
    if (c->args != NULL) {
	if (asprintf(&cmnd, "%s %s", c->cmnd, c->args) == -1) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
    }
    value.type = JSON_STRING;
    value.u.string = cmnd ? cmnd : "ALL";

    if (!negated && TAILQ_EMPTY(&c->digests)) {
	/* Print as { "command": "command and args" } */
	sudo_json_add_value_as_object(json, "command", &value);
    } else {
	/* Print as multi-line object. */
	sudo_json_open_object(json, NULL);
	sudo_json_add_value(json, "command", &value);

	/* Optional digest list. */
	TAILQ_FOREACH(digest, &c->digests, entries) {
	    digest_name = digest_type_to_name(digest->digest_type);
	    value.type = JSON_STRING;
	    value.u.string = digest->digest_str;
	    sudo_json_add_value(json, digest_name, &value);
	}

	/* Command may be negated. */
	if (negated) {
	    value.type = JSON_BOOL;
	    value.u.boolean = true;
	    sudo_json_add_value(json, "negated", &value);
	}

	sudo_json_close_object(json);
    }

    if (cmnd != c->cmnd)
	free(cmnd);

    debug_return;
}

/*
 * Map an alias type to enum word_type.
 */
static enum word_type
alias_to_word_type(int alias_type)
{
    switch (alias_type) {
    case CMNDALIAS:
	return TYPE_COMMAND;
    case HOSTALIAS:
	return TYPE_HOSTNAME;
    case RUNASALIAS:
	return TYPE_RUNASUSER;
    case USERALIAS:
	return TYPE_USERNAME;
    default:
	sudo_fatalx_nodebug("unexpected alias type %d", alias_type);
    }
}

/*
 * Map a Defaults type to enum word_type.
 */
static enum word_type
defaults_to_word_type(int defaults_type)
{
    switch (defaults_type) {
    case DEFAULTS_CMND:
	return TYPE_COMMAND;
    case DEFAULTS_HOST:
	return TYPE_HOSTNAME;
    case DEFAULTS_RUNAS:
	return TYPE_RUNASUSER;
    case DEFAULTS_USER:
	return TYPE_USERNAME;
    default:
	sudo_fatalx_nodebug("unexpected defaults type %d", defaults_type);
    }
}

/*
 * Print struct member in JSON format, with correct indentation.
 */
static void
print_member_json_int(struct json_container *json,
    struct sudoers_parse_tree *parse_tree, char *name, int type, bool negated,
    enum word_type word_type, bool expand_aliases)
{
    struct json_value value;
    const char *typestr = NULL;
    const char *errstr;
    int alias_type = UNSPEC;
    id_t id;
    debug_decl(print_member_json_int, SUDOERS_DEBUG_UTIL);

    /* Most of the time we print a string. */
    value.type = JSON_STRING;
    switch (type) {
    case ALL:
	if (name == NULL) {
	    value.u.string = "ALL";
	} else {
	    /* ALL used with digest, print as a command. */
	    type = COMMAND;
	}
	break;
    case MYSELF:
	value.u.string = "";
	break;
    default:
	if (name == NULL)
	    sudo_fatalx("missing member name for type %d", type);
	value.u.string = name;
    }

    switch (type) {
    case USERGROUP:
	value.u.string++; /* skip leading '%' */
	if (*value.u.string == ':') {
	    value.u.string++;
	    typestr = "nonunixgroup";
	    if (*value.u.string == '#') {
		id = sudo_strtoid(value.u.string + 1, &errstr);
		if (errstr != NULL) {
		    sudo_warnx("internal error: non-Unix group-ID %s: \"%s\"",
			errstr, value.u.string + 1);
		} else {
		    value.type = JSON_ID;
		    value.u.id = id;
		    typestr = "nonunixgid";
		}
	    }
	} else {
	    typestr = "usergroup";
	    if (*value.u.string == '#') {
		id = sudo_strtoid(value.u.string + 1, &errstr);
		if (errstr != NULL) {
		    sudo_warnx("internal error: group-ID %s: \"%s\"",
			errstr, value.u.string + 1);
		} else {
		    value.type = JSON_ID;
		    value.u.id = id;
		    typestr = "usergid";
		}
	    }
	}
	break;
    case NETGROUP:
	typestr = "netgroup";
	value.u.string++; /* skip leading '+' */
	break;
    case NTWKADDR:
	typestr = "networkaddr";
	break;
    case COMMAND:
	print_command_json(json, name, negated);
	debug_return;
    case ALL:
    case MYSELF:
    case WORD:
	switch (word_type) {
	case TYPE_COMMAND:
	    typestr = "command";
	    break;
	case TYPE_HOSTNAME:
	    typestr = "hostname";
	    break;
	case TYPE_RUNASGROUP:
	    typestr = "usergroup";
	    break;
	case TYPE_RUNASUSER:
	case TYPE_USERNAME:
	    typestr = "username";
	    if (*value.u.string == '#') {
		id = sudo_strtoid(value.u.string + 1, &errstr);
		if (errstr != NULL) {
		    sudo_warnx("internal error: user-ID %s: \"%s\"",
			errstr, name);
		} else {
		    value.type = JSON_ID;
		    value.u.id = id;
		    typestr = "userid";
		}
	    }
	    break;
	default:
	    sudo_fatalx("unexpected word type %d", word_type);
	}
	break;
    case ALIAS:
	switch (word_type) {
	case TYPE_COMMAND:
	    if (expand_aliases) {
		alias_type = CMNDALIAS;
	    } else {
		typestr = "cmndalias";
	    }
	    break;
	case TYPE_HOSTNAME:
	    if (expand_aliases) {
		alias_type = HOSTALIAS;
	    } else {
		typestr = "hostalias";
	    }
	    break;
	case TYPE_RUNASGROUP:
	case TYPE_RUNASUSER:
	    if (expand_aliases) {
		alias_type = RUNASALIAS;
	    } else {
		typestr = "runasalias";
	    }
	    break;
	case TYPE_USERNAME:
	    if (expand_aliases) {
		alias_type = USERALIAS;
	    } else {
		typestr = "useralias";
	    }
	    break;
	default:
	    sudo_fatalx("unexpected word type %d", word_type);
	}
	break;
    default:
	sudo_fatalx("unexpected member type %d", type);
    }

    if (expand_aliases && type == ALIAS) {
	struct alias *a;
	struct member *m;

	/* Print each member of the alias. */
	if ((a = alias_get(parse_tree, value.u.string, alias_type)) != NULL) {
	    TAILQ_FOREACH(m, &a->members, entries) {
		print_member_json_int(json, parse_tree, m->name, m->type,
		    negated ? !m->negated : m->negated,
		    alias_to_word_type(alias_type), true);
	    }
	    alias_put(a);
	}
    } else {
	if (negated) {
	    sudo_json_open_object(json, NULL);
	    sudo_json_add_value(json, typestr, &value);
	    value.type = JSON_BOOL;
	    value.u.boolean = true;
	    sudo_json_add_value(json, "negated", &value);
	    sudo_json_close_object(json);
	} else {
	    sudo_json_add_value_as_object(json, typestr, &value);
	}
    }

    debug_return;
}

static void
print_member_json(struct json_container *json,
    struct sudoers_parse_tree *parse_tree, struct member *m,
    enum word_type word_type, bool expand_aliases)
{
    print_member_json_int(json, parse_tree, m->name, m->type, m->negated,
	word_type, expand_aliases);
}

/*
 * Callback for alias_apply() to print an alias entry if it matches
 * the type specified in the closure.
 */
static int
print_alias_json(struct sudoers_parse_tree *parse_tree, struct alias *a, void *v)
{
    struct json_alias_closure *closure = v;
    struct member *m;
    debug_decl(print_alias_json, SUDOERS_DEBUG_UTIL);

    if (a->type != closure->alias_type)
	debug_return_int(0);

    /* Open the aliases object or close the last entry, then open new one. */
    if (closure->count++ == 0) {
	sudo_json_open_object(closure->json, closure->title);
    } else {
	sudo_json_close_array(closure->json);
    }
    sudo_json_open_array(closure->json, a->name);

    TAILQ_FOREACH(m, &a->members, entries) {
	print_member_json(closure->json, parse_tree, m,
	    alias_to_word_type(closure->alias_type), false);
    }
    debug_return_int(0);
}

/*
 * Print the binding for a Defaults entry of the specified type.
 */
static void
print_binding_json(struct json_container *json,
    struct sudoers_parse_tree *parse_tree, struct member_list *binding,
    int type, bool expand_aliases)
{
    struct member *m;
    debug_decl(print_binding_json, SUDOERS_DEBUG_UTIL);

    if (TAILQ_EMPTY(binding))
	debug_return;

    /* Print each member object in binding. */
    sudo_json_open_array(json, "Binding");
    TAILQ_FOREACH(m, binding, entries) {
	print_member_json(json, parse_tree, m, defaults_to_word_type(type),
	     expand_aliases);
    }
    sudo_json_close_array(json);

    debug_return;
}

/*
 * Print a Defaults list JSON format.
 */
static void
print_defaults_list_json(struct json_container *json, struct defaults *def)
{
    char savech, *start, *end = def->val;
    struct json_value value;
    debug_decl(print_defaults_list_json, SUDOERS_DEBUG_UTIL);

    sudo_json_open_object(json, NULL);
    value.type = JSON_STRING;
    switch (def->op) {
    case '+':
	value.u.string = "list_add";
	break;
    case '-':
	value.u.string = "list_remove";
	break;
    case true:
	value.u.string = "list_assign";
	break;
    default:
	sudo_warnx("internal error: unexpected list op %d", def->op);
	value.u.string = "unsupported";
	break;
    }
    sudo_json_add_value(json, "operation", &value);
    sudo_json_open_array(json, def->var);
    /* Split value into multiple space-separated words. */
    do {
	/* Remove leading blanks, must have a non-empty string. */
	for (start = end; isblank((unsigned char)*start); start++)
	    continue;
	if (*start == '\0')
	    break;

	/* Find the end and print it. */
	for (end = start; *end && !isblank((unsigned char)*end); end++)
	    continue;
	savech = *end;
	*end = '\0';
	value.type = JSON_STRING;
	value.u.string = start;
	sudo_json_add_value(json, NULL, &value);
	*end = savech;
    } while (*end++ != '\0');
    sudo_json_close_array(json);
    sudo_json_close_object(json);

    debug_return;
}

static int
get_defaults_type(struct defaults *def)
{
    struct sudo_defs_types *cur;

    /* Look up def in table to find its type. */
    for (cur = sudo_defs_table; cur->name; cur++) {
	if (strcmp(def->var, cur->name) == 0)
	    return cur->type;
    }
    return -1;
}

/*
 * Export all Defaults in JSON format.
 */
static void
print_defaults_json(struct json_container *json,
    struct sudoers_parse_tree *parse_tree, bool expand_aliases)
{
    struct json_value value;
    struct defaults *def, *next;
    int type;
    debug_decl(print_defaults_json, SUDOERS_DEBUG_UTIL);

    if (TAILQ_EMPTY(&parse_tree->defaults))
	debug_return;

    sudo_json_open_array(json, "Defaults");

    TAILQ_FOREACH_SAFE(def, &parse_tree->defaults, entries, next) {
	type = get_defaults_type(def);
	if (type == -1) {
	    sudo_warnx(U_("unknown defaults entry \"%s\""), def->var);
	    /* XXX - just pass it through as a string anyway? */
	    continue;
	}

	/* Found it, print object container and binding (if any). */
	sudo_json_open_object(json, NULL);
	print_binding_json(json, parse_tree, def->binding, def->type,
	    expand_aliases);

	/* Validation checks. */
	/* XXX - validate values in addition to names? */

	/* Print options, merging ones with the same binding. */
	sudo_json_open_array(json, "Options");
	for (;;) {
	    next = TAILQ_NEXT(def, entries);
	    /* XXX - need to update cur too */
	    if ((type & T_MASK) == T_FLAG || def->val == NULL) {
		value.type = JSON_BOOL;
		value.u.boolean = def->op;
		sudo_json_add_value_as_object(json, def->var, &value);
	    } else if ((type & T_MASK) == T_LIST) {
		print_defaults_list_json(json, def);
	    } else {
		value.type = JSON_STRING;
		value.u.string = def->val;
		sudo_json_add_value_as_object(json, def->var, &value);
	    }
	    if (next == NULL || def->binding != next->binding)
		break;
	    def = next;
	    type = get_defaults_type(def);
	    if (type == -1) {
		sudo_warnx(U_("unknown defaults entry \"%s\""), def->var);
		/* XXX - just pass it through as a string anyway? */
		break;
	    }
	}
	sudo_json_close_array(json);
	sudo_json_close_object(json);
    }

    /* Close Defaults array; comma (if any) & newline will be printer later. */
    sudo_json_close_array(json);

    debug_return;
}

/*
 * Export all aliases of the specified type in JSON format.
 * Iterates through the entire aliases tree.
 */
static void
print_aliases_by_type_json(struct json_container *json,
    struct sudoers_parse_tree *parse_tree, int alias_type, const char *title)
{
    struct json_alias_closure closure;
    debug_decl(print_aliases_by_type_json, SUDOERS_DEBUG_UTIL);

    closure.json = json;
    closure.count = 0;
    closure.alias_type = alias_type;
    closure.title = title;
    alias_apply(parse_tree, print_alias_json, &closure);
    if (closure.count != 0) {
	sudo_json_close_array(json);
	sudo_json_close_object(json);
    }

    debug_return;
}

/*
 * Export all aliases in JSON format.
 */
static void
print_aliases_json(struct json_container *json,
    struct sudoers_parse_tree *parse_tree)
{
    debug_decl(print_aliases_json, SUDOERS_DEBUG_UTIL);

    print_aliases_by_type_json(json, parse_tree, USERALIAS, "User_Aliases");
    print_aliases_by_type_json(json, parse_tree, RUNASALIAS, "Runas_Aliases");
    print_aliases_by_type_json(json, parse_tree, HOSTALIAS, "Host_Aliases");
    print_aliases_by_type_json(json, parse_tree, CMNDALIAS, "Command_Aliases");

    debug_return;
}

/* Does the next entry differ only in the command itself? */
static bool
cmndspec_continues(struct cmndspec *cs, struct cmndspec *next)
{
    bool ret = next != NULL &&
	!RUNAS_CHANGED(cs, next) && !TAGS_CHANGED(cs->tags, next->tags)
#ifdef HAVE_PRIV_SET
	&& cs->privs == next->privs && cs->limitprivs == next->limitprivs
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
	&& cs->role == next->role && cs->type == next->type
#endif /* HAVE_SELINUX */
	;
    return ret;
}

/*
 * Print a Cmnd_Spec in JSON format at the correct indent level.
 * A pointer to the next Cmnd_Spec is passed in to make it possible to
 * merge adjacent entries that are identical in all but the command.
 */
static void
print_cmndspec_json(struct json_container *json,
    struct sudoers_parse_tree *parse_tree, struct cmndspec *cs,
    struct cmndspec **nextp, struct defaults_list *options, bool expand_aliases)
{
    struct cmndspec *next = *nextp;
    struct json_value value;
    struct defaults *def;
    struct member *m;
    struct tm *tp;
    char timebuf[sizeof("20120727121554Z")];
    debug_decl(print_cmndspec_json, SUDOERS_DEBUG_UTIL);

    /* Open Cmnd_Spec object. */
    sudo_json_open_object(json, NULL);

    /* Print runasuserlist */
    if (cs->runasuserlist != NULL) {
	sudo_json_open_array(json, "runasusers");
	TAILQ_FOREACH(m, cs->runasuserlist, entries) {
	    print_member_json(json, parse_tree, m, TYPE_RUNASUSER,
		expand_aliases);
	}
	sudo_json_close_array(json);
    }

    /* Print runasgrouplist */
    if (cs->runasgrouplist != NULL) {
	sudo_json_open_array(json, "runasgroups");
	TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
	    print_member_json(json, parse_tree, m, TYPE_RUNASGROUP,
		expand_aliases);
	}
	sudo_json_close_array(json);
    }

    /* Print options and tags */
    if (cs->timeout > 0 || cs->notbefore != UNSPEC || cs->notafter != UNSPEC ||
	TAGS_SET(cs->tags) || !TAILQ_EMPTY(options)) {
	struct cmndtag tag = cs->tags;

	sudo_json_open_array(json, "Options");
	if (cs->timeout > 0) {
	    value.type = JSON_NUMBER;
	    value.u.number = cs->timeout;
	    sudo_json_add_value_as_object(json, "command_timeout", &value);
	}
	if (cs->notbefore != UNSPEC) {
	    if ((tp = gmtime(&cs->notbefore)) == NULL) {
		sudo_warn(U_("unable to get GMT time"));
	    } else {
		if (strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", tp) == 0) {
		    sudo_warnx(U_("unable to format timestamp"));
		} else {
		    value.type = JSON_STRING;
		    value.u.string = timebuf;
		    sudo_json_add_value_as_object(json, "notbefore", &value);
		}
	    }
	}
	if (cs->notafter != UNSPEC) {
	    if ((tp = gmtime(&cs->notafter)) == NULL) {
		sudo_warn(U_("unable to get GMT time"));
	    } else {
		if (strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", tp) == 0) {
		    sudo_warnx(U_("unable to format timestamp"));
		} else {
		    value.type = JSON_STRING;
		    value.u.string = timebuf;
		    sudo_json_add_value_as_object(json, "notafter", &value);
		}
	    }
	}
	if (tag.nopasswd != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = !tag.nopasswd;
	    sudo_json_add_value_as_object(json, "authenticate", &value);
	}
	if (tag.noexec != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.noexec;
	    sudo_json_add_value_as_object(json, "noexec", &value);
	}
	if (tag.send_mail != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.send_mail;
	    sudo_json_add_value_as_object(json, "send_mail", &value);
	}
	if (tag.setenv != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.setenv;
	    sudo_json_add_value_as_object(json, "setenv", &value);
	}
	if (tag.follow != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.follow;
	    sudo_json_add_value_as_object(json, "sudoedit_follow", &value);
	}
	if (tag.log_input != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.log_input;
	    sudo_json_add_value_as_object(json, "log_input", &value);
	}
	if (tag.log_output != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.log_output;
	    sudo_json_add_value_as_object(json, "log_output", &value);
	}
	TAILQ_FOREACH(def, options, entries) {
	    int type = get_defaults_type(def);
	    if (type == -1) {
		sudo_warnx(U_("unknown defaults entry \"%s\""), def->var);
		/* XXX - just pass it through as a string anyway? */
		continue;
	    }
	    if ((type & T_MASK) == T_FLAG || def->val == NULL) {
		value.type = JSON_BOOL;
		value.u.boolean = def->op;
		sudo_json_add_value_as_object(json, def->var, &value);
	    } else if ((type & T_MASK) == T_LIST) {
		print_defaults_list_json(json, def);
	    } else {
		value.type = JSON_STRING;
		value.u.string = def->val;
		sudo_json_add_value_as_object(json, def->var, &value);
	    }
	}
	sudo_json_close_array(json);
    }

#ifdef HAVE_SELINUX
    /* Print SELinux role/type */
    if (cs->role != NULL && cs->type != NULL) {
	sudo_json_open_array(json, "SELinux_Spec");
	value.type = JSON_STRING;
	value.u.string = cs->role;
	sudo_json_add_value(json, "role", &value);
	value.u.string = cs->type;
	sudo_json_add_value(json, "type", &value);
	sudo_json_close_array(json);
    }
#endif /* HAVE_SELINUX */

#ifdef HAVE_PRIV_SET
    /* Print Solaris privs/limitprivs */
    if (cs->privs != NULL || cs->limitprivs != NULL) {
	sudo_json_open_array(json, "Solaris_Priv_Spec");
	value.type = JSON_STRING;
	if (cs->privs != NULL) {
	    value.u.string = cs->privs;
	    sudo_json_add_value(json, "privs", &value);
	}
	if (cs->limitprivs != NULL) {
	    value.u.string = cs->limitprivs;
	    sudo_json_add_value(json, "limitprivs", &value);
	}
	sudo_json_close_array(json);
    }
#endif /* HAVE_PRIV_SET */

    /*
     * Merge adjacent commands with matching tags, runas, SELinux
     * role/type and Solaris priv settings.
     */
    sudo_json_open_array(json, "Commands");
    for (;;) {
	print_member_json(json, parse_tree, cs->cmnd, TYPE_COMMAND,
	    expand_aliases);
	/* Does the next entry differ only in the command itself? */
	if (!cmndspec_continues(cs, next))
	    break;
	cs = next;
	next = TAILQ_NEXT(cs, entries);
    }
    sudo_json_close_array(json);

    /* Close Cmnd_Spec object. */
    sudo_json_close_object(json);

    *nextp = next;

    debug_return;
}

/*
 * Print a User_Spec in JSON format at the correct indent level.
 */
static void
print_userspec_json(struct json_container *json,
    struct sudoers_parse_tree *parse_tree, struct userspec *us,
    bool expand_aliases)
{
    struct privilege *priv;
    struct member *m;
    struct cmndspec *cs, *next;
    debug_decl(print_userspec_json, SUDOERS_DEBUG_UTIL);

    /*
     * Each userspec struct may contain multiple privileges for
     * a user.  We export each privilege as a separate User_Spec
     * object for simplicity's sake.
     */
    TAILQ_FOREACH(priv, &us->privileges, entries) {
	/* Open User_Spec object. */
	sudo_json_open_object(json, NULL);

	/* Print users list. */
	sudo_json_open_array(json, "User_List");
	TAILQ_FOREACH(m, &us->users, entries) {
	    print_member_json(json, parse_tree, m, TYPE_USERNAME,
		expand_aliases);
	}
	sudo_json_close_array(json);

	/* Print hosts list. */
	sudo_json_open_array(json, "Host_List");
	TAILQ_FOREACH(m, &priv->hostlist, entries) {
	    print_member_json(json, parse_tree, m, TYPE_HOSTNAME,
		expand_aliases);
	}
	sudo_json_close_array(json);

	/* Print commands. */
	sudo_json_open_array(json, "Cmnd_Specs");
	TAILQ_FOREACH_SAFE(cs, &priv->cmndlist, entries, next) {
	    print_cmndspec_json(json, parse_tree, cs, &next, &priv->defaults,
		expand_aliases);
	}
	sudo_json_close_array(json);

	/* Close User_Spec object. */
	sudo_json_close_object(json);
    }

    debug_return;
}

static void
print_userspecs_json(struct json_container *json,
    struct sudoers_parse_tree *parse_tree, bool expand_aliases)
{
    struct userspec *us;
    debug_decl(print_userspecs_json, SUDOERS_DEBUG_UTIL);

    if (TAILQ_EMPTY(&parse_tree->userspecs))
	debug_return;

    sudo_json_open_array(json, "User_Specs");
    TAILQ_FOREACH(us, &parse_tree->userspecs, entries) {
	print_userspec_json(json, parse_tree, us, expand_aliases);
    }
    sudo_json_close_array(json);

    debug_return;
}

/*
 * Export the parsed sudoers file in JSON format.
 */
bool
convert_sudoers_json(struct sudoers_parse_tree *parse_tree,
    const char *output_file, struct cvtsudoers_config *conf)
{
    struct json_container json;
    bool ret = true;
    FILE *output_fp = stdout;
    debug_decl(convert_sudoers_json, SUDOERS_DEBUG_UTIL);

    if (strcmp(output_file, "-") != 0) {
	if ((output_fp = fopen(output_file, "w")) == NULL)
	    sudo_fatal(U_("unable to open %s"), output_file);
    }

    /* 4 space indent, non-compact, exit on memory allocation failure. */
    sudo_json_init(&json, 4, false, true);

    /* Dump Defaults in JSON format. */
    if (!ISSET(conf->suppress, SUPPRESS_DEFAULTS)) {
	print_defaults_json(&json, parse_tree, conf->expand_aliases);
    }

    /* Dump Aliases in JSON format. */
    if (!conf->expand_aliases && !ISSET(conf->suppress, SUPPRESS_ALIASES)) {
	print_aliases_json(&json, parse_tree);
    }

    /* Dump User_Specs in JSON format. */
    if (!ISSET(conf->suppress, SUPPRESS_PRIVS)) {
	print_userspecs_json(&json, parse_tree, conf->expand_aliases);
    }

    /* Write JSON output. */
    if (sudo_json_get_len(&json) != 0) {
	putc('{', output_fp);
	fputs(sudo_json_get_buf(&json), output_fp);
	fputs("\n}\n", output_fp);
	(void)fflush(output_fp);
	if (ferror(output_fp))
	    ret = false;
    }
    sudo_json_free(&json);
    if (output_fp != stdout)
	fclose(output_fp);

    debug_return_bool(ret);
}
