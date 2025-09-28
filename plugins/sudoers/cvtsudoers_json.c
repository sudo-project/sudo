/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013-2024 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>

#include <sudoers.h>
#include <sudo_digest.h>
#include <sudo_json.h>
#include <cvtsudoers.h>
#include <gram.h>

/*
 * Closure used to store state when iterating over all aliases.
 */
struct json_alias_closure {
    struct json_container *jsonc;
    const char *title;
    unsigned int count;
    short alias_type;
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
 * Returns true on success, false on a memory allocation failure.
 */
static bool
print_command_json(struct json_container *jsonc, const char *name, bool negated)
{
    struct sudo_command *c = (struct sudo_command *)name;
    struct command_digest *digest;
    struct json_value value;
    char *cmnd = c->cmnd;
    unsigned int digest_type;
    const char *digest_name;
    debug_decl(print_command_json, SUDOERS_DEBUG_UTIL);

    /* Print command with optional command line args. */
    if (c->args != NULL) {
	if (asprintf(&cmnd, "%s %s", c->cmnd, c->args) == -1)
	    debug_return_bool(false);
    }
    value.type = JSON_STRING;
    value.u.string = cmnd ? cmnd : (char *)"ALL";

    if (!negated && TAILQ_EMPTY(&c->digests)) {
	/* Print as { "command": "command and args" } */
	if (!sudo_json_add_value_as_object(jsonc, "command", &value))
	    debug_return_bool(false);
    } else {
	/* Print as multi-line object. */
	if (!sudo_json_open_object(jsonc, NULL))
	    debug_return_bool(false);
	if (!sudo_json_add_value(jsonc, "command", &value))
	    debug_return_bool(false);

	/* Optional digest list, ordered by digest type. */
	for (digest_type = 0; digest_type < SUDO_DIGEST_INVALID; digest_type++) {
	    unsigned int ndigests = 0;

	    TAILQ_FOREACH(digest, &c->digests, entries) {
		if (digest->digest_type == digest_type)
		    ndigests++;
	    }
	    if (ndigests == 0)
		continue;

	    digest_name = digest_type_to_name(digest_type);
	    if (ndigests > 1) {
		if (!sudo_json_open_array(jsonc, digest_name))
		    debug_return_bool(false);
		/* Only use digest_name for the array key, not value. */
		digest_name = NULL;
	    }
	    TAILQ_FOREACH(digest, &c->digests, entries) {
		if (digest->digest_type != digest_type)
		    continue;
		value.type = JSON_STRING;
		value.u.string = digest->digest_str;
		if (!sudo_json_add_value(jsonc, digest_name, &value))
		    debug_return_bool(false);
	    }
	    if (ndigests > 1) {
		if (!sudo_json_close_array(jsonc))
		    debug_return_bool(false);
	    }
	}

	/* Command may be negated. */
	if (negated) {
	    value.type = JSON_BOOL;
	    value.u.boolean = true;
	    if (!sudo_json_add_value(jsonc, "negated", &value))
		debug_return_bool(false);
	}

	if (!sudo_json_close_object(jsonc))
	    debug_return_bool(false);
    }

    if (cmnd != c->cmnd)
	free(cmnd);

    debug_return_bool(true);
}

/*
 * Map an alias type to enum word_type.
 */
static enum word_type
alias_to_word_type(short alias_type)
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
 * Returns true on success, false on a memory allocation failure.
 */
static bool
print_member_json_int(struct json_container *jsonc,
    const struct sudoers_parse_tree *parse_tree, char *name, int type,
    bool negated, enum word_type word_type, bool expand_aliases)
{
    struct json_value value;
    const char *typestr = NULL;
    short alias_type = UNSPEC;
    struct alias *a = NULL;
    const char *errstr;
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

    /* Special handling for ALIAS, which might actually be a WORD. */
    if (type == ALIAS) {
	switch (word_type) {
	case TYPE_COMMAND:
	    alias_type = CMNDALIAS;
	    typestr = "cmndalias";
	    break;
	case TYPE_HOSTNAME:
	    alias_type = HOSTALIAS;
	    typestr = "hostalias";
	    break;
	case TYPE_RUNASGROUP:
	case TYPE_RUNASUSER:
	    alias_type = RUNASALIAS;
	    typestr = "runasalias";
	    break;
	case TYPE_USERNAME:
	    alias_type = USERALIAS;
	    typestr = "useralias";
	    break;
	default:
	    sudo_fatalx("unexpected word type %d", word_type);
	}

	a = alias_get(parse_tree, value.u.string, alias_type);
	if (a == NULL && alias_type != CMNDALIAS) {
	    /* Alias does not resolve, treat as WORD instead. */
	    type = WORD;
	}
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
	if (!print_command_json(jsonc, name, negated))
	    goto oom;
	debug_return_bool(true);
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
	/* handled earlier */
	break;
    default:
	sudo_fatalx("unexpected member type %d", type);
    }

    if (expand_aliases && type == ALIAS) {
	/* Print each member of the alias. */
	if (a != NULL) {
	    struct member *m;

	    TAILQ_FOREACH(m, &a->members, entries) {
		if (!print_member_json_int(jsonc, parse_tree, m->name, m->type,
			negated ? !m->negated : m->negated, word_type, true))
		    goto oom;
	    }
	}
    } else {
	if (negated) {
	    if (!sudo_json_open_object(jsonc, NULL))
		goto oom;
	    if (!sudo_json_add_value(jsonc, typestr, &value))
		goto oom;
	    value.type = JSON_BOOL;
	    value.u.boolean = true;
	    if (!sudo_json_add_value(jsonc, "negated", &value))
		goto oom;
	    if (!sudo_json_close_object(jsonc))
		goto oom;
	} else {
	    if (!sudo_json_add_value_as_object(jsonc, typestr, &value))
		goto oom;
	}
    }

    if (a != NULL)
	alias_put(a);
    debug_return_bool(true);
oom:
    /* warning printed by caller */
    if (a != NULL)
	alias_put(a);
    debug_return_bool(false);
}

static bool
print_member_json(struct json_container *jsonc,
    const struct sudoers_parse_tree *parse_tree, struct member *m,
    enum word_type word_type, bool expand_aliases)
{
    return print_member_json_int(jsonc, parse_tree, m->name, m->type,
	m->negated, word_type, expand_aliases);
}

/*
 * Callback for alias_apply() to print an alias entry if it matches
 * the type specified in the closure.
 * Returns 0 on success and -1 on memory allocation failure.
 */
static int
print_alias_json(struct sudoers_parse_tree *parse_tree, struct alias *a,
    void *v)
{
    struct json_alias_closure *closure = v;
    struct member *m;
    debug_decl(print_alias_json, SUDOERS_DEBUG_UTIL);

    if (a->type != closure->alias_type)
	debug_return_int(0);

    /* Open the aliases object or close the last entry, then open new one. */
    if (closure->count++ == 0) {
	if (!sudo_json_open_object(closure->jsonc, closure->title))
	    debug_return_int(-1);
    } else {
	if (!sudo_json_close_array(closure->jsonc))
	    debug_return_int(-1);
    }
    if (!sudo_json_open_array(closure->jsonc, a->name))
	debug_return_int(-1);

    TAILQ_FOREACH(m, &a->members, entries) {
	if (!print_member_json(closure->jsonc, parse_tree, m,
		alias_to_word_type(closure->alias_type), false))
	    debug_return_int(-1);
    }
    debug_return_int(0);
}

/*
 * Print the binding for a Defaults entry of the specified type.
 * Returns true on success, false on a memory allocation failure.
 */
static bool
print_binding_json(struct json_container *jsonc,
    const struct sudoers_parse_tree *parse_tree,
    struct defaults_binding *binding, int type, bool expand_aliases)
{
    struct member *m;
    debug_decl(print_binding_json, SUDOERS_DEBUG_UTIL);

    if (TAILQ_EMPTY(&binding->members))
	debug_return_bool(true);

    /* Print each member object in binding. */
    if (!sudo_json_open_array(jsonc, "Binding"))
	goto oom;
    TAILQ_FOREACH(m, &binding->members, entries) {
	if (!print_member_json(jsonc, parse_tree, m,
		defaults_to_word_type(type), expand_aliases))
	    goto oom;
    }
    if (!sudo_json_close_array(jsonc))
	goto oom;

    debug_return_bool(true);
oom:
    /* warning printed by caller */
    debug_return_bool(false);
}

/*
 * Print a Defaults list JSON format.
 * Returns true on success, false on a memory allocation failure.
 */
static bool
print_defaults_list_json(struct json_container *jsonc, struct defaults *def)
{
    char savech, *start, *end = def->val;
    struct json_value value;
    debug_decl(print_defaults_list_json, SUDOERS_DEBUG_UTIL);

    if (!sudo_json_open_object(jsonc, NULL))
	goto oom;
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
    if (!sudo_json_add_value(jsonc, "operation", &value))
	goto oom;
    if (!sudo_json_open_array(jsonc, def->var))
	goto oom;
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
	if (!sudo_json_add_value(jsonc, NULL, &value))
	    goto oom;
	*end = savech;
    } while (*end++ != '\0');
    if (!sudo_json_close_array(jsonc))
	goto oom;
    if (!sudo_json_close_object(jsonc))
	goto oom;

    debug_return_bool(true);
oom:
    /* warning printed by caller */
    debug_return_bool(false);
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
 * Returns true on success, else false, displaying a warning.
 */
static bool
print_defaults_json(struct json_container *jsonc,
    const struct sudoers_parse_tree *parse_tree, bool expand_aliases)
{
    struct json_value value;
    struct defaults *def, *next;
    int type;
    debug_decl(print_defaults_json, SUDOERS_DEBUG_UTIL);

    if (TAILQ_EMPTY(&parse_tree->defaults))
	debug_return_bool(true);

    if (!sudo_json_open_array(jsonc, "Defaults"))
	goto oom;

    TAILQ_FOREACH_SAFE(def, &parse_tree->defaults, entries, next) {
	type = get_defaults_type(def);
	if (type == -1) {
	    log_warnx(U_("%s:%d:%d: unknown defaults entry \"%s\""),
		def->file, def->line, def->column, def->var);
	    /* XXX - just pass it through as a string anyway? */
	    continue;
	}

	/* Found it, print object container and binding (if any). */
	if (!sudo_json_open_object(jsonc, NULL))
	    goto oom;
	if (!print_binding_json(jsonc, parse_tree, def->binding, def->type,
		expand_aliases))
	    goto oom;

	/* Validation checks. */
	/* XXX - validate values in addition to names? */

	/* Print options, merging ones with the same binding. */
	if (!sudo_json_open_array(jsonc, "Options"))
	    goto oom;
	for (;;) {
	    next = TAILQ_NEXT(def, entries);
	    /* XXX - need to update cur too */
	    if ((type & T_MASK) == T_FLAG || def->val == NULL) {
		value.type = JSON_BOOL;
		value.u.boolean = def->op;
		if (!sudo_json_add_value_as_object(jsonc, def->var, &value))
		    goto oom;
	    } else if ((type & T_MASK) == T_LIST) {
		if (!print_defaults_list_json(jsonc, def))
		    goto oom;
	    } else {
		value.type = JSON_STRING;
		value.u.string = def->val;
		if (!sudo_json_add_value_as_object(jsonc, def->var, &value))
		    goto oom;
	    }
	    if (next == NULL || def->binding != next->binding)
		break;
	    def = next;
	    type = get_defaults_type(def);
	    if (type == -1) {
		log_warnx(U_("%s:%d:%d: unknown defaults entry \"%s\""),
		    def->file, def->line, def->column, def->var);
		/* XXX - just pass it through as a string anyway? */
		break;
	    }
	}
	if (!sudo_json_close_array(jsonc) || !sudo_json_close_object(jsonc))
	    goto oom;
    }

    /* Close Defaults array; comma (if any) & newline will be printer later. */
    if (!sudo_json_close_array(jsonc))
	goto oom;

    debug_return_bool(true);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    debug_return_bool(false);
}

/*
 * Export all aliases of the specified type in JSON format.
 * Iterates through the entire aliases tree.
 * Returns true on success, else false, displaying a warning.
 */
static bool
print_aliases_by_type(struct json_container *jsonc,
    const struct sudoers_parse_tree *parse_tree, short alias_type,
    const char *title)
{
    struct json_alias_closure closure;
    debug_decl(print_aliases_by_type, SUDOERS_DEBUG_UTIL);

    /* print_alias_json() does not modify parse_tree. */
    closure.jsonc = jsonc;
    closure.count = 0;
    closure.alias_type = alias_type;
    closure.title = title;
    if (!alias_apply((struct sudoers_parse_tree *)parse_tree, print_alias_json,
	    &closure))
	goto oom;
    if (closure.count != 0) {
	if (!sudo_json_close_array(jsonc))
	    goto oom;
	if (!sudo_json_close_object(jsonc)) {
	    goto oom;
	}
    }

    debug_return_bool(true);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    debug_return_bool(false);
}

/*
 * Export all aliases in JSON format.
 * Returns true on success, false on a memory allocation failure.
 */
static bool
print_aliases_json(struct json_container *jsonc,
    const struct sudoers_parse_tree *parse_tree)
{
    debug_decl(print_aliases_json, SUDOERS_DEBUG_UTIL);

    if (!print_aliases_by_type(jsonc, parse_tree, USERALIAS, "User_Aliases"))
	debug_return_bool(false);
    if (!print_aliases_by_type(jsonc, parse_tree, RUNASALIAS, "Runas_Aliases"))
	debug_return_bool(false);
    if (!print_aliases_by_type(jsonc, parse_tree, HOSTALIAS, "Host_Aliases"))
	debug_return_bool(false);
    if (!print_aliases_by_type(jsonc, parse_tree, CMNDALIAS, "Command_Aliases"))
	debug_return_bool(false);

    debug_return_bool(true);
}

/* Does the next entry differ only in the command itself? */
static bool
cmndspec_continues(struct cmndspec *cs, struct cmndspec *next)
{
    bool ret = next != NULL &&
	!RUNAS_CHANGED(cs, next) && !TAGS_CHANGED(cs->tags, next->tags)
	&& cs->privs == next->privs && cs->limitprivs == next->limitprivs
	&& cs->role == next->role && cs->type == next->type
	&& cs->apparmor_profile == next->apparmor_profile
	&& cs->runchroot == next->runchroot && cs->runcwd == next->runcwd;
    return ret;
}

/*
 * Print a Cmnd_Spec in JSON format at the correct indent level.
 * A pointer to the next Cmnd_Spec is passed in to make it possible to
 * merge adjacent entries that are identical in all but the command.
 * Returns true on success, false on a memory allocation failure.
 */
static bool
print_cmndspec_json(struct json_container *jsonc,
    const struct sudoers_parse_tree *parse_tree, struct cmndspec *cs,
    struct cmndspec **nextp, struct defaults_list *options, bool expand_aliases)
{
    char timebuf[sizeof("20120727121554Z")];
    struct cmndspec *next = *nextp;
    bool has_options = false;
    struct json_value value;
    struct defaults *def;
    struct member *m;
    struct tm gmt;
    size_t len;
    debug_decl(print_cmndspec_json, SUDOERS_DEBUG_UTIL);

    /* Open Cmnd_Spec object. */
    if (!sudo_json_open_object(jsonc, NULL))
	goto oom;

    /* Print runasuserlist */
    if (cs->runasuserlist != NULL) {
	if (!sudo_json_open_array(jsonc, "runasusers"))
	    goto oom;
	TAILQ_FOREACH(m, cs->runasuserlist, entries) {
	    if (!print_member_json(jsonc, parse_tree, m, TYPE_RUNASUSER,
		    expand_aliases))
		goto oom;
	}
	if (!sudo_json_close_array(jsonc))
	    goto oom;
    }

    /* Print runasgrouplist */
    if (cs->runasgrouplist != NULL) {
	if (!sudo_json_open_array(jsonc, "runasgroups"))
	    goto oom;
	TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
	    if (!print_member_json(jsonc, parse_tree, m, TYPE_RUNASGROUP,
		    expand_aliases))
		goto oom;
	}
	if (!sudo_json_close_array(jsonc))
	    goto oom;
    }

    /* Print options and tags */
    has_options = TAGS_SET(cs->tags) || !TAILQ_EMPTY(options) ||
	cs->timeout > 0 || cs->notbefore != UNSPEC || cs->notafter != UNSPEC ||
	cs->runchroot != NULL || cs->runcwd != NULL ||
	(cs->role != NULL && cs->type != NULL) || cs->apparmor_profile != NULL
	|| cs->privs != NULL || cs->limitprivs != NULL;
    if (has_options) {
	struct cmndtag tag = cs->tags;

	if (!sudo_json_open_array(jsonc, "Options"))
	    goto oom;
	if (cs->runchroot != NULL) {
	    value.type = JSON_STRING;
	    value.u.string = cs->runchroot;
	    if (!sudo_json_add_value_as_object(jsonc, "runchroot", &value))
		goto oom;
	}
	if (cs->runcwd != NULL) {
	    value.type = JSON_STRING;
	    value.u.string = cs->runcwd;
	    if (!sudo_json_add_value_as_object(jsonc, "runcwd", &value))
		goto oom;
	}
	if (cs->timeout > 0) {
	    value.type = JSON_NUMBER;
	    value.u.number = cs->timeout;
	    if (!sudo_json_add_value_as_object(jsonc, "command_timeout", &value))
		goto oom;
	}
	if (cs->notbefore != UNSPEC) {
	    if (gmtime_r(&cs->notbefore, &gmt) == NULL) {
		sudo_warn("%s", U_("unable to get GMT time"));
	    } else {
		timebuf[sizeof(timebuf) - 1] = '\0';
		len = strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", &gmt);
		if (len == 0 || timebuf[sizeof(timebuf) - 1] != '\0') {
		    sudo_warnx("%s", U_("unable to format timestamp"));
		} else {
		    value.type = JSON_STRING;
		    value.u.string = timebuf;
		    if (!sudo_json_add_value_as_object(jsonc, "notbefore", &value))
			goto oom;
		}
	    }
	}
	if (cs->notafter != UNSPEC) {
	    if (gmtime_r(&cs->notafter, &gmt) == NULL) {
		sudo_warn("%s", U_("unable to get GMT time"));
	    } else {
		timebuf[sizeof(timebuf) - 1] = '\0';
		len = strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", &gmt);
		if (len == 0 || timebuf[sizeof(timebuf) - 1] != '\0') {
		    sudo_warnx("%s", U_("unable to format timestamp"));
		} else {
		    value.type = JSON_STRING;
		    value.u.string = timebuf;
		    if (!sudo_json_add_value_as_object(jsonc, "notafter", &value))
			goto oom;
		}
	    }
	}
	if (tag.nopasswd != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = !tag.nopasswd;
	    if (!sudo_json_add_value_as_object(jsonc, "authenticate", &value))
		goto oom;
	}
	if (tag.noexec != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.noexec;
	    if (!sudo_json_add_value_as_object(jsonc, "noexec", &value))
		goto oom;
	}
	if (tag.intercept != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.intercept;
	    if (!sudo_json_add_value_as_object(jsonc, "intercept", &value))
		goto oom;
	}
	if (tag.send_mail != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.send_mail;
	    if (!sudo_json_add_value_as_object(jsonc, "send_mail", &value))
		goto oom;
	}
	if (tag.setenv != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.setenv;
	    if (!sudo_json_add_value_as_object(jsonc, "setenv", &value))
		goto oom;
	}
	if (tag.follow != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.follow;
	    if (!sudo_json_add_value_as_object(jsonc, "sudoedit_follow", &value))
		goto oom;
	}
	if (tag.log_input != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.log_input;
	    if (!sudo_json_add_value_as_object(jsonc, "log_input", &value))
		goto oom;
	}
	if (tag.log_output != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.log_output;
	    if (!sudo_json_add_value_as_object(jsonc, "log_output", &value))
		goto oom;
	}
	TAILQ_FOREACH(def, options, entries) {
	    int type = get_defaults_type(def);
	    if (type == -1) {
		log_warnx(U_("%s:%d:%d: unknown defaults entry \"%s\""),
		    def->file, def->line, def->column, def->var);
		/* XXX - just pass it through as a string anyway? */
		continue;
	    }
	    if ((type & T_MASK) == T_FLAG || def->val == NULL) {
		value.type = JSON_BOOL;
		value.u.boolean = def->op;
		if (!sudo_json_add_value_as_object(jsonc, def->var, &value))
		    goto oom;
	    } else if ((type & T_MASK) == T_LIST) {
		if (!print_defaults_list_json(jsonc, def))
		    goto oom;
	    } else {
		value.type = JSON_STRING;
		value.u.string = def->val;
		if (!sudo_json_add_value_as_object(jsonc, def->var, &value))
		    goto oom;
	    }
	}
	if (cs->role != NULL && cs->type != NULL) {
	    value.type = JSON_STRING;
	    value.u.string = cs->role;
	    if (!sudo_json_add_value_as_object(jsonc, "role", &value))
		goto oom;
	    value.u.string = cs->type;
	    if (!sudo_json_add_value_as_object(jsonc, "type", &value))
		goto oom;
	}
	if (cs->apparmor_profile != NULL) {
	    value.type = JSON_STRING;
	    value.u.string = cs->apparmor_profile;
	    if (!sudo_json_add_value_as_object(jsonc, "apparmor_profile", &value))
		goto oom;
	}
	if (cs->privs != NULL) {
	    value.type = JSON_STRING;
	    value.u.string = cs->privs;
	    if (!sudo_json_add_value_as_object(jsonc, "privs", &value))
		goto oom;
	}
	if (cs->limitprivs != NULL) {
	    value.type = JSON_STRING;
	    value.u.string = cs->limitprivs;
	    if (!sudo_json_add_value_as_object(jsonc, "limitprivs", &value))
		goto oom;
	}
	if (!sudo_json_close_array(jsonc))
	    goto oom;
    }

    /*
     * Merge adjacent commands with matching tags, runas, SELinux
     * role/type and Solaris priv settings.
     */
    if (!sudo_json_open_array(jsonc, "Commands"))
	goto oom;
    for (;;) {
	if (!print_member_json(jsonc, parse_tree, cs->cmnd, TYPE_COMMAND,
		expand_aliases))
	    goto oom;
	/* Does the next entry differ only in the command itself? */
	if (!cmndspec_continues(cs, next))
	    break;
	cs = next;
	next = TAILQ_NEXT(cs, entries);
    }
    if (!sudo_json_close_array(jsonc))
	goto oom;

    /* Close Cmnd_Spec object. */
    if (!sudo_json_close_object(jsonc))
	goto oom;

    *nextp = next;

    debug_return_bool(true);
oom:
    /* warning printed by caller */
    debug_return_bool(false);
}

/*
 * Print a User_Spec in JSON format at the correct indent level.
 * Returns true on success, false on a memory allocation failure.
 */
static bool
print_userspec_json(struct json_container *jsonc,
    const struct sudoers_parse_tree *parse_tree, struct userspec *us,
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
	if (!sudo_json_open_object(jsonc, NULL))
	    goto oom;

	/* Print users list. */
	if (!sudo_json_open_array(jsonc, "User_List"))
	    goto oom;
	TAILQ_FOREACH(m, &us->users, entries) {
	    if (!print_member_json(jsonc, parse_tree, m, TYPE_USERNAME,
		    expand_aliases))
		goto oom;
	}
	if (!sudo_json_close_array(jsonc))
	    goto oom;

	/* Print hosts list. */
	if (!sudo_json_open_array(jsonc, "Host_List"))
	    goto oom;
	TAILQ_FOREACH(m, &priv->hostlist, entries) {
	    if (!print_member_json(jsonc, parse_tree, m, TYPE_HOSTNAME,
		    expand_aliases))
		goto oom;
	}
	if (!sudo_json_close_array(jsonc))
	    goto oom;

	/* Print commands. */
	if (!sudo_json_open_array(jsonc, "Cmnd_Specs"))
	    goto oom;
	TAILQ_FOREACH_SAFE(cs, &priv->cmndlist, entries, next) {
	    if (!print_cmndspec_json(jsonc, parse_tree, cs, &next,
		    &priv->defaults, expand_aliases))
		goto oom;
	}
	if (!sudo_json_close_array(jsonc))
	    goto oom;

	/* Close User_Spec object. */
	if (!sudo_json_close_object(jsonc))
	    goto oom;
    }

    debug_return_bool(true);
oom:
    /* warning printed by caller */
    debug_return_bool(false);
}

/*
 * Print an array of User_Spec in JSON format.
 * Returns true on success, else false, displaying a warning.
 */
static bool
print_userspecs_json(struct json_container *jsonc,
    const struct sudoers_parse_tree *parse_tree, bool expand_aliases)
{
    struct userspec *us;
    debug_decl(print_userspecs_json, SUDOERS_DEBUG_UTIL);

    if (TAILQ_EMPTY(&parse_tree->userspecs))
	debug_return_bool(true);

    if (!sudo_json_open_array(jsonc, "User_Specs"))
	goto oom;
    TAILQ_FOREACH(us, &parse_tree->userspecs, entries) {
	if (!print_userspec_json(jsonc, parse_tree, us, expand_aliases))
	    goto oom;
    }
    if (!sudo_json_close_array(jsonc))
	goto oom;

    debug_return_bool(true);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    debug_return_bool(false);
}

/*
 * Export the parsed sudoers file in JSON format.
 */
bool
convert_sudoers_json(const struct sudoers_parse_tree *parse_tree,
    const char *output_file, struct cvtsudoers_config *conf)
{
    struct json_container jsonc;
    bool ret = false;
    FILE *output_fp = stdout;
    debug_decl(convert_sudoers_json, SUDOERS_DEBUG_UTIL);

    if (strcmp(output_file, "-") != 0) {
	if ((output_fp = fopen(output_file, "w")) == NULL) {
	    sudo_warn(U_("unable to open %s"), output_file);
	    debug_return_bool(false);
	}
    }

    /* 4 space indent, non-compact, exit on memory allocation failure. */
    if (!sudo_json_init(&jsonc, 4, false, false, false)) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto cleanup;
    }

    /* Dump Defaults in JSON format. */
    if (!ISSET(conf->suppress, SUPPRESS_DEFAULTS)) {
	if (!print_defaults_json(&jsonc, parse_tree, conf->expand_aliases))
	    goto cleanup;
    }

    /* Dump Aliases in JSON format. */
    if (!conf->expand_aliases && !ISSET(conf->suppress, SUPPRESS_ALIASES)) {
	if (!print_aliases_json(&jsonc, parse_tree))
	    goto cleanup;
    }

    /* Dump User_Specs in JSON format. */
    if (!ISSET(conf->suppress, SUPPRESS_PRIVS)) {
	if (!print_userspecs_json(&jsonc, parse_tree, conf->expand_aliases))
	    goto cleanup;
    }

    /* Write JSON output. */
    if (sudo_json_get_len(&jsonc) != 0) {
	putc('{', output_fp);
	fputs(sudo_json_get_buf(&jsonc), output_fp);
	fputs("\n}\n", output_fp);
	(void)fflush(output_fp);
    }
    if (!ferror(output_fp))
	ret = true;

cleanup:
    sudo_json_free(&jsonc);
    if (output_fp != stdout)
	fclose(output_fp);

    debug_return_bool(ret);
}
