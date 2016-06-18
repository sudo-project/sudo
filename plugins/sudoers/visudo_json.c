/*
 * Copyright (c) 2013-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>

#include "sudoers.h"
#include "parse.h"
#include <gram.h>

/*
 * JSON values may be of the following types.
 */
enum json_value_type {
    JSON_STRING,
    JSON_ID,
    JSON_NUMBER,
    JSON_OBJECT,
    JSON_ARRAY,
    JSON_BOOL,
    JSON_NULL
};

/*
 * JSON value suitable for printing.
 * Note: this does not support object or array values.
 */
struct json_value {
    enum json_value_type type;
    union {
	char *string;
	int number;
	id_t id;
	bool boolean;
    } u;
};

/*
 * Closure used to store state when iterating over all aliases.
 */
struct json_alias_closure {
    FILE *fp;
    const char *title;
    unsigned int count;
    int alias_type;
    int indent;
    bool need_comma;
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
 * Print "indent" number of blank characters.
 */
static void
print_indent(FILE *fp, int indent)
{
    while (indent--)
	putc(' ', fp);
}

/*
 * Print a JSON string, escaping special characters.
 * Does not support unicode escapes.
 */
static void
print_string_json_unquoted(FILE *fp, const char *str)
{
    char ch;

    while ((ch = *str++) != '\0') {
	switch (ch) {
	case '"':
	case '\\':
	    putc('\\', fp);
	    break;
	case '\b':
	    ch = 'b';
	    putc('\\', fp);
	    break;
	case '\f':
	    ch = 'f';
	    putc('\\', fp);
	    break;
	case '\n':
	    ch = 'n';
	    putc('\\', fp);
	    break;
	case '\r':
	    ch = 'r';
	    putc('\\', fp);
	    break;
	case '\t':
	    ch = 't';
	    putc('\\', fp);
	    break;
	}
	putc(ch, fp);
    }
}

/*
 * Print a quoted JSON string, escaping special characters.
 * Does not support unicode escapes.
 */
static void
print_string_json(FILE *fp, const char *str)
{
    putc('\"', fp);
    print_string_json_unquoted(fp, str);
    putc('\"', fp);
}

/*
 * Print a JSON name: value pair with proper quoting and escaping.
 */
static void
print_pair_json(FILE *fp, const char *pre, const char *name,
    const struct json_value *value, const char *post, int indent)
{
    debug_decl(print_pair_json, SUDOERS_DEBUG_UTIL)

    print_indent(fp, indent);

    /* prefix */
    if (pre != NULL)
	fputs(pre, fp);

    /* name */
    print_string_json(fp, name);
    putc(':', fp);
    putc(' ', fp);

    /* value */
    switch (value->type) {
    case JSON_STRING:
	print_string_json(fp, value->u.string);
	break;
    case JSON_ID:
	fprintf(fp, "%u", (unsigned int)value->u.id);
	break;
    case JSON_NUMBER:
	fprintf(fp, "%d", value->u.number);
	break;
    case JSON_NULL:
	fputs("null", fp);
	break;
    case JSON_BOOL:
	fputs(value->u.boolean ? "true" : "false", fp);
	break;
    case JSON_OBJECT:
	sudo_fatalx("internal error: can't print JSON_OBJECT");
	break;
    case JSON_ARRAY:
	sudo_fatalx("internal error: can't print JSON_ARRAY");
	break;
    }

    /* postfix */
    if (post != NULL)
	fputs(post, fp);

    debug_return;
}

/*
 * Print a JSON string with optional prefix and postfix to fp.
 * Strings are not quoted but are escaped as per the JSON spec.
 */
static void
printstr_json(FILE *fp, const char *pre, const char *str, const char *post,
    int indent)
{
    debug_decl(printstr_json, SUDOERS_DEBUG_UTIL)

    print_indent(fp, indent);
    if (pre != NULL)
	fputs(pre, fp);
    if (str != NULL) {
	print_string_json_unquoted(fp, str);
    }
    if (post != NULL)
	fputs(post, fp);
    debug_return;
}

/*
 * Print sudo command member in JSON format, with specified indentation.
 * If last_one is false, a comma will be printed before the newline
 * that closes the object.
 */
static void
print_command_json(FILE *fp, struct member *m, int indent, bool last_one)
{
    struct sudo_command *c = (struct sudo_command *)m->name;
    struct json_value value;
    const char *digest_name;
    debug_decl(print_command_json, SUDOERS_DEBUG_UTIL)

    printstr_json(fp, "{", NULL, NULL, indent);
    if (m->negated || c->digest != NULL) {
	putc('\n', fp);
	indent += 4;
    } else {
	putc(' ', fp);
	indent = 0;
    }

    /* Print command with optional command line args. */
    if (c->args != NULL) {
	printstr_json(fp, "\"", "command", "\": ", indent);
	printstr_json(fp, "\"", c->cmnd, " ", 0);
	printstr_json(fp, NULL, c->args, "\"", 0);
    } else {
	value.type = JSON_STRING;
	value.u.string = c->cmnd;
	print_pair_json(fp, NULL, "command", &value, NULL, indent);
    }

    /* Optional digest. */
    if (c->digest != NULL) {
	fputs(",\n", fp);
	switch (c->digest->digest_type) {
	case SUDO_DIGEST_SHA224:
	    digest_name = "sha224";
	    break;
	case SUDO_DIGEST_SHA256:
	    digest_name = "sha256";
	    break;
	case SUDO_DIGEST_SHA384:
	    digest_name = "sha384";
	    break;
	case SUDO_DIGEST_SHA512:
	    digest_name = "sha512";
	    break;
	default:
	    digest_name = "invalid digest";
	    break;
	}
	value.type = JSON_STRING;
	value.u.string = c->digest->digest_str;
	print_pair_json(fp, NULL, digest_name, &value, NULL, indent);
    }

    /* Command may be negated. */
    if (m->negated) {
	fputs(",\n", fp);
	value.type = JSON_BOOL;
	value.u.boolean = true;
	print_pair_json(fp, NULL, "negated", &value, NULL, indent);
    }

    if (indent != 0) {
	indent -= 4;
	putc('\n', fp);
	print_indent(fp, indent);
    } else {
	putc(' ', fp);
    }
    putc('}', fp);
    if (!last_one)
	putc(',', fp);
    putc('\n', fp);

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
 * Print struct member in JSON format, with specified indentation.
 * If last_one is false, a comma will be printed before the newline
 * that closes the object.
 */
static void
print_member_json(FILE *fp, struct member *m, enum word_type word_type,
    bool last_one, int indent)
{
    struct json_value value;
    const char *typestr;
    const char *errstr;
    id_t id;
    debug_decl(print_member_json, SUDOERS_DEBUG_UTIL)

    /* Most of the time we print a string. */
    value.type = JSON_STRING;
    value.u.string = m->name;

    switch (m->type) {
    case USERGROUP:
	value.u.string++; /* skip leading '%' */
	if (*value.u.string == ':') {
	    value.u.string++;
	    typestr = "nonunixgroup";
	    if (*value.u.string == '#') {
		id = sudo_strtoid(m->name + 3, NULL, NULL, &errstr);
		if (errstr != NULL) {
		    sudo_warnx("internal error: non-Unix group ID %s: \"%s\"",
			errstr, m->name);
		} else {
		    value.type = JSON_ID;
		    value.u.id = id;
		    typestr = "nonunixgid";
		}
	    }
	} else {
	    typestr = "usergroup";
	    if (*value.u.string == '#') {
		id = sudo_strtoid(m->name + 2, NULL, NULL, &errstr);
		if (errstr != NULL) {
		    sudo_warnx("internal error: group ID %s: \"%s\"",
			errstr, m->name);
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
	print_command_json(fp, m, indent, last_one);
	debug_return;
    case WORD:
	switch (word_type) {
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
		id = sudo_strtoid(m->name + 1, NULL, NULL, &errstr);
		if (errstr != NULL) {
		    sudo_warnx("internal error: user ID %s: \"%s\"",
			errstr, m->name);
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
    case ALL:
	value.u.string = "ALL";
	/* FALLTHROUGH */
    case ALIAS:
	switch (word_type) {
	case TYPE_COMMAND:
	    typestr = "cmndalias";
	    break;
	case TYPE_HOSTNAME:
	    typestr = "hostalias";
	    break;
	case TYPE_RUNASGROUP:
	case TYPE_RUNASUSER:
	    typestr = "runasalias";
	    break;
	case TYPE_USERNAME:
	    typestr = "useralias";
	    break;
	default:
	    sudo_fatalx("unexpected word type %d", word_type);
	}
	break;
    default:
	sudo_fatalx("unexpected member type %d", m->type);
    }

    if (m->negated) {
	print_indent(fp, indent);
	fputs("{\n", fp);
	indent += 4;
	print_pair_json(fp, NULL, typestr, &value, ",\n", indent);
	value.type = JSON_BOOL;
	value.u.boolean = true;
	print_pair_json(fp, NULL, "negated", &value, "\n", indent);
	indent -= 4;
	print_indent(fp, indent);
	putc('}', fp);
    } else {
	print_pair_json(fp, "{ ", typestr, &value, " }", indent);
    }
    if (!last_one)
	putc(',', fp);
    putc('\n', fp);

    debug_return;
}

/*
 * Callback for alias_apply() to print an alias entry if it matches
 * the type specified in the closure.
 */
int
print_alias_json(void *v1, void *v2)
{
    struct alias *a = v1;
    struct json_alias_closure *closure = v2;
    struct member *m;
    debug_decl(print_alias_json, SUDOERS_DEBUG_UTIL)

    if (a->type != closure->alias_type)
	debug_return_int(0);

    /* Open the aliases object or close the last entry, then open new one. */
    if (closure->count++ == 0) {
	fprintf(closure->fp, "%s\n%*s\"%s\": {\n",
	    closure->need_comma ? "," : "", closure->indent, "",
	    closure->title);
	closure->indent += 4;
    } else {
	fprintf(closure->fp, "%*s],\n", closure->indent, "");
    }
    printstr_json(closure->fp, "\"", a->name, "\": [\n", closure->indent);

    closure->indent += 4;
    TAILQ_FOREACH(m, &a->members, entries) {
	print_member_json(closure->fp, m,
	    alias_to_word_type(closure->alias_type),
	    TAILQ_NEXT(m, entries) == NULL, closure->indent);
    }
    closure->indent -= 4;
    debug_return_int(0);
}

/*
 * Print the binding for a Defaults entry of the specified type.
 */
static void
print_binding_json(FILE *fp, struct member_list *binding, int type, int indent)
{
    struct member *m;
    debug_decl(print_binding_json, SUDOERS_DEBUG_UTIL)

    if (TAILQ_EMPTY(binding))
	debug_return;

    fprintf(fp, "%*s\"Binding\": [\n", indent, "");
    indent += 4;

    /* Print each member object in binding. */
    TAILQ_FOREACH(m, binding, entries) {
	print_member_json(fp, m, defaults_to_word_type(type),
	     TAILQ_NEXT(m, entries) == NULL, indent);
    }

    indent -= 4;
    fprintf(fp, "%*s],\n", indent, "");

    debug_return;
}

/*
 * Print a Defaults list JSON format.
 */
static void
print_defaults_list_json(FILE *fp, struct defaults *def, int indent)
{
    char savech, *start, *end = def->val;
    struct json_value value;
    debug_decl(print_defaults_list_json, SUDOERS_DEBUG_UTIL)

    fprintf(fp, "%*s{\n", indent, "");
    indent += 4;
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
    print_pair_json(fp, NULL, "operation", &value, ",\n", indent);
    printstr_json(fp, "\"", def->var, "\": [\n", indent);
    indent += 4;
    print_indent(fp, indent);
    /* Split value into multiple space-separated words. */
    do {
	/* Remove leading blanks, must have a non-empty string. */
	for (start = end; isblank((unsigned char)*start); start++)
	    ;
	if (*start == '\0')
	    break;

	/* Find the end and print it. */
	for (end = start; *end && !isblank((unsigned char)*end); end++)
	    ;
	savech = *end;
	*end = '\0';
	print_string_json(fp, start);
	if (savech != '\0')
	    putc(',', fp);
	*end = savech;
    } while (*end++ != '\0');
    putc('\n', fp);
    indent -= 4;
    fprintf(fp, "%*s]\n", indent, "");
    indent -= 4;
    fprintf(fp, "%*s}", indent, "");

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
static bool
print_defaults_json(FILE *fp, int indent, bool need_comma)
{
    struct json_value value;
    struct defaults *def, *next;
    int type;
    debug_decl(print_defaults_json, SUDOERS_DEBUG_UTIL)

    if (TAILQ_EMPTY(&defaults))
	debug_return_bool(need_comma);

    fprintf(fp, "%s\n%*s\"Defaults\": [\n", need_comma ? "," : "", indent, "");
    indent += 4;

    TAILQ_FOREACH_SAFE(def, &defaults, entries, next) {
	type = get_defaults_type(def);
	if (type == -1) {
	    sudo_warnx(U_("unknown defaults entry `%s'"), def->var);
	    /* XXX - just pass it through as a string anyway? */
	    continue;
	}

	/* Found it, print object container and binding (if any). */
	fprintf(fp, "%*s{\n", indent, "");
	indent += 4;
	print_binding_json(fp, def->binding, def->type, indent);

	/* Validation checks. */
	/* XXX - validate values in addition to names? */

	/* Print options, merging ones with the same binding. */
	fprintf(fp, "%*s\"Options\": [\n", indent, "");
	indent += 4;
	for (;;) {
	    next = TAILQ_NEXT(def, entries);
	    /* XXX - need to update cur too */
	    if ((type & T_MASK) == T_FLAG || def->val == NULL) {
		value.type = JSON_BOOL;
		value.u.boolean = def->op;
		print_pair_json(fp, "{ ", def->var, &value, " }", indent);
	    } else if ((type & T_MASK) == T_LIST) {
		print_defaults_list_json(fp, def, indent);
	    } else {
		value.type = JSON_STRING;
		value.u.string = def->val;
		print_pair_json(fp, "{ ", def->var, &value, " }", indent);
	    }
	    if (next == NULL || def->binding != next->binding)
		break;
	    def = next;
	    type = get_defaults_type(def);
	    if (type == -1) {
		sudo_warnx(U_("unknown defaults entry `%s'"), def->var);
		/* XXX - just pass it through as a string anyway? */
		break;
	    }
	    fputs(",\n", fp);
	}
	putc('\n', fp);
	indent -= 4;
	print_indent(fp, indent);
	fputs("]\n", fp);
	indent -= 4;
	print_indent(fp, indent);
	fprintf(fp, "}%s\n", next != NULL ? "," : "");
    }

    /* Close Defaults array; comma (if any) & newline will be printer later. */
    indent -= 4;
    print_indent(fp, indent);
    fputs("]", fp);

    debug_return_bool(true);
}

/*
 * Export all aliases of the specified type in JSON format.
 * Iterates through the entire aliases tree.
 */
static bool
print_aliases_by_type_json(FILE *fp, int alias_type, const char *title,
    int indent, bool need_comma)
{
    struct json_alias_closure closure;
    debug_decl(print_aliases_by_type_json, SUDOERS_DEBUG_UTIL)

    closure.fp = fp;
    closure.indent = indent;
    closure.count = 0;
    closure.alias_type = alias_type;
    closure.title = title;
    closure.need_comma = need_comma;
    alias_apply(print_alias_json, &closure);
    if (closure.count != 0) {
	print_indent(fp, closure.indent);
	fputs("]\n", fp);
	closure.indent -= 4;
	print_indent(fp, closure.indent);
	putc('}', fp);
	need_comma = true;
    }

    debug_return_bool(need_comma);
}

/*
 * Export all aliases in JSON format.
 */
static bool
print_aliases_json(FILE *fp, int indent, bool need_comma)
{
    debug_decl(print_aliases_json, SUDOERS_DEBUG_UTIL)

    need_comma = print_aliases_by_type_json(fp, USERALIAS, "User_Aliases",
	indent, need_comma);
    need_comma = print_aliases_by_type_json(fp, RUNASALIAS, "Runas_Aliases",
	indent, need_comma);
    need_comma = print_aliases_by_type_json(fp, HOSTALIAS, "Host_Aliases",
	indent, need_comma);
    need_comma = print_aliases_by_type_json(fp, CMNDALIAS, "Command_Aliases",
	indent, need_comma);

    debug_return_bool(need_comma);
}

/*
 * Print a Cmnd_Spec in JSON format at the specified indent level.
 * A pointer to the next Cmnd_Spec is passed in to make it possible to
 * merge adjacent entries that are identical in all but the command.
 */
static void
print_cmndspec_json(FILE *fp, struct cmndspec *cs, struct cmndspec **nextp,
    int indent)
{
    struct cmndspec *next = *nextp;
    struct json_value value;
    struct member *m;
    bool last_one;
    debug_decl(print_cmndspec_json, SUDOERS_DEBUG_UTIL)

    /* Open Cmnd_Spec object. */
    fprintf(fp, "%*s{\n", indent, "");
    indent += 4;

    /* Print runasuserlist */
    if (cs->runasuserlist != NULL) {
	fprintf(fp, "%*s\"runasusers\": [\n", indent, "");
	indent += 4;
	TAILQ_FOREACH(m, cs->runasuserlist, entries) {
	    print_member_json(fp, m, TYPE_RUNASUSER,
		TAILQ_NEXT(m, entries) == NULL, indent);
	}
	indent -= 4;
	fprintf(fp, "%*s],\n", indent, "");
    }

    /* Print runasgrouplist */
    if (cs->runasgrouplist != NULL) {
	fprintf(fp, "%*s\"runasgroups\": [\n", indent, "");
	indent += 4;
	TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
	    print_member_json(fp, m, TYPE_RUNASGROUP,
		TAILQ_NEXT(m, entries) == NULL, indent);
	}
	indent -= 4;
	fprintf(fp, "%*s],\n", indent, "");
    }

    /* Print tags */
    if (TAGS_SET(cs->tags)) {
	struct cmndtag tag = cs->tags;

	fprintf(fp, "%*s\"Options\": [\n", indent, "");
	indent += 4;
	if (tag.nopasswd != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = !tag.nopasswd;
	    tag.nopasswd = UNSPEC;
	    print_pair_json(fp, "{ ", "authenticate", &value,
		TAGS_SET(tag) ? " },\n" : " }\n", indent);
	}
	if (tag.noexec != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.noexec;
	    tag.noexec = UNSPEC;
	    print_pair_json(fp, "{ ", "noexec", &value,
		TAGS_SET(tag) ? " },\n" : " }\n", indent);
	}
	if (tag.send_mail != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.send_mail;
	    tag.send_mail = UNSPEC;
	    print_pair_json(fp, "{ ", "send_mail", &value,
		TAGS_SET(tag) ? " },\n" : " }\n", indent);
	}
	if (tag.setenv != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.setenv;
	    tag.setenv = UNSPEC;
	    print_pair_json(fp, "{ ", "setenv", &value,
		TAGS_SET(tag) ? " },\n" : " }\n", indent);
	}
	if (tag.follow != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.follow;
	    tag.follow = UNSPEC;
	    print_pair_json(fp, "{ ", "sudoedit_follow", &value,
		TAGS_SET(tag) ? " },\n" : " }\n", indent);
	}
	if (tag.log_input != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.log_input;
	    tag.log_input = UNSPEC;
	    print_pair_json(fp, "{ ", "log_input", &value,
		TAGS_SET(tag) ? " },\n" : " }\n", indent);
	}
	if (tag.log_output != UNSPEC) {
	    value.type = JSON_BOOL;
	    value.u.boolean = tag.log_output;
	    tag.log_output = UNSPEC;
	    print_pair_json(fp, "{ ", "log_output", &value,
		TAGS_SET(tag) ? " },\n" : " }\n", indent);
	}
	indent -= 4;
	fprintf(fp, "%*s],\n", indent, "");
    }

#ifdef HAVE_SELINUX
    /* Print SELinux role/type */
    if (cs->role != NULL && cs->type != NULL) {
	fprintf(fp, "%*s\"SELinux_Spec\": [\n", indent, "");
	indent += 4;
	value.type = JSON_STRING;
	value.u.string = cs->role;
	print_pair_json(fp, NULL, "role", &value, ",\n", indent);
	value.u.string = cs->type;
	print_pair_json(fp, NULL, "type", &value, "\n", indent);
	indent -= 4;
	fprintf(fp, "%*s],\n", indent, "");
    }
#endif /* HAVE_SELINUX */

#ifdef HAVE_PRIV_SET
    /* Print Solaris privs/limitprivs */
    if (cs->privs != NULL || cs->limitprivs != NULL) {
	fprintf(fp, "%*s\"Solaris_Priv_Spec\": [\n", indent, "");
	indent += 4;
	value.type = JSON_STRING;
	if (cs->privs != NULL) {
	    value.u.string = cs->privs;
	    print_pair_json(fp, NULL, "privs", &value,
		cs->limitprivs != NULL ? ",\n" : "\n", indent);
	}
	if (cs->limitprivs != NULL) {
	    value.u.string = cs->limitprivs;
	    print_pair_json(fp, NULL, "limitprivs", &value, "\n", indent);
	}
	indent -= 4;
	fprintf(fp, "%*s],\n", indent, "");
    }
#endif /* HAVE_PRIV_SET */

    /*
     * Merge adjacent commands with matching tags, runas, SELinux
     * role/type and Solaris priv settings.
     */
    fprintf(fp, "%*s\"Commands\": [\n", indent, "");
    indent += 4;
    for (;;) {
	/* Does the next entry differ only in the command itself? */
	/* XXX - move into a function that returns bool */
	last_one = next == NULL ||
	    RUNAS_CHANGED(cs, next) || TAGS_CHANGED(cs->tags, next->tags)
#ifdef HAVE_PRIV_SET
	    || cs->privs != next->privs || cs->limitprivs != next->limitprivs
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
	    || cs->role != next->role || cs->type != next->type
#endif /* HAVE_SELINUX */
	    ;

	print_member_json(fp, cs->cmnd, TYPE_COMMAND, last_one, indent);
	if (last_one)
	    break;
	cs = next;
	next = TAILQ_NEXT(cs, entries);
    }
    indent -= 4;
    fprintf(fp, "%*s]\n", indent, "");

    /* Close Cmnd_Spec object. */
    indent -= 4;
    fprintf(fp, "%*s}%s\n", indent, "", TAILQ_NEXT(cs, entries) != NULL ? "," : "");

    *nextp = next;

    debug_return;
}

/*
 * Print a User_Spec in JSON format at the specified indent level.
 */
static void
print_userspec_json(FILE *fp, struct userspec *us, int indent)
{
    struct privilege *priv;
    struct member *m;
    struct cmndspec *cs, *next;
    debug_decl(print_userspec_json, SUDOERS_DEBUG_UTIL)

    /*
     * Each userspec struct may contain multiple privileges for
     * a user.  We export each privilege as a separate User_Spec
     * object for simplicity's sake.
     */
    TAILQ_FOREACH(priv, &us->privileges, entries) {
	/* Open User_Spec object. */
	fprintf(fp, "%*s{\n", indent, "");
	indent += 4;

	/* Print users list. */
	fprintf(fp, "%*s\"User_List\": [\n", indent, "");
	indent += 4;
	TAILQ_FOREACH(m, &us->users, entries) {
	    print_member_json(fp, m, TYPE_USERNAME,
		TAILQ_NEXT(m, entries) == NULL, indent);
	}
	indent -= 4;
	fprintf(fp, "%*s],\n", indent, "");

	/* Print hosts list. */
	fprintf(fp, "%*s\"Host_List\": [\n", indent, "");
	indent += 4;
	TAILQ_FOREACH(m, &priv->hostlist, entries) {
	    print_member_json(fp, m, TYPE_HOSTNAME,
		TAILQ_NEXT(m, entries) == NULL, indent);
	}
	indent -= 4;
	fprintf(fp, "%*s],\n", indent, "");

	/* Print commands. */
	fprintf(fp, "%*s\"Cmnd_Specs\": [\n", indent, "");
	indent += 4;
	TAILQ_FOREACH_SAFE(cs, &priv->cmndlist, entries, next) {
	    print_cmndspec_json(fp, cs, &next, indent);
	}
	indent -= 4;
	fprintf(fp, "%*s]\n", indent, "");

	/* Close User_Spec object. */
	indent -= 4;
	fprintf(fp, "%*s}%s\n", indent, "", TAILQ_NEXT(priv, entries) != NULL ||
	    TAILQ_NEXT(us, entries) != NULL ? "," : "");
    }

    debug_return;
}

static bool
print_userspecs_json(FILE *fp, int indent, bool need_comma)
{
    struct userspec *us;
    debug_decl(print_userspecs_json, SUDOERS_DEBUG_UTIL)

    if (TAILQ_EMPTY(&userspecs))
	debug_return_bool(need_comma);

    fprintf(fp, "%s\n%*s\"User_Specs\": [\n", need_comma ? "," : "", indent, "");
    indent += 4;
    TAILQ_FOREACH(us, &userspecs, entries) {
	print_userspec_json(fp, us, indent);
    }
    indent -= 4;
    fprintf(fp, "%*s]", indent, "");

    debug_return_bool(true);
}

/*
 * Export the parsed sudoers file in JSON format.
 * XXX - ignores strict flag and doesn't pass through quiet flag
 */
bool
export_sudoers(const char *sudoers_path, const char *export_path,
    bool quiet, bool strict)
{
    bool rval = false, need_comma = false;
    const int indent = 4;
    FILE *export_fp = stdout;
    debug_decl(export_sudoers, SUDOERS_DEBUG_UTIL)

    if (strcmp(sudoers_path, "-") == 0) {
	sudoersin = stdin;
	sudoers_path = "stdin";
    } else if ((sudoersin = fopen(sudoers_path, "r")) == NULL) {
	if (!quiet)
	    sudo_warn(U_("unable to open %s"), sudoers_path);
	goto done;
    }
    if (strcmp(export_path, "-") != 0) {
	if (strcmp(sudoers_path, export_path) == 0) {
	    if (!quiet) {
		sudo_warnx(U_("%s: input and output files must be different"),
		    sudoers_path);
	    }
	    goto done;
	}
	if ((export_fp = fopen(export_path, "w")) == NULL) {
	    if (!quiet)
		sudo_warn(U_("unable to open %s"), export_path);
	    goto done;
	}
    }
    init_parser(sudoers_path, quiet);
    if (sudoersparse() && !parse_error) {
	if (!quiet)
	    sudo_warnx(U_("failed to parse %s file, unknown error"), sudoers_path);
	parse_error = true;
	errorfile = sudoers_path;
    }
    rval = !parse_error;

    if (parse_error) {
	if (!quiet) {
	    if (errorlineno != -1)
		sudo_warnx(U_("parse error in %s near line %d\n"),
		    errorfile, errorlineno);
	    else if (errorfile != NULL)
		sudo_warnx(U_("parse error in %s\n"), errorfile);
	}
	goto done;
    }

    /* Open JSON output. */
    putc('{', export_fp);

    /* Dump Defaults in JSON format. */
    need_comma = print_defaults_json(export_fp, indent, need_comma);

    /* Dump Aliases in JSON format. */
    need_comma = print_aliases_json(export_fp, indent, need_comma);

    /* Dump User_Specs in JSON format. */
    print_userspecs_json(export_fp, indent, need_comma);

    /* Close JSON output. */
    fputs("\n}\n", export_fp);

done:
    if (export_fp != NULL) {
	(void)fflush(export_fp);
	if (ferror(export_fp))
	    rval = false;
	if (export_fp != stdout)
	    fclose(export_fp);
    }
    debug_return_bool(rval);
}
