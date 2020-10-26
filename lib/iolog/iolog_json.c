/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2020 Todd C. Miller <Todd.Miller@sudo.ws>
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
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <time.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_eventlog.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_iolog.h"
#include "sudo_util.h"

#include "iolog_json.h"

struct json_stack {
    unsigned int depth;
    unsigned int maxdepth;
    struct json_object *frames[64];
};
#define JSON_STACK_INTIALIZER(s) { 0, nitems((s).frames) };

static bool
json_store_columns(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_columns, SUDO_DEBUG_UTIL);

    if (item->u.number < 1 || item->u.number > INT_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "tty cols %lld: out of range", item->u.number);
	evlog->columns = 0;
	debug_return_bool(false);
    }

    evlog->columns = item->u.number;
    debug_return_bool(true);
}

static bool
json_store_command(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_command, SUDO_DEBUG_UTIL);

    /*
     * Note: struct eventlog must store command + args.
     *       We don't have argv yet so we append the args later.
     */
    evlog->command = item->u.string;
    item->u.string = NULL;
    debug_return_bool(true);
}

static bool
json_store_lines(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_lines, SUDO_DEBUG_UTIL);

    if (item->u.number < 1 || item->u.number > INT_MAX) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "tty lines %lld: out of range", item->u.number);
	evlog->lines = 0;
	debug_return_bool(false);
    }

    evlog->lines = item->u.number;
    debug_return_bool(true);
}

char **
json_array_to_strvec(struct json_object *array)
{
    struct json_item *item;
    int len = 0;
    char **ret;
    debug_decl(json_array_to_strvec, SUDO_DEBUG_UTIL);

    TAILQ_FOREACH(item, &array->items, entries) {
	/* Can only convert arrays of string. */
	if (item->type != JSON_STRING) {
	    sudo_warnx(U_("expected JSON_STRING, got %d"), item->type);
	    debug_return_ptr(NULL);
	}
	len++;
    }
    if ((ret = reallocarray(NULL, len + 1, sizeof(char *))) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_ptr(NULL);
    }
    len = 0;
    TAILQ_FOREACH(item, &array->items, entries) {
	ret[len++] = item->u.string;
	item->u.string = NULL;
    }
    ret[len] = NULL;

    debug_return_ptr(ret);
}

static bool
json_store_runargv(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_runargv, SUDO_DEBUG_UTIL);

    evlog->argv = json_array_to_strvec(&item->u.child);

    debug_return_bool(evlog->argv != NULL);
}

static bool
json_store_runenv(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_runenv, SUDO_DEBUG_UTIL);

    evlog->envp = json_array_to_strvec(&item->u.child);

    debug_return_bool(evlog->envp != NULL);
}

static bool
json_store_rungid(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_rungid, SUDO_DEBUG_UTIL);

    evlog->rungid = (gid_t)item->u.number;
    debug_return_bool(true);
}

static bool
json_store_rungroup(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_rungroup, SUDO_DEBUG_UTIL);

    evlog->rungroup = item->u.string;
    item->u.string = NULL;
    debug_return_bool(true);
}

static bool
json_store_runuid(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_runuid, SUDO_DEBUG_UTIL);

    evlog->runuid = (uid_t)item->u.number;
    debug_return_bool(true);
}

static bool
json_store_runuser(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_runuser, SUDO_DEBUG_UTIL);

    evlog->runuser = item->u.string;
    item->u.string = NULL;
    debug_return_bool(true);
}

static bool
json_store_runchroot(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_runchroot, SUDO_DEBUG_UTIL);

    evlog->runchroot = item->u.string;
    item->u.string = NULL;
    debug_return_bool(true);
}

static bool
json_store_runcwd(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_runcwd, SUDO_DEBUG_UTIL);

    evlog->runcwd = item->u.string;
    item->u.string = NULL;
    debug_return_bool(true);
}

static bool
json_store_submitcwd(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_submitcwd, SUDO_DEBUG_UTIL);

    evlog->cwd = item->u.string;
    item->u.string = NULL;
    debug_return_bool(true);
}

static bool
json_store_submithost(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_submithost, SUDO_DEBUG_UTIL);

    evlog->submithost = item->u.string;
    item->u.string = NULL;
    debug_return_bool(true);
}

static bool
json_store_submituser(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_submituser, SUDO_DEBUG_UTIL);

    evlog->submituser = item->u.string;
    item->u.string = NULL;
    debug_return_bool(true);
}

static bool
json_store_timestamp(struct json_item *item, struct eventlog *evlog)
{
    struct json_object *object;
    debug_decl(json_store_timestamp, SUDO_DEBUG_UTIL);

    object = &item->u.child;
    TAILQ_FOREACH(item, &object->items, entries) {
	if (item->type != JSON_NUMBER)
	    continue;
	if (strcmp(item->name, "seconds") == 0) {
	    evlog->submit_time.tv_sec = item->u.number;
	    continue;
	}
	if (strcmp(item->name, "nanoseconds") == 0) {
	    evlog->submit_time.tv_nsec = item->u.number;
	    continue;
	}
    }
    debug_return_bool(true);
}

static bool
json_store_ttyname(struct json_item *item, struct eventlog *evlog)
{
    debug_decl(json_store_ttyname, SUDO_DEBUG_UTIL);

    evlog->ttyname = item->u.string;
    item->u.string = NULL;
    debug_return_bool(true);
}

static struct iolog_json_key {
    const char *name;
    enum json_value_type type;
    bool (*setter)(struct json_item *, struct eventlog *);
} iolog_json_keys[] = {
    { "columns", JSON_NUMBER, json_store_columns },
    { "command", JSON_STRING, json_store_command },
    { "lines", JSON_NUMBER, json_store_lines },
    { "runargv", JSON_ARRAY, json_store_runargv },
    { "runenv", JSON_ARRAY, json_store_runenv },
    { "rungid", JSON_ID, json_store_rungid },
    { "rungroup", JSON_STRING, json_store_rungroup },
    { "runuid", JSON_ID, json_store_runuid },
    { "runuser", JSON_STRING, json_store_runuser },
    { "runchroot", JSON_STRING, json_store_runchroot },
    { "runcwd", JSON_STRING, json_store_runcwd },
    { "submitcwd", JSON_STRING, json_store_submitcwd },
    { "submithost", JSON_STRING, json_store_submithost },
    { "submituser", JSON_STRING, json_store_submituser },
    { "timestamp", JSON_OBJECT, json_store_timestamp },
    { "ttyname", JSON_STRING, json_store_ttyname },
    { NULL }
};

static struct json_item *
new_json_item(enum json_value_type type, char *name, unsigned int lineno)
{
    struct json_item *item;
    debug_decl(new_json_item, SUDO_DEBUG_UTIL);

    if ((item = malloc(sizeof(*item))) == NULL)  {
	sudo_warnx(U_("%s: %s"), __func__,
	    U_("unable to allocate memory"));
	debug_return_ptr(NULL);
    }
    item->name = name;
    item->type = type;
    item->lineno = lineno;

    debug_return_ptr(item);
}

static char *
json_parse_string(char **strp)
{
    char *dst, *end, *ret, *src = *strp + 1;
    size_t len;
    debug_decl(json_parse_string, SUDO_DEBUG_UTIL);

    for (end = src; *end != '"' && *end != '\0'; end++) {
	if (end[0] == '\\' && end[1] == '"')
	    end++;
    }
    if (*end != '"') {
	sudo_warnx("%s", U_("missing double quote in name"));
	debug_return_str(NULL);
    }
    len = (size_t)(end - src);

    /* Copy string, flattening escaped chars. */
    dst = ret = malloc(len + 1);
    if (dst == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    while (src < end) {
	char ch = *src++;
	/* TODO: handle unicode escapes */
	if (ch == '\\') {
	    switch (*src) {
	    case 'b':
		ch = '\b';
		break;
	    case 'f':
		ch = '\f';
		break;
	    case 'n':
		ch = '\n';
		break;
	    case 'r':
		ch = '\r';
		break;
	    case 't':
		ch = '\t';
		break;
	    case '"':
	    case '\\':
	    default:
		/* Note: a bare \ at the end of a string will be removed. */
		ch = *src;
		break;
	    }
	    src++;
	}
	*dst++ = ch;
    }
    *dst = '\0';

    /* Trim trailing whitespace. */
    do {
	end++;
    } while (isspace((unsigned char)*end));
    *strp = end;

    debug_return_str(ret);
}

void
free_json_items(struct json_item_list *items)
{
    struct json_item *item;
    debug_decl(free_json_items, SUDO_DEBUG_UTIL);

    while ((item = TAILQ_FIRST(items)) != NULL) {
	TAILQ_REMOVE(items, item, entries);
	switch (item->type) {
	case JSON_STRING:
	    free(item->u.string);
	    break;
	case JSON_ARRAY:
	case JSON_OBJECT:
	    free_json_items(&item->u.child.items);
	    break;
	default:
	    break;
	}
	free(item->name);
	free(item);
    }

    debug_return;
}

static bool
iolog_parse_json_object(struct json_object *object, struct eventlog *evlog)
{
    struct json_item *item;
    bool ret = false;
    debug_decl(iolog_parse_json_object, SUDO_DEBUG_UTIL);

    /* First object holds all the actual data. */
    item = TAILQ_FIRST(&object->items);
    if (item->type != JSON_OBJECT) {
	sudo_warnx(U_("expected JSON_OBJECT, got %d"), item->type);
	goto done;
    }
    object = &item->u.child;

    TAILQ_FOREACH(item, &object->items, entries) {
	struct iolog_json_key *key;

	/* lookup name */
	for (key = iolog_json_keys; key->name != NULL; key++) {
	    if (strcmp(item->name, key->name) == 0)
		break;
	}
	if (key->name == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
		"%s: unknown key %s", __func__, item->name);
	} else if (key->type != item->type &&
		(key->type != JSON_ID || item->type != JSON_NUMBER)) {
	    sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
		"%s: key mismatch %s type %d, expected %d", __func__,
		item->name, item->type, key->type);
	    goto done;
	} else {
	    /* Matched name and type. */
	    if (!key->setter(item, evlog)) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "unable to store %s", key->name);
		goto done;
	    }
	}
    }

    /* Merge cmd and argv as sudoreplay expects. */
    if (evlog->command != NULL && evlog->argv != NULL) {
	size_t len = strlen(evlog->command) + 1;
	char *newcmd;
	int ac;

	/* Skip argv[0], we use evlog->command instead. */
	for (ac = 1; evlog->argv[ac] != NULL; ac++)
	    len += strlen(evlog->argv[ac]) + 1;

	if ((newcmd = malloc(len)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}

	/* TODO: optimize this. */
	if (strlcpy(newcmd, evlog->command, len) >= len)
	    sudo_fatalx(U_("internal error, %s overflow"), __func__);
	for (ac = 1; evlog->argv[ac] != NULL; ac++) {
	    if (strlcat(newcmd, " ", len) >= len)
		sudo_fatalx(U_("internal error, %s overflow"), __func__);
	    if (strlcat(newcmd, evlog->argv[ac], len) >= len)
		sudo_fatalx(U_("internal error, %s overflow"), __func__);
	}

	free(evlog->command);
	evlog->command = newcmd;
    }

    ret = true;

done:
    debug_return_bool(ret);
}

static bool
json_insert_bool(struct json_item_list *items, char *name, bool value,
    unsigned int lineno)
{
    struct json_item *item;
    debug_decl(json_insert_bool, SUDO_DEBUG_UTIL);

    if ((item = new_json_item(JSON_BOOL, name, lineno)) == NULL)
	debug_return_bool(false);
    item->u.boolean = value;
    TAILQ_INSERT_TAIL(items, item, entries);

    debug_return_bool(true);
}

static bool
json_insert_null(struct json_item_list *items, char *name, unsigned int lineno)
{
    struct json_item *item;
    debug_decl(json_insert_null, SUDO_DEBUG_UTIL);

    if ((item = new_json_item(JSON_NULL, name, lineno)) == NULL)
	debug_return_bool(false);
    TAILQ_INSERT_TAIL(items, item, entries);

    debug_return_bool(true);
}

static bool
json_insert_num(struct json_item_list *items, char *name, long long value,
    unsigned int lineno)
{
    struct json_item *item;
    debug_decl(json_insert_num, SUDO_DEBUG_UTIL);

    if ((item = new_json_item(JSON_NUMBER, name, lineno)) == NULL)
	debug_return_bool(false);
    item->u.number = value;
    TAILQ_INSERT_TAIL(items, item, entries);

    debug_return_bool(true);
}

static bool
json_insert_str(struct json_item_list *items, char *name, char **strp,
    unsigned int lineno)
{
    struct json_item *item;
    debug_decl(json_insert_str, SUDO_DEBUG_UTIL);

    if ((item = new_json_item(JSON_STRING, name, lineno)) == NULL)
	debug_return_bool(false);
    item->u.string = json_parse_string(strp);
    if (item->u.string == NULL) {
	free(item);
	debug_return_bool(false);
    }
    TAILQ_INSERT_TAIL(items, item, entries);

    debug_return_bool(true);
}

static struct json_object *
json_stack_push(struct json_stack *stack, struct json_item_list *items,
    struct json_object *frame, enum json_value_type type, char *name,
    unsigned int lineno)
{
    struct json_item *item;
    debug_decl(iolog_parse_loginfo_json, SUDO_DEBUG_UTIL);

    /* Allocate a new item and insert it into the list. */
    if ((item = new_json_item(type, name, lineno)) == NULL)
	debug_return_ptr(NULL);
    TAILQ_INIT(&item->u.child.items);
    item->u.child.parent = item;
    TAILQ_INSERT_TAIL(items, item, entries);

    /* Push the current frame onto the stack. */
    if (stack->depth == stack->maxdepth)
	sudo_fatalx(U_("internal error, %s overflow"), __func__);
    stack->frames[stack->depth++] = frame;

    /* Return the new frame */
    debug_return_ptr(&item->u.child);
}

/* Only expect a value if a name is defined or we are in an array. */
#define expect_value (name != NULL || (frame->parent != NULL && frame->parent->type == JSON_ARRAY))

bool
iolog_parse_json(FILE *fp, const char *filename, struct json_object *root)
{
    struct json_object *frame = root;
    struct json_stack stack = JSON_STACK_INTIALIZER(stack);
    unsigned int lineno = 0;
    char *name = NULL;
    char *buf = NULL;
    size_t bufsize = 0;
    ssize_t len;
    bool ret = false;
    long long num;
    char ch;
    debug_decl(iolog_parse_json, SUDO_DEBUG_UTIL);

    root->parent = NULL;
    TAILQ_INIT(&root->items);

    while ((len = getdelim(&buf, &bufsize, '\n', fp)) != -1) {
	char *cp = buf;
	char *ep = buf + len - 1;

	lineno++;

	/* Trim trailing whitespace. */
	while (ep > cp && isspace((unsigned char)*ep))
	    ep--;
	ep[1] = '\0';

	for (;;) {
	    const char *errstr;

	    /* Trim leading whitespace, skip blank lines. */
	    while (isspace((unsigned char)*cp))
		cp++;

	    /* Strip out commas.  TODO: require commas between values. */
	    if (*cp == ',') {
		cp++;
		while (isspace((unsigned char)*cp))
		    cp++;
	    }

	    if (*cp == '\0')
		break;

	    switch (*cp) {
	    case '{':
		cp++;
		frame = json_stack_push(&stack, &frame->items, frame,
		    JSON_OBJECT, name, lineno);
		if (frame == NULL)
		    goto parse_error;
		name = NULL;
		break;
	    case '}':
		cp++;
		if (stack.depth == 0 || frame->parent == NULL ||
			frame->parent->type != JSON_OBJECT) {
		    sudo_warnx("%s", U_("unmatched close brace"));
		    goto parse_error;
		}
		frame = stack.frames[--stack.depth];
		break;
	    case '[':
		cp++;
		if (frame->parent == NULL) {
		    /* Must have an enclosing object. */
		    sudo_warnx("%s", U_("unexpected array"));
		    goto parse_error;
		}
		frame = json_stack_push(&stack, &frame->items, frame,
		    JSON_ARRAY, name, lineno);
		if (frame == NULL)
		    goto parse_error;
		name = NULL;
		break;
	    case ']':
		cp++;
		if (stack.depth == 0 || frame->parent == NULL ||
			frame->parent->type != JSON_ARRAY) {
		    sudo_warnx("%s", U_("unmatched close bracket"));
		    goto parse_error;
		}
		frame = stack.frames[--stack.depth];
		break;
	    case '"':
		if (frame->parent == NULL) {
		    /* Must have an enclosing object. */
		    sudo_warnx("%s", U_("unexpected string"));
		    goto parse_error;
		}

		if (!expect_value) {
		    /* Parse "name": */
		    if ((name = json_parse_string(&cp)) == NULL)
			goto parse_error;
		    /* TODO: allow colon on next line? */
		    if (*cp++ != ':') {
			sudo_warnx("%s", U_("missing colon after name"));
			goto parse_error;
		    }
		} else {
		    if (!json_insert_str(&frame->items, name, &cp, lineno))
			goto parse_error;
		    name = NULL;
		}
		break;
	    case 't':
		if (!expect_value) {
		    sudo_warnx("%s", U_("unexpected boolean"));
		    goto parse_error;
		}
		if (strncmp(cp, "true", sizeof("true") - 1) != 0)
		    goto parse_error;
		cp += sizeof("true") - 1;
		if (*cp != ',' && !isspace((unsigned char)*cp) && *cp != '\0')
		    goto parse_error;

		if (!json_insert_bool(&frame->items, name, true, lineno))
		    goto parse_error;
		name = NULL;
		break;
	    case 'f':
		if (!expect_value) {
		    sudo_warnx("%s", U_("unexpected boolean"));
		    goto parse_error;
		}
		if (strncmp(cp, "false", sizeof("false") - 1) != 0)
		    goto parse_error;
		cp += sizeof("false") - 1;
		if (*cp != ',' && !isspace((unsigned char)*cp) && *cp != '\0')
		    goto parse_error;

		if (!json_insert_bool(&frame->items, name, false, lineno))
		    goto parse_error;
		name = NULL;
		break;
	    case 'n':
		if (!expect_value) {
		    sudo_warnx("%s", U_("unexpected boolean"));
		    goto parse_error;
		}
		if (strncmp(cp, "null", sizeof("null") - 1) != 0)
		    goto parse_error;
		cp += sizeof("null") - 1;
		if (*cp != ',' && !isspace((unsigned char)*cp) && *cp != '\0')
		    goto parse_error;

		if (!json_insert_null(&frame->items, name, lineno))
		    goto parse_error;
		name = NULL;
		break;
	    case '+': case '-': case '0': case '1': case '2': case '3':
	    case '4': case '5': case '6': case '7': case '8': case '9':
		if (!expect_value) {
		    sudo_warnx("%s", U_("unexpected number"));
		    goto parse_error;
		}
		/* XXX - strtonumx() would be simpler here. */
		len = strcspn(cp, " \f\n\r\t\v,");
		ch = cp[len];
		cp[len] = '\0';
		num = sudo_strtonum(cp, LLONG_MIN, LLONG_MAX, &errstr);
		if (errstr != NULL) {
		    sudo_warnx(U_("%s: %s"), cp, U_(errstr));
		    goto parse_error;
		}
		cp += len;
		*cp = ch;

		if (!json_insert_num(&frame->items, name, num, lineno))
		    goto parse_error;
		name = NULL;
		break;
	    default:
		goto parse_error;
	    }
	}
    }
    if (stack.depth != 0) {
	frame = stack.frames[stack.depth - 1];
	if (frame->parent == NULL || frame->parent->type == JSON_OBJECT)
	    sudo_warnx("%s", U_("unmatched close brace"));
	else
	    sudo_warnx("%s", U_("unmatched close bracket"));
	goto parse_error;
    }

    ret = true;
    goto done;

parse_error:
    sudo_warnx(U_("%s:%u unable to parse \"%s\""), filename, lineno, buf);
done:
    free(buf);
    free(name);
    if (!ret)
	free_json_items(&root->items);

    debug_return_bool(ret);
}

bool
iolog_parse_loginfo_json(FILE *fp, const char *iolog_dir, struct eventlog *evlog)
{
    struct json_object root;
    bool ret = false;
    debug_decl(iolog_parse_loginfo_json, SUDO_DEBUG_UTIL);

    if (iolog_parse_json(fp, iolog_dir, &root)) {
	/* Walk the stack and parse entries. */
	ret = iolog_parse_json_object(&root, evlog);

	/* Cleanup. */
	free_json_items(&root.items);
    }

    debug_return_bool(ret);
}
