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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_fatal.h"
#include "sudo_util.h"
#include "sudo_json.h"

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
 * Print a quoted JSON string, escaping special characters.
 * Does not support unicode escapes.
 */
static void
json_print_string(struct json_container *json, const char *str)
{
    char ch;

    putc('\"', json->fp);
    while ((ch = *str++) != '\0') {
	switch (ch) {
	case '"':
	case '\\':
	    putc('\\', json->fp);
	    break;
	case '\b':
	    ch = 'b';
	    putc('\\', json->fp);
	    break;
	case '\f':
	    ch = 'f';
	    putc('\\', json->fp);
	    break;
	case '\n':
	    ch = 'n';
	    putc('\\', json->fp);
	    break;
	case '\r':
	    ch = 'r';
	    putc('\\', json->fp);
	    break;
	case '\t':
	    ch = 't';
	    putc('\\', json->fp);
	    break;
	}
	putc(ch, json->fp);
    }
    putc('\"', json->fp);
}

bool
sudo_json_init_v1(struct json_container *json, FILE *fp, int indent)
{
    debug_decl(sudo_json_init, SUDO_DEBUG_UTIL);

    memset(json, 0, sizeof(*json));
    json->fp = fp;
    json->indent_level = indent;
    json->indent_increment = indent;

    debug_return_bool(true);
}

bool
sudo_json_open_object_v1(struct json_container *json, const char *name)
{
    debug_decl(sudo_json_open_object, SUDO_DEBUG_UTIL);

    /* Add comma if we are continuing an object/array. */
    if (json->need_comma)
	putc(',', json->fp);
    putc('\n', json->fp);

    print_indent(json->fp, json->indent_level);

    json_print_string(json, name);
    putc(':', json->fp);
    putc(' ', json->fp);
    putc('{', json->fp);

    json->indent_level += json->indent_increment;
    json->need_comma = false;

    debug_return_bool(true);
}

bool
sudo_json_close_object_v1(struct json_container *json)
{
    debug_decl(sudo_json_close_object, SUDO_DEBUG_UTIL);

    json->indent_level -= json->indent_increment;
    putc('\n', json->fp);
    print_indent(json->fp, json->indent_level);
    putc('}', json->fp);

    debug_return_bool(true);
}

bool
sudo_json_open_array_v1(struct json_container *json, const char *name)
{
    debug_decl(sudo_json_open_array, SUDO_DEBUG_UTIL);

    /* Add comma if we are continuing an object/array. */
    if (json->need_comma)
	putc(',', json->fp);
    putc('\n', json->fp);

    print_indent(json->fp, json->indent_level);

    json_print_string(json, name);
    putc(':', json->fp);
    putc(' ', json->fp);
    putc('[', json->fp);

    json->indent_level += json->indent_increment;
    json->need_comma = false;

    debug_return_bool(true);
}

bool
sudo_json_close_array_v1(struct json_container *json)
{
    debug_decl(sudo_json_close_array, SUDO_DEBUG_UTIL);

    json->indent_level -= json->indent_increment;
    putc('\n', json->fp);
    print_indent(json->fp, json->indent_level);
    putc(']', json->fp);

    debug_return_bool(true);
}

bool
sudo_json_add_value_v1(struct json_container *json, const char *name,
    struct json_value *value)
{
    unsigned int i;
    debug_decl(sudo_json_add_value, SUDO_DEBUG_UTIL);

    /* Add comma if we are continuing an object/array. */
    if (json->need_comma)
	putc(',', json->fp);
    putc('\n', json->fp);
    json->need_comma = true;

    print_indent(json->fp, json->indent_level);

    /* name */
    json_print_string(json, name);
    putc(':', json->fp);
    putc(' ', json->fp);

    /* value */
    switch (value->type) {
    case JSON_STRING:
	json_print_string(json, value->u.string);
	break;
    case JSON_ID:
	fprintf(json->fp, "%u", (unsigned int)value->u.id);
	break;
    case JSON_NUMBER:
	fprintf(json->fp, "%lld", value->u.number);
	break;
    case JSON_NULL:
	fputs("null", json->fp);
	break;
    case JSON_BOOL:
	fputs(value->u.boolean ? "true" : "false", json->fp);
	break;
    case JSON_ARRAY:
	if (value->u.array[0] == NULL || value->u.array[1] == NULL) {
	    putc('[', json->fp);
	    putc(' ', json->fp);
	    if (value->u.array[0] != NULL) {
		json_print_string(json, value->u.array[0]);
		putc(' ', json->fp);
	    }
	    putc(']', json->fp);
	} else  {
	    putc('[', json->fp);
	    putc('\n', json->fp);
	    json->indent_level += json->indent_increment;
	    for (i = 0; value->u.array[i] != NULL; i++) {
		print_indent(json->fp, json->indent_level);
		json_print_string(json, value->u.array[i]);
		if (value->u.array[i + 1] != NULL) {
		    putc(',', json->fp);
		    putc(' ', json->fp);
		}
		putc('\n', json->fp);
	    }
	    json->indent_level -= json->indent_increment;
	    print_indent(json->fp, json->indent_level);
	    putc(']', json->fp);
	}
	break;
    case JSON_OBJECT:
	sudo_fatalx("internal error: can't print JSON_OBJECT");
	break;
    }

    debug_return_bool(true);
}
