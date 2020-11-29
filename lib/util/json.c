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
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#include <string.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_json.h"
#include "sudo_util.h"

/*
 * Double the size of the json buffer.
 * Returns true on success, false if out of memory.
 */
static bool
json_expand_buf(struct json_container *json)
{
    char *newbuf;
    debug_decl(json_expand_buf, SUDO_DEBUG_UTIL);

    if ((newbuf = reallocarray(json->buf, 2, json->bufsize)) == NULL) {
	if (json->memfatal) {
	    sudo_fatalx(U_("%s: %s"),
		__func__, U_("unable to allocate memory"));
	}
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "%s: %s", __func__, "unable to allocate memory");
	debug_return_bool(false);
    }
    json->buf = newbuf;
    json->bufsize *= 2;

    debug_return_bool(true);
}

/*
 * Start a new line and indent unless formatting as minimal JSON.
 * Append "indent" number of blank characters.
 */
static bool
json_new_line(struct json_container *json)
{
    int indent = json->indent_level;
    debug_decl(json_new_line, SUDO_DEBUG_UTIL);

    /* No non-essential white space in minimal mode. */
    if (json->minimal)
	debug_return_bool(true);

    while (json->buflen + 1 + indent >= json->bufsize) {
	if (!json_expand_buf(json))
	    debug_return_bool(false);
    }
    json->buf[json->buflen++] = '\n';
    while (indent--) {
	json->buf[json->buflen++] = ' ';
    }
    json->buf[json->buflen] = '\0';

    debug_return_bool(true);
}

/*
 * Append a string to the JSON buffer, expanding as needed.
 * Does not perform any quoting.
 */
static bool
json_append_buf(struct json_container *json, const char *str)
{
    size_t len;
    debug_decl(json_append_buf, SUDO_DEBUG_UTIL);

    len = strlen(str);
    while (json->buflen + len >= json->bufsize) {
	if (!json_expand_buf(json))
	    debug_return_bool(false);
    }

    memcpy(json->buf + json->buflen, str, len);
    json->buflen += len;
    json->buf[json->buflen] = '\0';

    debug_return_bool(true);
}

/*
 * Append a quoted JSON string, escaping special chars and expanding as needed.
 * Does not support unicode escapes.
 */
static bool
json_append_string(struct json_container *json, const char *str)
{
    char ch;
    debug_decl(json_append_string, SUDO_DEBUG_UTIL);

    if (!json_append_buf(json, "\""))
	    debug_return_bool(false);
    while ((ch = *str++) != '\0') {
	char buf[3], *cp = buf;

	switch (ch) {
	case '"':
	case '\\':
	    *cp++ = '\\';
	    break;
	case '\b':
	    *cp++ = '\\';
	    ch = 'b';
	    break;
	case '\f':
	    *cp++ = '\\';
	    ch = 'f';
	    break;
	case '\n':
	    *cp++ = '\\';
	    ch = 'n';
	    break;
	case '\r':
	    *cp++ = '\\';
	    ch = 'r';
	    break;
	case '\t':
	    *cp++ = '\\';
	    ch = 't';
	    break;
	}
	*cp++ = ch;
	*cp++ = '\0';
	if (!json_append_buf(json, buf))
		debug_return_bool(false);
    }
    if (!json_append_buf(json, "\""))
	    debug_return_bool(false);

    debug_return_bool(true);
}

bool
sudo_json_init_v1(struct json_container *json, int indent, bool minimal,
    bool memfatal)
{
    debug_decl(sudo_json_init, SUDO_DEBUG_UTIL);

    memset(json, 0, sizeof(*json));
    json->indent_level = indent;
    json->indent_increment = indent;
    json->minimal = minimal;
    json->memfatal = memfatal;
    json->buf = malloc(64 * 1024);
    if (json->buf == NULL) {
	if (json->memfatal) {
	    sudo_fatalx(U_("%s: %s"),
		__func__, U_("unable to allocate memory"));
	}
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "%s: %s", __func__, "unable to allocate memory");
	debug_return_bool(false);
    }
    *json->buf = '\0';
    json->bufsize = 64 * 1024;

    debug_return_bool(true);
}

void
sudo_json_free_v1(struct json_container *json)
{
    debug_decl(sudo_json_free, SUDO_DEBUG_UTIL);

    free(json->buf);
    memset(json, 0, sizeof(*json));

    debug_return;
}

bool
sudo_json_open_object_v1(struct json_container *json, const char *name)
{
    debug_decl(sudo_json_open_object, SUDO_DEBUG_UTIL);

    /* Add comma if we are continuing an object/array. */
    if (json->need_comma) {
	if (!json_append_buf(json, ","))
	    debug_return_bool(false);
    }
    if (!json_new_line(json))
	debug_return_bool(false);

    if (name != NULL) {
	json_append_string(json, name);
	if (!json_append_buf(json, json->minimal ? ":{" : ": {"))
	    debug_return_bool(false);
    } else {
	if (!json_append_buf(json, "{"))
	    debug_return_bool(false);
    }

    json->indent_level += json->indent_increment;
    json->need_comma = false;

    debug_return_bool(true);
}

bool
sudo_json_close_object_v1(struct json_container *json)
{
    debug_decl(sudo_json_close_object, SUDO_DEBUG_UTIL);

    if (!json->minimal) {
	json->indent_level -= json->indent_increment;
	if (!json_new_line(json))
	    debug_return_bool(false);
    }
    if (!json_append_buf(json, "}"))
	debug_return_bool(false);

    debug_return_bool(true);
}

bool
sudo_json_open_array_v1(struct json_container *json, const char *name)
{
    debug_decl(sudo_json_open_array, SUDO_DEBUG_UTIL);

    /* Add comma if we are continuing an object/array. */
    if (json->need_comma) {
	if (!json_append_buf(json, ","))
	    debug_return_bool(false);
    }
    if (!json_new_line(json))
	debug_return_bool(false);

    if (name != NULL) {
	json_append_string(json, name);
	if (!json_append_buf(json, json->minimal ? ":[" : ": ["))
	    debug_return_bool(false);
    } else {
	if (!json_append_buf(json, "["))
	    debug_return_bool(false);
    }

    json->indent_level += json->indent_increment;
    json->need_comma = false;

    debug_return_bool(true);
}

bool
sudo_json_close_array_v1(struct json_container *json)
{
    debug_decl(sudo_json_close_array, SUDO_DEBUG_UTIL);

    if (!json->minimal) {
	json->indent_level -= json->indent_increment;
	if (!json_new_line(json))
	    debug_return_bool(false);
    }
    if (!json_append_buf(json, "]"))
	debug_return_bool(false);

    debug_return_bool(true);
}

static bool
sudo_json_add_value_int(struct json_container *json, const char *name,
    struct json_value *value, bool as_object)
{
    char numbuf[(((sizeof(long long) * 8) + 2) / 3) + 2];
    debug_decl(sudo_json_add_value, SUDO_DEBUG_UTIL);

    /* Add comma if we are continuing an object/array. */
    if (json->need_comma) {
	if (!json_append_buf(json, ","))
	    debug_return_bool(false);
    }
    if (!json_new_line(json))
	debug_return_bool(false);
    json->need_comma = true;

    if (as_object) {
	if (!json_append_buf(json, json->minimal ? "{" : "{ "))
	    debug_return_bool(false);
    }

    /* name */
    if (name != NULL) {
	if (!json_append_string(json, name))
	    debug_return_bool(false);
	if (!json_append_buf(json, json->minimal ? ":" : ": "))
	    debug_return_bool(false);
    }

    /* value */
    switch (value->type) {
    case JSON_STRING:
	if (!json_append_string(json, value->u.string))
	    debug_return_bool(false);
	break;
    case JSON_ID:
	snprintf(numbuf, sizeof(numbuf), "%u", (unsigned int)value->u.id);
	if (!json_append_buf(json, numbuf))
	    debug_return_bool(false);
	break;
    case JSON_NUMBER:
	snprintf(numbuf, sizeof(numbuf), "%lld", value->u.number);
	if (!json_append_buf(json, numbuf))
	    debug_return_bool(false);
	break;
    case JSON_NULL:
	if (!json_append_buf(json, "null"))
	    debug_return_bool(false);
	break;
    case JSON_BOOL:
	if (!json_append_buf(json, value->u.boolean ? "true" : "false"))
	    debug_return_bool(false);
	break;
    case JSON_ARRAY:
	sudo_fatalx("internal error: can't print JSON_ARRAY");
	break;
    case JSON_OBJECT:
	sudo_fatalx("internal error: can't print JSON_OBJECT");
	break;
    }

    if (as_object) {
	if (!json_append_buf(json, json->minimal ? "}" : " }"))
	    debug_return_bool(false);
    }

    debug_return_bool(true);
}

bool
sudo_json_add_value_v1(struct json_container *json, const char *name,
    struct json_value *value)
{
    return sudo_json_add_value_int(json, name, value, false);
}

bool
sudo_json_add_value_as_object_v1(struct json_container *json, const char *name,
    struct json_value *value)
{
    return sudo_json_add_value_int(json, name, value, true);
}

char *
sudo_json_get_buf_v1(struct json_container *json)
{
    return json->buf;
}

unsigned int
sudo_json_get_len_v1(struct json_container *json)
{
    return json->buflen;
}
