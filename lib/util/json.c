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
json_expand_buf(struct json_container *jsonc)
{
    char *newbuf;
    debug_decl(json_expand_buf, SUDO_DEBUG_UTIL);

    if ((newbuf = reallocarray(jsonc->buf, 2, jsonc->bufsize)) == NULL) {
	if (jsonc->memfatal) {
	    sudo_fatalx(U_("%s: %s"),
		__func__, U_("unable to allocate memory"));
	}
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "%s: %s", __func__, "unable to allocate memory");
	debug_return_bool(false);
    }
    jsonc->buf = newbuf;
    jsonc->bufsize *= 2;

    debug_return_bool(true);
}

/*
 * Start a new line and indent unless formatting as minimal JSON.
 * Append "indent" number of blank characters.
 */
static bool
json_new_line(struct json_container *jsonc)
{
    int indent = jsonc->indent_level;
    debug_decl(json_new_line, SUDO_DEBUG_UTIL);

    /* No non-essential white space in minimal mode. */
    if (jsonc->minimal)
	debug_return_bool(true);

    while (jsonc->buflen + 1 + indent >= jsonc->bufsize) {
	if (!json_expand_buf(jsonc))
	    debug_return_bool(false);
    }
    jsonc->buf[jsonc->buflen++] = '\n';
    while (indent--) {
	jsonc->buf[jsonc->buflen++] = ' ';
    }
    jsonc->buf[jsonc->buflen] = '\0';

    debug_return_bool(true);
}

/*
 * Append a string to the JSON buffer, expanding as needed.
 * Does not perform any quoting.
 */
static bool
json_append_buf(struct json_container *jsonc, const char *str)
{
    size_t len;
    debug_decl(json_append_buf, SUDO_DEBUG_UTIL);

    len = strlen(str);
    while (jsonc->buflen + len >= jsonc->bufsize) {
	if (!json_expand_buf(jsonc))
	    debug_return_bool(false);
    }

    memcpy(jsonc->buf + jsonc->buflen, str, len);
    jsonc->buflen += len;
    jsonc->buf[jsonc->buflen] = '\0';

    debug_return_bool(true);
}

/*
 * Append a quoted JSON string, escaping special chars and expanding as needed.
 * Does not support unicode escapes.
 */
static bool
json_append_string(struct json_container *jsonc, const char *str)
{
    char ch;
    debug_decl(json_append_string, SUDO_DEBUG_UTIL);

    if (!json_append_buf(jsonc, "\""))
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
	if (!json_append_buf(jsonc, buf))
		debug_return_bool(false);
    }
    if (!json_append_buf(jsonc, "\""))
	    debug_return_bool(false);

    debug_return_bool(true);
}

bool
sudo_json_init_v1(struct json_container *jsonc, int indent, bool minimal,
    bool memfatal)
{
    debug_decl(sudo_json_init, SUDO_DEBUG_UTIL);

    memset(jsonc, 0, sizeof(*jsonc));
    jsonc->indent_level = indent;
    jsonc->indent_increment = indent;
    jsonc->minimal = minimal;
    jsonc->memfatal = memfatal;
    jsonc->buf = malloc(64 * 1024);
    if (jsonc->buf == NULL) {
	if (jsonc->memfatal) {
	    sudo_fatalx(U_("%s: %s"),
		__func__, U_("unable to allocate memory"));
	}
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
	    "%s: %s", __func__, "unable to allocate memory");
	debug_return_bool(false);
    }
    *jsonc->buf = '\0';
    jsonc->bufsize = 64 * 1024;

    debug_return_bool(true);
}

void
sudo_json_free_v1(struct json_container *jsonc)
{
    debug_decl(sudo_json_free, SUDO_DEBUG_UTIL);

    free(jsonc->buf);
    memset(jsonc, 0, sizeof(*jsonc));

    debug_return;
}

bool
sudo_json_open_object_v1(struct json_container *jsonc, const char *name)
{
    debug_decl(sudo_json_open_object, SUDO_DEBUG_UTIL);

    /* Add comma if we are continuing an object/array. */
    if (jsonc->need_comma) {
	if (!json_append_buf(jsonc, ","))
	    debug_return_bool(false);
    }
    if (!json_new_line(jsonc))
	debug_return_bool(false);

    if (name != NULL) {
	json_append_string(jsonc, name);
	if (!json_append_buf(jsonc, jsonc->minimal ? ":{" : ": {"))
	    debug_return_bool(false);
    } else {
	if (!json_append_buf(jsonc, "{"))
	    debug_return_bool(false);
    }

    jsonc->indent_level += jsonc->indent_increment;
    jsonc->need_comma = false;

    debug_return_bool(true);
}

bool
sudo_json_close_object_v1(struct json_container *jsonc)
{
    debug_decl(sudo_json_close_object, SUDO_DEBUG_UTIL);

    if (!jsonc->minimal) {
	jsonc->indent_level -= jsonc->indent_increment;
	if (!json_new_line(jsonc))
	    debug_return_bool(false);
    }
    if (!json_append_buf(jsonc, "}"))
	debug_return_bool(false);

    debug_return_bool(true);
}

bool
sudo_json_open_array_v1(struct json_container *jsonc, const char *name)
{
    debug_decl(sudo_json_open_array, SUDO_DEBUG_UTIL);

    /* Add comma if we are continuing an object/array. */
    if (jsonc->need_comma) {
	if (!json_append_buf(jsonc, ","))
	    debug_return_bool(false);
    }
    if (!json_new_line(jsonc))
	debug_return_bool(false);

    if (name != NULL) {
	json_append_string(jsonc, name);
	if (!json_append_buf(jsonc, jsonc->minimal ? ":[" : ": ["))
	    debug_return_bool(false);
    } else {
	if (!json_append_buf(jsonc, "["))
	    debug_return_bool(false);
    }

    jsonc->indent_level += jsonc->indent_increment;
    jsonc->need_comma = false;

    debug_return_bool(true);
}

bool
sudo_json_close_array_v1(struct json_container *jsonc)
{
    debug_decl(sudo_json_close_array, SUDO_DEBUG_UTIL);

    if (!jsonc->minimal) {
	jsonc->indent_level -= jsonc->indent_increment;
	if (!json_new_line(jsonc))
	    debug_return_bool(false);
    }
    if (!json_append_buf(jsonc, "]"))
	debug_return_bool(false);

    debug_return_bool(true);
}

static bool
sudo_json_add_value_int(struct json_container *jsonc, const char *name,
    struct json_value *value, bool as_object)
{
    char numbuf[(((sizeof(long long) * 8) + 2) / 3) + 2];
    debug_decl(sudo_json_add_value, SUDO_DEBUG_UTIL);

    /* Add comma if we are continuing an object/array. */
    if (jsonc->need_comma) {
	if (!json_append_buf(jsonc, ","))
	    debug_return_bool(false);
    }
    if (!json_new_line(jsonc))
	debug_return_bool(false);
    jsonc->need_comma = true;

    if (as_object) {
	if (!json_append_buf(jsonc, jsonc->minimal ? "{" : "{ "))
	    debug_return_bool(false);
    }

    /* name */
    if (name != NULL) {
	if (!json_append_string(jsonc, name))
	    debug_return_bool(false);
	if (!json_append_buf(jsonc, jsonc->minimal ? ":" : ": "))
	    debug_return_bool(false);
    }

    /* value */
    switch (value->type) {
    case JSON_STRING:
	if (!json_append_string(jsonc, value->u.string))
	    debug_return_bool(false);
	break;
    case JSON_ID:
	snprintf(numbuf, sizeof(numbuf), "%u", (unsigned int)value->u.id);
	if (!json_append_buf(jsonc, numbuf))
	    debug_return_bool(false);
	break;
    case JSON_NUMBER:
	snprintf(numbuf, sizeof(numbuf), "%lld", value->u.number);
	if (!json_append_buf(jsonc, numbuf))
	    debug_return_bool(false);
	break;
    case JSON_NULL:
	if (!json_append_buf(jsonc, "null"))
	    debug_return_bool(false);
	break;
    case JSON_BOOL:
	if (!json_append_buf(jsonc, value->u.boolean ? "true" : "false"))
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
	if (!json_append_buf(jsonc, jsonc->minimal ? "}" : " }"))
	    debug_return_bool(false);
    }

    debug_return_bool(true);
}

bool
sudo_json_add_value_v1(struct json_container *jsonc, const char *name,
    struct json_value *value)
{
    return sudo_json_add_value_int(jsonc, name, value, false);
}

bool
sudo_json_add_value_as_object_v1(struct json_container *jsonc, const char *name,
    struct json_value *value)
{
    return sudo_json_add_value_int(jsonc, name, value, true);
}

char *
sudo_json_get_buf_v1(struct json_container *jsonc)
{
    return jsonc->buf;
}

unsigned int
sudo_json_get_len_v1(struct json_container *jsonc)
{
    return jsonc->buflen;
}
