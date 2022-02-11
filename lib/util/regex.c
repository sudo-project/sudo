/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2022 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "sudo_gettext.h"

static char errbuf[1024];

/*
 * Like strdup but collapses repeated '?', '*' and '+' ops in a regex.
 * Glibc regcomp() has a bug where it uses excessive memory for repeated
 * '+' ops.  Collapse them to avoid running the fuzzer out of memory.
 */
static char *
dup_pattern(const char *src)
{
    char *dst, *ret;
    char ch, prev = '\0';
    size_t len;
    debug_decl(dup_pattern, SUDO_DEBUG_UTIL);

    len = strlen(src);
    ret = malloc(len + 1);
    if (ret == NULL)
	debug_return_ptr(NULL);

    dst = ret;
    while ((ch = *src++) != '\0') {
	switch (ch) {
	case '\\':
	    if (*src != '\0') {
		*dst++ = '\\';
		*dst++ = *src++;
		prev = '\0';
		continue;
	    }
	    break;
	case '?':
	case '*':
	case '+':
	    if (ch == prev) {
		continue;
	    }
	    break;
	}
	*dst++ = ch;
	prev = ch;
    }
    *dst = '\0';

    debug_return_ptr(ret);
}

/*
 * Wrapper around regcomp() that handles a regex starting with (?i).
 * Avoid using regex_t in the function args so we don't need to
 * include regex.h everywhere.
 */
bool
sudo_regex_compile_v1(void *v, const char *pattern, const char **errstr)
{
    int errcode, cflags = REG_EXTENDED|REG_NOSUB;
    regex_t *preg;
    char *copy = NULL;
    const char *cp;
    regex_t rebuf;
    debug_decl(regex_compile, SUDO_DEBUG_UTIL);

    /* Some callers just want to check the validity of the pattern. */
    preg = v ? v : &rebuf;

    /* Check for (?i) to enable case-insensitive matching. */
    cp = pattern[0] == '^' ? pattern + 1 : pattern;
    if (strncmp(cp, "(?i)", 4) == 0) {
	cflags |= REG_ICASE;
	copy = dup_pattern(pattern + 4);
	if (copy == NULL) {
	    *errstr = N_("unable to allocate memory");
	    debug_return_bool(false);
	}
	if (pattern[0] == '^')
	    copy[0] = '^';
    } else {
	copy = dup_pattern(pattern);
	if (copy == NULL) {
	    *errstr = N_("unable to allocate memory");
	    debug_return_bool(false);
	}
    }

    errcode = regcomp(preg, copy, cflags);
    if (errcode == 0) {
	if (preg == &rebuf)
	    regfree(&rebuf);
    } else {
        regerror(errcode, preg, errbuf, sizeof(errbuf));
        *errstr = errbuf;
    }
    free(copy);

    debug_return_bool(errcode == 0);
}
