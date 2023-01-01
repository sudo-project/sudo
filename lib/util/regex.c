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
#include <ctype.h>
#include <regex.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "sudo_gettext.h"

static char errbuf[1024];

/*
 * Check pattern for invalid repetition sequences.
 * This is implementation-specific behavior, not all regcomp(3) forbid them.
 * Glibc allows it but uses excessive memory for repeated '+' ops.
 */
static int
check_pattern(const char *pattern)
{
    debug_decl(check_pattern, SUDO_DEBUG_UTIL);
    const char *cp = pattern;
    unsigned long b1, b2 = 0;
    char ch, *ep, prev = '\0';

    while ((ch = *cp++) != '\0') {
	switch (ch) {
	case '\\':
	    if (*cp != '\0') {
		/* Skip escaped character. */
		cp++;
		prev = '\0';
		continue;
	    }
	    break;
	case '?':
	case '*':
	case '+':
	    if (prev == '?' || prev == '*' || prev == '+' || prev == '{' ) {
		/* Invalid repetition operator. */
		debug_return_int(REG_BADRPT);
	    }
	    break;
	case '{':
	    /* Try to match bound: {[0-9]*\?,[0-9]*} */
	    b1 = strtoul(cp, &ep, 10);
	    switch (ep[0]) {
	    case '\\':
		/* glibc allows the comma to be escaped */
		if (ep[1] != ',')
		    break;
		ep++;
		FALLTHROUGH;
	    case ',':
		cp = ep + 1;
		b2 = strtoul(cp, &ep, 10);
		break;
	    }
	    cp = ep;
	    if (*cp == '}') {
		if (b1 > 255 || b2 > 255) {
		    /* Invalid bound value. */
		    debug_return_int(REG_BADBR);
		}
		if (prev == '?' || prev == '*' || prev == '+' || prev == '{' ) {
		    /* Invalid repetition operator. */
		    debug_return_int(REG_BADRPT);
		}
		/* Skip past '}', prev will be set to '{' below */
		cp++;
		break;
	    }
	    prev = '\0';
	    continue;
	}
	prev = ch;
    }

    debug_return_int(0);
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

    /* Limit the length of regular expressions to avoid fuzzer issues. */
    if (strlen(pattern) > 1024) {
	*errstr = N_("regular expression too large");
	debug_return_bool(false);
    }

    /* Check for (?i) to enable case-insensitive matching. */
    cp = pattern[0] == '^' ? pattern + 1 : pattern;
    if (strncmp(cp, "(?i)", 4) == 0) {
	cflags |= REG_ICASE;
	copy = strdup(pattern + 4);
	if (copy == NULL) {
	    *errstr = N_("unable to allocate memory");
	    debug_return_bool(false);
	}
	if (pattern[0] == '^')
	    copy[0] = '^';
	pattern = copy;
    }

    errcode = check_pattern(pattern);
    if (errcode == 0)
	errcode = regcomp(preg, pattern, cflags);
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
