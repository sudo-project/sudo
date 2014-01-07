/*
 * Copyright (c) 2010-2014 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#include "missing.h"
#include "sudo_debug.h"
#include "sudo_util.h"

int
atobool(const char *str)
{
    debug_decl(atobool, SUDO_DEBUG_UTIL)

    switch (*str) {
	case '0':
	case '1':
	    if (str[1] == '\0')
		debug_return_int(*str - '0');
	    break;
	case 'y':
	case 'Y':
	    if (strcasecmp(str, "yes") == 0)
		debug_return_int(1);
	    break;
	case 't':
	case 'T':
	    if (strcasecmp(str, "true") == 0)
		debug_return_int(1);
	    break;
	case 'o':
	case 'O':
	    if (strcasecmp(str, "on") == 0)
		debug_return_int(1);
	    if (strcasecmp(str, "off") == 0)
		debug_return_int(0);
	    break;
	case 'n':
	case 'N':
	    if (strcasecmp(str, "no") == 0)
		debug_return_int(0);
	    break;
	case 'f':
	case 'F':
	    if (strcasecmp(str, "false") == 0)
		debug_return_int(0);
	    break;
    }
    debug_return_int(-1);
}
