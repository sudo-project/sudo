/*
 * Copyright (c) 2011 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _FNMATCH_H
#define _FNMATCH_H

#define	FNM_NOMATCH	1		/* String does not match pattern */

#define	FNM_PATHNAME	(1 << 0)	/* Globbing chars don't match '/' */
#define	FNM_PERIOD	(1 << 1)	/* Leading '.' in string must exactly */
#define	FNM_NOESCAPE	(1 << 2)	/* Backslash treated as ordinary char */
#define	FNM_LEADING_DIR	(1 << 3)	/* Only match the leading directory */
#define	FNM_CASEFOLD	(1 << 4)	/* Case insensitive matching */

int fnmatch __P((const char *pattern, const char *string, int flags));

#endif /* _FNMATCH_H */
