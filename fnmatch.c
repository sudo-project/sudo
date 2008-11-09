/*
 * Copyright (c) 2008 Todd C. Miller <Todd.Miller@courtesan.com>
 * Copyright (c) 1989, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Guido van Rossum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Function fnmatch() as specified in POSIX 1003.2-1992, section B.6.
 * Compares a filename or pathname to a pattern.
 */

#include <config.h>

#include <stdio.h>
#include <ctype.h>
#ifdef HAVE_STRING_H
# include <string.h>
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */

#include <compat.h>
#include "emul/fnmatch.h"
#include "emul/charclass.h"

#undef	EOS
#define	EOS	'\0'

#define	RANGE_MATCH	1
#define	RANGE_NOMATCH	0
#define	RANGE_ERROR	(-1)

#if defined(LIBC_SCCS) && !defined(lint)
__unused static const char rcsid[] = "$OpenBSD: fnmatch.c,v 1.6 1998/03/19 00:29:59 millert Exp $";
#endif /* LIBC_SCCS and not lint */

static int rangematch __P((const char *, int, int, char **));
static int classmatch __P((const char *, int, int, const char **));

int
fnmatch(pattern, string, flags)
	const char *pattern, *string;
	int flags;
{
	const char *stringstart;
	char *newp;
	char c, test;

	for (stringstart = string;;)
		switch (c = *pattern++) {
		case EOS:
			if (ISSET(flags, FNM_LEADING_DIR) && *string == '/')
				return (0);
			return (*string == EOS ? 0 : FNM_NOMATCH);
		case '?':
			if (*string == EOS)
				return (FNM_NOMATCH);
			if (*string == '/' && ISSET(flags, FNM_PATHNAME))
				return (FNM_NOMATCH);
			if (*string == '.' && ISSET(flags, FNM_PERIOD) &&
			    (string == stringstart ||
			    (ISSET(flags, FNM_PATHNAME) && *(string - 1) == '/')))
				return (FNM_NOMATCH);
			++string;
			break;
		case '*':
			c = *pattern;
			/* Collapse multiple stars. */
			while (c == '*')
				c = *++pattern;

			if (*string == '.' && ISSET(flags, FNM_PERIOD) &&
			    (string == stringstart ||
			    (ISSET(flags, FNM_PATHNAME) && *(string - 1) == '/')))
				return (FNM_NOMATCH);

			/* Optimize for pattern with * at end or before /. */
			if (c == EOS) {
				if (ISSET(flags, FNM_PATHNAME))
					return (ISSET(flags, FNM_LEADING_DIR) ||
					    strchr(string, '/') == NULL ?
					    0 : FNM_NOMATCH);
				else
					return (0);
			} else if (c == '/' && ISSET(flags, FNM_PATHNAME)) {
				if ((string = strchr(string, '/')) == NULL)
					return (FNM_NOMATCH);
				break;
			}

			/* General case, use recursion. */
			while ((test = *string) != EOS) {
				if (!fnmatch(pattern, string, flags & ~FNM_PERIOD))
					return (0);
				if (test == '/' && ISSET(flags, FNM_PATHNAME))
					break;
				++string;
			}
			return (FNM_NOMATCH);
		case '[':
			if (*string == EOS)
				return (FNM_NOMATCH);
			if (*string == '/' && ISSET(flags, FNM_PATHNAME))
				return (FNM_NOMATCH);
			if (*string == '.' && ISSET(flags, FNM_PERIOD) &&
			    (string == stringstart ||
			    (ISSET(flags, FNM_PATHNAME) && *(string - 1) == '/')))
				return (FNM_NOMATCH);

			switch (rangematch(pattern, *string, flags, &newp)) {
			case RANGE_ERROR:
				/* not a good range, treat as normal text */
				goto normal;
			case RANGE_MATCH:
				pattern = newp;
				break;
			case RANGE_NOMATCH:
				return (FNM_NOMATCH);
			}
			++string;
			break;
		case '\\':
			if (!ISSET(flags, FNM_NOESCAPE)) {
				if ((c = *pattern++) == EOS) {
					c = '\\';
					--pattern;
				}
			}
			/* FALLTHROUGH */
		default:
		normal:
			if (c != *string && !(ISSET(flags, FNM_CASEFOLD) &&
				 (tolower((unsigned char)c) ==
				 tolower((unsigned char)*string))))
				return (FNM_NOMATCH);
			++string;
			break;
		}
	/* NOTREACHED */
}

static int
#ifdef __STDC__
rangematch(const char *pattern, int test, int flags, char **newp)
#else
rangematch(pattern, test, flags, newp)
	const char *pattern;
	int test;
	int flags;
	char **newp;
#endif
{
	int negate, ok, rv;
	char c, c2;

	/*
	 * A bracket expression starting with an unquoted circumflex
	 * character produces unspecified results (IEEE 1003.2-1992,
	 * 3.13.2).  This implementation treats it like '!', for
	 * consistency with the regular expression syntax.
	 * J.T. Conklin (conklin@ngai.kaleida.com)
	 */
	if ((negate = (*pattern == '!' || *pattern == '^')))
		++pattern;

	if (ISSET(flags, FNM_CASEFOLD))
		test = tolower(test);

	/*
	 * A right bracket shall lose its special meaning and represent
	 * itself in a bracket expression if it occurs first in the list.
	 * -- POSIX.2 2.8.3.2
	 */
	ok = 0;
	c = *pattern++;
	do {
		if (c == '[' && *pattern == ':') {
			do {
				rv = classmatch(pattern + 1, test,
				    (flags & FNM_CASEFOLD), &pattern);
				if (rv == RANGE_MATCH)
					ok = 1;
				c = *pattern++;
			} while (rv != RANGE_ERROR && c == '[' && *pattern == ':');
			if (c == ']')
			break;
		}
		if (c == '\\' && !ISSET(flags, FNM_NOESCAPE))
			c = *pattern++;
		if (c == EOS)
			return (RANGE_ERROR);
		if (c == '/' && ISSET(flags, FNM_PATHNAME))
			return (RANGE_NOMATCH);
		if (ISSET(flags, FNM_CASEFOLD))
			c = tolower((unsigned char)c);
		if (*pattern == '-'
		    && (c2 = *(pattern+1)) != EOS && c2 != ']') {
			pattern += 2;
			if (c2 == '\\' && !ISSET(flags, FNM_NOESCAPE))
				c2 = *pattern++;
			if (c2 == EOS)
				return (RANGE_ERROR);
			if (ISSET(flags, FNM_CASEFOLD))
				c2 = tolower((unsigned char)c2);
			if (c <= test && test <= c2)
				ok = 1;
		} else if (c == test)
			ok = 1;
	} while ((c = *pattern++) != ']');

	*newp = (char *)pattern;
	return (ok == negate ? RANGE_NOMATCH : RANGE_MATCH);
}

static int
#ifdef __STDC__
classmatch(const char *pattern, int test, int foldcase, const char **ep)
#else
classmatch(pattern, test, foldcase, ep)
	const char *pattern;
	int test;
	int foldcase;
	const char **ep;
#endif
{
	struct cclass *cc;
	const char *colon;
	size_t len;
	int rval = RANGE_NOMATCH;

	if ((colon = strchr(pattern, ':')) == NULL || colon[1] != ']') {
		*ep = pattern - 2;
		return(RANGE_ERROR);
	}
	*ep = colon + 2;
	len = (size_t)(colon - pattern);

	if (foldcase && strncmp(pattern, "upper:]", 7) == 0)
		pattern = "lower:]";
	for (cc = cclasses; cc->name != NULL; cc++) {
		if (!strncmp(pattern, cc->name, len) && cc->name[len] == '\0') {
			if (cc->isctype(test))
				rval = RANGE_MATCH;
			break;
		}
	}
	if (cc->name == NULL) {
		/* invalid character class, return EOS */
		*ep = colon + strlen(colon);
		rval = RANGE_ERROR;
	}
	return(rval);
}
