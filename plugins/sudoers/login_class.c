/*
 * Copyright (c) 2004, 2011 Todd C. Miller <Todd.Miller@courtesan.com>
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
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>

#include <login_cap.h>

#include "sudoers.h"

/*
 * Check whether or not a tilde in a string should be expanded.
 * We only do expansion for things like "~", "~/...", ~me", "~me/...".
 */
#define tilde_valid(s, u, l) \
    ((s)[1] == '/' || (s)[1] == '\0' || \
    (strncmp((s)+1, u, l) == 0 && ((s)[l+1] == '/' || (s)[l+1] == '\0')))

/*
 * Make a copy of a string, expanding '~' to the user's homedir, '$' to the
 * login name and other escape sequences as per cgetstr(3).
 */
static char *
expandstr(const char *ostr, const struct passwd *pwd)
{
	size_t n, olen, nlen, ulen, dlen;
	const char *ep, *eo, *op;
	char *nstr, *np;
	int ch;

	/* calculate the size of the new string */
	ulen = strlen(pwd->pw_name);
	dlen = strlen(pwd->pw_dir);
	olen = nlen = strlen(ostr);
	for (op = ostr, ep = ostr + olen; op < ep; op++) {
		switch (*op) {
		case '~':
			if (!tilde_valid(op, pwd->pw_name, ulen))
				break;
			if (op[1] != '/' && op[1] != '\0') {
				op += ulen;	/* ~username */
				nlen = nlen - ulen - 1 + dlen;
			} else
				nlen += dlen - 1;
			break;
		case '$':
			nlen += ulen - 1;
			break;
		case '^':
			/* control char */
			if (*++op != '\0')
				nlen--;
			break;
		case '\\':
			if (op[1] == '\0')
				break;
			/*
			 * Byte in octal notation (\123) or an escaped char (\t)
			 */
			eo = op + 4;
			do {
				op++;
				nlen--;
			} while (op < eo && *op >= '0' && *op <= '7');
			break;
		}
	}
	np = nstr = emalloc(++nlen);

	for (op = ostr, ep = ostr + olen; op < ep; op++) {
		switch ((ch = *op)) {
		case '~':
			if (!tilde_valid(op, pwd->pw_name, ulen))
				break;
			if (op[1] != '/' && op[1] != '\0')
				op += ulen;	/* ~username */
			strlcpy(np, pwd->pw_dir, nlen);
			nlen -= dlen;
			np += dlen;
			continue;
		case '$':
			strlcpy(np, pwd->pw_name, nlen);
			nlen -= ulen;
			np += ulen;
			continue;
		case '^':
			if (op[1] != '\0')
				ch = *++op & 037;
			break;
		case '\\':
			if (op[1] == '\0')
				break;
			switch(*++op) {
			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
				/* byte in octal up to 3 digits long */
				ch = 0;
				n = 3;
				do {
					ch = ch * 8 + (*op++ - '0');
				} while (--n && *op >= '0' && *op <= '7');
				break;
			case 'b': case 'B':
				ch = '\b';
				break;
			case 't': case 'T':
				ch = '\t';
				break;
			case 'n': case 'N':
				ch = '\n';
				break;
			case 'f': case 'F':
				ch = '\f';
				break;
			case 'r': case 'R':
				ch = '\r';
				break;
			case 'e': case 'E':
				ch = '\033';
				break;
			case 'c': case 'C':
				ch = ':';
				break;
			default:
				ch = *op;
				break;
			}
			break;
		}
		*np++ = ch;
		nlen--;
	}
	*np = '\0';
	return (nstr);
}

/*
 * Set an environment variable, substituting for ~ and $
 */
static void
login_setenv(char *name, char *ovalue, const struct passwd *pwd)
{
	char *value = NULL;

	if (*ovalue != '\0')
		value = expandstr(ovalue, pwd);
	sudo_setenv(name, value ? value : ovalue, 1);
	efree(value);
}

/*
 * Look up "setenv" for this user in login.conf and set the comma-separated
 * list of environment variables, expanding '~' and '$'.
 */
int
sudo_login_setenv(login_cap_t *lc, const struct passwd *pwd)
{
	char *beg, *end, *ep, *list, *value;
	int len;

	if (lc == NULL || lc->lc_cap == NULL)
		return (-1);		/* impossible */

	if ((len = cgetustr(lc->lc_cap, "setenv", &list)) <= 0)
		return (0);

	for (beg = end = list, ep = list + len + 1; end < ep; end++) {
		switch (*end) {
		case '\\':
			if (*(end + 1) == ',')
				end++;	/* skip escaped comma */
			continue;
		case ',':
		case '\0':
			*end = '\0';
			if (beg == end) {
				beg++;
				continue;
			}
			break;
		default:
			continue;
		}

		if ((value = strchr(beg, '=')) != NULL)
			*value++ = '\0';
		else
			value = "";
		login_setenv(beg, value, pwd);
		beg = end + 1;
	}
	efree(list);
	return (0);
}
