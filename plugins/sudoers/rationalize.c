/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2026 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <assert.h>
#include <string.h>

#include <sudoers.h>

/*
 * Rationalize a path by removing consecutive '/' and "/./" path elements.
 * Also removes "/../" elements if dotdot is true.
 */
char *
rationalize_path(char *path, bool dotdot)
{
    char *cp, *ep, *path_end;
    debug_decl(rationalize_path, SUDOERS_DEBUG_UTIL);

    path_end = path + strlen(path);
    for (cp = path; *cp != '\0';) {
	if (cp[0] == '/') {
	    /* Collapse consecutive '/' characters. */
	    if (cp[1] == '/') {
		for (ep = cp + 1; ep[1] == '/'; ep++)
		    continue;

		/* The size argument includes the terminating NUL byte. */
		assert(ep <= path_end);
		memmove(cp, ep, (size_t)(path_end - ep) + 1);
		path_end -= ep - cp;
		assert(*path_end == '\0');
		continue;
	    }

	    /* Remove "/./" in path or "/." at path_end. */
	    if (cp[1] == '.' && (cp[2] == '/' || cp[2] == '\0')) {
		/* /./foo -> /foo OR /foo/. -> /foo */
		ep = cp + 2;

		/* The size argument includes the terminating NUL byte. */
		assert(ep <= path_end);
		memmove(cp, ep, (size_t)(path_end - ep) + 1);
		path_end -= ep - cp;

		/* An absolute path must not collapse to the empty string. */
		if (cp == path && *cp == '\0') {
		    /* /. -> / */
		    path[0] = '/';
		    path[1] = '\0';
		    path_end = path + 1;
		}
		assert(*path_end == '\0');
		continue;
	    }

	    /* Remove "/../" in path or "/.." at path_end. */
	    if (dotdot && cp[1] == '.' && cp[2] == '.' &&
		    (cp[3] == '/' || cp[3] == '\0')) {

		/* Skip ep past "/../" or "/.." */
		ep = cp + 3 + (cp[3] == '/');

		/* Set cp to the previous '/' if there is one. */
		if (cp != path) {
		    char *saved_cp = cp;
		    ep = cp + 3 + (cp[3] == '/');
		    do {
			cp--;
		    } while (cp > path && *cp != '/');
		    if (*cp != '/') {
			/* No previous '/', path doesn't start with '/'? */
			cp = saved_cp;
		    }
		}

		/* The size argument includes the terminating NUL byte. */
		assert(ep <= path_end);
		memmove(cp + 1, ep, (size_t)(path_end - ep) + 1);
		path_end -= ep - (cp + 1);
		assert(*path_end == '\0');
		continue;
	    }
	}
	cp++;
    }
    debug_return_str(path);
}
