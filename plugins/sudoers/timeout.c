/*
 * Copyright (c) 2017 Todd C. Miller <Todd.Miller@courtesan.com>
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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#include "sudo_compat.h"
#include "sudoers_debug.h"
#include "parse.h"

/*
 * Parse a command timeout in sudoers in the format 1d2h3m4s
 * (days, hours, minutes, seconds) or a number of seconds with no suffix.
 * Returns the number of seconds or -1 on error.
 */
int
parse_timeout(const char *timestr)
{
    debug_decl(parse_timeout, SUDOERS_DEBUG_PARSER)
    const char digits[] = "0123456789";
    const char suffixes[] = "dhms";
    const char *cp;
    int timeout = 0;
    size_t len = 0;
    int idx = 0;

    for (cp = timestr; *cp != '\0'; cp += len) {
	char ch;
	long l;

	if ((len = strspn(cp, digits)) == 0) {
	    /* parse error */
	    errno = EINVAL;
	    debug_return_int(-1);
	}
	if (cp[len] == '\0') {
	    /* no suffix, assume seconds. */
	    ch = 's';
	} else {
	    ch = tolower(cp[len]);
	    len++;
	}

	/* Find a matching suffix or return an error. */
	while (suffixes[idx] != ch) {
	    if (suffixes[idx] == '\0') {
		/* parse error */
		errno = EINVAL;
		debug_return_int(-1);
	    }
	    idx++;
	}

	errno = 0;
	l = strtol(cp, NULL, 10);
	if (errno == ERANGE || l > INT_MAX)
	    goto overflow;
	switch (ch) {
	case 'd':
	    if (l > INT_MAX / (24 * 60 * 60))
		goto overflow;
	    l *= 24 * 60 * 60;
	    break;
	case 'h':
	    if (l > INT_MAX / (60 * 60))
		goto overflow;
	    l *= 60 * 60;
	    break;
	case 'm':
	    if (l > INT_MAX / 60)
		goto overflow;
	    l *= 60;
	    break;
	}
	if (l > INT_MAX - timeout)
	    goto overflow;

	timeout += l;
    }

    debug_return_int(timeout);
overflow:
    errno = ERANGE;
    debug_return_int(-1);
}
