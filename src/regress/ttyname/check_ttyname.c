/*
 * Copyright (c) 2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <unistd.h>
#include <errno.h>

#include "missing.h"
#include "alloc.h"
#include "fatal.h"
#include "sudo_util.h"

__dso_public int main(int argc, char *argv[]);

extern char *get_process_ttyname(void);

int
main(int argc, char *argv[])
{
    char *tty_libc, *tty_sudo;
    int rval = 0;

    initprogname(argc > 0 ? argv[0] : "check_ttyname");

    /* Lookup tty name via libc. */
    if ((tty_libc = ttyname(STDIN_FILENO)) == NULL &&
	(tty_libc = ttyname(STDOUT_FILENO)) == NULL &&
	(tty_libc = ttyname(STDERR_FILENO)) == NULL)
	tty_libc = "none";
    tty_libc = estrdup(tty_libc);

    /* Lookup tty name via sudo (using kernel info if possible). */
    if ((tty_sudo = get_process_ttyname()) == NULL)
	tty_sudo = estrdup("none");

    if (strcmp(tty_libc, "none") == 0) {
	printf("%s: SKIP (%s)\n", getprogname(), tty_sudo);
    } else if (strcmp(tty_libc, tty_sudo) == 0) {
	printf("%s: OK (%s)\n", getprogname(), tty_sudo);
    } else {
	printf("%s: FAIL %s (sudo) vs. %s (libc)\n", getprogname(),
	    tty_sudo, tty_libc);
	rval = 1;
    }

    efree(tty_libc);
    efree(tty_sudo);
    exit(rval);
}
