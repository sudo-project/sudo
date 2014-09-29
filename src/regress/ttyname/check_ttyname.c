/*
 * Copyright (c) 2013-2014 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include "sudo_compat.h"
#include "sudo_alloc.h"
#include "sudo_fatal.h"
#include "sudo_util.h"

__dso_public int main(int argc, char *argv[]);

extern char *get_process_ttyname(void);

int
main(int argc, char *argv[])
{
    char *cp, *tty_libc = NULL, *tty_sudo;
    int fd, rval = 1;

    initprogname(argc > 0 ? argv[0] : "check_ttyname");

    /* Lookup tty name via sudo (using kernel info if possible). */
    if ((tty_sudo = get_process_ttyname()) == NULL)
	tty_sudo = sudo_estrdup("none");

    /* Lookup tty name via libc and compare to kernel tty. */
    for (fd = STDERR_FILENO; fd >= STDIN_FILENO; fd--) {
	cp = ttyname(fd);
	if (cp != NULL) {
	    if (tty_libc == NULL || strcmp(cp, tty_libc) != 0) {
		sudo_efree(tty_libc);
		tty_libc = sudo_estrdup(cp);
	    }
	    if (tty_sudo != NULL && strcmp(tty_libc, tty_sudo) == 0) {
		rval = 0;
		break;
	    }
	}
    }
    if (tty_libc == NULL && tty_sudo == NULL)
	rval = 0;

    if (rval == 0) {
	printf("%s: OK (%s)\n", getprogname(), tty_sudo ? tty_sudo : "none");
    } else if (tty_libc == NULL) {
	printf("%s: SKIP (%s)\n", getprogname(), tty_sudo ? tty_sudo : "none");
	rval = 0;
    } else {
	printf("%s: FAIL %s (sudo) vs. %s (libc)\n", getprogname(),
	    tty_sudo ? tty_sudo : "none", tty_libc ? tty_libc : "none");
    }

    sudo_efree(tty_libc);
    sudo_efree(tty_sudo);
    exit(rval);
}
