/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_util.h"
#include "sudo_debug.h"

sudo_dso_public int main(int argc, char *argv[]);

int sudo_debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;
extern char *get_process_ttyname(char *name, size_t namelen);

static int
match_ttys(const char *tty1, const char *tty2)
{
    struct stat sb1, sb2;

    if (tty1 != NULL && tty2 != NULL) {
	if (strcmp(tty1, tty2) == 0)
	    return 0;
	/* Could be the same device with a different name. */
	if (stat(tty1, &sb1) == 0 && S_ISCHR(sb1.st_mode) &&
	    stat(tty2, &sb2) == 0 && S_ISCHR(sb2.st_mode)) {
	    if (sb1.st_rdev == sb2.st_rdev)
		return 0;
	}
    } else if (tty1 == NULL && tty2 == NULL) {
	return 0;
    }

    return 1;
}


int
main(int argc, char *argv[])
{
    char *tty_libc = NULL, *tty_sudo = NULL;
    char pathbuf[PATH_MAX];
    int ret = 1;

    initprogname(argc > 0 ? argv[0] : "check_ttyname");

    /* Lookup tty name using kernel info if possible. */
    if (get_process_ttyname(pathbuf, sizeof(pathbuf)) != NULL)
	tty_sudo = pathbuf;

#if defined(HAVE_KINFO_PROC2_NETBSD) || \
    defined(HAVE_KINFO_PROC_OPENBSD) || \
    defined(HAVE_KINFO_PROC_FREEBSD) || \
    defined(HAVE_KINFO_PROC_44BSD) || \
    defined(HAVE__TTYNAME_DEV) || defined(HAVE_STRUCT_PSINFO_PR_TTYDEV) || \
    defined(HAVE_PSTAT_GETPROC) || defined(__linux__)

    /* Lookup tty name attached to stdin via libc. */
    tty_libc = ttyname(STDIN_FILENO);
#endif

    /* Compare libc and kernel ttys. */
    ret = match_ttys(tty_libc, tty_sudo);
    if (ret == 0) {
	printf("%s: OK (%s)\n", getprogname(), tty_sudo ? tty_sudo : "none");
    } else if (tty_libc == NULL) {
	printf("%s: SKIP (%s)\n", getprogname(), tty_sudo ? tty_sudo : "none");
	ret = 0;
    } else {
	printf("%s: FAIL %s (sudo) vs. %s (libc)\n", getprogname(),
	    tty_sudo ? tty_sudo : "none", tty_libc ? tty_libc : "none");
    }

    return ret;
}
