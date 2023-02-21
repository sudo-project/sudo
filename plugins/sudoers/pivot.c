/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2023 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "sudoers.h"

#define OLD_ROOT	0
#define OLD_CWD		1

/*
 * Pivot to a new root directory, storing the old root and old cwd
 * in fds[2].  Changes current working directory to the new root.
 * Returns true on success, else false.
 */
bool
pivot_root(const char *new_root, int fds[2])
{
    debug_decl(pivot_root, SUDOERS_DEBUG_UTIL);

    fds[OLD_ROOT] = open("/", O_RDONLY);
    fds[OLD_CWD] = open(".", O_RDONLY);
    if (fds[OLD_ROOT] == -1 || fds[OLD_CWD] == -1 || chroot(new_root) == -1) {
	if (fds[OLD_ROOT] != -1) {
	    close(fds[OLD_ROOT]);
	    fds[OLD_ROOT] = -1;
	}
	if (fds[OLD_CWD] != -1) {
	    close(fds[OLD_CWD]);
	    fds[OLD_CWD] = -1;
	}
	debug_return_bool(false);
    }
    debug_return_bool(chdir("/") == 0);
}

/*
 * Pivot back to the stored root directory and restore the old cwd.
 * Returns true on success, else false.
 */
bool
unpivot_root(int fds[2])
{
    bool ret = true;
    debug_decl(unpivot_root, SUDOERS_DEBUG_UTIL);

    /* Order is imporant: restore old root, *then* change cwd. */
    if (fds[OLD_ROOT] != -1) {
	if (fchdir(fds[OLD_ROOT]) == -1 || chroot(".") == -1) {
	    sudo_warn("%s", U_("unable to restore root directory"));
	    ret = false;
	}
	close(fds[OLD_ROOT]);
	fds[OLD_ROOT] = -1;
    }
    if (fds[OLD_CWD] != -1) {
	if (fchdir(fds[OLD_CWD]) == -1) {
	    sudo_warn("%s", U_("unable to restore current working directory"));
	    ret = false;
	}
	close(fds[OLD_CWD]);
	fds[OLD_CWD] = -1;
    }

    debug_return_bool(ret);
}
