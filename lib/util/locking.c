/*
 * Copyright (c) 1999-2005, 2007, 2009-2015
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRING_H */
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif

#include "sudo_compat.h"
#include "sudo_util.h"
#include "sudo_debug.h"

/*
 * Lock/unlock all or part of a file.
 */
#ifdef HAVE_LOCKF
bool
sudo_lock_file_v1(int fd, int type)
{
    return sudo_lock_region_v1(fd, type, 0);
}

bool
sudo_lock_region_v1(int fd, int type, off_t len)
{
    int op;
    debug_decl(sudo_lock_region, SUDO_DEBUG_UTIL)

    switch (type) {
	case SUDO_LOCK:
	    op = F_LOCK;
	    break;
	case SUDO_TLOCK:
	    op = F_TLOCK;
	    break;
	case SUDO_UNLOCK:
	    op = F_ULOCK;
	    break;
	default:
	    debug_return_bool(false);
    }
    debug_return_bool(lockf(fd, op, len) == 0);
}
#else
bool
sudo_lock_file_v1(int fd, int type)
{
    return sudo_lock_region_v1(fd, type, 0);
}

bool
sudo_lock_region_v1(int fd, int type, off_t len)
{
    int func;
    struct flock lock;
    debug_decl(sudo_lock_file, SUDO_DEBUG_UTIL)

    lock.l_start = 0;
    lock.l_len = len;
    lock.l_pid = 0;
    lock.l_type = (type == SUDO_UNLOCK) ? F_UNLCK : F_WRLCK;
    lock.l_whence = len ? SEEK_CUR : SEEK_SET;
    func = (type == SUDO_LOCK) ? F_SETLKW : F_SETLK;

    debug_return_bool(fcntl(fd, func, &lock) == 0);
}
#endif
