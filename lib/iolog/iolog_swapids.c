/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2021 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdlib.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif
#include <time.h>
#include <unistd.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_iolog.h"

/*
 * Set effective user and group-IDs to iolog_uid and iolog_gid.
 * If restore flag is set, swap them back.
 */
bool
iolog_swapids(bool restore)
{
#ifdef HAVE_SETEUID
    static uid_t user_euid = (uid_t)-1;
    static gid_t user_egid = (gid_t)-1;
    const uid_t iolog_uid = iolog_get_uid();
    const gid_t iolog_gid = iolog_get_gid();
    debug_decl(io_swapids, SUDO_DEBUG_UTIL);

    if (user_euid == (uid_t)-1)
	user_euid = geteuid();
    if (user_egid == (gid_t)-1)
	user_egid = getegid();

    if (restore) {
	if (seteuid(user_euid) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to restore effective uid to %u", __func__,
		(unsigned int)user_euid);
	    sudo_warn("seteuid() %u -> %u", (unsigned int)iolog_uid, (unsigned int)user_euid);
	    debug_return_bool(false);
	}
	if (setegid(user_egid) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to restore effective gid to %u", __func__,
		(unsigned int)user_egid);
	    sudo_warn("setegid() %u -> %u", (unsigned int)iolog_gid, (unsigned int)user_egid);
	    debug_return_bool(false);
	}
    } else {
	/* Fail silently if the user has insufficient privileges. */
	if (setegid(iolog_gid) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to set effective gid to %u", __func__,
		(unsigned int)iolog_gid);
	    debug_return_bool(false);
	}
	if (seteuid(iolog_uid) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"%s: unable to set effective uid to %u", __func__,
		(unsigned int)iolog_uid);
	    debug_return_bool(false);
	}
    }
    debug_return_bool(true);
#else
    return false;
#endif
}
