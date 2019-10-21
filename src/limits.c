/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2019 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/types.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#ifdef __linux__
# include <sys/prctl.h>
#endif

#include "sudo.h"

static struct saved_limit {
    int resource;
    bool saved;
    struct rlimit limit;
} saved_limits[] = {
#ifdef RLIMIT_AS
    { RLIMIT_AS },
#endif
    { RLIMIT_CPU },
    { RLIMIT_DATA },
    { RLIMIT_FSIZE },
    { RLIMIT_NOFILE },
#ifdef RLIMIT_NPROC
    { RLIMIT_NPROC },
#endif
#ifdef RLIMIT_RSS
    { RLIMIT_RSS },
#endif
    { RLIMIT_STACK }
};

static struct rlimit corelimit;
static bool coredump_disabled;
#ifdef __linux__
static struct rlimit nproclimit;
static int dumpflag;
#endif

/*
 * Disable core dumps to avoid dropping a core with user password in it.
 * Not all operating systems disable core dumps for setuid processes.
 */
void
disable_coredump(void)
{
    struct rlimit rl = { 0, 0 };
    debug_decl(disable_coredump, SUDO_DEBUG_UTIL)

    if (getrlimit(RLIMIT_CORE, &corelimit) == -1)
	sudo_warn("getrlimit(RLIMIT_CORE)");
    if (setrlimit(RLIMIT_CORE, &rl) == -1)
	sudo_warn("setrlimit(RLIMIT_CORE)");
#ifdef __linux__
    /* On Linux, also set PR_SET_DUMPABLE to zero (reset by execve). */
    if ((dumpflag = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)) == -1)
	dumpflag = 0;
    (void) prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif /* __linux__ */
    coredump_disabled = true;

    debug_return;
}

/*
 * Restore core resource limit before executing the command.
 */
static void
restore_coredump(void)
{
    debug_decl(restore_coredump, SUDO_DEBUG_UTIL)

    if (coredump_disabled) {
	if (setrlimit(RLIMIT_CORE, &corelimit) == -1)
	    sudo_warn("setrlimit(RLIMIT_CORE)");
#ifdef __linux__
	(void) prctl(PR_SET_DUMPABLE, dumpflag, 0, 0, 0);
#endif /* __linux__ */
    }
    debug_return;
}

/*
 * Unlimit the number of processes since Linux's setuid() will
 * apply resource limits when changing uid and return EAGAIN if
 * nproc would be exceeded by the uid switch.
 *
 * This function is called *after* session setup and before the
 * final setuid() call.
 */
void
unlimit_nproc(void)
{
#ifdef __linux__
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    debug_decl(unlimit_nproc, SUDO_DEBUG_UTIL)

    if (getrlimit(RLIMIT_NPROC, &nproclimit) != 0)
	sudo_warn("getrlimit(RLIMIT_NPROC)");
    if (setrlimit(RLIMIT_NPROC, &rl) == -1) {
	rl.rlim_cur = rl.rlim_max = nproclimit.rlim_max;
	if (setrlimit(RLIMIT_NPROC, &rl) != 0)
	    sudo_warn("setrlimit(RLIMIT_NPROC)");
    }
    debug_return;
#endif /* __linux__ */
}

/*
 * Restore saved value of RLIMIT_NPROC before execve().
 */
void
restore_nproc(void)
{
#ifdef __linux__
    debug_decl(restore_nproc, SUDO_DEBUG_UTIL)

    if (setrlimit(RLIMIT_NPROC, &nproclimit) != 0)
	sudo_warn("setrlimit(RLIMIT_NPROC)");

    debug_return;
#endif /* __linux__ */
}

/*
 * Unlimit resource limits so sudo is not limited by, e.g.
 * stack, data or file table sizes.
 */
void
unlimit_sudo(void)
{
    struct rlimit inf = { RLIM_INFINITY, RLIM_INFINITY };
    unsigned int idx;
    debug_decl(unlimit_sudo, SUDO_DEBUG_UTIL)

    /* Set resource limits to unlimited and stash the old values. */
    for (idx = 0; idx < nitems(saved_limits); idx++) {
	struct saved_limit *lim = &saved_limits[idx];
	if (getrlimit(lim->resource, &lim->limit) == -1)
	    continue;
	lim->saved = true;
	if (setrlimit(lim->resource, &inf) == -1) {
	    struct rlimit rl = lim->limit;
	    rl.rlim_cur = rl.rlim_max;
	    if (setrlimit(lim->resource, &rl) == -1)
		sudo_warn("setrlimit(%d)", lim->resource);
	}
    }

    debug_return;
}

/*
 * Restore resource limits modified by unlimit_sudo() and disable_coredump().
 */
void
restore_limits(void)
{
    unsigned int idx;
    debug_decl(restore_limits, SUDO_DEBUG_UTIL)

    /* Restore resource limits to saved values. */
    for (idx = 0; idx < nitems(saved_limits); idx++) {
	struct saved_limit *lim = &saved_limits[idx];
	if (lim->saved) {
	    if (setrlimit(lim->resource, &lim->limit) == -1)
		sudo_warn("setrlimit(%d)", lim->resource);
	}
    }
    restore_coredump();

    debug_return;
}
