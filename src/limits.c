/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1999-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
# include <sys/prctl.h>
#endif
#include <errno.h>
#include <limits.h>

#include "sudo.h"

#if defined(OPEN_MAX) && OPEN_MAX > 256
# define SUDO_OPEN_MAX	OPEN_MAX
#else
# define SUDO_OPEN_MAX	256
#endif

#ifdef __LP64__
# define SUDO_STACK_MIN	(4 * 1024 * 1024)
#else
# define SUDO_STACK_MIN	(2 * 1024 * 1024)
#endif

#ifdef HAVE_SETRLIMIT64
# define getrlimit(a, b) getrlimit64((a), (b))
# define setrlimit(a, b) setrlimit64((a), (b))
# define rlimit rlimit64
# define rlim_t rlim64_t
# undef RLIM_INFINITY
# define RLIM_INFINITY RLIM64_INFINITY
#endif /* HAVE_SETRLIMIT64 */

/* Older BSD systems have RLIMIT_VMEM, not RLIMIT_AS. */
#if !defined(RLIMIT_AS) && defined(RLIMIT_VMEM)
# define RLIMIT_AS RLIMIT_VMEM
#endif

/*
 * macOS doesn't allow nofile soft limit to be infinite or
 * the stack hard limit to be infinite.
 * Linux containers have a problem with an infinite stack soft limit.
 */
static struct rlimit nofile_fallback = { SUDO_OPEN_MAX, RLIM_INFINITY };
static struct rlimit stack_fallback = { SUDO_STACK_MIN, 65532 * 1024 };

static struct saved_limit {
    const char *name;		/* rlimit_foo in lower case */
    int resource;		/* RLIMIT_FOO definition */
    bool override;		/* override limit while sudo executes? */
    bool saved;			/* true if we were able to get the value */
    struct rlimit *fallback;	/* fallback if we fail to set to newlimit */
    struct rlimit newlimit;	/* new limit to use if override is true */
    struct rlimit oldlimit;	/* original limit, valid if saved is true */
} saved_limits[] = {
#ifdef RLIMIT_AS
    { "rlimit_as", RLIMIT_AS, true, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
#endif
    { "rlimit_core", RLIMIT_CORE, false },
    { "rlimit_cpu", RLIMIT_CPU, true, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
    { "rlimit_data", RLIMIT_DATA, true, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
    { "rlimit_fsize", RLIMIT_FSIZE, true, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
#ifdef RLIMIT_LOCKS
    { "rlimit_locks", RLIMIT_LOCKS, false },
#endif
#ifdef RLIMIT_MEMLOCK
    { "rlimit_memlock", RLIMIT_MEMLOCK, false },
#endif
    { "rlimit_nofile", RLIMIT_NOFILE, true, false, &nofile_fallback, { RLIM_INFINITY, RLIM_INFINITY } },
#ifdef RLIMIT_NPROC
    { "rlimit_nproc", RLIMIT_NPROC, true, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
#endif
#ifdef RLIMIT_RSS
    { "rlimit_rss", RLIMIT_RSS, true, false, NULL, { RLIM_INFINITY, RLIM_INFINITY } },
#endif
    { "rlimit_stack", RLIMIT_STACK, true, false, &stack_fallback, { SUDO_STACK_MIN, RLIM_INFINITY } }
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
    debug_decl(disable_coredump, SUDO_DEBUG_UTIL);

    if (getrlimit(RLIMIT_CORE, &corelimit) == -1)
	sudo_warn("getrlimit(RLIMIT_CORE)");
    sudo_debug_printf(SUDO_DEBUG_INFO, "RLIMIT_CORE [%lld, %lld] -> [0, 0]",
	(long long)corelimit.rlim_cur, (long long)corelimit.rlim_max);
    if (setrlimit(RLIMIT_CORE, &rl) == -1)
	sudo_warn("setrlimit(RLIMIT_CORE)");
#ifdef __linux__
    /* On Linux, also set PR_SET_DUMPABLE to zero (reset by execve). */
    if ((dumpflag = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)");
	dumpflag = 0;
    }
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == -1) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "prctl(PR_SET_DUMPABLE, %d, 0, 0, 0)", dumpflag);
    }
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
    debug_decl(restore_coredump, SUDO_DEBUG_UTIL);

    if (coredump_disabled) {
	/*
	 * Linux containers don't allow RLIMIT_CORE to be set back to
	 * RLIM_INFINITY if we set the limit to zero, even for root.
	 */
	if (setrlimit(RLIMIT_CORE, &corelimit) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"setrlimit(RLIMIT_CORE, [%lld, %lld])",
		(long long)corelimit.rlim_cur, (long long)corelimit.rlim_max);
	}
#ifdef __linux__
	if (prctl(PR_SET_DUMPABLE, dumpflag, 0, 0, 0) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"prctl(PR_SET_DUMPABLE, %d, 0, 0, 0)", dumpflag);
	}
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
    debug_decl(unlimit_nproc, SUDO_DEBUG_UTIL);

    if (getrlimit(RLIMIT_NPROC, &nproclimit) != 0)
	sudo_warn("getrlimit(RLIMIT_NPROC)");
    sudo_debug_printf(SUDO_DEBUG_INFO, "RLIMIT_NPROC [%lld, %lld] -> [inf, inf]",
	(long long)nproclimit.rlim_cur, (long long)nproclimit.rlim_max);
    if (setrlimit(RLIMIT_NPROC, &rl) == -1) {
	rl.rlim_cur = rl.rlim_max = nproclimit.rlim_max;
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "RLIMIT_NPROC [%lld, %lld] -> [%lld, %lld]",
	    (long long)nproclimit.rlim_cur, (long long)nproclimit.rlim_max,
	    (long long)rl.rlim_cur, (long long)rl.rlim_max);
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
    debug_decl(restore_nproc, SUDO_DEBUG_UTIL);

    if (setrlimit(RLIMIT_NPROC, &nproclimit) != 0) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
	    "setrlimit(RLIMIT_NPROC, [%lld, %lld])",
	    (long long)nproclimit.rlim_cur, (long long)nproclimit.rlim_max);
    }

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
    unsigned int idx;
    int rc;
    debug_decl(unlimit_sudo, SUDO_DEBUG_UTIL);

    /* Set resource limits to unlimited and stash the old values. */
    for (idx = 0; idx < nitems(saved_limits); idx++) {
	struct saved_limit *lim = &saved_limits[idx];
	if (getrlimit(lim->resource, &lim->oldlimit) == -1)
	    continue;
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "getrlimit(lim->name) -> [%lld, %lld]",
	    (long long)lim->oldlimit.rlim_cur,
	    (long long)lim->oldlimit.rlim_max);

	lim->saved = true;
	if (!lim->override)
	    continue;

	if (lim->newlimit.rlim_cur != RLIM_INFINITY) {
	    /* Don't reduce the soft resource limit. */
	    if (lim->oldlimit.rlim_cur == RLIM_INFINITY ||
		    lim->oldlimit.rlim_cur > lim->newlimit.rlim_cur)
		lim->newlimit.rlim_cur = lim->oldlimit.rlim_cur;
	}
	if (lim->newlimit.rlim_max != RLIM_INFINITY) {
	    /* Don't reduce the hard resource limit. */
	    if (lim->oldlimit.rlim_max == RLIM_INFINITY ||
		    lim->oldlimit.rlim_max > lim->newlimit.rlim_max)
		lim->newlimit.rlim_max = lim->oldlimit.rlim_max;
	}
	if ((rc = setrlimit(lim->resource, &lim->newlimit)) == -1) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		"setrlimit(%s, [%lld, %lld])", lim->name,
		(long long)lim->newlimit.rlim_cur,
		(long long)lim->newlimit.rlim_max);
	    if (lim->fallback != NULL) {
		if ((rc = setrlimit(lim->resource, lim->fallback)) == -1) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"setrlimit(%s, [%lld, %lld])", lim->name,
			(long long)lim->fallback->rlim_cur,
			(long long)lim->fallback->rlim_max);
		}
	    }
	    if (rc == -1) {
		/* Try setting new rlim_cur to old rlim_max. */
		lim->newlimit.rlim_cur = lim->oldlimit.rlim_max;
		lim->newlimit.rlim_max = lim->oldlimit.rlim_max;
		if ((rc = setrlimit(lim->resource, &lim->newlimit)) == -1) {
		    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
			"setrlimit(%s, [%lld, %lld])", lim->name,
			(long long)lim->newlimit.rlim_cur,
			(long long)lim->newlimit.rlim_max);
		}
	    }
	    if (rc == -1)
		sudo_warn("setrlimit(%s)", lim->name);
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
    debug_decl(restore_limits, SUDO_DEBUG_UTIL);

    /* Restore resource limits to saved values. */
    for (idx = 0; idx < nitems(saved_limits); idx++) {
	struct saved_limit *lim = &saved_limits[idx];
	if (lim->override && lim->saved) {
	    struct rlimit rl = lim->oldlimit;
	    int i, rc;

	    for (i = 0; i < 10; i++) {
		rc = setrlimit(lim->resource, &rl);
		if (rc != -1 || errno != EINVAL)
		    break;

		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		    "setrlimit(%s, [%lld, %lld])", lim->name,
		    (long long)rl.rlim_cur, (long long)rl.rlim_max);

		/*
		 * Soft limit could be lower than current resource usage.
		 * This can be an issue on NetBSD with RLIMIT_STACK and ASLR.
		 */
		if (rl.rlim_cur > LLONG_MAX / 2)
		    break;
		rl.rlim_cur *= 2;
		if (lim->newlimit.rlim_cur != RLIM_INFINITY &&
			rl.rlim_cur > lim->newlimit.rlim_cur) {
		    rl.rlim_cur = lim->newlimit.rlim_cur;
		}
		if (rl.rlim_max != RLIM_INFINITY &&
			rl.rlim_cur > rl.rlim_max) {
		    rl.rlim_max = rl.rlim_cur;
		}
		rc = setrlimit(lim->resource, &rl);
		if (rc != -1 || errno != EINVAL)
		    break;
	    }
	    if (rc == -1)
		sudo_warn("setrlimit(%s)", lim->name);
	}
    }
    restore_coredump();

    debug_return;
}

int
serialize_limits(char **info, size_t info_max)
{
    char *str;
    unsigned int idx, nstored = 0;
    debug_decl(serialize_limits, SUDO_DEBUG_UTIL);

    for (idx = 0; idx < nitems(saved_limits); idx++) {
	const struct saved_limit *lim = &saved_limits[idx];
	const struct rlimit *rl = &lim->oldlimit;
	char curlim[(((sizeof(long long) * 8) + 2) / 3) + 2];
	char maxlim[(((sizeof(long long) * 8) + 2) / 3) + 2];

	if (!lim->saved)
	    continue;

	if (nstored == info_max)
	    goto oom;

	if (rl->rlim_cur == RLIM_INFINITY) {
	    strlcpy(curlim, "infinity", sizeof(curlim));
	} else {
	    snprintf(curlim, sizeof(curlim), "%llu",
		(unsigned long long)rl->rlim_cur);
	}
	if (rl->rlim_max == RLIM_INFINITY) {
	    strlcpy(maxlim, "infinity", sizeof(maxlim));
	} else {
	    snprintf(maxlim, sizeof(maxlim), "%llu",
		(unsigned long long)rl->rlim_max);
	}
	if (asprintf(&str, "%s=%s,%s", lim->name, curlim, maxlim) == -1)
	    goto oom;
	info[nstored++] = str;
    }
    debug_return_int(nstored);
oom:
    while (nstored--)
	free(info[nstored]);
    debug_return_int(-1);
}
