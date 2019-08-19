/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef HAVE_STR2SIG

#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <ctype.h>
#include <signal.h>
#include <unistd.h>

#include "sudo_compat.h"

#if defined(HAVE_DECL_SYS_SIGNAME) && HAVE_DECL_SYS_SIGNAME == 1
#  define sudo_sys_signame	sys_signame
#elif defined(HAVE_DECL__SYS_SIGNAME) && HAVE_DECL__SYS_SIGNAME == 1
#  define sudo_sys_signame	_sys_signame
#elif defined(HAVE_DECL_SYS_SIGABBREV) && HAVE_DECL_SYS_SIGABBREV == 1
#  define sudo_sys_signame	sys_sigabbrev
#else
# ifdef HAVE_SYS_SIGABBREV
   /* sys_sigabbrev is not declared by glibc */
#  define sudo_sys_signame	sys_sigabbrev
# endif
extern const char *const sudo_sys_signame[NSIG];
#endif

/*
 * Translate signal name to number.
 */
int
sudo_str2sig(const char *signame, int *result)
{
    int signo;
    const char *errstr;

    /* Could be a signal number encoded as a string. */
    if (isdigit((unsigned char)signame[0])) {
	signo = strtonum(signame, 0, NSIG - 1, &errstr);
	if (errstr != NULL)
	    return -1;
	*result = signo;
	return 0;
    }

    /* Special cases. */
    switch (signame[0]) {
    case 'C':
	/* support both SIGCLD and SIGCHLD */
#ifdef SIGCLD
	if (strcmp(signame, "CLD") == 0) {
	    *result = SIGCLD;
	    return 0;
	}
#endif
#ifdef SIGCHLD
	if (strcmp(signame, "CHLD") == 0) {
	    *result = SIGCHLD;
	    return 0;
	}
#endif
	break;
#ifdef SIGIO
    case 'I':
	/* support both SIGIO and SIGPOLL */
	if (strcmp(signame, "IO") == 0) {
	    *result = SIGIO;
	    return 0;
	}
	break;
#endif
#ifdef SIGPOLL
    case 'P':
	/* support both SIGIO and SIGPOLL */
	if (strcmp(signame, "POLL") == 0) {
	    *result = SIGPOLL;
	    return 0;
	}
	break;
#endif
    case 'R':
	/* real-time signals */
#if defined(SIGRTMIN)
	if (strncmp(signame, "RTMIN", 5) == 0) {
	    if (signame[5] == '\0') {
		*result = SIGRTMIN;
		return 0;
	    }
	    if (signame[5] == '+') {
		if (isdigit((unsigned char)signame[6])) {
		    const long rtmax = sysconf(_SC_RTSIG_MAX);
		    const int off = signame[6] - '0';

		    if (rtmax > 0 && off < rtmax / 2) {
			*result = SIGRTMIN + off;
			return 0;
		    }
		}
	    }
	}
#endif
#if defined(SIGRTMAX)
	if (strncmp(signame, "RTMAX", 5) == 0) {
	    if (signame[5] == '\0') {
		*result = SIGRTMAX;
		return 0;
	    }
	    if (signame[5] == '-') {
		if (isdigit((unsigned char)signame[6])) {
		    const long rtmax = sysconf(_SC_RTSIG_MAX);
		    const int off = signame[6] - '0';

		    if (rtmax > 0 && off < rtmax / 2) {
			*result = SIGRTMAX - off;
			return 0;
		    }
		}
	    }
	}
#endif
	break;
    }

    for (signo = 1; signo < NSIG; signo++) {
	if (sudo_sys_signame[signo] != NULL) {
	    if (strcmp(signame, sudo_sys_signame[signo]) == 0) {
		*result = signo;
		return 0;
	    }
	}
    }

    errno = EINVAL;
    return -1;
}
#endif /* HAVE_STR2SIG */
