/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2013-2015 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <stdlib.h>
#include <string.h>

#include "sudo_compat.h"
#include "sudo_util.h"

#ifdef HAVE_GETPROGNAME

# ifndef HAVE_SETPROGNAME
/* Assume __progname if have getprogname(3) but not setprogname(3). */
extern const char *__progname;

void
sudo_setprogname(const char *name)
{
    const char *slash = strrchr(name, '/');
    __progname = slash ? slash + 1 : name;
}
# endif

void
initprogname2(const char *name, const char * const * allowed)
{
    const char *progname;
    int i;

    /* Fall back on "name" if getprogname() returns an empty string. */
    if ((progname = getprogname()) != NULL && *progname != '\0')
	name = progname;

    /* Check for libtool prefix and strip it if present. */
    if (name[0] == 'l' && name[1] == 't' && name[2] == '-' && name[3] != '\0')
	name += 3;

    /* Check allow list if present (first element is the default). */
    if (allowed != NULL) {
	for (i = 0; ; i++) {
	    if (allowed[i] == NULL) {
		name = allowed[0];
		break;
	    }
	    if (strcmp(allowed[i], name) == 0)
		break;
	}
    }

    /* Update internal progname if needed. */
    if (name != progname)
	setprogname(name);
    return;
}

#else /* !HAVE_GETPROGNAME */

static const char *progname = "";

void
initprogname2(const char *name, const char * const * allowed)
{
    int i;
# ifdef HAVE___PROGNAME
    extern const char *__progname;

    if (__progname != NULL && *__progname != '\0')
	progname = __progname;
    else
# endif
    if ((progname = strrchr(name, '/')) != NULL) {
	progname++;
    } else {
	progname = name;
    }

    /* Check for libtool prefix and strip it if present. */
    if (progname[0] == 'l' && progname[1] == 't' && progname[2] == '-' &&
	progname[3] != '\0')
	progname += 3;

    /* Check allow list if present (first element is the default). */
    if (allowed != NULL) {
	for (i = 0; ; i++) {
	    if (allowed[i] == NULL) {
		progname = allowed[0];
		break;
	    }
	    if (strcmp(allowed[i], progname) == 0)
		break;
	}
    }
}

const char *
sudo_getprogname(void)
{
    return progname;
}

void
sudo_setprogname(const char *name)
{
    const char *slash = strrchr(name, '/');
    progname = slash ? slash + 1 : name;
}
#endif /* !HAVE_GETPROGNAME */

void
initprogname(const char *name)
{
    initprogname2(name, NULL);
}
