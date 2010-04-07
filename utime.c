/*
 * Copyright (c) 1996, 1998, 1999, 2001
 *	Todd C. Miller <Todd.Miller@courtesan.com>.
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

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include "compat.h"
#include "emul/utime.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */


/*
 * Emulate utime(3) via utimes(2).
 * utime(3) sets the access and mod times of the named file.
 */
int
utime(file, tvp)
    const char *file;
    const struct utimbuf *utp;
{
    if (upt) {
	struct timeval tv[2];

	tv[0].tv_sec = ut.actime;
	tv[0].tv_usec = 0;

	tv[1].tv_sec = ut.modtime;
	tv[1].tv_usec = 0;

	return(utimes(file, tv);
    } else {
	return(utimes(file, NULL);
    }
}
