/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Roger L. Snyder.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include <compat.h>
#include "emul/search.h"

#if defined(LIBC_SCCS) && !defined(lint)
static const char sccsid[] = "@(#)lsearch.c	8.1 (Berkeley) 6/4/93";
#endif /* LIBC_SCCS and not lint */

typedef int (*cmp_fn_t) __P((const VOID *, const VOID *));
static VOID *linear_base __P((const VOID *, const VOID *, size_t *, size_t,
			     cmp_fn_t, int));

VOID *
lsearch(key, base, nelp, width, compar)
	const VOID *key, *base;
	size_t *nelp, width;
	cmp_fn_t compar;
{
	return(linear_base(key, base, nelp, width, compar, 1));
}

VOID *
lfind(key, base, nelp, width, compar)
	const VOID *key, *base;
	size_t *nelp, width;
	cmp_fn_t compar;
{
	return(linear_base(key, base, nelp, width, compar, 0));
}

static VOID *
linear_base(key, base, nelp, width, compar, add_flag)
	const VOID *key, *base;
	size_t *nelp, width;
	cmp_fn_t compar;
	int add_flag;
{
	/* Strict ANSI does not allow pointer arithmetic on void *'s */
	const char *element, *end;

	end = (const char *) base + *nelp * width;
	for (element = (const char *) base; element < end; element += width)
		if (!compar(key, (VOID *) element))	/* key found */
			return((VOID *) element);
	if (!add_flag)					/* key not found */
		return(NULL);

	/*
	 * The UNIX System User's Manual, 1986 edition claims that
	 * a NULL pointer is returned by lsearch with errno set
	 * appropriately, if there is not enough room in the table
	 * to add a new item.  This can't be done as none of these
	 * routines have any method of determining the size of the
	 * table.  This comment was isn't in the 1986-87 System V
	 * manual.
	 */
	++*nelp;
	(void) memcpy((VOID *)end, key, width);
	return((VOID *) end);
}
