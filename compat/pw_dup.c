/*
 * Copyright (c) 2000, 2002, 2012 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#include <pwd.h>

#define PW_SIZE(name, size)				\
do {							\
	if (pw->name) {					\
		size = strlen(pw->name) + 1;		\
		total += size;				\
	}						\
} while (0)

#define PW_COPY(name, size)				\
do {							\
	if (pw->name) {					\
		(void)memcpy(cp, pw->name, size);	\
		newpw->name = cp;			\
		cp += size;				\
	}						\
} while (0)

struct passwd *
pw_dup(const struct passwd *pw)
{
	char		*cp;
	size_t		 nsize, psize, gsize, dsize, ssize, total;
#ifdef HAVE_LOGIN_CAP_H
	size_t		 csize;
#endif
	struct passwd	*newpw;

	/* Allocate in one big chunk for easy freeing */
	total = sizeof(struct passwd);
	PW_SIZE(pw_name, nsize);
	PW_SIZE(pw_passwd, psize);
#ifdef HAVE_LOGIN_CAP_H
	PW_SIZE(pw_class, csize);
#endif
	PW_SIZE(pw_gecos, gsize);
	PW_SIZE(pw_dir, dsize);
	PW_SIZE(pw_shell, ssize);

	if ((cp = malloc(total)) == NULL)
		return (NULL);
	newpw = (struct passwd *)cp;

	/*
	 * Copy in passwd contents and make strings relative to space
	 * at the end of the buffer.
	 */
	(void)memcpy(newpw, pw, sizeof(struct passwd));
	cp += sizeof(struct passwd);

	PW_COPY(pw_name, nsize);
	PW_COPY(pw_passwd, psize);
#ifdef HAVE_LOGIN_CAP_H
	PW_COPY(pw_class, csize);
#endif
	PW_COPY(pw_gecos, gsize);
	PW_COPY(pw_dir, dsize);
	PW_COPY(pw_shell, ssize);

	return newpw;
}
