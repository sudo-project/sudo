/*
 * Copyright (c) 2001, 2003, 2004, 2008-2010
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include <ctype.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif

#include "sudo.h"

static unsigned int get_random __P((void));
static void seed_random __P((void));

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define NUM_CHARS	(sizeof(TEMPCHARS) - 1)

#ifndef INT_MAX
#define INT_MAX	0x7fffffff
#endif

int
mkstemps(path, slen)
	char *path;
	int slen;
{
	char *start, *cp, *ep;
	const char *tempchars = TEMPCHARS;
	unsigned int r, tries;
	int fd;

	for (ep = path; *ep; ep++)
		;
	if (path + slen >= ep) {
		errno = EINVAL;
		return -1;
	}
	ep -= slen;

	tries = 1;
	for (start = ep; start > path && start[-1] == 'X'; start--) {
		if (tries < INT_MAX / NUM_CHARS)
			tries *= NUM_CHARS;
	}
	tries *= 2;

	do {
		for (cp = start; *cp; cp++) {
			r = get_random() % NUM_CHARS;
			*cp = tempchars[r];
		}

		fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
		if (fd != -1 || errno != EEXIST)
			return fd;
	} while (--tries);

	errno = EEXIST;
	return -1;
}

#ifdef HAVE_RANDOM
# define RAND		random
# define SRAND		srandom
# define SEED_T		unsigned int
#else
# ifdef HAVE_LRAND48
#  define RAND		lrand48
#  define SRAND		srand48
#  define SEED_T	long
# else
#  define RAND		rand
#  define SRAND		srand
#  define SEED_T	unsigned int
# endif
#endif

static void
seed_random()
{
	SEED_T seed;
	struct timeval tv;

	/*
	 * Seed from time of day and process id multiplied by small primes.
	 */
	(void) gettime(&tv);
	seed = (tv.tv_sec % 10000) * 523 + tv.tv_usec * 13 +
	    (getpid() % 1000) * 983;
	SRAND(seed);
}

static unsigned int
get_random()
{
	static int initialized;

	if (!initialized) {
		seed_random();
		initialized = 1;
	}

	return RAND() & 0xffffffff;
}
