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

#include "missing.h"

static unsigned int get_random(void);
static void seed_random(void);

#define MKTEMP_FILE	1
#define MKTEMP_DIR	2

#define TEMPCHARS	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define NUM_CHARS	(sizeof(TEMPCHARS) - 1)

#ifndef INT_MAX
#define INT_MAX	0x7fffffff
#endif

#ifndef HAVE_MKSTEMPS
int
mkstemps(char *path, int slen)
{
	return mktemp_internal(path, slen, MKTEMP_FILE);
}
#endif /* HAVE_MKSTEMPS */

#ifndef HAVE_MKDTEMP
char *
mkdtemp(char *path)
{
	if (mktemp_internal(path, 0, MKTEMP_DIR) == -1)
		return NULL;
	return path;
}
#endif /* HAVE_MKDTEMP */

int
mktemp_internal(char *path, int slen, int mode)
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

		switch (mode) {
		case MKTEMP_FILE:
			fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
			if (fd != -1 || errno != EEXIST)
				return fd;
			break;
		case MKTEMP_DIR:
			if (mkdir(path, S_IRWXU) == 0)
				return 0;
			if (errno != EEXIST)
				return -1;
			break;
		}
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
seed_random(void)
{
	SEED_T seed;
	struct timeval tv;

	/*
	 * Seed from time of day and process id multiplied by small primes.
	 */
	(void) gettimeofday(&tv, NULL);
	seed = (tv.tv_sec % 10000) * 523 + tv.tv_usec * 13 +
	    (getpid() % 1000) * 983;
	SRAND(seed);
}

static unsigned int
get_random(void)
{
	static int initialized;

	if (!initialized) {
		seed_random();
		initialized = 1;
	}

	return RAND() & 0xffffffff;
}
