/*
 * Copyright (c) 2001, 2003, 2008 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include <ctype.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include <compat.h>

static unsigned int get_random(void);
static void seed_random(void);

int
mkstemp(char *path)
{
	char *start, *cp;
	int fd, r;
	char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	if (*path == '\0') {
		errno = EINVAL;
		return(0);
	}

	for (cp = path; *cp; cp++)
		;
	do {
		cp--;
	} while (cp >= path && *cp == 'X');
	start = cp + 1;

	for (;;) {
		for (cp = start; *cp; cp++) {
			r = get_random % (26 + 26);
			*cp = alphabet[r];
		}

		fd = open(path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
		if (fd != -1 || errno != EEXIST)
			return(fd);
	}
	/*NOTREACHED*/
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
	struct timespec ts;

	/*
	 * Seed from time of day and process id multiplied by small primes.
	 */
	(void) gettime(&ts);
	seed = (ts.tv_sec % 10000) * 523 + ts.tv_nsec / 1000 * 13 +
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

	return(RAND() & 0xffffffff);
}
