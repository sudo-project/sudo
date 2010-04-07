/*	$OpenBSD: mktemp.c,v 1.19 2005/08/08 08:05:36 espie Exp $	*/

/*
 * Copyright (c) 2000, 2001, 2005 Todd C. Miller <Todd.Miller@courtesan.com>
 * Copyright (c) 1987, 1993
 *	The Regents of the University of California.  All rights reserved.
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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#if defined(TIME_WITH_SYS_TIME) || defined(HAVE_SYS_TIME_H)
# include <sys/time.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */
#include <ctype.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include "sudo.h"

static unsigned int get_random __P((void));
static void seed_random __P((void));

int
mkstemp(path)
	char *path;
{
	char *start, *trv;
	struct stat sbuf;
	int fd, rval;
	pid_t pid;
	char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	if (*path == '\0') {
		errno = EINVAL;
		return (-1);		/* zero length path */
	}
	pid = getpid();
	for (trv = path; *trv; ++trv)
		;
	--trv;
	while (trv >= path && *trv == 'X' && pid != 0) {
		*trv-- = (pid % 10) + '0';
		pid /= 10;
	}
	while (trv >= path && *trv == 'X') {
		char c;

		/* assumes pid_t is at least 16 bits */
		pid = (get_random() & 0xffff) % (26 + 26);
		c = alphabet[pid];
		*trv-- = c;
	}
	start = trv + 1;

	/*
	 * check the target directory; if you have six X's and it
	 * doesn't exist this runs for a *very* long time.
	 */
	for (;; --trv) {
		if (trv <= path)
			break;
		if (*trv == '/') {
			*trv = '\0';
			rval = stat(path, &sbuf);
			*trv = '/';
			if (rval != 0)
				return (-1);
			if (!S_ISDIR(sbuf.st_mode)) {
				errno = ENOTDIR;
				return (-1);
			}
			break;
		}
	}

	for (;;) {
		if ((fd = open(path, O_CREAT|O_EXCL|O_RDWR, 0600)) >= 0)
			return (fd);
		if (errno != EEXIST)
			return (-1);

		/* tricky little algorithm for backward compatibility */
		for (trv = start;;) {
			if (!*trv)
				return (-1);
			if (*trv == 'Z')
				*trv++ = 'a';
			else {
				if (isdigit((unsigned char)(*trv)))
					*trv = 'a';
				else if (*trv == 'z')	/* wrap from z to A */
					*trv = 'A';
				else {
#ifdef HAVE_EBCDIC
					switch(*trv) {
					case 'i':
						*trv = 'j';
						break;
					case 'r':
						*trv = 's';
						break;
					case 'I':
						*trv = 'J';
						break;
					case 'R':
						*trv = 'S';
						break;
					default:
						++*trv;
						break;
					}
#else
					++*trv;
#endif
				}
				break;
			}
		}
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
seed_random()
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
get_random()
{
	static int initialized;

	if (!initialized) {
		seed_random();
		initialized = 1;
	}

	return(RAND() & 0xffffffff);
}
