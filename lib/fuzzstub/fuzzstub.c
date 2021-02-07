/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2021 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif

#include "sudo_compat.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/*
 * Simple driver for fuzzers built for LLVM libfuzzer.
 * This stub library allows fuzz targets to be built and run without
 * libfuzzer.  No actual fuzzing will occur but the provided inputs
 * will be tested.
 */
int
main(int argc, char *argv[])
{
    size_t bufsize = 0;
    ssize_t nread;
    struct stat sb;
    uint8_t *buf = NULL;
    int fd, i, errors = 0;

    /* Test provided input files. */
    for (i = 1; i < argc; i++) {
	fd = open(argv[i], O_RDONLY);
	if (fd == -1 || fstat(fd, &sb) != 0) {
	    fprintf(stderr, "open %s: %s\n", argv[i], strerror(errno));
	    if (fd != -1)
		close(fd);
	    errors++;
	    continue;
	}
	if (sb.st_size > SSIZE_MAX) {
	    errno = E2BIG;
	    fprintf(stderr, "%s: %s\n", argv[i], strerror(errno));
	    close(fd);
	    errors++;
	    continue;
	}
	if (bufsize < (size_t)sb.st_size) {
	    void *tmp = realloc(buf, sb.st_size);
	    if (tmp == NULL) {
		fprintf(stderr, "realloc: %s\n", strerror(errno));
		close(fd);
		errors++;
		continue;
	    }
	    buf = tmp;
	    bufsize = sb.st_size;
	}
	nread = read(fd, buf, sb.st_size);
	if (nread != sb.st_size) {
	    if (nread == -1)
		fprintf(stderr, "read %s: %s\n", argv[i], strerror(errno));
	    else
		fprintf(stderr, "read %s: short read\n", argv[i]);
	    close(fd);
	    errors++;
	    continue;
	}
	close(fd);

	/* NOTE: doesn't support LLVMFuzzerInitialize() (but we don't use it) */
	LLVMFuzzerTestOneInput(buf, nread);
    }
    free(buf);

    return errors;
}
