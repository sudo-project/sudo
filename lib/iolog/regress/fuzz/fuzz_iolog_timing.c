/*
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

#include <config.h>

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_eventlog.h"
#include "sudo_fatal.h"
#include "sudo_iolog.h"
#include "sudo_util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct iolog_file iolog_file = { true };
    struct timing_closure closure;
    char logdir[] = "/tmp/timing.XXXXXX";
    int dfd = -1, fd = -1;

    if (mkdtemp(logdir) == NULL) {
	sudo_warn_nodebug("unable to make temp dir");
	return 0;
    }
    dfd = open(logdir, O_RDONLY);
    if (dfd == -1) {
	sudo_warn_nodebug("unable to open %s", logdir);
	goto cleanup;
    }

    fd = openat(dfd, "timing", O_WRONLY|O_CREAT|O_EXCL, S_IRWXU);
    if (fd == -1) {
	sudo_warn_nodebug("unable to open %s/timing", logdir);
	goto cleanup;
    }
    if (write(fd, data, size) != (ssize_t)size) {
	sudo_warn_nodebug("unable to write %s/timing", logdir);
	goto cleanup;
    }
    close(fd);
    fd = -1;

    if (!iolog_open(&iolog_file, dfd, IOFD_TIMING, "r")) {
	sudo_warn_nodebug("unable to iolog_open %s/timing", logdir);
	goto cleanup;
    }

    memset(&closure, 0, sizeof(closure));
    closure.decimal = ".";
    for (;;) {
	if (iolog_read_timing_record(&iolog_file, &closure) != 0)
	    break;
    }
    iolog_close(&iolog_file, NULL);

cleanup:
    if (dfd != -1) {
	if (fd != -1) {
	    close(fd);
	    unlinkat(dfd, "timing", 0);
	}
	close(dfd);
    }
    rmdir(logdir);

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int
main(int argc, char *argv[])
{
    /* Nothing for now. */
    return LLVMFuzzerTestOneInput(NULL, 0);
}
#endif
