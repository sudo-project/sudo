/*
 * Copyright (c) 2017 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "sudo_compat.h"
#include "sudo_util.h"
#include "check.h"

__dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    int ntests = 0, errors = 0;
    struct timespec ts;
    pid_t pids[2];
    int i;

    initprogname(argc > 0 ? argv[0] : "check_starttime");

    pids[0] = getpid();
    pids[1] = getppid();

    /*
     * We don't try to check the resulting timespec as it differs
     * by platform.  On some it is wallclock time, on others it
     * is relative to boot time.
     */
    for (i = 0; i < 2; i++) {
	ntests++;
	if (get_starttime(pids[i], &ts)  == -1) {
	    printf("%s: test %d: unable to get start time for pid %d\n",
		getprogname(), ntests, (int)pids[i]);
	    errors++;
	}
    }

    printf("%s: %d tests run, %d errors, %d%% success rate\n", getprogname(),
	ntests, errors, (ntests - errors) * 100 / ntests);

    exit(errors);
}
