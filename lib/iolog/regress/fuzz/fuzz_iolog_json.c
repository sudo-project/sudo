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

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_eventlog.h"
#include "sudo_iolog.h"
#include "sudo_util.h"

#include "iolog_json.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct eventlog *evlog = NULL;
    FILE *fp;

    /* Operate in-memory. */
    fp = fmemopen((void *)data, size, "r");
    if (fp == NULL)
        return 0;

    /* Parsed contents of an log.json file are stored in evlog. */
    evlog = calloc(1, sizeof(*evlog));
    if (evlog != NULL) {
	evlog->runuid = (uid_t)-1;
	evlog->rungid = (gid_t)-1;

	/* Try to parse buffer as a JSON-format I/O log info file. */
	iolog_parse_loginfo_json(fp, "fuzz.json", evlog);
	eventlog_free(evlog);
    }
    fclose(fp);

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
