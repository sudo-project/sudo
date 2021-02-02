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

#include "sudoers.h"

/* Required to link with parser. */
struct sudo_user sudo_user;
struct passwd *list_pw;

FILE *
open_sudoers(const char *file, bool doedit, bool *keepopen)
{
    return fopen(file, "r");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct sudoers_parse_tree parse_tree;
    FILE *fp;

    /* Don't waste time fuzzing tiny inputs. */
    if (size < 5)
        return 0;

    /* Operate in-memory, do not fclose or it will free() data. */
    fp = fmemopen((void *)data, size, "r");
    if (fp == NULL)
        return 0;

    /* Initialize defaults and parse LDIF-format sudoers. */
    init_defaults();
    init_parse_tree(&parse_tree, NULL, NULL);
    sudoers_parse_ldif(&parse_tree, fp, NULL, true);

    /* Cleanup. */
    free_parse_tree(&parse_tree);

    return 0;
}
