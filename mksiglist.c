/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#include <signal.h>

#include "missing.h"

int
main(argc, argv)
    int argc;
    char *argv[];
{
    static char *sudo_sys_siglist[NSIG];
    int i;

#include "mksiglist.h"

    printf("#include <config.h>\n");
    printf("#include <signal.h>\n");
    printf("#include \"missing.h\"\n\n");
    printf("const char *const sudo_sys_siglist[NSIG] = {\n");
    for (i = 0; i < NSIG; i++) {
	if (sudo_sys_siglist[i] != NULL) {
	    printf("    \"%s\",\n", sudo_sys_siglist[i]);
	} else {
	    printf("    \"Signal %d\",\n", i);
	}
    }
    printf("};\n");

    exit(0);
}
