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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include "sudo_compat.h"
#include "sudo_fatal.h"
#include "sudo_util.h"

sudo_dso_public int main(int argc, char *argv[]);

extern int get_net_ifs(char **addrinfo);

int
main(int argc, char *argv[])
{
    char *interfaces = NULL;
    int ninterfaces;
    int ret = 0;

    initprogname(argc > 0 ? argv[0] : "check_net_ifs");

    ninterfaces = get_net_ifs(&interfaces);
    switch (ninterfaces) {
    case -1:
	sudo_warn_nodebug("unable to get network interfaces");
	ret = 1;
	break;
    case 0:
	/* no interfaces or STUB_LOAD_INTERFACES defined. */
	sudo_warnx_nodebug("OK: (0 interfaces)");
	break;
    default:
	sudo_warnx_nodebug("OK: (%d interface%s, %s)", ninterfaces,
	    ninterfaces > 1 ? "s" : "", interfaces);
	break;
    }

    free(interfaces);

    return ret;
}
