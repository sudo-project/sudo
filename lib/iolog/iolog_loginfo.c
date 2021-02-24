/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2009-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_eventlog.h"
#include "sudo_fatal.h"
#include "sudo_gettext.h"
#include "sudo_iolog.h"
#include "sudo_util.h"

struct eventlog *
iolog_parse_loginfo(int dfd, const char *iolog_dir)
{
    struct eventlog *evlog = NULL;
    FILE *fp = NULL;
    int fd = -1;
    int tmpfd = -1;
    bool ok, legacy = false;
    debug_decl(iolog_parse_loginfo, SUDO_DEBUG_UTIL);

    if (dfd == -1) {
	if ((tmpfd = open(iolog_dir, O_RDONLY)) == -1) {
	    sudo_warn("%s", iolog_dir);
	    goto bad;
	}
	dfd = tmpfd;
    }
    if ((fd = openat(dfd, "log.json", O_RDONLY, 0)) == -1) {
	fd = openat(dfd, "log", O_RDONLY, 0);
	legacy = true;
    }
    if (tmpfd != -1)
	close(tmpfd);
    if (fd == -1 || (fp = fdopen(fd, "r")) == NULL) {
	sudo_warn("%s/log", iolog_dir);
	goto bad;
    }
    fd = -1;

    if ((evlog = calloc(1, sizeof(*evlog))) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto bad;
    }
    evlog->runuid = (uid_t)-1;
    evlog->rungid = (gid_t)-1;

    ok = legacy ? iolog_parse_loginfo_legacy(fp, iolog_dir, evlog) :
	iolog_parse_loginfo_json(fp, iolog_dir, evlog);
    if (ok) {
	fclose(fp);
	debug_return_ptr(evlog);
    }

bad:
    if (fd != -1)
	close(fd);
    if (fp != NULL)
	fclose(fp);
    eventlog_free(evlog);
    debug_return_ptr(NULL);
}
