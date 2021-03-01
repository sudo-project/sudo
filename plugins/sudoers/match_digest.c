/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1996, 1998-2005, 2007-2020
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sudoers.h"
#include "sudo_digest.h"
#include <gram.h>

bool
digest_matches(int fd, const char *path, const char *runchroot,
    const struct command_digest_list *digests)
{
    unsigned int digest_type = SUDO_DIGEST_INVALID;
    unsigned char *file_digest = NULL;
    unsigned char *sudoers_digest = NULL;
    struct command_digest *digest;
    size_t digest_len = (size_t)-1;
    char pathbuf[PATH_MAX];
    bool matched = false;
    debug_decl(digest_matches, SUDOERS_DEBUG_MATCH);

    if (TAILQ_EMPTY(digests)) {
	/* No digest, no problem. */
	debug_return_bool(true);
    }

    if (fd == -1) {
	/* No file, no match. */
	goto done;
    }

    if (runchroot != NULL) {
	const int len =
	    snprintf(pathbuf, sizeof(pathbuf), "%s%s", runchroot, path);
	if (len >= ssizeof(pathbuf)) {
	    errno = ENAMETOOLONG;
	    debug_return_bool(false);
	}
	path = pathbuf;
    }

    TAILQ_FOREACH(digest, digests, entries) {
	/* Compute file digest if needed. */
	if (digest->digest_type != digest_type) {
	    free(file_digest);
	    file_digest = sudo_filedigest(fd, path, digest->digest_type,
		&digest_len);
	    if (lseek(fd, (off_t)0, SEEK_SET) == -1) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO|SUDO_DEBUG_LINENO,
		    "unable to rewind digest fd");
	    }
	    digest_type = digest->digest_type;
	}
	if (file_digest == NULL) {
	    /* Warning (if any) printed by sudo_filedigest() */
	    goto done;
	}

	/* Convert the command digest from ascii to binary. */
	if ((sudoers_digest = malloc(digest_len)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}
	if (strlen(digest->digest_str) == digest_len * 2) {
	    /* Convert ascii hex to binary. */
	    unsigned int i;
	    for (i = 0; i < digest_len; i++) {
		const int h = hexchar(&digest->digest_str[i + i]);
		if (h == -1)
		    goto bad_format;
		sudoers_digest[i] = (unsigned char)h;
	    }
	} else {
	    /* Convert base64 to binary. */
	    size_t len = base64_decode(digest->digest_str, sudoers_digest, digest_len);
	    if (len != digest_len) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		    "incorrect length for digest, expected %zu, got %zu",
		    digest_len, len);
		goto bad_format;
	    }
	}
	if (memcmp(file_digest, sudoers_digest, digest_len) == 0) {
	    matched = true;
	    break;
	}

	sudo_debug_printf(SUDO_DEBUG_DIAG|SUDO_DEBUG_LINENO,
	    "%s digest mismatch for %s, expecting %s",
	    digest_type_to_name(digest->digest_type), path, digest->digest_str);
	free(sudoers_digest);
	sudoers_digest = NULL;
    }
    goto done;

bad_format:
    sudo_warnx(U_("digest for %s (%s) is not in %s form"), path,
	digest->digest_str, digest_type_to_name(digest->digest_type));
done:
    free(sudoers_digest);
    free(file_digest);
    debug_return_bool(matched);
}
