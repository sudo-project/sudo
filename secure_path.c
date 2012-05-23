/*
 * Copyright (c) 2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
#include <stdio.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <errno.h>

#include "missing.h"
#include "secure_path.h"

/*
 * Verify that path is the right type and not writable by other users.
 */
int
sudo_secure_path(path, type, uid, gid, sbp)
    const char *path;
    int type;
    uid_t uid;
    gid_t gid;
    struct stat *sbp;
{
    struct stat sb;
    int rval = SUDO_PATH_MISSING;

    if (path != NULL && stat(path, &sb) == 0) {
	if ((sb.st_mode & _S_IFMT) != type) {
	    rval = SUDO_PATH_BAD_TYPE;
	} else if (uid != (uid_t)-1 && sb.st_uid != uid) {
	    rval = SUDO_PATH_WRONG_OWNER;
	} else if (sb.st_mode & S_IWOTH) {
	    rval = SUDO_PATH_WORLD_WRITABLE;
	} else if (ISSET(sb.st_mode, S_IWGRP) &&
	    (gid == (gid_t)-1 || sb.st_gid != gid)) {
	    rval = SUDO_PATH_GROUP_WRITABLE;
	} else {
	    rval = SUDO_PATH_SECURE;
	}
	if (sbp)
	    (void) memcpy(sbp, &sb, sizeof(struct stat));
    }

    return rval;
}

/*
 * Verify that path is a regular file and not writable by other users.
 */
int
sudo_secure_file(path, uid, gid, sbp)
    const char *path;
    uid_t uid;
    gid_t gid;
    struct stat *sbp;
{
    return sudo_secure_path(path, _S_IFREG, uid, gid, sbp);
}

/*
 * Verify that path is a directory and not writable by other users.
 */
int
sudo_secure_dir(path, uid, gid, sbp)
    const char *path;
    uid_t uid;
    gid_t gid;
    struct stat *sbp;
{
    return sudo_secure_path(path, _S_IFDIR, uid, gid, sbp);
}
