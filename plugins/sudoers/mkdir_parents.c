/*
 * Copyright (c) 2009-2016 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"

/*
 * Create any parent directories needed by path (but not path itself).
 */
bool
sudo_mkdir_parents(char *path, uid_t uid, gid_t *gidp, mode_t mode, bool quiet)
{
    struct stat sb;
    gid_t parent_gid = 0;
    char *slash = path;
    bool ret = true;
    debug_decl(sudo_mkdir_parents, SUDOERS_DEBUG_UTIL)

    /* If no gid specified, inherit from parent dir. */
    if (*gidp != (gid_t)-1)
	parent_gid = *gidp;
    else if (stat("/", &sb) == 0)
	parent_gid = sb.st_gid;

    /* Create parent directories as needed. */
    while ((slash = strchr(slash + 1, '/')) != NULL) {
	*slash = '\0';
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "mkdir %s, mode 0%o, uid %d, gid %d", path, (unsigned int)mode,
	    (int)uid, (int)parent_gid);
	if (mkdir(path, mode) == 0) {
	    ignore_result(chown(path, uid, parent_gid));
	} else {
	    if (errno != EEXIST) {
		if (!quiet)
		    sudo_warn(U_("unable to mkdir %s"), path);
		ret = false;
		break;
	    }
	    /* Already exists, make sure it is a directory. */
	    if (stat(path, &sb) != 0) {
		if (!quiet)
		    sudo_warn(U_("unable to stat %s"), path);
		ret = false;
		break;
	    }
	    if (!S_ISDIR(sb.st_mode)) {
		if (!quiet)
		    sudo_warnx(U_("%s exists but is not a directory (0%o)"),
			path, (unsigned int) sb.st_mode);
		ret = false;
		break;
	    }
	    /* Inherit gid of parent dir for ownership. */
	    if (*gidp == (gid_t)-1)
		parent_gid = sb.st_gid;
	}
	*slash = '/';
    }

    /* Return parent gid if none was specified by caller. */
    if (ret && *gidp == (gid_t)-1)
	*gidp = parent_gid;
    debug_return_bool(ret);
}
