/*
 * Copyright (c) 2011-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <errno.h>
#include <grp.h>
#include <limits.h>

#include "missing.h"
#include "sudo_debug.h"
#include "sudo_util.h"

int
sudo_setgroups(int ngids, const GETGROUPS_T *gids)
{
    int maxgids, rval;
    debug_decl(sudo_setgroups, SUDO_DEBUG_UTIL)

    rval = setgroups(ngids, (GETGROUPS_T *)gids);
    if (rval == -1 && errno == EINVAL) {
	/* Too many groups, try again with fewer. */
#if defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	maxgids = (int)sysconf(_SC_NGROUPS_MAX);
	if (maxgids == -1)
#endif
	    maxgids = NGROUPS_MAX;
	if (ngids > maxgids)
	    rval = setgroups(maxgids, (GETGROUPS_T *)gids);
    }
    debug_return_int(rval);
}
