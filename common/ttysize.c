/*
 * Copyright (c) 2010-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/ioctl.h>
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
#include <termios.h>
#include <limits.h>

#include "missing.h"
#include "sudo_debug.h"
#include "sudo_util.h"

/* Compatibility with older tty systems. */
#if !defined(TIOCGWINSZ) && defined(TIOCGSIZE)
# define TIOCGWINSZ	TIOCGSIZE
# define winsize	ttysize
# define ws_col		ts_cols
# define ws_row		ts_lines
#endif

#ifdef TIOCGWINSZ
static int
get_ttysize_ioctl(int *rowp, int *colp)
{
    struct winsize wsize;
    debug_decl(get_ttysize_ioctl, SUDO_DEBUG_EXEC)

    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &wsize) == 0 &&
	wsize.ws_row != 0 && wsize.ws_col  != 0) {
	*rowp = wsize.ws_row;
	*colp = wsize.ws_col;
	debug_return_int(0);
    }
    debug_return_int(-1);
}
#else
static int
get_ttysize_ioctl(int *rowp, int *colp)
{
    return -1;
}
#endif /* TIOCGWINSZ */

void
get_ttysize(int *rowp, int *colp)
{
    debug_decl(fork_cmnd, SUDO_DEBUG_EXEC)

    if (get_ttysize_ioctl(rowp, colp) == -1) {
	char *p;

	/* Fall back on $LINES and $COLUMNS. */
	if ((p = getenv("LINES")) == NULL ||
	    (*rowp = strtonum(p, 1, INT_MAX, NULL)) <= 0) {
	    *rowp = 24;
	}
	if ((p = getenv("COLUMNS")) == NULL ||
	    (*colp = strtonum(p, 1, INT_MAX, NULL)) <= 0) {
	    *colp = 80;
	}
    }

    debug_return;
}
