/*
 * Copyright (c) 2008 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "missing.h"

int
main (int argc, char **argv)
{
    char *cp, *cmnd;

    if (argc < 2)
	errx(EXIT_FAILURE, "requires at least one argument");

    /* Shift argv and make a copy of the command to execute. */
    argv++;
    argc--;
    cmnd = strdup(argv[0]);
    if (cmnd == NULL)
	err(EXIT_FAILURE, NULL);

    /* If invoked as a login shell, modify argv[0] accordingly. */
    if (argv[0][0] == '-') {
	if ((cp = strrchr(argv[0], '/')) == NULL)
	    cp = argv[0];
	*cp = '-';
    }
    execv(cmnd, argv);
    warn("unable to execute %s", argv[0]);
    _exit(EXIT_FAILURE);
}
