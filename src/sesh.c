/*
 * Copyright (c) 2008, 2010-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#include "gettext.h"		/* must be included before missing.h */

#include "missing.h"
#include "alloc.h"
#include "fatal.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_exec.h"
#include "sudo_plugin.h"

__dso_public int main(int argc, char *argv[], char *envp[]);

int
main(int argc, char *argv[], char *envp[])
{
    char *cp, *cmnd;
    bool login_shell, noexec = false;
    debug_decl(main, SUDO_DEBUG_MAIN)

    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE_NAME, LOCALEDIR);
    textdomain(PACKAGE_NAME);

    if (argc < 2)
	fatalx(U_("requires at least one argument"));

    /* Read sudo.conf. */
    sudo_conf_read(NULL);

    /* If the first char of argv[0] is '-', we are running as a login shell. */
    login_shell = argv[0][0] == '-';

    /* If argv[0] ends in -noexec, pass the flag to sudo_execve() */
    if ((cp = strrchr(argv[0], '-')) != NULL && cp != argv[0])
	noexec = strcmp(cp, "-noexec") == 0;

    /* Shift argv and make a copy of the command to execute. */
    argv++;
    argc--;
    cmnd = estrdup(argv[0]);

    /* If invoked as a login shell, modify argv[0] accordingly. */
    if (login_shell) {
	if ((cp = strrchr(argv[0], '/')) == NULL)
	    cp = argv[0];
	*cp = '-';
    }
    sudo_execve(cmnd, argv, envp, noexec);
    warning(U_("unable to execute %s"), argv[0]);
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, EXIT_FAILURE);                
    _exit(EXIT_FAILURE);
}
