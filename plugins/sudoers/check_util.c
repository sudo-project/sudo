/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2019-2020, 2023 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "sudoers.h"

/*
 * Returns true if the specified shell is allowed by /etc/shells, else false.
 */
bool
check_user_shell(const struct passwd *pw)
{
    const char *shell;
    debug_decl(check_user_shell, SUDOERS_DEBUG_AUTH);

    if (!def_runas_check_shell)
	debug_return_bool(true);

    sudo_debug_printf(SUDO_DEBUG_INFO,
	"%s: checking /etc/shells for %s", __func__, pw->pw_shell);

    setusershell();
    while ((shell = getusershell()) != NULL) {
	if (strcmp(shell, pw->pw_shell) == 0)
	    debug_return_bool(true);
    }
    endusershell();

    debug_return_bool(false);
}

/*
 * Check whether user_runchroot matches def_runchroot.
 * Returns true if matched, false if not matched and -1 on error.
 */
int
check_user_runchroot(void)
{
    debug_decl(check_user_runchroot, SUDOERS_DEBUG_AUTH);

    if (user_runchroot == NULL)
	debug_return_bool(true);

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"def_runchroot %s, user_runchroot %s",
	def_runchroot ? def_runchroot : "none",
	user_runchroot ? user_runchroot : "none");

    if (def_runchroot == NULL || (strcmp(def_runchroot, "*") != 0 &&
	    strcmp(def_runchroot, user_runchroot) != 0)) {
	debug_return_bool(false);
    }
    free(def_runchroot);
    if ((def_runchroot = strdup(user_runchroot)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }
    debug_return_bool(true);
}

/*
 * Check whether user_runcwd matches def_runcwd.
 * Returns true if matched, false if not matched and -1 on error.
 */
int
check_user_runcwd(void)
{
    debug_decl(check_user_runcwd, SUDOERS_DEBUG_AUTH);

    if (user_runcwd == NULL)
	debug_return_bool(true);

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
        "def_runcwd %s, user_runcwd %s",
        def_runcwd ? def_runcwd : "none",
        user_runcwd ? user_runcwd : "none");

    if (def_runcwd == NULL || (strcmp(def_runcwd, "*") != 0 &&
            strcmp(def_runcwd, user_runcwd) != 0)) {
        debug_return_bool(false);
    }
    free(def_runcwd);
    if ((def_runcwd = strdup(user_runcwd)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }
    debug_return_bool(true);
}
