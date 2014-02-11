/*
 * Copyright (c) 2009-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */
#include <stdarg.h>

#define DEFAULT_TEXT_DOMAIN	"sudoers"
#include "gettext.h"		/* must be included before missing.h */

#include "missing.h"
#include "logging.h"
#include "sudo_debug.h"

#ifdef HAVE_BSM_AUDIT
# include "bsm_audit.h"
#endif
#ifdef HAVE_LINUX_AUDIT
# include "linux_audit.h"
#endif

void
audit_success(char *exec_args[])
{
    debug_decl(audit_success, SUDO_DEBUG_AUDIT)

    if (exec_args != NULL) {
#ifdef HAVE_BSM_AUDIT
	bsm_audit_success(exec_args);
#endif
#ifdef HAVE_LINUX_AUDIT
	linux_audit_command(exec_args, 1);
#endif
    }

    debug_return;
}

void
audit_failure(char *exec_args[], char const *const fmt, ...)
{
    va_list ap;
    int oldlocale;
    debug_decl(audit_success, SUDO_DEBUG_AUDIT)

    /* Audit error messages should be in the sudoers locale. */
    sudoers_setlocale(SUDOERS_LOCALE_SUDOERS, &oldlocale);

    if (exec_args != NULL) {
	va_start(ap, fmt);
#ifdef HAVE_BSM_AUDIT
	bsm_audit_failure(exec_args, _(fmt), ap);
#endif
#ifdef HAVE_LINUX_AUDIT
	linux_audit_command(exec_args, 0);
#endif
	va_end(ap);
    }

    sudoers_setlocale(oldlocale, NULL);

    debug_return;
}
