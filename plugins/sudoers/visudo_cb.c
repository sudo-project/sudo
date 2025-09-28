/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2023 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <sudoers.h>

static bool
cb_runchroot(struct sudoers_context *ctx, const char *file, int line, int column, const union sudo_defs_val *sd_un, int op)
{
    parser_warnx(ctx, file, line, column, ctx->parser_conf.strict > 1,
	!ctx->parser_conf.verbose,
	N_("\"runchroot\" is deprecated and will be removed in a future sudo release"));

    return true;
}

/*
 * Set visudo Defaults callbacks.
 */
void
set_callbacks(void)
{
    debug_decl(set_callbacks, SUDOERS_DEBUG_UTIL);

    /* Set locale callback. */
    sudo_defs_table[I_SUDOERS_LOCALE].callback = sudoers_locale_callback;

    /* The "runchroot" setting is deprecated. */
    sudo_defs_table[I_RUNCHROOT].callback = cb_runchroot;

    debug_return;
}
