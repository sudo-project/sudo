/*
 * Copyright (c) 2011 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_CONF_H
#define _SUDO_CONF_H

#include "list.h"

struct plugin_info {
    struct plugin_info *prev; /* required */
    struct plugin_info *next; /* required */
    const char *path;
    const char *symbol_name;
};
TQ_DECLARE(plugin_info)

/* Read main sudo.conf file. */
void sudo_conf_read(void);

/* Accessor functions. */
const char *sudo_conf_askpass_path(void);
const char *sudo_conf_noexec_path(void);
const char *sudo_conf_debug_flags(void);
struct plugin_info_list *sudo_conf_plugins(void);

#endif /* _SUDO_CONF_H */
