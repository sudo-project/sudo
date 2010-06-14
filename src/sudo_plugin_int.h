/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_PLUGIN_INT_H
#define _SUDO_PLUGIN_INT_H

/*
 * Sudo plugin internals.
 */

struct plugin_info {
    struct plugin_info *prev; /* required */
    struct plugin_info *next; /* required */
    const char *path;
    const char *symbol_name;
};
TQ_DECLARE(plugin_info)

struct plugin_container {
    struct plugin_container *prev; /* required */
    struct plugin_container *next; /* required */
    const char *name;
    void *handle;
    union {
	struct generic_plugin *generic;
	struct policy_plugin *policy;
	struct io_plugin *io;
    } u;
};
TQ_DECLARE(plugin_container)

extern struct plugin_container_list policy_plugins;
extern struct plugin_container_list io_plugins;

int sudo_conversation(int num_msgs, const struct sudo_conv_message msgs[],
    struct sudo_conv_reply replies[]);
int _sudo_printf(int msg_type, const char *fmt, ...);

void sudo_load_plugins(const char *conf_file,
    struct plugin_container *policy_plugin,
    struct plugin_container_list *io_plugins);

#endif /* _SUDO_PLUGIN_INT_H */
