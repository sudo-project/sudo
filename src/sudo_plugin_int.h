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
 * All plugin structures start with a type and a version.
 */
struct generic_plugin {
    unsigned int type;
    unsigned int version;
    /* the rest depends on the type... */
};

/*
 * Backwards-compatible structures for API bumps.
 */
struct io_plugin_1_0 {
    unsigned int type;
    unsigned int version;
    int (*open)(unsigned int version, sudo_conv_t conversation,
        sudo_printf_t sudo_printf, char * const settings[],
        char * const user_info[], int argc, char * const argv[],
        char * const user_env[]);
    void (*close)(int exit_status, int error);
    int (*show_version)(int verbose);
    int (*log_ttyin)(const char *buf, unsigned int len);
    int (*log_ttyout)(const char *buf, unsigned int len);
    int (*log_stdin)(const char *buf, unsigned int len);
    int (*log_stdout)(const char *buf, unsigned int len);
    int (*log_stderr)(const char *buf, unsigned int len);
};

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
	struct io_plugin_1_0 *io_1_0;
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
