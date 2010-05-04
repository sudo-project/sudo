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
int sudo_printf(int msg_type, const char *fmt, ...);

void sudo_load_plugins(const char *conf_file,
    struct plugin_container *policy_plugin,
    struct plugin_container_list *io_plugins);

#endif /* _SUDO_PLUGIN_INT_H */
