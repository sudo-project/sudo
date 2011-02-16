/*
 * Copyright (c) 2009-2011 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_DLOPEN
# include <dlfcn.h>
#else
# include "compat/dlfcn.h"
#endif
#include <errno.h>

#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"

#ifndef RTLD_LOCAL
# define RTLD_LOCAL	0
#endif

/*
 * Read in /etc/sudo.conf
 * Returns a list of plugins.
 */
static struct plugin_info_list *
sudo_read_conf(const char *conf_file)
{
    FILE *fp;
    char *cp, *name, *path;
    struct plugin_info *info;
    static struct plugin_info_list pil; /* XXX */

    if ((fp = fopen(conf_file, "r")) == NULL)
	goto done;

    while ((cp = sudo_parseln(fp)) != NULL) {
	/* Skip blank or comment lines */
	if (*cp == '\0')
	    continue;

	/* Look for a line starting with "Path" */
	if (strncasecmp(cp, "Path", 4) == 0) {
	    /* Parse line */
	    if ((name = strtok(cp + 4, " \t")) == NULL ||
		(path = strtok(NULL, " \t")) == NULL) {
		continue;
	    }
	    if (strcasecmp(name, "askpass") != 0)
		continue;
	    askpass_path = estrdup(path);
	    continue;
	}

	/* Look for a line starting with "Plugin" */
	if (strncasecmp(cp, "Plugin", 6) == 0) {
	    /* Parse line */
	    if ((name = strtok(cp + 6, " \t")) == NULL ||
		(path = strtok(NULL, " \t")) == NULL) {
		continue;
	    }
	    info = emalloc(sizeof(*info));
	    info->symbol_name = estrdup(name);
	    info->path = estrdup(path);
	    info->prev = info;
	    info->next = NULL;
	    tq_append(&pil, info);
	    continue;
	}
    }
    fclose(fp);

done:
    if (tq_empty(&pil)) {
	/* Default policy plugin */
	info = emalloc(sizeof(*info));
	info->symbol_name = "sudoers_policy";
	info->path = SUDOERS_PLUGIN;
	info->prev = info;
	info->next = NULL;
	tq_append(&pil, info);

	/* Default I/O plugin */
	info = emalloc(sizeof(*info));
	info->symbol_name = "sudoers_io";
	info->path = SUDOERS_PLUGIN;
	info->prev = info;
	info->next = NULL;
	tq_append(&pil, info);
    }

    return &pil;
}

/*
 * Load the plugins listed in conf_file.
 */
void
sudo_load_plugins(const char *conf_file,
    struct plugin_container *policy_plugin,
    struct plugin_container_list *io_plugins)
{
    struct generic_plugin *plugin;
    struct plugin_container *container;
    struct plugin_info *info;
    struct plugin_info_list *plugin_list;
    struct stat sb;
    void *handle;
    char path[PATH_MAX];

    /* Parse sudo.conf */
    plugin_list = sudo_read_conf(conf_file);

    tq_foreach_fwd(plugin_list, info) {
	if (info->path[0] == '/') {
	    if (strlcpy(path, info->path, sizeof(path)) >= sizeof(path))
		errorx(1, "%s: %s", info->path, strerror(ENAMETOOLONG));
	} else {
	    if (snprintf(path, sizeof(path), "%s%s", _PATH_SUDO_PLUGIN_DIR,
		info->path) >= sizeof(path)) {
		errorx(1, "%s%s: %s", _PATH_SUDO_PLUGIN_DIR, info->path,
		    strerror(ENAMETOOLONG));
	    }
	}
	if (stat(path, &sb) != 0)
	    error(1, "%s", path);
	if (sb.st_uid != ROOT_UID)
	    errorx(1, "%s must be owned by uid %d", path, ROOT_UID);
	if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
	    errorx(1, "%s must be only be writable by owner", path);

	/* Open plugin and map in symbol */
	handle = dlopen(path, RTLD_LAZY|RTLD_LOCAL);
	if (!handle)
	    errorx(1, "unable to dlopen %s: %s", path, dlerror());
	plugin = dlsym(handle, info->symbol_name);
	if (!plugin)
	    errorx(1, "unable to find symbol %s in %s", info->symbol_name, path);

	if (plugin->type != SUDO_POLICY_PLUGIN && plugin->type != SUDO_IO_PLUGIN) {
	    errorx(1, "%s: unknown policy type %d", path, plugin->type);
	}
	if (SUDO_API_VERSION_GET_MAJOR(plugin->version) != SUDO_API_VERSION_MAJOR) {
	    errorx(1, "%s: incompatible policy major version %d, expected %d",
		path, SUDO_API_VERSION_GET_MAJOR(plugin->version),
		SUDO_API_VERSION_MAJOR);
	}
	if (plugin->type == SUDO_POLICY_PLUGIN) {
	    if (policy_plugin->handle)
		errorx(1, "only a single policy plugin may be loaded");
	    policy_plugin->handle = handle;
	    policy_plugin->name = info->symbol_name;
	    policy_plugin->u.generic = plugin;
	} else if (plugin->type == SUDO_IO_PLUGIN) {
	    container = emalloc(sizeof(*container));
	    container->prev = container;
	    container->next = NULL;
	    container->handle = handle;
	    container->name = info->symbol_name;
	    container->u.generic = plugin;
	    tq_append(io_plugins, container);
	}
    }
    if (policy_plugin->handle == NULL)
	errorx(1, "%s: at least one policy plugin must be specified", conf_file);
    if (policy_plugin->u.policy->check_policy == NULL)
	errorx(1, "policy plugin %s does not include a check_policy method");
}
