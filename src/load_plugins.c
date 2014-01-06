/*
 * Copyright (c) 2009-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <errno.h>

#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"
#include "sudo_conf.h"
#include "sudo_dso.h"
#include "sudo_debug.h"

/* We always use the same name for the sudoers plugin, regardless of the OS */
#define SUDOERS_PLUGIN	"sudoers.so"

#ifdef _PATH_SUDO_PLUGIN_DIR
static int
sudo_stat_plugin(struct plugin_info *info, char *fullpath,
    size_t pathsize, struct stat *sb)
{
    int status = -1;
    debug_decl(sudo_stat_plugin, SUDO_DEBUG_PLUGIN)

    if (info->path[0] == '/') {
	if (strlcpy(fullpath, info->path, pathsize) >= pathsize) {
	    warningx(U_("error in %s, line %d while loading plugin `%s'"),
		_PATH_SUDO_CONF, info->lineno, info->symbol_name);
	    warningx(U_("%s: %s"), info->path, strerror(ENAMETOOLONG));
	    goto done;
	}
	status = stat(fullpath, sb);
    } else {
	int len;

#ifdef STATIC_SUDOERS_PLUGIN
	/* Check static symbols. */
	if (strcmp(info->path, SUDOERS_PLUGIN) == 0) {
	    if (strlcpy(fullpath, info->path, pathsize) >= pathsize) {
		warningx(U_("error in %s, line %d while loading plugin `%s'"),
		    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
		warningx(U_("%s: %s"), info->path, strerror(ENAMETOOLONG));
		goto done;
	    }
	    /* Plugin is static, fake up struct stat. */
	    memset(sb, 0, sizeof(*sb));
	    sb->st_uid = ROOT_UID;
	    sb->st_mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	    status = 0;
	    goto done;
	}
#endif /* STATIC_SUDOERS_PLUGIN */

	len = snprintf(fullpath, pathsize, "%s%s", _PATH_SUDO_PLUGIN_DIR,
	    info->path);
	if (len <= 0 || (size_t)len >= pathsize) {
	    warningx(U_("error in %s, line %d while loading plugin `%s'"),
		_PATH_SUDO_CONF, info->lineno, info->symbol_name);
	    warningx(U_("%s%s: %s"), _PATH_SUDO_PLUGIN_DIR, info->path,
		strerror(ENAMETOOLONG));
	    goto done;
	}
	/* Try parent dir for compatibility with old plugindir default. */
	if ((status = stat(fullpath, sb)) != 0) {
	    char *cp = strrchr(fullpath, '/');
	    if (cp > fullpath + 4 && cp[-5] == '/' && cp[-4] == 's' &&
		cp[-3] == 'u' && cp[-2] == 'd' && cp[-1] == 'o') {
		int serrno = errno;
		strlcpy(cp - 4, info->path, pathsize - (cp - 4 - fullpath));
		if ((status = stat(fullpath, sb)) != 0)
		    errno = serrno;
	    }
	}
# ifdef __hpux
	/* Try .sl instead of .so on HP-UX for backwards compatibility. */
	if (status != 0) {
	    size_t len = strlen(info->path);
	    if (len >= 3 && info->path[len - 3] == '.' &&
		info->path[len - 2] == 's' && info->path[len - 1] == 'o') {
		const char *sopath = info->path;
		char *slpath = estrdup(info->path);
		int serrno = errno;

		slpath[len - 1] = 'l';
		info->path = slpath;
		status = sudo_stat_plugin(info, fullpath, pathsize, sb);
		if (status == 0) {
		    efree((void *)sopath);
		} else {
		    efree(slpath);
		    info->path = sopath;
		    errno = serrno;
		}
	    }
	}
# endif /* __hpux */
    }
done:
    debug_return_int(status);
}

static bool
sudo_check_plugin(struct plugin_info *info, char *fullpath, size_t pathsize)
{
    struct stat sb;
    int rval = false;
    debug_decl(sudo_check_plugin, SUDO_DEBUG_PLUGIN)

    if (sudo_stat_plugin(info, fullpath, pathsize, &sb) != 0) {
	warningx(U_("error in %s, line %d while loading plugin `%s'"),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	warning("%s%s", _PATH_SUDO_PLUGIN_DIR, info->path);
	goto done;
    }
    if (sb.st_uid != ROOT_UID) {
	warningx(U_("error in %s, line %d while loading plugin `%s'"),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	warningx(U_("%s must be owned by uid %d"), fullpath, ROOT_UID);
	goto done;
    }
    if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0) {
	warningx(U_("error in %s, line %d while loading plugin `%s'"),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	warningx(U_("%s must be only be writable by owner"), fullpath);
	goto done;
    }
    rval = true;

done:
    debug_return_bool(rval);
}
#else
static bool
sudo_check_plugin(struct plugin_info *info, char *fullpath, size_t pathsize)
{
    debug_decl(sudo_check_plugin, SUDO_DEBUG_PLUGIN)
    (void)strlcpy(fullpath, info->path, pathsize);
    debug_return_bool(true);
}
#endif /* _PATH_SUDO_PLUGIN_DIR */

/*
 * Load the plugin specified by "info".
 */
static bool
sudo_load_plugin(struct plugin_container *policy_plugin,
    struct plugin_container_list *io_plugins, struct plugin_info *info)
{
    struct plugin_container *container;
    struct generic_plugin *plugin;
    char path[PATH_MAX];
    bool rval = false;
    void *handle;
    debug_decl(sudo_load_plugin, SUDO_DEBUG_PLUGIN)

    /* Sanity check plugin and fill in path */
    if (!sudo_check_plugin(info, path, sizeof(path)))
	goto done;

    /* Open plugin and map in symbol */
    handle = sudo_dso_load(path, SUDO_DSO_LAZY|SUDO_DSO_GLOBAL);
    if (!handle) {
	warningx(U_("error in %s, line %d while loading plugin `%s'"),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	warningx(U_("unable to load %s: %s"), path, sudo_dso_strerror());
	goto done;
    }
    plugin = sudo_dso_findsym(handle, info->symbol_name);
    if (!plugin) {
	warningx(U_("error in %s, line %d while loading plugin `%s'"),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	warningx(U_("unable to find symbol `%s' in %s"), info->symbol_name, path);
	goto done;
    }

    if (plugin->type != SUDO_POLICY_PLUGIN && plugin->type != SUDO_IO_PLUGIN) {
	warningx(U_("error in %s, line %d while loading plugin `%s'"),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	warningx(U_("unknown policy type %d found in %s"), plugin->type, path);
	goto done;
    }
    if (SUDO_API_VERSION_GET_MAJOR(plugin->version) != SUDO_API_VERSION_MAJOR) {
	warningx(U_("error in %s, line %d while loading plugin `%s'"),
	    _PATH_SUDO_CONF, info->lineno, info->symbol_name);
	warningx(U_("incompatible plugin major version %d (expected %d) found in %s"),
	    SUDO_API_VERSION_GET_MAJOR(plugin->version),
	    SUDO_API_VERSION_MAJOR, path);
	goto done;
    }
    if (plugin->type == SUDO_POLICY_PLUGIN) {
	if (policy_plugin->handle) {
	    /* Ignore duplicate entries. */
	    if (strcmp(policy_plugin->name, info->symbol_name) != 0) {
		warningx(U_("ignoring policy plugin `%s' in %s, line %d"),
		    info->symbol_name, _PATH_SUDO_CONF, info->lineno);
		warningx(U_("only a single policy plugin may be specified"));
		goto done;
	    }
	    warningx(U_("ignoring duplicate policy plugin `%s' in %s, line %d"),
		info->symbol_name, _PATH_SUDO_CONF, info->lineno);
	    sudo_dso_unload(handle);
	    handle = NULL;
	}
	if (handle != NULL) {
	    policy_plugin->handle = handle;
	    policy_plugin->name = info->symbol_name;
	    policy_plugin->options = info->options;
	    policy_plugin->u.generic = plugin;
	}
    } else if (plugin->type == SUDO_IO_PLUGIN) {
	/* Check for duplicate entries. */
	TAILQ_FOREACH(container, io_plugins, entries) {
	    if (strcmp(container->name, info->symbol_name) == 0) {
		warningx(U_("ignoring duplicate I/O plugin `%s' in %s, line %d"),
		    info->symbol_name, _PATH_SUDO_CONF, info->lineno);
		sudo_dso_unload(handle);
		handle = NULL;
		break;
	    }
	}
	if (handle != NULL) {
	    container = ecalloc(1, sizeof(*container));
	    container->handle = handle;
	    container->name = info->symbol_name;
	    container->options = info->options;
	    container->u.generic = plugin;
	    TAILQ_INSERT_TAIL(io_plugins, container, entries);
	}
    }

    rval = true;
done:
    debug_return_bool(rval);
}

/*
 * Load the plugins listed in sudo.conf.
 */
bool
sudo_load_plugins(struct plugin_container *policy_plugin,
    struct plugin_container_list *io_plugins)
{
    struct plugin_container *container;
    struct plugin_info_list *plugins;
    struct plugin_info *info;
    bool rval = false;
    debug_decl(sudo_load_plugins, SUDO_DEBUG_PLUGIN)

    /* Walk the plugin list from sudo.conf, if any. */
    plugins = sudo_conf_plugins();
    TAILQ_FOREACH(info, plugins, entries) {
	rval = sudo_load_plugin(policy_plugin, io_plugins, info);
	if (!rval)
	    goto done;
    }

    /*
     * If no policy plugin, fall back to the default (sudoers).
     * If there is also no I/O log plugin, sudoers for that too.
     */
    if (policy_plugin->handle == NULL) {
	/* Default policy plugin */
	info = ecalloc(1, sizeof(*info));
	info->symbol_name = "sudoers_policy";
	info->path = SUDOERS_PLUGIN;
	/* info->options = NULL; */
	rval = sudo_load_plugin(policy_plugin, io_plugins, info);
	efree(info);
	if (!rval)
	    goto done;

	/* Default I/O plugin */
	if (TAILQ_EMPTY(io_plugins)) {
	    info = ecalloc(1, sizeof(*info));
	    info->symbol_name = "sudoers_io";
	    info->path = SUDOERS_PLUGIN;
	    /* info->options = NULL; */
	    rval = sudo_load_plugin(policy_plugin, io_plugins, info);
	    efree(info);
	    if (!rval)
		goto done;
	}
    }
    if (policy_plugin->u.policy->check_policy == NULL) {
	warningx(U_("policy plugin %s does not include a check_policy method"),
	    policy_plugin->name);
	rval = false;
	goto done;
    }

    /* Install hooks (XXX - later). */
    if (policy_plugin->u.policy->version >= SUDO_API_MKVERSION(1, 2)) {
	if (policy_plugin->u.policy->register_hooks != NULL)
	    policy_plugin->u.policy->register_hooks(SUDO_HOOK_VERSION, register_hook);
    }
    TAILQ_FOREACH(container, io_plugins, entries) {
	if (container->u.io->version >= SUDO_API_MKVERSION(1, 2)) {
	    if (container->u.io->register_hooks != NULL)
		container->u.io->register_hooks(SUDO_HOOK_VERSION, register_hook);
	}
    }

done:
    debug_return_bool(rval);
}
