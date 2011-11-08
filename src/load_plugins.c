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
#include <ctype.h>
#include <errno.h>

#define SUDO_ERROR_WRAP	0

#include "sudo.h"
#include "sudo_plugin.h"
#include "sudo_plugin_int.h"
#include "sudo_debug.h"

#ifndef RTLD_GLOBAL
# define RTLD_GLOBAL	0
#endif

#ifdef _PATH_SUDO_NOEXEC
const char *noexec_path = _PATH_SUDO_NOEXEC;
#endif

/* XXX - for parse_args() */
const char *debug_file;
const char *debug_flags;

struct sudo_conf_table {
    const char *name;
    unsigned int namelen;
    int (*setter)(const char *entry, void *data);
};

struct sudo_conf_paths {
    const char *pname;
    unsigned int pnamelen;
    const char **pval;
};

static int set_debug(const char *entry, void *data);
static int set_path(const char *entry, void *data);
static int set_plugin(const char *entry, void *data);

static struct plugin_info_list plugin_info_list;

static struct sudo_conf_table sudo_conf_table[] = {
    { "Debug", sizeof("Debug") - 1, set_debug },
    { "Path", sizeof("Path") - 1, set_path },
    { "Plugin", sizeof("Plugin") - 1, set_plugin },
    { NULL }
};

static struct sudo_conf_paths sudo_conf_paths[] = {
    { "askpass", sizeof("askpass"), &askpass_path },
#ifdef _PATH_SUDO_NOEXEC
    { "noexec", sizeof("noexec"), &noexec_path },
#endif
    { NULL }
};

/*
 * "Debug progname debug_file debug_flags"
 */
static int
set_debug(const char *entry, void *data)
{
    size_t filelen, proglen;
    const char *progname;

    /* Is this debug setting for me? */
    progname = getprogname();
    if (strcmp(progname, "sudoedit") == 0)
	progname = "sudo";
    proglen = strlen(progname);
    if (strncmp(entry, progname, proglen) != 0 ||
	!isblank((unsigned char)entry[proglen]))
    	return FALSE;
    entry += proglen + 1;
    while (isblank((unsigned char)*entry))
	entry++;

    debug_flags = strpbrk(entry, " \t");
    if (debug_flags == NULL)
    	return FALSE;
    filelen = (size_t)(debug_flags - entry);
    while (isblank((unsigned char)*debug_flags))
	debug_flags++;

    /* Set debug file and parse the flags. */
    debug_file = estrndup(entry, filelen);
    debug_flags = estrdup(debug_flags);
    sudo_debug_init(debug_file, debug_flags);

    return TRUE;
}

static int
set_path(const char *entry, void *data)
{
    const char *name, *path;
    struct sudo_conf_paths *cur;

    /* Parse Path line */
    name = entry;
    path = strpbrk(entry, " \t");
    if (path == NULL)
    	return FALSE;
    while (isblank((unsigned char)*path))
	path++;

    /* Match supported paths, ignore the rest. */
    for (cur = sudo_conf_paths; cur->pname != NULL; cur++) {
	if (strncasecmp(name, cur->pname, cur->pnamelen) == 0 &&
	    isblank((unsigned char)name[cur->pnamelen])) {
	    *(cur->pval) = estrdup(path);
	    break;
	}
    }

    return TRUE;
}

static int
set_plugin(const char *entry, void *data)
{
    struct plugin_info_list *pil = data;
    struct plugin_info *info;
    const char *name, *path;
    size_t namelen;

    /* Parse Plugin line */
    name = entry;
    path = strpbrk(entry, " \t");
    if (path == NULL)
    	return FALSE;
    namelen = (size_t)(path - name);
    while (isblank((unsigned char)*path))
	path++;

    info = emalloc(sizeof(*info));
    info->symbol_name = estrndup(name, namelen);
    info->path = estrdup(path);
    info->prev = info;
    info->next = NULL;
    tq_append(pil, info);

    return TRUE;
}

/*
 * Reads in /etc/sudo.conf
 * Returns a list of plugins.
 */
void
sudo_read_conf(void)
{
    struct sudo_conf_table *cur;
    struct plugin_info *info;
    FILE *fp;
    char *cp;

    if ((fp = fopen(_PATH_SUDO_CONF, "r")) == NULL)
	goto done;

    while ((cp = sudo_parseln(fp)) != NULL) {
	/* Skip blank or comment lines */
	if (*cp == '\0')
	    continue;

	for (cur = sudo_conf_table; cur->name != NULL; cur++) {
	    if (strncasecmp(cp, cur->name, cur->namelen) == 0 &&
		isblank((unsigned char)cp[cur->namelen])) {
		cp += cur->namelen;
		while (isblank((unsigned char)*cp))
		    cp++;
		if (cur->setter(cp, &plugin_info_list))
		    break;
	    }
	}
    }
    fclose(fp);

done:
    if (tq_empty(&plugin_info_list)) {
	/* Default policy plugin */
	info = emalloc(sizeof(*info));
	info->symbol_name = "sudoers_policy";
	info->path = SUDOERS_PLUGIN;
	info->prev = info;
	info->next = NULL;
	tq_append(&plugin_info_list, info);

	/* Default I/O plugin */
	info = emalloc(sizeof(*info));
	info->symbol_name = "sudoers_io";
	info->path = SUDOERS_PLUGIN;
	info->prev = info;
	info->next = NULL;
	tq_append(&plugin_info_list, info);
    }
}

/*
 * Load the plugins listed in sudo.conf.
 */
int
sudo_load_plugins(struct plugin_container *policy_plugin,
    struct plugin_container_list *io_plugins)
{
    struct generic_plugin *plugin;
    struct plugin_container *container;
    struct plugin_info *info;
    struct stat sb;
    void *handle;
    char path[PATH_MAX];
    int rval = FALSE;

    /* Walk plugin list. */
    tq_foreach_fwd(&plugin_info_list, info) {
	if (info->path[0] == '/') {
	    if (strlcpy(path, info->path, sizeof(path)) >= sizeof(path)) {
		warningx(_("%s: %s"), info->path, strerror(ENAMETOOLONG));
		goto done;
	    }
	} else {
	    if (snprintf(path, sizeof(path), "%s%s", _PATH_SUDO_PLUGIN_DIR,
		info->path) >= sizeof(path)) {
		warningx(_("%s%s: %s"), _PATH_SUDO_PLUGIN_DIR, info->path,
		    strerror(ENAMETOOLONG));
		goto done;
	    }
	}
	if (stat(path, &sb) != 0) {
	    warning("%s", path);
	    goto done;
	}
	if (sb.st_uid != ROOT_UID) {
	    warningx(_("%s must be owned by uid %d"), path, ROOT_UID);
	    goto done;
	}
	if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0) {
	    warningx(_("%s must be only be writable by owner"), path);
	    goto done;
	}

	/* Open plugin and map in symbol */
	handle = dlopen(path, RTLD_LAZY|RTLD_GLOBAL);
	if (!handle) {
	    warningx(_("unable to dlopen %s: %s"), path, dlerror());
	    goto done;
	}
	plugin = dlsym(handle, info->symbol_name);
	if (!plugin) {
	    warningx(_("%s: unable to find symbol %s"), path,
		info->symbol_name);
	    goto done;
	}

	if (plugin->type != SUDO_POLICY_PLUGIN && plugin->type != SUDO_IO_PLUGIN) {
	    warningx(_("%s: unknown policy type %d"), path, plugin->type);
	    goto done;
	}
	if (SUDO_API_VERSION_GET_MAJOR(plugin->version) != SUDO_API_VERSION_MAJOR) {
	    warningx(_("%s: incompatible policy major version %d, expected %d"),
		path, SUDO_API_VERSION_GET_MAJOR(plugin->version),
		SUDO_API_VERSION_MAJOR);
	    goto done;
	}
	if (plugin->type == SUDO_POLICY_PLUGIN) {
	    if (policy_plugin->handle) {
		warningx(_("%s: only a single policy plugin may be loaded"),
		    _PATH_SUDO_CONF);
		goto done;
	    }
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
    if (policy_plugin->handle == NULL) {
	warningx(_("%s: at least one policy plugin must be specified"),
	    _PATH_SUDO_CONF);
	goto done;
    }
    if (policy_plugin->u.policy->check_policy == NULL) {
	warningx(_("policy plugin %s does not include a check_policy method"),
	    policy_plugin->name);
	goto done;
    }

    rval = TRUE;

done:
    return rval;
}
