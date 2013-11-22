/*
 * Copyright (c) 2010-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/time.h>
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
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <pwd.h>

#include "sudoers.h"
#include "sudo_dso.h"

#if defined(HAVE_DLOPEN) || defined(HAVE_SHL_LOAD)

static void *group_handle;
static struct sudoers_group_plugin *group_plugin;

/*
 * Load the specified plugin and run its init function.
 * Returns -1 if unable to open the plugin, else it returns
 * the value from the plugin's init function.
 */
int
group_plugin_load(char *plugin_info)
{
    struct stat sb;
    char *args, path[PATH_MAX];
    char **argv = NULL;
    int len, rc = -1;
    debug_decl(group_plugin_load, SUDO_DEBUG_UTIL)

    /*
     * Fill in .so path and split out args (if any).
     */
    if ((args = strpbrk(plugin_info, " \t")) != NULL) {
	len = snprintf(path, sizeof(path), "%s%.*s",
	    (*plugin_info != '/') ? _PATH_SUDO_PLUGIN_DIR : "",
	    (int)(args - plugin_info), plugin_info);
	args++;
    } else {
	len = snprintf(path, sizeof(path), "%s%s",
	    (*plugin_info != '/') ? _PATH_SUDO_PLUGIN_DIR : "", plugin_info);
    }
    if (len <= 0 || (size_t)len >= sizeof(path)) {
	errno = ENAMETOOLONG;
	warning("%s%s",
	    (*plugin_info != '/') ? _PATH_SUDO_PLUGIN_DIR : "", plugin_info);
	goto done;
    }

    /* Sanity check plugin path. */
    if (stat(path, &sb) != 0) {
	warning("%s", path);
	goto done;
    }
    if (sb.st_uid != ROOT_UID) {
	warningx(U_("%s must be owned by uid %d"), path, ROOT_UID);
	goto done;
    }
    if ((sb.st_mode & (S_IWGRP|S_IWOTH)) != 0) {
	warningx(U_("%s must only be writable by owner"), path);
	goto done;
    }

    /* Open plugin and map in symbol. */
    group_handle = sudo_dso_load(path, SUDO_DSO_LAZY|SUDO_DSO_GLOBAL);
    if (!group_handle) {
	warningx(U_("unable to load %s: %s"), path, sudo_dso_strerror());
	goto done;
    }
    group_plugin = sudo_dso_findsym(group_handle, "group_plugin");
    if (group_plugin == NULL) {
	warningx(U_("unable to find symbol \"group_plugin\" in %s"), path);
	goto done;
    }

    if (GROUP_API_VERSION_GET_MAJOR(group_plugin->version) != GROUP_API_VERSION_MAJOR) {
	warningx(U_("%s: incompatible group plugin major version %d, expected %d"),
	    path, GROUP_API_VERSION_GET_MAJOR(group_plugin->version),
	    GROUP_API_VERSION_MAJOR);
	goto done;
    }

    /*
     * Split args into a vector if specified.
     */
    if (args != NULL) {
	int ac = 0;
	bool wasblank = true;
	char *cp;

        for (cp = args; *cp != '\0'; cp++) {
            if (isblank((unsigned char)*cp)) {
                wasblank = true;
            } else if (wasblank) {
                wasblank = false;
                ac++;
            }
        }
	if (ac != 0) 	{
	    argv = emalloc2(ac, sizeof(char *));
	    ac = 0;
	    for ((cp = strtok(args, " \t")); cp; (cp = strtok(NULL, " \t")))
		argv[ac++] = cp;
	}
    }

    rc = (group_plugin->init)(GROUP_API_VERSION, sudo_printf, argv);

done:
    efree(argv);

    if (rc != true) {
	if (group_handle != NULL) {
	    sudo_dso_unload(group_handle);
	    group_handle = NULL;
	    group_plugin = NULL;
	}
    }

    debug_return_bool(rc);
}

void
group_plugin_unload(void)
{
    debug_decl(group_plugin_unload, SUDO_DEBUG_UTIL)

    if (group_plugin != NULL) {
	(group_plugin->cleanup)();
	group_plugin = NULL;
    }
    if (group_handle != NULL) {
	sudo_dso_unload(group_handle);
	group_handle = NULL;
    }
    debug_return;
}

int
group_plugin_query(const char *user, const char *group,
    const struct passwd *pwd)
{
    debug_decl(group_plugin_query, SUDO_DEBUG_UTIL)

    if (group_plugin == NULL)
	debug_return_bool(false);
    debug_return_bool((group_plugin->query)(user, group, pwd));
}

#else /* !HAVE_DLOPEN && !HAVE_SHL_LOAD */

/*
 * No loadable shared object support.
 */

int
group_plugin_load(char *plugin_info)
{
    debug_decl(group_plugin_load, SUDO_DEBUG_UTIL)
    debug_return_bool(false);
}

void
group_plugin_unload(void)
{
    debug_decl(group_plugin_unload, SUDO_DEBUG_UTIL)
    debug_return;
}

int
group_plugin_query(const char *user, const char *group,
    const struct passwd *pwd)
{
    debug_decl(group_plugin_query, SUDO_DEBUG_UTIL)
    debug_return_bool(false);
}

#endif /* HAVE_DLOPEN || HAVE_SHL_LOAD */
