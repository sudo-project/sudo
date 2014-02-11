/*
 * Copyright (c) 2009-2014 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <ctype.h>
#include <errno.h>
#include <limits.h>

#define DEFAULT_TEXT_DOMAIN	"sudo"
#include "gettext.h"		/* must be included before missing.h */

#define SUDO_ERROR_WRAP	0

#include "missing.h"
#include "alloc.h"
#include "fatal.h"
#include "fileops.h"
#include "pathnames.h"
#include "sudo_plugin.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "secure_path.h"

#ifdef __TANDEM
# define ROOT_UID	65535
#else
# define ROOT_UID	0
#endif

struct sudo_conf_table {
    const char *name;
    unsigned int namelen;
    void (*setter)(const char *entry, const char *conf_file);
};

struct sudo_conf_paths {
    const char *pname;
    unsigned int pnamelen;
    const char *pval;
};

static void set_debug(const char *entry, const char *conf_file);
static void set_path(const char *entry, const char *conf_file);
static void set_plugin(const char *entry, const char *conf_file);
static void set_variable(const char *entry, const char *conf_file);
static void set_var_disable_coredump(const char *entry, const char *conf_file);
static void set_var_group_source(const char *entry, const char *conf_file);
static void set_var_max_groups(const char *entry, const char *conf_file);
static void set_var_probe_interfaces(const char *entry, const char *conf_file);

static unsigned int conf_lineno;

static struct sudo_conf_table sudo_conf_table[] = {
    { "Debug", sizeof("Debug") - 1, set_debug },
    { "Path", sizeof("Path") - 1, set_path },
    { "Plugin", sizeof("Plugin") - 1, set_plugin },
    { "Set", sizeof("Set") - 1, set_variable },
    { NULL }
};

static struct sudo_conf_table sudo_conf_table_vars[] = {
    { "disable_coredump", sizeof("disable_coredump") - 1, set_var_disable_coredump },
    { "group_source", sizeof("group_source") - 1, set_var_group_source },
    { "max_groups", sizeof("max_groups") - 1, set_var_max_groups },
    { "probe_interfaces", sizeof("probe_interfaces") - 1, set_var_probe_interfaces },
    { NULL }
};

static struct sudo_conf_data {
    bool disable_coredump;
    bool probe_interfaces;
    int group_source;
    int max_groups;
    const char *debug_flags;
    struct plugin_info_list plugins;
    struct sudo_conf_paths paths[5];
} sudo_conf_data = {
    true,
    true,
    GROUP_SOURCE_ADAPTIVE,
    -1,
    NULL,
    TAILQ_HEAD_INITIALIZER(sudo_conf_data.plugins),
    {
#define SUDO_CONF_ASKPASS_IDX	0
	{ "askpass", sizeof("askpass") - 1, _PATH_SUDO_ASKPASS },
#define SUDO_CONF_SESH_IDX	1
	{ "sesh", sizeof("sesh") - 1, _PATH_SUDO_SESH },
#ifdef _PATH_SUDO_NOEXEC
#define SUDO_CONF_NOEXEC_IDX	2
	{ "noexec", sizeof("noexec") - 1, _PATH_SUDO_NOEXEC },
#endif
#ifdef _PATH_SUDO_PLUGIN_DIR
#define SUDO_CONF_PLUGIN_IDX	3
	{ "plugin", sizeof("plugin") - 1, _PATH_SUDO_PLUGIN_DIR },
#endif
	{ NULL }
    }
};

/*
 * "Set variable_name value"
 */
static void
set_variable(const char *entry, const char *conf_file)
{
    struct sudo_conf_table *var;

    for (var = sudo_conf_table_vars; var->name != NULL; var++) {
	if (strncmp(entry, var->name, var->namelen) == 0 &&
	    isblank((unsigned char)entry[var->namelen])) {
	    entry += var->namelen + 1;
	    while (isblank((unsigned char)*entry))
		entry++;
	    var->setter(entry, conf_file);
	    break;
	}
    }
}

static void
set_var_disable_coredump(const char *entry, const char *conf_file)
{
    int val = atobool(entry);

    if (val != -1)
	sudo_conf_data.disable_coredump = val;
}

static void
set_var_group_source(const char *entry, const char *conf_file)
{
    if (strcasecmp(entry, "adaptive") == 0) {
	sudo_conf_data.group_source = GROUP_SOURCE_ADAPTIVE;
    } else if (strcasecmp(entry, "static") == 0) {
	sudo_conf_data.group_source = GROUP_SOURCE_STATIC;
    } else if (strcasecmp(entry, "dynamic") == 0) {
	sudo_conf_data.group_source = GROUP_SOURCE_DYNAMIC;
    } else {
	warningx(U_("unsupported group source `%s' in %s, line %d"), entry,
	    conf_file, conf_lineno);
    }
}

static void
set_var_max_groups(const char *entry, const char *conf_file)
{
    int max_groups;

    max_groups = strtonum(entry, 1, INT_MAX, NULL);
    if (max_groups > 0) {
	sudo_conf_data.max_groups = max_groups;
    } else {
	warningx(U_("invalid max groups `%s' in %s, line %d"), entry,
	    conf_file, conf_lineno);
    }
}

static void
set_var_probe_interfaces(const char *entry, const char *conf_file)
{
    int val = atobool(entry);

    if (val != -1)
	sudo_conf_data.probe_interfaces = val;
}

/*
 * "Debug progname debug_file debug_flags"
 */
static void
set_debug(const char *entry, const char *conf_file)
{
    size_t filelen, proglen;
    const char *progname;
    char *debug_file, *debug_flags;

    /* Is this debug setting for me? */
    progname = getprogname();
    if (strcmp(progname, "sudoedit") == 0)
	progname = "sudo";
    proglen = strlen(progname);
    if (strncmp(entry, progname, proglen) != 0 ||
	!isblank((unsigned char)entry[proglen]))
    	return;
    entry += proglen + 1;
    while (isblank((unsigned char)*entry))
	entry++;

    debug_flags = strpbrk(entry, " \t");
    if (debug_flags == NULL)
    	return;
    filelen = (size_t)(debug_flags - entry);
    while (isblank((unsigned char)*debug_flags))
	debug_flags++;

    /* Set debug file and parse the flags (init debug as soon as possible). */
    debug_file = estrndup(entry, filelen);
    debug_flags = estrdup(debug_flags);
    sudo_debug_init(debug_file, debug_flags);
    efree(debug_file);

    sudo_conf_data.debug_flags = debug_flags;
}

static void
set_path(const char *entry, const char *conf_file)
{
    const char *name, *path;
    struct sudo_conf_paths *cur;

    /* Parse Path line */
    name = entry;
    path = strpbrk(entry, " \t");
    if (path == NULL)
    	return;
    while (isblank((unsigned char)*path))
	path++;

    /* Match supported paths, ignore the rest. */
    for (cur = sudo_conf_data.paths; cur->pname != NULL; cur++) {
	if (strncasecmp(name, cur->pname, cur->pnamelen) == 0 &&
	    isblank((unsigned char)name[cur->pnamelen])) {
	    cur->pval = estrdup(path);
	    break;
	}
    }
}

static void
set_plugin(const char *entry, const char *conf_file)
{
    struct plugin_info *info;
    const char *name, *path, *cp, *ep;
    char **options = NULL;
    size_t namelen, pathlen;
    unsigned int nopts;

    /* Parse Plugin line */
    name = entry;
    path = strpbrk(entry, " \t");
    if (path == NULL)
    	return;
    namelen = (size_t)(path - name);
    while (isblank((unsigned char)*path))
	path++;
    if ((cp = strpbrk(path, " \t")) != NULL) {
	/* Convert any options to an array. */
	pathlen = (size_t)(cp - path);
	while (isblank((unsigned char)*cp))
	    cp++;
	/* Count number of options and allocate array. */
	for (ep = cp, nopts = 1; (ep = strpbrk(ep, " \t")) != NULL; nopts++) {
	    while (isblank((unsigned char)*ep))
		ep++;
	}
	options = emalloc2(nopts + 1, sizeof(*options));
	/* Fill in options array, there is at least one element. */
	for (nopts = 0; (ep = strpbrk(cp, " \t")) != NULL; ) {
	    options[nopts++] = estrndup(cp, (size_t)(ep - cp));
	    while (isblank((unsigned char)*ep))
		ep++;
	    cp = ep;
	}
	options[nopts++] = estrdup(cp);
	options[nopts] = NULL;
    } else {
	/* No extra options. */
	pathlen = strlen(path);
    }

    info = ecalloc(1, sizeof(*info));
    info->symbol_name = estrndup(name, namelen);
    info->path = estrndup(path, pathlen);
    info->options = options;
    info->lineno = conf_lineno;
    TAILQ_INSERT_TAIL(&sudo_conf_data.plugins, info, entries);
}

const char *
sudo_conf_askpass_path(void)
{
    return sudo_conf_data.paths[SUDO_CONF_ASKPASS_IDX].pval;
}

const char *
sudo_conf_sesh_path(void)
{
    return sudo_conf_data.paths[SUDO_CONF_SESH_IDX].pval;
}

#ifdef _PATH_SUDO_NOEXEC
const char *
sudo_conf_noexec_path(void)
{
    return sudo_conf_data.paths[SUDO_CONF_NOEXEC_IDX].pval;
}
#endif

#ifdef _PATH_SUDO_PLUGIN_DIR
const char *
sudo_conf_plugin_dir_path(void)
{
    return sudo_conf_data.paths[SUDO_CONF_PLUGIN_IDX].pval;
}
#endif

const char *
sudo_conf_debug_flags(void)
{
    return sudo_conf_data.debug_flags;
}

int
sudo_conf_group_source(void)
{
    return sudo_conf_data.group_source;
}

int
sudo_conf_max_groups(void)
{
    return sudo_conf_data.max_groups;
}

struct plugin_info_list *
sudo_conf_plugins(void)
{
    return &sudo_conf_data.plugins;
}

bool
sudo_conf_disable_coredump(void)
{
    return sudo_conf_data.disable_coredump;
}

bool
sudo_conf_probe_interfaces(void)
{
    return sudo_conf_data.probe_interfaces;
}

/*
 * Reads in /etc/sudo.conf and populates sudo_conf_data.
 */
void
sudo_conf_read(const char *conf_file)
{
    struct sudo_conf_table *cur;
    struct stat sb;
    FILE *fp;
    char *cp, *line = NULL;
    char *prev_locale = estrdup(setlocale(LC_ALL, NULL));
    size_t linesize = 0;

    /* Parse sudo.conf in the "C" locale. */
    if (prev_locale[0] != 'C' || prev_locale[1] != '\0')
        setlocale(LC_ALL, "C");

    if (conf_file == NULL) {
	conf_file = _PATH_SUDO_CONF;
	switch (sudo_secure_file(conf_file, ROOT_UID, -1, &sb)) {
	    case SUDO_PATH_SECURE:
		break;
	    case SUDO_PATH_MISSING:
		/* Root should always be able to read sudo.conf. */
		if (errno != ENOENT && geteuid() == ROOT_UID)
		    warning(U_("unable to stat %s"), conf_file);
		goto done;
	    case SUDO_PATH_BAD_TYPE:
		warningx(U_("%s is not a regular file"), conf_file);
		goto done;
	    case SUDO_PATH_WRONG_OWNER:
		warningx(U_("%s is owned by uid %u, should be %u"),
		    conf_file, (unsigned int) sb.st_uid, ROOT_UID);
		goto done;
	    case SUDO_PATH_WORLD_WRITABLE:
		warningx(U_("%s is world writable"), conf_file);
		goto done;
	    case SUDO_PATH_GROUP_WRITABLE:
		warningx(U_("%s is group writable"), conf_file);
		goto done;
	    default:
		/* NOTREACHED */
		goto done;
	}
    }

    if ((fp = fopen(conf_file, "r")) == NULL) {
	if (errno != ENOENT && geteuid() == ROOT_UID)
	    warning(U_("unable to open %s"), conf_file);
	goto done;
    }

    conf_lineno = 0;
    while (sudo_parseln(&line, &linesize, &conf_lineno, fp) != -1) {
	if (*(cp = line) == '\0')
	    continue;		/* empty line or comment */

	for (cur = sudo_conf_table; cur->name != NULL; cur++) {
	    if (strncasecmp(cp, cur->name, cur->namelen) == 0 &&
		isblank((unsigned char)cp[cur->namelen])) {
		cp += cur->namelen;
		while (isblank((unsigned char)*cp))
		    cp++;
		cur->setter(cp, conf_file);
		break;
	    }
	}
    }
    fclose(fp);
    free(line);
done:
    /* Restore locale if needed. */
    if (prev_locale[0] != 'C' || prev_locale[1] != '\0')
        setlocale(LC_ALL, prev_locale);
    efree(prev_locale);
}
