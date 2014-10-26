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
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#define SUDO_ERROR_WRAP	0

#include "sudo_compat.h"
#include "sudo_alloc.h"
#include "sudo_fatal.h"
#include "pathnames.h"
#include "sudo_plugin.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_util.h"

#ifdef __TANDEM
# define ROOT_UID	65535
#else
# define ROOT_UID	0
#endif

struct sudo_conf_table {
    const char *name;
    unsigned int namelen;
    void (*parser)(const char *entry, unsigned int lineno);
};

struct sudo_conf_var_table {
    const char *name;
    bool (*setter)(const char *entry, const char *conf_file, unsigned int conf_lineno);
};

struct sudo_conf_path_table {
    const char *pname;
    const char *pval;
};

struct sudo_conf_setting {
    TAILQ_ENTRY(sudo_conf_setting) entries;
    char *name;
    char *value;
    unsigned int lineno;
};
TAILQ_HEAD(sudo_conf_setting_list, sudo_conf_setting);

static void store_debug(const char *entry, unsigned int lineno);
static void store_path(const char *entry, unsigned int lineno);
static void store_plugin(const char *entry, unsigned int lineno);
static void store_variable(const char *entry, unsigned int lineno);

static struct sudo_conf_table sudo_conf_table[] = {
    { "Debug", sizeof("Debug") - 1, store_debug },
    { "Path", sizeof("Path") - 1, store_path },
    { "Plugin", sizeof("Plugin") - 1, store_plugin },
    { "Set", sizeof("Set") - 1, store_variable },
    { NULL }
};

static bool set_var_disable_coredump(const char *entry, const char *conf_file, unsigned int);
static bool set_var_group_source(const char *entry, const char *conf_file, unsigned int);
static bool set_var_max_groups(const char *entry, const char *conf_file, unsigned int);
static bool set_var_probe_interfaces(const char *entry, const char *conf_file, unsigned int);

static struct sudo_conf_var_table sudo_conf_var_table[] = {
    { "disable_coredump", set_var_disable_coredump },
    { "group_source", set_var_group_source },
    { "max_groups", set_var_max_groups },
    { "probe_interfaces", set_var_probe_interfaces },
    { NULL }
};

/* XXX - it would be nice to make this local to sudo_conf_read */
static struct sudo_conf_data {
    bool disable_coredump;
    bool probe_interfaces;
    int group_source;
    int max_groups;
    struct sudo_conf_setting_list paths;
    struct sudo_conf_setting_list settings;
    struct sudo_conf_debug_list debugging;
    struct plugin_info_list plugins;
    struct sudo_conf_path_table path_table[5];
} sudo_conf_data = {
    true,
    true,
    GROUP_SOURCE_ADAPTIVE,
    -1,
    TAILQ_HEAD_INITIALIZER(sudo_conf_data.paths),
    TAILQ_HEAD_INITIALIZER(sudo_conf_data.settings),
    TAILQ_HEAD_INITIALIZER(sudo_conf_data.debugging),
    TAILQ_HEAD_INITIALIZER(sudo_conf_data.plugins),
    {
#define SUDO_CONF_ASKPASS_IDX	0
	{ "askpass", _PATH_SUDO_ASKPASS },
#define SUDO_CONF_SESH_IDX	1
	{ "sesh", _PATH_SUDO_SESH },
#ifdef _PATH_SUDO_NOEXEC
#define SUDO_CONF_NOEXEC_IDX	2
	{ "noexec", _PATH_SUDO_NOEXEC },
#endif
#ifdef _PATH_SUDO_PLUGIN_DIR
#define SUDO_CONF_PLUGIN_IDX	3
	{ "plugin", _PATH_SUDO_PLUGIN_DIR },
#endif
	{ NULL }
    }
};

/*
 * "Set variable_name value"
 */
static void
store_variable(const char *entry, unsigned int lineno)
{
    struct sudo_conf_setting *setting;
    const char *value;
    size_t namelen;

    /* Split line into name and value. */
    namelen = strcspn(entry, " \t");
    if (entry[namelen] == '\0')
	return;		/* no value! */
    value = entry + namelen;
    do {
	value++;
    } while (isblank((unsigned char)*value));
    if (*value == '\0')
	return;		/* no value! */

    setting = sudo_ecalloc(1, sizeof(*setting));
    setting->name = sudo_estrndup(entry, namelen);
    setting->value = sudo_estrdup(value);
    setting->lineno = lineno;
    TAILQ_INSERT_TAIL(&sudo_conf_data.settings, setting, entries);
}

/*
 * "Path name /path/to/file"
 */
static void
store_path(const char *entry, unsigned int lineno)
{
    struct sudo_conf_setting *path_spec;
    const char *path;
    size_t namelen;

    /* Split line into name and path. */
    namelen = strcspn(entry, " \t");
    if (entry[namelen] == '\0')
	return;		/* no path! */
    path = entry + namelen;
    do {
	path++;
    } while (isblank((unsigned char)*path));
    if (*path == '\0')
	return;		/* no path! */

    path_spec = sudo_ecalloc(1, sizeof(*path_spec));
    path_spec->name = sudo_estrndup(entry, namelen);
    path_spec->value = sudo_estrdup(path);
    path_spec->lineno = lineno;
    TAILQ_INSERT_TAIL(&sudo_conf_data.paths, path_spec, entries);
}

/*
 * "Debug program /path/to/log flags,..."
 */
static void
store_debug(const char *progname, unsigned int lineno)
{
    struct sudo_conf_debug *debug_spec;
    struct sudo_debug_file *debug_file;
    const char *path, *flags, *cp = progname;
    size_t pathlen, prognamelen;

    /* Parse progname. */
    while (*cp != '\0' && !isblank((unsigned char)*cp))
	cp++;
    if (*cp == '\0')
	return;		/* not enough fields */
    prognamelen = (size_t)(cp - progname);
    do {
	cp++;
    } while (isblank((unsigned char)*cp));
    if (*cp == '\0')
	return;		/* not enough fields */

    /* Parse path. */
    path = cp;
    while (*cp != '\0' && !isblank((unsigned char)*cp))
	cp++;
    if (*cp == '\0')
	return;		/* not enough fields */
    pathlen = (size_t)(cp - path);
    do {
	cp++;
    } while (isblank((unsigned char)*cp));
    if (*cp == '\0')
	return;		/* not enough fields */

    /* Remainder is flags (freeform). */
    flags = cp;

    /* If progname already exists, use it, else alloc a new one. */
    TAILQ_FOREACH(debug_spec, &sudo_conf_data.debugging, entries) {
	if (strncmp(debug_spec->progname, progname, prognamelen) == 0 &&
	    debug_spec->progname[prognamelen] == '\0' &&
	    isblank((unsigned char)debug_spec->progname[prognamelen]))
	    break;
    }
    if (debug_spec == NULL) {
	debug_spec = sudo_emalloc(sizeof(*debug_spec));
	debug_spec->progname = sudo_estrndup(progname, prognamelen);
	TAILQ_INIT(&debug_spec->debug_files);
	TAILQ_INSERT_TAIL(&sudo_conf_data.debugging, debug_spec, entries);
    }
    debug_file = sudo_emalloc(sizeof(*debug_file));
    debug_file->debug_file = sudo_estrndup(path, pathlen);
    debug_file->debug_flags = sudo_estrdup(flags);
    TAILQ_INSERT_TAIL(&debug_spec->debug_files, debug_file, entries);
}

/*
 * "Plugin symbol /path/to/log args..."
 */
static void
store_plugin(const char *cp, unsigned int lineno)
{
    struct plugin_info *info;
    const char *ep, *path, *symbol;
    char **options = NULL;
    size_t pathlen, symlen;
    unsigned int nopts;

    /* Parse symbol. */
    if (*cp == '\0')
	return;		/* not enough fields */
    symbol = cp;
    while (*cp != '\0' && !isblank((unsigned char)*cp))
	cp++;
    symlen = (size_t)(cp - symbol);
    while (isblank((unsigned char)*cp))
	cp++;

    /* Parse path. */
    if (*cp == '\0')
	return;		/* not enough fields */
    path = cp;
    while (*cp != '\0' && !isblank((unsigned char)*cp))
	cp++;
    pathlen = (size_t)(cp - path);
    while (isblank((unsigned char)*cp))
	cp++;

    /* Split options into an array if present. */
    /* XXX - consider as separate function */
    if (*cp != '\0') {
	/* Count number of options and allocate array. */
	for (ep = cp, nopts = 1; (ep = strpbrk(ep, " \t")) != NULL; nopts++) {
	    while (isblank((unsigned char)*ep))
		ep++;
	}
	options = sudo_emallocarray(nopts + 1, sizeof(*options));
	/* Fill in options array, there is at least one element. */
	for (nopts = 0; (ep = strpbrk(cp, " \t")) != NULL; ) {
	    options[nopts++] = sudo_estrndup(cp, (size_t)(ep - cp));
	    while (isblank((unsigned char)*ep))
		ep++;
	    cp = ep;
	}
	options[nopts++] = sudo_estrdup(cp);
	options[nopts] = NULL;
    }

    info = sudo_emalloc(sizeof(*info));
    info->symbol_name = sudo_estrndup(symbol, symlen);
    info->path = sudo_estrndup(path, pathlen);
    info->options = options;
    info->lineno = lineno;
    TAILQ_INSERT_TAIL(&sudo_conf_data.plugins, info, entries);
}

/*
 * Update path settings.
 */
static void
set_paths(const char *conf_file)
{
    struct sudo_conf_setting *path_spec, *next;
    unsigned int i;
    debug_decl(sudo_conf_set_paths, SUDO_DEBUG_UTIL, SUDO_DEBUG_INSTANCE_DEFAULT)

    /*
     * Store matching paths in sudo_conf_data.path_table.
     */
    TAILQ_FOREACH_SAFE(path_spec, &sudo_conf_data.paths, entries, next) {
	TAILQ_REMOVE(&sudo_conf_data.paths, path_spec, entries);
	/* Store path in sudo_conf_data, ignoring unsupported paths. */
	for (i = 0; sudo_conf_data.path_table[i].pname != NULL; i++) {
	    if (strcmp(path_spec->name, sudo_conf_data.path_table[i].pname) == 0) {
		sudo_conf_data.path_table[i].pval = path_spec->value;
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: %s:%u: path %s=%s\n", __func__, conf_file,
		    path_spec->lineno, path_spec->name, path_spec->value);
		break;
	    }
	}
	if (sudo_conf_data.path_table[i].pname == NULL) {
	    /* not found */
	    sudo_debug_printf(SUDO_DEBUG_WARN,
		"%s: %s:%u: unknown path %s=%s\n", __func__, conf_file,
		path_spec->lineno, path_spec->name, path_spec->value);
	    sudo_efree(path_spec->value);
	}
	sudo_efree(path_spec->name);
	sudo_efree(path_spec);
    }
    debug_return;
}

/*
 * Update variable settings.
 */
static void
set_variables(const char *conf_file)
{
    struct sudo_conf_setting *setting, *next;
    struct sudo_conf_var_table *var;
    debug_decl(sudo_conf_set_variables, SUDO_DEBUG_UTIL, SUDO_DEBUG_INSTANCE_DEFAULT)

    TAILQ_FOREACH_SAFE(setting, &sudo_conf_data.settings, entries, next) {
	TAILQ_REMOVE(&sudo_conf_data.settings, setting, entries);
	for (var = sudo_conf_var_table; var->name != NULL; var++) {
	    if (strcmp(setting->name, var->name) == 0) {
		if (var->setter(setting->value, conf_file, setting->lineno)) {
		    sudo_debug_printf(SUDO_DEBUG_INFO,
			"%s: %s:%u: var %s=%s\n", __func__, conf_file,
			setting->lineno, setting->name, setting->value);
		}
		break;
	    }
	}
	if (var->name == NULL) {
	    /* not found */
	    sudo_debug_printf(SUDO_DEBUG_WARN,
		"%s: %s:%u: unknown var %s=%s\n", __func__, conf_file,
		setting->lineno, setting->name, setting->value);
	}
	sudo_efree(setting->name);
	sudo_efree(setting->value);
	sudo_efree(setting);
    }
    debug_return;
}

static bool
set_var_disable_coredump(const char *entry, const char *conf_file,
    unsigned int conf_lineno)
{
    int val = sudo_strtobool(entry);

    if (val == -1)
	return false;
    sudo_conf_data.disable_coredump = val;
    return true;
}

static bool
set_var_group_source(const char *strval, const char *conf_file,
    unsigned int conf_lineno)
{
    if (strcasecmp(strval, "adaptive") == 0) {
	sudo_conf_data.group_source = GROUP_SOURCE_ADAPTIVE;
    } else if (strcasecmp(strval, "static") == 0) {
	sudo_conf_data.group_source = GROUP_SOURCE_STATIC;
    } else if (strcasecmp(strval, "dynamic") == 0) {
	sudo_conf_data.group_source = GROUP_SOURCE_DYNAMIC;
    } else {
	sudo_warnx(U_("unsupported group source `%s' in %s, line %d"), strval,
	    conf_file, conf_lineno);
	return false;
    }
    return true;
}

static bool
set_var_max_groups(const char *strval, const char *conf_file,
    unsigned int conf_lineno)
{
    int max_groups;

    max_groups = strtonum(strval, 1, INT_MAX, NULL);
    if (max_groups <= 0) {
	sudo_warnx(U_("invalid max groups `%s' in %s, line %d"), strval,
	    conf_file, conf_lineno);
	return false;
    }
    sudo_conf_data.max_groups = max_groups;
    return true;
}

static bool
set_var_probe_interfaces(const char *strval, const char *conf_file,
    unsigned int conf_lineno)
{
    int val = sudo_strtobool(strval);

    if (val == -1)
	return false;
    sudo_conf_data.probe_interfaces = val;
    return true;
}

const char *
sudo_conf_askpass_path_v1(void)
{
    return sudo_conf_data.path_table[SUDO_CONF_ASKPASS_IDX].pval;
}

const char *
sudo_conf_sesh_path_v1(void)
{
    return sudo_conf_data.path_table[SUDO_CONF_SESH_IDX].pval;
}

#ifdef _PATH_SUDO_NOEXEC
const char *
sudo_conf_noexec_path_v1(void)
{
    return sudo_conf_data.path_table[SUDO_CONF_NOEXEC_IDX].pval;
}
#endif

#ifdef _PATH_SUDO_PLUGIN_DIR
const char *
sudo_conf_plugin_dir_path_v1(void)
{
    return sudo_conf_data.path_table[SUDO_CONF_PLUGIN_IDX].pval;
}
#endif

int
sudo_conf_group_source_v1(void)
{
    return sudo_conf_data.group_source;
}

int
sudo_conf_max_groups_v1(void)
{
    return sudo_conf_data.max_groups;
}

struct plugin_info_list *
sudo_conf_plugins_v1(void)
{
    return &sudo_conf_data.plugins;
}

struct sudo_conf_debug_list *
sudo_conf_debugging_v1(void)
{
    return &sudo_conf_data.debugging;
}

/* Return the debug files list for a program, or NULL if none. */
struct sudo_conf_debug_file_list *
sudo_conf_debug_files_v1(const char *progname)
{
    struct sudo_conf_debug *debug_spec;
    size_t prognamelen, progbaselen;
    const char *progbase = progname;
    debug_decl(sudo_conf_debug_files, SUDO_DEBUG_UTIL, SUDO_DEBUG_INSTANCE_DEFAULT)

    /* Determine basename if program is fully qualified (like for plugins). */
    prognamelen = progbaselen = strlen(progname);
    if (*progname == '/') {
	progbase = strrchr(progname, '/');
	progbaselen = strlen(++progbase);
    }
    /* Convert sudoedit -> sudo. */
    if (progbaselen > 4 && strcmp(progbase + 4, "edit") == 0) {
	progbaselen -= 4;
    }
    TAILQ_FOREACH(debug_spec, &sudo_conf_data.debugging, entries) {
	const char *prog = progbase;
	size_t len = progbaselen;

	if (debug_spec->progname[0] == '/') {
	    /* Match fully-qualified name, if possible. */
	    prog = progname;
	    len = prognamelen;
	}
	if (strncmp(debug_spec->progname, prog, len) == 0 &&
	    debug_spec->progname[len] == '\0') {
	    debug_return_ptr(&debug_spec->debug_files);
	}
    }
    debug_return_ptr(NULL);
}

bool
sudo_conf_disable_coredump_v1(void)
{
    return sudo_conf_data.disable_coredump;
}

bool
sudo_conf_probe_interfaces_v1(void)
{
    return sudo_conf_data.probe_interfaces;
}

/*
 * Reads in /etc/sudo.conf and populates sudo_conf_data.
 */
void
sudo_conf_read_v1(const char *conf_file, int conf_types)
{
    struct stat sb;
    FILE *fp;
    char *line = NULL;
    char *prev_locale = sudo_estrdup(setlocale(LC_ALL, NULL));
    unsigned int conf_lineno = 0;
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
		    sudo_warn(U_("unable to stat %s"), conf_file);
		goto done;
	    case SUDO_PATH_BAD_TYPE:
		sudo_warnx(U_("%s is not a regular file"), conf_file);
		goto done;
	    case SUDO_PATH_WRONG_OWNER:
		sudo_warnx(U_("%s is owned by uid %u, should be %u"),
		    conf_file, (unsigned int) sb.st_uid, ROOT_UID);
		goto done;
	    case SUDO_PATH_WORLD_WRITABLE:
		sudo_warnx(U_("%s is world writable"), conf_file);
		goto done;
	    case SUDO_PATH_GROUP_WRITABLE:
		sudo_warnx(U_("%s is group writable"), conf_file);
		goto done;
	    default:
		/* NOTREACHED */
		goto done;
	}
    }

    if ((fp = fopen(conf_file, "r")) == NULL) {
	if (errno != ENOENT && geteuid() == ROOT_UID)
	    sudo_warn(U_("unable to open %s"), conf_file);
	goto done;
    }

    while (sudo_parseln(&line, &linesize, &conf_lineno, fp) != -1) {
	struct sudo_conf_table *cur;
	unsigned int i;
	char *cp;

	if (*(cp = line) == '\0')
	    continue;		/* empty line or comment */

	for (i = 0, cur = sudo_conf_table; cur->name != NULL; i++, cur++) {
	    if (!ISSET(conf_types, (1 << i)))
		continue;
	    if (strncasecmp(cp, cur->name, cur->namelen) == 0 &&
		isblank((unsigned char)cp[cur->namelen])) {
		cp += cur->namelen;
		while (isblank((unsigned char)*cp))
		    cp++;
		cur->parser(cp, conf_lineno);
		break;
	    }
	}
    }
    fclose(fp);
    free(line);

    /* Parse paths and variables as needed. */
    if (ISSET(conf_types, SUDO_CONF_PATHS))
	set_paths(conf_file);
    if (ISSET(conf_types, SUDO_CONF_SETTINGS))
	set_variables(conf_file);

done:
    /* Restore locale if needed. */
    if (prev_locale[0] != 'C' || prev_locale[1] != '\0')
        setlocale(LC_ALL, prev_locale);
    sudo_efree(prev_locale);
}
