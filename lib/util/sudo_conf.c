/*
 * Copyright (c) 2009-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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
    bool (*parser)(const char *entry, const char *conf_file, unsigned int lineno);
};

struct sudo_conf_path_table {
    const char *pname;
    unsigned int pnamelen;
    const char *pval;
};

static bool parse_debug(const char *entry, const char *conf_file, unsigned int lineno);
static bool parse_path(const char *entry, const char *conf_file, unsigned int lineno);
static bool parse_plugin(const char *entry, const char *conf_file, unsigned int lineno);
static bool parse_variable(const char *entry, const char *conf_file, unsigned int lineno);

static struct sudo_conf_table sudo_conf_table[] = {
    { "Debug", sizeof("Debug") - 1, parse_debug },
    { "Path", sizeof("Path") - 1, parse_path },
    { "Plugin", sizeof("Plugin") - 1, parse_plugin },
    { "Set", sizeof("Set") - 1, parse_variable },
    { NULL }
};

static bool set_var_disable_coredump(const char *entry, const char *conf_file, unsigned int);
static bool set_var_group_source(const char *entry, const char *conf_file, unsigned int);
static bool set_var_max_groups(const char *entry, const char *conf_file, unsigned int);
static bool set_var_probe_interfaces(const char *entry, const char *conf_file, unsigned int);

static struct sudo_conf_table sudo_conf_var_table[] = {
    { "disable_coredump", sizeof("disable_coredump") - 1, set_var_disable_coredump },
    { "group_source", sizeof("group_source") - 1, set_var_group_source },
    { "max_groups", sizeof("max_groups") - 1, set_var_max_groups },
    { "probe_interfaces", sizeof("probe_interfaces") - 1, set_var_probe_interfaces },
    { NULL }
};

/* XXX - it would be nice to make this local to sudo_conf_read */
static struct sudo_conf_data {
    bool disable_coredump;
    bool probe_interfaces;
    int group_source;
    int max_groups;
    struct sudo_conf_debug_list debugging;
    struct plugin_info_list plugins;
    struct sudo_conf_path_table path_table[5];
} sudo_conf_data = {
    true,
    true,
    GROUP_SOURCE_ADAPTIVE,
    -1,
    TAILQ_HEAD_INITIALIZER(sudo_conf_data.debugging),
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
static bool
parse_variable(const char *entry, const char *conf_file, unsigned int lineno)
{
    struct sudo_conf_table *var;
    bool rval;
    debug_decl(parse_variable, SUDO_DEBUG_UTIL)

    for (var = sudo_conf_var_table; var->name != NULL; var++) {
	if (strncmp(entry, var->name, var->namelen) == 0 &&
	    isblank((unsigned char)entry[var->namelen])) {
	    entry += var->namelen + 1;
	    while (isblank((unsigned char)*entry))
		entry++;
	    rval = var->parser(entry, conf_file, lineno);
	    sudo_debug_printf(rval ? SUDO_DEBUG_INFO : SUDO_DEBUG_ERROR,
		"%s: %s:%u: Set %s %s", __func__, conf_file,
		lineno, var->name, entry);
	    debug_return_bool(rval);
	}
    }
    sudo_debug_printf(SUDO_DEBUG_WARN, "%s: %s:%u: unknown setting %s",
	__func__, conf_file, lineno, entry);
    debug_return_bool(false);
}

/*
 * "Path name /path/to/file"
 */
static bool
parse_path(const char *entry, const char *conf_file, unsigned int lineno)
{
    const char *name, *path;
    struct sudo_conf_path_table *cur;
    debug_decl(parse_path, SUDO_DEBUG_UTIL)

    /* Parse Path line */
    name = entry;
    path = strpbrk(entry, " \t");
    if (path == NULL)
	goto bad;
    while (isblank((unsigned char)*path))
	path++;
    if (*path != '/')
	goto bad;

    /* Match supported paths, ignore the rest. */
    for (cur = sudo_conf_data.path_table; cur->pname != NULL; cur++) {
	if (strncasecmp(name, cur->pname, cur->pnamelen) == 0 &&
	    isblank((unsigned char)name[cur->pnamelen])) {
	    cur->pval = sudo_estrdup(path);
	    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: %s:%u: Path %s %s",
		__func__, conf_file, lineno, cur->pname, cur->pval);
	    debug_return_bool(true);
	}
    }
    sudo_debug_printf(SUDO_DEBUG_WARN, "%s: %s:%u: unknown path %s",
	__func__, conf_file, lineno, entry);
    debug_return_bool(false);
bad:
    sudo_warnx(U_("invalid Path value `%s' in %s, line %u"),
	entry, conf_file, lineno);
    debug_return_bool(false);
}

/*
 * "Debug program /path/to/log flags,..."
 */
static bool
parse_debug(const char *progname, const char *conf_file, unsigned int lineno)
{
    struct sudo_conf_debug *debug_spec;
    struct sudo_debug_file *debug_file;
    const char *path, *flags, *cp = progname;
    size_t pathlen, prognamelen;
    debug_decl(parse_debug, SUDO_DEBUG_UTIL)

    /* Parse progname. */
    while (*cp != '\0' && !isblank((unsigned char)*cp))
	cp++;
    if (*cp == '\0')
	debug_return_bool(false);	/* not enough fields */
    prognamelen = (size_t)(cp - progname);
    do {
	cp++;
    } while (isblank((unsigned char)*cp));
    if (*cp == '\0')
	debug_return_bool(false);	/* not enough fields */

    /* Parse path. */
    path = cp;
    while (*cp != '\0' && !isblank((unsigned char)*cp))
	cp++;
    if (*cp == '\0')
	debug_return_bool(false);	/* not enough fields */
    pathlen = (size_t)(cp - path);
    do {
	cp++;
    } while (isblank((unsigned char)*cp));
    if (*cp == '\0')
	debug_return_bool(false);	/* not enough fields */

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

    debug_return_bool(true);
}

/*
 * "Plugin symbol /path/to/log args..."
 */
static bool
parse_plugin(const char *cp, const char *conf_file, unsigned int lineno)
{
    struct plugin_info *info;
    const char *ep, *path, *symbol;
    char **options = NULL;
    size_t pathlen, symlen;
    unsigned int nopts;
    debug_decl(parse_plugin, SUDO_DEBUG_UTIL)

    /* Parse symbol. */
    if (*cp == '\0')
	debug_return_bool(false);	/* not enough fields */
    symbol = cp;
    while (*cp != '\0' && !isblank((unsigned char)*cp))
	cp++;
    symlen = (size_t)(cp - symbol);
    while (isblank((unsigned char)*cp))
	cp++;

    /* Parse path. */
    if (*cp == '\0')
	debug_return_bool(false);	/* not enough fields */
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

    debug_return_bool(true);
}

static bool
set_var_disable_coredump(const char *strval, const char *conf_file,
    unsigned int lineno)
{
    int val = sudo_strtobool(strval);
    debug_decl(set_var_disable_coredump, SUDO_DEBUG_UTIL)

    if (val == -1) {
	sudo_warnx(U_("invalid value for %s `%s' in %s, line %u"),
	    "disable_coredump", strval, conf_file, lineno);
	debug_return_bool(false);
    }
    sudo_conf_data.disable_coredump = val;
    debug_return_bool(true);
}

static bool
set_var_group_source(const char *strval, const char *conf_file,
    unsigned int lineno)
{
    debug_decl(set_var_group_source, SUDO_DEBUG_UTIL)

    if (strcasecmp(strval, "adaptive") == 0) {
	sudo_conf_data.group_source = GROUP_SOURCE_ADAPTIVE;
    } else if (strcasecmp(strval, "static") == 0) {
	sudo_conf_data.group_source = GROUP_SOURCE_STATIC;
    } else if (strcasecmp(strval, "dynamic") == 0) {
	sudo_conf_data.group_source = GROUP_SOURCE_DYNAMIC;
    } else {
	sudo_warnx(U_("unsupported group source `%s' in %s, line %u"), strval,
	    conf_file, lineno);
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
set_var_max_groups(const char *strval, const char *conf_file,
    unsigned int lineno)
{
    int max_groups;
    debug_decl(set_var_max_groups, SUDO_DEBUG_UTIL)

    max_groups = strtonum(strval, 1, INT_MAX, NULL);
    if (max_groups <= 0) {
	sudo_warnx(U_("invalid max groups `%s' in %s, line %u"), strval,
	    conf_file, lineno);
	debug_return_bool(false);
    }
    sudo_conf_data.max_groups = max_groups;
    debug_return_bool(true);
}

static bool
set_var_probe_interfaces(const char *strval, const char *conf_file,
    unsigned int lineno)
{
    int val = sudo_strtobool(strval);
    debug_decl(set_var_probe_interfaces, SUDO_DEBUG_UTIL)

    if (val == -1) {
	sudo_warnx(U_("invalid value for %s `%s' in %s, line %u"),
	    "probe_interfaces", strval, conf_file, lineno);
	debug_return_bool(false);
    }
    sudo_conf_data.probe_interfaces = val;
    debug_return_bool(true);
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
    debug_decl(sudo_conf_debug_files, SUDO_DEBUG_UTIL)

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
    debug_decl(sudo_conf_read, SUDO_DEBUG_UTIL)

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
	    if (strncasecmp(cp, cur->name, cur->namelen) == 0 &&
		isblank((unsigned char)cp[cur->namelen])) {
		if (ISSET(conf_types, (1 << i))) {
		    cp += cur->namelen;
		    while (isblank((unsigned char)*cp))
			cp++;
		    cur->parser(cp, conf_file, conf_lineno);
		}
		break;
	    }
	}
	if (cur->name == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_WARN,
		"%s: %s:%u: unsupported entry: %s", __func__, conf_file,
		conf_lineno, line);
	}
    }
    fclose(fp);
    free(line);

done:
    /* Restore locale if needed. */
    if (prev_locale[0] != 'C' || prev_locale[1] != '\0')
        setlocale(LC_ALL, prev_locale);
    sudo_efree(prev_locale);
    debug_return;
}
