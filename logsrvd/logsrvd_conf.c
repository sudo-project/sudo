/*
 * Copyright (c) 2019 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include "config.h"

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>

#include "log_server.pb-c.h"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */
#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "sudo_fatal.h"
#include "sudo_iolog.h"
#include "pathnames.h"
#include "logsrvd.h"

typedef bool (*logsrvd_conf_cb_t)(const char *);

struct logsrvd_config_table {
    char *conf_str;
    logsrvd_conf_cb_t setter;
};

static char *logsrvd_iolog_dir;

const char *
logsrvd_conf_iolog_dir(void)
{
    return logsrvd_iolog_dir;
}

static char *logsrvd_iolog_file;

const char *
logsrvd_conf_iolog_file(void)
{
    return logsrvd_iolog_file;
}

static bool
cb_iolog_dir(const char *path)
{
    debug_decl(cb_iolog_dir, SUDO_DEBUG_UTIL)

    free(logsrvd_iolog_dir);
    if ((logsrvd_iolog_dir = strdup(path)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "strdup");
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_iolog_file(const char *path)
{
    debug_decl(cb_iolog_file, SUDO_DEBUG_UTIL)

    free(logsrvd_iolog_file);
    if ((logsrvd_iolog_file = strdup(path)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
	    "strdup");
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_iolog_compress(const char *str)
{
    return iolog_set_compress(str);
}

static bool
cb_iolog_flush(const char *str)
{
    return iolog_set_flush(str);
}

static bool
cb_iolog_user(const char *user)
{
    struct passwd *pw;
    debug_decl(cb_iolog_user, SUDO_DEBUG_UTIL)

    if ((pw = getpwnam(user)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unknown user %s", user);
	debug_return_bool(false);
    }

    debug_return_bool(iolog_set_user(pw));
}

static bool
cb_iolog_group(const char *group)
{
    struct group *gr;
    debug_decl(cb_iolog_group, SUDO_DEBUG_UTIL)

    if ((gr = getgrnam(group)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unknown group %s", group);
	debug_return_bool(false);
    }

    debug_return_bool(iolog_set_group(gr));
}

static bool
cb_iolog_mode(const char *str)
{
    const char *errstr;
    mode_t mode;
    debug_decl(cb_iolog_mode, SUDO_DEBUG_UTIL)

    mode = sudo_strtomode(str, &errstr);
    if (errstr != NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to parse iolog mode %s", str);
	debug_return_bool(false);
    }
    debug_return_bool(iolog_set_mode(mode));
}

static bool
cb_maxseq(const char *str)
{
    return iolog_set_maxseq(str);
}

static struct logsrvd_config_table conf_table[] = {
    { "iolog_dir", cb_iolog_dir },
    { "iolog_file", cb_iolog_file },
    { "iolog_flush", cb_iolog_flush },
    { "iolog_compress", cb_iolog_compress },
    { "iolog_user", cb_iolog_user },
    { "iolog_group", cb_iolog_group },
    { "iolog_mode", cb_iolog_mode },
    { "maxseq", cb_maxseq },
    { NULL }
};

void
logsrvd_conf_read(const char *path)
{
    unsigned int lineno = 0;
    size_t linesize = 0;
    char *line = NULL;
    FILE *fp;
    debug_decl(read_config, SUDO_DEBUG_UTIL)

    if ((fp = fopen(path, "r")) == NULL) {
	if (errno != ENOENT)
	    sudo_warn("%s", path);
	debug_return;
    }

    while (sudo_parseln(&line, &linesize, &lineno, fp, 0) != -1) {
	struct logsrvd_config_table *ct;
	char *ep, *val;

	/* Skip blank, comment or invalid lines. */
	if (*line == '\0')
	    continue;
	if ((ep = strchr(line, '=')) == NULL) {
	    sudo_warnx("%s:%d invalid setting %s", path, lineno, line);
	    continue;
	}

	val = ep + 1;
	while (isspace((unsigned char)*val))
	    val++;
	while (ep > line && isspace((unsigned char)ep[-1]))
	    ep--;
	*ep = '\0';
	for (ct = conf_table; ct->conf_str != NULL; ct++) {
	    if (strcmp(line, ct->conf_str) == 0) {
		if (!ct->setter(val))
		    sudo_warnx("invalid value for %s: %s", ct->conf_str, val);
		break;
	    }
	}
    }

    /* All the others have default values. */
    if (logsrvd_iolog_dir == NULL)
	logsrvd_iolog_dir = strdup(_PATH_SUDO_IO_LOGDIR);
    if (logsrvd_iolog_file == NULL)
	logsrvd_iolog_file = strdup("%{seq}");

    debug_return;
}
