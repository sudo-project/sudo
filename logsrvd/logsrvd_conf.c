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

#include "log_server.pb-c.h"
#include "sudo_gettext.h"	/* must be included before sudo_compat.h */
#include "sudo_compat.h"
#include "sudo_debug.h"
#include "sudo_util.h"
#include "sudo_fatal.h"
#include "pathnames.h"
#include "logsrvd.h"
#include "iolog.h"

enum config_type {
    CONF_BOOL,
    CONF_INT,
    CONF_UINT,
    CONF_MODE,
    CONF_STR
};

union config_value {
    char *strval;
    int intval;
    unsigned int uintval;
    mode_t modeval;
    bool boolval;
};

struct logsrvd_config_table {
    char *conf_str;
    enum config_type conf_type;
    union config_value conf_val;
};

/* Indexes into conf_table */
#define LOGSRVD_CONF_IOLOG_DIR		0
#define LOGSRVD_CONF_IOLOG_FILE		1
#define LOGSRVD_CONF_IOLOG_FLUSH	2
#define LOGSRVD_CONF_IOLOG_COMPRESS	3
#define LOGSRVD_CONF_IOLOG_USER		4
#define LOGSRVD_CONF_IOLOG_GROUP	5
#define LOGSRVD_CONF_IOLOG_MODE		6
#define LOGSRVD_CONF_MAXSEQ		7

/* XXX - use callbacks into iolog.c instead */
static struct logsrvd_config_table conf_table[] = {
    { "iolog_dir", CONF_STR, { .strval = _PATH_SUDO_IO_LOGDIR } },
    { "iolog_file", CONF_STR, { .strval = "%{seq}" } },
    { "iolog_flush", CONF_BOOL, { .boolval = true } },
    { "iolog_compress", CONF_BOOL, { .boolval = false } },
    { "iolog_user", CONF_STR, { .strval = NULL } },
    { "iolog_group", CONF_STR, { .strval = NULL } },
    { "iolog_mode", CONF_MODE, { .intval = S_IRUSR|S_IWUSR } },
    { "maxseq", CONF_UINT, { .intval = SESSID_MAX } },
    { NULL }
};

static bool
parse_value(struct logsrvd_config_table *ct, const char *val)
{
    int ival;
    unsigned int uval;
    mode_t mode;
    const char *errstr;
    debug_decl(parse_value, SUDO_DEBUG_UTIL)

    switch (ct->conf_type) {
    case CONF_BOOL:
	ival = sudo_strtobool(val);
	if (ival == -1)
	    debug_return_bool(false);
	ct->conf_val.boolval = ival;
	break;
    case CONF_INT:
	ival = sudo_strtonum(val, INT_MIN, INT_MAX, &errstr);
	if (errstr != NULL)
	    debug_return_bool(false);
	ct->conf_val.intval = ival;
	break;
    case CONF_UINT:
	uval = sudo_strtonum(val, 0, UINT_MAX, &errstr);
	if (errstr != NULL)
	    debug_return_bool(false);
	ct->conf_val.uintval = uval;
	break;
    case CONF_MODE:
	mode = sudo_strtomode(val, &errstr);
	if (errstr != NULL)
	    debug_return_bool(false);
	ct->conf_val.modeval = mode;
	break;
    case CONF_STR:
	ct->conf_val.strval = strdup(val);
	if (ct->conf_val.strval == NULL)
	    debug_return_bool(false);
	break;
    default:
	debug_return_bool(false);
    }

    debug_return_bool(true);
}

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

	// XXX - warn about bogus lines
	if ((ep = strchr(line, '=')) == NULL)
	    continue;
	val = ep + 1;
	while (isspace((unsigned char)*val))
	    val++;
	while (ep > line && isspace((unsigned char)ep[-1]))
	    ep--;
	*ep = '\0';
	for (ct = conf_table; ct->conf_str != NULL; ct++) {
	    if (strcmp(line, ct->conf_str) == 0) {
		if (!parse_value(ct, val))
		    sudo_warnx("invalid value for %s: %s", ct->conf_str, val);
		break;
	    }
	}
    }

#if 0
    /*
     * TODO: iolog_dir, iolog_file, iolog_flush, iolog_compress
     */
    iolog_set_user(conf_table[LOGSRVD_CONF_IOLOG_USER].conf_val.strval);
    iolog_set_group(conf_table[LOGSRVD_CONF_IOLOG_GROUP].conf_val.strval);
    iolog_set_mode(conf_table[LOGSRVD_CONF_IOLOG_MODE].conf_val.modeval);
    /* XXX - expects a string */
    iolog_set_max_sessid(conf_table[LOGSRVD_CONF_MAXSEQ].conf_val.uintval);
#endif

    debug_return;
}

/* XXX - use callbacks instead */
const char *
logsrvd_conf_iolog_dir(void)
{
    return conf_table[LOGSRVD_CONF_IOLOG_DIR].conf_val.strval;
}

const char *
logsrvd_conf_iolog_file(void)
{
    return conf_table[LOGSRVD_CONF_IOLOG_FILE].conf_val.strval;
}

const char *
logsrvd_conf_iolog_user(void)
{
    return conf_table[LOGSRVD_CONF_IOLOG_USER].conf_val.strval;
}

const char *
logsrvd_conf_iolog_group(void)
{
    return conf_table[LOGSRVD_CONF_IOLOG_GROUP].conf_val.strval;
}

bool
logsrvd_conf_iolog_flush(void)
{
    return conf_table[LOGSRVD_CONF_IOLOG_FLUSH].conf_val.boolval;
}

bool
logsrvd_conf_iolog_compress(void)
{
    return conf_table[LOGSRVD_CONF_IOLOG_COMPRESS].conf_val.boolval;
}

mode_t
logsrvd_conf_iolog_mode(void)
{
    return conf_table[LOGSRVD_CONF_IOLOG_MODE].conf_val.modeval;
}

unsigned int
logsrvd_conf_maxseq(void)
{
    return conf_table[LOGSRVD_CONF_MAXSEQ].conf_val.uintval;
}
