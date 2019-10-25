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
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
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

#ifndef HAVE_GETADDRINFO
# include "compat/getaddrinfo.h"
#endif

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

struct logsrvd_config_entry {
    char *conf_str;
    logsrvd_conf_cb_t setter;
};

struct logsrvd_config_section {
    char *name;
    struct logsrvd_config_entry *entries;
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

static struct listen_address_list addresses = TAILQ_HEAD_INITIALIZER(addresses);

struct listen_address_list *
logsrvd_conf_listen_address(void)
{
    return &addresses;
}

static void
logsrvd_conf_reset(void)
{
    struct listen_address *addr;
    debug_decl(logsrvd_conf_reset, SUDO_DEBUG_UTIL)

    iolog_set_defaults();
    free(logsrvd_iolog_dir);
    logsrvd_iolog_dir = NULL;
    free(logsrvd_iolog_file);
    logsrvd_iolog_file = NULL;

    while ((addr = TAILQ_FIRST(&addresses))) {
        TAILQ_REMOVE(&addresses, addr, entries);
	free(addr);
    }

    debug_return;
}

static bool
cb_iolog_dir(const char *path)
{
    debug_decl(cb_iolog_dir, SUDO_DEBUG_UTIL)

    free(logsrvd_iolog_dir);
    if ((logsrvd_iolog_dir = strdup(path)) == NULL) {
	sudo_warn(NULL);
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
	sudo_warn(NULL);
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

/* TODO: unit test */
static bool
cb_listen_address(const char *str)
{
    struct addrinfo hints, *res, *res0 = NULL;
    char *copy, *host, *port;
    bool ret = false;
    int error;
    debug_decl(cb_iolog_mode, SUDO_DEBUG_UTIL)

    if ((copy = strdup(str)) == NULL) {
	sudo_warn(NULL);
	debug_return_bool(false);
    }
    host = copy;

    /* Check for IPv6 address like [::0] followed by optional port */
    if (*host == '[') {
	host++;
	port = strchr(host, ']');
	if (port == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"invalid IPv6 address %s", str);
	    goto done;
	}
	*port++ = '\0';
	if (*port == ':') {
	    port++;
	} else if (*port == '\0') {
	    port = NULL;		/* no port specified */
	} else {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"invalid IPv6 address %s", str);
	    goto done;
	}
    } else {
	port = strrchr(host, ':');
	if (port != NULL)
	    *port++ = '\0';
    }

    if (port == NULL)
	port = DEFAULT_PORT_STR;
    if (host[0] == '*' && host[1] == '\0')
	host = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    error = getaddrinfo(host, port, &hints, &res0);
    if (error != 0) {
	sudo_warnx("%s", gai_strerror(error));
	goto done;
    }
    for (res = res0; res != NULL; res = res->ai_next) {
	struct listen_address *addr;

	if ((addr = malloc(sizeof(*addr))) == NULL) {
	    sudo_warn(NULL);
	    goto done;
	}
	memcpy(&addr->sa_un, res->ai_addr, res->ai_addrlen);
	addr->sa_len = res->ai_addrlen;
	TAILQ_INSERT_TAIL(&addresses, addr, entries);
    }

    ret = true;
done:
    if (res0 != NULL)
	freeaddrinfo(res0);
    free(copy);
    debug_return_bool(ret);
}

static bool
cb_maxseq(const char *str)
{
    return iolog_set_maxseq(str);
}

static struct logsrvd_config_entry server_conf_entries[] = {
    { "listen_address", cb_listen_address },    
    { NULL }
};

static struct logsrvd_config_entry iolog_conf_entries[] = {
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

static struct logsrvd_config_section logsrvd_config_sections[] = {
    { "server", server_conf_entries },
    { "iolog", iolog_conf_entries },
    { NULL }
};

/*
 * Read .ini style logsrvd.conf file.
 * Note that we use '#' not ';' for the comment character.
 */
/* XXX - on reload we should preserve old config if there is an error */
bool
logsrvd_conf_read(const char *path)
{
    struct logsrvd_config_section *conf_section = NULL;
    unsigned int lineno = 0;
    size_t linesize = 0;
    char *line = NULL;
    FILE *fp;
    debug_decl(read_config, SUDO_DEBUG_UTIL)

    if ((fp = fopen(path, "r")) == NULL) {
	if (errno == ENOENT)
	    debug_return_bool(true);
	sudo_warn("%s", path);
	debug_return_bool(false);
    }

    logsrvd_conf_reset();

    while (sudo_parseln(&line, &linesize, &lineno, fp, 0) != -1) {
	struct logsrvd_config_entry *entry;
	char *ep, *val;

	/* Skip blank, comment or invalid lines. */
	if (*line == '\0' || *line == ';')
	    continue;

	/* New section */
	if (line[0] == '[') {
	    char *section_name = line + 1;
	    char *cp = strchr(section_name, ']');
	    if (cp == NULL) {
		sudo_warnx(U_("%s:%d unmatched '[': %s"),
		    path, lineno, line);
		debug_return_bool(false);
	    }
	    *cp = '\0';
	    for (conf_section = logsrvd_config_sections; conf_section->name != NULL;
		    conf_section++) {
		if (strcasecmp(section_name, conf_section->name) == 0)
		    break;
	    }
	    if (conf_section->name == NULL) {
		sudo_warnx(U_("%s:%d invalid config section: %s"),
		    path, lineno, section_name);
		debug_return_bool(false);
	    }
	    continue;
	}

	if ((ep = strchr(line, '=')) == NULL) {
	    sudo_warnx(U_("%s:%d invalid configuration line: %s"),
		path, lineno, line);
	    debug_return_bool(false);
	}

	if (conf_section == NULL) {
	    sudo_warnx(U_("%s:%d expected section name: %s"),
		path, lineno, line);
	    debug_return_bool(false);
	}

	val = ep + 1;
	while (isspace((unsigned char)*val))
	    val++;
	while (ep > line && isspace((unsigned char)ep[-1]))
	    ep--;
	*ep = '\0';
	for (entry = conf_section->entries; entry->conf_str != NULL; entry++) {
	    if (strcasecmp(line, entry->conf_str) == 0) {
		if (!entry->setter(val)) {
		    sudo_warnx(U_("invalid value for %s: %s"),
			entry->conf_str, val);
		    debug_return_bool(false);
		}
		break;
	    }
	}
	if (entry->conf_str == NULL) {
	    sudo_warnx(U_("%s:%d unknown key: %s"),
		path, lineno, line);
	    debug_return_bool(false);
	}
    }

    /* All the others have default values. */
    if (logsrvd_iolog_dir == NULL) {
	if ((logsrvd_iolog_dir = strdup(_PATH_SUDO_IO_LOGDIR)) == NULL) {
	    sudo_warn(NULL);
	    debug_return_bool(false);
	}
    }
    if (logsrvd_iolog_file == NULL) {
	if ((logsrvd_iolog_file = strdup("%{seq}")) == NULL) {
	    sudo_warn(NULL);
	    debug_return_bool(false);
	}
    }
    if (TAILQ_EMPTY(&addresses)) {
	if (!cb_listen_address("*:30344"))
	    debug_return_bool(false);
    }

    debug_return_bool(true);
}
