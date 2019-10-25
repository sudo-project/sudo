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

static struct logsrvd_config {
    struct logsrvd_config_server {
	struct listen_address_list addresses;
    } server;
    struct logsrvd_config_iolog {
	/* XXX - others private to iolog */
	char *iolog_dir;
	char *iolog_file;
    } iolog;
    struct logsrvd_config_eventlog {
	enum logsrvd_eventlog_type log_type;
	enum logsrvd_eventlog_format log_format;
    } eventlog;
    struct logsrvd_config_syslog {
	unsigned int maxlen;
	int facility;
	int acceptpri;
	int rejectpri;
	int alertpri;
    } syslog;
    struct logsrvd_config_logfile {
	char *path;
	char *time_format;
    } logfile;
} logsrvd_config = {
    { TAILQ_HEAD_INITIALIZER(logsrvd_config.server.addresses) }
};

/* iolog getters */
const char *
logsrvd_conf_iolog_dir(void)
{
    return logsrvd_config.iolog.iolog_dir;
}

const char *
logsrvd_conf_iolog_file(void)
{
    return logsrvd_config.iolog.iolog_file;
}

/* server getters */
struct listen_address_list *
logsrvd_conf_listen_address(void)
{
    return &logsrvd_config.server.addresses;
}

/* eventlog getters */
enum logsrvd_eventlog_type
logsrvd_conf_eventlog_type(void)
{
    return logsrvd_config.eventlog.log_type;
}

enum logsrvd_eventlog_format
logsrvd_conf_eventlog_format(void)
{
    return logsrvd_config.eventlog.log_format;
}

/* syslog getters */
unsigned int
logsrvd_conf_syslog_maxlen(void)
{
    return logsrvd_config.syslog.maxlen;
}

int
logsrvd_conf_syslog_facility(void)
{
    return logsrvd_config.syslog.facility;
}

int
logsrvd_conf_syslog_acceptpri(void)
{
    return logsrvd_config.syslog.acceptpri;
}

int
logsrvd_conf_syslog_rejectpri(void)
{
    return logsrvd_config.syslog.rejectpri;
}

int
logsrvd_conf_syslog_alertpri(void)
{
    return logsrvd_config.syslog.alertpri;
}

/* logfile getters */
const char *
logsrvd_conf_logfile_path(void)
{
    return logsrvd_config.logfile.path;
}

const char *
logsrvd_conf_logfile_time_format(void)
{
    return logsrvd_config.logfile.time_format;
}

/*
 * Reset logsrvd_config to default values and reset I/O log values.
 */
static void
logsrvd_conf_reset(void)
{
    struct listen_address *addr;
    debug_decl(logsrvd_conf_reset, SUDO_DEBUG_UTIL)

    iolog_set_defaults();
    free(logsrvd_config.iolog.iolog_dir);
    logsrvd_config.iolog.iolog_dir = NULL;
    free(logsrvd_config.iolog.iolog_file);
    logsrvd_config.iolog.iolog_file = NULL;

    while ((addr = TAILQ_FIRST(&logsrvd_config.server.addresses))) {
        TAILQ_REMOVE(&logsrvd_config.server.addresses, addr, entries);
	free(addr);
    }

    free(logsrvd_config.logfile.path);
    free(logsrvd_config.logfile.time_format);

    debug_return;
}

/* I/O log callbacks */
static bool
cb_iolog_dir(const char *path)
{
    debug_decl(cb_iolog_dir, SUDO_DEBUG_UTIL)

    free(logsrvd_config.iolog.iolog_dir);
    if ((logsrvd_config.iolog.iolog_dir = strdup(path)) == NULL) {
	sudo_warn(NULL);
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_iolog_file(const char *path)
{
    debug_decl(cb_iolog_file, SUDO_DEBUG_UTIL)

    free(logsrvd_config.iolog.iolog_file);
    if ((logsrvd_config.iolog.iolog_file = strdup(path)) == NULL) {
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

static bool
cb_iolog_maxseq(const char *str)
{
    return iolog_set_maxseq(str);
}

/* Server callbacks */
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
	TAILQ_INSERT_TAIL(&logsrvd_config.server.addresses, addr, entries);
    }

    ret = true;
done:
    if (res0 != NULL)
	freeaddrinfo(res0);
    free(copy);
    debug_return_bool(ret);
}

/* eventlog callbacks */
static bool
cb_eventlog_type(const char *str)
{
    debug_decl(cb_eventlog_type, SUDO_DEBUG_UTIL)

    if (strcmp(str, "none") == 0)
	logsrvd_config.eventlog.log_type = EVLOG_NONE;
    else if (strcmp(str, "syslog") == 0)
	logsrvd_config.eventlog.log_type = EVLOG_SYSLOG;
    else if (strcmp(str, "logfile") == 0)
	logsrvd_config.eventlog.log_type = EVLOG_FILE;
    else
	debug_return_bool(false);

    debug_return_bool(true);
}

static bool
cb_eventlog_format(const char *str)
{
    debug_decl(cb_eventlog_format, SUDO_DEBUG_UTIL)

    if (strcmp(str, "sudo") == 0)
	logsrvd_config.eventlog.log_format = EVLOG_SUDO;
    else
	debug_return_bool(false);

    debug_return_bool(true);
}

/* syslog callbacks */
static bool
cb_syslog_maxlen(const char *str)
{
    unsigned int maxlen;
    const char *errstr;
    debug_decl(cb_syslog_maxlen, SUDO_DEBUG_UTIL)

    maxlen = sudo_strtonum(str, 1, UINT_MAX, &errstr);
    if (errstr != NULL)
	debug_return_bool(false);

    logsrvd_config.syslog.maxlen = maxlen;

    debug_return_bool(true);
}

static bool
cb_syslog_facility(const char *str)
{
    int logfac;
    debug_decl(cb_syslog_facility, SUDO_DEBUG_UTIL)

    if (!sudo_str2logfac(str, &logfac)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid syslog priority %s", str);
	debug_return_bool(false);
    }

    logsrvd_config.syslog.facility = logfac;

    debug_return_bool(true);
}

static bool
cb_syslog_acceptpri(const char *str)
{
    int logpri;
    debug_decl(cb_syslog_acceptpri, SUDO_DEBUG_UTIL)

    if (!sudo_str2logpri(str, &logpri)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid syslog priority %s", str);
	debug_return_bool(false);
    }

    logsrvd_config.syslog.acceptpri = logpri;

    debug_return_bool(true);
}

static bool
cb_syslog_rejectpri(const char *str)
{
    int logpri;
    debug_decl(cb_syslog_rejectpri, SUDO_DEBUG_UTIL)

    if (!sudo_str2logpri(str, &logpri))
	debug_return_bool(false);

    logsrvd_config.syslog.rejectpri = logpri;

    debug_return_bool(true);
}

static bool
cb_syslog_alertpri(const char *str)
{
    int logpri;
    debug_decl(cb_syslog_alertpri, SUDO_DEBUG_UTIL)

    if (!sudo_str2logpri(str, &logpri)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid syslog priority %s", str);
	debug_return_bool(false);
    }

    logsrvd_config.syslog.alertpri = logpri;

    debug_return_bool(true);
}

/* logfile callbacks */
static bool
cb_logfile_path(const char *str)
{
    char *copy = NULL;
    debug_decl(cb_logfile_path, SUDO_DEBUG_UTIL)

    if (*str != '/') {
	debug_return_bool(false);
	sudo_warnx(U_("%s: not a fully qualified path"), str);
	debug_return_bool(false);
    }
    if ((copy = strdup(str)) == NULL) {
	sudo_warn(NULL);
	debug_return_bool(false);
    }

    free(logsrvd_config.logfile.path);
    logsrvd_config.logfile.path = copy;

    debug_return_bool(true);
}

static bool
cb_logfile_time_format(const char *str)
{
    char *copy = NULL;
    debug_decl(cb_logfile_time_format, SUDO_DEBUG_UTIL)

    if ((copy = strdup(str)) == NULL) {
	sudo_warn(NULL);
	debug_return_bool(false);
    }

    free(logsrvd_config.logfile.time_format);
    logsrvd_config.logfile.time_format = copy;

    debug_return_bool(true);
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
    { "maxseq", cb_iolog_maxseq },
    { NULL }
};

static struct logsrvd_config_entry eventlog_conf_entries[] = {
    { "log_type", cb_eventlog_type },
    { "log_format", cb_eventlog_format },
    { NULL }
};

static struct logsrvd_config_entry syslog_conf_entries[] = {
    { "maxlen", cb_syslog_maxlen },
    { "facility", cb_syslog_facility },
    { "reject_priority", cb_syslog_rejectpri },
    { "accept_priority", cb_syslog_acceptpri },
    { "alert_priority", cb_syslog_alertpri },
    { NULL }
};

static struct logsrvd_config_entry logfile_conf_entries[] = {
    { "path", cb_logfile_path },
    { "time_format", cb_logfile_time_format },
    { NULL }
};

static struct logsrvd_config_section logsrvd_config_sections[] = {
    { "server", server_conf_entries },
    { "iolog", iolog_conf_entries },
    { "eventlog", eventlog_conf_entries },
    { "syslog", syslog_conf_entries },
    { "logfile", logfile_conf_entries },
    { NULL }
};

static bool
logsrvd_conf_parse(FILE *fp, const char *path)
{
    struct logsrvd_config_section *conf_section = NULL;
    unsigned int lineno = 0;
    size_t linesize = 0;
    char *line = NULL;
    bool ret = false;
    debug_decl(logsrvd_conf_parse, SUDO_DEBUG_UTIL)

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
		goto done;
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
		goto done;
	    }
	    continue;
	}

	if ((ep = strchr(line, '=')) == NULL) {
	    sudo_warnx(U_("%s:%d invalid configuration line: %s"),
		path, lineno, line);
	    goto done;
	}

	if (conf_section == NULL) {
	    sudo_warnx(U_("%s:%d expected section name: %s"),
		path, lineno, line);
	    goto done;
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
		    goto done;
		}
		break;
	    }
	}
	if (entry->conf_str == NULL) {
	    sudo_warnx(U_("%s:%d unknown key: %s"), path, lineno, line);
	    goto done;
	}
    }
    ret = true;

done:
    free(line);
    debug_return_bool(ret);
}

/*
 * Read .ini style logsrvd.conf file.
 * Note that we use '#' not ';' for the comment character.
 */
/* XXX - split into read and apply so we don't overwrite good config with bad */
bool
logsrvd_conf_read(const char *path)
{
    bool ret = false;
    FILE *fp = NULL;
    debug_decl(logsrvd_conf_read, SUDO_DEBUG_UTIL)

    /* Initialize default values for settings that take int values. */
    logsrvd_conf_reset();
    logsrvd_config.eventlog.log_type = EVLOG_SYSLOG;
    logsrvd_config.eventlog.log_format = EVLOG_SUDO;
    logsrvd_config.syslog.maxlen = 960;
    if (!cb_syslog_facility(LOGFAC)) {
	sudo_warnx(U_("unknown syslog facility %s"), LOGFAC);
	goto done;
    }
    if (!cb_syslog_acceptpri(PRI_SUCCESS)) {
	sudo_warnx(U_("unknown syslog priority %s"), PRI_SUCCESS);
	goto done;
    }
    if (!cb_syslog_rejectpri(PRI_FAILURE)) {
	sudo_warnx(U_("unknown syslog priority %s"), PRI_FAILURE);
	goto done;
    }
    if (!cb_syslog_alertpri(PRI_FAILURE)) {
	sudo_warnx(U_("unknown syslog priority %s"), PRI_FAILURE);
	goto done;
    }

    if ((fp = fopen(path, "r")) == NULL) {
	if (errno != ENOENT) {
	    sudo_warn("%s", path);
	    goto done;
	}
    } else {
	if (!logsrvd_conf_parse(fp, path))
	    goto done;
    }

    /* For settings with pointer values we can tell what is unset. */
    if (logsrvd_config.iolog.iolog_dir == NULL) {
	if (!cb_iolog_dir(_PATH_SUDO_IO_LOGDIR))
	    goto done;
    }
    if (logsrvd_config.iolog.iolog_file == NULL) {
	if (!cb_iolog_file("%{seq}"))
	    goto done;
    }
    if (TAILQ_EMPTY(&logsrvd_config.server.addresses)) {
	if (!cb_listen_address("*:30344"))
	    goto done;
    }
    if (logsrvd_config.logfile.time_format == NULL) {
	if (!cb_logfile_time_format("%h %e %T"))
	    goto done;
    }
    if (logsrvd_config.logfile.path == NULL) {
	if (!cb_logfile_path(_PATH_SUDO_LOGFILE))
	    goto done;
    }
    ret = true;

done:
    if (fp != NULL)
	fclose(fp);
    debug_return_bool(ret);
}
