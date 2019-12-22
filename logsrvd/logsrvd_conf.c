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

#if defined(HAVE_OPENSSL)
# define DEFAULT_CA_CERT_PATH       "/etc/ssl/sudo/cacert.pem"
# define DEFAULT_SERVER_CERT_PATH   "/etc/ssl/sudo/logsrvd_cert.pem"
#endif

struct logsrvd_config;
typedef bool (*logsrvd_conf_cb_t)(struct logsrvd_config *config, const char *);

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
        struct timespec timeout;
#if defined(HAVE_OPENSSL)
        bool tls;
        struct logsrvd_tls_config tls_config;
        struct logsrvd_tls_runtime tls_runtime;
#endif
    } server;
    struct logsrvd_config_iolog {
	bool compress;
	bool flush;
	bool gid_set;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	unsigned int maxseq;
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
} *logsrvd_config;

/* iolog getters */
mode_t
logsrvd_conf_iolog_mode(void)
{
    return logsrvd_config->iolog.mode;
}

const char *
logsrvd_conf_iolog_dir(void)
{
    return logsrvd_config->iolog.iolog_dir;
}

const char *
logsrvd_conf_iolog_file(void)
{
    return logsrvd_config->iolog.iolog_file;
}

/* server getters */
struct listen_address_list *
logsrvd_conf_listen_address(void)
{
    return &logsrvd_config->server.addresses;
}

struct timespec *
logsrvd_conf_get_sock_timeout(void)
{
    if (sudo_timespecisset(&logsrvd_config->server.timeout)) {
        return &(logsrvd_config->server.timeout);
    }

    return NULL;
}

#if defined(HAVE_OPENSSL)
bool
logsrvd_conf_get_tls_opt(void)
{
    return logsrvd_config->server.tls;
}

const struct logsrvd_tls_config *
logsrvd_get_tls_config(void)
{
    return &logsrvd_config->server.tls_config;
}

struct logsrvd_tls_runtime *
logsrvd_get_tls_runtime(void)
{
    return &logsrvd_config->server.tls_runtime;
}
#endif

/* eventlog getters */
enum logsrvd_eventlog_type
logsrvd_conf_eventlog_type(void)
{
    return logsrvd_config->eventlog.log_type;
}

enum logsrvd_eventlog_format
logsrvd_conf_eventlog_format(void)
{
    return logsrvd_config->eventlog.log_format;
}

/* syslog getters */
unsigned int
logsrvd_conf_syslog_maxlen(void)
{
    return logsrvd_config->syslog.maxlen;
}

int
logsrvd_conf_syslog_facility(void)
{
    return logsrvd_config->syslog.facility;
}

int
logsrvd_conf_syslog_acceptpri(void)
{
    return logsrvd_config->syslog.acceptpri;
}

int
logsrvd_conf_syslog_rejectpri(void)
{
    return logsrvd_config->syslog.rejectpri;
}

int
logsrvd_conf_syslog_alertpri(void)
{
    return logsrvd_config->syslog.alertpri;
}

/* logfile getters */
const char *
logsrvd_conf_logfile_path(void)
{
    return logsrvd_config->logfile.path;
}

const char *
logsrvd_conf_logfile_time_format(void)
{
    return logsrvd_config->logfile.time_format;
}

/* I/O log callbacks */
static bool
cb_iolog_dir(struct logsrvd_config *config, const char *path)
{
    debug_decl(cb_iolog_dir, SUDO_DEBUG_UTIL);

    free(config->iolog.iolog_dir);
    if ((config->iolog.iolog_dir = strdup(path)) == NULL) {
	sudo_warn(NULL);
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_iolog_file(struct logsrvd_config *config, const char *path)
{
    debug_decl(cb_iolog_file, SUDO_DEBUG_UTIL);

    free(config->iolog.iolog_file);
    if ((config->iolog.iolog_file = strdup(path)) == NULL) {
	sudo_warn(NULL);
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_iolog_compress(struct logsrvd_config *config, const char *str)
{
    int val;
    debug_decl(cb_iolog_compress, SUDO_DEBUG_UTIL);

    if ((val = sudo_strtobool(str)) == -1)
	debug_return_bool(false);

    config->iolog.compress = val;
    debug_return_bool(true);
}

static bool
cb_iolog_flush(struct logsrvd_config *config, const char *str)
{
    int val;
    debug_decl(cb_iolog_flush, SUDO_DEBUG_UTIL);

    if ((val = sudo_strtobool(str)) == -1)
	debug_return_bool(false);

    config->iolog.flush = val;
    debug_return_bool(true);
}

static bool
cb_iolog_user(struct logsrvd_config *config, const char *user)
{
    struct passwd *pw;
    debug_decl(cb_iolog_user, SUDO_DEBUG_UTIL);

    if ((pw = getpwnam(user)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unknown user %s", user);
	debug_return_bool(false);
    }
    config->iolog.uid = pw->pw_uid;
    if (!config->iolog.gid_set)
	config->iolog.gid = pw->pw_gid;

    debug_return_bool(true);
}

static bool
cb_iolog_group(struct logsrvd_config *config, const char *group)
{
    struct group *gr;
    debug_decl(cb_iolog_group, SUDO_DEBUG_UTIL);

    if ((gr = getgrnam(group)) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unknown group %s", group);
	debug_return_bool(false);
    }
    config->iolog.gid = gr->gr_gid;
    config->iolog.gid_set = true;

    debug_return_bool(true);
}

static bool
cb_iolog_mode(struct logsrvd_config *config, const char *str)
{
    const char *errstr;
    mode_t mode;
    debug_decl(cb_iolog_mode, SUDO_DEBUG_UTIL);

    mode = sudo_strtomode(str, &errstr);
    if (errstr != NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to parse iolog mode %s", str);
	debug_return_bool(false);
    }
    config->iolog.mode = mode;
    debug_return_bool(true);
}

static bool
cb_iolog_maxseq(struct logsrvd_config *config, const char *str)
{
    const char *errstr;
    unsigned int value;
    debug_decl(cb_iolog_maxseq, SUDO_DEBUG_UTIL);

    value = sudo_strtonum(str, 0, SESSID_MAX, &errstr);
    if (errstr != NULL) {
        if (errno != ERANGE) {
            sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
                "bad maxseq: %s: %s", str, errstr);
            debug_return_bool(false);
        }
        /* Out of range, clamp to SESSID_MAX as documented. */
        value = SESSID_MAX;
    }
    config->iolog.maxseq = value;
    debug_return_bool(true);
}

/* Server callbacks */
/* TODO: unit test */
static bool
cb_listen_address(struct logsrvd_config *config, const char *str)
{
    struct addrinfo hints, *res, *res0 = NULL;
    char *copy, *host, *port;
    bool ret = false;
    int error;
    debug_decl(cb_iolog_mode, SUDO_DEBUG_UTIL);

    if ((copy = strdup(str)) == NULL) {
	sudo_warn(NULL);
	debug_return_bool(false);
    }

    /* Parse host[:port] */
    if (!sudo_parse_host_port(copy, &host, &port, DEFAULT_PORT_STR))
	goto done;
    if (host[0] == '*' && host[1] == '\0')
	host = NULL;

    /* Resolve host (and port if it is a service). */
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
	TAILQ_INSERT_TAIL(&config->server.addresses, addr, entries);
    }

    ret = true;
done:
    if (res0 != NULL)
	freeaddrinfo(res0);
    free(copy);
    debug_return_bool(ret);
}

static bool
cb_timeout(struct logsrvd_config *config, const char *str)
{
    int timeout;
    const char* errstr;
    debug_decl(cb_timeout, SUDO_DEBUG_UTIL);

    timeout = sudo_strtonum(str, 0, UINT_MAX, &errstr);
    if (errstr != NULL)
	debug_return_bool(false);

    config->server.timeout.tv_sec = timeout;

    debug_return_bool(true);
}

#if defined(HAVE_OPENSSL)
static bool
cb_tls_opt(struct logsrvd_config *config, const char *str)
{
    int val;
    debug_decl(cb_tls_opt, SUDO_DEBUG_UTIL);

    if ((val = sudo_strtobool(str)) == -1)
	debug_return_bool(false);

    config->server.tls = val;
    debug_return_bool(true);
}

static bool
cb_tls_key(struct logsrvd_config *config, const char *path)
{
    debug_decl(cb_tls_key, SUDO_DEBUG_UTIL);

    free(config->server.tls_config.pkey_path);
    if ((config->server.tls_config.pkey_path = strdup(path)) == NULL) {
        sudo_warn(NULL);
        debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_tls_cacert(struct logsrvd_config *config, const char *path)
{
    debug_decl(cb_tls_cacert, SUDO_DEBUG_UTIL);

    free(config->server.tls_config.cacert_path);
    if ((config->server.tls_config.cacert_path = strdup(path)) == NULL) {
        sudo_warn(NULL);
        debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_tls_cert(struct logsrvd_config *config, const char *path)
{
    debug_decl(cb_tls_cert, SUDO_DEBUG_UTIL);

    free(config->server.tls_config.cert_path);
    if ((config->server.tls_config.cert_path = strdup(path)) == NULL) {
        sudo_warn(NULL);
        debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_tls_dhparam(struct logsrvd_config *config, const char *path)
{
    debug_decl(cb_tls_dhparam, SUDO_DEBUG_UTIL);

    free(config->server.tls_config.dhparams_path);
    if ((config->server.tls_config.dhparams_path = strdup(path)) == NULL) {
        sudo_warn(NULL);
        debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_tls_ciphers12(struct logsrvd_config *config, const char *str)
{
    debug_decl(cb_tls_ciphers12, SUDO_DEBUG_UTIL);

    free(config->server.tls_config.ciphers_v12);
    if ((config->server.tls_config.ciphers_v12 = strdup(str)) == NULL) {
        sudo_warn(NULL);
        debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_tls_ciphers13(struct logsrvd_config *config, const char *str)
{
    debug_decl(cb_tls_ciphers13, SUDO_DEBUG_UTIL);

    free(config->server.tls_config.ciphers_v13);
    if ((config->server.tls_config.ciphers_v13 = strdup(str)) == NULL) {
        sudo_warn(NULL);
        debug_return_bool(false);
    }
    debug_return_bool(true);
}

static bool
cb_tls_checkpeer(struct logsrvd_config *config, const char *str)
{
    int val;
    debug_decl(cb_tls_checkpeer, SUDO_DEBUG_UTIL);

    if ((val = sudo_strtobool(str)) == -1)
	debug_return_bool(false);

    config->server.tls_config.check_peer = val;
    debug_return_bool(true);
}
#endif

/* eventlog callbacks */
static bool
cb_eventlog_type(struct logsrvd_config *config, const char *str)
{
    debug_decl(cb_eventlog_type, SUDO_DEBUG_UTIL);

    if (strcmp(str, "none") == 0)
	config->eventlog.log_type = EVLOG_NONE;
    else if (strcmp(str, "syslog") == 0)
	config->eventlog.log_type = EVLOG_SYSLOG;
    else if (strcmp(str, "logfile") == 0)
	config->eventlog.log_type = EVLOG_FILE;
    else
	debug_return_bool(false);

    debug_return_bool(true);
}

static bool
cb_eventlog_format(struct logsrvd_config *config, const char *str)
{
    debug_decl(cb_eventlog_format, SUDO_DEBUG_UTIL);

    if (strcmp(str, "sudo") == 0)
	config->eventlog.log_format = EVLOG_SUDO;
    else
	debug_return_bool(false);

    debug_return_bool(true);
}

/* syslog callbacks */
static bool
cb_syslog_maxlen(struct logsrvd_config *config, const char *str)
{
    unsigned int maxlen;
    const char *errstr;
    debug_decl(cb_syslog_maxlen, SUDO_DEBUG_UTIL);

    maxlen = sudo_strtonum(str, 1, UINT_MAX, &errstr);
    if (errstr != NULL)
	debug_return_bool(false);

    config->syslog.maxlen = maxlen;

    debug_return_bool(true);
}

static bool
cb_syslog_facility(struct logsrvd_config *config, const char *str)
{
    int logfac;
    debug_decl(cb_syslog_facility, SUDO_DEBUG_UTIL);

    if (!sudo_str2logfac(str, &logfac)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid syslog priority %s", str);
	debug_return_bool(false);
    }

    config->syslog.facility = logfac;

    debug_return_bool(true);
}

static bool
cb_syslog_acceptpri(struct logsrvd_config *config, const char *str)
{
    int logpri;
    debug_decl(cb_syslog_acceptpri, SUDO_DEBUG_UTIL);

    if (!sudo_str2logpri(str, &logpri)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid syslog priority %s", str);
	debug_return_bool(false);
    }

    config->syslog.acceptpri = logpri;

    debug_return_bool(true);
}

static bool
cb_syslog_rejectpri(struct logsrvd_config *config, const char *str)
{
    int logpri;
    debug_decl(cb_syslog_rejectpri, SUDO_DEBUG_UTIL);

    if (!sudo_str2logpri(str, &logpri))
	debug_return_bool(false);

    config->syslog.rejectpri = logpri;

    debug_return_bool(true);
}

static bool
cb_syslog_alertpri(struct logsrvd_config *config, const char *str)
{
    int logpri;
    debug_decl(cb_syslog_alertpri, SUDO_DEBUG_UTIL);

    if (!sudo_str2logpri(str, &logpri)) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "invalid syslog priority %s", str);
	debug_return_bool(false);
    }

    config->syslog.alertpri = logpri;

    debug_return_bool(true);
}

/* logfile callbacks */
static bool
cb_logfile_path(struct logsrvd_config *config, const char *str)
{
    char *copy = NULL;
    debug_decl(cb_logfile_path, SUDO_DEBUG_UTIL);

    if (*str != '/') {
	debug_return_bool(false);
	sudo_warnx(U_("%s: not a fully qualified path"), str);
	debug_return_bool(false);
    }
    if ((copy = strdup(str)) == NULL) {
	sudo_warn(NULL);
	debug_return_bool(false);
    }

    free(config->logfile.path);
    config->logfile.path = copy;

    debug_return_bool(true);
}

static bool
cb_logfile_time_format(struct logsrvd_config *config, const char *str)
{
    char *copy = NULL;
    debug_decl(cb_logfile_time_format, SUDO_DEBUG_UTIL);

    if ((copy = strdup(str)) == NULL) {
	sudo_warn(NULL);
	debug_return_bool(false);
    }

    free(config->logfile.time_format);
    config->logfile.time_format = copy;

    debug_return_bool(true);
}

static struct logsrvd_config_entry server_conf_entries[] = {
    { "listen_address", cb_listen_address },
    { "timeout", cb_timeout },
#if defined(HAVE_OPENSSL)
    { "tls", cb_tls_opt },
    { "tls_key", cb_tls_key },
    { "tls_cacert", cb_tls_cacert },
    { "tls_cert", cb_tls_cert },
    { "tls_dhparams", cb_tls_dhparam },
    { "tls_ciphers_v12", cb_tls_ciphers12 },
    { "tls_ciphers_v13", cb_tls_ciphers13 },
    { "tls_checkpeer", cb_tls_checkpeer },
#endif
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
logsrvd_conf_parse(struct logsrvd_config *config, FILE *fp, const char *path)
{
    struct logsrvd_config_section *conf_section = NULL;
    unsigned int lineno = 0;
    size_t linesize = 0;
    char *line = NULL;
    bool ret = false;
    debug_decl(logsrvd_conf_parse, SUDO_DEBUG_UTIL);

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
		if (!entry->setter(config, val)) {
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

/* Free the specified struct logsrvd_config and its contents. */
void
logsrvd_conf_free(struct logsrvd_config *config)
{
    struct listen_address *addr;
    debug_decl(logsrvd_conf_free, SUDO_DEBUG_UTIL);

    if (config == NULL)
	debug_return;

    /* struct logsrvd_config_server */
    while ((addr = TAILQ_FIRST(&config->server.addresses))) {
	TAILQ_REMOVE(&config->server.addresses, addr, entries);
	free(addr);
    }

    /* struct logsrvd_config_iolog */
    free(config->iolog.iolog_dir);
    free(config->iolog.iolog_file);

    /* struct logsrvd_config_logfile */
    free(config->logfile.path);
    free(config->logfile.time_format);

    free(config);

    debug_return;
}

/* Allocate a new struct logsrvd_config and set default values. */
struct logsrvd_config *
logsrvd_conf_alloc(void)
{
    struct logsrvd_config *config;
    debug_decl(logsrvd_conf_alloc, SUDO_DEBUG_UTIL);

    if ((config = calloc(1, sizeof(*config))) == NULL) {
	sudo_warn(NULL);
	debug_return_ptr(NULL);
    }

    /* Server defaults */
    TAILQ_INIT(&config->server.addresses);
    config->server.timeout.tv_sec = DEFAULT_SOCKET_TIMEOUT_SEC;

#if defined(HAVE_OPENSSL)
    config->server.tls_config.cacert_path = strdup(DEFAULT_CA_CERT_PATH);
    config->server.tls_config.cert_path = strdup(DEFAULT_SERVER_CERT_PATH);
#endif

    /* I/O log defaults */
    config->iolog.compress = false;
    config->iolog.flush = true;
    config->iolog.mode = S_IRUSR|S_IWUSR;
    config->iolog.maxseq = SESSID_MAX;
    if (!cb_iolog_dir(config, _PATH_SUDO_IO_LOGDIR))
	goto bad;
    if (!cb_iolog_file(config, "%{seq}"))
	goto bad;
    config->iolog.uid = ROOT_UID;
    config->iolog.gid = ROOT_GID;
    config->iolog.gid_set = false;

    /* Event log defaults */
    config->eventlog.log_type = EVLOG_SYSLOG;
    config->eventlog.log_format = EVLOG_SUDO;

    /* Syslog defaults */
    config->syslog.maxlen = 960;
    if (!cb_syslog_facility(config, LOGFAC)) {
	sudo_warnx(U_("unknown syslog facility %s"), LOGFAC);
	goto bad;
    }
    if (!cb_syslog_acceptpri(config, PRI_SUCCESS)) {
	sudo_warnx(U_("unknown syslog priority %s"), PRI_SUCCESS);
	goto bad;
    }
    if (!cb_syslog_rejectpri(config, PRI_FAILURE)) {
	sudo_warnx(U_("unknown syslog priority %s"), PRI_FAILURE);
	goto bad;
    }
    if (!cb_syslog_alertpri(config, PRI_FAILURE)) {
	sudo_warnx(U_("unknown syslog priority %s"), PRI_FAILURE);
	goto bad;
    }

    /* Log file defaults */
    if (!cb_logfile_time_format(config, "%h %e %T"))
	goto bad;
    if (!cb_logfile_path(config, _PATH_SUDO_LOGFILE))
	goto bad;

    debug_return_ptr(config);
bad:
    logsrvd_conf_free(config);
    debug_return_ptr(NULL);
}

bool
logsrvd_conf_apply(struct logsrvd_config *config)
{
    debug_decl(logsrvd_conf_apply, SUDO_DEBUG_UTIL);

    /* There can be multiple addresses so we can't set a default earlier. */
    if (TAILQ_EMPTY(&config->server.addresses)) {
	if (!cb_listen_address(config, "*:30344"))
	    debug_return_bool(false);
    }

    /* Set I/O log library settings */
    iolog_set_defaults();
    iolog_set_compress(config->iolog.compress);
    iolog_set_flush(config->iolog.flush);
    iolog_set_owner(config->iolog.uid, config->iolog.gid);
    iolog_set_mode(config->iolog.mode);
    iolog_set_maxseq(config->iolog.maxseq);

    logsrvd_conf_free(logsrvd_config);
    logsrvd_config = config;

    debug_return_bool(true);
}

/*
 * Read .ini style logsrvd.conf file.
 * Note that we use '#' not ';' for the comment character.
 */
bool
logsrvd_conf_read(const char *path)
{
    struct logsrvd_config *config;
    bool ret = false;
    FILE *fp = NULL;
    debug_decl(logsrvd_conf_read, SUDO_DEBUG_UTIL);

    config = logsrvd_conf_alloc();

    if ((fp = fopen(path, "r")) == NULL) {
	if (errno != ENOENT) {
	    sudo_warn("%s", path);
	    goto done;
	}
    } else {
	if (!logsrvd_conf_parse(config, fp, path))
	    goto done;
    }

    /* Install new config */
    if (logsrvd_conf_apply(config)) {
	config = NULL;
	ret = true;
    }

done:
    logsrvd_conf_free(config);
    if (fp != NULL)
	fclose(fp);
    debug_return_bool(ret);
}
