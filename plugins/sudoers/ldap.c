/*
 * Copyright (c) 2003-2014 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * This code is derived from software contributed by Aaron Spangler.
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
#include <sys/time.h>
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
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef HAVE_LBER_H
# include <lber.h>
#endif
#include <ldap.h>
#if defined(HAVE_LDAP_SSL_H)
# include <ldap_ssl.h>
#elif defined(HAVE_MPS_LDAP_SSL_H)
# include <mps/ldap_ssl.h>
#endif
#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
# ifdef HAVE_SASL_SASL_H
#  include <sasl/sasl.h>
# else
#  include <sasl.h>
# endif
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */

#include "sudoers.h"
#include "parse.h"
#include "lbuf.h"
#include "sudo_dso.h"

/* Older Netscape LDAP SDKs don't prototype ldapssl_set_strength() */
#if defined(HAVE_LDAPSSL_SET_STRENGTH) && !defined(HAVE_LDAP_SSL_H) && !defined(HAVE_MPS_LDAP_SSL_H)
extern int ldapssl_set_strength(LDAP *ldap, int strength);
#endif

#if !defined(LDAP_OPT_NETWORK_TIMEOUT) && defined(LDAP_OPT_CONNECT_TIMEOUT)
# define LDAP_OPT_NETWORK_TIMEOUT LDAP_OPT_CONNECT_TIMEOUT
#endif

#ifndef LDAP_OPT_SUCCESS
# define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#ifndef LDAPS_PORT
# define LDAPS_PORT 636
#endif

#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && !defined(LDAP_SASL_QUIET)
# define LDAP_SASL_QUIET	0
#endif

#ifndef HAVE_LDAP_UNBIND_EXT_S
#define ldap_unbind_ext_s(a, b, c)	ldap_unbind_s(a)
#endif

#ifndef HAVE_LDAP_SEARCH_EXT_S
# ifdef HAVE_LDAP_SEARCH_ST
#  define ldap_search_ext_s(a, b, c, d, e, f, g, h, i, j, k)		\
	ldap_search_st(a, b, c, d, e, f, i, k)
# else
#  define ldap_search_ext_s(a, b, c, d, e, f, g, h, i, j, k)		\
	ldap_search_s(a, b, c, d, e, f, k)
# endif
#endif

#define LDAP_FOREACH(var, ld, res)					\
    for ((var) = ldap_first_entry((ld), (res));				\
	(var) != NULL;							\
	(var) = ldap_next_entry((ld), (var)))

#if defined(__GNUC__) && __GNUC__ == 2
# define DPRINTF1(fmt...) do {						\
    if (ldap_conf.debug >= 1)						\
	warningx(__VA_ARGS__);						\
    sudo_debug_printf(SUDO_DEBUG_DIAG, fmt);				\
} while (0)
# define DPRINTF2(fmt...) do {						\
    if (ldap_conf.debug >= 2)						\
	warningx(__VA_ARGS__);						\
    sudo_debug_printf(SUDO_DEBUG_INFO, fmt);				\
} while (0)
#else
# define DPRINTF1(...) do {						\
    if (ldap_conf.debug >= 1)						\
	warningx(__VA_ARGS__);						\
    sudo_debug_printf(SUDO_DEBUG_DIAG, __VA_ARGS__);			\
} while (0)
# define DPRINTF2(...) do {						\
    if (ldap_conf.debug >= 2)						\
	warningx(__VA_ARGS__);						\
    sudo_debug_printf(SUDO_DEBUG_INFO, __VA_ARGS__);			\
} while (0)
#endif

#define CONF_BOOL	0
#define CONF_INT	1
#define CONF_STR	2
#define CONF_LIST_STR	4
#define CONF_DEREF_VAL	5

#define SUDO_LDAP_CLEAR		0
#define SUDO_LDAP_SSL		1
#define SUDO_LDAP_STARTTLS	2

/* Default search filter. */
#define DEFAULT_SEARCH_FILTER	"(objectClass=sudoRole)"

/* The TIMEFILTER_LENGTH is the length of the filter when timed entries
   are used. The length is computed as follows:
       81       for the filter itself
       + 2 * 17 for the now timestamp
*/
#define TIMEFILTER_LENGTH	115

/*
 * The ldap_search structure implements a linked list of ldap and
 * search result pointers, which allows us to remove them after
 * all search results have been combined in memory.
 */
struct ldap_search_result {
    STAILQ_ENTRY(ldap_search_result) entries;
    LDAP *ldap;
    LDAPMessage *searchresult;
};
STAILQ_HEAD(ldap_search_list, ldap_search_result);

/*
 * The ldap_entry_wrapper structure is used to implement sorted result entries.
 * A double is used for the order to allow for insertion of new entries
 * without having to renumber everything.
 * Note: there is no standard floating point type in LDAP.
 *       As a result, some LDAP servers will only allow an integer.
 */
struct ldap_entry_wrapper {
    LDAPMessage	*entry;
    double order;
};

/*
 * The ldap_result structure contains the list of matching searches as
 * well as an array of all result entries sorted by the sudoOrder attribute.
 */
struct ldap_result {
    struct ldap_search_list searches;
    struct ldap_entry_wrapper *entries;
    int allocated_entries;
    int nentries;
    int user_matches;
    int host_matches;
};
#define	ALLOCATION_INCREMENT	100

struct ldap_config_table {
    const char *conf_str;	/* config file string */
    int type;			/* CONF_BOOL, CONF_INT, CONF_STR */
    int opt_val;		/* LDAP_OPT_* (or -1 for sudo internal) */
    void *valp;			/* pointer into ldap_conf */
};

struct ldap_config_str {
    STAILQ_ENTRY(ldap_config_str) entries;
    char val[1];
};

STAILQ_HEAD(ldap_config_str_list, ldap_config_str);

/* LDAP configuration structure */
static struct ldap_config {
    int port;
    int version;
    int debug;
    int ldap_debug;
    int tls_checkpeer;
    int timelimit;
    int timeout;
    int bind_timelimit;
    int use_sasl;
    int rootuse_sasl;
    int ssl_mode;
    int timed;
    int deref;
    char *host;
    struct ldap_config_str_list uri;
    char *binddn;
    char *bindpw;
    char *rootbinddn;
    struct ldap_config_str_list base;
    char *search_filter;
    char *ssl;
    char *tls_cacertfile;
    char *tls_cacertdir;
    char *tls_random_file;
    char *tls_cipher_suite;
    char *tls_certfile;
    char *tls_keyfile;
    char *tls_keypw;
    char *sasl_auth_id;
    char *rootsasl_auth_id;
    char *sasl_secprops;
    char *krb5_ccname;
} ldap_conf;

static struct ldap_config_table ldap_conf_global[] = {
    { "sudoers_debug", CONF_INT, -1, &ldap_conf.debug },
    { "host", CONF_STR, -1, &ldap_conf.host },
    { "port", CONF_INT, -1, &ldap_conf.port },
    { "ssl", CONF_STR, -1, &ldap_conf.ssl },
    { "sslpath", CONF_STR, -1, &ldap_conf.tls_certfile },
    { "uri", CONF_LIST_STR, -1, &ldap_conf.uri },
#ifdef LDAP_OPT_DEBUG_LEVEL
    { "debug", CONF_INT, LDAP_OPT_DEBUG_LEVEL, &ldap_conf.ldap_debug },
#endif
#ifdef LDAP_OPT_X_TLS_REQUIRE_CERT
    { "tls_checkpeer", CONF_BOOL, LDAP_OPT_X_TLS_REQUIRE_CERT,
	&ldap_conf.tls_checkpeer },
#else
    { "tls_checkpeer", CONF_BOOL, -1, &ldap_conf.tls_checkpeer },
#endif
#ifdef LDAP_OPT_X_TLS_CACERTFILE
    { "tls_cacertfile", CONF_STR, LDAP_OPT_X_TLS_CACERTFILE,
	&ldap_conf.tls_cacertfile },
    { "tls_cacert", CONF_STR, LDAP_OPT_X_TLS_CACERTFILE,
	&ldap_conf.tls_cacertfile },
#endif
#ifdef LDAP_OPT_X_TLS_CACERTDIR
    { "tls_cacertdir", CONF_STR, LDAP_OPT_X_TLS_CACERTDIR,
	&ldap_conf.tls_cacertdir },
#endif
#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
    { "tls_randfile", CONF_STR, LDAP_OPT_X_TLS_RANDOM_FILE,
	&ldap_conf.tls_random_file },
#endif
#ifdef LDAP_OPT_X_TLS_CIPHER_SUITE
    { "tls_ciphers", CONF_STR, LDAP_OPT_X_TLS_CIPHER_SUITE,
	&ldap_conf.tls_cipher_suite },
#elif defined(LDAP_OPT_SSL_CIPHER)
    { "tls_ciphers", CONF_STR, LDAP_OPT_SSL_CIPHER,
	&ldap_conf.tls_cipher_suite },
#endif
#ifdef LDAP_OPT_X_TLS_CERTFILE
    { "tls_cert", CONF_STR, LDAP_OPT_X_TLS_CERTFILE,
	&ldap_conf.tls_certfile },
#else
    { "tls_cert", CONF_STR, -1, &ldap_conf.tls_certfile },
#endif
#ifdef LDAP_OPT_X_TLS_KEYFILE
    { "tls_key", CONF_STR, LDAP_OPT_X_TLS_KEYFILE,
	&ldap_conf.tls_keyfile },
#else
    { "tls_key", CONF_STR, -1, &ldap_conf.tls_keyfile },
#endif
#ifdef HAVE_LDAP_SSL_CLIENT_INIT
    { "tls_keypw", CONF_STR, -1, &ldap_conf.tls_keypw },
#endif
    { "binddn", CONF_STR, -1, &ldap_conf.binddn },
    { "bindpw", CONF_STR, -1, &ldap_conf.bindpw },
    { "rootbinddn", CONF_STR, -1, &ldap_conf.rootbinddn },
    { "sudoers_base", CONF_LIST_STR, -1, &ldap_conf.base },
    { "sudoers_timed", CONF_BOOL, -1, &ldap_conf.timed },
    { "sudoers_search_filter", CONF_STR, -1, &ldap_conf.search_filter },
#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    { "use_sasl", CONF_BOOL, -1, &ldap_conf.use_sasl },
    { "sasl_auth_id", CONF_STR, -1, &ldap_conf.sasl_auth_id },
    { "rootuse_sasl", CONF_BOOL, -1, &ldap_conf.rootuse_sasl },
    { "rootsasl_auth_id", CONF_STR, -1, &ldap_conf.rootsasl_auth_id },
    { "krb5_ccname", CONF_STR, -1, &ldap_conf.krb5_ccname },
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */
    { NULL }
};

static struct ldap_config_table ldap_conf_conn[] = {
#ifdef LDAP_OPT_PROTOCOL_VERSION
    { "ldap_version", CONF_INT, LDAP_OPT_PROTOCOL_VERSION,
	&ldap_conf.version },
#endif
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    { "bind_timelimit", CONF_INT, -1 /* needs timeval, set manually */,
	&ldap_conf.bind_timelimit },
    { "network_timeout", CONF_INT, -1 /* needs timeval, set manually */,
	&ldap_conf.bind_timelimit },
#elif defined(LDAP_X_OPT_CONNECT_TIMEOUT)
    { "bind_timelimit", CONF_INT, LDAP_X_OPT_CONNECT_TIMEOUT,
	&ldap_conf.bind_timelimit },
    { "network_timeout", CONF_INT, LDAP_X_OPT_CONNECT_TIMEOUT,
	&ldap_conf.bind_timelimit },
#endif
    { "timelimit", CONF_INT, LDAP_OPT_TIMELIMIT, &ldap_conf.timelimit },
#ifdef LDAP_OPT_TIMEOUT
    { "timeout", CONF_INT, -1 /* needs timeval, set manually */,
	&ldap_conf.timeout },
#endif
#ifdef LDAP_OPT_DEREF
    { "deref", CONF_DEREF_VAL, LDAP_OPT_DEREF, &ldap_conf.deref },
#endif
#ifdef LDAP_OPT_X_SASL_SECPROPS
    { "sasl_secprops", CONF_STR, LDAP_OPT_X_SASL_SECPROPS,
	&ldap_conf.sasl_secprops },
#endif
    { NULL }
};

/* sudo_nss implementation */
static int sudo_ldap_open(struct sudo_nss *nss);
static int sudo_ldap_close(struct sudo_nss *nss);
static int sudo_ldap_parse(struct sudo_nss *nss);
static int sudo_ldap_setdefs(struct sudo_nss *nss);
static int sudo_ldap_lookup(struct sudo_nss *nss, int ret, int pwflag);
static int sudo_ldap_display_cmnd(struct sudo_nss *nss, struct passwd *pw);
static int sudo_ldap_display_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf);
static int sudo_ldap_display_bound_defaults(struct sudo_nss *nss,
    struct passwd *pw, struct lbuf *lbuf);
static int sudo_ldap_display_privs(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf);
static struct ldap_result *sudo_ldap_result_get(struct sudo_nss *nss,
    struct passwd *pw);

/*
 * LDAP sudo_nss handle.
 * We store the connection to the LDAP server, the cached ldap_result object
 * (if any), and the name of the user the query was performed for.
 * If a new query is launched with sudo_ldap_result_get() that specifies a
 * different user, the old cached result is freed before the new query is run.
 */
struct sudo_ldap_handle {
    LDAP *ld;
    struct ldap_result *result;
    char *username;
    struct group_list *grlist;
};

struct sudo_nss sudo_nss_ldap = {
    { NULL, NULL },
    sudo_ldap_open,
    sudo_ldap_close,
    sudo_ldap_parse,
    sudo_ldap_setdefs,
    sudo_ldap_lookup,
    sudo_ldap_display_cmnd,
    sudo_ldap_display_defaults,
    sudo_ldap_display_bound_defaults,
    sudo_ldap_display_privs
};

#ifdef HAVE_LDAP_CREATE
/*
 * Rebuild the hosts list and include a specific port for each host.
 * ldap_create() does not take a default port parameter so we must
 * append one if we want something other than LDAP_PORT.
 */
static void
sudo_ldap_conf_add_ports(void)
{

    char *host, *port, defport[13];
    char hostbuf[LINE_MAX * 2];
    int len;
    debug_decl(sudo_ldap_conf_add_ports, SUDO_DEBUG_LDAP)

    hostbuf[0] = '\0';
    len = snprintf(defport, sizeof(defport), ":%d", ldap_conf.port);
    if (len <= 0 || (size_t)len >= sizeof(defport))
	fatalx(U_("sudo_ldap_conf_add_ports: port too large"));

    for ((host = strtok(ldap_conf.host, " \t")); host; (host = strtok(NULL, " \t"))) {
	if (hostbuf[0] != '\0') {
	    if (strlcat(hostbuf, " ", sizeof(hostbuf)) >= sizeof(hostbuf))
		goto toobig;
	}

	if (strlcat(hostbuf, host, sizeof(hostbuf)) >= sizeof(hostbuf))
	    goto toobig;
	/* Append port if there is not one already. */
	if ((port = strrchr(host, ':')) == NULL ||
	    !isdigit((unsigned char)port[1])) {
	    if (strlcat(hostbuf, defport, sizeof(hostbuf)) >= sizeof(hostbuf))
		goto toobig;
	}
    }

    efree(ldap_conf.host);
    ldap_conf.host = estrdup(hostbuf);
    debug_return;

toobig:
    fatalx(U_("sudo_ldap_conf_add_ports: out of space expanding hostbuf"));
}
#endif

#ifndef HAVE_LDAP_INITIALIZE
/*
 * For each uri, convert to host:port pairs.  For ldaps:// enable SSL
 * Accepts: uris of the form ldap:/// or ldap://hostname:portnum/
 * where the trailing slash is optional.
 * Returns LDAP_SUCCESS on success, else non-zero.
 */
static int
sudo_ldap_parse_uri(const struct ldap_config_str_list *uri_list)
{
    const struct ldap_config_str *entry;
    char *buf, *uri, *host, *cp, *port;
    char hostbuf[LINE_MAX];
    int nldap = 0, nldaps = 0;
    int rc = -1;
    debug_decl(sudo_ldap_parse_uri, SUDO_DEBUG_LDAP)

    hostbuf[0] = '\0';
    STAILQ_FOREACH(entry, uri_list, entries) {
	buf = estrdup(entry->val);
	for ((uri = strtok(buf, " \t")); uri != NULL; (uri = strtok(NULL, " \t"))) {
	    if (strncasecmp(uri, "ldap://", 7) == 0) {
		nldap++;
		host = uri + 7;
	    } else if (strncasecmp(uri, "ldaps://", 8) == 0) {
		nldaps++;
		host = uri + 8;
	    } else {
		warningx(U_("unsupported LDAP uri type: %s"), uri);
		goto done;
	    }

	    /* trim optional trailing slash */
	    if ((cp = strrchr(host, '/')) != NULL && cp[1] == '\0') {
		*cp = '\0';
	    }

	    if (hostbuf[0] != '\0') {
		if (strlcat(hostbuf, " ", sizeof(hostbuf)) >= sizeof(hostbuf))
		    goto toobig;
	    }

	    if (*host == '\0')
		host = "localhost";		/* no host specified, use localhost */

	    if (strlcat(hostbuf, host, sizeof(hostbuf)) >= sizeof(hostbuf))
		goto toobig;

	    /* If using SSL and no port specified, add port 636 */
	    if (nldaps) {
		if ((port = strrchr(host, ':')) == NULL ||
		    !isdigit((unsigned char)port[1]))
		    if (strlcat(hostbuf, ":636", sizeof(hostbuf)) >= sizeof(hostbuf))
			goto toobig;
	    }
	}

	if (nldaps != 0) {
	    if (nldap != 0) {
		warningx(U_("unable to mix ldap and ldaps URIs"));
		goto done;
	    }
	    if (ldap_conf.ssl_mode == SUDO_LDAP_STARTTLS)
		warningx(U_("starttls not supported when using ldaps"));
	    ldap_conf.ssl_mode = SUDO_LDAP_SSL;
	}
	efree(buf);
    }
    buf = NULL;

    /* Store parsed URI(s) in host for ldap_create() or ldap_init(). */
    efree(ldap_conf.host);
    ldap_conf.host = estrdup(hostbuf);

    rc = LDAP_SUCCESS;

done:
    efree(buf);
    debug_return_int(rc);

toobig:
    fatalx(U_("sudo_ldap_parse_uri: out of space building hostbuf"));
}
#else
static char *
sudo_ldap_join_uri(struct ldap_config_str_list *uri_list)
{
    struct ldap_config_str *uri;
    size_t len = 0;
    char *buf, *cp;
    debug_decl(sudo_ldap_join_uri, SUDO_DEBUG_LDAP)

    STAILQ_FOREACH(uri, uri_list, entries) {
	if (ldap_conf.ssl_mode == SUDO_LDAP_STARTTLS) {
	    if (strncasecmp(uri->val, "ldaps://", 8) == 0) {
		warningx(U_("starttls not supported when using ldaps"));
		ldap_conf.ssl_mode = SUDO_LDAP_SSL;
	    }
	}
	len += strlen(uri->val) + 1;
    }
    buf = cp = emalloc(len);
    buf[0] = '\0';
    STAILQ_FOREACH(uri, uri_list, entries) {
	cp += strlcpy(cp, uri->val, len - (cp - buf));
	*cp++ = ' ';
    }
    cp[-1] = '\0';
    debug_return_str(buf);
}
#endif /* HAVE_LDAP_INITIALIZE */

/*
 * Wrapper for ldap_create() or ldap_init() that handles
 * SSL/TLS initialization as well.
 * Returns LDAP_SUCCESS on success, else non-zero.
 */
static int
sudo_ldap_init(LDAP **ldp, const char *host, int port)
{
    LDAP *ld;
    int rc = LDAP_CONNECT_ERROR;
    debug_decl(sudo_ldap_init, SUDO_DEBUG_LDAP)

#ifdef HAVE_LDAPSSL_INIT
    if (ldap_conf.ssl_mode != SUDO_LDAP_CLEAR) {
	const int defsecure = ldap_conf.ssl_mode == SUDO_LDAP_SSL;
	DPRINTF2("ldapssl_clientauth_init(%s, %s)",
	    ldap_conf.tls_certfile ? ldap_conf.tls_certfile : "NULL",
	    ldap_conf.tls_keyfile ? ldap_conf.tls_keyfile : "NULL");
	rc = ldapssl_clientauth_init(ldap_conf.tls_certfile, NULL,
	    ldap_conf.tls_keyfile != NULL, ldap_conf.tls_keyfile, NULL);
	/*
	 * Starting with version 5.0, Mozilla-derived LDAP SDKs require
	 * the cert and key paths to be a directory, not a file.
	 * If the user specified a file and it fails, try the parent dir.
	 */
	if (rc != LDAP_SUCCESS) {
	    bool retry = false;
	    if (ldap_conf.tls_certfile != NULL) {
		char *cp = strrchr(ldap_conf.tls_certfile, '/');
		if (cp != NULL && strncmp(cp + 1, "cert", 4) == 0) {
		    *cp = '\0';
		    retry = true;
		}
	    }
	    if (ldap_conf.tls_keyfile != NULL) {
		char *cp = strrchr(ldap_conf.tls_keyfile, '/');
		if (cp != NULL && strncmp(cp + 1, "key", 3) == 0) {
		    *cp = '\0';
		    retry = true;
		}
	    }
	    if (retry) {
		DPRINTF2("ldapssl_clientauth_init(%s, %s)",
		    ldap_conf.tls_certfile ? ldap_conf.tls_certfile : "NULL",
		    ldap_conf.tls_keyfile ? ldap_conf.tls_keyfile : "NULL");
		rc = ldapssl_clientauth_init(ldap_conf.tls_certfile, NULL,
		    ldap_conf.tls_keyfile != NULL, ldap_conf.tls_keyfile, NULL);
	    }
	}
	if (rc != LDAP_SUCCESS) {
	    warningx(U_("unable to initialize SSL cert and key db: %s"),
		ldapssl_err2string(rc));
	    if (ldap_conf.tls_certfile == NULL)
		warningx(U_("you must set TLS_CERT in %s to use SSL"),
		    path_ldap_conf);
	    goto done;
	}

	DPRINTF2("ldapssl_init(%s, %d, %d)", host, port, defsecure);
	if ((ld = ldapssl_init(host, port, defsecure)) != NULL)
	    rc = LDAP_SUCCESS;
    } else
#elif defined(HAVE_LDAP_SSL_INIT) && defined(HAVE_LDAP_SSL_CLIENT_INIT)
    if (ldap_conf.ssl_mode == SUDO_LDAP_SSL) {
	int sslrc;
	rc = ldap_ssl_client_init(ldap_conf.tls_keyfile, ldap_conf.tls_keypw,
	    0, &sslrc);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_ssl_client_init(): %s (SSL reason code %d)",
		ldap_err2string(rc), sslrc);
	    goto done;
	}
	DPRINTF2("ldap_ssl_init(%s, %d, NULL)", host, port);
	if ((ld = ldap_ssl_init((char *)host, port, NULL)) != NULL)
	    rc = LDAP_SUCCESS;
    } else
#endif
    {
#ifdef HAVE_LDAP_CREATE
	DPRINTF2("ldap_create()");
	if ((rc = ldap_create(&ld)) != LDAP_SUCCESS)
	    goto done;
	DPRINTF2("ldap_set_option(LDAP_OPT_HOST_NAME, %s)", host);
	rc = ldap_set_option(ld, LDAP_OPT_HOST_NAME, host);
#else
	DPRINTF2("ldap_init(%s, %d)", host, port);
	if ((ld = ldap_init((char *)host, port)) == NULL)
	    goto done;
	rc = LDAP_SUCCESS;
#endif
    }

    *ldp = ld;
done:
    debug_return_int(rc);
}

/*
 * Walk through search results and return true if we have a matching
 * non-Unix group (including netgroups), else false.
 */
static bool
sudo_ldap_check_non_unix_group(LDAP *ld, LDAPMessage *entry, struct passwd *pw)
{
    struct berval **bv, **p;
    char *val;
    int ret = false;
    debug_decl(sudo_ldap_check_non_unix_group, SUDO_DEBUG_LDAP)

    if (!entry)
	debug_return_bool(ret);

    /* get the values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoUser");
    if (bv == NULL)
	debug_return_bool(ret);

    /* walk through values */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	if (*val == '+') {
	    if (netgr_matches(val, NULL, NULL, pw->pw_name))
		ret = true;
	    DPRINTF2("ldap sudoUser netgroup '%s' ... %s", val,
		ret ? "MATCH!" : "not");
	} else {
	    if (group_plugin_query(pw->pw_name, val + 2, pw))
		ret = true;
	    DPRINTF2("ldap sudoUser non-Unix group '%s' ... %s", val,
		ret ? "MATCH!" : "not");
	}
    }

    ldap_value_free_len(bv);	/* cleanup */

    debug_return_bool(ret);
}

/*
* Walk through search results and return true if we have a
* host match, else false.
*/
static bool
sudo_ldap_check_host(LDAP *ld, LDAPMessage *entry)
{
    struct berval **bv, **p;
    char *val;
    bool ret = false;
    debug_decl(sudo_ldap_check_host, SUDO_DEBUG_LDAP)

    if (!entry)
	debug_return_bool(ret);

    /* get the values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoHost");
    if (bv == NULL)
	debug_return_bool(ret);

    /* walk through values */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	/* match any or address or netgroup or hostname */
	if (!strcmp(val, "ALL") || addr_matches(val) ||
	    netgr_matches(val, user_host, user_shost, NULL) ||
	    hostname_matches(user_shost, user_host, val))
	    ret = true;
	DPRINTF2("ldap sudoHost '%s' ... %s", val, ret ? "MATCH!" : "not");
    }

    ldap_value_free_len(bv);	/* cleanup */

    debug_return_bool(ret);
}

static int
sudo_ldap_check_runas_user(LDAP *ld, LDAPMessage *entry)
{
    struct berval **bv, **p;
    char *val;
    bool ret = false;
    debug_decl(sudo_ldap_check_runas_user, SUDO_DEBUG_LDAP)

    if (!runas_pw)
	debug_return_bool(UNSPEC);

    /* get the runas user from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoRunAsUser");
    if (bv == NULL)
	bv = ldap_get_values_len(ld, entry, "sudoRunAs"); /* old style */

    /*
     * BUG:
     * 
     * if runas is not specified on the command line, the only information
     * as to which user to run as is in the runas_default option.  We should
     * check to see if we have the local option present.  Unfortunately we
     * don't parse these options until after this routine says yes or no.
     * The query has already returned, so we could peek at the attribute
     * values here though.
     * 
     * For now just require users to always use -u option unless its set
     * in the global defaults. This behaviour is no different than the global
     * /etc/sudoers.
     * 
     * Sigh - maybe add this feature later
     */

    /*
     * If there are no runas entries, match runas_default against
     * what the user specified on the command line.
     */
    if (bv == NULL)
	debug_return_bool(!strcasecmp(runas_pw->pw_name, def_runas_default));

    /* walk through values returned, looking for a match */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	switch (val[0]) {
	case '+':
	    if (netgr_matches(val, NULL, NULL, runas_pw->pw_name))
		ret = true;
	    break;
	case '%':
	    if (usergr_matches(val, runas_pw->pw_name, runas_pw))
		ret = true;
	    break;
	case 'A':
	    if (strcmp(val, "ALL") == 0) {
		ret = true;
		break;
	    }
	    /* FALLTHROUGH */
	default:
	    if (userpw_matches(val, runas_pw->pw_name, runas_pw))
		ret = true;
	    break;
	}
	DPRINTF2("ldap sudoRunAsUser '%s' ... %s", val, ret ? "MATCH!" : "not");
    }

    ldap_value_free_len(bv);	/* cleanup */

    debug_return_bool(ret);
}

static int
sudo_ldap_check_runas_group(LDAP *ld, LDAPMessage *entry)
{
    struct berval **bv, **p;
    char *val;
    bool ret = false;
    debug_decl(sudo_ldap_check_runas_group, SUDO_DEBUG_LDAP)

    /* runas_gr is only set if the user specified the -g flag */
    if (!runas_gr)
	debug_return_bool(UNSPEC);

    /* get the values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoRunAsGroup");
    if (bv == NULL)
	debug_return_bool(ret);

    /* walk through values returned, looking for a match */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	if (strcmp(val, "ALL") == 0 || group_matches(val, runas_gr))
	    ret = true;
	DPRINTF2("ldap sudoRunAsGroup '%s' ... %s",
	    val, ret ? "MATCH!" : "not");
    }

    ldap_value_free_len(bv);	/* cleanup */

    debug_return_bool(ret);
}

/*
 * Walk through search results and return true if we have a runas match,
 * else false.  RunAs info is optional.
 */
static bool
sudo_ldap_check_runas(LDAP *ld, LDAPMessage *entry)
{
    bool ret;
    debug_decl(sudo_ldap_check_runas, SUDO_DEBUG_LDAP)

    if (!entry)
	debug_return_bool(false);

    ret = sudo_ldap_check_runas_user(ld, entry) != false &&
	sudo_ldap_check_runas_group(ld, entry) != false;

    debug_return_bool(ret);
}

static struct sudo_digest *
sudo_ldap_extract_digest(char **cmnd, struct sudo_digest *digest)
{
    char *ep, *cp = *cmnd;
    int digest_type = SUDO_DIGEST_INVALID;
    debug_decl(sudo_ldap_check_command, SUDO_DEBUG_LDAP)

    /*
     * Check for and extract a digest prefix, e.g.
     * sha224:d06a2617c98d377c250edd470fd5e576327748d82915d6e33b5f8db1 /bin/ls
     */
    if (cp[0] == 's' && cp[1] == 'h' && cp[2] == 'a') {
	switch (cp[3]) {
	case '2':
	    if (cp[4] == '2' && cp[5] == '4')
		digest_type = SUDO_DIGEST_SHA224;
	    else if (cp[4] == '5' && cp[5] == '6')
		digest_type = SUDO_DIGEST_SHA256;
	    break;
	case '3':
	    if (cp[4] == '8' && cp[5] == '4')
		digest_type = SUDO_DIGEST_SHA384;
	    break;
	case '5':
	    if (cp[4] == '1' && cp[5] == '2')
		digest_type = SUDO_DIGEST_SHA512;
	    break;
	}
	if (digest_type != SUDO_DIGEST_INVALID) {
	    cp += 6;
	    while (isblank((unsigned char)*cp))
		cp++;
	    if (*cp == ':') {
		cp++;
		while (isblank((unsigned char)*cp))
		    cp++;
		ep = cp;
		while (*ep != '\0' && !isblank((unsigned char)*ep))
		    ep++;
		if (*ep != '\0') {
		    digest->digest_type = digest_type;
		    digest->digest_str = estrndup(cp, (size_t)(ep - cp));
		    cp = ep + 1;
		    while (isblank((unsigned char)*cp))
			cp++;
		    *cmnd = cp;
		    DPRINTF1("%s digest %s for %s",
			digest_type == SUDO_DIGEST_SHA224 ? "sha224" :
			digest_type == SUDO_DIGEST_SHA256 ? "sha256" :
			digest_type == SUDO_DIGEST_SHA384 ? "sha384" :
			"sha512", digest->digest_str, cp);
		    debug_return_ptr(digest);
		}
	    }
	}
    }
    debug_return_ptr(NULL);
}

/*
 * Walk through search results and return true if we have a command match,
 * false if disallowed and UNSPEC if not matched.
 */
static int
sudo_ldap_check_command(LDAP *ld, LDAPMessage *entry, int *setenv_implied)
{
    struct sudo_digest digest, *allowed_digest = NULL;
    struct berval **bv, **p;
    char *allowed_cmnd, *allowed_args, *val;
    bool foundbang;
    int ret = UNSPEC;
    debug_decl(sudo_ldap_check_command, SUDO_DEBUG_LDAP)

    if (!entry)
	debug_return_bool(ret);

    bv = ldap_get_values_len(ld, entry, "sudoCommand");
    if (bv == NULL)
	debug_return_bool(ret);

    for (p = bv; *p != NULL && ret != false; p++) {
	val = (*p)->bv_val;
	/* Match against ALL ? */
	if (!strcmp(val, "ALL")) {
	    ret = true;
	    if (setenv_implied != NULL)
		*setenv_implied = true;
	    DPRINTF2("ldap sudoCommand '%s' ... MATCH!", val);
	    continue;
	}

	/* check for sha-2 digest */
	allowed_digest = sudo_ldap_extract_digest(&val, &digest);

	/* check for !command */
	if (*val == '!') {
	    foundbang = true;
	    allowed_cmnd = estrdup(1 + val);	/* !command */
	} else {
	    foundbang = false;
	    allowed_cmnd = estrdup(val);	/* command */
	}

	/* split optional args away from command */
	allowed_args = strchr(allowed_cmnd, ' ');
	if (allowed_args)
	    *allowed_args++ = '\0';

	/* check the command like normal */
	if (command_matches(allowed_cmnd, allowed_args, allowed_digest)) {
	    /*
	     * If allowed (no bang) set ret but keep on checking.
	     * If disallowed (bang), exit loop.
	     */
	    ret = foundbang ? false : true;
	}
	DPRINTF2("ldap sudoCommand '%s' ... %s",
	    val, ret == true ? "MATCH!" : "not");

	efree(allowed_cmnd);	/* cleanup */
	if (allowed_digest != NULL)
	    efree(allowed_digest->digest_str);
    }

    ldap_value_free_len(bv);	/* more cleanup */

    debug_return_bool(ret);
}

/*
 * Search for boolean "option" in sudoOption.
 * Returns true if found and allowed, false if negated, else UNSPEC.
 */
static int
sudo_ldap_check_bool(LDAP *ld, LDAPMessage *entry, char *option)
{
    struct berval **bv, **p;
    char ch, *var;
    int ret = UNSPEC;
    debug_decl(sudo_ldap_check_bool, SUDO_DEBUG_LDAP)

    if (entry == NULL)
	debug_return_bool(ret);

    bv = ldap_get_values_len(ld, entry, "sudoOption");
    if (bv == NULL)
	debug_return_bool(ret);

    /* walk through options */
    for (p = bv; *p != NULL; p++) {
	var = (*p)->bv_val;;
	DPRINTF2("ldap sudoOption: '%s'", var);

	if ((ch = *var) == '!')
	    var++;
	if (strcmp(var, option) == 0)
	    ret = (ch != '!');
    }

    ldap_value_free_len(bv);

    debug_return_bool(ret);
}

/*
 * Read sudoOption and modify the defaults as we go.  This is used once
 * from the cn=defaults entry and also once when a final sudoRole is matched.
 */
static void
sudo_ldap_parse_options(LDAP *ld, LDAPMessage *entry)
{
    struct berval **bv, **p;
    char op, *var, *val;
    debug_decl(sudo_ldap_parse_options, SUDO_DEBUG_LDAP)

    if (entry == NULL)
	debug_return;

    bv = ldap_get_values_len(ld, entry, "sudoOption");
    if (bv == NULL)
	debug_return;

    /* walk through options */
    for (p = bv; *p != NULL; p++) {
	var = estrdup((*p)->bv_val);
	DPRINTF2("ldap sudoOption: '%s'", var);

	/* check for equals sign past first char */
	val = strchr(var, '=');
	if (val > var) {
	    *val++ = '\0';	/* split on = and truncate var */
	    op = *(val - 2);	/* peek for += or -= cases */
	    if (op == '+' || op == '-') {
		*(val - 2) = '\0';	/* found, remove extra char */
		/* case var+=val or var-=val */
		set_default(var, val, (int) op);
	    } else {
		/* case var=val */
		set_default(var, val, true);
	    }
	} else if (*var == '!') {
	    /* case !var Boolean False */
	    set_default(var + 1, NULL, false);
	} else {
	    /* case var Boolean True */
	    set_default(var, NULL, true);
	}
	efree(var);
    }

    ldap_value_free_len(bv);

    debug_return;
}

/*
 * Build an LDAP timefilter.
 *
 * Stores a filter in the buffer that makes sure only entries
 * are selected that have a sudoNotBefore in the past and a
 * sudoNotAfter in the future, i.e. a filter of the following
 * structure (spaced out a little more for better readability:
 *
 * (&
 *   (|
 *	(!(sudoNotAfter=*))
 *	(sudoNotAfter>__now__)
 *   )
 *   (|
 *	(!(sudoNotBefore=*))
 *	(sudoNotBefore<__now__)
 *   )
 * )
 *
 * If either the sudoNotAfter or sudoNotBefore attributes are missing,
 * no time restriction shall be imposed.
 */
static int
sudo_ldap_timefilter(char *buffer, size_t buffersize)
{
    struct tm *tp;
    time_t now;
    char timebuffer[sizeof("20120727121554.0Z")];
    int bytes = 0;
    debug_decl(sudo_ldap_timefilter, SUDO_DEBUG_LDAP)

    /* Make sure we have a formatted timestamp for __now__. */
    time(&now);
    if ((tp = gmtime(&now)) == NULL) {
	warning(U_("unable to get GMT time"));
	goto done;
    }

    /* Format the timestamp according to the RFC. */
    if (strftime(timebuffer, sizeof(timebuffer), "%Y%m%d%H%M%S.0Z", tp) == 0) {
	warningx(U_("unable to format timestamp"));
	goto done;
    }

    /* Build filter. */
    bytes = snprintf(buffer, buffersize, "(&(|(!(sudoNotAfter=*))(sudoNotAfter>=%s))(|(!(sudoNotBefore=*))(sudoNotBefore<=%s)))",
	timebuffer, timebuffer);
    if (bytes <= 0 || (size_t)bytes >= buffersize) {
	warning(U_("unable to build time filter"));
	bytes = 0;
    }

done:
    debug_return_int(bytes);
}

/*
 * Builds up a filter to search for default settings
 */
static char *
sudo_ldap_build_default_filter(void)
{
    char *filt;
    debug_decl(sudo_ldap_build_default_filter, SUDO_DEBUG_LDAP)

    if (ldap_conf.search_filter)
	easprintf(&filt, "(&%s(cn=defaults))", ldap_conf.search_filter);
    else
	filt = estrdup("cn=defaults");
    debug_return_str(filt);
}

/*
 * Determine length of query value after escaping characters
 * as per RFC 4515.
 */
static size_t
sudo_ldap_value_len(const char *value)
{
    const char *s;
    size_t len = 0;

    for (s = value; *s != '\0'; s++) {
	switch (*s) {
	case '\\':
	case '(':
	case ')':
	case '*':
	    len += 2;
	    break;
	}
    }
    len += (size_t)(s - value);
    return len;
}

/*
 * Like strlcat() but escapes characters as per RFC 4515.
 */
static size_t
sudo_ldap_value_cat(char *dst, const char *src, size_t size)
{
    char *d = dst;
    const char *s = src;
    size_t n = size;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end */
    while (n-- != 0 && *d != '\0')
	d++;
    dlen = d - dst;
    n = size - dlen;

    if (n == 0)
	return dlen + strlen(s);
    while (*s != '\0') {
	switch (*s) {
	case '\\':
	    if (n < 3)
		goto done;
	    *d++ = '\\';
	    *d++ = '5';
	    *d++ = 'c';
	    n -= 3;
	    break;
	case '(':
	    if (n < 3)
		goto done;
	    *d++ = '\\';
	    *d++ = '2';
	    *d++ = '8';
	    n -= 3;
	    break;
	case ')':
	    if (n < 3)
		goto done;
	    *d++ = '\\';
	    *d++ = '2';
	    *d++ = '9';
	    n -= 3;
	    break;
	case '*':
	    if (n < 3)
		goto done;
	    *d++ = '\\';
	    *d++ = '2';
	    *d++ = 'a';
	    n -= 3;
	    break;
	default:
	    if (n < 1)
		goto done;
	    *d++ = *s;
	    n--;
	    break;
	}
	s++;
    }
done:
    *d = '\0';
    while (*s != '\0')
	s++;
    return dlen + (s - src);	/* count does not include NUL */
}

/*
 * Builds up a filter to check against LDAP.
 */
static char *
sudo_ldap_build_pass1(struct passwd *pw)
{
    struct group *grp;
    char *buf, timebuffer[TIMEFILTER_LENGTH + 1], gidbuf[MAX_UID_T_LEN + 1];
    struct group_list *grlist;
    size_t sz = 0;
    int i;
    debug_decl(sudo_ldap_build_pass1, SUDO_DEBUG_LDAP)

    /* If there is a filter, allocate space for the global AND. */
    if (ldap_conf.timed || ldap_conf.search_filter)
	sz += 3;

    /* Add LDAP search filter if present. */
    if (ldap_conf.search_filter)
	sz += strlen(ldap_conf.search_filter);

    /* Then add (|(sudoUser=USERNAME)(sudoUser=ALL)) + NUL */
    sz += 29 + sudo_ldap_value_len(pw->pw_name);

    /* Add space for primary and supplementary groups and gids */
    if ((grp = sudo_getgrgid(pw->pw_gid)) != NULL) {
	sz += 12 + sudo_ldap_value_len(grp->gr_name);
    }
    sz += 13 + MAX_UID_T_LEN;
    if ((grlist = sudo_get_grlist(pw)) != NULL) {
	for (i = 0; i < grlist->ngroups; i++) {
	    if (grp != NULL && strcasecmp(grlist->groups[i], grp->gr_name) == 0)
		continue;
	    sz += 12 + sudo_ldap_value_len(grlist->groups[i]);
	}
	for (i = 0; i < grlist->ngids; i++) {
	    if (pw->pw_gid == grlist->gids[i])
		continue;
	    sz += 13 + MAX_UID_T_LEN;
	}
    }

    /* If timed, add space for time limits. */
    if (ldap_conf.timed)
	sz += TIMEFILTER_LENGTH;
    buf = emalloc(sz);
    *buf = '\0';

    /*
     * If timed or using a search filter, start a global AND clause to
     * contain the search filter, search criteria, and time restriction.
     */
    if (ldap_conf.timed || ldap_conf.search_filter)
	(void) strlcpy(buf, "(&", sz);

    if (ldap_conf.search_filter)
	(void) strlcat(buf, ldap_conf.search_filter, sz);

    /* Global OR + sudoUser=user_name filter */
    (void) strlcat(buf, "(|(sudoUser=", sz);
    (void) sudo_ldap_value_cat(buf, pw->pw_name, sz);
    (void) strlcat(buf, ")", sz);

    /* Append primary group and gid */
    if (grp != NULL) {
	(void) strlcat(buf, "(sudoUser=%", sz);
	(void) sudo_ldap_value_cat(buf, grp->gr_name, sz);
	(void) strlcat(buf, ")", sz);
    }
    (void) snprintf(gidbuf, sizeof(gidbuf), "%u", (unsigned int)pw->pw_gid);
    (void) strlcat(buf, "(sudoUser=%#", sz);
    (void) strlcat(buf, gidbuf, sz);
    (void) strlcat(buf, ")", sz);

    /* Append supplementary groups and gids */
    if (grlist != NULL) {
	for (i = 0; i < grlist->ngroups; i++) {
	    if (grp != NULL && strcasecmp(grlist->groups[i], grp->gr_name) == 0)
		continue;
	    (void) strlcat(buf, "(sudoUser=%", sz);
	    (void) sudo_ldap_value_cat(buf, grlist->groups[i], sz);
	    (void) strlcat(buf, ")", sz);
	}
	for (i = 0; i < grlist->ngids; i++) {
	    if (pw->pw_gid == grlist->gids[i])
		continue;
	    (void) snprintf(gidbuf, sizeof(gidbuf), "%u",
		(unsigned int)grlist->gids[i]);
	    (void) strlcat(buf, "(sudoUser=%#", sz);
	    (void) strlcat(buf, gidbuf, sz);
	    (void) strlcat(buf, ")", sz);
	}
    }

    /* Done with groups. */
    if (grlist != NULL)
	sudo_grlist_delref(grlist);
    if (grp != NULL)
	sudo_gr_delref(grp);

    /* Add ALL to list and end the global OR */
    if (strlcat(buf, "(sudoUser=ALL)", sz) >= sz)
	fatalx(U_("sudo_ldap_build_pass1 allocation mismatch"));

    /* Add the time restriction, or simply end the global OR. */
    if (ldap_conf.timed) {
	strlcat(buf, ")", sz); /* closes the global OR */
	sudo_ldap_timefilter(timebuffer, sizeof(timebuffer));
	strlcat(buf, timebuffer, sz);
    } else if (ldap_conf.search_filter) {
	strlcat(buf, ")", sz); /* closes the global OR */
    }
    strlcat(buf, ")", sz); /* closes the global OR or the global AND */

    debug_return_str(buf);
}

/*
 * Builds up a filter to check against non-Unix group
 * entries in LDAP, including netgroups.
 */
static char *
sudo_ldap_build_pass2(void)
{
    char *filt, timebuffer[TIMEFILTER_LENGTH + 1];
    debug_decl(sudo_ldap_build_pass2, SUDO_DEBUG_LDAP)

    /* Short circuit if no non-Unix group support. */
    if (!def_use_netgroups && !def_group_plugin) {
	debug_return_str(NULL);
    }

    if (ldap_conf.timed)
	sudo_ldap_timefilter(timebuffer, sizeof(timebuffer));

    /*
     * Match all sudoUsers beginning with '+' or '%:'.
     * If a search filter or time restriction is specified, 
     * those get ANDed in to the expression.
     */
    if (def_group_plugin) {
	easprintf(&filt, "%s%s(|(sudoUser=%s*)(sudoUser=%%:*))%s%s",
	    (ldap_conf.timed || ldap_conf.search_filter) ? "(&" : "",
	    ldap_conf.search_filter ? ldap_conf.search_filter : "",
	    def_use_netgroups ? "+" : "",
	    ldap_conf.timed ? timebuffer : "",
	    (ldap_conf.timed || ldap_conf.search_filter) ? ")" : "");
    } else {
	easprintf(&filt, "%s%s(sudoUser=*)(sudoUser=+*)%s%s",
	    (ldap_conf.timed || ldap_conf.search_filter) ? "(&" : "",
	    ldap_conf.search_filter ? ldap_conf.search_filter : "",
	    ldap_conf.timed ? timebuffer : "",
	    (ldap_conf.timed || ldap_conf.search_filter) ? ")" : "");
    }

    debug_return_str(filt);
}

static void
sudo_ldap_read_secret(const char *path)
{
    FILE *fp;
    char buf[LINE_MAX], *cp;
    debug_decl(sudo_ldap_read_secret, SUDO_DEBUG_LDAP)

    if ((fp = fopen(path_ldap_secret, "r")) != NULL) {
	if (fgets(buf, sizeof(buf), fp) != NULL) {
	    if ((cp = strchr(buf, '\n')) != NULL)
		*cp = '\0';
	    /* copy to bindpw and binddn */
	    efree(ldap_conf.bindpw);
	    ldap_conf.bindpw = estrdup(buf);
	    efree(ldap_conf.binddn);
	    ldap_conf.binddn = ldap_conf.rootbinddn;
	    ldap_conf.rootbinddn = NULL;
	}
	fclose(fp);
    }
    debug_return;
}

/*
 * Look up keyword in config tables.
 * Returns true if found, else false.
 */
static bool
sudo_ldap_parse_keyword(const char *keyword, const char *value,
    struct ldap_config_table *table)
{
    struct ldap_config_table *cur;
    const char *errstr;
    debug_decl(sudo_ldap_parse_keyword, SUDO_DEBUG_LDAP)

    /* Look up keyword in config tables */
    for (cur = table; cur->conf_str != NULL; cur++) {
	if (strcasecmp(keyword, cur->conf_str) == 0) {
	    switch (cur->type) {
	    case CONF_DEREF_VAL:
		if (strcasecmp(value, "searching") == 0)
		    *(int *)(cur->valp) = LDAP_DEREF_SEARCHING;
		else if (strcasecmp(value, "finding") == 0)
		    *(int *)(cur->valp) = LDAP_DEREF_FINDING;
		else if (strcasecmp(value, "always") == 0)
		    *(int *)(cur->valp) = LDAP_DEREF_ALWAYS;
		else
		    *(int *)(cur->valp) = LDAP_DEREF_NEVER;
		break;
	    case CONF_BOOL:
		*(int *)(cur->valp) = atobool(value) == true;
		break;
	    case CONF_INT:
		*(int *)(cur->valp) = strtonum(value, INT_MIN, INT_MAX, &errstr);
		if (errstr != NULL) {
		    warningx(U_("%s: %s: %s: %s"),
			path_ldap_conf, keyword, value, U_(errstr));
		}
		break;
	    case CONF_STR:
		efree(*(char **)(cur->valp));
		*(char **)(cur->valp) = *value ? estrdup(value) : NULL;
		break;
	    case CONF_LIST_STR:
		{
		    struct ldap_config_str_list *head;
		    struct ldap_config_str *str;
		    size_t len = strlen(value);

		    if (len > 0) {
			head = (struct ldap_config_str_list *)cur->valp;
			str = emalloc(sizeof(*str) + len);
			memcpy(str->val, value, len + 1);
			STAILQ_INSERT_TAIL(head, str, entries);
		    }
		}
		break;
	    }
	    debug_return_bool(true);
	}
    }
    debug_return_bool(false);
}

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
static const char *
sudo_krb5_ccname_path(const char *old_ccname)
{
    const char *ccname = old_ccname;
    debug_decl(sudo_krb5_ccname_path, SUDO_DEBUG_LDAP)

    /* Strip off leading FILE: or WRFILE: prefix. */
    switch (ccname[0]) {
	case 'F':
	case 'f':
	    if (strncasecmp(ccname, "FILE:", 5) == 0)
		ccname += 5;
	    break;
	case 'W':
	case 'w':
	    if (strncasecmp(ccname, "WRFILE:", 7) == 0)
		ccname += 7;
	    break;
    }
    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
	"ccache %s -> %s", old_ccname, ccname);

    /* Credential cache must be a fully-qualified path name. */
    debug_return_const_str(*ccname == '/' ? ccname : NULL);
}

static bool
sudo_check_krb5_ccname(const char *ccname)
{
    int fd = -1;
    const char *ccname_path;
    debug_decl(sudo_check_krb5_ccname, SUDO_DEBUG_LDAP)

    /* Strip off prefix to get path name. */
    ccname_path = sudo_krb5_ccname_path(ccname);
    if (ccname_path == NULL) {
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
	    "unsupported krb5 credential cache path: %s", ccname);
	debug_return_bool(false);
    }
    /* Make sure credential cache is fully-qualified and exists. */
    fd = open(ccname_path, O_RDONLY|O_NONBLOCK, 0);
    if (fd == -1) {
	sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
	    "unable to open krb5 credential cache: %s", ccname_path);
	debug_return_bool(false);
    }
    close(fd);
    sudo_debug_printf(SUDO_DEBUG_INFO,
	"using krb5 credential cache: %s", ccname_path);
    debug_return_bool(true);
}
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */

static bool
sudo_ldap_read_config(void)
{
    FILE *fp;
    char *cp, *keyword, *value, *line = NULL;
    size_t linesize = 0;
    debug_decl(sudo_ldap_read_config, SUDO_DEBUG_LDAP)

    /* defaults */
    ldap_conf.version = 3;
    ldap_conf.port = -1;
    ldap_conf.tls_checkpeer = -1;
    ldap_conf.timelimit = -1;
    ldap_conf.timeout = -1;
    ldap_conf.bind_timelimit = -1;
    ldap_conf.use_sasl = -1;
    ldap_conf.rootuse_sasl = -1;
    ldap_conf.deref = -1;
    ldap_conf.search_filter = estrdup(DEFAULT_SEARCH_FILTER);
    STAILQ_INIT(&ldap_conf.uri);
    STAILQ_INIT(&ldap_conf.base);

    if ((fp = fopen(path_ldap_conf, "r")) == NULL)
	debug_return_bool(false);

    while (sudo_parseln(&line, &linesize, NULL, fp) != -1) {
	if (*line == '\0')
	    continue;		/* skip empty line */

	/* split into keyword and value */
	keyword = cp = line;
	while (*cp && !isblank((unsigned char) *cp))
	    cp++;
	if (*cp)
	    *cp++ = '\0';	/* terminate keyword */

	/* skip whitespace before value */
	while (isblank((unsigned char) *cp))
	    cp++;
	value = cp;

	/* Look up keyword in config tables */
	if (!sudo_ldap_parse_keyword(keyword, value, ldap_conf_global))
	    sudo_ldap_parse_keyword(keyword, value, ldap_conf_conn);
    }
    free(line);
    fclose(fp);

    if (!ldap_conf.host)
	ldap_conf.host = estrdup("localhost");

    DPRINTF1("LDAP Config Summary");
    DPRINTF1("===================");
    if (!STAILQ_EMPTY(&ldap_conf.uri)) {
	struct ldap_config_str *uri;

	STAILQ_FOREACH(uri, &ldap_conf.uri, entries) {
	    DPRINTF1("uri              %s", uri->val);
	}
    } else {
	DPRINTF1("host             %s",
	    ldap_conf.host ? ldap_conf.host : "(NONE)");
	DPRINTF1("port             %d", ldap_conf.port);
    }
    DPRINTF1("ldap_version     %d", ldap_conf.version);

    if (!STAILQ_EMPTY(&ldap_conf.base)) {
	struct ldap_config_str *base;
	STAILQ_FOREACH(base, &ldap_conf.base, entries) {
	    DPRINTF1("sudoers_base     %s", base->val);
	}
    } else {
	DPRINTF1("sudoers_base     %s", "(NONE: LDAP disabled)");
    }
    if (ldap_conf.search_filter) {
	DPRINTF1("search_filter    %s", ldap_conf.search_filter);
    }
    DPRINTF1("binddn           %s",
	ldap_conf.binddn ? ldap_conf.binddn : "(anonymous)");
    DPRINTF1("bindpw           %s",
	ldap_conf.bindpw ? ldap_conf.bindpw : "(anonymous)");
    if (ldap_conf.bind_timelimit > 0) {
	DPRINTF1("bind_timelimit   %d", ldap_conf.bind_timelimit);
    }
    if (ldap_conf.timelimit > 0) {
	DPRINTF1("timelimit        %d", ldap_conf.timelimit);
    }
    if (ldap_conf.deref != -1) {
	DPRINTF1("deref            %d", ldap_conf.deref);
    }
    DPRINTF1("ssl              %s", ldap_conf.ssl ? ldap_conf.ssl : "(no)");
    if (ldap_conf.tls_checkpeer != -1) {
	DPRINTF1("tls_checkpeer    %s",
	    ldap_conf.tls_checkpeer ? "(yes)" : "(no)");
    }
    if (ldap_conf.tls_cacertfile != NULL) {
	DPRINTF1("tls_cacertfile   %s", ldap_conf.tls_cacertfile);
    }
    if (ldap_conf.tls_cacertdir != NULL) {
	DPRINTF1("tls_cacertdir    %s", ldap_conf.tls_cacertdir);
    }
    if (ldap_conf.tls_random_file != NULL) {
	DPRINTF1("tls_random_file  %s", ldap_conf.tls_random_file);
    }
    if (ldap_conf.tls_cipher_suite != NULL) {
	DPRINTF1("tls_cipher_suite %s", ldap_conf.tls_cipher_suite);
    }
    if (ldap_conf.tls_certfile != NULL) {
	DPRINTF1("tls_certfile     %s", ldap_conf.tls_certfile);
    }
    if (ldap_conf.tls_keyfile != NULL) {
	DPRINTF1("tls_keyfile      %s", ldap_conf.tls_keyfile);
    }
#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    if (ldap_conf.use_sasl != -1) {
	DPRINTF1("use_sasl         %s", ldap_conf.use_sasl ? "yes" : "no");
	DPRINTF1("sasl_auth_id     %s",
	    ldap_conf.sasl_auth_id ? ldap_conf.sasl_auth_id : "(NONE)");
	DPRINTF1("rootuse_sasl     %d",
	    ldap_conf.rootuse_sasl);
	DPRINTF1("rootsasl_auth_id %s",
	    ldap_conf.rootsasl_auth_id ? ldap_conf.rootsasl_auth_id : "(NONE)");
	DPRINTF1("sasl_secprops    %s",
	    ldap_conf.sasl_secprops ? ldap_conf.sasl_secprops : "(NONE)");
	DPRINTF1("krb5_ccname      %s",
	    ldap_conf.krb5_ccname ? ldap_conf.krb5_ccname : "(NONE)");
    }
#endif
    DPRINTF1("===================");

    if (STAILQ_EMPTY(&ldap_conf.base))
	debug_return_bool(false);	/* if no base is defined, ignore LDAP */

    if (ldap_conf.bind_timelimit > 0)
	ldap_conf.bind_timelimit *= 1000;	/* convert to ms */

    /*
     * Interpret SSL option
     */
    if (ldap_conf.ssl != NULL) {
	if (strcasecmp(ldap_conf.ssl, "start_tls") == 0)
	    ldap_conf.ssl_mode = SUDO_LDAP_STARTTLS;
	else if (atobool(ldap_conf.ssl) == true)
	    ldap_conf.ssl_mode = SUDO_LDAP_SSL;
    }

#if defined(HAVE_LDAPSSL_SET_STRENGTH) && !defined(LDAP_OPT_X_TLS_REQUIRE_CERT)
    if (ldap_conf.tls_checkpeer != -1) {
	ldapssl_set_strength(NULL,
	    ldap_conf.tls_checkpeer ? LDAPSSL_AUTH_CERT : LDAPSSL_AUTH_WEAK);
    }
#endif

#ifndef HAVE_LDAP_INITIALIZE
    /* Convert uri list to host list if no ldap_initialize(). */
    if (!STAILQ_EMPTY(&ldap_conf.uri)) {
	struct ldap_config_str *uri;

	if (sudo_ldap_parse_uri(&ldap_conf.uri) != LDAP_SUCCESS)
	    debug_return_bool(false);
	while ((uri = STAILQ_FIRST(&ldap_conf.uri)) != NULL) {
	    STAILQ_REMOVE_HEAD(&ldap_conf.uri, entries);
	    efree(uri);
	}
	ldap_conf.port = LDAP_PORT;
    }
#endif

    if (STAILQ_EMPTY(&ldap_conf.uri)) {
	/* Use port 389 for plaintext LDAP and port 636 for SSL LDAP */
	if (ldap_conf.port < 0)
	    ldap_conf.port =
		ldap_conf.ssl_mode == SUDO_LDAP_SSL ? LDAPS_PORT : LDAP_PORT;

#ifdef HAVE_LDAP_CREATE
	/*
	 * Cannot specify port directly to ldap_create(), each host must
	 * include :port to override the default.
	 */
	if (ldap_conf.port != LDAP_PORT)
	    sudo_ldap_conf_add_ports();
#endif
    }

    /* If search filter is not parenthesized, make it so. */
    if (ldap_conf.search_filter && ldap_conf.search_filter[0] != '(') {
	size_t len = strlen(ldap_conf.search_filter);
	cp = ldap_conf.search_filter;
	ldap_conf.search_filter = emalloc(len + 3);
	ldap_conf.search_filter[0] = '(';
	memcpy(ldap_conf.search_filter + 1, cp, len);
	ldap_conf.search_filter[len + 1] = ')';
	ldap_conf.search_filter[len + 2] = '\0';
	efree(cp);
    }

    /* If rootbinddn set, read in /etc/ldap.secret if it exists. */
    if (ldap_conf.rootbinddn)
	sudo_ldap_read_secret(path_ldap_secret);

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    /*
     * Make sure we can open the file specified by krb5_ccname.
     */
    if (ldap_conf.krb5_ccname != NULL) {
	if (!sudo_check_krb5_ccname(ldap_conf.krb5_ccname))
	    ldap_conf.krb5_ccname = NULL;
    }
#endif

    debug_return_bool(true);
}

/*
 * Extract the dn from an entry and return the first rdn from it.
 */
static char *
sudo_ldap_get_first_rdn(LDAP *ld, LDAPMessage *entry)
{
#ifdef HAVE_LDAP_STR2DN
    char *dn, *rdn = NULL;
    LDAPDN tmpDN;
    debug_decl(sudo_ldap_get_first_rdn, SUDO_DEBUG_LDAP)

    if ((dn = ldap_get_dn(ld, entry)) == NULL)
	debug_return_str(NULL);
    if (ldap_str2dn(dn, &tmpDN, LDAP_DN_FORMAT_LDAP) == LDAP_SUCCESS) {
	ldap_rdn2str(tmpDN[0], &rdn, LDAP_DN_FORMAT_UFN);
	ldap_dnfree(tmpDN);
    }
    ldap_memfree(dn);
    debug_return_str(rdn);
#else
    char *dn, **edn;
    debug_decl(sudo_ldap_get_first_rdn, SUDO_DEBUG_LDAP)

    if ((dn = ldap_get_dn(ld, entry)) == NULL)
	return NULL;
    edn = ldap_explode_dn(dn, 1);
    ldap_memfree(dn);
    debug_return_str(edn ? edn[0] : NULL);
#endif
}

/*
 * Fetch and display the global Options.
 */
static int
sudo_ldap_display_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf)
{
    struct berval **bv, **p;
    struct timeval tv, *tvp = NULL;
    struct ldap_config_str *base;
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    LDAPMessage *entry, *result;
    char *prefix, *filt;
    int rc, count = 0;
    debug_decl(sudo_ldap_display_defaults, SUDO_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	goto done;
    ld = handle->ld;

    filt = sudo_ldap_build_default_filter();
    STAILQ_FOREACH(base, &ldap_conf.base, entries) {
	if (ldap_conf.timeout > 0) {
	    tv.tv_sec = ldap_conf.timeout;
	    tv.tv_usec = 0;
	    tvp = &tv;
	}
	result = NULL;
	rc = ldap_search_ext_s(ld, base->val, LDAP_SCOPE_SUBTREE,
	    filt, NULL, 0, NULL, NULL, tvp, 0, &result);
	if (rc == LDAP_SUCCESS && (entry = ldap_first_entry(ld, result))) {
	    bv = ldap_get_values_len(ld, entry, "sudoOption");
	    if (bv != NULL) {
		if (lbuf->len == 0 || isspace((unsigned char)lbuf->buf[lbuf->len - 1]))
		    prefix = "    ";
		else
		    prefix = ", ";
		for (p = bv; *p != NULL; p++) {
		    lbuf_append(lbuf, "%s%s", prefix, (*p)->bv_val);
		    prefix = ", ";
		    count++;
		}
		ldap_value_free_len(bv);
	    }
	}
	if (result)
	    ldap_msgfree(result);
    }
    efree(filt);
done:
    debug_return_int(count);
}

/*
 * STUB
 */
static int
sudo_ldap_display_bound_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf)
{
    debug_decl(sudo_ldap_display_bound_defaults, SUDO_DEBUG_LDAP)
    debug_return_int(0);
}

/*
 * Print a record in the short form, ala file sudoers.
 */
static int
sudo_ldap_display_entry_short(LDAP *ld, LDAPMessage *entry, struct lbuf *lbuf)
{
    struct berval **bv, **p;
    int count = 0;
    debug_decl(sudo_ldap_display_entry_short, SUDO_DEBUG_LDAP)

    lbuf_append(lbuf, "    (");

    /* get the RunAsUser Values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoRunAsUser");
    if (bv == NULL)
	bv = ldap_get_values_len(ld, entry, "sudoRunAs");
    if (bv != NULL) {
	for (p = bv; *p != NULL; p++) {
	    lbuf_append(lbuf, "%s%s", p != bv ? ", " : "", (*p)->bv_val);
	}
	ldap_value_free_len(bv);
    } else
	lbuf_append(lbuf, "%s", def_runas_default);

    /* get the RunAsGroup Values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoRunAsGroup");
    if (bv != NULL) {
	lbuf_append(lbuf, " : ");
	for (p = bv; *p != NULL; p++) {
	    lbuf_append(lbuf, "%s%s", p != bv ? ", " : "", (*p)->bv_val);
	}
	ldap_value_free_len(bv);
    }
    lbuf_append(lbuf, ") ");

    /* get the Option Values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoOption");
    if (bv != NULL) {
	for (p = bv; *p != NULL; p++) {
	    char *cp = (*p)->bv_val;
	    if (*cp == '!')
		cp++;
	    if (strcmp(cp, "authenticate") == 0)
		lbuf_append(lbuf, (*p)->bv_val[0] == '!' ?
		    "NOPASSWD: " : "PASSWD: ");
	    else if (strcmp(cp, "noexec") == 0)
		lbuf_append(lbuf, (*p)->bv_val[0] == '!' ?
		    "EXEC: " : "NOEXEC: ");
	    else if (strcmp(cp, "setenv") == 0)
		lbuf_append(lbuf, (*p)->bv_val[0] == '!' ?
		    "NOSETENV: " : "SETENV: ");
	}
	ldap_value_free_len(bv);
    }

    /* get the Command Values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoCommand");
    if (bv != NULL) {
	for (p = bv; *p != NULL; p++) {
	    lbuf_append(lbuf, "%s%s", p != bv ? ", " : "", (*p)->bv_val);
	    count++;
	}
	ldap_value_free_len(bv);
    }
    lbuf_append(lbuf, "\n");

    debug_return_int(count);
}

/*
 * Print a record in the long form.
 */
static int
sudo_ldap_display_entry_long(LDAP *ld, LDAPMessage *entry, struct lbuf *lbuf)
{
    struct berval **bv, **p;
    char *rdn;
    int count = 0;
    debug_decl(sudo_ldap_display_entry_long, SUDO_DEBUG_LDAP)

    /* extract the dn, only show the first rdn */
    rdn = sudo_ldap_get_first_rdn(ld, entry);
    if (rdn != NULL)
	lbuf_append(lbuf, _("\nLDAP Role: %s\n"), rdn);
    else
	lbuf_append(lbuf, _("\nLDAP Role: UNKNOWN\n"));
    if (rdn)
	ldap_memfree(rdn);

    /* get the RunAsUser Values from the entry */
    lbuf_append(lbuf, "    RunAsUsers: ");
    bv = ldap_get_values_len(ld, entry, "sudoRunAsUser");
    if (bv == NULL)
	bv = ldap_get_values_len(ld, entry, "sudoRunAs");
    if (bv != NULL) {
	for (p = bv; *p != NULL; p++) {
	    lbuf_append(lbuf, "%s%s", p != bv ? ", " : "", (*p)->bv_val);
	}
	ldap_value_free_len(bv);
    } else
	lbuf_append(lbuf, "%s", def_runas_default);
    lbuf_append(lbuf, "\n");

    /* get the RunAsGroup Values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoRunAsGroup");
    if (bv != NULL) {
	lbuf_append(lbuf, "    RunAsGroups: ");
	for (p = bv; *p != NULL; p++) {
	    lbuf_append(lbuf, "%s%s", p != bv ? ", " : "", (*p)->bv_val);
	}
	ldap_value_free_len(bv);
	lbuf_append(lbuf, "\n");
    }

    /* get the Option Values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoOption");
    if (bv != NULL) {
	lbuf_append(lbuf, "    Options: ");
	for (p = bv; *p != NULL; p++) {
	    lbuf_append(lbuf, "%s%s", p != bv ? ", " : "", (*p)->bv_val);
	}
	ldap_value_free_len(bv);
	lbuf_append(lbuf, "\n");
    }

    /*
     * Display order attribute if present.  This attribute is single valued,
     * so there is no need for a loop.
     */
    bv = ldap_get_values_len(ld, entry, "sudoOrder");
    if (bv != NULL) {
	if (*bv != NULL) {
	    lbuf_append(lbuf, _("    Order: %s\n"), (*bv)->bv_val);
	}
	ldap_value_free_len(bv);
    }

    /* Get the command values from the entry. */
    bv = ldap_get_values_len(ld, entry, "sudoCommand");
    if (bv != NULL) {
	lbuf_append(lbuf, _("    Commands:\n"));
	for (p = bv; *p != NULL; p++) {
	    lbuf_append(lbuf, "\t%s\n", (*p)->bv_val);
	    count++;
	}
	ldap_value_free_len(bv);
    }

    debug_return_int(count);
}

/*
 * Like sudo_ldap_lookup(), except we just print entries.
 */
static int
sudo_ldap_display_privs(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf)
{
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    struct ldap_result *lres;
    LDAPMessage *entry;
    int i, count = 0;
    debug_decl(sudo_ldap_display_privs, SUDO_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	goto done;
    ld = handle->ld;

    DPRINTF1("ldap search for command list");
    lres = sudo_ldap_result_get(nss, pw);

    /* Display all matching entries. */
    for (i = 0; i < lres->nentries; i++) {
	entry = lres->entries[i].entry;
	if (long_list)
	    count += sudo_ldap_display_entry_long(ld, entry, lbuf);
	else
	    count += sudo_ldap_display_entry_short(ld, entry, lbuf);
    }

done:
    debug_return_int(count);
}

static int
sudo_ldap_display_cmnd(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    struct ldap_result *lres;
    LDAPMessage *entry;
    bool found = false;
    int i;
    debug_decl(sudo_ldap_display_cmnd, SUDO_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	goto done;
    ld = handle->ld;

    /*
     * The sudo_ldap_result_get() function returns all nodes that match
     * the user and the host.
     */
    DPRINTF1("ldap search for command list");
    lres = sudo_ldap_result_get(nss, pw);
    for (i = 0; i < lres->nentries; i++) {
	entry = lres->entries[i].entry;
	if (sudo_ldap_check_command(ld, entry, NULL) &&
	    sudo_ldap_check_runas(ld, entry)) {
	    found = true;
	    goto done;
	}
    }

done:
    if (found)
	printf("%s%s%s\n", safe_cmnd ? safe_cmnd : user_cmnd,
	    user_args ? " " : "", user_args ? user_args : "");
   debug_return_bool(!found);
}

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
static unsigned int (*sudo_gss_krb5_ccache_name)(unsigned int *minor_status, const char *name, const char **old_name);

static int
sudo_set_krb5_ccache_name(const char *name, const char **old_name)
{
    int rc = 0;
    unsigned int junk;
    static bool initialized;
    debug_decl(sudo_set_krb5_ccache_name, SUDO_DEBUG_LDAP)

    if (!initialized) {
	sudo_gss_krb5_ccache_name =
	    sudo_dso_findsym(SUDO_DSO_DEFAULT, "gss_krb5_ccache_name");
	initialized = true;
    }

    /*
     * Try to use gss_krb5_ccache_name() if possible.
     * We also need to set KRB5CCNAME since some LDAP libs may not use
     * gss_krb5_ccache_name().
     */
    if (sudo_gss_krb5_ccache_name != NULL) {
	rc = sudo_gss_krb5_ccache_name(&junk, name, old_name);
    } else {
	/* No gss_krb5_ccache_name(), fall back on KRB5CCNAME. */
	if (old_name != NULL)
	    *old_name = sudo_getenv("KRB5CCNAME");
    }
    if (name != NULL && *name != '\0')
	sudo_setenv("KRB5CCNAME", name, true);
    else
	sudo_unsetenv("KRB5CCNAME");

    debug_return_int(rc);
}

/*
 * Make a copy of the credential cache file specified by KRB5CCNAME
 * which must be readable by the user.  The resulting cache file
 * is root-owned and will be removed after authenticating via SASL.
 */
static char *
sudo_krb5_copy_cc_file(const char *old_ccname)
{
    int ofd, nfd;
    ssize_t nread, nwritten = -1;
    static char new_ccname[sizeof(_PATH_TMP) + sizeof("sudocc_XXXXXXXX") - 1];
    char buf[10240], *ret = NULL;
    debug_decl(sudo_krb5_copy_cc_file, SUDO_DEBUG_LDAP)

    old_ccname = sudo_krb5_ccname_path(old_ccname);
    if (old_ccname != NULL) {
	/* Open credential cache as user to prevent stolen creds. */
	set_perms(PERM_USER);
	ofd = open(old_ccname, O_RDONLY|O_NONBLOCK);
	restore_perms();

	if (ofd != -1) {
	    (void) fcntl(ofd, F_SETFL, 0);
	    if (lock_file(ofd, SUDO_LOCK)) {
		snprintf(new_ccname, sizeof(new_ccname), "%s%s",
		    _PATH_TMP, "sudocc_XXXXXXXX");
		nfd = mkstemp(new_ccname);
		if (nfd != -1) {
		    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
			"copy ccache %s -> %s", old_ccname, new_ccname);
		    while ((nread = read(ofd, buf, sizeof(buf))) > 0) {
			ssize_t off = 0;
			do {
			    nwritten = write(nfd, buf + off, nread - off);
			    if (nwritten == -1) {
				warning("error writing to %s", new_ccname);
				goto write_error;
			    }
			    off += nwritten;
			} while (off < nread);
		    }
		    if (nread == -1)
			warning("unable to read %s", new_ccname);
write_error:
		    close(nfd);
		    if (nread != -1 && nwritten != -1) {
			ret = new_ccname;	/* success! */
		    } else {
			unlink(new_ccname);	/* failed */
		    }
		} else {
		    warning("unable to create temp file %s", new_ccname);
		}
	    }
	    close(ofd);
	} else {
	    sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO,
		"unable to open %s", old_ccname);
	}
    }
    debug_return_str(ret);
}

static int
sudo_ldap_sasl_interact(LDAP *ld, unsigned int flags, void *_auth_id,
    void *_interact)
{
    char *auth_id = (char *)_auth_id;
    sasl_interact_t *interact = (sasl_interact_t *)_interact;
    int rc = LDAP_SUCCESS;
    debug_decl(sudo_ldap_sasl_interact, SUDO_DEBUG_LDAP)

    for (; interact->id != SASL_CB_LIST_END; interact++) {
	if (interact->id != SASL_CB_USER) {
	    warningx("sudo_ldap_sasl_interact: unexpected interact id %lu",
		interact->id);
	    rc = LDAP_PARAM_ERROR;
	    break;
	}

	if (auth_id != NULL)
	    interact->result = auth_id;
	else if (interact->defresult != NULL)
	    interact->result = interact->defresult;
	else
	    interact->result = "";

	interact->len = strlen(interact->result);
#if SASL_VERSION_MAJOR < 2
	interact->result = strdup(interact->result);
	if (interact->result == NULL) {
	    rc = LDAP_NO_MEMORY;
	    break;
	}
#endif /* SASL_VERSION_MAJOR < 2 */
	DPRINTF2("sudo_ldap_sasl_interact: SASL_CB_USER %s",
	    (const char *)interact->result);
    }
    debug_return_int(rc);
}
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */

/*
 * Set LDAP options from the specified options table
 * Returns LDAP_SUCCESS on success, else non-zero.
 */
static int
sudo_ldap_set_options_table(LDAP *ld, struct ldap_config_table *table)
{
    struct ldap_config_table *cur;
    int ival, rc, errors = 0;
    char *sval;
    debug_decl(sudo_ldap_set_options_table, SUDO_DEBUG_LDAP)

    for (cur = table; cur->conf_str != NULL; cur++) {
	if (cur->opt_val == -1)
	    continue;

	switch (cur->type) {
	case CONF_BOOL:
	case CONF_INT:
	    ival = *(int *)(cur->valp);
	    if (ival >= 0) {
		DPRINTF1("ldap_set_option: %s -> %d", cur->conf_str, ival);
		rc = ldap_set_option(ld, cur->opt_val, &ival);
		if (rc != LDAP_OPT_SUCCESS) {
		    warningx("ldap_set_option: %s -> %d: %s",
			cur->conf_str, ival, ldap_err2string(rc));
		    errors++;
		}
	    }
	    break;
	case CONF_STR:
	    sval = *(char **)(cur->valp);
	    if (sval != NULL) {
		DPRINTF1("ldap_set_option: %s -> %s", cur->conf_str, sval);
		rc = ldap_set_option(ld, cur->opt_val, sval);
		if (rc != LDAP_OPT_SUCCESS) {
		    warningx("ldap_set_option: %s -> %s: %s",
			cur->conf_str, sval, ldap_err2string(rc));
		    errors++;
		}
	    }
	    break;
	}
    }
    debug_return_int(errors ? -1 : LDAP_SUCCESS);
}

/*
 * Set LDAP options based on the global config table.
 * Returns LDAP_SUCCESS on success, else non-zero.
 */
static int
sudo_ldap_set_options_global(void)
{
    int rc;
    debug_decl(sudo_ldap_set_options_global, SUDO_DEBUG_LDAP)

    /* Set ber options */
#ifdef LBER_OPT_DEBUG_LEVEL
    if (ldap_conf.ldap_debug)
	ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &ldap_conf.ldap_debug);
#endif

    /* Parse global LDAP options table. */
    rc = sudo_ldap_set_options_table(NULL, ldap_conf_global);
    debug_return_int(rc);
}

/*
 * Set LDAP options based on the per-connection config table.
 * Returns LDAP_SUCCESS on success, else non-zero.
 */
static int
sudo_ldap_set_options_conn(LDAP *ld)
{
    int rc;
    debug_decl(sudo_ldap_set_options_conn, SUDO_DEBUG_LDAP)

    /* Parse per-connection LDAP options table. */
    rc = sudo_ldap_set_options_table(ld, ldap_conf_conn);
    if (rc == -1)
	debug_return_int(-1);

#ifdef LDAP_OPT_TIMEOUT
    /* Convert timeout to a timeval */
    if (ldap_conf.timeout > 0) {
	struct timeval tv;
	tv.tv_sec = ldap_conf.timeout;
	tv.tv_usec = 0;
	DPRINTF1("ldap_set_option(LDAP_OPT_TIMEOUT, %d)", ldap_conf.timeout);
	rc = ldap_set_option(ld, LDAP_OPT_TIMEOUT, &tv);
	if (rc != LDAP_OPT_SUCCESS) {
	    warningx("ldap_set_option(TIMEOUT, %d): %s",
		ldap_conf.timeout, ldap_err2string(rc));
	}
    }
#endif
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    /* Convert bind_timelimit to a timeval */
    if (ldap_conf.bind_timelimit > 0) {
	struct timeval tv;
	tv.tv_sec = ldap_conf.bind_timelimit / 1000;
	tv.tv_usec = 0;
	DPRINTF1("ldap_set_option(LDAP_OPT_NETWORK_TIMEOUT, %d)",
	    ldap_conf.bind_timelimit / 1000);
	rc = ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
# if !defined(LDAP_OPT_CONNECT_TIMEOUT) || LDAP_VENDOR_VERSION != 510
	/* Tivoli Directory Server 6.3 libs always return a (bogus) error. */
	if (rc != LDAP_OPT_SUCCESS) {
	    warningx("ldap_set_option(NETWORK_TIMEOUT, %d): %s",
		ldap_conf.bind_timelimit / 1000, ldap_err2string(rc));
	}
# endif
    }
#endif

#if defined(LDAP_OPT_X_TLS) && !defined(HAVE_LDAPSSL_INIT)
    if (ldap_conf.ssl_mode == SUDO_LDAP_SSL) {
	int val = LDAP_OPT_X_TLS_HARD;
	DPRINTF1("ldap_set_option(LDAP_OPT_X_TLS, LDAP_OPT_X_TLS_HARD)");
	rc = ldap_set_option(ld, LDAP_OPT_X_TLS, &val);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_set_option(LDAP_OPT_X_TLS, LDAP_OPT_X_TLS_HARD): %s",
		ldap_err2string(rc));
	    debug_return_int(-1);
	}
    }
#endif
    debug_return_int(LDAP_SUCCESS);
}

/*
 * Create a new sudo_ldap_result structure.
 */
static struct ldap_result *
sudo_ldap_result_alloc(void)
{
    struct ldap_result *result;
    debug_decl(sudo_ldap_result_alloc, SUDO_DEBUG_LDAP)

    result = ecalloc(1, sizeof(*result));
    STAILQ_INIT(&result->searches);

    debug_return_ptr(result);
}

/*
 * Free the ldap result structure
 */
static void
sudo_ldap_result_free(struct ldap_result *lres)
{
    struct ldap_search_result *s;
    debug_decl(sudo_ldap_result_free, SUDO_DEBUG_LDAP)

    if (lres != NULL) {
	if (lres->nentries) {
	    efree(lres->entries);
	    lres->entries = NULL;
	}
	while ((s = STAILQ_FIRST(&lres->searches)) != NULL) {
	    STAILQ_REMOVE_HEAD(&lres->searches, entries);
	    ldap_msgfree(s->searchresult);
	    efree(s);
	}
	efree(lres);
    }
    debug_return;
}

/*
 * Add a search result to the ldap_result structure.
 */
static struct ldap_search_result *
sudo_ldap_result_add_search(struct ldap_result *lres, LDAP *ldap,
    LDAPMessage *searchresult)
{
    struct ldap_search_result *news;
    debug_decl(sudo_ldap_result_add_search, SUDO_DEBUG_LDAP)

    /* Create new entry and add it to the end of the chain. */
    news = ecalloc(1, sizeof(*news));
    news->ldap = ldap;
    news->searchresult = searchresult;
    STAILQ_INSERT_TAIL(&lres->searches, news, entries);

    debug_return_ptr(news);
}

/*
 * Connect to the LDAP server specified by ld.
 * Returns LDAP_SUCCESS on success, else non-zero.
 */
static int
sudo_ldap_bind_s(LDAP *ld)
{
    int rc;
    debug_decl(sudo_ldap_bind_s, SUDO_DEBUG_LDAP)

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    if (ldap_conf.rootuse_sasl == true ||
	(ldap_conf.rootuse_sasl != false && ldap_conf.use_sasl == true)) {
	const char *old_ccname = NULL;
	const char *new_ccname = ldap_conf.krb5_ccname;
	const char *tmp_ccname = NULL;
	void *auth_id = ldap_conf.rootsasl_auth_id ?
	    ldap_conf.rootsasl_auth_id : ldap_conf.sasl_auth_id;

	/* Make temp copy of the user's credential cache as needed. */
	if (ldap_conf.krb5_ccname == NULL && user_ccname != NULL) {
	    new_ccname = tmp_ccname = sudo_krb5_copy_cc_file(user_ccname);
	    if (tmp_ccname == NULL) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "unable to copy user ccache %s", user_ccname);
	    }
	}

	if (new_ccname != NULL) {
	    rc = sudo_set_krb5_ccache_name(new_ccname, &old_ccname);
	    if (rc == 0) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "set ccache name %s -> %s",
		    old_ccname ? old_ccname : "(none)", new_ccname);
	    } else {
		sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
		    "gss_krb5_ccache_name() failed: %d", rc);
	    }
	}
	rc = ldap_sasl_interactive_bind_s(ld, ldap_conf.binddn, "GSSAPI",
	    NULL, NULL, LDAP_SASL_QUIET, sudo_ldap_sasl_interact, auth_id);
	if (new_ccname != NULL) {
	    rc = sudo_set_krb5_ccache_name(old_ccname, NULL);
	    if (rc == 0) {
		sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		    "restore ccache name %s -> %s", new_ccname, old_ccname);
	    } else {
		sudo_debug_printf(SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO,
		    "gss_krb5_ccache_name() failed: %d", rc);
	    }
	    /* Remove temporary copy of user's credential cache. */
	    if (tmp_ccname != NULL)
		unlink(tmp_ccname);
	}
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_sasl_interactive_bind_s(): %s",
		ldap_err2string(rc));
	    goto done;
	}
	DPRINTF1("ldap_sasl_interactive_bind_s() ok");
    } else
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */
#ifdef HAVE_LDAP_SASL_BIND_S
    {
	struct berval bv;

	bv.bv_val = ldap_conf.bindpw ? ldap_conf.bindpw : "";
	bv.bv_len = strlen(bv.bv_val);

	rc = ldap_sasl_bind_s(ld, ldap_conf.binddn, LDAP_SASL_SIMPLE, &bv,
	    NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_sasl_bind_s(): %s", ldap_err2string(rc));
	    goto done;
	}
	DPRINTF1("ldap_sasl_bind_s() ok");
    }
#else
    {
	rc = ldap_simple_bind_s(ld, ldap_conf.binddn, ldap_conf.bindpw);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_simple_bind_s(): %s", ldap_err2string(rc));
	    goto done;
	}
	DPRINTF1("ldap_simple_bind_s() ok");
    }
#endif
done:
    debug_return_int(rc);
}

/*
 * Open a connection to the LDAP server.
 * Returns 0 on success and non-zero on failure.
 */
static int
sudo_ldap_open(struct sudo_nss *nss)
{
    LDAP *ld;
    int rc = -1;
    sigaction_t sa, saved_sa_pipe;
    bool ldapnoinit = false;
    struct sudo_ldap_handle *handle;
    debug_decl(sudo_ldap_open, SUDO_DEBUG_LDAP)

    /* Ignore SIGPIPE if we cannot bind to the server. */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    (void) sigaction(SIGPIPE, &sa, &saved_sa_pipe);

    if (!sudo_ldap_read_config())
	goto done;

    /* Prevent reading of user ldaprc and system defaults. */
    if (sudo_getenv("LDAPNOINIT") == NULL) {
	ldapnoinit = true;
	sudo_setenv("LDAPNOINIT", "1", true);
    }

    /* Set global LDAP options */
    if (sudo_ldap_set_options_global() != LDAP_SUCCESS)
	goto done;

    /* Connect to LDAP server */
#ifdef HAVE_LDAP_INITIALIZE
    if (!STAILQ_EMPTY(&ldap_conf.uri)) {
	char *buf = sudo_ldap_join_uri(&ldap_conf.uri);
	if (buf != NULL) {
	    DPRINTF2("ldap_initialize(ld, %s)", buf);
	    rc = ldap_initialize(&ld, buf);
	    efree(buf);
	    if (rc != LDAP_SUCCESS) {
		warningx(U_("unable to initialize LDAP: %s"),
		    ldap_err2string(rc));
	    }
	}
    } else
#endif
	rc = sudo_ldap_init(&ld, ldap_conf.host, ldap_conf.port);
    if (rc != LDAP_SUCCESS)
	goto done;

    /* Set LDAP per-connection options */
    rc = sudo_ldap_set_options_conn(ld);
    if (rc != LDAP_SUCCESS)
	goto done;

    if (ldapnoinit)
	sudo_unsetenv("LDAPNOINIT");

    if (ldap_conf.ssl_mode == SUDO_LDAP_STARTTLS) {
#if defined(HAVE_LDAP_START_TLS_S)
	rc = ldap_start_tls_s(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_start_tls_s(): %s", ldap_err2string(rc));
	    goto done;
	}
	DPRINTF1("ldap_start_tls_s() ok");
#elif defined(HAVE_LDAP_SSL_CLIENT_INIT) && defined(HAVE_LDAP_START_TLS_S_NP)
	int sslrc;
	rc = ldap_ssl_client_init(ldap_conf.tls_keyfile, ldap_conf.tls_keypw,
	    0, &sslrc);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_ssl_client_init(): %s (SSL reason code %d)",
		ldap_err2string(rc), sslrc);
	    goto done;
	}
	rc = ldap_start_tls_s_np(ld, NULL);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_start_tls_s_np(): %s", ldap_err2string(rc));
	    goto done;
	}
	DPRINTF1("ldap_start_tls_s_np() ok");
#else
	warningx(U_("start_tls specified but LDAP libs do not support ldap_start_tls_s() or ldap_start_tls_s_np()"));
#endif /* !HAVE_LDAP_START_TLS_S && !HAVE_LDAP_START_TLS_S_NP */
    }

    /* Actually connect */
    rc = sudo_ldap_bind_s(ld);
    if (rc != LDAP_SUCCESS)
	goto done;

    /* Create a handle container. */
    handle = ecalloc(1, sizeof(struct sudo_ldap_handle));
    handle->ld = ld;
    /* handle->result = NULL; */
    /* handle->username = NULL; */
    /* handle->grlist = NULL; */
    nss->handle = handle;

done:
    (void) sigaction(SIGPIPE, &saved_sa_pipe, NULL);
    debug_return_int(rc == LDAP_SUCCESS ? 0 : -1);
}

static int
sudo_ldap_setdefs(struct sudo_nss *nss)
{
    struct ldap_config_str *base;
    struct sudo_ldap_handle *handle = nss->handle;
    struct timeval tv, *tvp = NULL;
    LDAP *ld;
    LDAPMessage *entry, *result;
    char *filt;
    int rc;
    debug_decl(sudo_ldap_setdefs, SUDO_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	debug_return_int(-1);
    ld = handle->ld;

    filt = sudo_ldap_build_default_filter();
    DPRINTF1("Looking for cn=defaults: %s", filt);

    STAILQ_FOREACH(base, &ldap_conf.base, entries) {
	if (ldap_conf.timeout > 0) {
	    tv.tv_sec = ldap_conf.timeout;
	    tv.tv_usec = 0;
	    tvp = &tv;
	}
	result = NULL;
	rc = ldap_search_ext_s(ld, base->val, LDAP_SCOPE_SUBTREE,
	    filt, NULL, 0, NULL, NULL, tvp, 0, &result);
	if (rc == LDAP_SUCCESS && (entry = ldap_first_entry(ld, result))) {
	    DPRINTF1("found:%s", ldap_get_dn(ld, entry));
	    sudo_ldap_parse_options(ld, entry);
	} else {
	    DPRINTF1("no default options found in %s", base->val);
	}
	if (result)
	    ldap_msgfree(result);
    }
    efree(filt);

    debug_return_int(0);
}

/*
 * like sudoers_lookup() - only LDAP style
 */
static int
sudo_ldap_lookup(struct sudo_nss *nss, int ret, int pwflag)
{
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    LDAPMessage *entry;
    int i, rc, setenv_implied;
    struct ldap_result *lres = NULL;
    debug_decl(sudo_ldap_lookup, SUDO_DEBUG_LDAP)

    if (handle == NULL || handle->ld == NULL)
	debug_return_int(ret);
    ld = handle->ld;

    /* Fetch list of sudoRole entries that match user and host. */
    lres = sudo_ldap_result_get(nss, sudo_user.pw);

    /*
     * The following queries are only determine whether or not a
     * password is required, so the order of the entries doesn't matter.
     */
    if (pwflag) {
	int doauth = UNSPEC;
	int matched = UNSPEC;
	enum def_tuple pwcheck = 
	    (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;

	DPRINTF1("perform search for pwflag %d", pwflag);
	for (i = 0; i < lres->nentries; i++) {
	    entry = lres->entries[i].entry;
	    if ((pwcheck == any && doauth != false) ||
		(pwcheck == all && doauth == false)) {
		doauth = sudo_ldap_check_bool(ld, entry, "authenticate");
	    }
	    /* Only check the command when listing another user. */
	    if (user_uid == 0 || list_pw == NULL ||
		user_uid == list_pw->pw_uid ||
		sudo_ldap_check_command(ld, entry, NULL)) {
		matched = true;
		break;
	    }
	}
	if (matched || user_uid == 0) {
	    SET(ret, VALIDATE_OK);
	    CLR(ret, VALIDATE_NOT_OK);
	    if (def_authenticate) {
		switch (pwcheck) {
		    case always:
			SET(ret, FLAG_CHECK_USER);
			break;
		    case all:
		    case any:
			if (doauth == false)
			    def_authenticate = false;
			break;
		    case never:
			def_authenticate = false;
			break;
		    default:
			break;
		}
	    }
	}
	goto done;
    }

    DPRINTF1("searching LDAP for sudoers entries");

    setenv_implied = false;
    for (i = 0; i < lres->nentries; i++) {
	entry = lres->entries[i].entry;
	if (!sudo_ldap_check_runas(ld, entry))
	    continue;
	rc = sudo_ldap_check_command(ld, entry, &setenv_implied);
	if (rc != UNSPEC) {
	    /* We have a match. */
	    DPRINTF1("Command %sallowed", rc == true ? "" : "NOT ");
	    if (rc == true) {
		DPRINTF1("LDAP entry: %p", entry);
		/* Apply entry-specific options. */
		if (setenv_implied)
		    def_setenv = true;
		sudo_ldap_parse_options(ld, entry);
#ifdef HAVE_SELINUX
		/* Set role and type if not specified on command line. */
		if (user_role == NULL)
		    user_role = def_role;
		if (user_type == NULL)
		    user_type = def_type;
#endif /* HAVE_SELINUX */
		SET(ret, VALIDATE_OK);
		CLR(ret, VALIDATE_NOT_OK);
	    } else {
		SET(ret, VALIDATE_NOT_OK);
		CLR(ret, VALIDATE_OK);
	    }
	    break;
	}
    }

done:
    DPRINTF1("done with LDAP searches");
    DPRINTF1("user_matches=%d", lres->user_matches);
    DPRINTF1("host_matches=%d", lres->host_matches);

    if (!ISSET(ret, VALIDATE_OK)) {
	/* No matching entries. */
	if (pwflag && list_pw == NULL)
	    SET(ret, FLAG_NO_CHECK);
    }
    if (lres->user_matches)
	CLR(ret, FLAG_NO_USER);
    if (lres->host_matches)
	CLR(ret, FLAG_NO_HOST);
    DPRINTF1("sudo_ldap_lookup(%d)=0x%02x", pwflag, ret);

    debug_return_int(ret);
}

/*
 * Comparison function for ldap_entry_wrapper structures, descending order.
 */
static int
ldap_entry_compare(const void *a, const void *b)
{
    const struct ldap_entry_wrapper *aw = a;
    const struct ldap_entry_wrapper *bw = b;
    debug_decl(ldap_entry_compare, SUDO_DEBUG_LDAP)

    debug_return_int(bw->order < aw->order ? -1 :
	(bw->order > aw->order ? 1 : 0));
}

/*
 * Return the last entry in the list of searches, usually the
 * one currently being used to add entries.
 */
static struct ldap_search_result *
sudo_ldap_result_last_search(struct ldap_result *lres)
{
    debug_decl(sudo_ldap_result_last_search, SUDO_DEBUG_LDAP)

    debug_return_ptr(STAILQ_LAST(&lres->searches, ldap_search_result, entries));
}

/*
 * Add an entry to the result structure.
 */
static struct ldap_entry_wrapper *
sudo_ldap_result_add_entry(struct ldap_result *lres, LDAPMessage *entry)
{
    struct ldap_search_result *last;
    struct berval **bv;
    double order = 0.0;
    char *ep;
    debug_decl(sudo_ldap_result_add_entry, SUDO_DEBUG_LDAP)

    /* Determine whether the entry has the sudoOrder attribute. */
    last = sudo_ldap_result_last_search(lres);
    bv = ldap_get_values_len(last->ldap, entry, "sudoOrder");
    if (bv != NULL) {
	if (ldap_count_values_len(bv) > 0) {
	    /* Get the value of this attribute, 0 if not present. */
	    DPRINTF2("order attribute raw: %s", (*bv)->bv_val);
	    order = strtod((*bv)->bv_val, &ep);
	    if (ep == (*bv)->bv_val || *ep != '\0') {
		warningx(U_("invalid sudoOrder attribute: %s"), (*bv)->bv_val);
		order = 0.0;
	    }
	    DPRINTF2("order attribute: %f", order);
	}
	ldap_value_free_len(bv);
    }

    /*
     * Enlarge the array of entry wrappers as needed, preallocating blocks
     * of 100 entries to save on allocation time.
     */
    if (++lres->nentries > lres->allocated_entries) {
	lres->allocated_entries += ALLOCATION_INCREMENT;
	lres->entries = erealloc3(lres->entries, lres->allocated_entries,
	    sizeof(lres->entries[0]));
    }

    /* Fill in the new entry and return it. */
    lres->entries[lres->nentries - 1].entry = entry;
    lres->entries[lres->nentries - 1].order = order;

    debug_return_ptr(&lres->entries[lres->nentries - 1]);
}

/*
 * Free the ldap result structure in the sudo_nss handle.
 */
static void
sudo_ldap_result_free_nss(struct sudo_nss *nss)
{
    struct sudo_ldap_handle *handle = nss->handle;
    debug_decl(sudo_ldap_result_free_nss, SUDO_DEBUG_LDAP)

    if (handle->result != NULL) {
	DPRINTF1("removing reusable search result");
	sudo_ldap_result_free(handle->result);
	if (handle->username) {
	    efree(handle->username);
	    handle->username = NULL;
	}
	handle->grlist = NULL;
	handle->result = NULL;
    }
    debug_return;
}

/*
 * Perform the LDAP query for the user or return a cached query if
 * there is one for this user.
 */
static struct ldap_result *
sudo_ldap_result_get(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_ldap_handle *handle = nss->handle;
    struct ldap_config_str *base;
    struct ldap_result *lres;
    struct timeval tv, *tvp = NULL;
    LDAPMessage *entry, *result;
    LDAP *ld = handle->ld;
    int pass, rc;
    char *filt;
    debug_decl(sudo_ldap_result_get, SUDO_DEBUG_LDAP)

    /*
     * If we already have a cached result, return it so we don't have to
     * have to contact the LDAP server again.
     */
    if (handle->result) {
	if (handle->grlist == user_group_list &&
	    strcmp(pw->pw_name, handle->username) == 0) {
	    DPRINTF1("reusing previous result (user %s) with %d entries",
		handle->username, handle->result->nentries);
	    debug_return_ptr(handle->result);
	}
	/* User mismatch, cached result cannot be used. */
	DPRINTF1("removing result (user %s), new search (user %s)",
	    handle->username, pw->pw_name);
	sudo_ldap_result_free_nss(nss);
    }

    /*
     * Okay - time to search for anything that matches this user
     * Lets limit it to only two queries of the LDAP server
     *
     * The first pass will look by the username, groups, and
     * the keyword ALL.  We will then inspect the results that
     * came back from the query.  We don't need to inspect the
     * sudoUser in this pass since the LDAP server already scanned
     * it for us.
     *
     * The second pass will return all the entries that contain non-
     * Unix groups, including netgroups.  Then we take the non-Unix
     * groups returned and try to match them against the username.
     *
     * Since we have to sort the possible entries before we make a
     * decision, we perform the queries and store all of the results in
     * an ldap_result object.  The results are then sorted by sudoOrder.
     */
    lres = sudo_ldap_result_alloc();
    for (pass = 0; pass < 2; pass++) {
	filt = pass ? sudo_ldap_build_pass2() : sudo_ldap_build_pass1(pw);
	if (filt != NULL) {
	    DPRINTF1("ldap search '%s'", filt);
	    STAILQ_FOREACH(base, &ldap_conf.base, entries) {
		DPRINTF1("searching from base '%s'",
		    base->val);
		if (ldap_conf.timeout > 0) {
		    tv.tv_sec = ldap_conf.timeout;
		    tv.tv_usec = 0;
		    tvp = &tv;
		}
		result = NULL;
		rc = ldap_search_ext_s(ld, base->val, LDAP_SCOPE_SUBTREE, filt,
		    NULL, 0, NULL, NULL, tvp, 0, &result);
		if (rc != LDAP_SUCCESS) {
		    DPRINTF1("nothing found for '%s'", filt);
		    continue;
		}
		lres->user_matches = true;

		/* Add the seach result to list of search results. */
		DPRINTF1("adding search result");
		sudo_ldap_result_add_search(lres, ld, result);
		LDAP_FOREACH(entry, ld, result) {
		    if ((!pass ||
			sudo_ldap_check_non_unix_group(ld, entry, pw)) &&
			sudo_ldap_check_host(ld, entry)) {
			lres->host_matches = true;
			sudo_ldap_result_add_entry(lres, entry);
		    }
		}
		DPRINTF1("result now has %d entries", lres->nentries);
	    }
	    efree(filt);
	}
    }

    /* Sort the entries by the sudoOrder attribute. */
    DPRINTF1("sorting remaining %d entries", lres->nentries);
    qsort(lres->entries, lres->nentries, sizeof(lres->entries[0]),
	ldap_entry_compare);

    /* Store everything in the sudo_nss handle. */
    handle->result = lres;
    handle->username = estrdup(pw->pw_name);
    handle->grlist = user_group_list;

    debug_return_ptr(lres);
}

/*
 * Shut down the LDAP connection.
 */
static int
sudo_ldap_close(struct sudo_nss *nss)
{
    struct sudo_ldap_handle *handle = nss->handle;
    debug_decl(sudo_ldap_close, SUDO_DEBUG_LDAP)

    if (handle != NULL) {
	/* Free the result before unbinding; it may use the LDAP connection. */
	sudo_ldap_result_free_nss(nss);

	/* Unbind and close the LDAP connection. */
	if (handle->ld != NULL) {
	    ldap_unbind_ext_s(handle->ld, NULL, NULL);
	    handle->ld = NULL;
	}

	/* Free the handle container. */
	efree(nss->handle);
	nss->handle = NULL;
    }
    debug_return_int(0);
}

/*
 * STUB
 */
static int
sudo_ldap_parse(struct sudo_nss *nss)
{
    return 0;
}

#if 0
/*
 * Create an ldap_result from an LDAP search result.
 *
 * This function is currently not used anywhere, it is left here as
 * an example of how to use the cached searches.
 */
static struct ldap_result *
sudo_ldap_result_from_search(LDAP *ldap, LDAPMessage *searchresult)
{
    /*
     * An ldap_result is built from several search results, which are
     * organized in a list. The head of the list is maintained in the
     * ldap_result structure, together with the wrappers that point
     * to individual entries, this has to be initialized first.
     */
    struct ldap_result *result = sudo_ldap_result_alloc();

    /*
     * Build a new list node for the search result, this creates the
     * list node.
     */
    struct ldap_search_result *last = sudo_ldap_result_add_search(result,
	ldap, searchresult);

    /*
     * Now add each entry in the search result to the array of of entries
     * in the ldap_result object.
     */
    LDAPMessage	*entry;
    LDAP_FOREACH(entry, last->ldap, last->searchresult) {
	sudo_ldap_result_add_entry(result, entry);
    }
    DPRINTF1("sudo_ldap_result_from_search: %d entries found", result->nentries);
    return result;
}
#endif
