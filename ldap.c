/*
 * Copyright (c) 2003-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <sys/param.h>
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
#if TIME_WITH_SYS_TIME
# include <time.h>
#endif
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
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
# if HAVE_GSS_KRB5_CCACHE_NAME
#  if defined(HAVE_GSSAPI_GSSAPI_KRB5_H)
#   include <gssapi/gssapi.h>
#   include <gssapi/gssapi_krb5.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_H)
#   include <gssapi/gssapi.h>
#  else
#   include <gssapi.h>
#  endif
# endif
#endif

#include "sudo.h"
#include "parse.h"
#include "lbuf.h"

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

#define	DPRINTF(args, level)	if (ldap_conf.debug >= level) warningx args

#define CONF_BOOL	0
#define CONF_INT	1
#define CONF_STR	2
#define CONF_LIST_STR	4
#define CONF_DEREF_VAL	5

#define SUDO_LDAP_CLEAR		0
#define SUDO_LDAP_SSL		1
#define SUDO_LDAP_STARTTLS	2

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
 * XXX - should probably be a tailq since we do appends
 */
struct ldap_search_list {
    LDAP *ldap;
    LDAPMessage *searchresult;
    struct ldap_search_list *next;
};

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
    struct ldap_search_list *searches;
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

struct ldap_config_list_str {
    struct ldap_config_list_str *next;
    char val[1];
};

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
    struct ldap_config_list_str *uri;
    char *binddn;
    char *bindpw;
    char *rootbinddn;
    struct ldap_config_list_str *base;
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
static int sudo_ldap_open __P((struct sudo_nss *nss));
static int sudo_ldap_close __P((struct sudo_nss *nss));
static int sudo_ldap_parse __P((struct sudo_nss *nss));
static int sudo_ldap_setdefs __P((struct sudo_nss *nss));
static int sudo_ldap_lookup __P((struct sudo_nss *nss, int ret, int pwflag));
static int sudo_ldap_display_cmnd __P((struct sudo_nss *nss,
    struct passwd *pw));
static int sudo_ldap_display_defaults __P((struct sudo_nss *nss,
    struct passwd *pw, struct lbuf *lbuf));
static int sudo_ldap_display_bound_defaults __P((struct sudo_nss *nss,
    struct passwd *pw, struct lbuf *lbuf));
static int sudo_ldap_display_privs __P((struct sudo_nss *nss,
    struct passwd *pw, struct lbuf *lbuf));
static struct ldap_result *sudo_ldap_result_get __P((struct sudo_nss *nss,
    struct passwd *pw));

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
    GETGROUPS_T *groups;
};

struct sudo_nss sudo_nss_ldap = {
    &sudo_nss_ldap,
    NULL,
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
sudo_ldap_conf_add_ports()
{

    char *host, *port, defport[13];
    char hostbuf[LINE_MAX * 2];

    hostbuf[0] = '\0';
    if (snprintf(defport, sizeof(defport), ":%d", ldap_conf.port) >= sizeof(defport))
	errorx(1, "sudo_ldap_conf_add_ports: port too large");

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
    return;

toobig:
    errorx(1, "sudo_ldap_conf_add_ports: out of space expanding hostbuf");
}
#endif

#ifndef HAVE_LDAP_INITIALIZE
/*
 * For each uri, convert to host:port pairs.  For ldaps:// enable SSL
 * Accepts: uris of the form ldap:/// or ldap://hostname:portnum/
 * where the trailing slash is optional.
 */
static int
sudo_ldap_parse_uri(uri_list)
    const struct ldap_config_list_str *uri_list;
{
    char *buf, *uri, *host, *cp, *port;
    char hostbuf[LINE_MAX];
    int nldap = 0, nldaps = 0;
    int rc = -1;

    do {
	buf = estrdup(uri_list->val);
	hostbuf[0] = '\0';
	for ((uri = strtok(buf, " \t")); uri != NULL; (uri = strtok(NULL, " \t"))) {
	    if (strncasecmp(uri, "ldap://", 7) == 0) {
		nldap++;
		host = uri + 7;
	    } else if (strncasecmp(uri, "ldaps://", 8) == 0) {
		nldaps++;
		host = uri + 8;
	    } else {
		warningx("unsupported LDAP uri type: %s", uri);
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
	if (hostbuf[0] == '\0') {
	    warningx("invalid uri: %s", uri_list->val);
	    goto done;
	}

	if (nldaps != 0) {
	    if (nldap != 0) {
		warningx("cannot mix ldap and ldaps URIs");
		goto done;
	    }
	    if (ldap_conf.ssl_mode == SUDO_LDAP_STARTTLS) {
		warningx("cannot mix ldaps and starttls");
		goto done;
	    }
	    ldap_conf.ssl_mode = SUDO_LDAP_SSL;
	}

	efree(ldap_conf.host);
	ldap_conf.host = estrdup(hostbuf);
	efree(buf);
    } while ((uri_list = uri_list->next));

    buf = NULL;
    rc = 0;

done:
    efree(buf);
    return rc;

toobig:
    errorx(1, "sudo_ldap_parse_uri: out of space building hostbuf");
}
#else
static char *
sudo_ldap_join_uri(uri_list)
    struct ldap_config_list_str *uri_list;
{
    struct ldap_config_list_str *uri;
    size_t len = 0;
    char *buf, *cp;

    /* Usually just a single entry. */
    if (uri_list->next == NULL)
	return estrdup(uri_list->val);

    for (uri = uri_list; uri != NULL; uri = uri->next) {
	len += strlen(uri->val) + 1;
    }
    buf = cp = emalloc(len);
    buf[0] = '\0';
    for (uri = uri_list; uri != NULL; uri = uri->next) {
	cp += strlcpy(cp, uri->val, len - (cp - buf));
	*cp++ = ' ';
    }
    cp[-1] = '\0';
    return buf;
}
#endif /* HAVE_LDAP_INITIALIZE */

static int
sudo_ldap_init(ldp, host, port)
    LDAP **ldp;
    const char *host;
    int port;
{
    LDAP *ld = NULL;
    int rc = LDAP_CONNECT_ERROR;

#ifdef HAVE_LDAPSSL_INIT
    if (ldap_conf.ssl_mode != SUDO_LDAP_CLEAR) {
	const int defsecure = ldap_conf.ssl_mode == SUDO_LDAP_SSL;
	DPRINTF(("ldapssl_clientauth_init(%s, %s)",
	    ldap_conf.tls_certfile ? ldap_conf.tls_certfile : "NULL",
	    ldap_conf.tls_keyfile ? ldap_conf.tls_keyfile : "NULL"), 2);
	rc = ldapssl_clientauth_init(ldap_conf.tls_certfile, NULL,
	    ldap_conf.tls_keyfile != NULL, ldap_conf.tls_keyfile, NULL);
	/*
	 * Starting with version 5.0, Mozilla-derived LDAP SDKs require
	 * the cert and key paths to be a directory, not a file.
	 * If the user specified a file and it fails, try the parent dir.
	 */
	if (rc != LDAP_SUCCESS) {
	    int retry = FALSE;
	    if (ldap_conf.tls_certfile != NULL) {
		char *cp = strrchr(ldap_conf.tls_certfile, '/');
		if (cp != NULL && strncmp(cp + 1, "cert", 4) == 0) {
		    *cp = '\0';
		    retry = TRUE;
		}
	    }
	    if (ldap_conf.tls_keyfile != NULL) {
		char *cp = strrchr(ldap_conf.tls_keyfile, '/');
		if (cp != NULL && strncmp(cp + 1, "key", 3) == 0) {
		    *cp = '\0';
		    retry = TRUE;
		}
	    }
	    if (retry) {
		DPRINTF(("ldapssl_clientauth_init(%s, %s)",
		    ldap_conf.tls_certfile ? ldap_conf.tls_certfile : "NULL",
		    ldap_conf.tls_keyfile ? ldap_conf.tls_keyfile : "NULL"), 2);
		rc = ldapssl_clientauth_init(ldap_conf.tls_certfile, NULL,
		    ldap_conf.tls_keyfile != NULL, ldap_conf.tls_keyfile, NULL);
	    }
	}
	if (rc != LDAP_SUCCESS) {
	    warningx("unable to initialize SSL cert and key db: %s",
		ldapssl_err2string(rc));
	    if (ldap_conf.tls_certfile == NULL)
		warningx("you must set TLS_CERT in %s to use SSL",
		    _PATH_LDAP_CONF);
	    goto done;
	}

	DPRINTF(("ldapssl_init(%s, %d, %d)", host, port, defsecure), 2);
	if ((ld = ldapssl_init(host, port, defsecure)) != NULL)
	    rc = LDAP_SUCCESS;
    } else
#elif defined(HAVE_LDAP_SSL_INIT) && defined(HAVE_LDAP_SSL_CLIENT_INIT)
    if (ldap_conf.ssl_mode == SUDO_LDAP_SSL) {
	if (ldap_ssl_client_init(ldap_conf.tls_keyfile, ldap_conf.tls_keypw, 0, &rc) != LDAP_SUCCESS) {
	    warningx("ldap_ssl_client_init(): %s", ldap_err2string(rc));
	    debug_return_int(-1);
	}
	DPRINTF(("ldap_ssl_init(%s, %d, NULL)", host, port), 2);
	if ((ld = ldap_ssl_init((char *)host, port, NULL)) != NULL)
	    rc = LDAP_SUCCESS;
    } else
#endif
    {
#ifdef HAVE_LDAP_CREATE
	DPRINTF(("ldap_create()"), 2);
	if ((rc = ldap_create(&ld)) != LDAP_SUCCESS)
	    goto done;
	DPRINTF(("ldap_set_option(LDAP_OPT_HOST_NAME, %s)", host), 2);
	rc = ldap_set_option(ld, LDAP_OPT_HOST_NAME, host);
#else
	DPRINTF(("ldap_init(%s, %d)", host, port), 2);
	if ((ld = ldap_init((char *)host, port)) != NULL)
	    rc = LDAP_SUCCESS;
#endif
    }

done:
    *ldp = ld;
    return rc;
}

/*
 * Walk through search results and return TRUE if we have a matching
 * netgroup, else FALSE.
 */
static int
sudo_ldap_check_user_netgroup(ld, entry, user)
    LDAP *ld;
    LDAPMessage *entry;
    char *user;
{
    struct berval **bv, **p;
    char *val;
    int ret = FALSE;

    if (!entry)
	return ret;

    /* get the values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoUser");
    if (bv == NULL)
	return ret;

    /* walk through values */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	/* match any */
	if (netgr_matches(val, NULL, NULL, user))
	    ret = TRUE;
	DPRINTF(("ldap sudoUser netgroup '%s' ... %s", val,
	    ret ? "MATCH!" : "not"), 2 + ((ret) ? 0 : 1));
    }

    ldap_value_free_len(bv);	/* cleanup */

    return ret;
}

/*
 * Walk through search results and return TRUE if we have a
 * host match, else FALSE.
 */
static int
sudo_ldap_check_host(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    struct berval **bv, **p;
    char *val;
    int ret = FALSE;

    if (!entry)
	return ret;

    /* get the values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoHost");
    if (bv == NULL)
	return ret;

    /* walk through values */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	/* match any or address or netgroup or hostname */
	if (!strcmp(val, "ALL") || addr_matches(val) ||
	    netgr_matches(val, user_host, user_shost, NULL) ||
	    hostname_matches(user_shost, user_host, val))
	    ret = TRUE;
	DPRINTF(("ldap sudoHost '%s' ... %s", val,
	    ret ? "MATCH!" : "not"), 2);
    }

    ldap_value_free_len(bv);	/* cleanup */

    return ret;
}

static int
sudo_ldap_check_runas_user(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    struct berval **bv, **p;
    char *val;
    int ret = FALSE;

    if (!runas_pw)
	return UNSPEC;

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
	return !strcasecmp(runas_pw->pw_name, def_runas_default);

    /* walk through values returned, looking for a match */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	switch (val[0]) {
	case '+':
	    if (netgr_matches(val, NULL, NULL, runas_pw->pw_name))
		ret = TRUE;
	    break;
	case '%':
	    if (usergr_matches(val, runas_pw->pw_name, runas_pw))
		ret = TRUE;
	    break;
	case 'A':
	    if (strcmp(val, "ALL") == 0) {
		ret = TRUE;
		break;
	    }
	    /* FALLTHROUGH */
	default:
	    if (strcasecmp(val, runas_pw->pw_name) == 0)
		ret = TRUE;
	    break;
	}
	DPRINTF(("ldap sudoRunAsUser '%s' ... %s", val,
	    ret ? "MATCH!" : "not"), 2);
    }

    ldap_value_free_len(bv);	/* cleanup */

    return ret;
}

static int
sudo_ldap_check_runas_group(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    struct berval **bv, **p;
    char *val;
    int ret = FALSE;

    /* runas_gr is only set if the user specified the -g flag */
    if (!runas_gr)
	return UNSPEC;

    /* get the values from the entry */
    bv = ldap_get_values_len(ld, entry, "sudoRunAsGroup");
    if (bv == NULL)
	return ret;

    /* walk through values returned, looking for a match */
    for (p = bv; *p != NULL && !ret; p++) {
	val = (*p)->bv_val;
	if (strcmp(val, "ALL") == 0 || group_matches(val, runas_gr))
	    ret = TRUE;
	DPRINTF(("ldap sudoRunAsGroup '%s' ... %s", val,
	    ret ? "MATCH!" : "not"), 2);
    }

    ldap_value_free_len(bv);	/* cleanup */

    return ret;
}

/*
 * Walk through search results and return TRUE if we have a runas match,
 * else FALSE.  RunAs info is optional.
 */
static int
sudo_ldap_check_runas(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    int ret;

    if (!entry)
	return FALSE;

    ret = sudo_ldap_check_runas_user(ld, entry) != FALSE &&
	sudo_ldap_check_runas_group(ld, entry) != FALSE;

    return ret;
}

/*
 * Walk through search results and return TRUE if we have a command match,
 * FALSE if disallowed and UNSPEC if not matched.
 */
static int
sudo_ldap_check_command(ld, entry, setenv_implied)
    LDAP *ld;
    LDAPMessage *entry;
    int *setenv_implied;
{
    struct berval **bv, **p;
    char *allowed_cmnd, *allowed_args, *val;
    int foundbang, ret = UNSPEC;

    if (!entry)
	return ret;

    bv = ldap_get_values_len(ld, entry, "sudoCommand");
    if (bv == NULL)
	return ret;

    for (p = bv; *p != NULL && ret != FALSE; p++) {
	val = (*p)->bv_val;
	/* Match against ALL ? */
	if (!strcmp(val, "ALL")) {
	    ret = TRUE;
	    if (setenv_implied != NULL)
		*setenv_implied = TRUE;
	    DPRINTF(("ldap sudoCommand '%s' ... MATCH!", val), 2);
	    continue;
	}

	/* check for !command */
	if (*val == '!') {
	    foundbang = TRUE;
	    allowed_cmnd = estrdup(1 + val);	/* !command */
	} else {
	    foundbang = FALSE;
	    allowed_cmnd = estrdup(val);	/* command */
	}

	/* split optional args away from command */
	allowed_args = strchr(allowed_cmnd, ' ');
	if (allowed_args)
	    *allowed_args++ = '\0';

	/* check the command like normal */
	if (command_matches(allowed_cmnd, allowed_args)) {
	    /*
	     * If allowed (no bang) set ret but keep on checking.
	     * If disallowed (bang), exit loop.
	     */
	    ret = foundbang ? FALSE : TRUE;
	}
	DPRINTF(("ldap sudoCommand '%s' ... %s", val,
	    ret == TRUE ? "MATCH!" : "not"), 2);

	efree(allowed_cmnd);	/* cleanup */
    }

    ldap_value_free_len(bv);	/* more cleanup */

    return ret;
}

/*
 * Search for boolean "option" in sudoOption.
 * Returns TRUE if found and allowed, FALSE if negated, else UNSPEC.
 */
static int
sudo_ldap_check_bool(ld, entry, option)
    LDAP *ld;
    LDAPMessage *entry;
    char *option;
{
    struct berval **bv, **p;
    char ch, *var;
    int ret = UNSPEC;

    if (entry == NULL)
	return UNSPEC;

    bv = ldap_get_values_len(ld, entry, "sudoOption");
    if (bv == NULL)
	return ret;

    /* walk through options */
    for (p = bv; *p != NULL; p++) {
	var = (*p)->bv_val;;
	DPRINTF(("ldap sudoOption: '%s'", var), 2);

	if ((ch = *var) == '!')
	    var++;
	if (strcmp(var, option) == 0)
	    ret = (ch != '!');
    }

    ldap_value_free_len(bv);

    return ret;
}

/*
 * Read sudoOption and modify the defaults as we go.  This is used once
 * from the cn=defaults entry and also once when a final sudoRole is matched.
 */
static void
sudo_ldap_parse_options(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    struct berval **bv, **p;
    char op, *var, *val;

    if (entry == NULL)
	return;

    bv = ldap_get_values_len(ld, entry, "sudoOption");
    if (bv == NULL)
	return;

    /* walk through options */
    for (p = bv; *p != NULL; p++) {
	var = estrdup((*p)->bv_val);
	DPRINTF(("ldap sudoOption: '%s'", var), 2);

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
		set_default(var, val, TRUE);
	    }
	} else if (*var == '!') {
	    /* case !var Boolean False */
	    set_default(var + 1, NULL, FALSE);
	} else {
	    /* case var Boolean True */
	    set_default(var, NULL, TRUE);
	}
	efree(var);
    }

    ldap_value_free_len(bv);
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
sudo_ldap_timefilter(buffer, buffersize)
    char *buffer;
    size_t buffersize;
{
    struct tm *tp;
    time_t now;
    char timebuffer[sizeof("20120727121554.0Z")];
    int bytes = 0;

    /* Make sure we have a formatted timestamp for __now__. */
    time(&now);
    if ((tp = gmtime(&now)) == NULL) {
	warning("unable to get GMT");
	goto done;
    }

    /* Format the timestamp according to the RFC. */
    if (strftime(timebuffer, sizeof(timebuffer), "%Y%m%d%H%M%S.0Z", tp) == 0) {
	warningx("unable to format timestamp");
	goto done;
    }

    /* Build filter. */
    bytes = snprintf(buffer, buffersize, "(&(|(!(sudoNotAfter=*))(sudoNotAfter>=%s))(|(!(sudoNotBefore=*))(sudoNotBefore<=%s)))",
	timebuffer, timebuffer);
    if (bytes < 0 || bytes >= buffersize) {
	warning("unable to build time filter");
	bytes = 0;
    }

done:
    return bytes;
}

/*
 * Builds up a filter to search for default settings
 */
static char *
sudo_ldap_build_default_filter()
{
    char *filt;

    if (ldap_conf.search_filter)
	easprintf(&filt, "(&%s(cn=defaults))", ldap_conf.search_filter);
    else
	filt = estrdup("cn=defaults");
    return filt;
}

 /*
 * Determine length of query value after escaping characters
 * as per RFC 4515.
 */
static size_t
sudo_ldap_value_len(value)
    const char *value;
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
sudo_ldap_value_cat(dst, src, size)
    char *dst;
    const char *src;
    size_t size;
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
sudo_ldap_build_pass1(pw)
    struct passwd *pw;
{
    struct group *grp;
    char *buf, timebuffer[TIMEFILTER_LENGTH + 1];
    size_t sz = 0;
    int i;

    /* If there is a filter, allocate space for the global AND. */
    if (ldap_conf.timed || ldap_conf.search_filter)
	sz += 3;

    /* Add LDAP search filter if present. */
    if (ldap_conf.search_filter)
	sz += strlen(ldap_conf.search_filter);

    /* Then add (|(sudoUser=USERNAME)(sudoUser=ALL)) + NUL */
    sz += 29 + sudo_ldap_value_len(pw->pw_name);

    /* Add space for primary and supplementary groups. */
    if ((grp = sudo_getgrgid(pw->pw_gid)) != NULL) {
	sz += 12 + sudo_ldap_value_len(grp->gr_name);
	gr_delref(grp);
    }
    for (i = 0; i < user_ngroups; i++) {
	if (user_groups[i] == pw->pw_gid)
	    continue;
	if ((grp = sudo_getgrgid(user_groups[i])) != NULL) {
	    sz += 12 + sudo_ldap_value_len(grp->gr_name);
	    gr_delref(grp);
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

    /* Append primary group */
    if ((grp = sudo_getgrgid(pw->pw_gid)) != NULL) {
	(void) strlcat(buf, "(sudoUser=%", sz);
	(void) sudo_ldap_value_cat(buf, grp->gr_name, sz);
	(void) strlcat(buf, ")", sz);
	gr_delref(grp);
    }

    /* Append supplementary groups */
    for (i = 0; i < user_ngroups; i++) {
	if (user_groups[i] == pw->pw_gid)
	    continue;
	if ((grp = sudo_getgrgid(user_groups[i])) != NULL) {
	    (void) strlcat(buf, "(sudoUser=%", sz);
	    (void) sudo_ldap_value_cat(buf, grp->gr_name, sz);
	    (void) strlcat(buf, ")", sz);
	    gr_delref(grp);
	}
    }

    /* Add ALL to list and end the global OR */
    if (strlcat(buf, "(sudoUser=ALL)", sz) >= sz)
	errorx(1, "sudo_ldap_build_pass1 allocation mismatch");

    /* Add the time restriction, or simply end the global OR. */
    if (ldap_conf.timed) {
	strlcat(buf, ")", sz); /* closes the global OR */
	sudo_ldap_timefilter(timebuffer, sizeof(timebuffer));
	strlcat(buf, timebuffer, sz);
    } else if (ldap_conf.search_filter) {
	strlcat(buf, ")", sz); /* closes the global OR */
    }
    strlcat(buf, ")", sz); /* closes the global OR or the global AND */

    return buf;
}

/*
 * Builds up a filter to check against netgroup entries in LDAP.
 */
static char *
sudo_ldap_build_pass2()
{
    char *filt, timebuffer[TIMEFILTER_LENGTH + 1];

    if (ldap_conf.timed)
	sudo_ldap_timefilter(timebuffer, sizeof(timebuffer));

    /*
     * Match all sudoUsers beginning with a '+'.
     * If a search filter or time restriction is specified, 
     * those get ANDed in to the expression.
     */
    easprintf(&filt, "%s%s(sudoUser=+*)%s%s",
	(ldap_conf.timed || ldap_conf.search_filter) ? "(&" : "",
	ldap_conf.search_filter ? ldap_conf.search_filter : "",
	ldap_conf.timed ? timebuffer : "",
	(ldap_conf.timed || ldap_conf.search_filter) ? ")" : "");

    return filt;
}

/*
 * Map yes/true/on to TRUE, no/false/off to FALSE, else -1
 */
static int
_atobool(s)
    const char *s;
{
    switch (*s) {
	case 'y':
	case 'Y':
	    if (strcasecmp(s, "yes") == 0)
		return TRUE;
	    break;
	case 't':
	case 'T':
	    if (strcasecmp(s, "true") == 0)
		return TRUE;
	    break;
	case 'o':
	case 'O':
	    if (strcasecmp(s, "on") == 0)
		return TRUE;
	    if (strcasecmp(s, "off") == 0)
		return FALSE;
	    break;
	case 'n':
	case 'N':
	    if (strcasecmp(s, "no") == 0)
		return FALSE;
	    break;
	case 'f':
	case 'F':
	    if (strcasecmp(s, "false") == 0)
		return FALSE;
	    break;
    }
    return -1;
}

static void
sudo_ldap_read_secret(path)
    const char *path;
{
    FILE *fp;
    char buf[LINE_MAX], *cp;

    if ((fp = fopen(_PATH_LDAP_SECRET, "r")) != NULL) {
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
}

/*
 * Look up keyword in config tables.
 * Returns TRUE if found, else FALSE.
 */
static int
sudo_ldap_parse_keyword(keyword, value, table)
    const char *keyword;
    const char *value;
    struct ldap_config_table *table;
{
    struct ldap_config_table *cur;

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
		*(int *)(cur->valp) = _atobool(value) == TRUE;
		break;
	    case CONF_INT:
		*(int *)(cur->valp) = atoi(value);
		break;
	    case CONF_STR:
		efree(*(char **)(cur->valp));
		*(char **)(cur->valp) = estrdup(value);
		break;
	    case CONF_LIST_STR:
		{
		    struct ldap_config_list_str **p;
		    size_t len = strlen(value);

		    if (len > 0) {
			p = (struct ldap_config_list_str **)cur->valp;
			while (*p != NULL)
			    p = &(*p)->next;
			*p = emalloc(sizeof(struct ldap_config_list_str) + len);
			memcpy((*p)->val, value, len + 1);
			(*p)->next = NULL;
		    }
		}
		break;
	    }
	    return TRUE;
	}
    }
    return FALSE;
}

static int
sudo_ldap_read_config()
{
    FILE *fp;
    char *cp, *keyword, *value;

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

    if ((fp = fopen(_PATH_LDAP_CONF, "r")) == NULL)
	return FALSE;

    while ((cp = sudo_parseln(fp)) != NULL) {
	if (*cp == '\0')
	    continue;		/* skip empty line */

	/* split into keyword and value */
	keyword = cp;
	while (*cp && !isblank((unsigned char) *cp))
	    cp++;
	if (*cp)
	    *cp++ = '\0';	/* terminate keyword */

	/* skip whitespace before value */
	while (isblank((unsigned char) *cp))
	    cp++;
	value = cp;

	/* Look up keyword in config tables. */
	if (!sudo_ldap_parse_keyword(keyword, value, ldap_conf_global))
	    sudo_ldap_parse_keyword(keyword, value, ldap_conf_conn);
    }
    fclose(fp);

    if (!ldap_conf.host)
	ldap_conf.host = estrdup("localhost");

    if (ldap_conf.debug > 1) {
	fprintf(stderr, "LDAP Config Summary\n");
	fprintf(stderr, "===================\n");
	if (ldap_conf.uri) {
	    struct ldap_config_list_str *uri = ldap_conf.uri;

	    do {
		fprintf(stderr, "uri              %s\n", uri->val);
	    } while ((uri = uri->next) != NULL);
	} else {
	    fprintf(stderr, "host             %s\n", ldap_conf.host ?
		ldap_conf.host : "(NONE)");
	    fprintf(stderr, "port             %d\n", ldap_conf.port);
	}
	fprintf(stderr, "ldap_version     %d\n", ldap_conf.version);
	if (ldap_conf.base) {
	    struct ldap_config_list_str *base = ldap_conf.base;

	    do {
		fprintf(stderr, "sudoers_base     %s\n", base->val);
	    } while ((base = base->next) != NULL);
	} else {
	    fprintf(stderr, "sudoers_base     %s\n",
		"(NONE) <---Sudo will ignore ldap)");
	}
	if (ldap_conf.search_filter)
	    fprintf(stderr, "search_filter    %s\n", ldap_conf.search_filter);
	fprintf(stderr, "binddn           %s\n", ldap_conf.binddn ?
	    ldap_conf.binddn : "(anonymous)");
	fprintf(stderr, "bindpw           %s\n", ldap_conf.bindpw ?
	    ldap_conf.bindpw : "(anonymous)");
	if (ldap_conf.bind_timelimit > 0)
	    fprintf(stderr, "bind_timelimit   %d\n", ldap_conf.bind_timelimit);
	if (ldap_conf.timelimit > 0)
	    fprintf(stderr, "timelimit        %d\n", ldap_conf.timelimit);
	if (ldap_conf.timeout > 0)
	    fprintf(stderr, "timeout          %d\n", ldap_conf.timeout);
	if (ldap_conf.deref != -1)
	    fprintf(stderr, "deref            %d\n", ldap_conf.deref);
	fprintf(stderr, "ssl              %s\n", ldap_conf.ssl ?
	    ldap_conf.ssl : "(no)");
	if (ldap_conf.tls_checkpeer != -1)
	    fprintf(stderr, "tls_checkpeer    %s\n", ldap_conf.tls_checkpeer ?
		"(yes)" : "(no)");
	if (ldap_conf.tls_cacertfile != NULL)
	    fprintf(stderr, "tls_cacertfile   %s\n", ldap_conf.tls_cacertfile);
	if (ldap_conf.tls_cacertdir != NULL)
	    fprintf(stderr, "tls_cacertdir    %s\n", ldap_conf.tls_cacertdir);
	if (ldap_conf.tls_random_file != NULL)
	    fprintf(stderr, "tls_random_file  %s\n", ldap_conf.tls_random_file);
	if (ldap_conf.tls_cipher_suite != NULL)
	    fprintf(stderr, "tls_cipher_suite %s\n", ldap_conf.tls_cipher_suite);
	if (ldap_conf.tls_certfile != NULL)
	    fprintf(stderr, "tls_certfile     %s\n", ldap_conf.tls_certfile);
	if (ldap_conf.tls_keyfile != NULL)
	    fprintf(stderr, "tls_keyfile      %s\n", ldap_conf.tls_keyfile);
#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
	if (ldap_conf.use_sasl != -1) {
	    fprintf(stderr, "use_sasl         %s\n",
		ldap_conf.use_sasl ? "yes" : "no");
	    fprintf(stderr, "sasl_auth_id     %s\n", ldap_conf.sasl_auth_id ?
		ldap_conf.sasl_auth_id : "(NONE)");
	    fprintf(stderr, "rootuse_sasl     %d\n", ldap_conf.rootuse_sasl);
	    fprintf(stderr, "rootsasl_auth_id %s\n", ldap_conf.rootsasl_auth_id ?
		ldap_conf.rootsasl_auth_id : "(NONE)");
	    fprintf(stderr, "sasl_secprops    %s\n", ldap_conf.sasl_secprops ?
		ldap_conf.sasl_secprops : "(NONE)");
	    fprintf(stderr, "krb5_ccname      %s\n", ldap_conf.krb5_ccname ?
		ldap_conf.krb5_ccname : "(NONE)");
	}
#endif
	fprintf(stderr, "===================\n");
    }
    if (!ldap_conf.base)
	return FALSE;		/* if no base is defined, ignore LDAP */

    if (ldap_conf.bind_timelimit > 0)
	ldap_conf.bind_timelimit *= 1000;	/* convert to ms */

    /*
     * Interpret SSL option
     */
    if (ldap_conf.ssl != NULL) {
	if (strcasecmp(ldap_conf.ssl, "start_tls") == 0)
	    ldap_conf.ssl_mode = SUDO_LDAP_STARTTLS;
	else if (_atobool(ldap_conf.ssl))
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
    if (ldap_conf.uri) {
	struct ldap_config_list_str *uri = ldap_conf.uri;
	if (sudo_ldap_parse_uri(uri) != 0)
	    return FALSE;
	do {
	    ldap_conf.uri = uri->next;
	    efree(uri);
	} while ((uri = ldap_conf.uri));
	ldap_conf.port = LDAP_PORT;
    }
#endif

    if (!ldap_conf.uri) {
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
	sudo_ldap_read_secret(_PATH_LDAP_SECRET);

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    /*
     * Make sure we can open the file specified by krb5_ccname.
     */
    if (ldap_conf.krb5_ccname != NULL) {
	if (strncasecmp(ldap_conf.krb5_ccname, "FILE:", 5) == 0 ||
	    strncasecmp(ldap_conf.krb5_ccname, "WRFILE:", 7) == 0) {
	    value = ldap_conf.krb5_ccname +
		(ldap_conf.krb5_ccname[4] == ':' ? 5 : 7);
	    if ((fp = fopen(value, "r")) != NULL) {
		DPRINTF(("using krb5 credential cache: %s", value), 1);
		fclose(fp);
	    } else {
		/* Can't open it, just ignore the entry. */
		DPRINTF(("unable to open krb5 credential cache: %s", value), 1);
		efree(ldap_conf.krb5_ccname);
		ldap_conf.krb5_ccname = NULL;
	    }
	}
    }
#endif
    return TRUE;
}

/*
 * Extract the dn from an entry and return the first rdn from it.
 */
static char *
sudo_ldap_get_first_rdn(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
#ifdef HAVE_LDAP_STR2DN
    char *dn, *rdn = NULL;
    LDAPDN tmpDN;

    if ((dn = ldap_get_dn(ld, entry)) == NULL)
	return NULL;
    if (ldap_str2dn(dn, &tmpDN, LDAP_DN_FORMAT_LDAP) == LDAP_SUCCESS) {
	ldap_rdn2str(tmpDN[0], &rdn, LDAP_DN_FORMAT_UFN);
	ldap_dnfree(tmpDN);
    }
    ldap_memfree(dn);
    return rdn;
#else
    char *dn, **edn;

    if ((dn = ldap_get_dn(ld, entry)) == NULL)
	return NULL;
    edn = ldap_explode_dn(dn, 1);
    ldap_memfree(dn);
    return edn ? edn[0] : NULL;
#endif
}

/*
 * Fetch and display the global Options.
 */
static int
sudo_ldap_display_defaults(nss, pw, lbuf)
    struct sudo_nss *nss;
    struct passwd *pw;
    struct lbuf *lbuf;
{
    struct berval **bv, **p;
    struct timeval tv, *tvp = NULL;
    struct ldap_config_list_str *base;
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    LDAPMessage *entry, *result;
    char *prefix, *filt;
    int rc, count = 0;

    if (handle == NULL || handle->ld == NULL)
	goto done;
    ld = handle->ld;

    filt = sudo_ldap_build_default_filter();
    for (base = ldap_conf.base; base != NULL; base = base->next) {
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
    return count;
}

/*
 * STUB
 */
static int
sudo_ldap_display_bound_defaults(nss, pw, lbuf)
    struct sudo_nss *nss;
    struct passwd *pw;
    struct lbuf *lbuf;
{
    return 0;
}

/*
 * Print a record in the short form, ala file sudoers.
 */
static int
sudo_ldap_display_entry_short(ld, entry, lbuf)
    LDAP *ld;
    LDAPMessage *entry;
    struct lbuf *lbuf;
{
    struct berval **bv, **p;
    int count = 0;

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

    return count;
}

/*
 * Print a record in the long form.
 */
static int
sudo_ldap_display_entry_long(ld, entry, lbuf)
    LDAP *ld;
    LDAPMessage *entry;
    struct lbuf *lbuf;
{
    struct berval **bv, **p;
    char *rdn;
    int count = 0;

    /* extract the dn, only show the first rdn */
    rdn = sudo_ldap_get_first_rdn(ld, entry);
    lbuf_append(lbuf, "\nLDAP Role: %s\n", rdn ? rdn : "UNKNOWN");
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
	    lbuf_append(lbuf, "    Order: %s\n", (*bv)->bv_val);
	}
	ldap_value_free_len(bv);
    }

    /* Get the command values from the entry. */
    bv = ldap_get_values_len(ld, entry, "sudoCommand");
    if (bv != NULL) {
	lbuf_append(lbuf, "    Commands:\n");
	for (p = bv; *p != NULL; p++) {
	    lbuf_append(lbuf, "\t%s\n", (*p)->bv_val);
	    count++;
	}
	ldap_value_free_len(bv);
    }

    return count;
}

/*
 * Like sudo_ldap_lookup(), except we just print entries.
 */
static int
sudo_ldap_display_privs(nss, pw, lbuf)
    struct sudo_nss *nss;
    struct passwd *pw;
    struct lbuf *lbuf;
{
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    struct ldap_result *lres;
    LDAPMessage *entry;
    int i, count = 0;

    if (handle == NULL || handle->ld == NULL)
	goto done;
    ld = handle->ld;

    DPRINTF(("ldap search for command list"), 1);
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
    return count;
}

static int
sudo_ldap_display_cmnd(nss, pw)
    struct sudo_nss *nss;
    struct passwd *pw;
{
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    struct ldap_result *lres;
    LDAPMessage *entry;
    int i, found = FALSE;

    if (handle == NULL || handle->ld == NULL)
	goto done;
    ld = handle->ld;

    /*
     * The sudo_ldap_result_get() function returns all nodes that match
     * the user and the host.
     */
    DPRINTF(("ldap search for command list"), 1);
    lres = sudo_ldap_result_get(nss, pw);
    for (i = 0; i < lres->nentries; i++) {
	entry = lres->entries[i].entry;
	if (sudo_ldap_check_command(ld, entry, NULL) &&
	    sudo_ldap_check_runas(ld, entry)) {
	    found = TRUE;
	    goto done;
	}
    }

done:
    if (found)
	printf("%s%s%s\n", safe_cmnd ? safe_cmnd : user_cmnd,
	    user_args ? " " : "", user_args ? user_args : "");
   return !found;
}

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
static int
sudo_ldap_sasl_interact(ld, flags, _auth_id, _interact)
    LDAP *ld;
    unsigned int flags;
    void *_auth_id;
    void *_interact;
{
    char *auth_id = (char *)_auth_id;
    sasl_interact_t *interact = (sasl_interact_t *)_interact;

    for (; interact->id != SASL_CB_LIST_END; interact++) {
	if (interact->id != SASL_CB_USER)
	    return LDAP_PARAM_ERROR;

	if (auth_id != NULL)
	    interact->result = auth_id;
	else if (interact->defresult != NULL)
	    interact->result = interact->defresult;
	else
	    interact->result = "";

	interact->len = strlen(interact->result);
#if SASL_VERSION_MAJOR < 2
	interact->result = estrdup(interact->result);
#endif /* SASL_VERSION_MAJOR < 2 */
    }
    return LDAP_SUCCESS;
}
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */

/*
 * Set LDAP options from the specified options table
 */
static int
sudo_ldap_set_options_table(ld, table)
    LDAP *ld;
    struct ldap_config_table *table;
{
    struct ldap_config_table *cur;
    int ival, rc, errors = 0;
    char *sval;

    for (cur = table; cur->conf_str != NULL; cur++) {
	if (cur->opt_val == -1)
	    continue;

	switch (cur->type) {
	case CONF_BOOL:
	case CONF_INT:
	    ival = *(int *)(cur->valp);
	    if (ival >= 0) {
		DPRINTF(("ldap_set_option: %s -> %d", cur->conf_str, ival), 1);
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
		DPRINTF(("ldap_set_option: %s -> %s", cur->conf_str, sval), 1);
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
    return errors ? -1 : 0;
}

/*
 * Set LDAP options based on the global config table.
 */
static int
sudo_ldap_set_options_global()
{
    int rc;

    /* Set ber options */
#ifdef LBER_OPT_DEBUG_LEVEL
    if (ldap_conf.ldap_debug)
	ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &ldap_conf.ldap_debug);
#endif

    /* Parse global LDAP options table. */
    rc = sudo_ldap_set_options_table(NULL, ldap_conf_global);
    if (rc == -1)
	return -1;
    return 0;
}

/*
 * Set LDAP options based on the per-connection config table.
 */
static int
sudo_ldap_set_options_conn(ld)
    LDAP *ld;
{
    int rc;

    /* Parse per-connection LDAP options table. */
    rc = sudo_ldap_set_options_table(ld, ldap_conf_conn);
    if (rc == -1)
	return -1;

#ifdef LDAP_OPT_TIMEOUT
    /* Convert timeout to a timeval */
    if (ldap_conf.timeout > 0) {
	struct timeval tv;
	tv.tv_sec = ldap_conf.timeout;
	tv.tv_usec = 0;
	DPRINTF(("ldap_set_option(LDAP_OPT_TIMEOUT, %ld)",
	    (long)tv.tv_sec), 1);
	rc = ldap_set_option(ld, LDAP_OPT_TIMEOUT, &tv);
	if (rc != LDAP_OPT_SUCCESS) {
	    warningx("ldap_set_option(TIMEOUT, %ld): %s",
		(long)tv.tv_sec, ldap_err2string(rc));
	}
    }
#endif
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    /* Convert bind_timelimit to a timeval */
    if (ldap_conf.bind_timelimit > 0) {
	struct timeval tv;
	tv.tv_sec = ldap_conf.bind_timelimit / 1000;
	tv.tv_usec = 0;
	DPRINTF(("ldap_set_option(LDAP_OPT_NETWORK_TIMEOUT, %ld)",
	    (long)tv.tv_sec), 1);
	rc = ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
# if !defined(LDAP_OPT_CONNECT_TIMEOUT) || LDAP_VENDOR_VERSION != 510
	/* Tivoli Directory Server 6.3 libs always return a (bogus) error. */
	if (rc != LDAP_OPT_SUCCESS) {
	    warningx("ldap_set_option(NETWORK_TIMEOUT, %ld): %s",
		(long)tv.tv_sec, ldap_err2string(rc));
	}
# endif
    }
#endif

#if defined(LDAP_OPT_X_TLS) && !defined(HAVE_LDAPSSL_INIT)
    if (ldap_conf.ssl_mode == SUDO_LDAP_SSL) {
	int val = LDAP_OPT_X_TLS_HARD;
	DPRINTF(("ldap_set_option(LDAP_OPT_X_TLS, LDAP_OPT_X_TLS_HARD)"), 1);
	rc = ldap_set_option(ld, LDAP_OPT_X_TLS, &val);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_set_option(LDAP_OPT_X_TLS, LDAP_OPT_X_TLS_HARD): %s",
		ldap_err2string(rc));
	    return -1;
	}
    }
#endif
    return 0;
}

/*
 * Create a new sudo_ldap_result structure.
 */
static struct ldap_result *
sudo_ldap_result_alloc()
{
    return ecalloc(1, sizeof(struct ldap_result));
}

/*
 * Free the ldap result structure
 */
static void
sudo_ldap_result_free(lres)
    struct ldap_result *lres;
{
    struct ldap_search_list *s;

    if (lres != NULL) {
	if (lres->nentries) {
	    efree(lres->entries);
	    lres->entries = NULL;
	}
	if (lres->searches) {
	    while ((s = lres->searches) != NULL) {
		ldap_msgfree(s->searchresult);
		lres->searches = s->next;
		efree(s);
	    }
	}
	efree(lres);
    }
}

/*
 * Add a search result to the ldap_result structure.
 */
static struct ldap_search_list *
sudo_ldap_result_add_search(lres, ldap, searchresult)
    struct ldap_result *lres;
    LDAP *ldap;
    LDAPMessage *searchresult;
{
    struct ldap_search_list *s, *news;

    news = ecalloc(1, sizeof(struct ldap_search_list));
    news->ldap = ldap;
    news->searchresult = searchresult;
    /* news->next = NULL; */

    /* Add entry to the end of the chain (XXX - tailq instead?). */
    if (lres->searches) {
	for (s = lres->searches; s->next != NULL; s = s->next)
	    continue;
	s->next = news;
    } else {
	lres->searches = news;
    }
    return news;
}

/*
 * Connect to the LDAP server specified by ld
 */
static int
sudo_ldap_bind_s(ld)
    LDAP *ld;
{
    int rc;
#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    const char *old_ccname = user_ccname;
# ifdef HAVE_GSS_KRB5_CCACHE_NAME
    unsigned int status;
# endif
#endif

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    if (ldap_conf.rootuse_sasl == TRUE ||
	(ldap_conf.rootuse_sasl != FALSE && ldap_conf.use_sasl == TRUE)) {
	void *auth_id = ldap_conf.rootsasl_auth_id ?
	    ldap_conf.rootsasl_auth_id : ldap_conf.sasl_auth_id;

	if (ldap_conf.krb5_ccname != NULL) {
# ifdef HAVE_GSS_KRB5_CCACHE_NAME
	    if (gss_krb5_ccache_name(&status, ldap_conf.krb5_ccname, &old_ccname)
		!= GSS_S_COMPLETE) {
		old_ccname = NULL;
		DPRINTF(("gss_krb5_ccache_name() failed: %d", status), 1);
	    }
# else
	    setenv("KRB5CCNAME", ldap_conf.krb5_ccname, TRUE);
# endif
	}
	rc = ldap_sasl_interactive_bind_s(ld, ldap_conf.binddn, "GSSAPI",
	    NULL, NULL, LDAP_SASL_QUIET, sudo_ldap_sasl_interact, auth_id);
	if (ldap_conf.krb5_ccname != NULL) {
# ifdef HAVE_GSS_KRB5_CCACHE_NAME
	    if (gss_krb5_ccache_name(&status, old_ccname, NULL) != GSS_S_COMPLETE)
		    DPRINTF(("gss_krb5_ccache_name() failed: %d", status), 1);
# else
	    if (old_ccname != NULL)
		setenv("KRB5CCNAME", old_ccname, TRUE);
	    else
		unsetenv("KRB5CCNAME");
# endif
	}
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_sasl_interactive_bind_s(): %s", ldap_err2string(rc));
	    return -1;
	}
	DPRINTF(("ldap_sasl_interactive_bind_s() ok"), 1);
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
	    return -1;
	}
	DPRINTF(("ldap_sasl_bind_s() ok"), 1);
    }
#else
    {
	rc = ldap_simple_bind_s(ld, ldap_conf.binddn, ldap_conf.bindpw);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_simple_bind_s(): %s", ldap_err2string(rc));
	    return -1;
	}
	DPRINTF(("ldap_simple_bind_s() ok"), 1);
    }
#endif
    return 0;
}

/*
 * Open a connection to the LDAP server.
 * Returns 0 on success and non-zero on failure.
 */
static int
sudo_ldap_open(nss)
    struct sudo_nss *nss;
{
    LDAP *ld;
    int rc, ldapnoinit = FALSE;
    struct sudo_ldap_handle	*handle;

    if (!sudo_ldap_read_config())
	return -1;

    /* Prevent reading of user ldaprc and system defaults. */
    if (getenv("LDAPNOINIT") == NULL) {
	ldapnoinit = TRUE;
	setenv("LDAPNOINIT", "1", TRUE);
    }

    /* Set global LDAP options */
    if (sudo_ldap_set_options_global() < 0)
	return -1;

    /* Connect to LDAP server */
#ifdef HAVE_LDAP_INITIALIZE
    if (ldap_conf.uri != NULL) {
	char *buf = sudo_ldap_join_uri(ldap_conf.uri);
	DPRINTF(("ldap_initialize(ld, %s)", buf), 2);
	rc = ldap_initialize(&ld, buf);
	efree(buf);
	if (rc != LDAP_SUCCESS)
	    warningx("unable to initialize LDAP: %s", ldap_err2string(rc));
    } else
#endif
	rc = sudo_ldap_init(&ld, ldap_conf.host, ldap_conf.port);
    if (rc != LDAP_SUCCESS)
	return -1;

    /* Set LDAP per-connection options */
    if (sudo_ldap_set_options_conn(ld) < 0)
	return -1;

    if (ldapnoinit)
	unsetenv("LDAPNOINIT");

    if (ldap_conf.ssl_mode == SUDO_LDAP_STARTTLS) {
#if defined(HAVE_LDAP_START_TLS_S)
	rc = ldap_start_tls_s(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_start_tls_s(): %s", ldap_err2string(rc));
	    return -1;
	}
	DPRINTF(("ldap_start_tls_s() ok"), 1);
#elif defined(HAVE_LDAP_SSL_CLIENT_INIT) && defined(HAVE_LDAP_START_TLS_S_NP)
	if (ldap_ssl_client_init(ldap_conf.tls_keyfile, ldap_conf.tls_keypw, 0, &rc) != LDAP_SUCCESS) {
	    warningx("ldap_ssl_client_init(): %s", ldap_err2string(rc));
	    return -1;
	}
	rc = ldap_start_tls_s_np(ld, NULL);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_start_tls_s_np(): %s", ldap_err2string(rc));
	    return -1;
	}
	DPRINTF(("ldap_start_tls_s_np() ok"), 1);
#else
	warningx("start_tls specified but LDAP libs do not support ldap_start_tls_s() or ldap_start_tls_s_np()");
#endif /* !HAVE_LDAP_START_TLS_S && !HAVE_LDAP_START_TLS_S_NP */
    }

    /* Actually connect */
    if (sudo_ldap_bind_s(ld) != 0)
	return -1;

    /* Create a handle container. */
    handle = ecalloc(1, sizeof(struct sudo_ldap_handle));
    handle->ld = ld;
    /* handle->result = NULL; */
    /* handle->username = NULL; */
    /* handle->groups = NULL; */
    nss->handle = handle;

    return 0;
}

static int
sudo_ldap_setdefs(nss)
    struct sudo_nss *nss;
{
    struct ldap_config_list_str *base;
    struct sudo_ldap_handle *handle = nss->handle;
    struct timeval tv, *tvp = NULL;
    LDAP *ld;
    LDAPMessage *entry, *result;
    char *filt;
    int rc;

    if (handle == NULL || handle->ld == NULL)
	return -1;
    ld = handle->ld;

    filt = sudo_ldap_build_default_filter();
    DPRINTF(("Looking for cn=defaults: %s", filt), 1);

    for (base = ldap_conf.base; base != NULL; base = base->next) {
	if (ldap_conf.timeout > 0) {
	    tv.tv_sec = ldap_conf.timeout;
	    tv.tv_usec = 0;
	    tvp = &tv;
	}
	result = NULL;
	rc = ldap_search_ext_s(ld, base->val, LDAP_SCOPE_SUBTREE,
	    filt, NULL, 0, NULL, NULL, tvp, 0, &result);
	if (rc == LDAP_SUCCESS && (entry = ldap_first_entry(ld, result))) {
	    DPRINTF(("found:%s", ldap_get_dn(ld, entry)), 1);
	    sudo_ldap_parse_options(ld, entry);
	} else
	    DPRINTF(("no default options found in %s", base->val), 1);

	if (result)
	    ldap_msgfree(result);
    }
    efree(filt);

    return 0;
}

/*
 * like sudoers_lookup() - only LDAP style
 */
static int
sudo_ldap_lookup(nss, ret, pwflag)
    struct sudo_nss *nss;
    int ret;
    int pwflag;
{
    struct sudo_ldap_handle *handle = nss->handle;
    LDAP *ld;
    LDAPMessage *entry;
    int i, rc, setenv_implied;
    struct ldap_result *lres = NULL;

    if (handle == NULL || handle->ld == NULL)
	return ret;
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
	enum def_tupple pwcheck = 
	    (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;

	DPRINTF(("perform search for pwflag %d", pwflag), 1);
	for (i = 0; i < lres->nentries; i++) {
	    entry = lres->entries[i].entry;
	    if ((pwcheck == any && doauth != FALSE) ||
		(pwcheck == all && doauth == FALSE)) {
		doauth = sudo_ldap_check_bool(ld, entry, "authenticate");
	    }
	    /* Only check the command when listing another user. */
	    if (user_uid == 0 || list_pw == NULL ||
		user_uid == list_pw->pw_uid ||
		sudo_ldap_check_command(ld, entry, NULL)) {
		matched = TRUE;
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
			if (doauth == FALSE)
			    def_authenticate = FALSE;
			break;
		    case never:
			def_authenticate = FALSE;
			break;
		    default:
			break;
		}
	    }
	}
	goto done;
    }

    DPRINTF(("searching LDAP for sudoers entries"), 1);

    setenv_implied = FALSE;
    for (i = 0; i < lres->nentries; i++) {
	entry = lres->entries[i].entry;
	if (!sudo_ldap_check_runas(ld, entry))
	    continue;
	rc = sudo_ldap_check_command(ld, entry, &setenv_implied);
	if (rc != UNSPEC) {
	    /* We have a match. */
	    DPRINTF(("Command %sallowed", rc == TRUE ? "" : "NOT "), 1);
	    if (rc == TRUE) {
		DPRINTF(("LDAP entry: %p", entry), 1);
		/* Apply entry-specific options. */
		if (setenv_implied)
		    def_setenv = TRUE;
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
    DPRINTF(("done with LDAP searches"), 1);
    DPRINTF(("user_matches=%d", lres->user_matches), 1);
    DPRINTF(("host_matches=%d", lres->host_matches), 1);

    if (!ISSET(ret, VALIDATE_OK)) {
	/* No matching entries. */
	if (pwflag && list_pw == NULL)
	    SET(ret, FLAG_NO_CHECK);
    }
    if (lres->user_matches)
	CLR(ret, FLAG_NO_USER);
    if (lres->host_matches)
	CLR(ret, FLAG_NO_HOST);
    DPRINTF(("sudo_ldap_lookup(%d)=0x%02x", pwflag, ret), 1);

    return ret;
}

/*
 * Comparison function for ldap_entry_wrapper structures, descending order.
 */
static int
ldap_entry_compare(a, b)
    const void *a;
    const void *b;
{
    const struct ldap_entry_wrapper *aw = a;
    const struct ldap_entry_wrapper *bw = b;

    return bw->order < aw->order ? -1 :
	(bw->order > aw->order ? 1 : 0);
}

/*
 * Find the last entry in the list of searches, usually the
 * one currently being used to add entries.
 * XXX - use a tailq instead?
 */
static struct ldap_search_list *
sudo_ldap_result_last_search(lres)
    struct ldap_result *lres;
{
    struct ldap_search_list *result = lres->searches;

    if (result) {
	while (result->next)
	    result = result->next;
    }
    return result;
}

/*
 * Add an entry to the result structure.
 */
static struct ldap_entry_wrapper *
sudo_ldap_result_add_entry(lres, entry)
    struct ldap_result *lres;
    LDAPMessage *entry;
{
    struct ldap_search_list *last;
    struct berval **bv;
    double order = 0.0;
    char *ep;

    /* Determine whether the entry has the sudoOrder attribute. */
    last = sudo_ldap_result_last_search(lres);
    bv = ldap_get_values_len(last->ldap, entry, "sudoOrder");
    if (bv != NULL) {
	if (ldap_count_values_len(bv) > 0) {
	    /* Get the value of this attribute, 0 if not present. */
	    DPRINTF(("order attribute raw: %s", (*bv)->bv_val), 1);
	    order = strtod((*bv)->bv_val, &ep);
	    if (ep == (*bv)->bv_val || *ep != '\0') {
		warningx("invalid sudoOrder attribute: %s", (*bv)->bv_val);
		order = 0.0;
	    }
	    DPRINTF(("order attribute: %f", order), 1);
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

    return &lres->entries[lres->nentries - 1];
}

/*
 * Free the ldap result structure in the sudo_nss handle.
 */
static void
sudo_ldap_result_free_nss(nss)
    struct sudo_nss *nss;
{
    struct sudo_ldap_handle *handle = nss->handle;

    if (handle->result != NULL) {
	DPRINTF(("removing reusable search result"), 1);
	sudo_ldap_result_free(handle->result);
	if (handle->username) {
	    efree(handle->username);
	    handle->username = NULL;
	}
	handle->groups = NULL;
	handle->result = NULL;
    }
}

/*
 * Perform the LDAP query for the user or return a cached query if
 * there is one for this user.
 */
static struct ldap_result *
sudo_ldap_result_get(nss, pw)
    struct sudo_nss *nss;
    struct passwd *pw;
{
    struct sudo_ldap_handle *handle = nss->handle;
    struct ldap_config_list_str *base;
    struct ldap_result *lres;
    struct timeval tv, *tvp = NULL;
    LDAPMessage *entry, *result;
    LDAP *ld = handle->ld;
    int do_netgr, rc;
    char *filt;

    /*
     * If we already have a cached result, return it so we don't have to
     * have to contact the LDAP server again.
     */
    if (handle->result) {
	if (handle->groups == user_groups &&
	    strcmp(pw->pw_name, handle->username) == 0) {
	    DPRINTF(("reusing previous result (user %s) with %d entries",
		handle->username, handle->result->nentries), 1);
	    return handle->result;
	}
	/* User mismatch, cached result cannot be used. */
	DPRINTF(("removing result (user %s), new search (user %s)",
	    handle->username, pw->pw_name), 1);
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
     * The second pass will return all the entries that contain
     * user netgroups.  Then we take the netgroups returned and
     * try to match them against the username.
     *
     * Since we have to sort the possible entries before we make a
     * decision, we perform the queries and store all of the results in
     * an ldap_result object.  The results are then sorted by sudoOrder.
     */
    lres = sudo_ldap_result_alloc();
    for (do_netgr = 0; do_netgr < 2; do_netgr++) {
	filt = do_netgr ? sudo_ldap_build_pass2() : sudo_ldap_build_pass1(pw);
	DPRINTF(("ldap search '%s'", filt), 1);
	for (base = ldap_conf.base; base != NULL; base = base->next) {
	    DPRINTF(("searching from base '%s'", base->val), 1);
	    if (ldap_conf.timeout > 0) {
		tv.tv_sec = ldap_conf.timeout;
		tv.tv_usec = 0;
		tvp = &tv;
	    }
	    result = NULL;
	    rc = ldap_search_ext_s(ld, base->val, LDAP_SCOPE_SUBTREE, filt,
		NULL, 0, NULL, NULL, tvp, 0, &result);
	    if (rc != LDAP_SUCCESS) {
		DPRINTF(("nothing found for '%s'", filt), 1);
		continue;
	    }
	    lres->user_matches = TRUE;

	    /* Add the seach result to list of search results. */
	    DPRINTF(("adding search result"), 1);
	    sudo_ldap_result_add_search(lres, ld, result);
	    LDAP_FOREACH(entry, ld, result) {
		if ((!do_netgr ||
		    sudo_ldap_check_user_netgroup(ld, entry, pw->pw_name)) &&
		    sudo_ldap_check_host(ld, entry)) {
		    lres->host_matches = TRUE;
		    sudo_ldap_result_add_entry(lres, entry);
		}
	    }
	    DPRINTF(("result now has %d entries", lres->nentries), 1);
	}
	efree(filt);
    }

    /* Sort the entries by the sudoOrder attribute. */
    DPRINTF(("sorting remaining %d entries", lres->nentries), 1);
    qsort(lres->entries, lres->nentries, sizeof(lres->entries[0]),
	ldap_entry_compare);

    /* Store everything in the sudo_nss handle. */
    handle->result = lres;
    handle->username = estrdup(pw->pw_name);
    handle->groups = user_groups;

    return lres;
}

/*
 * Shut down the LDAP connection.
 */
static int
sudo_ldap_close(nss)
    struct sudo_nss *nss;
{
    struct sudo_ldap_handle *handle = nss->handle;

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
    return 0;
}

/*
 * STUB
 */
static int
sudo_ldap_parse(nss)
    struct sudo_nss *nss;
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
sudo_ldap_result_from_search(ldap, searchresult)
    LDAP *ldap;
    LDAPMessage *searchresult;
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
    struct ldap_search_list *last = sudo_ldap_result_add_search(result,
	ldap, searchresult);

    /*
     * Now add each entry in the search result to the array of of entries
     * in the ldap_result object.
     */
    LDAPMessage	*entry;
    LDAP_FOREACH(entry, last->ldap, last->searchresult) {
	sudo_ldap_result_add_entry(result, entry);
    }
    DPRINTF(("sudo_ldap_result_from_search: %d entries found",
	result->nentries), 2);
    return result;
}
#endif
