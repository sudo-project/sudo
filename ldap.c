/*
 * Copyright (c) 2003-2005 Todd C. Miller <Todd.Miller@courtesan.com>
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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
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

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

#ifndef LDAP_OPT_SUCCESS
# define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#if defined(HAVE_LDAP_SASL_INTERACTIVE_BIND_S) && !defined(LDAP_SASL_QUIET)
# define LDAP_SASL_QUIET	0
#endif

#define LDAP_FOREACH(var, ld, res)					\
    for ((var) = ldap_first_entry((ld), (res));				\
	(var) != NULL;							\
	(var) = ldap_next_entry((ld), (var)))

#define	DPRINTF(args, level)	if (ldap_conf.debug >= level) warningx args

#define CONF_BOOL	0
#define CONF_INT	1
#define CONF_STR	2

#define SUDO_LDAP_SSL		1
#define SUDO_LDAP_STARTTLS	2

struct ldap_config_table {
    const char *conf_str;	/* config file string */
    short type;			/* CONF_BOOL, CONF_INT, CONF_STR */
    short connected;		/* connection-specific value? */
    int opt_val;		/* LDAP_OPT_* (or -1 for sudo internal) */
    void *valp;			/* pointer into ldap_conf */
};

/* ldap configuration structure */
static struct ldap_config {
    int port;
    int version;
    int debug;
    int ldap_debug;
    int tls_checkpeer;
    int timelimit;
    int bind_timelimit;
    int use_sasl;
    int rootuse_sasl;
    int ssl_mode;
    char *host;
    char *uri;
    char *binddn;
    char *bindpw;
    char *rootbinddn;
    char *base;
    char *ssl;
    char *tls_cacertfile;
    char *tls_cacertdir;
    char *tls_random_file;
    char *tls_cipher_suite;
    char *tls_certfile;
    char *tls_keyfile;
    char *sasl_auth_id;
    char *rootsasl_auth_id;
    char *sasl_secprops;
    char *krb5_ccname;
} ldap_conf;

static struct ldap_config_table ldap_conf_table[] = {
    { "sudoers_debug", CONF_INT, FALSE, -1, &ldap_conf.debug },
    { "host", CONF_STR, FALSE, -1, &ldap_conf.host },
    { "port", CONF_INT, FALSE, -1, &ldap_conf.port },
    { "ssl", CONF_STR, FALSE, -1, &ldap_conf.ssl },
    { "sslpath", CONF_STR, FALSE, -1, &ldap_conf.tls_certfile },
    { "uri", CONF_STR, FALSE, -1, &ldap_conf.uri },
#ifdef LDAP_OPT_DEBUG_LEVEL
    { "debug", CONF_INT, FALSE, LDAP_OPT_DEBUG_LEVEL, &ldap_conf.ldap_debug },
#endif
#ifdef LDAP_OPT_PROTOCOL_VERSION
    { "ldap_version", CONF_INT, TRUE, LDAP_OPT_PROTOCOL_VERSION,
	&ldap_conf.version },
#endif
#ifdef LDAP_OPT_X_TLS_REQUIRE_CERT
    { "tls_checkpeer", CONF_BOOL, FALSE, LDAP_OPT_X_TLS_REQUIRE_CERT,
	&ldap_conf.tls_checkpeer },
#endif
#ifdef LDAP_OPT_X_TLS_CACERTFILE
    { "tls_cacertfile", CONF_STR, FALSE, LDAP_OPT_X_TLS_CACERTFILE,
	&ldap_conf.tls_cacertfile },
#endif
#ifdef LDAP_OPT_X_TLS_CACERTDIR
    { "tls_cacertdir", CONF_STR, FALSE, LDAP_OPT_X_TLS_CACERTDIR,
	&ldap_conf.tls_cacertdir },
#endif
#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
    { "tls_randfile", CONF_STR, FALSE, LDAP_OPT_X_TLS_RANDOM_FILE,
	&ldap_conf.tls_random_file },
#endif
#ifdef LDAP_OPT_X_TLS_CIPHER_SUITE
    { "tls_ciphers", CONF_STR, FALSE, LDAP_OPT_X_TLS_CIPHER_SUITE,
	&ldap_conf.tls_cipher_suite },
#endif
#ifdef LDAP_OPT_X_TLS_CERTFILE
    { "tls_cert", CONF_STR, FALSE, LDAP_OPT_X_TLS_CERTFILE,
	&ldap_conf.tls_certfile },
#else
    { "tls_cert", CONF_STR, FALSE, -1, &ldap_conf.tls_certfile },
#endif
#ifdef LDAP_OPT_X_TLS_KEYFILE
    { "tls_key", CONF_STR, FALSE, LDAP_OPT_X_TLS_KEYFILE,
	&ldap_conf.tls_keyfile },
#else
    { "tls_key", CONF_STR, FALSE, -1, &ldap_conf.tls_keyfile },
#endif
#ifdef LDAP_OPT_NETWORK_TIMEOUT
    { "bind_timelimit", CONF_INT, TRUE, -1 /* needs timeval, set manually */,
	&ldap_conf.bind_timelimit },
#elif defined(LDAP_X_OPT_CONNECT_TIMEOUT)
    { "bind_timelimit", CONF_INT, TRUE, LDAP_X_OPT_CONNECT_TIMEOUT,
	&ldap_conf.bind_timelimit },
#endif
    { "timelimit", CONF_INT, TRUE, LDAP_OPT_TIMELIMIT, &ldap_conf.timelimit },
    { "binddn", CONF_STR, FALSE, -1, &ldap_conf.binddn },
    { "bindpw", CONF_STR, FALSE, -1, &ldap_conf.bindpw },
    { "rootbinddn", CONF_STR, FALSE, -1, &ldap_conf.rootbinddn },
    { "sudoers_base", CONF_STR, FALSE, -1, &ldap_conf.base },
#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    { "use_sasl", CONF_BOOL, FALSE, -1, &ldap_conf.use_sasl },
    { "sasl_auth_id", CONF_STR, FALSE, -1, &ldap_conf.sasl_auth_id },
    { "rootuse_sasl", CONF_BOOL, FALSE, -1, &ldap_conf.rootuse_sasl },
    { "rootsasl_auth_id", CONF_STR, FALSE, -1, &ldap_conf.rootsasl_auth_id },
# ifdef LDAP_OPT_X_SASL_SECPROPS
    { "sasl_secprops", CONF_STR, TRUE, LDAP_OPT_X_SASL_SECPROPS,
	&ldap_conf.sasl_secprops },
# endif
    { "krb5_ccname", CONF_STR, FALSE, -1, &ldap_conf.krb5_ccname },
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */
    { NULL }
};

struct sudo_nss sudo_nss_ldap = {
    &sudo_nss_ldap,
    NULL,
    sudo_ldap_open,
    sudo_ldap_close,
    sudo_ldap_parse,
    sudo_ldap_setdefs,
    sudo_ldap_lookup,
    sudo_ldap_display_privs,
    sudo_ldap_display_cmnd
};

/*
 * Walk through search results and return TRUE if we have a matching
 * netgroup, else FALSE.
 */
int
sudo_ldap_check_user_netgroup(ld, entry, user)
    LDAP *ld;
    LDAPMessage *entry;
    char *user;
{
    char **v = NULL, **p = NULL;
    int ret = FALSE;

    if (!entry)
	return(ret);

    /* get the values from the entry */
    v = ldap_get_values(ld, entry, "sudoUser");

    /* walk through values */
    for (p = v; p && *p && !ret; p++) {
	/* match any */
	if (netgr_matches(*p, NULL, NULL, user))
	    ret = TRUE;
	DPRINTF(("ldap sudoUser netgroup '%s' ... %s", *p,
	    ret ? "MATCH!" : "not"), 2);
    }

    if (v)
	ldap_value_free(v);	/* cleanup */

    return(ret);
}

/*
 * Walk through search results and return TRUE if we have a
 * host match, else FALSE.
 */
int
sudo_ldap_check_host(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    char **v = NULL, **p = NULL;
    int ret = FALSE;

    if (!entry)
	return(ret);

    /* get the values from the entry */
    v = ldap_get_values(ld, entry, "sudoHost");

    /* walk through values */
    for (p = v; p && *p && !ret; p++) {
	/* match any or address or netgroup or hostname */
	if (!strcmp(*p, "ALL") || addr_matches(*p) ||
	    netgr_matches(*p, user_host, user_shost, NULL) ||
	    hostname_matches(user_shost, user_host, *p))
	    ret = TRUE;
	DPRINTF(("ldap sudoHost '%s' ... %s", *p,
	    ret ? "MATCH!" : "not"), 2);
    }

    if (v)
	ldap_value_free(v);	/* cleanup */

    return(ret);
}

int
sudo_ldap_check_runas_user(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    char **v = NULL, **p = NULL;
    int ret = FALSE;

    if (!runas_pw)
	return(UNSPEC);

    /* get the values from the entry */
    v = ldap_get_values(ld, entry, "sudoRunAsUser");
    if (v == NULL)
	v = ldap_get_values(ld, entry, "sudoRunAs");	/* backwards compat */

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
    if (!v)
	ret = !strcasecmp(runas_pw->pw_name, def_runas_default);

    /* walk through values returned, looking for a match */
    for (p = v; p && *p && !ret; p++) {
	switch (*p[0]) {
	case '+':
	    if (netgr_matches(*p, NULL, NULL, runas_pw->pw_name))
		ret = TRUE;
	    break;
	case '%':
	    if (usergr_matches(*p, runas_pw->pw_name, runas_pw))
		ret = TRUE;
	    break;
	case 'A':
	    if (strcmp(*p, "ALL") == 0) {
		ret = TRUE;
		break;
	    }
	    /* FALLTHROUGH */
	default:
	    if (strcasecmp(*p, runas_pw->pw_name) == 0)
		ret = TRUE;
	    break;
	}
	DPRINTF(("ldap sudoRunAsUser '%s' ... %s", *p,
	    ret ? "MATCH!" : "not"), 2);
    }

    if (v)
	ldap_value_free(v);	/* cleanup */

    return(ret);
}

int
sudo_ldap_check_runas_group(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    char **v = NULL, **p = NULL;
    int ret = FALSE;

    /* runas_gr is only set if the user specified the -g flag */
    if (!runas_gr)
	return(UNSPEC);

    /* get the values from the entry */
    v = ldap_get_values(ld, entry, "sudoRunAsGroup");

    /* walk through values returned, looking for a match */
    for (p = v; p && *p && !ret; p++) {
	if (strcmp(*p, "ALL") == 0 || group_matches(*p, runas_gr))
	    ret = TRUE;
	DPRINTF(("ldap sudoRunAsGroup '%s' ... %s", *p,
	    ret ? "MATCH!" : "not"), 2);
    }

    if (v)
	ldap_value_free(v);	/* cleanup */

    return(ret);
}

/*
 * Walk through search results and return TRUE if we have a runas match,
 * else FALSE.  RunAs info is optional.
 */
int
sudo_ldap_check_runas(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    int ret;

    if (!entry)
	return(FALSE);

    ret = sudo_ldap_check_runas_user(ld, entry) != FALSE &&
	sudo_ldap_check_runas_group(ld, entry) != FALSE;

    return(ret);
}

/*
 * Walk through search results and return TRUE if we have a command match.
 */
int
sudo_ldap_check_command(ld, entry, setenv_implied)
    LDAP *ld;
    LDAPMessage *entry;
    int *setenv_implied;
{
    char *allowed_cmnd, *allowed_args, **v = NULL, **p = NULL;
    int foundbang, ret = FALSE;

    if (!entry)
	return(ret);

    v = ldap_get_values(ld, entry, "sudoCommand");

    for (p = v; p && *p && ret >= 0; p++) {
	/* Match against ALL ? */
	if (!strcmp(*p, "ALL")) {
	    ret = TRUE;
	    if (setenv_implied != NULL)
		*setenv_implied = TRUE;
	    DPRINTF(("ldap sudoCommand '%s' ... MATCH!", *p), 2);
	    continue;
	}

	/* check for !command */
	if (**p == '!') {
	    foundbang = TRUE;
	    allowed_cmnd = estrdup(1 + *p);	/* !command */
	} else {
	    foundbang = FALSE;
	    allowed_cmnd = estrdup(*p);		/* command */
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
	    ret = foundbang ? -1 : TRUE;
	}
	DPRINTF(("ldap sudoCommand '%s' ... %s", *p,
	    ret == TRUE ? "MATCH!" : "not"), 2);

	efree(allowed_cmnd);	/* cleanup */
    }

    if (v)
	ldap_value_free(v);	/* more cleanup */

    /* return TRUE if we found at least one ALLOW and no DENY */
    return(ret > 0);
}

/*
 * Search for boolean "option" in sudoOption.
 * Returns TRUE if found and allowed, FALSE if negated, else UNSPEC.
 */
int
sudo_ldap_check_bool(ld, entry, option)
    LDAP *ld;
    LDAPMessage *entry;
    char *option;
{
    char ch, *var, **v, **p;
    int ret = UNSPEC;

    if (entry == NULL)
	return(UNSPEC);

    /* walk through options */
    v = ldap_get_values(ld, entry, "sudoOption");
    for (p = v; p && *p; p++) {
	var = *p;
	DPRINTF(("ldap sudoOption: '%s'", var), 2);

	if ((ch = *var) == '!')
	    var++;
	if (strcmp(var, option) == 0)
	    ret = (ch != '!');
    }

    if (v)
	ldap_value_free(v);

    return(ret);
}

/*
 * Read sudoOption and modify the defaults as we go.  This is used once
 * from the cn=defaults entry and also once when a final sudoRole is matched.
 */
void
sudo_ldap_parse_options(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    char op, *var, *val, **v, **p;

    if (entry == NULL)
	return;

    v = ldap_get_values(ld, entry, "sudoOption");

    /* walk through options */
    for (p = v; p && *p; p++) {

	DPRINTF(("ldap sudoOption: '%s'", *p), 2);
	var = estrdup(*p);

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

    if (v)
	ldap_value_free(v);
}

/*
 * builds together a filter to check against ldap
 */
char *
sudo_ldap_build_pass1(pw)
    struct passwd *pw;
{
    struct group *grp;
    size_t sz;
    char *buf;
    int i;

    /* Start with (|(sudoUser=USERNAME)(sudoUser=ALL)) + NUL */
    sz = 29 + strlen(pw->pw_name);

    /* Add space for groups */
    if ((grp = sudo_getgrgid(pw->pw_gid)) != NULL)
	sz += 12 + strlen(grp->gr_name);	/* primary group */
    for (i = 0; i < user_ngroups; i++) {
	if ((grp = sudo_getgrgid(user_groups[i])) != NULL)
	    sz += 12 + strlen(grp->gr_name);	/* supplementary group */
    }
    buf = emalloc(sz);

    /* Global OR + sudoUser=user_name filter */
    (void) strlcpy(buf, "(|(sudoUser=", sz);
    (void) strlcat(buf, pw->pw_name, sz);
    (void) strlcat(buf, ")", sz);

    /* Append primary group */
    if ((grp = sudo_getgrgid(pw->pw_gid)) != NULL) {
	(void) strlcat(buf, "(sudoUser=%", sz);
	(void) strlcat(buf, grp->gr_name, sz);
	(void) strlcat(buf, ")", sz);
    }

    /* Append supplementary groups */
    for (i = 0; i < user_ngroups; i++) {
	if ((grp = sudo_getgrgid(user_groups[i])) != NULL) {
	    (void) strlcat(buf, "(sudoUser=%", sz);
	    (void) strlcat(buf, grp->gr_name, sz);
	    (void) strlcat(buf, ")", sz);
	}
    }

    /* Add ALL to list and end the global OR */
    if (strlcat(buf, "(sudoUser=ALL))", sz) >= sz)
	errorx(1, "sudo_ldap_build_pass1 allocation mismatch");

    return(buf);
}

/*
 * Map yes/true/on to TRUE, no/false/off to FALSE, else -1
 */
int
_atobool(s)
    const char *s;
{
    switch (*s) {
	case 'y':
	case 'Y':
	    if (strcasecmp(s, "yes") == 0)
		return(TRUE);
	    break;
	case 't':
	case 'T':
	    if (strcasecmp(s, "true") == 0)
		return(TRUE);
	    break;
	case 'o':
	case 'O':
	    if (strcasecmp(s, "on") == 0)
		return(TRUE);
	    if (strcasecmp(s, "off") == 0)
		return(FALSE);
	    break;
	case 'n':
	case 'N':
	    if (strcasecmp(s, "no") == 0)
		return(FALSE);
	    break;
	case 'f':
	case 'F':
	    if (strcasecmp(s, "false") == 0)
		return(FALSE);
	    break;
    }
    return(-1);
}

int
sudo_ldap_read_config()
{
    FILE *fp;
    char *cp, *keyword, *value;
    struct ldap_config_table *cur;

    /* defaults */
    ldap_conf.version = 3;
    ldap_conf.port = -1;
    ldap_conf.tls_checkpeer = -1;
    ldap_conf.timelimit = -1;
    ldap_conf.bind_timelimit = -1;
    ldap_conf.use_sasl = -1;
    ldap_conf.rootuse_sasl = -1;

    if ((fp = fopen(_PATH_LDAP_CONF, "r")) == NULL)
	return(FALSE);

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

	/* Look up keyword in config table. */
	for (cur = ldap_conf_table; cur->conf_str != NULL; cur++) {
	    if (strcasecmp(keyword, cur->conf_str) == 0) {
		switch (cur->type) {
		case CONF_BOOL:
		    *(int *)(cur->valp) = _atobool(value);
		    break;
		case CONF_INT:
		    *(int *)(cur->valp) = atoi(value);
		    break;
		case CONF_STR:
		    efree(*(char **)(cur->valp));
		    *(char **)(cur->valp) = estrdup(value);
		    break;
		}
		break;
	    }
	}
    }
    fclose(fp);

    if (!ldap_conf.host)
	ldap_conf.host = "localhost";

    if (ldap_conf.bind_timelimit > 0)
	ldap_conf.bind_timelimit *= 1000;	/* convert to ms */

    if (ldap_conf.debug > 1) {
	fprintf(stderr, "LDAP Config Summary\n");
	fprintf(stderr, "===================\n");
#ifdef HAVE_LDAP_INITIALIZE
	if (ldap_conf.uri) {
	    fprintf(stderr, "uri              %s\n", ldap_conf.uri);
	} else
#endif
	{
	    fprintf(stderr, "host             %s\n", ldap_conf.host ?
		ldap_conf.host : "(NONE)");
	    fprintf(stderr, "port             %d\n", ldap_conf.port);
	}
	fprintf(stderr, "ldap_version     %d\n", ldap_conf.version);

	fprintf(stderr, "sudoers_base     %s\n", ldap_conf.base ?
	    ldap_conf.base : "(NONE) <---Sudo will ignore ldap)");
	fprintf(stderr, "binddn           %s\n", ldap_conf.binddn ?
	    ldap_conf.binddn : "(anonymous)");
	fprintf(stderr, "bindpw           %s\n", ldap_conf.bindpw ?
	    ldap_conf.bindpw : "(anonymous)");
	if (ldap_conf.bind_timelimit > 0)
	    fprintf(stderr, "bind_timelimit   %d\n", ldap_conf.bind_timelimit);
	if (ldap_conf.timelimit > 0)
	    fprintf(stderr, "timelimit        %d\n", ldap_conf.timelimit);
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
	return(FALSE);		/* if no base is defined, ignore LDAP */

    /*
     * Interpret SSL option
     */
    if (ldap_conf.ssl != NULL) {
	    if (strcasecmp(ldap_conf.ssl, "start_tls") == 0)
		ldap_conf.ssl_mode = SUDO_LDAP_STARTTLS;
	    else if (_atobool(ldap_conf.ssl))
		ldap_conf.ssl_mode = SUDO_LDAP_SSL;
    }

    /* Use port 389 for plaintext LDAP and port 636 for SSL LDAP */
    if (ldap_conf.port < 0)
	ldap_conf.port =
	    ldap_conf.ssl_mode == SUDO_LDAP_SSL ? LDAPS_PORT : LDAP_PORT;

    /* If rootbinddn set, read in /etc/ldap.secret if it exists. */
    if (ldap_conf.rootbinddn) {
	if ((fp = fopen(_PATH_LDAP_SECRET, "r")) != NULL) {
	    if ((cp = sudo_parseln(fp)) != NULL) {
		/* copy to bindpw and binddn */
		efree(ldap_conf.bindpw);
		ldap_conf.bindpw = estrdup(cp);
		efree(ldap_conf.binddn);
		ldap_conf.binddn = ldap_conf.rootbinddn;
		ldap_conf.rootbinddn = NULL;
	    }
	    fclose(fp);
	}
    }
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
		fclose(fp);
	    } else {
		/* Can't open it, just ignore the entry. */
		efree(ldap_conf.krb5_ccname);
		ldap_conf.krb5_ccname = NULL;
	    }
	}
    }
#endif
    return(TRUE);
}

/*
 * Like sudo_ldap_lookup(), except we just print entries.
 */
void
sudo_ldap_display_privs(nss, pw)
    struct sudo_nss *nss;
    struct passwd *pw;
{
    LDAP *ld = (LDAP *) nss->handle;
    LDAPMessage *entry = NULL, *result = NULL;	/* used for searches */
    char *filt;					/* used to parse attributes */
    char *dn, **edn, **v, **p;
    int rc, do_netgr;

    if (ld == NULL)
	return;

    /*
     * First, get (and display) the global Options.
     */
    rc = ldap_search_s(ld, ldap_conf.base, LDAP_SCOPE_SUBTREE,
	"cn=defaults", NULL, 0, &result);
    if (rc == LDAP_SUCCESS && (entry = ldap_first_entry(ld, result))) {
	v = ldap_get_values(ld, entry, "sudoOption");
	if (v != NULL) {
	    fputs("Global LDAP options:\n  ", stdout);
	    for (p = v; *p != NULL; p++) {
		if (p != v)
		    fputs("\n  ", stdout);
		fputs(*p, stdout);
	    }
	    putchar('\n');
	    ldap_value_free(v);
	}
    }
    if (result) {
	ldap_msgfree(result);
	result = NULL;
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
     */
    for (do_netgr = 0; do_netgr < 2; do_netgr++) {
	filt = do_netgr ? estrdup("sudoUser=+*") : sudo_ldap_build_pass1(pw);
	DPRINTF(("ldap search '%s'", filt), 1);
	rc = ldap_search_s(ld, ldap_conf.base, LDAP_SCOPE_SUBTREE, filt,
	    NULL, 0, &result);
	efree(filt);
	if (rc != LDAP_SUCCESS)
	    continue;	/* no entries for this pass */

	/* print each matching entry */
	LDAP_FOREACH(entry, ld, result) {
	    if ((!do_netgr ||
		sudo_ldap_check_user_netgroup(ld, entry, pw->pw_passwd)) &&
		sudo_ldap_check_host(ld, entry)) {

		/* collect the dn, only show the rdn */
		dn = ldap_get_dn(ld, entry);
		edn = dn ? ldap_explode_dn(dn, 1) : NULL;
		printf("\nLDAP Role: %s\n", (edn && *edn) ? *edn : "UNKNOWN");
		if (dn)
		    ldap_memfree(dn);
		if (edn)
		    ldap_value_free(edn);

		/* get the Option Values from the entry */
		v = ldap_get_values(ld, entry, "sudoOption");
		if (v != NULL) {
		    fputs("  Options:\n    ", stdout);
		    for (p = v; *p != NULL; p++) {
			if (p != v)
			    fputs("\n    ", stdout);
			fputs(*p, stdout);
		    }
		    putchar('\n');
		    ldap_value_free(v);
		}

		/* get the RunAsUser Values from the entry */
		v = ldap_get_values(ld, entry, "sudoRunAsUser");
		if (v == NULL)
		    v = ldap_get_values(ld, entry, "sudoRunAs");
		if (v != NULL) {
		    fputs("  RunAsUsers: ", stdout);
		    for (p = v; *p != NULL; p++) {
			if (p != v)
			    fputs(", ", stdout);
			fputs(*p, stdout);
		    }
		    putchar('\n');
		    ldap_value_free(v);
		}

		/* get the RunAsGroup Values from the entry */
		v = ldap_get_values(ld, entry, "sudoRunAsGroup");
		if (v != NULL) {
		    fputs("  RunAsGroups: ", stdout);
		    for (p = v; *p != NULL; p++) {
			if (p != v)
			    fputs(", ", stdout);
			fputs(*p, stdout);
		    }
		    putchar('\n');
		    ldap_value_free(v);
		}

		/* get the Command Values from the entry */
		v = ldap_get_values(ld, entry, "sudoCommand");
		if (v != NULL) {
		    fputs("  Commands:\n    ", stdout);
		    for (p = v; *p != NULL; p++) {
			if (p != v)
			    fputs("\n    ", stdout);
			fputs(*p, stdout);
		    }
		    putchar('\n');
		    ldap_value_free(v);
		} else {
		    puts("  Commands: NONE");
		}
	    }
	}
	ldap_msgfree(result);
	result = NULL;
    }
}

int
sudo_ldap_display_cmnd(nss, pw)
    struct sudo_nss *nss;
    struct passwd *pw;
{
    LDAP *ld = (LDAP *) nss->handle;
    LDAPMessage *entry = NULL, *result = NULL;	/* used for searches */
    char *filt;					/* used to parse attributes */
    int rc, found, do_netgr;			/* temp/final return values */

    if (ld == NULL)
	return(1);

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
     */
    for (found = FALSE, do_netgr = 0; !found && do_netgr < 2; do_netgr++) {
	filt = do_netgr ? estrdup("sudoUser=+*") : sudo_ldap_build_pass1(pw);
	DPRINTF(("ldap search '%s'", filt), 1);
	rc = ldap_search_s(ld, ldap_conf.base, LDAP_SCOPE_SUBTREE, filt,
	    NULL, 0, &result);
	efree(filt);
	if (rc != LDAP_SUCCESS)
	    continue;	/* no entries for this pass */

	LDAP_FOREACH(entry, ld, result) {
	    if ((!do_netgr ||
		sudo_ldap_check_user_netgroup(ld, entry, pw->pw_name)) &&
		sudo_ldap_check_host(ld, entry) &&
		sudo_ldap_check_command(ld, entry, NULL) &&
		sudo_ldap_check_runas(ld, entry)) {

		found = TRUE;
		break;
	    }
	}
	ldap_msgfree(result);
	result = NULL;
    }

    if (found)
	printf("%s%s%s\n", safe_cmnd ? safe_cmnd : user_cmnd,
	    user_args ? " " : "", user_args ? user_args : "");
   return(!found);
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
	    return(LDAP_PARAM_ERROR);

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
    return(LDAP_SUCCESS);
}
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */

/*
 * Set LDAP options based on the config table.
 */
int
sudo_ldap_set_options(ld)
    LDAP *ld;
{
    struct ldap_config_table *cur;
    int rc;

    /* Set ber options */
#ifdef LBER_OPT_DEBUG_LEVEL
    if (ldap_conf.ldap_debug)
	ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &ldap_conf.ldap_debug);
#endif

    /* Set simple LDAP options */
    for (cur = ldap_conf_table; cur->conf_str != NULL; cur++) {
	LDAP *conn;
	int ival;
	char *sval;

	if (cur->opt_val == -1)
	    continue;

	conn = cur->connected ? ld : NULL;
	switch (cur->type) {
	case CONF_BOOL:
	case CONF_INT:
	    ival = *(int *)(cur->valp);
	    if (ival >= 0) {
		rc = ldap_set_option(conn, cur->opt_val, &ival);
		if (rc != LDAP_OPT_SUCCESS) {
		    warningx("ldap_set_option: %s -> %d: %s",
			cur->conf_str, ival, ldap_err2string(rc));
		    return(-1);
		}
		DPRINTF(("ldap_set_option: %s -> %d", cur->conf_str, ival), 1);
	    }
	    break;
	case CONF_STR:
	    sval = *(char **)(cur->valp);
	    if (sval != NULL) {
		rc = ldap_set_option(conn, cur->opt_val, sval);
		if (rc != LDAP_OPT_SUCCESS) {
		    warningx("ldap_set_option: %s -> %s: %s",
			cur->conf_str, sval, ldap_err2string(rc));
		    return(-1);
		}
		DPRINTF(("ldap_set_option: %s -> %s", cur->conf_str, sval), 1);
	    }
	    break;
	}
    }

#ifdef LDAP_OPT_NETWORK_TIMEOUT
    /* Convert bind_timelimit to a timeval */
    if (ldap_conf.bind_timelimit > 0) {
	struct timeval tv;
	tv.tv_sec = ldap_conf.bind_timelimit / 1000;
	tv.tv_usec = 0;
	rc = ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &tv);
	if (rc != LDAP_OPT_SUCCESS) {
	    warningx("ldap_set_option(NETWORK_TIMEOUT, %ld): %s",
		(long)tv.tv_sec, ldap_err2string(rc));
	    return(-1);
	}
	DPRINTF(("ldap_set_option(LDAP_OPT_NETWORK_TIMEOUT, %ld)\n",
	    (long)tv.tv_sec), 1);
    }
#endif

#if defined(LDAP_OPT_X_TLS) && !defined(HAVE_LDAPSSL_INIT)
    if (ldap_conf.ssl_mode == SUDO_LDAP_SSL) {
	int val = LDAP_OPT_X_TLS_HARD;
	rc = ldap_set_option(ld, LDAP_OPT_X_TLS, &val);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_set_option(LDAP_OPT_X_TLS, LDAP_OPT_X_TLS_HARD): %s",
		ldap_err2string(rc));
	    return(-1);
	}

    }
#endif
    return(0);
}

/*
 * Open a connection to the LDAP server.
 * Returns 0 on success and non-zero on failure.
 */
int
sudo_ldap_open(nss)
    struct sudo_nss *nss;
{
    LDAP *ld;
    const char *old_ccname = user_ccname;
    int rc, ldapnoinit = FALSE;
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
    unsigned int status;
#endif

    if (!sudo_ldap_read_config())
	return(-1);

    /* Prevent reading of user ldaprc and system defaults. */
    if (getenv("LDAPNOINIT") == NULL) {
	ldapnoinit = TRUE;
	sudo_setenv("LDAPNOINIT", "1", TRUE);
    }

#ifdef HAVE_LDAPSSL_INIT
    if (ldap_conf.ssl_mode == SUDO_LDAP_SSL) {
	DPRINTF(("ldapssl_clientauth_init(%s, %s)",
	    ldap_conf.tls_certfile ? ldap_conf.tls_certfile : "NULL",
	    ldap_conf.tls_keyfile ? ldap_conf.tls_keyfile : "NULL"), 2);
	rc = ldapssl_clientauth_init(ldap_conf.tls_certfile, NULL,
	    ldap_conf.tls_keyfile != NULL, ldap_conf.tls_keyfile, NULL);
	if (rc != LDAP_SUCCESS) {
	    warningx("unable to initialize SSL cert and key db: %s",
		ldapssl_err2string(rc));
	    return(-1);
	}
    }
#endif /* HAVE_LDAPSSL_INIT */

    /* Connect to LDAP server */
#ifdef HAVE_LDAP_INITIALIZE
    if (ldap_conf.uri) {
	DPRINTF(("ldap_initialize(ld, %s)", ldap_conf.uri), 2);
	rc = ldap_initialize(&ld, ldap_conf.uri);
	if (rc != LDAP_SUCCESS) {
	    warningx("unable to initialize LDAP: %s", ldap_err2string(rc));
	    return(-1);
	}
    } else
#endif /* HAVE_LDAP_INITIALIZE */
    {
#ifdef HAVE_LDAPSSL_INIT
	DPRINTF(("ldapssl_init(%s, %d, %d)", ldap_conf.host, ldap_conf.port,
	    ldap_conf.ssl_mode == SUDO_LDAP_SSL), 2);
	ld = ldapssl_init(ldap_conf.host, ldap_conf.port,
	    ldap_conf.ssl_mode == SUDO_LDAP_SSL);
#else
	DPRINTF(("ldap_init(%s, %d)", ldap_conf.host, ldap_conf.port), 2);
	ld = ldap_init(ldap_conf.host, ldap_conf.port);
#endif
	if (ld == NULL) {
	    warning("unable to initialize LDAP");
	    return(-1);
	}
    }

    if (ldapnoinit)
	sudo_unsetenv("LDAPNOINIT");

    /* Set LDAP options */
    if (sudo_ldap_set_options(ld) < 0)
	return(-1);

    if (ldap_conf.ssl_mode == SUDO_LDAP_STARTTLS) {
#ifdef HAVE_LDAP_START_TLS_S
	rc = ldap_start_tls_s(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_start_tls_s(): %s", ldap_err2string(rc));
	    return(-1);
	}
	DPRINTF(("ldap_start_tls_s() ok"), 1);
#else
	warningx("start_tls specified but LDAP libs do not support ldap_start_tls_s()");
#endif /* HAVE_LDAP_START_TLS_S */
    }

#ifdef HAVE_LDAP_SASL_INTERACTIVE_BIND_S
    if (ldap_conf.rootuse_sasl == TRUE ||
	(ldap_conf.rootuse_sasl != FALSE && ldap_conf.use_sasl == TRUE)) {
	void *auth_id = ldap_conf.rootsasl_auth_id ?
	    ldap_conf.rootsasl_auth_id : ldap_conf.sasl_auth_id;

	if (ldap_conf.krb5_ccname != NULL) {
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
	    if (gss_krb5_ccache_name(&status, ldap_conf.krb5_ccname, &old_ccname)
		!= GSS_S_COMPLETE) {
		old_ccname = NULL;
		DPRINTF(("gss_krb5_ccache_name() failed: %d", status), 1);
	    }
#else
	    sudo_setenv("KRB5CCNAME", ldap_conf.krb5_ccname, TRUE);
#endif
	}
	rc = ldap_sasl_interactive_bind_s(ld, ldap_conf.binddn, "GSSAPI",
	    NULL, NULL, LDAP_SASL_QUIET, sudo_ldap_sasl_interact, auth_id);
	if (ldap_conf.krb5_ccname != NULL) {
#ifdef HAVE_GSS_KRB5_CCACHE_NAME
	    if (gss_krb5_ccache_name(&status, old_ccname, NULL) != GSS_S_COMPLETE)
		    DPRINTF(("gss_krb5_ccache_name() failed: %d", status), 1);
#else
	    if (old_ccname != NULL)
		sudo_setenv("KRB5CCNAME", old_ccname, TRUE);
	    else
		sudo_unsetenv("KRB5CCNAME");
#endif
	}
	if (rc != LDAP_SUCCESS) {
	    warningx("ldap_sasl_interactive_bind_s(): %s", ldap_err2string(rc));
	    return(-1);
	}
	DPRINTF(("ldap_sasl_interactive_bind_s() ok"), 1);
    } else
#endif /* HAVE_LDAP_SASL_INTERACTIVE_BIND_S */
    {
	/* Actually connect */
	if ((rc = ldap_simple_bind_s(ld, ldap_conf.binddn, ldap_conf.bindpw))) {
	    warningx("ldap_simple_bind_s(): %s", ldap_err2string(rc));
	    return(-1);
	}
	DPRINTF(("ldap_simple_bind_s() ok"), 1);
    }

    nss->handle = ld;
    return(0);
}

int
sudo_ldap_setdefs(nss)
    struct sudo_nss *nss;
{
    LDAP *ld = (LDAP *) nss->handle;
    LDAPMessage *entry = NULL, *result = NULL;	 /* used for searches */
    int rc;					 /* temp return value */

    if (ld == NULL)
	return(-1);

    rc = ldap_search_s(ld, ldap_conf.base, LDAP_SCOPE_SUBTREE,
	"cn=defaults", NULL, 0, &result);
    if (rc == 0 && (entry = ldap_first_entry(ld, result))) {
	DPRINTF(("found:%s", ldap_get_dn(ld, entry)), 1);
	sudo_ldap_parse_options(ld, entry);
    } else
	DPRINTF(("no default options found!"), 1);

    if (result)
	ldap_msgfree(result);

    return(0);
}

/*
 * like sudoers_lookup() - only LDAP style
 */
int
sudo_ldap_lookup(nss, pwflag)
    struct sudo_nss *nss;
    int pwflag;
{
    LDAP *ld = (LDAP *) nss->handle;
    LDAPMessage *entry = NULL, *result = NULL;	/* used for searches */
    char *filt;					/* used to parse attributes */
    int do_netgr, rc, ret;			/* temp/final return values */
    int setenv_implied;
    int ldap_user_matches = FALSE, ldap_host_matches = FALSE; /* flags */
    struct passwd *pw = list_pw ? list_pw : sudo_user.pw;

    if (ld == NULL)
	return(0);	/* XXX - if only LDAP and we return 0, it will misbehasve */

    if (pwflag) {
	int doauth = UNSPEC;
	enum def_tupple pwcheck = 
	    (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;

	for (ret = 0, do_netgr = 0; !ret && do_netgr < 2; do_netgr++) {
	    filt = do_netgr ? estrdup("sudoUser=+*") : sudo_ldap_build_pass1(pw);
	    rc = ldap_search_s(ld, ldap_conf.base, LDAP_SCOPE_SUBTREE, filt,
		NULL, 0, &result);
	    efree(filt);
	    if (rc != LDAP_SUCCESS)
		continue;

	    LDAP_FOREACH(entry, ld, result) {
		/* only verify netgroup matches in pass 2 */
		if (do_netgr && !sudo_ldap_check_user_netgroup(ld, entry, pw->pw_name))
		    continue;

		ldap_user_matches = TRUE;
		if (sudo_ldap_check_host(ld, entry)) {
		    ldap_host_matches = TRUE;
		    if ((pwcheck == any && doauth != FALSE) ||
			(pwcheck == all && doauth == FALSE))
			doauth = sudo_ldap_check_bool(ld, entry, "authenticate");
		    /* Only check the command when listing another user. */
		    if (user_uid == 0 || list_pw == NULL ||
			user_uid == list_pw->pw_uid ||
			sudo_ldap_check_command(ld, entry, NULL)) {
			ret = 1;
			break;	/* end foreach */
		    }
		}
	    }
	    ldap_msgfree(result);
	    result = NULL;
	}
	if (ret || user_uid == 0) {
	    ret = VALIDATE_OK;
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
     */
    setenv_implied = FALSE;
    for (ret = 0, do_netgr = 0; !ret && do_netgr < 2; do_netgr++) {
	filt = do_netgr ? estrdup("sudoUser=+*") : sudo_ldap_build_pass1(pw);
	DPRINTF(("ldap search '%s'", filt), 1);
	rc = ldap_search_s(ld, ldap_conf.base, LDAP_SCOPE_SUBTREE, filt,
	    NULL, 0, &result);
	if (rc != LDAP_SUCCESS)
	    DPRINTF(("nothing found for '%s'", filt), 1);
	efree(filt);

	/* parse each entry returned from this most recent search */
	if (rc == LDAP_SUCCESS) {
	    LDAP_FOREACH(entry, ld, result) {
		DPRINTF(("found:%s", ldap_get_dn(ld, entry)), 1);
		if (
		/* first verify user netgroup matches - only if in pass 2 */
		    (!do_netgr || sudo_ldap_check_user_netgroup(ld, entry, pw->pw_name)) &&
		/* remember that user matched */
		    (ldap_user_matches = TRUE) &&
		/* verify host match */
		    sudo_ldap_check_host(ld, entry) &&
		/* remember that host matched */
		    (ldap_host_matches = TRUE) &&
		/* verify command match */
		    sudo_ldap_check_command(ld, entry, &setenv_implied) &&
		/* verify runas match */
		    sudo_ldap_check_runas(ld, entry)
		    ) {
		    /* We have a match! */
		    DPRINTF(("Perfect Match!"), 1);
		    /* pick up any options */
		    if (setenv_implied)
			def_setenv = TRUE;
		    sudo_ldap_parse_options(ld, entry);
		    /* make sure we don't reenter loop */
		    ret = VALIDATE_OK;
		    /* break from inside for loop */
		    break;
		}
	    }
	    ldap_msgfree(result);
	    result = NULL;
	}
    }

done:
    DPRINTF(("user_matches=%d", ldap_user_matches), 1);
    DPRINTF(("host_matches=%d", ldap_host_matches), 1);

    if (!ISSET(ret, VALIDATE_OK)) {
	/* we do not have a match */
	ret = VALIDATE_NOT_OK;
	if (pwflag && list_pw == NULL)
	    SET(ret, FLAG_NO_CHECK);
	else if (!ldap_user_matches)
	    SET(ret, FLAG_NO_USER);
	else if (!ldap_host_matches)
	    SET(ret, FLAG_NO_HOST);
    }
    DPRINTF(("sudo_ldap_lookup(%d)=0x%02x", pwflag, ret), 1);

    return(ret);
}

/*
 * shut down LDAP connection
 */
int
sudo_ldap_close(nss)
    struct sudo_nss *nss;
{
    if (nss->handle != NULL)
	ldap_unbind_s((LDAP *) nss->handle);
    nss->handle = NULL;
    return(0);
}

/*
 * STUB
 */
int
sudo_ldap_parse(nss)
    struct sudo_nss *nss;
{
    return(0);
}
