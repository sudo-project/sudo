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
#include <errno.h>
#ifdef HAVE_LBER_H
# include <lber.h>
#endif
#include <ldap.h>

#include "sudo.h"
#include "parse.h"

#ifndef lint
__unused static const char rcsid[] = "$Sudo$";
#endif /* lint */

/* LDAP code below */

#ifndef BUF_SIZ
# define BUF_SIZ 1024
#endif

#ifndef LDAP_OPT_SUCCESS
# define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

/* ldap configuration structure */
struct ldap_config {
    char *host;
    int port;
    int version;
    char *uri;
    char *binddn;
    char *bindpw;
    char *base;
    char *ssl;
    int tls_checkpeer;
    char *tls_cacertfile;
    char *tls_cacertdir;
    char *tls_random_file;
    char *tls_cipher_suite;
    char *tls_certfile;
    char *tls_keyfile;
    int debug;
} ldap_conf;

/*
 * Walk through search results and return TRUE if we have a matching
 * netgroup, else FALSE.
 */
int
sudo_ldap_check_user_netgroup(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    char **v = NULL, **p = NULL;
    int ret = FALSE;

    if (!entry)
	return(ret);

    /* get the values from the entry */
    v = ldap_get_values(ld, entry, "sudoUser");

    /* walk through values */
    for (p = v; p && *p && !ret; p++) {
	if (ldap_conf.debug > 1)
	    printf("ldap sudoUser netgroup '%s' ...", *p);

	/* match any */
	if (netgr_matches(*p, NULL, NULL, user_name))
	    ret = TRUE;

	if (ldap_conf.debug > 1)
	    printf(" %s\n", ret ? "MATCH!" : "not");
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
	if (ldap_conf.debug > 1)
	    printf("ldap sudoHost '%s' ...", *p);

	/* match any or address or netgroup or hostname */
	if (!strcasecmp(*p, "ALL") || addr_matches(*p) ||
	    netgr_matches(*p, user_host, user_shost, NULL) ||
	    !hostname_matches(user_shost, user_host, *p))
	    ret = TRUE;

	if (ldap_conf.debug > 1)
	    printf(" %s\n", ret ? "MATCH!" : "not");
    }

    if (v)
	ldap_value_free(v);	/* cleanup */

    return(ret);
}

/*
 * Walk through search results and return TRUE if we have a runas match,
 * else FALSE.
 * Since the runas directive in /etc/sudoers is optional, so is sudoRunAs.
 */
int
sudo_ldap_check_runas(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    char **v = NULL, **p = NULL;
    int ret = FALSE;

    if (!entry)
	return(ret);

    /* get the values from the entry */
    v = ldap_get_values(ld, entry, "sudoRunAs");

    /*
     * BUG:
     * 
     * if runas is not specified on the command line, the only information as to
     * which user to run as is in the runas_default option. We should check
     * check to see if we have the local option present. Unfortunately we
     * don't parse these options until after this routine says yes * or no.
     * The query has already returned, so we could peek at the attribute
     * values here though.
     * 
     * For now just require users to always use -u option unless its set in the
     * global defaults. This behaviour is no different than the global
     * /etc/sudoers.
     * 
     * Sigh - maybe add this feature later
     * 
     */

    /*
     * If there are no runas entries, then match the runas_default with whats
     * on the command line
     */
    if (!v)
	ret = !strcasecmp(*user_runas, def_runas_default);

    /*
     * What about the case where exactly one runas is specified in the config
     * and the user forgets the -u option, should we switch it?
     * Probably not...
     */

    /* walk through values returned, looking for a match */
    for (p = v; p && *p && !ret; p++) {
	if (ldap_conf.debug > 1)
	    printf("ldap sudoRunAs '%s' ...", *p);

	if (!strcasecmp(*p, *user_runas) || !strcasecmp(*p, "ALL")) 
	    ret = TRUE;

	if (ldap_conf.debug > 1)
	    printf(" %s\n", ret ? "MATCH!" : "not");
    }

    if (v)
	ldap_value_free(v);	/* cleanup */

    return(ret);
}

/*
 * Walk through search results and return TRUE if we have a command match.
 */
int
sudo_ldap_check_command(ld, entry)
    LDAP *ld;
    LDAPMessage *entry;
{
    char *allowed_cmnd, *allowed_args, **v = NULL, **p = NULL;
    int foundbang, ret = FALSE;

    if (!entry)
	return(ret);

    v = ldap_get_values(ld, entry, "sudoCommand");

    /* get_first_entry */
    for (p = v; p && *p && ret >= 0; p++) {
	if (ldap_conf.debug > 1)
	    printf("ldap sudoCommand '%s' ...", *p);

	/* Match against ALL ? */
	if (!strcasecmp(*p, "ALL")) {
	    ret = TRUE;
	    if (safe_cmnd)
		free(safe_cmnd);
	    safe_cmnd = estrdup(user_cmnd);
	    if (ldap_conf.debug > 1)
		printf(" MATCH!\n");
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
	    if (ldap_conf.debug > 1)
		printf(" MATCH!\n");
	} else if (ldap_conf.debug > 1) {
	    printf(" not\n");
	}

	free(allowed_cmnd);	/* cleanup */
    }

    if (v)
	ldap_value_free(v);	/* more cleanup */

    /* return TRUE if we found at least one ALLOW and no DENY */
    return(ret > 0);
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
    char op, *var, *val, **v = NULL, **p = NULL;

    if (!entry)
	return;

    v = ldap_get_values(ld, entry, "sudoOption");

    /* walk through options */
    for (p = v; p && *p; p++) {

	if (ldap_conf.debug > 1)
	    printf("ldap sudoOption: '%s'\n", *p);
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
	free(var);
    }

    if (v)
	ldap_value_free(v);
}

/*
 * Concatenate strings, dynamically growing them as necessary.
 * Strings can be arbitrarily long and are allocated/reallocated on
 * the fly.  Make sure to free them when you are done.
 *
 * Usage:
 *
 * char *s=NULL;
 * size_t sz;
 *
 * ncat(&s,&sz,"This ");
 * ncat(&s,&sz,"is ");
 * ncat(&s,&sz,"an ");
 * ncat(&s,&sz,"arbitrarily ");
 * ncat(&s,&sz,"long ");
 * ncat(&s,&sz,"string!");
 *
 * printf("String Value='%s', but has %d bytes allocated\n",s,sz);
 *
 */
void
ncat(s, sz, src)
    char **s;
    size_t *sz;
    char *src;
{
    size_t nsz;

    /* handle initial alloc */
    if (*s == NULL) {
	*s = estrdup(src);
	*sz = strlen(src) + 1;
	return;
    }
    /* handle realloc */
    nsz = strlen(*s) + strlen(src) + 1;
    if (*sz < nsz)
	*s = erealloc((void *) *s, *sz = nsz * 2);
    strlcat(*s, src, *sz);
}

/*
 * builds together a filter to check against ldap
 */
char *
sudo_ldap_build_pass1()
{
    struct group *grp;
    size_t sz;
    char *b = NULL;
    int i;

    /* global OR */
    ncat(&b, &sz, "(|");

    /* build filter sudoUser=user_name */
    ncat(&b, &sz, "(sudoUser=");
    ncat(&b, &sz, user_name);
    ncat(&b, &sz, ")");

    /* Append primary group */
    grp = sudo_getgrgid(getgid());
    if (grp != NULL) {
	ncat(&b, &sz, "(sudoUser=%");
	ncat(&b, &sz, grp -> gr_name);
	ncat(&b, &sz, ")");
    }

    /* Append supplementary groups */
    for (i = 0; i < user_ngroups; i++) {
	if ((grp = sudo_getgrgid(user_groups[i])) != NULL) {
	    ncat(&b, &sz, "(sudoUser=%");
	    ncat(&b, &sz, grp -> gr_name);
	    ncat(&b, &sz, ")");
	}
    }

    /* Add ALL to list */
    ncat(&b, &sz, "(sudoUser=ALL)");

    /* End of OR List */
    ncat(&b, &sz, ")");

    return(b);
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
    FILE *f;
    char buf[BUF_SIZ], *c, *keyword, *value;

    ldap_conf.tls_checkpeer = -1;	/* default */

    if ((f = fopen(_PATH_LDAP_CONF, "r")) == NULL)
	return(FALSE);
    while (fgets(buf, sizeof(buf), f)) {
	c = buf;
	if (*c == '#')
	    continue;		/* ignore comment */
	if (*c == '\n')
	    continue;		/* skip newline */
	if (!*c)
	    continue;		/* incomplete last line */

	/* skip whitespace before keyword */
	while (isspace((unsigned char) *c))
	    c++;
	keyword = c;

	/* properly terminate keyword string */
	while (*c && !isspace((unsigned char) *c))
	    c++;
	if (*c)
	    *c++ = '\0';	/* terminate keyword */

	/* skip whitespace before value */
	while (isspace((unsigned char) *c))
	    c++;
	value = c;

	/* trim whitespace after value */
	while (*c)
	    c++;		/* wind to end */
	while (--c > value && isspace((unsigned char) *c))
	    *c = '\0';

	/* The following macros make the code much more readable */

#define MATCH_S(x,y) if (!strcasecmp(keyword,x)) \
    { if (y) free(y); y=estrdup(value); }
#define MATCH_I(x,y) if (!strcasecmp(keyword,x)) { y=atoi(value); }
#define MATCH_B(x,y) if (!strcasecmp(keyword,x)) { y=_atobool(value); }

	/*
	 * Parse values using a continues chain of if else if else if else if
	 * else ...
	 */
	MATCH_S("host", ldap_conf.host)
	    else
	MATCH_I("port", ldap_conf.port)
	    else
	MATCH_S("ssl", ldap_conf.ssl)
	    else
	MATCH_B("tls_checkpeer", ldap_conf.tls_checkpeer)
	    else
	MATCH_S("tls_cacertfile", ldap_conf.tls_cacertfile)
	    else
	MATCH_S("tls_cacertdir", ldap_conf.tls_cacertdir)
	    else
	MATCH_S("tls_randfile", ldap_conf.tls_random_file)
	    else
	MATCH_S("tls_ciphers", ldap_conf.tls_cipher_suite)
	    else
	MATCH_S("tls_cert", ldap_conf.tls_certfile)
	    else
	MATCH_S("tls_key", ldap_conf.tls_keyfile)
	    else
	MATCH_I("ldap_version", ldap_conf.version)
	    else
	MATCH_S("uri", ldap_conf.uri)
	    else
	MATCH_S("binddn", ldap_conf.binddn)
	    else
	MATCH_S("bindpw", ldap_conf.bindpw)
	    else
	MATCH_S("sudoers_base", ldap_conf.base)
	    else
	MATCH_I("sudoers_debug", ldap_conf.debug)
	    else {

	    /*
	     * The keyword was unrecognized.  Since this config file is
	     * shared by multiple programs, it is appropriate to silently
	     * ignore options this program does not understand
	     */
	}

    }
    fclose(f);

    /* defaults */
    if (!ldap_conf.version)
	ldap_conf.version = 3;
    if (!ldap_conf.port)
	ldap_conf.port = 389;
    if (!ldap_conf.host)
	ldap_conf.host = estrdup("localhost");

    if (ldap_conf.debug > 1) {
	printf("LDAP Config Summary\n");
	printf("===================\n");
#ifdef HAVE_LDAP_INITIALIZE
	if (ldap_conf.uri) {
	    printf("uri          %s\n", ldap_conf.uri);
	} else
#endif
	{
	    printf("host         %s\n", ldap_conf.host ?
		ldap_conf.host : "(NONE)");
	    printf("port         %d\n", ldap_conf.port);
	}
	printf("ldap_version %d\n", ldap_conf.version);

	printf("sudoers_base %s\n", ldap_conf.base ?
	    ldap_conf.base : "(NONE) <---Sudo will ignore ldap)");
	printf("binddn       %s\n", ldap_conf.binddn ?
	    ldap_conf.binddn : "(anonymous)");
	printf("bindpw       %s\n", ldap_conf.bindpw ?
	    ldap_conf.bindpw : "(anonymous)");
#ifdef HAVE_LDAP_START_TLS_S
	printf("ssl          %s\n", ldap_conf.ssl ?
	    ldap_conf.ssl : "(no)");
#endif
	printf("===================\n");
    }
    if (!ldap_conf.base)
	return(FALSE);		/* if no base is defined, ignore LDAP */
    return(TRUE);
}

/*
 * like perl's join(sep,@ARGS)
 */
char *
 _ldap_join_values(sep, v)
    char *sep;
    char **v;
{
    char *b = NULL, **p = NULL;
    size_t sz = 0;

    /* paste values together */
    for (p = v; p && *p; p++) {
	if (p != v && sep != NULL)
	    ncat(&b, &sz, sep);	/* append seperator */
	ncat(&b, &sz, *p);	/* append value */
    }

    /* sanity check */
    if (b[0] == '\0') {
	/* something went wrong, put something here */
	ncat(&b, &sz, "(empty list)");	/* append value */
    }

    return(b);
}

char *sudo_ldap_cm_list = NULL;
size_t sudo_ldap_cm_list_size;

#define SAVE_LIST(x) ncat(&sudo_ldap_cm_list,&sudo_ldap_cm_list_size,(x))
/*
 * Walks through search result and returns TRUE if we have a
 * command match
 */
int
sudo_ldap_add_match(ld, entry, pwflag)
    LDAP *ld;
    LDAPMessage *entry;
    int pwflag;
{
    char *dn, **edn, **v = NULL;

    /* if we are not collecting matches, then don't save them */
    if (pwflag != I_LISTPW)
	return(TRUE);

    /* collect the dn, only show the rdn */
    dn = ldap_get_dn(ld, entry);
    edn = dn ? ldap_explode_dn(dn, 1) : NULL;
    SAVE_LIST("\nLDAP Role: ");
    SAVE_LIST((edn && *edn) ? *edn : "UNKNOWN");
    SAVE_LIST("\n");
    if (dn)
	ldap_memfree(dn);
    if (edn)
	ldap_value_free(edn);

    /* get the Runas Values from the entry */
    v = ldap_get_values(ld, entry, "sudoRunAs");
    if (v && *v) {
	SAVE_LIST("  RunAs: (");
	SAVE_LIST(_ldap_join_values(", ", v));
	SAVE_LIST(")\n");
    }
    if (v)
	ldap_value_free(v);

    /* get the Command Values from the entry */
    v = ldap_get_values(ld, entry, "sudoCommand");
    if (v && *v) {
	SAVE_LIST("  Commands:\n    ");
	SAVE_LIST(_ldap_join_values("\n    ", v));
	SAVE_LIST("\n");
    } else {
	SAVE_LIST("  Commands: NONE\n");
    }
    if (v)
	ldap_value_free(v);

    return(FALSE);		/* Don't stop at the first match */
}
#undef SAVE_LIST

void
sudo_ldap_display_privs()
{
    if (sudo_ldap_cm_list != NULL)
	printf("%s", sudo_ldap_cm_list);
}

/*
 * Open a connection to the LDAP server.
 */
VOID *
sudo_ldap_open()
{
    LDAP *ld = NULL;
    int rc;					/* temp return value */

    if (!sudo_ldap_read_config())
	return(NULL);

    /* macro to set option, error on failure plus consistent debugging */
#define SET_OPT(opt,optname,val) \
  if (ldap_conf.val!=NULL) { \
    if (ldap_conf.debug>1) fprintf(stderr, \
           "ldap_set_option(LDAP_OPT_%s,\"%s\")\n",optname,ldap_conf.val); \
    rc=ldap_set_option(ld,opt,ldap_conf.val); \
    if(rc != LDAP_OPT_SUCCESS){ \
      fprintf(stderr,"ldap_set_option(LDAP_OPT_%s,\"%s\")=%d: %s\n", \
           optname, ldap_conf.val, rc, ldap_err2string(rc)); \
      return(NULL) ; \
    } \
  } \

    /* like above, but assumes val is in int */
#define SET_OPTI(opt,optname,val) \
    if (ldap_conf.debug>1) fprintf(stderr, \
           "ldap_set_option(LDAP_OPT_%s,0x%02x)\n",optname,ldap_conf.val); \
    rc=ldap_set_option(ld,opt,&ldap_conf.val); \
    if(rc != LDAP_OPT_SUCCESS){ \
      fprintf(stderr,"ldap_set_option(LDAP_OPT_%s,0x%02x)=%d: %s\n", \
           optname, ldap_conf.val, rc, ldap_err2string(rc)); \
      return(NULL) ; \
    } \

    /* attempt to setup ssl options */
#ifdef LDAP_OPT_X_TLS_CACERTFILE
    SET_OPT(LDAP_OPT_X_TLS_CACERTFILE, "X_TLS_CACERTFILE", tls_cacertfile);
#endif /* LDAP_OPT_X_TLS_CACERTFILE */

#ifdef LDAP_OPT_X_TLS_CACERTDIR
    SET_OPT(LDAP_OPT_X_TLS_CACERTDIR, "X_TLS_CACERTDIR", tls_cacertdir);
#endif /* LDAP_OPT_X_TLS_CACERTDIR */

#ifdef LDAP_OPT_X_TLS_CERTFILE
    SET_OPT(LDAP_OPT_X_TLS_CERTFILE, "X_TLS_CERTFILE", tls_certfile);
#endif /* LDAP_OPT_X_TLS_CERTFILE */

#ifdef LDAP_OPT_X_TLS_KEYFILE
    SET_OPT(LDAP_OPT_X_TLS_KEYFILE, "X_TLS_KEYFILE", tls_keyfile);
#endif /* LDAP_OPT_X_TLS_KEYFILE */

#ifdef LDAP_OPT_X_TLS_CIPHER_SUITE
    SET_OPT(LDAP_OPT_X_TLS_CIPHER_SUITE, "X_TLS_CIPHER_SUITE", tls_cipher_suite);
#endif /* LDAP_OPT_X_TLS_CIPHER_SUITE */

#ifdef LDAP_OPT_X_TLS_RANDOM_FILE
    SET_OPT(LDAP_OPT_X_TLS_RANDOM_FILE, "X_TLS_RANDOM_FILE", tls_random_file);
#endif /* LDAP_OPT_X_TLS_RANDOM_FILE */

#ifdef LDAP_OPT_X_TLS_REQUIRE_CERT
    /* check the server certificate? */
    if (ldap_conf.tls_checkpeer != -1) {
	SET_OPTI(LDAP_OPT_X_TLS_REQUIRE_CERT, "X_TLS_REQUIRE_CERT",
	    tls_checkpeer);
    }
#endif /* LDAP_OPT_X_TLS_REQUIRE_CERT */

    /* attempt connect */
#ifdef HAVE_LDAP_INITIALIZE
    if (ldap_conf.uri) {

	if (ldap_conf.debug > 1)
	    fprintf(stderr,
		"ldap_initialize(ld,%s)\n", ldap_conf.uri);

	rc = ldap_initialize(&ld, ldap_conf.uri);
	if (rc) {
	    fprintf(stderr, "ldap_initialize()=%d : %s\n",
		rc, ldap_err2string(rc));
	    return(NULL);
	}
    } else
#endif /* HAVE_LDAP_INITIALIZE */
    if (ldap_conf.host) {

	if (ldap_conf.debug > 1)
	    fprintf(stderr,
		"ldap_init(%s,%d)\n", ldap_conf.host, ldap_conf.port);

	if ((ld = ldap_init(ldap_conf.host, ldap_conf.port)) == NULL) {
	    fprintf(stderr, "ldap_init(): errno=%d : %s\n",
		errno, strerror(errno));
	    return(NULL);
	}
    }
#ifdef LDAP_OPT_PROTOCOL_VERSION

    /* Set the LDAP Protocol version */
    SET_OPTI(LDAP_OPT_PROTOCOL_VERSION, "PROTOCOL_VERSION", version);

#endif /* LDAP_OPT_PROTOCOL_VERSION */

#ifdef HAVE_LDAP_START_TLS_S
    /* Turn on TLS */
    if (ldap_conf.ssl && !strcasecmp(ldap_conf.ssl, "start_tls")) {
	rc = ldap_start_tls_s(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
	    fprintf(stderr, "ldap_start_tls_s(): %d: %s\n", rc,
		ldap_err2string(rc));
	    ldap_unbind(ld);
	    return(NULL);
	}
	if (ldap_conf.debug)
	    printf("ldap_start_tls_s() ok\n");
    }
#endif /* HAVE_LDAP_START_TLS_S */

    /* Actually connect */
    if ((rc = ldap_simple_bind_s(ld, ldap_conf.binddn, ldap_conf.bindpw))) {
	fprintf(stderr, "ldap_simple_bind_s()=%d : %s\n",
	    rc, ldap_err2string(rc));
	return(NULL);
    }
    if (ldap_conf.debug)
	printf("ldap_bind() ok\n");

    return((VOID *) ld);
}

void
sudo_ldap_update_defaults(v)
    VOID *v;
{
    LDAP *ld = (LDAP *) v;
    LDAPMessage *entry = NULL, *result = NULL;	 /* used for searches */
    int rc;					 /* temp return value */

    rc = ldap_search_s(ld, ldap_conf.base, LDAP_SCOPE_ONELEVEL,
	"cn=defaults", NULL, 0, &result);
    if (!rc && (entry = ldap_first_entry(ld, result))) {
	if (ldap_conf.debug)
	    printf("found:%s\n", ldap_get_dn(ld, entry));
	sudo_ldap_parse_options(ld, entry);
    } else {
	if (ldap_conf.debug)
	    printf("no default options found!\n");
    }

    if (result)
	ldap_msgfree(result);
}

/*
 * like sudoers_lookup() - only LDAP style
 */
int
sudo_ldap_check(v, pwflag)
    VOID *v;
    int pwflag;
{
    LDAP *ld = (LDAP *) v;
    LDAPMessage *entry = NULL, *result = NULL;	/* used for searches */
    char *filt;					/* used to parse attributes */
    int rc = FALSE, ret = FALSE, pass = FALSE;	/* temp/final return values */
    int ldap_user_matches = FALSE, ldap_host_matches = FALSE; /* flags */

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

    for (pass = 1; !ret && pass <= 2; pass++) {
	if (pass == 1) {
	    /* Want the entries that match our usernames or groups */
	    filt = sudo_ldap_build_pass1();
	} else {		/* pass=2 */
	    /* Want the entries that have user netgroups in them. */
	    filt = strdup("sudoUser=+*");
	}
	if (ldap_conf.debug)
	    printf("ldap search '%s'\n", filt);
	rc = ldap_search_s(ld, ldap_conf.base, LDAP_SCOPE_ONELEVEL, filt,
	    NULL, 0, &result);
	if (rc) {
	    if (ldap_conf.debug)
		printf("nothing found for '%s'\n", filt);
	}
	if (filt)
	    free(filt);

	/* parse each entry returned from this most recent search */
	entry = rc ? NULL : ldap_first_entry(ld, result);
	while (entry != NULL) {
	    if (ldap_conf.debug)
		printf("found:%s\n", ldap_get_dn(ld, entry));
	    if (
	    /* first verify user netgroup matches - only if in pass 2 */
		(pass != 2 || sudo_ldap_check_user_netgroup(ld, entry)) &&
	    /* remember that user matched */
		(ldap_user_matches = -1) &&
	    /* verify host match */
		sudo_ldap_check_host(ld, entry) &&
	    /* remember that host matched */
		(ldap_host_matches = -1) &&
	    /* add matches for listing later */
		sudo_ldap_add_match(ld, entry, pwflag) &&
	    /* verify command match */
		sudo_ldap_check_command(ld, entry) &&
	    /* verify runas match */
		sudo_ldap_check_runas(ld, entry)
		) {
		/* We have a match! */
		if (ldap_conf.debug)
		    printf("Perfect Matched!\n");
		/* pick up any options */
		sudo_ldap_parse_options(ld, entry);
		/* make sure we don't reenter loop */
		ret = VALIDATE_OK;
		/* break from inside for loop */
		break;
	    }
	    entry = ldap_next_entry(ld, entry);
	}
	if (result)
	    ldap_msgfree(result);
	result = NULL;
    }

    /* shut down connection */
    if (ld)
	ldap_unbind_s(ld);

    if (ldap_conf.debug)
	printf("user_matches=%d\n", ldap_user_matches);
    if (ldap_conf.debug)
	printf("host_matches=%d\n", ldap_host_matches);

    /* Check for special case for -v, -k, -l options */
    if (pwflag && ldap_user_matches && ldap_host_matches) {
	/*
         * Handle verifypw & listpw
         *
         * To be extra paranoid, since we haven't read any NOPASSWD options
         * in /etc/sudoers yet, but we have to make the decission now, lets
         * assume the worst and prefer to prompt for password unless the setting
         * is "never". (example verifypw=never or listpw=never)
         *
         */
	ret = VALIDATE_OK;
	if (pwflag != -1) {
	    switch (sudo_defs_table[pwflag].sd_un.tuple) {
	    case never:
		def_authenticate = FALSE;
		break;
	    case always:
		if (def_authenticate)
		    SET(ret, FLAG_CHECK_USER);
		break;
	    default:
		break;
	    }
	}
    }
    if (!ISSET(ret, VALIDATE_OK)) {
	/* we do not have a match */
	ret = VALIDATE_NOT_OK;
	if (pwflag)
	    SET(ret, FLAG_NO_CHECK);
	else if (!ldap_user_matches)
	    SET(ret, FLAG_NO_USER);
	else if (!ldap_host_matches)
	    SET(ret, FLAG_NO_HOST);
    }
    if (ldap_conf.debug)
	printf("sudo_ldap_check(%d)=0x%02x\n", pwflag, ret);

    return(ret);
}

/*
 * shut down LDAP connection
 */
void
sudo_ldap_close(v)
    VOID *v;
{
    if (v)
	ldap_unbind_s((LDAP *) v);
}
