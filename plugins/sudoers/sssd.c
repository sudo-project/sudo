/*
 * Copyright (c) 2003-2016 Todd C. Miller <Todd.Miller@courtesan.com>
 * Copyright (c) 2011 Daniel Kopecek <dkopecek@redhat.com>
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

#ifdef HAVE_SSSD

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include <errno.h>
#include <stdint.h>

#include "sudoers.h"
#include "parse.h"
#include "sudo_lbuf.h"
#include "sudo_dso.h"

/* SSSD <--> SUDO interface - do not change */
struct sss_sudo_attr {
    char *name;
    char **values;
    unsigned int num_values;
};

struct sss_sudo_rule {
    unsigned int num_attrs;
    struct sss_sudo_attr *attrs;
};

struct sss_sudo_result {
    unsigned int num_rules;
    struct sss_sudo_rule *rules;
};

typedef int  (*sss_sudo_send_recv_t)(uid_t, const char*, const char*,
                                     uint32_t*, struct sss_sudo_result**);

typedef int  (*sss_sudo_send_recv_defaults_t)(uid_t, const char*, uint32_t*,
                                              char**, struct sss_sudo_result**);

typedef void (*sss_sudo_free_result_t)(struct sss_sudo_result*);

typedef int  (*sss_sudo_get_values_t)(struct sss_sudo_rule*, const char*,
                                      char***);

typedef void (*sss_sudo_free_values_t)(char**);

/* sudo_nss implementation */

struct sudo_sss_handle {
    char *domainname;
    char *host;
    char *shost;
    struct passwd *pw;
    void *ssslib;
    sss_sudo_send_recv_t fn_send_recv;
    sss_sudo_send_recv_defaults_t fn_send_recv_defaults;
    sss_sudo_free_result_t fn_free_result;
    sss_sudo_get_values_t fn_get_values;
    sss_sudo_free_values_t fn_free_values;
};

static int sudo_sss_open(struct sudo_nss *nss);
static int sudo_sss_close(struct sudo_nss *nss);
static int sudo_sss_parse(struct sudo_nss *nss);
static bool sudo_sss_parse_options(struct sudo_sss_handle *handle,
				   struct sss_sudo_rule *rule);
static int sudo_sss_setdefs(struct sudo_nss *nss);
static int sudo_sss_lookup(struct sudo_nss *nss, int ret, int pwflag);
static int sudo_sss_display_cmnd(struct sudo_nss *nss, struct passwd *pw);
static int sudo_sss_display_defaults(struct sudo_nss *nss, struct passwd *pw,
				     struct sudo_lbuf *lbuf);

static int sudo_sss_display_bound_defaults(struct sudo_nss *nss,
					   struct passwd *pw, struct sudo_lbuf *lbuf);

static int sudo_sss_display_privs(struct sudo_nss *nss, struct passwd *pw,
				  struct sudo_lbuf *sudo_lbuf);


static struct sss_sudo_result *sudo_sss_result_get(struct sudo_nss *nss,
						   struct passwd *pw,
						   uint32_t *state);

static void
sudo_sss_attrfree(struct sss_sudo_attr *attr)
{
    unsigned int i;
    debug_decl(sudo_sss_attrfree, SUDOERS_DEBUG_SSSD)

    free(attr->name);
    attr->name = NULL;
    if (attr->values != NULL) {
	for (i = 0; i < attr->num_values; ++i)
	    free(attr->values[i]);
	free(attr->values);
	attr->values = NULL;
    }
    attr->num_values = 0;

    debug_return;
}

static bool
sudo_sss_attrcpy(struct sss_sudo_attr *dst, const struct sss_sudo_attr *src)
{
    unsigned int i = 0;
    debug_decl(sudo_sss_attrcpy, SUDOERS_DEBUG_SSSD)

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "dst=%p, src=%p", dst, src);
    sudo_debug_printf(SUDO_DEBUG_INFO, "malloc: cnt=%d", src->num_values);

    dst->name = strdup(src->name);
    dst->values = reallocarray(NULL, src->num_values, sizeof(char *));
    if (dst->name == NULL || dst->values == NULL)
	goto oom;
    dst->num_values = src->num_values;

    for (i = 0; i < dst->num_values; ++i) {
	dst->values[i] = strdup(src->values[i]);
	if (dst->values[i] == NULL) {
	    dst->num_values = i;
	    goto oom;
	}
    }

    debug_return_bool(true);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    sudo_sss_attrfree(dst);
    debug_return_bool(false);
}

static void
sudo_sss_rulefree(struct sss_sudo_rule *rule)
{
    unsigned int i;
    debug_decl(sudo_sss_rulefree, SUDOERS_DEBUG_SSSD)

    for (i = 0; i < rule->num_attrs; ++i)
	sudo_sss_attrfree(rule->attrs + i);
    free(rule->attrs);
    rule->attrs = NULL;
    rule->num_attrs = 0;

    debug_return;
}

static bool
sudo_sss_rulecpy(struct sss_sudo_rule *dst, const struct sss_sudo_rule *src)
{
    unsigned int i;
    debug_decl(sudo_sss_rulecpy, SUDOERS_DEBUG_SSSD)

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "dst=%p, src=%p", dst, src);
    sudo_debug_printf(SUDO_DEBUG_INFO, "malloc: cnt=%d", src->num_attrs);

    dst->num_attrs = 0;
    dst->attrs = reallocarray(NULL, src->num_attrs, sizeof(struct sss_sudo_attr));
    if (dst->attrs == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_bool(false);
    }

    for (i = 0; i < src->num_attrs; ++i) {
	if (!sudo_sss_attrcpy(dst->attrs + i, src->attrs + i)) {
	    dst->num_attrs = i;
	    sudo_sss_rulefree(dst);
	    debug_return_bool(false);
	}
    }
    dst->num_attrs = i;

    debug_return_bool(true);
}

#define SUDO_SSS_FILTER_INCLUDE 0
#define SUDO_SSS_FILTER_EXCLUDE 1

#define SUDO_SSS_STATE_HOSTMATCH 0x01
#define SUDO_SSS_STATE_USERMATCH 0x02

static struct sss_sudo_result *
sudo_sss_filter_result(struct sudo_sss_handle *handle,
    struct sss_sudo_result *in_res,
    int (*filterp)(struct sudo_sss_handle *, struct sss_sudo_rule *, void *),
    int act, void *filterp_arg)
{
    struct sss_sudo_result *out_res;
    unsigned int i, l;
    int r;
    debug_decl(sudo_sss_filter_result, SUDOERS_DEBUG_SSSD)

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "in_res=%p, count=%u, act=%s",
	in_res, in_res ? in_res->num_rules : 0,
	act == SUDO_SSS_FILTER_EXCLUDE ? "EXCLUDE" : "INCLUDE");

    if (in_res == NULL)
	debug_return_ptr(NULL);

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "malloc: cnt=%d", in_res->num_rules);

    if ((out_res = calloc(1, sizeof(struct sss_sudo_result))) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_ptr(NULL);
    }
    if (in_res->num_rules > 0) {
	out_res->rules =
	    reallocarray(NULL, in_res->num_rules, sizeof(struct sss_sudo_rule));
	if (out_res->rules == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    free(out_res);
	    debug_return_ptr(NULL);
	}
    }

    for (i = l = 0; i < in_res->num_rules; ++i) {
	 r = filterp(handle, in_res->rules + i, filterp_arg);

	 if (( r && act == SUDO_SSS_FILTER_INCLUDE) ||
	     (!r && act == SUDO_SSS_FILTER_EXCLUDE)) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG,
		"COPY (%s): %p[%u] => %p[%u] (= %p)",
		act == SUDO_SSS_FILTER_EXCLUDE ? "not excluded" : "included",
		in_res->rules, i, out_res->rules, l, in_res->rules + i);

	    if (!sudo_sss_rulecpy(out_res->rules + l, in_res->rules + i)) {
		while (l--) {
		    sudo_sss_rulefree(out_res->rules + l);
		}
		free(out_res->rules);
		free(out_res);
		debug_return_ptr(NULL);
	    }
	    ++l;
	}
    }

    if (l < in_res->num_rules) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "reallocating result: %p (count: %u -> %u)", out_res->rules,
	    in_res->num_rules, l);
	if (l > 0) {
	    struct sss_sudo_rule *rules =
		reallocarray(out_res->rules, l, sizeof(struct sss_sudo_rule));
	    if (out_res->rules == NULL) {
		sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
		while (l--) {
		    sudo_sss_rulefree(out_res->rules + l);
		}
		free(out_res->rules);
		free(out_res);
		debug_return_ptr(NULL);
	    }
	    out_res->rules = rules;
	} else {
	    free(out_res->rules);
	    out_res->rules = NULL;
	}
    }

    out_res->num_rules = l;

    debug_return_ptr(out_res);
}

static int
get_ipa_hostname(char **shostp, char **lhostp)
{
    size_t linesize = 0;
    char *lhost = NULL;
    char *shost = NULL;
    char *line = NULL;
    int ret = false;
    ssize_t len;
    FILE *fp;
    debug_decl(get_ipa_hostname, SUDOERS_DEBUG_SSSD)

    fp = fopen(_PATH_SSSD_CONF, "r");
    if (fp != NULL) {
	while ((len = getline(&line, &linesize, fp)) != -1) {
	    char *cp = line;

	    /* Trim trailing and leading spaces. */
	    while (isspace((unsigned char)line[len - 1]))
		line[--len] = '\0';
	    while (isspace((unsigned char)*cp))
		cp++;

	    /*
	     * Match ipa_hostname = foo
	     * Note: currently ignores the domain (XXX)
	     */
	    if (strncmp(cp, "ipa_hostname", 12) == 0) {
		cp += 12;
		/* Trim " = " after "ipa_hostname" */
		while (isblank((unsigned char)*cp))
		    cp++;
		if (*cp++ != '=')
		    continue;
		while (isblank((unsigned char)*cp))
		    cp++;
		/* Ignore empty value */
		if (*cp == '\0')
		    continue;
		lhost = strdup(cp);
		if (lhost != NULL && (cp = strchr(lhost, '.')) != NULL) {
		    shost = strndup(lhost, (size_t)(cp - lhost));
		} else {
		    shost = lhost;
		}
		if (shost != NULL && lhost != NULL) {
		    sudo_debug_printf(SUDO_DEBUG_INFO,
			"ipa_hostname %s overrides %s", lhost, user_host);
		    *shostp = shost;
		    *lhostp = lhost;
		    ret = true;
		} else {
		    free(shost);
		    free(lhost);
		    ret = -1;
		}
		break;
	    }
	}
	fclose(fp);
	free(line);
    }
    debug_return_int(ret);
}

struct sudo_nss sudo_nss_sss = {
    { NULL, NULL },
    sudo_sss_open,
    sudo_sss_close,
    sudo_sss_parse,
    sudo_sss_setdefs,
    sudo_sss_lookup,
    sudo_sss_display_cmnd,
    sudo_sss_display_defaults,
    sudo_sss_display_bound_defaults,
    sudo_sss_display_privs
};

/* sudo_nss implementation */
// ok
static int
sudo_sss_open(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle;
    static const char path[] = _PATH_SSSD_LIB"/libsss_sudo.so";
    debug_decl(sudo_sss_open, SUDOERS_DEBUG_SSSD);

    /* Create a handle container. */
    handle = malloc(sizeof(struct sudo_sss_handle));
    if (handle == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(ENOMEM);
    }

    /* Load symbols */
    handle->ssslib = sudo_dso_load(path, SUDO_DSO_LAZY);
    if (handle->ssslib == NULL) {
	const char *errstr = sudo_dso_strerror();
	sudo_warnx(U_("unable to load %s: %s"), path,
	    errstr ? errstr : "unknown error");
	sudo_warnx(U_("unable to initialize SSS source. Is SSSD installed on your machine?"));
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_send_recv =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_send_recv");
    if (handle->fn_send_recv == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_send_recv");
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_send_recv_defaults =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_send_recv_defaults");
    if (handle->fn_send_recv_defaults == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_send_recv_defaults");
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_free_result =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_free_result");
    if (handle->fn_free_result == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_free_result");
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_get_values =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_get_values");
    if (handle->fn_get_values == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_get_values");
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->fn_free_values =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_free_values");
    if (handle->fn_free_values == NULL) {
	sudo_warnx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_free_values");
	free(handle);
	debug_return_int(EFAULT);
    }

    handle->domainname = NULL;
    handle->host = user_runhost;
    handle->shost = user_srunhost;
    handle->pw = sudo_user.pw;
    nss->handle = handle;

    /*
     * If runhost is the same as the local host, check for ipa_hostname
     * in sssd.conf and use it in preference to user_runhost.
     */
    if (strcmp(user_runhost, user_host) == 0) {
	if (get_ipa_hostname(&handle->shost, &handle->host) == -1) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    free(handle);
	    debug_return_int(ENOMEM);
	}
    }

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "handle=%p", handle);

    debug_return_int(0);
}

// ok
static int
sudo_sss_close(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle;
    debug_decl(sudo_sss_close, SUDOERS_DEBUG_SSSD);

    if (nss && nss->handle) {
	handle = nss->handle;
	sudo_dso_unload(handle->ssslib);
	free(nss->handle);
    }
    debug_return_int(0);
}

// ok
static int
sudo_sss_parse(struct sudo_nss *nss)
{
    debug_decl(sudo_sss_parse, SUDOERS_DEBUG_SSSD);
    debug_return_int(0);
}

static int
sudo_sss_setdefs(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_result *sss_result = NULL;
    struct sss_sudo_rule   *sss_rule;
    uint32_t sss_error;
    unsigned int i;
    debug_decl(sudo_sss_setdefs, SUDOERS_DEBUG_SSSD);

    if (handle == NULL)
	debug_return_int(-1);

    sudo_debug_printf(SUDO_DEBUG_DIAG, "Looking for cn=defaults");

    if (handle->fn_send_recv_defaults(handle->pw->pw_uid, handle->pw->pw_name,
				      &sss_error, &handle->domainname,
				      &sss_result) != 0) {
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "handle->fn_send_recv_defaults: != 0, sss_error=%u", sss_error);
	debug_return_int(-1);
    }
    if (sss_error != 0) {
	if (sss_error == ENOENT) {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"The user was not found in SSSD.");
	    goto done;
	}
	sudo_debug_printf(SUDO_DEBUG_INFO, "sss_error=%u\n", sss_error);
	goto bad;
    }

    for (i = 0; i < sss_result->num_rules; ++i) {
	 sudo_debug_printf(SUDO_DEBUG_DIAG,
	    "Parsing cn=defaults, %d/%d", i, sss_result->num_rules);
	 sss_rule = sss_result->rules + i;
	 if (!sudo_sss_parse_options(handle, sss_rule))
	    goto bad;
    }

done:
    handle->fn_free_result(sss_result);
    debug_return_int(0);
bad:
    handle->fn_free_result(sss_result);
    debug_return_int(-1);
}

static int
sudo_sss_checkpw(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_sss_handle *handle = nss->handle;
    debug_decl(sudo_sss_checkpw, SUDOERS_DEBUG_SSSD);

    if (pw->pw_name != handle->pw->pw_name ||
	pw->pw_uid  != handle->pw->pw_uid) {
	sudo_debug_printf(SUDO_DEBUG_DIAG,
	    "Requested name or uid don't match the initial once, reinitializing...");
	handle->pw = pw;

	if (sudo_sss_setdefs(nss) != 0)
	    debug_return_int(-1);
    }

     debug_return_int(0);
}

static int
sudo_sss_check_runas_user(struct sudo_sss_handle *handle, struct sss_sudo_rule *sss_rule)
{
    char **val_array = NULL;
    char *val;
    int ret = false, i;
    debug_decl(sudo_sss_check_runas_user, SUDOERS_DEBUG_SSSD);

    if (!runas_pw)
	debug_return_int(UNSPEC);

    /* get the runas user from the entry */
    switch (handle->fn_get_values(sss_rule, "sudoRunAsUser", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result. Trying old style (sudoRunAs)");

	/* try old style */
	switch (handle->fn_get_values(sss_rule, "sudoRunAs", &val_array)) {
	case 0:
	    break;
	case ENOENT:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "No result. Matching against runas_default");
	    /*
	     * If there are no runas entries, match runas_default against
	     * what the user specified on the command line.
	     */
	    return !strcasecmp(runas_pw->pw_name, def_runas_default);
	default:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoRunAs): != 0");
	    debug_return_int(UNSPEC);
	}
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoRunAsUser): != 0");
	debug_return_int(UNSPEC);
    }

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

    /* walk through values returned, looking for a match */
    for (i = 0; val_array[i] != NULL && !ret; ++i) {
	val = val_array[i];

	sudo_debug_printf(SUDO_DEBUG_DEBUG, "val[%d]=%s", i, val);

	switch (val[0]) {
	case '+':
	    sudo_debug_printf(SUDO_DEBUG_DEBUG, "netgr_");
	    if (netgr_matches(val, def_netgroup_tuple ? handle->host : NULL,
		def_netgroup_tuple ? handle->shost : NULL, runas_pw->pw_name)) {
		sudo_debug_printf(SUDO_DEBUG_DEBUG, "=> match");
		ret = true;
	    }
	    break;
	case '%':
	    sudo_debug_printf(SUDO_DEBUG_DEBUG, "usergr_");
	    if (usergr_matches(val, runas_pw->pw_name, runas_pw)) {
		sudo_debug_printf(SUDO_DEBUG_DEBUG, "=> match");
		ret = true;
	    }
	    break;
	case 'A':
	    if (strcmp(val, "ALL") == 0) {
		sudo_debug_printf(SUDO_DEBUG_DEBUG, "ALL => match");
		ret = true;
		break;
	    }
	    /* FALLTHROUGH */
	    sudo_debug_printf(SUDO_DEBUG_DEBUG, "FALLTHROUGH");
	default:
	    if (userpw_matches(val, runas_pw->pw_name, runas_pw)) {
		sudo_debug_printf(SUDO_DEBUG_DEBUG,
		    "%s == %s (pw_name) => match", val, runas_pw->pw_name);
		ret = true;
	    }
	    break;
	}

	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "sssd/ldap sudoRunAsUser '%s' ... %s", val, ret ? "MATCH!" : "not");
    }

    handle->fn_free_values(val_array); /* cleanup */

    debug_return_int(ret);
}

static int
sudo_sss_check_runas_group(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule)
{
    char **val_array = NULL;
    char *val;
    int ret = false, i;
    debug_decl(sudo_sss_check_runas_group, SUDOERS_DEBUG_SSSD);

    /* runas_gr is only set if the user specified the -g flag */
    if (!runas_gr)
	debug_return_int(UNSPEC);

    /* get the values from the entry */
    switch (handle->fn_get_values(rule, "sudoRunAsGroup", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	debug_return_int(false);
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "handle->fn_get_values(sudoRunAsGroup): != 0");
	debug_return_int(UNSPEC);
    }

    /* walk through values returned, looking for a match */
    for (i = 0; val_array[i] != NULL; ++i) {
	val = val_array[i];
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "val[%d]=%s", i, val);

	if (strcmp(val, "ALL") == 0 || group_matches(val, runas_gr))
	    ret = true;

	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "sssd/ldap sudoRunAsGroup '%s' ... %s", val, ret ? "MATCH!" : "not");
    }

    handle->fn_free_values(val_array);

    debug_return_int(ret);
}

/*
 * Walk through search results and return true if we have a runas match,
 * else false.  RunAs info is optional.
 */
static bool
sudo_sss_check_runas(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule)
{
    bool ret;
    debug_decl(sudo_sss_check_runas, SUDOERS_DEBUG_SSSD);

    if (rule == NULL)
	 debug_return_bool(false);

    ret = sudo_sss_check_runas_user(handle, rule) != false &&
	 sudo_sss_check_runas_group(handle, rule) != false;

    debug_return_bool(ret);
}

static bool
sudo_sss_check_host(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule)
{
    char **val_array, *val;
    bool ret = false;
    int i;
    debug_decl(sudo_sss_check_host, SUDOERS_DEBUG_SSSD);

    if (rule == NULL)
	debug_return_bool(ret);

    /* get the values from the rule */
    switch (handle->fn_get_values(rule, "sudoHost", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	debug_return_bool(false);
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoHost): != 0");
	debug_return_bool(ret);
    }

    /* walk through values */
    for (i = 0; val_array[i] != NULL && !ret; ++i) {
	val = val_array[i];
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "val[%d]=%s", i, val);

	/* match any or address or netgroup or hostname */
	if (strcmp(val, "ALL") == 0 || addr_matches(val) ||
	    netgr_matches(val, handle->host, handle->shost,
	    def_netgroup_tuple ? handle->pw->pw_name : NULL) ||
	    hostname_matches(handle->shost, handle->host, val))
	    ret = true;

	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "sssd/ldap sudoHost '%s' ... %s", val, ret ? "MATCH!" : "not");
    }

    handle->fn_free_values(val_array);

    debug_return_bool(ret);
}

/*
 * SSSD doesn't handle netgroups, we have to ensure they are correctly filtered
 * in sudo. The rules may contain mixed sudoUser specification so we have to
 * check not only for netgroup membership but also for user and group matches.
 */
static bool
sudo_sss_check_user(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule)
{
    int ret = false;
    char **val_array;
    int i;
    debug_decl(sudo_sss_check_user, SUDOERS_DEBUG_SSSD);

    if (!handle || !rule)
	debug_return_bool(false);

    switch (handle->fn_get_values(rule, "sudoUser", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	debug_return_bool(false);
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "handle->fn_get_values(sudoUser): != 0");
	debug_return_bool(false);
    }

    /* Walk through sudoUser values.  */
    for (i = 0; val_array[i] != NULL && !ret; ++i) {
	const char *val = val_array[i];

	sudo_debug_printf(SUDO_DEBUG_DEBUG, "val[%d]=%s", i, val);
	switch (*val) {
	case '+':
	    /* Netgroup spec found, check membership. */
	    if (netgr_matches(val, def_netgroup_tuple ? handle->host : NULL,
		def_netgroup_tuple ? handle->shost : NULL, handle->pw->pw_name)) {
		ret = true;
	    }
	    break;
	case '%':
	    /* User group found, check membership. */
	    if (usergr_matches(val, handle->pw->pw_name, handle->pw)) {
		ret = true;
	    }
	    break;
	default:
	    /* Not a netgroup or user group. */
	    if (strcmp(val, "ALL") == 0 ||
		userpw_matches(val, handle->pw->pw_name, handle->pw)) {
		ret = true;
	    }
	    break;
	}
	sudo_debug_printf(SUDO_DEBUG_DIAG,
	    "sssd/ldap sudoUser '%s' ... %s (%s)", val,
	    ret ? "MATCH!" : "not", handle->pw->pw_name);
    }
    handle->fn_free_values(val_array);
    debug_return_bool(ret);
}

static int
sudo_sss_result_filterp(struct sudo_sss_handle *handle,
    struct sss_sudo_rule *rule, void *unused)
{
    (void)unused;
    debug_decl(sudo_sss_result_filterp, SUDOERS_DEBUG_SSSD);

    if (sudo_sss_check_host(handle, rule) &&
        sudo_sss_check_user(handle, rule))
	debug_return_int(1);
    else
	debug_return_int(0);
}

static struct sss_sudo_result *
sudo_sss_result_get(struct sudo_nss *nss, struct passwd *pw, uint32_t *state)
{
    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_result *u_sss_result, *f_sss_result;
    uint32_t sss_error = 0, ret;
    debug_decl(sudo_sss_result_get, SUDOERS_DEBUG_SSSD);

    if (sudo_sss_checkpw(nss, pw) != 0)
	debug_return_ptr(NULL);

    sudo_debug_printf(SUDO_DEBUG_DIAG, "  username=%s", handle->pw->pw_name);
    sudo_debug_printf(SUDO_DEBUG_DIAG, "domainname=%s",
	handle->domainname ? handle->domainname : "NULL");

    u_sss_result = f_sss_result = NULL;

    ret = handle->fn_send_recv(handle->pw->pw_uid, handle->pw->pw_name,
	handle->domainname, &sss_error, &u_sss_result);

    switch (ret) {
    case 0:
	switch (sss_error) {
	case 0:
	    if (u_sss_result != NULL) {
		if (state != NULL) {
		    sudo_debug_printf(SUDO_DEBUG_DEBUG, "state |= USERMATCH");
		    *state |= SUDO_SSS_STATE_USERMATCH;
		}
		sudo_debug_printf(SUDO_DEBUG_INFO, "Received %u rule(s)",
		    u_sss_result->num_rules);
	    } else {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "Internal error: u_sss_result == NULL && sss_error == 0");
		debug_return_ptr(NULL);
	    }
	    break;
	case ENOENT:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "The user was not found in SSSD.");
	    debug_return_ptr(NULL);
	default:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "sss_error=%u\n", sss_error);
	    debug_return_ptr(NULL);
	}
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "handle->fn_send_recv: != 0: ret=%d", ret);
	debug_return_ptr(NULL);
    }

    f_sss_result = sudo_sss_filter_result(handle, u_sss_result,
	sudo_sss_result_filterp, SUDO_SSS_FILTER_INCLUDE, NULL);

    if (f_sss_result != NULL) {
	if (f_sss_result->num_rules > 0) {
	    if (state != NULL) {
		sudo_debug_printf(SUDO_DEBUG_DEBUG, "state |= HOSTMATCH");
		*state |= SUDO_SSS_STATE_HOSTMATCH;
	    }
	}
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "u_sss_result=(%p, %u) => f_sss_result=(%p, %u)", u_sss_result,
	    u_sss_result->num_rules, f_sss_result, f_sss_result->num_rules);
    } else {
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "u_sss_result=(%p, %u) => f_sss_result=NULL", u_sss_result,
	    u_sss_result->num_rules);
    }

    handle->fn_free_result(u_sss_result);

    debug_return_ptr(f_sss_result);
}

/*
 * Search for boolean "option" in sudoOption.
 * Returns true if found and allowed, false if negated, else UNSPEC.
 */
static int
sudo_sss_check_bool(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule,
    char *option)
{
    char ch, *var, **val_array = NULL;
    int i, ret = UNSPEC;
    debug_decl(sudo_sss_check_bool, SUDOERS_DEBUG_SSSD);

    if (rule == NULL)
	debug_return_int(ret);

    switch (handle->fn_get_values(rule, "sudoOption", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	debug_return_int(ret);
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values: != 0");
	debug_return_int(ret);
    }

    /* walk through options */
    for (i = 0; val_array[i] != NULL; ++i) {
	var = val_array[i];
	sudo_debug_printf(SUDO_DEBUG_INFO, "sssd/ldap sudoOption: '%s'", var);

	if ((ch = *var) == '!')
	    var++;
	if (strcmp(var, option) == 0)
	    ret = (ch != '!');
    }

    handle->fn_free_values(val_array);

    debug_return_int(ret);
}

/*
 * If a digest prefix is present, fills in struct sudo_digest
 * and returns a pointer to it, updating cmnd to point to the
 * command after the digest.
 */
static struct sudo_digest *
sudo_sss_extract_digest(char **cmnd, struct sudo_digest *digest)
{
    char *ep, *cp = *cmnd;
    int digest_type = SUDO_DIGEST_INVALID;
    debug_decl(sudo_sss_check_command, SUDOERS_DEBUG_LDAP)

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
		    digest->digest_str = strndup(cp, (size_t)(ep - cp));
		    if (digest->digest_str == NULL) {
			sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
			debug_return_ptr(NULL);
		    }
		    cp = ep + 1;
		    while (isblank((unsigned char)*cp))
			cp++;
		    *cmnd = cp;
		    sudo_debug_printf(SUDO_DEBUG_INFO,
			"%s digest %s for %s",
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
sudo_sss_check_command(struct sudo_sss_handle *handle,
    struct sss_sudo_rule *rule, int *setenv_implied)
{
    char **val_array = NULL, *val;
    char *allowed_cmnd, *allowed_args;
    int ret = UNSPEC;
    bool foundbang;
    unsigned int i;
    struct sudo_digest digest, *allowed_digest = NULL;
    debug_decl(sudo_sss_check_command, SUDOERS_DEBUG_SSSD);

    if (rule == NULL)
	debug_return_int(ret);

    switch (handle->fn_get_values(rule, "sudoCommand", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	debug_return_int(ret);
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values: != 0");
	debug_return_int(ret);
    }

    for (i = 0; val_array[i] != NULL && ret != false; ++i) {
	val = val_array[i];

	sudo_debug_printf(SUDO_DEBUG_DEBUG, "val[%d]=%s", i, val);

	/* Match against ALL ? */
	if (strcmp(val, "ALL") == 0) {
	    ret = true;
	    if (setenv_implied != NULL)
		*setenv_implied = true;
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"sssd/ldap sudoCommand '%s' ... MATCH!", val);
	    continue;
	}

        /* check for sha-2 digest */
	allowed_digest = sudo_sss_extract_digest(&val, &digest);

	/* check for !command */
	if (*val == '!') {
	    foundbang = true;
	    allowed_cmnd = val + 1;	/* !command */
	} else {
	    foundbang = false;
	    allowed_cmnd = val;		/* command */
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
	if (allowed_args != NULL)
	    allowed_args[-1] = ' ';	/* restore val */

	sudo_debug_printf(SUDO_DEBUG_INFO, "sssd/ldap sudoCommand '%s' ... %s",
	    val, ret == true ? "MATCH!" : "not");
	if (allowed_digest != NULL)
	    free(allowed_digest->digest_str);
    }

    handle->fn_free_values(val_array); /* more cleanup */

    debug_return_int(ret);
}

static bool
sudo_sss_parse_options(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule)
{
    int i, op;
    bool ret = false;
    char *copy, *cp, *v;
    char **val_array = NULL;
    debug_decl(sudo_sss_parse_options, SUDOERS_DEBUG_SSSD);

    if (rule == NULL)
	debug_return_bool(true);

    switch (handle->fn_get_values(rule, "sudoOption", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	debug_return_bool(true);
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoOption): != 0");
	debug_return_bool(false);
    }

    /* walk through options */
    for (i = 0; val_array[i] != NULL; i++) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "sssd/ldap sudoOption: '%s'",
	 val_array[i]);
	if ((v = copy = strdup(val_array[i])) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto done;
	}

	/* check for equals sign past first char */
	cp = strchr(v, '=');
	if (cp > v) {
	    char *val = cp + 1;
	    op = cp[-1];	/* peek for += or -= cases */
	    if (op == '+' || op == '-') {
		/* case var+=val or var-=val */
		cp--;
	    } else {
		/* case var=val */
		op = true;
	    }
	    /* Trim whitespace between var and operator. */
	    while (cp > v && isblank((unsigned char)cp[-1]))
		cp--;
	    /* Truncate variable name. */
	    *cp = '\0';
	    /* Trim leading whitespace from val. */
	    while (isblank((unsigned char)*val))
		val++;
	    /* Strip double quotes if present. */
	    if (*val == '"') {
		char *ep = val + strlen(val);
		if (ep != val && ep[-1] == '"') {
		    val++;
		    ep[-1] = '\0';
		}
	    }
	    set_default(v, val, op);
	} else if (*v == '!') {
	    /* case !var Boolean False */
	    do {
		v++;
	    } while (isblank((unsigned char)*v));
	    set_default(v, NULL, false);
	} else {
	    /* case var Boolean True */
	    set_default(v, NULL, true);
	}
	free(copy);
    }
    ret = true;

done:
    handle->fn_free_values(val_array);
    debug_return_bool(ret);
}

static int
sudo_sss_lookup(struct sudo_nss *nss, int ret, int pwflag)
{
    int rc, setenv_implied;

    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_result *sss_result = NULL;
    struct sss_sudo_rule   *rule;
    uint32_t i, state = 0;
    debug_decl(sudo_sss_lookup, SUDOERS_DEBUG_SSSD);

    /* Fetch list of sudoRole entries that match user and host. */
    sss_result = sudo_sss_result_get(nss, sudo_user.pw, &state);

    /*
     * The following queries are only determine whether or not a
     * password is required, so the order of the entries doesn't matter.
     */
    if (pwflag) {
	int doauth = UNSPEC;
	int matched = UNSPEC;
	enum def_tuple pwcheck =
	    (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;

	sudo_debug_printf(SUDO_DEBUG_INFO, "perform search for pwflag %d", pwflag);
	if (sss_result != NULL) {
	    for (i = 0; i < sss_result->num_rules; i++) {
		rule = sss_result->rules + i;
		if ((pwcheck == any && doauth != false) ||
		    (pwcheck == all && doauth != true)) {
		    doauth = !!sudo_sss_check_bool(handle, rule, "authenticate");
		}
		/* Only check the command when listing another user. */
		if (user_uid == 0 || list_pw == NULL ||
		    user_uid == list_pw->pw_uid ||
		    sudo_sss_check_command(handle, rule, NULL) == true) {
		    matched = true;
		    break;
		}
	    }
	}
	if (matched == true || user_uid == 0) {
	    SET(ret, VALIDATE_SUCCESS);
	    CLR(ret, VALIDATE_FAILURE);
	    switch (pwcheck) {
		case always:
		    SET(ret, FLAG_CHECK_USER);
		    break;
		case all:
		case any:
		    if (doauth == false)
			SET(ret, FLAG_NOPASSWD);
		    break;
		default:
		    break;
	    }
	}
	goto done;
    }

    sudo_debug_printf(SUDO_DEBUG_DIAG,
	"searching SSSD/LDAP for sudoers entries");

    setenv_implied = false;
    if (sss_result != NULL) {
	for (i = 0; i < sss_result->num_rules; i++) {
	    rule = sss_result->rules + i;
	    if (!sudo_sss_check_runas(handle, rule))
		continue;
	    rc = sudo_sss_check_command(handle, rule, &setenv_implied);
	    if (rc != UNSPEC) {
		/* We have a match. */
		sudo_debug_printf(SUDO_DEBUG_DIAG, "Command %sallowed",
		    rc == true ? "" : "NOT ");
		if (rc == true) {
		    sudo_debug_printf(SUDO_DEBUG_DEBUG, "SSSD rule: %p", rule);
		    /* Apply entry-specific options. */
		    if (setenv_implied)
			def_setenv = true;
		    if (sudo_sss_parse_options(handle, rule)) {
#ifdef HAVE_SELINUX
			/* Set role/type if not specified on command line. */
			if (user_role == NULL)
			    user_role = def_role;
			if (user_type == NULL)
			    user_type = def_type;
#endif /* HAVE_SELINUX */
			SET(ret, VALIDATE_SUCCESS);
			CLR(ret, VALIDATE_FAILURE);
		    } else {
			SET(ret, VALIDATE_ERROR);
		    }
		} else {
		    SET(ret, VALIDATE_FAILURE);
		    CLR(ret, VALIDATE_SUCCESS);
		}
		break;
	    }
	}
    }
done:
    handle->fn_free_result(sss_result);

    sudo_debug_printf(SUDO_DEBUG_DIAG, "Done with LDAP searches");

    if (!ISSET(ret, VALIDATE_SUCCESS)) {
	/* No matching entries. */
	if (pwflag && list_pw == NULL)
	    SET(ret, FLAG_NO_CHECK);
    }

    if (pwflag || ISSET(state, SUDO_SSS_STATE_USERMATCH))
	CLR(ret, FLAG_NO_USER);
    if (pwflag || ISSET(state, SUDO_SSS_STATE_HOSTMATCH))
	CLR(ret, FLAG_NO_HOST);

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "sudo_sss_lookup(%d)=0x%02x",
	pwflag, ret);

    debug_return_int(ret);
}

static int
sudo_sss_display_cmnd(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_result *sss_result = NULL;
    struct sss_sudo_rule *rule;
    unsigned int i;
    bool found = false;
    debug_decl(sudo_sss_display_cmnd, SUDOERS_DEBUG_SSSD);

    if (handle == NULL)
	debug_return_int(-1);
    if (sudo_sss_checkpw(nss, pw) != 0)
	debug_return_int(-1);

    /*
     * The sudo_sss_result_get() function returns all nodes that match
     * the user and the host.
     */
    sudo_debug_printf(SUDO_DEBUG_DIAG, "sssd/ldap search for command list");
    sss_result = sudo_sss_result_get(nss, pw, NULL);

    if (sss_result == NULL)
	goto done;

    for (i = 0; i < sss_result->num_rules; i++) {
	rule = sss_result->rules + i;
	if (sudo_sss_check_command(handle, rule, NULL) &&
	    sudo_sss_check_runas(handle, rule)) {
	    found = true;
	    goto done;
	}
    }

done:
    if (found)
	sudo_printf(SUDO_CONV_INFO_MSG, "%s%s%s\n",
	    safe_cmnd ? safe_cmnd : user_cmnd,
	    user_args ? " " : "", user_args ? user_args : "");

    handle->fn_free_result(sss_result);

    debug_return_int(!found);
}

static int
sudo_sss_display_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf)
{
    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_rule *rule;
    struct sss_sudo_result *sss_result = NULL;
    uint32_t sss_error = 0;
    char *prefix, *val, **val_array = NULL;
    unsigned int i, j;
    int count = 0;
    debug_decl(sudo_sss_display_defaults, SUDOERS_DEBUG_SSSD);

    if (handle == NULL)
	goto done;

    if (handle->fn_send_recv_defaults(pw->pw_uid, pw->pw_name,
				    &sss_error, &handle->domainname,
				    &sss_result) != 0) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_send_recv_defaults: !=0, sss_error=%u", sss_error);
	goto done;
    }

    if (sss_error == ENOENT) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "The user was not found in SSSD.");
	goto done;
    } else if(sss_error != 0) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "sss_error=%u\n", sss_error);
	goto done;
    }

    handle->pw = pw;

    for (i = 0; i < sss_result->num_rules; ++i) {
	rule = sss_result->rules + i;

	switch (handle->fn_get_values(rule, "sudoOption", &val_array)) {
	case 0:
	    break;
	case ENOENT:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	    continue;
	default:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values: != 0");
	    continue;
	}

	if (lbuf->len == 0 || isspace((unsigned char)lbuf->buf[lbuf->len - 1]))
	    prefix = "    ";
	else
	    prefix = ", ";

	for (j = 0; val_array[j] != NULL; ++j) {
	    val = val_array[j];
	    sudo_lbuf_append(lbuf, "%s%s", prefix, val);
	    prefix = ", ";
	    count++;
	}

	handle->fn_free_values(val_array);
	val_array = NULL;
    }

    handle->fn_free_result(sss_result);
done:
    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(count);
}

// ok
static int
sudo_sss_display_bound_defaults(struct sudo_nss *nss,
    struct passwd *pw, struct sudo_lbuf *lbuf)
{
    debug_decl(sudo_sss_display_bound_defaults, SUDOERS_DEBUG_SSSD);
    debug_return_int(0);
}

static int
sudo_sss_display_entry_long(struct sudo_sss_handle *handle,
    struct sss_sudo_rule *rule, struct sudo_lbuf *lbuf)
{
    char **val_array = NULL;
    int count = 0, i;
    debug_decl(sudo_sss_display_entry_long, SUDOERS_DEBUG_SSSD);

    switch (handle->fn_get_values(rule, "cn", &val_array)) {
    case 0:
	if (val_array[0] != NULL)
	    sudo_lbuf_append(lbuf, _("\nSSSD Role: %s\n"), val_array[0]);
	handle->fn_free_values(val_array);
	val_array = NULL;
	break;
    default:
	sudo_lbuf_append(lbuf, _("\nSSSD Role: UNKNOWN\n"));
    }

    /* get the RunAsUser Values from the entry */
    sudo_lbuf_append(lbuf, "    RunAsUsers: ");
    switch (handle->fn_get_values(rule, "sudoRunAsUser", &val_array)) {
    case 0:
	for (i = 0; val_array[i] != NULL; ++i)
	    sudo_lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	break;
    case ENOENT:
	switch (handle->fn_get_values(rule, "sudoRunAs", &val_array)) {
	case 0:
	    for (i = 0; val_array[i] != NULL; ++i)
		 sudo_lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	    handle->fn_free_values(val_array);
	    break;
	case ENOENT:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	    sudo_lbuf_append(lbuf, "%s", def_runas_default);
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoRunAs): != 0");
	    debug_return_int(count);
	}
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoRunAsUser): != 0");
	debug_return_int(count);
    }
    sudo_lbuf_append(lbuf, "\n");

    /* get the RunAsGroup Values from the entry */
    switch (handle->fn_get_values(rule, "sudoRunAsGroup", &val_array)) {
    case 0:
	sudo_lbuf_append(lbuf, "    RunAsGroups: ");
	for (i = 0; val_array[i] != NULL; ++i)
	     sudo_lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	sudo_lbuf_append(lbuf, "\n");
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "handle->fn_get_values(sudoRunAsGroup): != 0");
	debug_return_int(count);
    }

    /* get the Option Values from the entry */
    switch (handle->fn_get_values(rule, "sudoOption", &val_array)) {
    case 0:
	sudo_lbuf_append(lbuf, "    Options: ");
	for (i = 0; val_array[i] != NULL; ++i)
	     sudo_lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	sudo_lbuf_append(lbuf, "\n");
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoOption): != 0");
	debug_return_int(count);
    }

    /* Get the command values from the entry. */
    switch (handle->fn_get_values(rule, "sudoCommand", &val_array)) {
    case 0:
	sudo_lbuf_append(lbuf, _("    Commands:\n"));
	for (i = 0; val_array[i] != NULL; ++i) {
	     sudo_lbuf_append(lbuf, "\t%s\n", val_array[i]);
	     count++;
	}
	handle->fn_free_values(val_array);
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "handle->fn_get_values(sudoCommand): != 0");
	debug_return_int(count);
    }

    debug_return_int(count);
}

static int
sudo_sss_display_entry_short(struct sudo_sss_handle *handle,
    struct sss_sudo_rule *rule, struct sudo_lbuf *lbuf)
{
    char **val_array = NULL;
    int count = 0, i;
    debug_decl(sudo_sss_display_entry_short, SUDOERS_DEBUG_SSSD);

    sudo_lbuf_append(lbuf, "    (");

    /* get the RunAsUser Values from the entry */
    switch (handle->fn_get_values(rule, "sudoRunAsUser", &val_array)) {
    case 0:
	for (i = 0; val_array[i] != NULL; ++i)
	     sudo_lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result. Trying old style (sudoRunAs).");
	/* try old style */
	switch (handle->fn_get_values(rule, "sudoRunAs", &val_array)) {
	case 0:
	    for (i = 0; val_array[i] != NULL; ++i)
		 sudo_lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	    handle->fn_free_values(val_array);
	    break;
	case ENOENT:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	    sudo_lbuf_append(lbuf, "%s", def_runas_default);
	    break;
	default:
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"handle->fn_get_values(sudoRunAs): != 0");
	    debug_return_int(count);
	}
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "handle->fn_get_values(sudoRunAsUser): != 0");
	debug_return_int(count);
    }

    /* get the RunAsGroup Values from the entry */
    switch (handle->fn_get_values(rule, "sudoRunAsGroup", &val_array)) {
    case 0:
	sudo_lbuf_append(lbuf, " : ");
	for (i = 0; val_array[i] != NULL; ++i)
	     sudo_lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoRunAsGroup): != 0");
	debug_return_int(count);
    }

    sudo_lbuf_append(lbuf, ") ");

    /* get the Option Values from the entry */
    switch (handle->fn_get_values(rule, "sudoOption", &val_array)) {
    case 0:
	for (i = 0; val_array[i] != NULL; ++i) {
	    char *cp = val_array[i];
	    if (*cp == '!')
		cp++;
	    if (strcmp(cp, "authenticate") == 0)
		sudo_lbuf_append(lbuf, val_array[i][0] == '!' ?
		    "NOPASSWD: " : "PASSWD: ");
	    else if (strcmp(cp, "noexec") == 0)
		sudo_lbuf_append(lbuf, val_array[i][0] == '!' ?
		    "EXEC: " : "NOEXEC: ");
	    else if (strcmp(cp, "setenv") == 0)
		sudo_lbuf_append(lbuf, val_array[i][0] == '!' ?
		    "NOSETENV: " : "SETENV: ");
	    else if (strcmp(cp, "mail_all_cmnds") == 0 || strcmp(cp, "mail_always") == 0)
		sudo_lbuf_append(lbuf, val_array[i][0] == '!' ?
		    "NOMAIL: " : "MAIL: ");
	}
	handle->fn_free_values(val_array);
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "handle->fn_get_values(sudoOption): != 0");
	debug_return_int(count);
    }

    /* get the Command Values from the entry */
    switch (handle->fn_get_values(rule, "sudoCommand", &val_array)) {
    case 0:
	for (i = 0; val_array[i] != NULL; ++i) {
	    sudo_lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	    count++;
	}
	handle->fn_free_values(val_array);
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "handle->fn_get_values(sudoCommand): != 0");
	debug_return_int(count);
    }
    sudo_lbuf_append(lbuf, "\n");

    debug_return_int(count);
}

static int
sudo_sss_display_privs(struct sudo_nss *nss, struct passwd *pw,
    struct sudo_lbuf *lbuf)
{
    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_result *sss_result = NULL;
    struct sss_sudo_rule *rule;
    unsigned int i, count = 0;
    debug_decl(sudo_sss_display_privs, SUDOERS_DEBUG_SSSD);

    if (handle == NULL)
	debug_return_int(-1);
    if (sudo_sss_checkpw(nss, pw) != 0)
	debug_return_int(-1);

    sudo_debug_printf(SUDO_DEBUG_INFO, "sssd/ldap search for command list");

    sss_result = sudo_sss_result_get(nss, pw, NULL);

    if (sss_result == NULL)
	debug_return_int(count);

    /* Display all matching entries. */
    for (i = 0; i < sss_result->num_rules; ++i) {
	rule = sss_result->rules + i;
	if (long_list)
	    count += sudo_sss_display_entry_long(handle, rule, lbuf);
	else
	    count += sudo_sss_display_entry_short(handle, rule, lbuf);
    }

    handle->fn_free_result(sss_result);

    if (sudo_lbuf_error(lbuf))
	debug_return_int(-1);
    debug_return_int(count);
}

#endif /* HAVE_SSSD */
