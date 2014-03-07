/*
 * Copyright (c) 2003-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <pwd.h>
#include <grp.h>

#include <errno.h>
#include <stdint.h>

#include "sudoers.h"
#include "parse.h"
#include "lbuf.h"
#include "sudo_dso.h"
#include "sudo_debug.h"

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
static void sudo_sss_parse_options(struct sudo_sss_handle *handle,
				   struct sss_sudo_rule *rule);
static int sudo_sss_setdefs(struct sudo_nss *nss);
static int sudo_sss_lookup(struct sudo_nss *nss, int ret, int pwflag);
static int sudo_sss_display_cmnd(struct sudo_nss *nss, struct passwd *pw);
static int sudo_sss_display_defaults(struct sudo_nss *nss, struct passwd *pw,
				     struct lbuf *lbuf);

static int sudo_sss_display_bound_defaults(struct sudo_nss *nss,
					   struct passwd *pw, struct lbuf *lbuf);

static int sudo_sss_display_privs(struct sudo_nss *nss, struct passwd *pw,
				  struct lbuf *lbuf);


static struct sss_sudo_result *sudo_sss_result_get(struct sudo_nss *nss,
						   struct passwd *pw,
						   uint32_t *state);

static void
sudo_sss_attrcpy(struct sss_sudo_attr *dst, const struct sss_sudo_attr *src)
{
     int i;
     debug_decl(sudo_sss_attrcpy, SUDO_DEBUG_SSSD)

     sudo_debug_printf(SUDO_DEBUG_DEBUG, "dst=%p, src=%p", dst, src);
     sudo_debug_printf(SUDO_DEBUG_INFO, "emalloc: cnt=%d", src->num_values);

     dst->name = estrdup(src->name);
     dst->num_values = src->num_values;
     dst->values = emalloc2(dst->num_values, sizeof(char *));

     for (i = 0; i < dst->num_values; ++i)
	  dst->values[i] = estrdup(src->values[i]);

     debug_return;
}

static void
sudo_sss_rulecpy(struct sss_sudo_rule *dst, const struct sss_sudo_rule *src)
{
     int i;
     debug_decl(sudo_sss_rulecpy, SUDO_DEBUG_SSSD)

     sudo_debug_printf(SUDO_DEBUG_DEBUG, "dst=%p, src=%p", dst, src);
     sudo_debug_printf(SUDO_DEBUG_INFO, "emalloc: cnt=%d", src->num_attrs);

     dst->num_attrs = src->num_attrs;
     dst->attrs = emalloc2(dst->num_attrs, sizeof(struct sss_sudo_attr));

     for (i = 0; i < dst->num_attrs; ++i)
	  sudo_sss_attrcpy(dst->attrs + i, src->attrs + i);

     debug_return;
}

#define _SUDO_SSS_FILTER_INCLUDE 0
#define _SUDO_SSS_FILTER_EXCLUDE 1

#define _SUDO_SSS_STATE_HOSTMATCH 0x01
#define _SUDO_SSS_STATE_USERMATCH 0x02

static struct sss_sudo_result *
sudo_sss_filter_result(struct sudo_sss_handle *handle,
    struct sss_sudo_result *in_res,
    int (*filterp)(struct sudo_sss_handle *, struct sss_sudo_rule *, void *),
    int act, void *filterp_arg)
{
    struct sss_sudo_result *out_res;
    int i, l, r;
    debug_decl(sudo_sss_filter_result, SUDO_DEBUG_SSSD)

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "in_res=%p, count=%u, act=%s",
	in_res, in_res ? in_res->num_rules : 0,
	act == _SUDO_SSS_FILTER_EXCLUDE ? "EXCLUDE" : "INCLUDE");

    if (in_res == NULL)
	debug_return_ptr(NULL);

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "emalloc: cnt=%d", in_res->num_rules);

    out_res = emalloc(sizeof(struct sss_sudo_result));
    out_res->rules = in_res->num_rules > 0 ?
	emalloc2(in_res->num_rules, sizeof(struct sss_sudo_rule)) : NULL;
    out_res->num_rules = 0;

    for (i = l = 0; i < in_res->num_rules; ++i) {
	 r = filterp(handle, in_res->rules + i, filterp_arg);

	 if (( r && act == _SUDO_SSS_FILTER_INCLUDE) ||
	     (!r && act == _SUDO_SSS_FILTER_EXCLUDE)) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG,
		"COPY (%s): %p[%u] => %p[%u] (= %p)",
		act == _SUDO_SSS_FILTER_EXCLUDE ? "not excluded" : "included",
		in_res->rules, i, out_res->rules, l, in_res->rules + i);

	    sudo_sss_rulecpy(out_res->rules + l, in_res->rules + i);
	    ++l;
	}
    }

    if (l < in_res->num_rules) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "reallocating result: %p (count: %u -> %u)", out_res->rules,
	    in_res->num_rules, l);
	if (l > 0) {
	    out_res->rules =
		erealloc3(out_res->rules, l, sizeof(struct sss_sudo_rule));
	} else {
	    efree(out_res->rules);
	    out_res->rules = NULL;
	}
    }

    out_res->num_rules = l;

    debug_return_ptr(out_res);
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
static int sudo_sss_open(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle;
    static const char path[] = _PATH_SSSD_LIB"/libsss_sudo.so";
    debug_decl(sudo_sss_open, SUDO_DEBUG_SSSD);

    /* Create a handle container. */
    handle = emalloc(sizeof(struct sudo_sss_handle));

    /* Load symbols */
    handle->ssslib = sudo_dso_load(path, SUDO_DSO_LAZY);
    if (handle->ssslib == NULL) {
	warningx(U_("unable to load %s: %s"), path, sudo_dso_strerror());
	warningx(U_("unable to initialize SSS source. Is SSSD installed on your machine?"));
	debug_return_int(EFAULT);
    }

    handle->fn_send_recv =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_send_recv");
    if (handle->fn_send_recv == NULL) {
	warningx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_send_recv");
	debug_return_int(EFAULT);
    }

    handle->fn_send_recv_defaults =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_send_recv_defaults");
    if (handle->fn_send_recv_defaults == NULL) {
	warningx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_send_recv_defaults");
	debug_return_int(EFAULT);
    }

    handle->fn_free_result =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_free_result");
    if (handle->fn_free_result == NULL) {
	warningx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_free_result");
	debug_return_int(EFAULT);
    }

    handle->fn_get_values =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_get_values");
    if (handle->fn_get_values == NULL) {
	warningx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_get_values");
	debug_return_int(EFAULT);
    }

    handle->fn_free_values =
	sudo_dso_findsym(handle->ssslib, "sss_sudo_free_values");
    if (handle->fn_free_values == NULL) {
	warningx(U_("unable to find symbol \"%s\" in %s"), path,
	   "sss_sudo_free_values");
	debug_return_int(EFAULT);
    }

    handle->domainname = NULL;
    handle->pw = sudo_user.pw;
    nss->handle = handle;

    sudo_debug_printf(SUDO_DEBUG_DEBUG, "handle=%p", handle);

    debug_return_int(0);
}

// ok
static int sudo_sss_close(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle;
    debug_decl(sudo_sss_close, SUDO_DEBUG_SSSD);

    if (nss && nss->handle) {
	handle = nss->handle;
	sudo_dso_unload(handle->ssslib);
	efree(nss->handle);
    }
    debug_return_int(0);
}

// ok
static int sudo_sss_parse(struct sudo_nss *nss)
{
    debug_decl(sudo_sss_parse, SUDO_DEBUG_SSSD);
    debug_return_int(0);
}

static int sudo_sss_setdefs(struct sudo_nss *nss)
{
    struct sudo_sss_handle *handle = nss->handle;

    struct sss_sudo_result *sss_result;
    struct sss_sudo_rule   *sss_rule;
    uint32_t sss_error;
    int i;
    debug_decl(sudo_sss_setdefs, SUDO_DEBUG_SSSD);

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

    if (sss_error == ENOENT) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "The user was not found in SSSD.");
	debug_return_int(0);
    } else if(sss_error != 0) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "sss_error=%u\n", sss_error);
	debug_return_int(-1);
    }

    for (i = 0; i < sss_result->num_rules; ++i) {
	 sudo_debug_printf(SUDO_DEBUG_DIAG,
	    "Parsing cn=defaults, %d/%d", i, sss_result->num_rules);
	 sss_rule = sss_result->rules + i;
	 sudo_sss_parse_options(handle, sss_rule);
    }

    handle->fn_free_result(sss_result);
    debug_return_int(0);
}

static int sudo_sss_checkpw(struct sudo_nss *nss, struct passwd *pw)
{
    struct sudo_sss_handle *handle = nss->handle;
    debug_decl(sudo_sss_checkpw, SUDO_DEBUG_SSSD);

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
    debug_decl(sudo_sss_check_runas_user, SUDO_DEBUG_SSSD);

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
	    if (netgr_matches(val, NULL, NULL, runas_pw->pw_name)) {
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
    debug_decl(sudo_sss_check_runas_group, SUDO_DEBUG_SSSD);

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
    debug_decl(sudo_sss_check_runas, SUDO_DEBUG_SSSD);

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
    debug_decl(sudo_sss_check_host, SUDO_DEBUG_SSSD);

    if (rule == NULL)
	debug_return_bool(ret);

    /* get the values from the rule */
    switch (handle->fn_get_values(rule, "sudoHost", &val_array))
    {
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
    for (i = 0; val_array[i] != NULL; ++i) {
	val = val_array[i];
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "val[%d]=%s", i, val);

	/* match any or address or netgroup or hostname */
	if (!strcmp(val, "ALL") || addr_matches(val) ||
	    netgr_matches(val, user_host, user_shost, NULL) ||
	    hostname_matches(user_shost, user_host, val))
	    ret = true;

	sudo_debug_printf(SUDO_DEBUG_INFO,
	    "sssd/ldap sudoHost '%s' ... %s", val, ret ? "MATCH!" : "not");
    }

    handle->fn_free_values(val_array);

    debug_return_bool(ret);
}

/*
 * Look for netgroup specifcations in the sudoUser attribute and
 * if found, filter according to netgroup membership.
 *  returns:
 *   true -> netgroup spec found && netgroup member
 *  false -> netgroup spec found && not a member of netgroup
 *   true -> netgroup spec not found (filtered by SSSD already, netgroups are an exception)
 */
static bool
sudo_sss_filter_user_netgroup(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule)
{
    bool ret = false, netgroup_spec_found = false;
    char **val_array, *val;
    int i;
    debug_decl(sudo_sss_filter_user_netgroup, SUDO_DEBUG_SSSD);

    if (!handle || !rule)
	debug_return_bool(ret);

    switch (handle->fn_get_values(rule, "sudoUser", &val_array)) {
	case 0:
	    break;
	case ENOENT:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	    debug_return_bool(ret);
	default:
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"handle->fn_get_values(sudoUser): != 0");
	    debug_return_bool(ret);
    }

    for (i = 0; val_array[i] != NULL && !ret; ++i) {
	val = val_array[i];
	if (*val == '+') {
	    netgroup_spec_found = true;
	}
	sudo_debug_printf(SUDO_DEBUG_DEBUG, "val[%d]=%s", i, val);
	if (strcmp(val, "ALL") == 0 || netgr_matches(val, NULL, NULL, handle->pw->pw_name)) {
	    ret = true;
	    sudo_debug_printf(SUDO_DEBUG_DIAG,
		"sssd/ldap sudoUser '%s' ... MATCH! (%s)",
		val, handle->pw->pw_name);
	    break;
	}
    }
    handle->fn_free_values(val_array);
    debug_return_bool(netgroup_spec_found ? ret : true);
}

static int
sudo_sss_result_filterp(struct sudo_sss_handle *handle,
    struct sss_sudo_rule *rule, void *unused)
{
    (void)unused;
    debug_decl(sudo_sss_result_filterp, SUDO_DEBUG_SSSD);

    if (sudo_sss_check_host(handle, rule) &&
        sudo_sss_filter_user_netgroup(handle, rule))
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
    debug_decl(sudo_sss_result_get, SUDO_DEBUG_SSSD);

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
		    *state |= _SUDO_SSS_STATE_USERMATCH;
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
	sudo_sss_result_filterp, _SUDO_SSS_FILTER_INCLUDE, NULL);

    if (f_sss_result != NULL) {
	if (f_sss_result->num_rules > 0) {
	    if (state != NULL) {
		sudo_debug_printf(SUDO_DEBUG_DEBUG, "state |= HOSTMATCH");
		*state |= _SUDO_SSS_STATE_HOSTMATCH;
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
    debug_decl(sudo_sss_check_bool, SUDO_DEBUG_SSSD);

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
    debug_decl(sudo_sss_check_command, SUDO_DEBUG_LDAP)

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
    int i, foundbang, ret = UNSPEC;
    struct sudo_digest digest, *allowed_digest = NULL;
    debug_decl(sudo_sss_check_command, SUDO_DEBUG_SSSD);

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
	if (!strcmp(val, "ALL")) {
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
	if (command_matches(allowed_cmnd, allowed_args, NULL)) {
	    /*
	     * If allowed (no bang) set ret but keep on checking.
	     * If disallowed (bang), exit loop.
	     */
	    ret = foundbang ? false : true;
	}

	sudo_debug_printf(SUDO_DEBUG_INFO, "sssd/ldap sudoCommand '%s' ... %s",
	    val, ret == true ? "MATCH!" : "not");
	efree(allowed_cmnd);	/* cleanup */
    }

    handle->fn_free_values(val_array); /* more cleanup */

    debug_return_int(ret);
}

static void
sudo_sss_parse_options(struct sudo_sss_handle *handle, struct sss_sudo_rule *rule)
{
    int i;
    char op, *v, *val;
    char **val_array = NULL;
    debug_decl(sudo_sss_parse_options, SUDO_DEBUG_SSSD);

    if (rule == NULL)
	debug_return;

    switch (handle->fn_get_values(rule, "sudoOption", &val_array)) {
    case 0:
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	debug_return;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoOption): != 0");
	debug_return;
    }

    /* walk through options */
    for (i = 0; val_array[i] != NULL; i++) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "sssd/ldap sudoOption: '%s'",
	 val_array[i]);
	v = estrdup(val_array[i]);

	/* check for equals sign past first char */
	val = strchr(v, '=');
	if (val > v) {
	    *val++ = '\0';	/* split on = and truncate var */
	    op = *(val - 2);	/* peek for += or -= cases */
	    if (op == '+' || op == '-') {
		*(val - 2) = '\0';	/* found, remove extra char */
		/* case var+=val or var-=val */
		set_default(v, val, (int) op);
	    } else {
		/* case var=val */
		set_default(v, val, true);
	    }
	} else if (*v == '!') {
	    /* case !var Boolean False */
	    set_default(v + 1, NULL, false);
	} else {
	    /* case var Boolean True */
	    set_default(v, NULL, true);
	}
	efree(v);
    }

    handle->fn_free_values(val_array);
    debug_return;
}

static int
sudo_sss_lookup(struct sudo_nss *nss, int ret, int pwflag)
{
    int rc, setenv_implied;

    struct sudo_sss_handle *handle = nss->handle;
    struct sss_sudo_result *sss_result = NULL;
    struct sss_sudo_rule   *rule;
    uint32_t i, state = 0;
    debug_decl(sudo_sss_lookup, SUDO_DEBUG_SSSD);

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
		    (pwcheck == all && doauth == false)) {
		    doauth = sudo_sss_check_bool(handle, rule, "authenticate");
		}
		/* Only check the command when listing another user. */
		if (user_uid == 0 || list_pw == NULL ||
		    user_uid == list_pw->pw_uid ||
		    sudo_sss_check_command(handle, rule, NULL)) {
		    matched = true;
		    break;
		}
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
		    sudo_sss_parse_options(handle, rule);
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
    }
done:
    sudo_debug_printf(SUDO_DEBUG_DIAG, "Done with LDAP searches");

    if (!ISSET(ret, VALIDATE_OK)) {
	/* No matching entries. */
	if (pwflag && list_pw == NULL)
	    SET(ret, FLAG_NO_CHECK);
    }

    if (state & _SUDO_SSS_STATE_USERMATCH)
	CLR(ret, FLAG_NO_USER);
    if (state & _SUDO_SSS_STATE_HOSTMATCH)
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
    int i, found = false;
    debug_decl(sudo_sss_display_cmnd, SUDO_DEBUG_SSSD);

    if (handle == NULL)
	goto done;

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
	printf("%s%s%s\n", safe_cmnd ? safe_cmnd : user_cmnd,
	    user_args ? " " : "", user_args ? user_args : "");

    if (sss_result != NULL)
	handle->fn_free_result(sss_result);

    debug_return_int(!found);
}

static int
sudo_sss_display_defaults(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf)
{
    struct sudo_sss_handle *handle = nss->handle;

    struct sss_sudo_rule *rule;
    struct sss_sudo_result *sss_result = NULL;

    uint32_t sss_error = 0;

    char *prefix, *val, **val_array = NULL;
    int count = 0, i, j;

    debug_decl(sudo_sss_display_defaults, SUDO_DEBUG_SSSD);

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
	    lbuf_append(lbuf, "%s%s", prefix, val);
	    prefix = ", ";
	    count++;
	}

	handle->fn_free_values(val_array);
	val_array = NULL;
    }

    handle->fn_free_result(sss_result);
done:
    debug_return_int(count);
}

// ok
static int
sudo_sss_display_bound_defaults(struct sudo_nss *nss,
    struct passwd *pw, struct lbuf *lbuf)
{
    debug_decl(sudo_sss_display_bound_defaults, SUDO_DEBUG_SSSD);
    debug_return_int(0);
}

static int
sudo_sss_display_entry_long(struct sudo_sss_handle *handle,
    struct sss_sudo_rule *rule, struct lbuf *lbuf)
{
    char **val_array = NULL;
    int count = 0, i;
    debug_decl(sudo_sss_display_entry_long, SUDO_DEBUG_SSSD);

    /* get the RunAsUser Values from the entry */
    lbuf_append(lbuf, "    RunAsUsers: ");
    switch (handle->fn_get_values(rule, "sudoRunAsUser", &val_array)) {
    case 0:
	for (i = 0; val_array[i] != NULL; ++i)
	    lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	break;
    case ENOENT:
	switch (handle->fn_get_values(rule, "sudoRunAs", &val_array)) {
	case 0:
	    for (i = 0; val_array[i] != NULL; ++i)
		 lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	    handle->fn_free_values(val_array);
	    break;
	case ENOENT:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	    lbuf_append(lbuf, "%s", def_runas_default);
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
    lbuf_append(lbuf, "\n");

    /* get the RunAsGroup Values from the entry */
    switch (handle->fn_get_values(rule, "sudoRunAsGroup", &val_array)) {
    case 0:
	lbuf_append(lbuf, "    RunAsGroups: ");
	for (i = 0; val_array[i] != NULL; ++i)
	     lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	lbuf_append(lbuf, "\n");
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
	lbuf_append(lbuf, "    Options: ");
	for (i = 0; val_array[i] != NULL; ++i)
	     lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	lbuf_append(lbuf, "\n");
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
	lbuf_append(lbuf, _("    Commands:\n"));
	for (i = 0; val_array[i] != NULL; ++i) {
	     lbuf_append(lbuf, "\t%s\n", val_array[i]);
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
    struct sss_sudo_rule *rule, struct lbuf *lbuf)
{
    char **val_array = NULL;
    int count = 0, i;
    debug_decl(sudo_sss_display_entry_short, SUDO_DEBUG_SSSD);

    lbuf_append(lbuf, "    (");

    /* get the RunAsUser Values from the entry */
    switch (handle->fn_get_values(rule, "sudoRunAsUser", &val_array)) {
    case 0:
	for (i = 0; val_array[i] != NULL; ++i)
	     lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result. Trying old style (sudoRunAs).");
	/* try old style */
	switch (handle->fn_get_values(rule, "sudoRunAs", &val_array)) {
	case 0:
	    for (i = 0; val_array[i] != NULL; ++i)
		 lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	    handle->fn_free_values(val_array);
	    break;
	case ENOENT:
	    sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	    lbuf_append(lbuf, "%s", def_runas_default);
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
	lbuf_append(lbuf, " : ");
	for (i = 0; val_array[i] != NULL; ++i)
	     lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
	handle->fn_free_values(val_array);
	break;
    case ENOENT:
	sudo_debug_printf(SUDO_DEBUG_INFO, "No result.");
	break;
    default:
	sudo_debug_printf(SUDO_DEBUG_INFO, "handle->fn_get_values(sudoRunAsGroup): != 0");
	debug_return_int(count);
    }

    lbuf_append(lbuf, ") ");

    /* get the Option Values from the entry */
    switch (handle->fn_get_values(rule, "sudoOption", &val_array)) {
    case 0:
	for (i = 0; val_array[i] != NULL; ++i) {
	    char *cp = val_array[i];
	    if (*cp == '!')
		cp++;
	    if (strcmp(cp, "authenticate") == 0)
		lbuf_append(lbuf, val_array[i][0] == '!' ?
			    "NOPASSWD: " : "PASSWD: ");
	    else if (strcmp(cp, "noexec") == 0)
		lbuf_append(lbuf, val_array[i][0] == '!' ?
			    "EXEC: " : "NOEXEC: ");
	    else if (strcmp(cp, "setenv") == 0)
		lbuf_append(lbuf, val_array[i][0] == '!' ?
			    "NOSETENV: " : "SETENV: ");
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
	    lbuf_append(lbuf, "%s%s", i != 0 ? ", " : "", val_array[i]);
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
    lbuf_append(lbuf, "\n");

    debug_return_int(count);
}

static int
sudo_sss_display_privs(struct sudo_nss *nss, struct passwd *pw,
    struct lbuf *lbuf)
{
    struct sudo_sss_handle *handle = nss->handle;

    struct sss_sudo_result *sss_result = NULL;
    struct sss_sudo_rule *rule;
    unsigned int i, count = 0;
    debug_decl(sudo_sss_display_privs, SUDO_DEBUG_SSSD);

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

    if (sss_result != NULL)
	handle->fn_free_result(sss_result);

    debug_return_int(count);
}
