/*
 * Copyright (c) 2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <stdarg.h>

#include "sudoers.h"
#include "sudo_ldap.h"
#include "redblack.h"
#include "cvtsudoers.h"
#include "sudo_lbuf.h"
#include <gram.h>

struct seen_user {
    const char *name;
    unsigned long count;
};

static struct rbtree *seen_users;

static int
seen_user_compare(const void *aa, const void *bb)
{
    const struct seen_user *a = aa;
    const struct seen_user *b = bb;

    return strcasecmp(a->name, b->name);
}

static void
seen_user_free(void *v)
{
    struct seen_user *su = v;

    free((void *)su->name);
    free(su);
}

static bool
safe_string(const char *str)
{
    unsigned int ch = *str++;
    debug_decl(safe_string, SUDOERS_DEBUG_UTIL)

    /* Initial char must be <= 127 and not LF, CR, SPACE, ':', '<' */
    switch (ch) {
    case '\0':
	debug_return_bool(true);
    case '\n':
    case '\r':
    case ' ':
    case ':':
    case '<':
	debug_return_bool(false);
    default:
	if (ch > 127)
	    debug_return_bool(false);
    }

    /* Any value <= 127 decimal except NUL, LF, and CR is safe */
    while ((ch = *str++) != '\0') {
	if (ch > 127 || ch == '\n' || ch == '\r')
	    debug_return_bool(false);
    }

    debug_return_bool(true);
}

static bool
print_attribute_ldif(FILE *fp, const char *name, const char *value)
{
    const unsigned char *uvalue = (unsigned char *)value;
    char *encoded = NULL;
    size_t esize;
    debug_decl(print_attribute_ldif, SUDOERS_DEBUG_UTIL)

    if (!safe_string(value)) {
	const size_t vlen = strlen(value);
	esize = ((vlen + 2) / 3 * 4) + 1;
	if ((encoded = malloc(esize)) == NULL)
	    debug_return_bool(false);
	if (base64_encode(uvalue, vlen, encoded, esize) == (size_t)-1) {
	    free(encoded);
	    debug_return_bool(false);
	}
	fprintf(fp, "%s:: %s\n", name, encoded);
	free(encoded);
    } else if (*value != '\0') {
	fprintf(fp, "%s: %s\n", name, value);
    } else {
	fprintf(fp, "%s:\n", name);
    }

    debug_return_bool(true);
}

/*
 * Print sudoOptions from a defaults_list.
 */
static bool
print_options_ldif(FILE *fp, struct defaults_list *options)
{
    struct defaults *opt;
    char *attr_val;
    int len;
    debug_decl(print_options_ldif, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH(opt, options, entries) {
	if (opt->type != DEFAULTS)
	    continue;		/* don't support bound defaults */

	if (opt->val != NULL) {
	    /* There is no need to double quote values here. */
	    len = asprintf(&attr_val, "%s%s%s", opt->var,
		opt->op == '+' ? "+=" : opt->op == '-' ? "-=" : "=", opt->val);
	} else {
	    /* Boolean flag. */
	    len = asprintf(&attr_val, "%s%s",
		opt->op == false ? "!" : "", opt->var);
	}
	if (len == -1) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	print_attribute_ldif(fp, "sudoOption", attr_val);
	free(attr_val);
    }

    debug_return_bool(!ferror(fp));
}

/*
 * Print global Defaults in a single sudoRole object.
 */
static bool
print_global_defaults_ldif(FILE *fp, const char *base)
{
    unsigned int count = 0;
    struct sudo_lbuf lbuf;
    struct defaults *opt;
    char *dn;
    debug_decl(print_global_defaults_ldif, SUDOERS_DEBUG_UTIL)

    sudo_lbuf_init(&lbuf, NULL, 0, NULL, 80);

    TAILQ_FOREACH(opt, &parsed_policy.defaults, entries) {
	/* Skip bound Defaults (unsupported). */
	if (opt->type == DEFAULTS) {
	    count++;
	} else {
	    lbuf.len = 0;
	    sudo_lbuf_append(&lbuf, "# ");
	    sudoers_format_default_line(&lbuf, &parsed_policy, opt, false, true);
	    fprintf(fp, "# Unable to translate %s:%d\n%s\n",
		opt->file, opt->lineno, lbuf.buf);
	}
    }
    sudo_lbuf_destroy(&lbuf);

    if (count == 0)
	debug_return_bool(true);

    if (asprintf(&dn, "cn=defaults,%s", base) == -1) {
	sudo_fatalx(U_("%s: %s"), __func__,
	    U_("unable to allocate memory"));
    }
    print_attribute_ldif(fp, "dn", dn);
    free(dn);
    print_attribute_ldif(fp, "objectClass", "top");
    print_attribute_ldif(fp, "objectClass", "sudoRole");
    print_attribute_ldif(fp, "cn", "defaults");
    print_attribute_ldif(fp, "description", "Default sudoOption's go here");

    print_options_ldif(fp, &parsed_policy.defaults);
    putc('\n', fp);

    debug_return_bool(!ferror(fp));
}

/*
 * Print struct member in LDIF format as the specified attribute.
 * See print_member_int() in parse.c.
 */
static void
print_member_ldif(FILE *fp, char *name, int type, bool negated,
    int alias_type, const char *attr_name)
{
    struct alias *a;
    struct member *m;
    struct sudo_command *c;
    char *attr_val;
    int len;
    debug_decl(print_member_ldif, SUDOERS_DEBUG_UTIL)

    switch (type) {
    case ALL:
	print_attribute_ldif(fp, attr_name, negated ? "!ALL" : "ALL");
	break;
    case MYSELF:
	/* Only valid for sudoRunasUser */
	print_attribute_ldif(fp, attr_name, "");
	break;
    case COMMAND:
	c = (struct sudo_command *)name;
	len = asprintf(&attr_val, "%s%s%s%s%s%s%s%s",
	    c->digest ? digest_type_to_name(c->digest->digest_type) : "",
	    c->digest ? ":" : "", c->digest ? c->digest->digest_str : "",
	    c->digest ? " " : "", negated ? "!" : "", c->cmnd,
	    c->args ? " " : "", c->args ? c->args : "");
	if (len == -1) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	print_attribute_ldif(fp, attr_name, attr_val);
	free(attr_val);
	break;
    case ALIAS:
	if ((a = alias_get(&parsed_policy, name, alias_type)) != NULL) {
	    TAILQ_FOREACH(m, &a->members, entries) {
		print_member_ldif(fp, m->name, m->type,
		    negated ? !m->negated : m->negated, alias_type, attr_name);
	    }
	    alias_put(a);
	    break;
	}
	/* FALLTHROUGH */
    default:
	len = asprintf(&attr_val, "%s%s", negated ? "!" : "", name);
	if (len == -1) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	print_attribute_ldif(fp, attr_name, attr_val);
	free(attr_val);
	break;
    }

    debug_return;
}

/*
 * Print a Cmnd_Spec in LDIF format.
 * A pointer to the next Cmnd_Spec is passed in to make it possible to
 * merge adjacent entries that are identical in all but the command.
 */
static void
print_cmndspec_ldif(FILE *fp, struct cmndspec *cs, struct cmndspec **nextp, struct defaults_list *options)
{
    struct cmndspec *next = *nextp;
    struct member *m;
    struct tm *tp;
    bool last_one;
    char timebuf[sizeof("20120727121554Z")];
    debug_decl(print_cmndspec_ldif, SUDOERS_DEBUG_UTIL)

    /* Print runasuserlist as sudoRunAsUser attributes */
    if (cs->runasuserlist != NULL) {
	TAILQ_FOREACH(m, cs->runasuserlist, entries) {
	    print_member_ldif(fp, m->name, m->type, m->negated,
		RUNASALIAS, "sudoRunAsUser");
	}
    }

    /* Print runasgrouplist as sudoRunAsGroup attributes */
    if (cs->runasgrouplist != NULL) {
	TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
	    print_member_ldif(fp, m->name, m->type, m->negated,
		RUNASALIAS, "sudoRunAsGroup");
	}
    }

    /* Print sudoNotBefore and sudoNotAfter attributes */
    if (cs->notbefore != UNSPEC) {
	if ((tp = gmtime(&cs->notbefore)) == NULL) {
	    sudo_warn(U_("unable to get GMT time"));
	} else {
	    if (strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", tp) == 0) {
		sudo_warnx(U_("unable to format timestamp"));
	    } else {
		print_attribute_ldif(fp, "sudoNotBefore", timebuf);
	    }
	}
    }
    if (cs->notafter != UNSPEC) {
	if ((tp = gmtime(&cs->notafter)) == NULL) {
	    sudo_warn(U_("unable to get GMT time"));
	} else {
	    if (strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", tp) == 0) {
		sudo_warnx(U_("unable to format timestamp"));
	    } else {
		print_attribute_ldif(fp, "sudoNotAfter", timebuf);
	    }
	}
    }

    /* Print timeout as a sudoOption. */
    if (cs->timeout > 0) {
	char *attr_val;
	if (asprintf(&attr_val, "command_timeout=%d", cs->timeout) == -1) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	print_attribute_ldif(fp, "sudoOption", attr_val);
	free(attr_val);
    }

    /* Print tags as sudoOption attributes */
    if (TAGS_SET(cs->tags)) {
	struct cmndtag tag = cs->tags;

	if (tag.nopasswd != UNSPEC) {
	    print_attribute_ldif(fp, "sudoOption",
		tag.nopasswd ? "!authenticate" : "authenticate");
	}
	if (tag.noexec != UNSPEC) {
	    print_attribute_ldif(fp, "sudoOption",
		tag.noexec ? "noexec" : "!noexec");
	}
	if (tag.send_mail != UNSPEC) {
	    if (tag.send_mail) {
		print_attribute_ldif(fp, "sudoOption", "mail_all_cmnds");
	    } else {
		print_attribute_ldif(fp, "sudoOption", "!mail_all_cmnds");
		print_attribute_ldif(fp, "sudoOption", "!mail_always");
		print_attribute_ldif(fp, "sudoOption", "!mail_no_perms");
	    }
	}
	if (tag.setenv != UNSPEC && tag.setenv != IMPLIED) {
	    print_attribute_ldif(fp, "sudoOption",
		tag.setenv ? "setenv" : "!setenv");
	}
	if (tag.follow != UNSPEC) {
	    print_attribute_ldif(fp, "sudoOption",
		tag.follow ? "sudoedit_follow" : "!sudoedit_follow");
	}
	if (tag.log_input != UNSPEC) {
	    print_attribute_ldif(fp, "sudoOption",
		tag.log_input ? "log_input" : "!log_input");
	}
	if (tag.log_output != UNSPEC) {
	    print_attribute_ldif(fp, "sudoOption",
		tag.log_output ? "log_output" : "!log_output");
	}
    }
    print_options_ldif(fp, options);

#ifdef HAVE_SELINUX
    /* Print SELinux role/type */
    if (cs->role != NULL && cs->type != NULL) {
	char *attr_val;
	int len;

	len = asprintf(&attr_val, "role=%s", cs->role);
	if (len == -1) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	print_attribute_ldif(fp, "sudoOption", attr_val);
	free(attr_val);

	len = asprintf(&attr_val, "type=%s", cs->type);
	if (len == -1) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	print_attribute_ldif(fp, "sudoOption", attr_val);
	free(attr_val);
    }
#endif /* HAVE_SELINUX */

#ifdef HAVE_PRIV_SET
    /* Print Solaris privs/limitprivs */
    if (cs->privs != NULL || cs->limitprivs != NULL) {
	char *attr_val;
	int len;

	if (cs->privs != NULL) {
	    len = asprintf(&attr_val, "privs=%s", cs->privs);
	    if (len == -1) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    print_attribute_ldif(fp, "sudoOption", attr_val);
	    free(attr_val);
	}
	if (cs->limitprivs != NULL) {
	    len = asprintf(&attr_val, "limitprivs=%s", cs->limitprivs);
	    if (len == -1) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    print_attribute_ldif(fp, "sudoOption", attr_val);
	    free(attr_val);
	}
    }
#endif /* HAVE_PRIV_SET */

    /*
     * Merge adjacent commands with matching tags, runas, SELinux
     * role/type and Solaris priv settings.
     */
    for (;;) {
	/* Does the next entry differ only in the command itself? */
	/* XXX - move into a function that returns bool */
	/* XXX - TAG_SET does not account for implied SETENV */
	last_one = next == NULL ||
	    RUNAS_CHANGED(cs, next) || TAGS_CHANGED(cs->tags, next->tags)
#ifdef HAVE_PRIV_SET
	    || cs->privs != next->privs || cs->limitprivs != next->limitprivs
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
	    || cs->role != next->role || cs->type != next->type
#endif /* HAVE_SELINUX */
	    ;

	print_member_ldif(fp, cs->cmnd->name, cs->cmnd->type, cs->cmnd->negated,
	    CMNDALIAS, "sudoCommand");
	if (last_one)
	    break;
	cs = next;
	next = TAILQ_NEXT(cs, entries);
    }

    *nextp = next;

    debug_return;
}

/*
 * Convert user name to cn, avoiding duplicates and quoting as needed.
 * See http://www.faqs.org/rfcs/rfc2253.html
 */
static char *
user_to_cn(const char *user)
{
    struct seen_user key, *su = NULL;
    struct rbnode *node;
    const char *src;
    char *cn, *dst;
    size_t size;
    debug_decl(user_to_cn, SUDOERS_DEBUG_UTIL)

    /* Allocate as much as we could possibly need. */
    size = (2 * strlen(user)) + 64 + 1;
    if ((cn = malloc(size)) == NULL)
	goto bad;

    /*
     * Increment the number of times we have seen this user.
     */
    key.name = user;
    node = rbfind(seen_users, &key);
    if (node != NULL) {
	su = node->data;
    } else {
	if ((su = malloc(sizeof(*su))) == NULL)
	    goto bad;
	su->count = 0;
	if ((su->name = strdup(user)) == NULL)
	    goto bad;
	if (rbinsert(seen_users, su, NULL) != 0)
	    goto bad;
    }

    /* Build cn, quoting special chars as needed (we allocated 2 x len). */
    for (src = user, dst = cn; *src != '\0'; src++) {
	switch (*src) {
	case ',':
	case '+':
	case '"':
	case '\\':
	case '<':
	case '>':
	case '#':
	case ';':
	    *dst++ = '\\';	/* always escape */
	    break;
	case ' ':
	    if (src == user || src[1] == '\0')
		*dst++ = '\\';	/* only escape at beginning or end of string */
	    break;
	default:
	    break;
	}
	*dst++ = *src;
    }
    *dst = '\0';

    /* Append count if there are duplicate users (cn must be unique). */
    if (su->count != 0) {
	size -= (size_t)(dst - cn);
	if ((size_t)snprintf(dst, size, "_%lu", su->count) >= size) {
	    sudo_warnx(U_("internal error, %s overflow"), __func__);
	    goto bad;
	}
    }
    su->count++;

    debug_return_str(cn);
bad:
    if (su != NULL && su->count == 0)
	seen_user_free(su);
    free(cn);
    debug_return_str(NULL);
}

/*
 * Print a single User_Spec.
 */
static bool
print_userspec_ldif(FILE *fp, struct userspec *us, struct cvtsudoers_config *conf)
{
    struct privilege *priv;
    struct member *m;
    struct cmndspec *cs, *next;
    debug_decl(print_userspec_ldif, SUDOERS_DEBUG_UTIL)

    /*
     * Each userspec struct may contain multiple privileges for
     * the user.  We export each privilege as a separate sudoRole
     * object for simplicity's sake.
     */
    TAILQ_FOREACH(priv, &us->privileges, entries) {
	TAILQ_FOREACH_SAFE(cs, &priv->cmndlist, entries, next) {
	    const char *base = conf->sudoers_base;
	    char *cn, *dn;

	    /*
	     * Increment the number of times we have seen this user.
	     * If more than one user is listed, just use the first one.
	     */
	    m = TAILQ_FIRST(&us->users);
	    cn = user_to_cn(m->type == ALL ? "ALL" : m->name);
	    if (cn == NULL || asprintf(&dn, "cn=%s,%s", cn, base) == -1) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }

	    print_attribute_ldif(fp, "dn", dn);
	    print_attribute_ldif(fp, "objectClass", "top");
	    print_attribute_ldif(fp, "objectClass", "sudoRole");
	    print_attribute_ldif(fp, "cn", cn);
	    free(cn);
	    free(dn);

	    TAILQ_FOREACH(m, &us->users, entries) {
		print_member_ldif(fp, m->name, m->type, m->negated,
		    USERALIAS, "sudoUser");
	    }

	    TAILQ_FOREACH(m, &priv->hostlist, entries) {
		print_member_ldif(fp, m->name, m->type, m->negated,
		    HOSTALIAS, "sudoHost");
	    }

	    print_cmndspec_ldif(fp, cs, &next, &priv->defaults);

	    if (conf->sudo_order != 0) {
		char numbuf[(((sizeof(conf->sudo_order) * 8) + 2) / 3) + 2];
		(void)snprintf(numbuf, sizeof(numbuf), "%u", conf->sudo_order);
		print_attribute_ldif(fp, "sudoOrder", numbuf);
		putc('\n', fp);
		conf->sudo_order += conf->order_increment;
	    }
	}
    }

    debug_return_bool(!ferror(fp));
}

/*
 * Print User_Specs.
 */
static bool
print_userspecs_ldif(FILE *fp, struct cvtsudoers_config *conf)
{
    struct userspec *us;
    debug_decl(print_userspecs_ldif, SUDOERS_DEBUG_UTIL)
 
    TAILQ_FOREACH(us, &parsed_policy.userspecs, entries) {
	if (!print_userspec_ldif(fp, us, conf))
	    debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Export the parsed sudoers file in LDIF format.
 */
bool
convert_sudoers_ldif(const char *output_file, struct cvtsudoers_config *conf)
{
    bool ret = true;
    FILE *output_fp = stdout;
    debug_decl(convert_sudoers_ldif, SUDOERS_DEBUG_UTIL)

    if (conf->sudoers_base == NULL) {
	sudo_fatalx(U_("the SUDOERS_BASE environment variable is not set and the -b option was not specified."));
    }

    if (output_file != NULL && strcmp(output_file, "-") != 0) {
	if ((output_fp = fopen(output_file, "w")) == NULL)
	    sudo_fatal(U_("unable to open %s"), output_file);
    }

    /* Create a dictionary of already-seen users. */
    seen_users = rbcreate(seen_user_compare);

    /* Dump global Defaults in LDIF format. */
    if (!ISSET(conf->suppress, SUPPRESS_DEFAULTS))
	print_global_defaults_ldif(output_fp, conf->sudoers_base);

    /* Dump User_Specs in LDIF format, expanding Aliases. */
    if (!ISSET(conf->suppress, SUPPRESS_PRIVS))
	print_userspecs_ldif(output_fp, conf);

    /* Clean up. */
    rbdestroy(seen_users, seen_user_free);

    (void)fflush(output_fp);
    if (ferror(output_fp))
	ret = false;
    if (output_fp != stdout)
	fclose(output_fp);

    debug_return_bool(ret);
}

struct sudo_role {
    STAILQ_ENTRY(sudo_role) entries;
    char *cn;
    char *notbefore;
    char *notafter;
    double order;
    struct cvtsudoers_str_list *cmnds;
    struct cvtsudoers_str_list *hosts;
    struct cvtsudoers_str_list *users;
    struct cvtsudoers_str_list *runasusers;
    struct cvtsudoers_str_list *runasgroups;
    struct cvtsudoers_str_list *options;
};
STAILQ_HEAD(sudo_role_list, sudo_role);

static void
sudo_role_free(struct sudo_role *role)
{
    debug_decl(sudo_role_free, SUDOERS_DEBUG_UTIL)

    if (role != NULL) {
	free(role->cn);
	free(role->notbefore);
	free(role->notafter);
	str_list_free(role->cmnds);
	str_list_free(role->hosts);
	str_list_free(role->users);
	str_list_free(role->runasusers);
	str_list_free(role->runasgroups);
	str_list_free(role->options);
	free(role);
    }

    debug_return;
}

static struct sudo_role *
sudo_role_alloc(void)
{
    struct sudo_role *role;
    debug_decl(sudo_role_alloc, SUDOERS_DEBUG_UTIL)

    role = calloc(1, sizeof(*role));
    if (role != NULL) {
	role->cmnds = str_list_alloc();
	role->hosts = str_list_alloc();
	role->users = str_list_alloc();
	role->runasusers = str_list_alloc();
	role->runasgroups = str_list_alloc();
	role->options = str_list_alloc();
	if (role->cmnds == NULL || role->hosts == NULL ||
	    role->users == NULL || role->runasusers == NULL ||
	    role->runasgroups == NULL || role->options == NULL) {
	    sudo_role_free(role);
	    role = NULL;
	}
    }

    debug_return_ptr(role);
}

/*
 * Parse an LDIF attribute, including base64 support.
 * See http://www.faqs.org/rfcs/rfc2849.html
 */
static char *
ldif_parse_attribute(char *str)
{
    bool encoded = false;
    char *attr, *ep;
    size_t len;
    debug_decl(ldif_parse_attribute, SUDOERS_DEBUG_UTIL)

    /* Check for foo:: base64str. */
    if (*str == ':') {
	encoded = true;
	str++;
    }

    /* Trim leading and trailing space. */
    while (*str == ' ')
	str++;

    ep = str + strlen(str);
    while (ep > str && ep[-1] == ' ') {
	/* Don't trim ecaped trailing space if not base64. */
	if (!encoded && ep != str && ep[-2] == '\\')
	    break;
	*--ep = '\0';
    }

    attr = str;
    if (encoded) {
	/*
	 * Decode base64 inline and add NUL-terminator.
	 * The copy allows us to provide a useful message on error.
	 */
	char *copy = strdup(str);
	if (copy == NULL) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	len = base64_decode(copy, (unsigned char *)attr, strlen(attr));
	if (len == (size_t)-1) {
	    sudo_warnx(U_("ignoring invalid attribute value: %s"), copy);
	    free(copy);
	    debug_return_str(NULL);
	}
	attr[len] = '\0';
	free(copy);
    }

    debug_return_str(attr);
}

/*
 * Allocate a struct cvtsudoers_string, store str in it and
 * insert into the specified strlist.
 */
static void
ldif_store_string(const char *str, struct cvtsudoers_str_list *strlist, bool sorted)
{
    struct cvtsudoers_string *ls;
    debug_decl(ldif_store_string, SUDOERS_DEBUG_UTIL)

    if ((ls = cvtsudoers_string_alloc(str)) == NULL) {
	sudo_fatalx(U_("%s: %s"), __func__,
	    U_("unable to allocate memory"));
    }
    if (!sorted) {
	STAILQ_INSERT_TAIL(strlist, ls, entries);
    } else {
	struct cvtsudoers_string *prev, *next;

	/* Insertion sort, list is small. */
	prev = STAILQ_FIRST(strlist);
	if (prev == NULL || strcasecmp(str, prev->str) <= 0) {
	    STAILQ_INSERT_HEAD(strlist, ls, entries);
	} else {
	    while ((next = STAILQ_NEXT(prev, entries)) != NULL) {
		if (strcasecmp(str, next->str) <= 0)
		    break;
		prev = next;
	    }
	    STAILQ_INSERT_AFTER(strlist, prev, ls, entries);
	}
    }

    debug_return;
}

/*
 * Iterator for sudo_ldap_role_to_priv().
 * Takes a pointer to a struct cvtsudoers_string *.
 * Returns the string or NULL if we've reached the end.
 */
static char *
cvtsudoers_string_iter(void **vp)
{
    struct cvtsudoers_string *ls = *vp;

    if (ls == NULL)
	return NULL;

    *vp = STAILQ_NEXT(ls, entries);

    return ls->str;
}

static int
role_order_cmp(const void *va, const void *vb)
{
    const struct sudo_role *a = *(const struct sudo_role **)va;
    const struct sudo_role *b = *(const struct sudo_role **)vb;
    debug_decl(role_order_cmp, SUDOERS_DEBUG_LDAP)

    debug_return_int(a->order < b->order ? -1 :
        (a->order > b->order ? 1 : 0));
}

/*
 * Parse list of sudoOption and store in global defaults list.
 */
static void
ldif_store_options(struct cvtsudoers_str_list *options)
{
    struct defaults *d;
    struct cvtsudoers_string *ls;
    char *var, *val;
    debug_decl(ldif_store_options, SUDOERS_DEBUG_UTIL)

    STAILQ_FOREACH(ls, options, entries) {
	if ((d = calloc(1, sizeof(*d))) == NULL ||
	    (d->binding = malloc(sizeof(*d->binding))) == NULL) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	TAILQ_INIT(d->binding);
	d->type = DEFAULTS;
	d->op = sudo_ldap_parse_option(ls->str, &var, &val);
	if ((d->var = strdup(var)) == NULL) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	if (val != NULL) {
	    if ((d->val = strdup(val)) == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	}
	TAILQ_INSERT_TAIL(&parsed_policy.defaults, d, entries);
    }
    debug_return;
}

static int
str_list_cmp(const void *aa, const void *bb)
{
    const struct cvtsudoers_str_list *a = aa;
    const struct cvtsudoers_str_list *b = bb;
    const struct cvtsudoers_string *lsa = STAILQ_FIRST(a);
    const struct cvtsudoers_string *lsb = STAILQ_FIRST(b);
    int ret;

    while (lsa != NULL && lsb != NULL) {
	if ((ret = strcmp(lsa->str, lsb->str)) != 0)
	    return ret;
	lsa = STAILQ_NEXT(lsa, entries);
	lsb = STAILQ_NEXT(lsb, entries);
    }
    return lsa == lsb ? 0 : (lsa == NULL ? -1 : 1);
}

static int
str_list_cache(struct rbtree *cache, struct cvtsudoers_str_list **strlistp)
{
    struct cvtsudoers_str_list *strlist = *strlistp;
    struct rbnode *node;
    int ret;
    debug_decl(str_list_cache, SUDOERS_DEBUG_UTIL)

    ret = rbinsert(cache, strlist, &node);
    switch (ret) {
    case 0:
	/* new entry, take a ref for the cache */
	strlist->refcnt++;
	break;
    case 1:
	/* already exists, use existing and take a ref. */
	str_list_free(strlist);
	strlist = node->data;
	strlist->refcnt++;
	*strlistp = strlist;
	break;
    }
    debug_return_int(ret);
}

/*
 * Convert a sudoRole to sudoers format and store in the global sudoers
 * data structures.
 */
static void
role_to_sudoers(struct sudo_role *role, bool store_options,
    bool reuse_userspec, bool reuse_privilege, bool reuse_runas)
{
    struct privilege *priv;
    struct cvtsudoers_string *ls;
    struct userspec *us;
    struct member *m;
    debug_decl(role_to_sudoers, SUDOERS_DEBUG_UTIL)

    /*
     * TODO: use cn to create a UserAlias if multiple users in it?
     */

    if (reuse_userspec) {
	/* Re-use the previous userspec */
	us = TAILQ_LAST(&parsed_policy.userspecs, userspec_list);
    } else {
	/* Allocate a new userspec and fill in the user list. */
	if ((us = calloc(1, sizeof(*us))) == NULL) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	TAILQ_INIT(&us->privileges);
	TAILQ_INIT(&us->users);
	STAILQ_INIT(&us->comments);

	STAILQ_FOREACH(ls, role->users, entries) {
	    char *user = ls->str;

	    if ((m = calloc(1, sizeof(*m))) == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    m->negated = sudo_ldap_is_negated(&user);
	    m->name = strdup(user);
	    if (m->name == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    if (strcmp(user, "ALL") == 0) {
		m->type = ALL;
	    } else if (*user == '+') {
		m->type = NETGROUP;
	    } else if (*user == '%') {
		m->type = USERGROUP;
	    } else {
		m->type = WORD;
	    }
	    TAILQ_INSERT_TAIL(&us->users, m, entries);
	}
    }

    /* Add source role as a comment. */
    if (role->cn != NULL) {
	struct sudoers_comment *comment = NULL;
	if (reuse_userspec) {
	    /* Try to re-use comment too. */
	    STAILQ_FOREACH(comment, &us->comments, entries) {
		if (strncmp(comment->str, "sudoRole ", 9) == 0) {
		    char *tmpstr;
		    if (asprintf(&tmpstr, "%s, %s", comment->str, role->cn) == -1) {
			sudo_fatalx(U_("%s: %s"), __func__,
			    U_("unable to allocate memory"));
		    }
		    free(comment->str);
		    comment->str = tmpstr;
		    break;
		}
	    }
	}
	if (comment == NULL) {
	    /* Create a new comment. */
	    if ((comment = malloc(sizeof(*comment))) == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    if (asprintf(&comment->str, "sudoRole %s", role->cn) == -1) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    STAILQ_INSERT_TAIL(&us->comments, comment, entries);
	}
    }

    /* Convert role to sudoers privilege. */
    priv = sudo_ldap_role_to_priv(role->cn, STAILQ_FIRST(role->hosts),
	STAILQ_FIRST(role->runasusers), STAILQ_FIRST(role->runasgroups),
	STAILQ_FIRST(role->cmnds), STAILQ_FIRST(role->options),
	role->notbefore, role->notafter, true, store_options,
	cvtsudoers_string_iter);
    if (priv == NULL) {
	sudo_fatalx(U_("%s: %s"), __func__,
	    U_("unable to allocate memory"));
    }

    if (reuse_privilege) {
	/* Hostspec unchanged, append cmndlist to previous privilege. */
	struct privilege *prev_priv = TAILQ_LAST(&us->privileges, privilege_list);
	if (reuse_runas) {
	    /* Runas users and groups same if as in previous privilege. */
	    struct member_list *runasuserlist =
		TAILQ_FIRST(&prev_priv->cmndlist)->runasuserlist;
	    struct member_list *runasgrouplist =
		TAILQ_FIRST(&prev_priv->cmndlist)->runasgrouplist;
	    struct cmndspec *cmndspec = TAILQ_FIRST(&priv->cmndlist);

	    /* Free duplicate runas lists. */
	    if (cmndspec->runasuserlist != NULL)
		free_members(cmndspec->runasuserlist);
	    if (cmndspec->runasgrouplist != NULL)
		free_members(cmndspec->runasgrouplist);

	    /* Update cmndspec with previous runas lists. */
	    TAILQ_FOREACH(cmndspec, &priv->cmndlist, entries) {
		cmndspec->runasuserlist = runasuserlist;
		cmndspec->runasgrouplist = runasgrouplist;
	    }
	}
	TAILQ_CONCAT(&prev_priv->cmndlist, &priv->cmndlist, entries);
	free_privilege(priv);
    } else {
	TAILQ_INSERT_TAIL(&us->privileges, priv, entries);
    }

    /* Add finished userspec to the list if new. */
    if (!reuse_userspec)
	TAILQ_INSERT_TAIL(&parsed_policy.userspecs, us, entries);

    debug_return;
}

/*
 * Convert the list of sudoRoles to sudoers format and
 * store in the global sudoers data structures.
 */
static void
ldif_to_sudoers(struct sudo_role_list *roles, unsigned int numroles,
    bool store_options)
{
    struct sudo_role **role_array, *role = NULL;
    unsigned int n;
    debug_decl(ldif_to_sudoers, SUDOERS_DEBUG_UTIL)

    /* Convert from list of roles to array and sort by order. */
    role_array = reallocarray(NULL, numroles + 1, sizeof(*role_array));
    for (n = 0; n < numroles; n++) {
	if ((role = STAILQ_FIRST(roles)) == NULL)
	    break;	/* cannot happen */
	STAILQ_REMOVE_HEAD(roles, entries);
	role_array[n] = role;
    }
    role_array[n] = NULL;
    qsort(role_array, numroles, sizeof(*role_array), role_order_cmp);

    /*
     * Iterate over roles in sorted order, converting to sudoers.
     */
    for (n = 0; n < numroles; n++) {
	bool reuse_userspec = false;
	bool reuse_privilege = false;
	bool reuse_runas = false;

	role = role_array[n];

	/* Check whether we can reuse the previous user and host specs */
	if (n > 0 && role->users == role_array[n - 1]->users) {
	    reuse_userspec = true;

	    /*
	     * Since options are stored per-privilege we can't
	     * append to the previous privilege's cmndlist if
	     * we are storing options.
	     */
	    if (!store_options) {
		if (role->hosts == role_array[n - 1]->hosts) {
		    reuse_privilege = true;

		    /* Reuse runasusers and runasgroups if possible. */
		    if (role->runasusers == role_array[n - 1]->runasusers &&
			role->runasgroups == role_array[n - 1]->runasgroups)
			reuse_runas = true;
		}
	    }
	}

	role_to_sudoers(role, store_options, reuse_userspec,
	    reuse_privilege, reuse_runas);
    }

    /* Clean up. */
    for (n = 0; n < numroles; n++)
	sudo_role_free(role_array[n]);
    free(role_array);

    debug_return;
}

/*
 * Given a cn with possible quoted characters, return a copy of
 * the cn with quote characters ('\\') removed.
 * The caller is responsible for freeing the returned string.
 */
static
char *unquote_cn(const char *src)
{
    char *dst, *new_cn;
    size_t len;
    debug_decl(unquote_cn, SUDOERS_DEBUG_UTIL)

    len = strlen(src);
    if ((new_cn = malloc(len + 1)) == NULL)
	debug_return_str(NULL);

    for (dst = new_cn; *src != '\0';) {
	if (src[0] == '\\' && src[1] != '\0')
	    src++;
	*dst++ = *src++;
    }
    *dst = '\0';

    debug_return_str(new_cn);
}

/*
 * Parse a sudoers file in LDIF format, https://tools.ietf.org/html/rfc2849
 * Parsed sudoRole objects are stored in the global sudoers data structures.
 */
bool
parse_ldif(const char *input_file, struct cvtsudoers_config *conf)
{
    struct sudo_role_list roles = STAILQ_HEAD_INITIALIZER(roles);
    struct sudo_role *role = NULL;
    struct rbtree *usercache, *groupcache, *hostcache;
    unsigned numroles = 0;
    bool in_role = false;
    size_t linesize = 0;
    char *attr, *line = NULL, *savedline = NULL;
    ssize_t savedlen = 0;
    bool mismatch = false;
    FILE *fp;
    debug_decl(parse_ldif, SUDOERS_DEBUG_UTIL)

    /* Open LDIF file and parse it. */
    if (strcmp(input_file, "-") == 0) {
        fp = stdin;
        input_file = "stdin";
    } else if ((fp = fopen(input_file, "r")) == NULL)
        sudo_fatal(U_("unable to open %s"), input_file);
    init_parser(input_file, false);

    /*
     * We cache user, group and host lists to make it eay to detect when there
     * are identical lists (simple pointer compare).  This makes it possible
     * to merge multiplpe sudoRole objects into a single UserSpec and/or
     * Privilege.  The lists are sorted since LDAP order is arbitrary.
     */
    usercache = rbcreate(str_list_cmp);
    groupcache = rbcreate(str_list_cmp);
    hostcache = rbcreate(str_list_cmp);
    if (usercache == NULL || groupcache == NULL || hostcache == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    /* Read through input, parsing into sudo_roles and global defaults. */
    for (;;) {
	int ch;
	ssize_t len = getline(&line, &linesize, fp);

	/* Trim trailing return or newline. */
	while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n'))
	    line[--len] = '\0';

	/* Blank line or EOF terminates an entry. */
	if (len <= 0) {
	    if (in_role) {
		if (role->cn != NULL && strcmp(role->cn, "defaults") == 0) {
		    ldif_store_options(role->options);
		    sudo_role_free(role);
		    role = NULL;
		} else if (STAILQ_EMPTY(role->users) ||
		    STAILQ_EMPTY(role->hosts) || STAILQ_EMPTY(role->cmnds)) {
		    /* Incomplete role. */
		    sudo_warnx(U_("ignoring incomplete sudoRole: cn: %s"),
			role->cn ? role->cn : "UNKNOWN");
		    sudo_role_free(role);
		    role = NULL;
		} else {
		    /* Cache users, hosts, runasusers and runasgroups. */
		    if (str_list_cache(usercache, &role->users) == -1 ||
			str_list_cache(hostcache, &role->hosts) == -1 ||
			str_list_cache(usercache, &role->runasusers) == -1 ||
			str_list_cache(groupcache, &role->runasgroups) == -1) {
			sudo_fatalx(U_("%s: %s"), __func__,
			    U_("unable to allocate memory"));
		    }

		    /* Store finished role. */
		    STAILQ_INSERT_TAIL(&roles, role, entries);
		    numroles++;
		}
		role = NULL;
		in_role = false;
	    }
	    if (len == -1) {
		/* EOF */
		break;
	    }
	    mismatch = false;
	    continue;
	}

	if (savedline != NULL) {
	    char *tmp;

	    /* Append to saved line. */
	    linesize = savedlen + len + 1;
	    if ((tmp = realloc(savedline, linesize)) == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	    memcpy(tmp + savedlen, line, len + 1);
	    free(line);
	    line = tmp;
	    savedline = NULL;
	} else {
	    /* Skip comment lines or records that don't match the base. */
	    if (*line == '#' || mismatch)
		continue;
	}

	/* Check for folded line */
	if ((ch = getc(fp)) == ' ') {
	    /* folded line, append to the saved portion. */
	    savedlen = len;
	    savedline = line;
	    line = NULL;
	    linesize = 0;
	    continue;
	} else {
	    /* not folded, push back ch */
	    ungetc(ch, fp);
	}

	/* Allocate new role as needed. */
	if (role == NULL) {
	    if ((role = sudo_role_alloc()) == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }
	}

	/* Parse dn and objectClass. */
	if (strncasecmp(line, "dn:", 3) == 0) {
	    /* Compare dn to base, if specified. */
	    if (conf->sudoers_base != NULL) {
		attr = ldif_parse_attribute(line + 3);
		if (attr == NULL) {
		    /* invalid attribute */
		    mismatch = true;
		    continue;
		}
		/* Skip over cn if present. */
		if (strncasecmp(attr, "cn=", 3) == 0) {
		    for (attr += 3; *attr != '\0'; attr++) {
			/* Handle escaped ',' chars. */
			if (*attr == '\\')
			    attr++;
			if (*attr == ',') {
			    attr++;
			    break;
			}
		    }
		}
		if (strcasecmp(attr, conf->sudoers_base) != 0) {
		    /* Doesn't match base, skip the rest of it. */
		    mismatch = true;
		    continue;
		}
	    }
	} else if (strncmp(line, "objectClass:", 12) == 0) {
	    attr = ldif_parse_attribute(line + 12);
	    if (attr != NULL && strcmp(attr, "sudoRole") == 0)
		in_role = true;
	}

	/* Not in a sudoRole, keep reading. */
	if (!in_role)
	    continue;

	/* Part of a sudoRole, parse it. */
	if (strncmp(line, "cn:", 3) == 0) {
	    attr = ldif_parse_attribute(line + 3);
	    if (attr != NULL) {
		free(role->cn);
		role->cn = unquote_cn(attr);
		if (role->cn == NULL) {
		    sudo_fatalx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		}
	    }
	} else if (strncmp(line, "sudoUser:", 9) == 0) {
	    attr = ldif_parse_attribute(line + 9);
	    if (attr != NULL)
		ldif_store_string(attr, role->users, true);
	} else if (strncmp(line, "sudoHost:", 9) == 0) {
	    attr = ldif_parse_attribute(line + 9);
	    if (attr != NULL)
		ldif_store_string(attr, role->hosts, true);
	} else if (strncmp(line, "sudoRunAs:", 10) == 0) {
	    attr = ldif_parse_attribute(line + 10);
	    if (attr != NULL)
		ldif_store_string(attr, role->runasusers, true);
	} else if (strncmp(line, "sudoRunAsUser:", 14) == 0) {
	    attr = ldif_parse_attribute(line + 14);
	    if (attr != NULL)
		ldif_store_string(attr, role->runasusers, true);
	} else if (strncmp(line, "sudoRunAsGroup:", 15) == 0) {
	    attr = ldif_parse_attribute(line + 15);
	    if (attr != NULL)
		ldif_store_string(attr, role->runasgroups, true);
	} else if (strncmp(line, "sudoCommand:", 12) == 0) {
	    attr = ldif_parse_attribute(line + 12);
	    if (attr != NULL)
		ldif_store_string(attr, role->cmnds, false);
	} else if (strncmp(line, "sudoOption:", 11) == 0) {
	    attr = ldif_parse_attribute(line + 11);
	    if (attr != NULL)
		ldif_store_string(attr, role->options, false);
	} else if (strncmp(line, "sudoOrder:", 10) == 0) {
	    char *ep;
	    attr = ldif_parse_attribute(line + 10);
	    if (attr != NULL) {
		role->order = strtod(attr, &ep);
		if (ep == attr || *ep != '\0')
		    sudo_warnx(U_("invalid sudoOrder attribute: %s"), attr);
	    }
	} else if (strncmp(line, "sudoNotBefore:", 14) == 0) {
	    attr = ldif_parse_attribute(line + 14);
	    if (attr != NULL) {
		free(role->notbefore);
		role->notbefore = strdup(attr);
		if (role->notbefore == NULL) {
		    sudo_fatalx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		}
	    }
	} else if (strncmp(line, "sudoNotAfter:", 13) == 0) {
	    attr = ldif_parse_attribute(line + 13);
	    if (attr != NULL) {
		free(role->notafter);
		role->notafter = strdup(attr);
		if (role->notafter == NULL) {
		    sudo_fatalx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		}
	    }
	}
    }
    sudo_role_free(role);
    free(line);

    /* Convert from roles to sudoers data structures. */
    ldif_to_sudoers(&roles, numroles, conf->store_options);

    /* Clean up. */
    rbdestroy(usercache, str_list_free);
    rbdestroy(groupcache, str_list_free);
    rbdestroy(hostcache, str_list_free);

    if (fp != stdin)
	fclose(fp);

    debug_return_bool(true);
}
