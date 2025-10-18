/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2018-2024 Todd C. Miller <Todd.Miller@sudo.ws>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <stdarg.h>

#include <sudoers.h>
#include <sudo_ldap.h>
#include <redblack.h>
#include <cvtsudoers.h>
#include <sudo_lbuf.h>
#include <gram.h>

struct seen_user {
    const char *name;
    unsigned long count;
};

static struct rbtree *seen_users;

static bool printf_attribute_ldif(FILE *fp, const char *name, const char * restrict fmt, ...) sudo_printflike(3, 4);

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
    const unsigned char *ustr = (const unsigned char *)str;
    unsigned char ch = *ustr++;
    debug_decl(safe_string, SUDOERS_DEBUG_UTIL);

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
    while ((ch = *ustr++) != '\0') {
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
    debug_decl(print_attribute_ldif, SUDOERS_DEBUG_UTIL);

    if (!safe_string(value)) {
	const size_t vlen = strlen(value);
	esize = ((vlen + 2) / 3 * 4) + 1;
	if ((encoded = malloc(esize)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_bool(false);
	}
	if (sudo_base64_encode(uvalue, vlen, encoded, esize) == (size_t)-1) {
	    sudo_warnx(U_("unable to base64 encode value \"%s\""), value);
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

    debug_return_bool(!ferror(fp));
}

static bool
printf_attribute_ldif(FILE *fp, const char *name, const char * restrict fmt, ...)
{
    char *attr_val;
    va_list ap;
    bool ret;
    int len;
    debug_decl(printf_attribute_ldif, SUDOERS_DEBUG_UTIL);

    va_start(ap, fmt);
    len = vasprintf(&attr_val, fmt, ap);
    va_end(ap);
    if (len == -1) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_bool(false);
    }

    ret = print_attribute_ldif(fp, name, attr_val);
    free(attr_val);

    debug_return_bool(ret);
}

/*
 * Print sudoOptions from a defaults_list.
 */
static bool
print_options_ldif(FILE *fp, const struct defaults_list *options)
{
    struct defaults *opt;
    bool ok;
    debug_decl(print_options_ldif, SUDOERS_DEBUG_UTIL);

    TAILQ_FOREACH(opt, options, entries) {
	if (opt->type != DEFAULTS)
	    continue;		/* don't support bound defaults */

	if (opt->val != NULL) {
	    /* There is no need to double quote values here. */
	    ok = printf_attribute_ldif(fp, "sudoOption", "%s%s%s", opt->var,
		opt->op == '+' ? "+=" : opt->op == '-' ? "-=" : "=", opt->val);
	} else {
	    /* Boolean flag. */
	    ok = printf_attribute_ldif(fp, "sudoOption", "%s%s",
		opt->op == false ? "!" : "", opt->var);
	}
	if (!ok)
	    debug_return_bool(false);
    }

    debug_return_bool(!ferror(fp));
}

/*
 * Print global Defaults in a single sudoRole object.
 */
static bool
print_global_defaults_ldif(FILE *fp,
    const struct sudoers_parse_tree *parse_tree, struct cvtsudoers_config *conf)
{
    unsigned int count = 0;
    struct sudo_lbuf lbuf;
    struct defaults *opt;
    bool ret = false;
    debug_decl(print_global_defaults_ldif, SUDOERS_DEBUG_UTIL);

    sudo_lbuf_init(&lbuf, NULL, 0, NULL, 80);

    TAILQ_FOREACH(opt, &parse_tree->defaults, entries) {
	/* Skip bound Defaults (unsupported). */
	if (opt->type == DEFAULTS) {
	    count++;
	} else {
	    lbuf.len = 0;
	    if (!sudo_lbuf_append(&lbuf, "# "))
		goto done;
	    if (!sudoers_format_default_line(&lbuf, parse_tree, opt, NULL, true))
		goto done;
	    fprintf(fp, "# Unable to translate %s:%d:%d:\n%s\n",
		opt->file, opt->line, opt->column, lbuf.buf);
	}
    }
    sudo_lbuf_destroy(&lbuf);

    if (count == 0)
	debug_return_bool(true);

    if (!printf_attribute_ldif(fp, "dn", "cn=defaults,%s", conf->sudoers_base) ||
	    !print_attribute_ldif(fp, "objectClass", "top") ||
	    !print_attribute_ldif(fp, "objectClass", "sudoRole") ||
	    !print_attribute_ldif(fp, "cn", "defaults") ||
	    !print_attribute_ldif(fp, "description", "Default sudoOption's go here")) {
	goto done;
    }
    if (!print_options_ldif(fp, &parse_tree->defaults))
	goto done;
    putc('\n', fp);
    if (!ferror(fp))
	ret = true;

done:
    debug_return_bool(ret);
}

/*
 * Format a sudo_command as a string.
 * Returns the formatted, dynamically allocated string or dies on error.
 */
static char *
format_cmnd(struct sudo_command *c, bool negated)
{
    struct command_digest *digest;
    char *buf, *cp, *cmnd;
    size_t bufsiz;
    int len;
    debug_decl(format_cmnd, SUDOERS_DEBUG_UTIL);

    cmnd = c->cmnd ? c->cmnd : (char *)"ALL";
    bufsiz = negated + strlen(cmnd) + 1;
    if (c->args != NULL)
	bufsiz += 1 + strlen(c->args);
    TAILQ_FOREACH(digest, &c->digests, entries) {
	bufsiz += strlen(digest_type_to_name(digest->digest_type)) + 1 +
	    strlen(digest->digest_str) + 1;
	if (TAILQ_NEXT(digest, entries) != NULL)
	    bufsiz += 2;
    }

    if ((buf = malloc(bufsiz)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_ptr(NULL);
    }

    cp = buf;
    TAILQ_FOREACH(digest, &c->digests, entries) {
	len = snprintf(cp, bufsiz - (size_t)(cp - buf), "%s:%s%s ", 
	    digest_type_to_name(digest->digest_type), digest->digest_str,
	    TAILQ_NEXT(digest, entries) ? "," : "");
	if (len < 0 || len >= (int)bufsiz - (cp - buf))
	    sudo_fatalx(U_("internal error, %s overflow"), __func__);
	cp += len;
    }

    len = snprintf(cp, bufsiz - (size_t)(cp - buf), "%s%s%s%s",
	negated ? "!" : "", cmnd, c->args ? " " : "", c->args ? c->args : "");
    if (len < 0 || len >= (int)bufsiz - (cp - buf))
	sudo_fatalx(U_("internal error, %s overflow"), __func__);

    debug_return_str(buf);
}

/*
 * Print struct member in LDIF format as the specified attribute.
 * See print_member_int() in parse.c.
 */
static bool
print_member_ldif(FILE *fp, const struct sudoers_parse_tree *parse_tree,
    char *name, int type, bool negated, short alias_type,
    const char *attr_name)
{
    struct alias *a;
    struct member *m;
    char *attr_val;
    debug_decl(print_member_ldif, SUDOERS_DEBUG_UTIL);

    switch (type) {
    case MYSELF:
	/* Only valid for sudoRunasUser */
	if (!print_attribute_ldif(fp, attr_name, ""))
	    debug_return_bool(false);
	break;
    case ALL:
	if (name == NULL) {
	    if (!print_attribute_ldif(fp, attr_name, negated ? "!ALL" : "ALL"))
		debug_return_bool(false);
	    break;
	}
	FALLTHROUGH;
    case COMMAND:
	attr_val = format_cmnd((struct sudo_command *)name, negated);
	if (attr_val == NULL) {
	    debug_return_bool(false);
	}
	if (!print_attribute_ldif(fp, attr_name, attr_val)) {
	    free(attr_val);
	    debug_return_bool(false);
	}
	free(attr_val);
	break;
    case ALIAS:
	if ((a = alias_get(parse_tree, name, alias_type)) != NULL) {
	    TAILQ_FOREACH(m, &a->members, entries) {
		if (!print_member_ldif(fp, parse_tree, m->name, m->type,
			negated ? !m->negated : m->negated, alias_type,
			attr_name)) {
		    debug_return_bool(false);
		}
	    }
	    alias_put(a);
	    break;
	}
	FALLTHROUGH;
    default:
	if (!printf_attribute_ldif(fp, attr_name, "%s%s", negated ? "!" : "",
		name)) {
	    debug_return_bool(false);
	}
	break;
    }

    debug_return_bool(true);
}

/*
 * Print a Cmnd_Spec in LDIF format.
 * A pointer to the next Cmnd_Spec is passed in to make it possible to
 * merge adjacent entries that are identical in all but the command.
 */
static bool
print_cmndspec_ldif(FILE *fp, const struct sudoers_parse_tree *parse_tree,
    struct cmndspec *cs, struct cmndspec **nextp, struct defaults_list *options)
{
    char timebuf[sizeof("20120727121554Z")];
    struct cmndspec *next = *nextp;
    struct member *m;
    struct tm gmt;
    bool last_one;
    size_t len;
    debug_decl(print_cmndspec_ldif, SUDOERS_DEBUG_UTIL);

    /* Print runasuserlist as sudoRunAsUser attributes */
    if (cs->runasuserlist != NULL) {
	TAILQ_FOREACH(m, cs->runasuserlist, entries) {
	    if (!print_member_ldif(fp, parse_tree, m->name, m->type, m->negated,
		    RUNASALIAS, "sudoRunAsUser")) {
		debug_return_bool(false);
	    }
	}
    }

    /* Print runasgrouplist as sudoRunAsGroup attributes */
    if (cs->runasgrouplist != NULL) {
	TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
	    if (!print_member_ldif(fp, parse_tree, m->name, m->type, m->negated,
		    RUNASALIAS, "sudoRunAsGroup")) {
		debug_return_bool(false);
	    }
	}
    }

    /* Print sudoNotBefore and sudoNotAfter attributes */
    if (cs->notbefore != UNSPEC) {
	if (gmtime_r(&cs->notbefore, &gmt) == NULL) {
	    sudo_warn("%s", U_("unable to get GMT time"));
	} else {
	    timebuf[sizeof(timebuf) - 1] = '\0';
	    len = strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", &gmt);
	    if (len == 0 || timebuf[sizeof(timebuf) - 1] != '\0') {
		sudo_warnx("%s", U_("unable to format timestamp"));
	    } else {
		if (!print_attribute_ldif(fp, "sudoNotBefore", timebuf))
		    debug_return_bool(false);
	    }
	}
    }
    if (cs->notafter != UNSPEC) {
	if (gmtime_r(&cs->notafter, &gmt) == NULL) {
	    sudo_warn("%s", U_("unable to get GMT time"));
	} else {
	    timebuf[sizeof(timebuf) - 1] = '\0';
	    len = strftime(timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", &gmt);
	    if (len == 0 || timebuf[sizeof(timebuf) - 1] != '\0') {
		sudo_warnx("%s", U_("unable to format timestamp"));
	    } else {
		if (!print_attribute_ldif(fp, "sudoNotAfter", timebuf))
		    debug_return_bool(false);
	    }
	}
    }

    /* Print timeout as a sudoOption. */
    if (cs->timeout > 0) {
	if (!printf_attribute_ldif(fp, "sudoOption", "command_timeout=%d",
		cs->timeout)) {
	    debug_return_bool(false);
	}
    }

    /* Print tags as sudoOption attributes */
    if (TAGS_SET(cs->tags)) {
	struct cmndtag tag = cs->tags;

	if (tag.nopasswd != UNSPEC) {
	    if (!print_attribute_ldif(fp, "sudoOption",
		    tag.nopasswd ? "!authenticate" : "authenticate")) {
		debug_return_bool(false);
	    }
	}
	if (tag.noexec != UNSPEC) {
	    if (!print_attribute_ldif(fp, "sudoOption",
		    tag.noexec ? "noexec" : "!noexec")) {
		debug_return_bool(false);
	    }
	}
	if (tag.intercept != UNSPEC) {
	    if (!print_attribute_ldif(fp, "sudoOption",
		    tag.intercept ? "intercept" : "!intercept")) {
		debug_return_bool(false);
	    }
	}
	if (tag.send_mail != UNSPEC) {
	    if (tag.send_mail) {
		if (!print_attribute_ldif(fp, "sudoOption", "mail_all_cmnds")) {
		    debug_return_bool(false);
		}
	    } else {
		if (!print_attribute_ldif(fp, "sudoOption", "!mail_all_cmnds") ||
			!print_attribute_ldif(fp, "sudoOption", "!mail_always") ||
			!print_attribute_ldif(fp, "sudoOption", "!mail_no_perms")) {
		    debug_return_bool(false);
		}
	    }
	}
	if (tag.setenv != UNSPEC && tag.setenv != IMPLIED) {
	    if (!print_attribute_ldif(fp, "sudoOption",
		    tag.setenv ? "setenv" : "!setenv")) {
		debug_return_bool(false);
	    }
	}
	if (tag.follow != UNSPEC) {
	    if (!print_attribute_ldif(fp, "sudoOption",
		    tag.follow ? "sudoedit_follow" : "!sudoedit_follow")) {
		debug_return_bool(false);
	    }
	}
	if (tag.log_input != UNSPEC) {
	    if (!print_attribute_ldif(fp, "sudoOption",
		    tag.log_input ? "log_input" : "!log_input")) {
		debug_return_bool(false);
	    }
	}
	if (tag.log_output != UNSPEC) {
	    if (!print_attribute_ldif(fp, "sudoOption",
		    tag.log_output ? "log_output" : "!log_output")) {
		debug_return_bool(false);
	    }
	}
    }
    if (!print_options_ldif(fp, options))
	debug_return_bool(false);

    /* Print runchroot and runcwd. */
    if (cs->runchroot != NULL) {
	if (!printf_attribute_ldif(fp, "sudoOption", "runchroot=%s",
		cs->runchroot)) {
	    debug_return_bool(false);
	}
    }
    if (cs->runcwd != NULL) {
	if (!printf_attribute_ldif(fp, "sudoOption", "runcwd=%s", cs->runcwd)) {
	    debug_return_bool(false);
	}
    }

    /* Print SELinux role/type */
    if (cs->role != NULL && cs->type != NULL) {
	if (!printf_attribute_ldif(fp, "sudoOption", "role=%s", cs->role) ||
		!printf_attribute_ldif(fp, "sudoOption", "type=%s", cs->type)) {
	    debug_return_bool(false);
	}
    }

    /* Print AppArmor profile */
    if (cs->apparmor_profile != NULL) {
	if (!printf_attribute_ldif(fp, "sudoOption", "apparmor_profile=%s",
		cs->apparmor_profile)) {
	    debug_return_bool(false);
	}
    }

    /* Print Solaris privs/limitprivs */
    if (cs->privs != NULL || cs->limitprivs != NULL) {
	if (cs->privs != NULL) {
	    if (!printf_attribute_ldif(fp, "sudoOption", "privs=%s",
		    cs->privs)) {
		debug_return_bool(false);
	    }
	}
	if (cs->limitprivs != NULL) {
	    if (!printf_attribute_ldif(fp, "sudoOption", "limitprivs=%s",
		    cs->limitprivs)) {
		debug_return_bool(false);
	    }
	}
    }

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
	    || cs->privs != next->privs || cs->limitprivs != next->limitprivs
	    || cs->role != next->role || cs->type != next->type
	    || cs->runchroot != next->runchroot || cs->runcwd != next->runcwd;

	if (!print_member_ldif(fp, parse_tree, cs->cmnd->name, cs->cmnd->type,
		cs->cmnd->negated, CMNDALIAS, "sudoCommand")) {
	    debug_return_bool(false);
	}
	if (last_one)
	    break;
	cs = next;
	next = TAILQ_NEXT(cs, entries);
    }

    *nextp = next;

    debug_return_bool(true);
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
    debug_decl(user_to_cn, SUDOERS_DEBUG_UTIL);

    /* Allocate as much as we could possibly need. */
    size = (2 * strlen(user)) + 64 + 1;
    if ((cn = malloc(size)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto bad;
    }

    /*
     * Increment the number of times we have seen this user.
     */
    key.name = user;
    node = rbfind(seen_users, &key);
    if (node != NULL) {
	su = node->data;
    } else {
	if ((su = malloc(sizeof(*su))) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto bad;
	}
	su->count = 0;
	if ((su->name = strdup(user)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    goto bad;
	}
	if (rbinsert(seen_users, su, NULL) != 0) {
	    sudo_warnx(U_("internal error, unable insert user %s"), user);
	    goto bad;
	}
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
print_userspec_ldif(FILE *fp, const struct sudoers_parse_tree *parse_tree,
    struct userspec *us, struct cvtsudoers_config *conf)
{
    struct privilege *priv;
    struct member *m;
    struct cmndspec *cs, *next;
    debug_decl(print_userspec_ldif, SUDOERS_DEBUG_UTIL);

    /*
     * Each userspec struct may contain multiple privileges for
     * the user.  We export each privilege as a separate sudoRole
     * object for simplicity's sake.
     */
    TAILQ_FOREACH(priv, &us->privileges, entries) {
	TAILQ_FOREACH_SAFE(cs, &priv->cmndlist, entries, next) {
	    const char *base = conf->sudoers_base;
	    char *cn;

	    /*
	     * Increment the number of times we have seen this user.
	     * If more than one user is listed, just use the first one.
	     */
	    m = TAILQ_FIRST(&us->users);
	    cn = user_to_cn(m->type == ALL ? "ALL" : m->name);
	    if (cn == NULL)
		debug_return_bool(false);

	    if (!printf_attribute_ldif(fp, "dn", "cn=%s,%s", cn, base) ||
		    !print_attribute_ldif(fp, "objectClass", "top") ||
		    !print_attribute_ldif(fp, "objectClass", "sudoRole") ||
		    !print_attribute_ldif(fp, "cn", cn)) {
		free(cn);
		debug_return_bool(false);
	    }
	    free(cn);

	    TAILQ_FOREACH(m, &us->users, entries) {
		if (!print_member_ldif(fp, parse_tree, m->name, m->type,
			m->negated, USERALIAS, "sudoUser")) {
		    debug_return_bool(false);
		}
	    }

	    TAILQ_FOREACH(m, &priv->hostlist, entries) {
		if (!print_member_ldif(fp, parse_tree, m->name, m->type,
			m->negated, HOSTALIAS, "sudoHost")) {
		    debug_return_bool(false);
		}
	    }

	    if (!print_cmndspec_ldif(fp, parse_tree, cs, &next, &priv->defaults))
		debug_return_bool(false);

	    if (conf->sudo_order != 0) {
		char numbuf[STRLEN_MAX_UNSIGNED(conf->sudo_order) + 1];
		if (conf->order_max != 0 && conf->sudo_order > conf->order_max) {
		    sudo_warnx(U_("too many sudoers entries, maximum %u"),
			conf->order_padding);
		    debug_return_bool(false);
		}
		(void)snprintf(numbuf, sizeof(numbuf), "%u", conf->sudo_order);
		if (!print_attribute_ldif(fp, "sudoOrder", numbuf))
		    debug_return_bool(false);
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
print_userspecs_ldif(FILE *fp, const struct sudoers_parse_tree *parse_tree,
    struct cvtsudoers_config *conf)
{
    struct userspec *us;
    debug_decl(print_userspecs_ldif, SUDOERS_DEBUG_UTIL);
 
    TAILQ_FOREACH(us, &parse_tree->userspecs, entries) {
	if (!print_userspec_ldif(fp, parse_tree, us, conf))
	    debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Export the parsed sudoers file in LDIF format.
 */
bool
convert_sudoers_ldif(const struct sudoers_parse_tree *parse_tree,
    const char *output_file, struct cvtsudoers_config *conf)
{
    bool ret = false;
    FILE *output_fp = stdout;
    debug_decl(convert_sudoers_ldif, SUDOERS_DEBUG_UTIL);

    if (conf->sudoers_base == NULL) {
	sudo_warnx("%s", U_("the SUDOERS_BASE environment variable is not set and the -b option was not specified."));
	debug_return_bool(false);
    }

    if (output_file != NULL && strcmp(output_file, "-") != 0) {
	if ((output_fp = fopen(output_file, "w")) == NULL) {
	    sudo_warn(U_("unable to open %s"), output_file);
	    debug_return_bool(false);
	}
    }

    /* Create a dictionary of already-seen users. */
    seen_users = rbcreate(seen_user_compare);
    if (seen_users == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	goto cleanup;
    }

    /* Dump global Defaults in LDIF format. */
    if (!ISSET(conf->suppress, SUPPRESS_DEFAULTS)) {
	if (!print_global_defaults_ldif(output_fp, parse_tree, conf))
	    goto cleanup;
    }

    /* Dump User_Specs in LDIF format, expanding Aliases. */
    if (!ISSET(conf->suppress, SUPPRESS_PRIVS)) {
	if (!print_userspecs_ldif(output_fp, parse_tree, conf))
	    goto cleanup;
    }

    ret = true;

cleanup:
    if (seen_users != NULL)
	rbdestroy(seen_users, seen_user_free);

    (void)fflush(output_fp);
    if (ferror(output_fp)) {
	sudo_warn("%s", output_file);
	ret = false;
    }
    if (output_fp != stdout)
	fclose(output_fp);

    debug_return_bool(ret);
}
