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
#include <ctype.h>

#include "sudoers.h"
#include "parse.h"
#include "redblack.h"
#include <gram.h>

struct seen_user {
    const char *name;
    unsigned long count;
};

static int sudo_order;
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

/*
 * Print global Defaults in a single sudoRole object.
 */
static bool
print_global_defaults_ldif(FILE *fp, const char *base)
{
    struct defaults *def;
    debug_decl(print_global_defaults_ldif, SUDOERS_DEBUG_UTIL)

    if (TAILQ_EMPTY(&defaults))
	debug_return_bool(true);

    fprintf(fp, "dn: cn=defaults,%s\n", base);
    fputs("objectClass: top\n", fp);
    fputs("objectClass: sudoRole\n", fp);
    fputs("cn: defaults\n", fp);
    fputs("description: Default sudoOption's go here\n", fp);

    TAILQ_FOREACH(def, &defaults, entries) {
	if (def->type != DEFAULTS)
	    continue;		/* only want global defaults */

	if (def->val != NULL) {
	    /* There is no need to double quote values here. */
	    fprintf(fp, "sudoOption: %s%s%s\n", def->var,
		def->op == '+' ? "+=" : def->op == '-' ? "-=" : "=", def->val);
	} else {
	    /* Boolean flag. */
	    fprintf(fp, "sudoOption: %s%s\n", def->op == false ? "!" : "",
		def->var);
	}
    }
    putc('\n', fp);

    debug_return_bool(!ferror(fp));
}

static void
warn_bound_defaults_ldif(FILE *fp)
{
    struct defaults *def;
    debug_decl(warn_bound_defaults_ldif, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH(def, &defaults, entries) {
	if (def->type == DEFAULTS)
	    continue;		/* only want bound defaults */

	/* XXX - print Defaults line */
	sudo_warnx(U_("%s:%d unable to translate Defaults line"),
	    def->file, def->lineno);
    }

    debug_return;
}

/*
 * Print struct member in LDIF format, with specified prefix.
 * See print_member_int() in parse.c.
 */
static void
print_member_ldif(FILE *fp, char *name, int type, bool negated,
    int alias_type, const char *prefix)
{
    struct alias *a;
    struct member *m;
    struct sudo_command *c;
    debug_decl(print_member_ldif, SUDOERS_DEBUG_UTIL)

    switch (type) {
    case ALL:
	fprintf(fp, "%s: %sALL\n", prefix, negated ? "!" : "");
	break;
    case MYSELF:
	/* Only valid for sudoRunasUser */
	fprintf(fp, "%s:\n", prefix);
	break;
    case COMMAND:
	c = (struct sudo_command *)name;
	fprintf(fp, "%s: ", prefix);
	if (c->digest != NULL)
	    fprintf(fp, "%s:", digest_type_to_name(c->digest->digest_type));
	fprintf(fp, "%s%s", negated ? "!" : "", c->cmnd);
	if (c->args != NULL)
	    fprintf(fp, " %s", c->args);
	putc('\n', fp);
	break;
    case ALIAS:
	if ((a = alias_get(name, alias_type)) != NULL) {
	    TAILQ_FOREACH(m, &a->members, entries) {
		print_member_ldif(fp, m->name, m->type,
		    negated ? !m->negated : m->negated, alias_type, prefix);
	    }
	    alias_put(a);
	    break;
	}
	/* FALLTHROUGH */
    default:
	fprintf(fp, "%s: %s%s\n", prefix, negated ? "!" : "", name);
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
print_cmndspec_ldif(FILE *fp, struct cmndspec *cs, struct cmndspec **nextp)
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
		fprintf(fp, "sudoNotBefore: %s\n", timebuf);
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
		fprintf(fp, "sudoNotAfter: %s\n", timebuf);
	    }
	}
    }

    /* Print tags as sudoOption attributes */
    if (cs->timeout > 0 || TAGS_SET(cs->tags)) {
	struct cmndtag tag = cs->tags;

	if (cs->timeout > 0) {
	    fprintf(fp, "sudoOption: command_timeout=%d\n", cs->timeout);
	}
	if (tag.nopasswd != UNSPEC) {
	    fprintf(fp, "sudoOption: %sauthenticate\n", tag.nopasswd ? "!" : "");
	}
	if (tag.noexec != UNSPEC) {
	    fprintf(fp, "sudoOption: %snoexec\n", tag.noexec ? "" : "!");
	}
	if (tag.send_mail != UNSPEC) {
	    if (tag.send_mail) {
		fprintf(fp, "sudoOption: mail_all_cmnds\n");
	    } else {
		fprintf(fp, "sudoOption: !mail_all_cmnds\n");
		fprintf(fp, "sudoOption: !mail_always\n");
		fprintf(fp, "sudoOption: !mail_no_perms\n");
	    }
	}
	if (tag.setenv != UNSPEC && tag.setenv != IMPLIED) {
	    fprintf(fp, "sudoOption: %ssetenv\n", tag.setenv ? "" : "!");
	}
	if (tag.follow != UNSPEC) {
	    fprintf(fp, "sudoOption: %ssudoedit_follow\n", tag.follow ? "" : "!");
	}
	if (tag.log_input != UNSPEC) {
	    fprintf(fp, "sudoOption: %slog_input\n", tag.log_input ? "" : "!");
	}
	if (tag.log_output != UNSPEC) {
	    fprintf(fp, "sudoOption: %slog_output\n", tag.log_output ? "" : "!");
	}
    }

#ifdef HAVE_SELINUX
    /* Print SELinux role/type */
    if (cs->role != NULL && cs->type != NULL) {
	fprintf(fp, "sudoOption: role=%s\n", cs->role);
	fprintf(fp, "sudoOption: type=%s\n", cs->type);
    }
#endif /* HAVE_SELINUX */

#ifdef HAVE_PRIV_SET
    /* Print Solaris privs/limitprivs */
    if (cs->privs != NULL || cs->limitprivs != NULL) {
	if (cs->privs != NULL)
	    fprintf(fp, "sudoOption: privs=%s\n", cs->privs);
	if (cs->limitprivs != NULL)
	    fprintf(fp, "sudoOption: limitprivs=%s\n", cs->limitprivs);
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
	case '\\':
	case '#':
	case '+':
	case '<':
	case '>':
	case ';':
	    *dst++ = '\\';
	    *dst++ = *src;
	    break;
	default:
	    *dst++ = *src;
	    break;
	}
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
print_userspec_ldif(FILE *fp, struct userspec *us, const char *base)
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
	    char *cn;

	    /*
	     * Increment the number of times we have seen this user.
	     * If more than one user is listed, just use the first one.
	     */
	    m = TAILQ_FIRST(&us->users);
	    cn = user_to_cn(m->type == ALL ? "ALL" : m->name);
	    if (cn == NULL) {
		sudo_fatalx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
	    }

	    fprintf(fp, "dn: cn=%s,%s\n", cn, base);
	    fprintf(fp, "objectClass: top\n");
	    fprintf(fp, "objectClass: sudoRole\n");
	    fprintf(fp, "cn: %s\n", cn);
	    free(cn);

	    TAILQ_FOREACH(m, &us->users, entries) {
		print_member_ldif(fp, m->name, m->type, m->negated,
		    USERALIAS, "sudoUser");
	    }

	    TAILQ_FOREACH(m, &priv->hostlist, entries) {
		print_member_ldif(fp, m->name, m->type, m->negated,
		    HOSTALIAS, "sudoHost");
	    }

	    print_cmndspec_ldif(fp, cs, &next);

	    fprintf(fp, "sudoOrder: %d\n\n", ++sudo_order);
	}
    }

    debug_return_bool(!ferror(fp));
}

/*
 * Print User_Specs.
 */
static bool
print_userspecs_ldif(FILE *fp, const char *base)
{
    struct userspec *us;
    debug_decl(print_userspecs_ldif, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH(us, &userspecs, entries) {
	if (!print_userspec_ldif(fp, us, base))
	    debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Export the parsed sudoers file in LDIF format.
 */
bool
convert_sudoers_ldif(const char *output_file, const char *base)
{
    bool ret = true;
    FILE *output_fp = stdout;
    debug_decl(convert_sudoers_ldif, SUDOERS_DEBUG_UTIL)

    if (base == NULL) {
	base = getenv("SUDOERS_BASE");
	if (base == NULL)
	    sudo_fatalx(U_("the SUDOERS_BASE environment variable is not set and the -b option was not specified."));
    }

    if (strcmp(output_file, "-") != 0) {
	if ((output_fp = fopen(output_file, "w")) == NULL)
	    sudo_fatal(U_("unable to open %s"), output_file);
    }

    /* Create a dictionary of already-seen users. */
    seen_users = rbcreate(seen_user_compare);

    /* Dump global Defaults in LDIF format. */
    print_global_defaults_ldif(output_fp, base);

    /* Dump User_Specs in LDIF format, expanding Aliases. */
    print_userspecs_ldif(output_fp, base);

    /* Warn about non-translatable Defaults entries. */
    warn_bound_defaults_ldif(output_fp);

    /* Clean up. */
    rbdestroy(seen_users, seen_user_free);

    (void)fflush(output_fp);
    if (ferror(output_fp))
	ret = false;
    if (output_fp != stdout)
	fclose(output_fp);

    debug_return_bool(ret);
}
