/*
 * Copyright (c) 2004-2005, 2007-2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <time.h>

#include "sudoers.h"
#include "parse.h"
#include "sudo_lbuf.h"
#include <gram.h>

/*
 * Write the contents of a struct member to the lbuf.
 * If alias_type is not UNSPEC, expand aliases using that type with
 * the specified separator (which must not be NULL in the UNSPEC case).
 */
static bool
sudoers_format_member_int(struct sudo_lbuf *lbuf, char *name, int type,
    bool negated, const char *separator, int alias_type)
{
    struct alias *a;
    struct member *m;
    struct sudo_command *c;
    debug_decl(sudoers_format_member_int, SUDOERS_DEBUG_UTIL)

    switch (type) {
	case ALL:
	    sudo_lbuf_append(lbuf, "%sALL", negated ? "!" : "");
	    break;
	case MYSELF:
	    sudo_lbuf_append(lbuf, "%s%s", negated ? "!" : "", user_name);
	    break;
	case COMMAND:
	    c = (struct sudo_command *) name;
	    if (c->digest != NULL) {
		sudo_lbuf_append(lbuf, "%s:%s ",
		    digest_type_to_name(c->digest->digest_type),
		    c->digest->digest_str);
	    }
	    if (negated)
		sudo_lbuf_append(lbuf, "!");
	    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED" \t", "%s", c->cmnd);
	    if (c->args) {
		sudo_lbuf_append(lbuf, " ");
		sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", c->args);
	    }
	    break;
	case USERGROUP:
	    /* Special case for %#gid, %:non-unix-group, %:#non-unix-gid */
	    if (strpbrk(name, " \t") == NULL) {
		if (*++name == ':') {
		    name++;
		    sudo_lbuf_append(lbuf, "%s", "%:");
		} else {
		    sudo_lbuf_append(lbuf, "%s", "%");
		}
	    }
	    goto print_word;
	case ALIAS:
	    if (alias_type != UNSPEC) {
		if ((a = alias_get(name, alias_type)) != NULL) {
		    TAILQ_FOREACH(m, &a->members, entries) {
			if (m != TAILQ_FIRST(&a->members))
			    sudo_lbuf_append(lbuf, "%s", separator);
			sudoers_format_member_int(lbuf, m->name, m->type,
			    negated ? !m->negated : m->negated, separator,
			    alias_type);
		    }
		    alias_put(a);
		    break;
		}
	    }
	    /* FALLTHROUGH */
	default:
	print_word:
	    /* Do not quote UID/GID, all others get quoted. */
	    if (name[0] == '#' &&
		name[strspn(name + 1, "0123456789") + 1] == '\0') {
		sudo_lbuf_append(lbuf, "%s%s", negated ? "!" : "", name);
	    } else {
		if (strpbrk(name, " \t") != NULL) {
		    sudo_lbuf_append(lbuf, "%s\"", negated ? "!" : "");
		    sudo_lbuf_append_quoted(lbuf, "\"", "%s", name);
		    sudo_lbuf_append(lbuf, "\"");
		} else {
		    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s%s",
			negated ? "!" : "", name);
		}
	    }
	    break;
    }
    debug_return_bool(!sudo_lbuf_error(lbuf));
}

bool
sudoers_format_member(struct sudo_lbuf *lbuf, struct member *m,
    const char *separator, int alias_type)
{
    return sudoers_format_member_int(lbuf, m->name, m->type, m->negated,
	separator, alias_type);
}

#define	FIELD_CHANGED(ocs, ncs, fld) \
	((ocs) == NULL || (ncs)->fld != (ocs)->fld)

#define	TAG_CHANGED(ocs, ncs, tt) \
	(TAG_SET((ncs)->tags.tt) && FIELD_CHANGED(ocs, ncs, tags.tt))

/*
 * Write a cmndspec to lbuf in sudoers format.
 */
bool
sudoers_format_cmndspec(struct sudo_lbuf *lbuf, struct cmndspec *cs,
    struct cmndspec *prev_cs, bool expand_aliases)
{
    debug_decl(sudoers_format_cmndspec, SUDOERS_DEBUG_UTIL)

#ifdef HAVE_PRIV_SET
    if (cs->privs != NULL && FIELD_CHANGED(prev_cs, cs, privs))
	sudo_lbuf_append(lbuf, "PRIVS=\"%s\" ", cs->privs);
    if (cs->limitprivs != NULL && FIELD_CHANGED(prev_cs, cs, limitprivs))
	sudo_lbuf_append(lbuf, "LIMITPRIVS=\"%s\" ", cs->limitprivs);
#endif /* HAVE_PRIV_SET */
#ifdef HAVE_SELINUX
    if (cs->role != NULL && FIELD_CHANGED(prev_cs, cs, role))
	sudo_lbuf_append(lbuf, "ROLE=%s ", cs->role);
    if (cs->type != NULL && FIELD_CHANGED(prev_cs, cs, type))
	sudo_lbuf_append(lbuf, "TYPE=%s ", cs->type);
#endif /* HAVE_SELINUX */
    if (cs->timeout > 0 && FIELD_CHANGED(prev_cs, cs, timeout)) {
	char numbuf[(((sizeof(int) * 8) + 2) / 3) + 2];
	snprintf(numbuf, sizeof(numbuf), "%d", cs->timeout);
	sudo_lbuf_append(lbuf, "TIMEOUT=%s ", numbuf);
    }
    if (cs->notbefore != UNSPEC && FIELD_CHANGED(prev_cs, cs, notbefore)) {
	char buf[sizeof("CCYYMMDDHHMMSSZ")];
	struct tm *tm = gmtime(&cs->notbefore);
	snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02dZ",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec);
	sudo_lbuf_append(lbuf, "NOTBEFORE=%s ", buf);
    }
    if (cs->notafter != UNSPEC && FIELD_CHANGED(prev_cs, cs, notafter)) {
	char buf[sizeof("CCYYMMDDHHMMSSZ")];
	struct tm *tm = gmtime(&cs->notafter);
	snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02dZ",
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec);
	sudo_lbuf_append(lbuf, "NOTAFTER=%s ", buf);
    }
    if (TAG_CHANGED(prev_cs, cs, setenv))
	sudo_lbuf_append(lbuf, cs->tags.setenv ? "SETENV: " : "NOSETENV: ");
    if (TAG_CHANGED(prev_cs, cs, noexec))
	sudo_lbuf_append(lbuf, cs->tags.noexec ? "NOEXEC: " : "EXEC: ");
    if (TAG_CHANGED(prev_cs, cs, nopasswd))
	sudo_lbuf_append(lbuf, cs->tags.nopasswd ? "NOPASSWD: " : "PASSWD: ");
    if (TAG_CHANGED(prev_cs, cs, log_input))
	sudo_lbuf_append(lbuf, cs->tags.log_input ? "LOG_INPUT: " : "NOLOG_INPUT: ");
    if (TAG_CHANGED(prev_cs, cs, log_output))
	sudo_lbuf_append(lbuf, cs->tags.log_output ? "LOG_OUTPUT: " : "NOLOG_OUTPUT: ");
    if (TAG_CHANGED(prev_cs, cs, send_mail))
	sudo_lbuf_append(lbuf, cs->tags.send_mail ? "MAIL: " : "NOMAIL: ");
    if (TAG_CHANGED(prev_cs, cs, follow))
	sudo_lbuf_append(lbuf, cs->tags.follow ? "FOLLOW: " : "NOFOLLOW: ");
    sudoers_format_member(lbuf, cs->cmnd, ", ",
	expand_aliases ? CMNDALIAS : UNSPEC);
    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Write a privilege to lbuf in sudoers format.
 */
bool
sudoers_format_privilege(struct sudo_lbuf *lbuf, struct privilege *priv,
    bool expand_aliases)
{
    struct cmndspec *cs, *prev_cs;
    struct member *m;
    debug_decl(sudoers_format_userspec, SUDOERS_DEBUG_UTIL)

    /* Print hosts list. */
    TAILQ_FOREACH(m, &priv->hostlist, entries) {
	if (m != TAILQ_FIRST(&priv->hostlist))
	    sudo_lbuf_append(lbuf, ", ");
	sudoers_format_member(lbuf, m, ", ",
	    expand_aliases ? HOSTALIAS : UNSPEC);
    }

    /* Print commands. */
    sudo_lbuf_append(lbuf, " = ");
    prev_cs = NULL;
    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
	if (prev_cs == NULL || RUNAS_CHANGED(cs, prev_cs)) {
	    if (cs != TAILQ_FIRST(&priv->cmndlist))
		sudo_lbuf_append(lbuf, ", ");
	    if (cs->runasuserlist != NULL || cs->runasgrouplist != NULL)
		sudo_lbuf_append(lbuf, "(");
	    if (cs->runasuserlist != NULL) {
		TAILQ_FOREACH(m, cs->runasuserlist, entries) {
		    if (m != TAILQ_FIRST(cs->runasuserlist))
			sudo_lbuf_append(lbuf, ", ");
		    sudoers_format_member(lbuf, m, ", ",
			expand_aliases ? RUNASALIAS : UNSPEC);
		}
	    }
	    if (cs->runasgrouplist != NULL) {
		sudo_lbuf_append(lbuf, " : ");
		TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
		    if (m != TAILQ_FIRST(cs->runasgrouplist))
			sudo_lbuf_append(lbuf, ", ");
		    sudoers_format_member(lbuf, m, ", ",
			expand_aliases ? RUNASALIAS : UNSPEC);
		}
	    }
	    if (cs->runasuserlist != NULL || cs->runasgrouplist != NULL)
		sudo_lbuf_append(lbuf, ") ");
	} else if (cs != TAILQ_FIRST(&priv->cmndlist)) {
	    sudo_lbuf_append(lbuf, ", ");
	}
	sudoers_format_cmndspec(lbuf, cs, prev_cs, expand_aliases);
	prev_cs = cs;
    }

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Write a userspec to lbuf in sudoers format.
 */
bool
sudoers_format_userspec(struct sudo_lbuf *lbuf, struct userspec *us,
    bool expand_aliases)
{
    struct privilege *priv;
    struct member *m;
    debug_decl(sudoers_format_userspec, SUDOERS_DEBUG_UTIL)

    /* Print users list. */
    TAILQ_FOREACH(m, &us->users, entries) {
	if (m != TAILQ_FIRST(&us->users))
	    sudo_lbuf_append(lbuf, ", ");
	sudoers_format_member(lbuf, m, ", ",
	    expand_aliases ? USERALIAS : UNSPEC);
    }

    TAILQ_FOREACH(priv, &us->privileges, entries) {
	if (priv != TAILQ_FIRST(&us->privileges))
	    sudo_lbuf_append(lbuf, " : ");
	else
	    sudo_lbuf_append(lbuf, " ");
	if (!sudoers_format_privilege(lbuf, priv, expand_aliases))
	    break;
    }
    sudo_lbuf_append(lbuf, "\n");

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Write a userspec_list to lbuf in sudoers format.
 */
bool
sudoers_format_userspecs(struct sudo_lbuf *lbuf, struct userspec_list *usl,
    bool expand_aliases)
{
    struct userspec *us;
    debug_decl(sudoers_format_userspecs, SUDOERS_DEBUG_UTIL)

    TAILQ_FOREACH(us, usl, entries) {
	if (!sudoers_format_userspec(lbuf, us, expand_aliases))
	    break;
    }

    debug_return_bool(!sudo_lbuf_error(lbuf));
}

/*
 * Format and append a defaults entry to the specified lbuf.
 */
bool
sudoers_format_default(struct sudo_lbuf *lbuf, struct defaults *d)
{
    debug_decl(sudoers_format_default, SUDOERS_DEBUG_UTIL)

    if (d->val != NULL) {
	sudo_lbuf_append(lbuf, "%s%s", d->var,
	    d->op == '+' ? "+=" : d->op == '-' ? "-=" : "=");
	if (strpbrk(d->val, " \t") != NULL) {
	    sudo_lbuf_append(lbuf, "\"");
	    sudo_lbuf_append_quoted(lbuf, "\"", "%s", d->val);
	    sudo_lbuf_append(lbuf, "\"");
	} else
	    sudo_lbuf_append_quoted(lbuf, SUDOERS_QUOTED, "%s", d->val);
    } else {
	sudo_lbuf_append(lbuf, "%s%s", d->op == false ? "!" : "", d->var);
    }
    debug_return_bool(!sudo_lbuf_error(lbuf));
}
