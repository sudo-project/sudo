/*
 * Copyright (c) 2013, 2016, 2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <ctype.h>
#ifdef HAVE_LBER_H
# include <lber.h>
#endif
#include <ldap.h>

#include "sudoers.h"
#include "parse.h"
#include "gram.h"
#include "sudo_lbuf.h"
#include "sudo_ldap.h"

/*
 * Returns true if the string pointed to by valp begins with an
 * odd number of '!' characters.  Intervening blanks are ignored.
 * Stores the address of the string after '!' removal in valp.
 */
bool
sudo_ldap_is_negated(char **valp)
{
    char *val = *valp;
    bool ret = false;
    debug_decl(sudo_ldap_is_negated, SUDOERS_DEBUG_LDAP)

    while (*val == '!') {
	ret = !ret;
	do {
	    val++;
	} while (isblank((unsigned char)*val));
    }
    *valp = val;
    debug_return_bool(ret);
}

/*
 * Parse an option string into a defaults structure.
 * The members of def are pointers into optstr (which is modified).
 */
int
sudo_ldap_parse_option(char *optstr, char **varp, char **valp)
{
    char *cp, *val = NULL;
    char *var = optstr;
    int op;
    debug_decl(sudo_ldap_parse_option, SUDOERS_DEBUG_LDAP)

    /* check for equals sign past first char */
    cp = strchr(var, '=');
    if (cp > var) {
	val = cp + 1;
	op = cp[-1];	/* peek for += or -= cases */
	if (op == '+' || op == '-') {
	    /* case var+=val or var-=val */
	    cp--;
	} else {
	    /* case var=val */
	    op = true;
	}
	/* Trim whitespace between var and operator. */
	while (cp > var && isblank((unsigned char)cp[-1]))
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
    } else {
	/* Boolean value, either true or false. */
	op = sudo_ldap_is_negated(&var) ? false : true;
    }
    *varp = var;
    *valp = val;

    debug_return_int(op);
}

/*
 * Convert an array to a member list.
 * The caller is responsible for freeing the returned struct member_list.
 */
static struct member_list *
array_to_member_list(void *a, sudo_ldap_iter_t iter)
{
    struct member_list *members;
    struct member *m;
    char *val;
    debug_decl(bv_to_member_list, SUDOERS_DEBUG_LDAP)

    if ((members = calloc(1, sizeof(*members))) == NULL)
	return NULL;
    TAILQ_INIT(members);                      

    while ((val = iter(&a)) != NULL) {
	if ((m = calloc(1, sizeof(*m))) == NULL)
	    goto bad;

	switch (val[0]) {
	case '\0':
	    /* Empty RunAsUser means run as the invoking user. */
	    m->type = MYSELF;
	    break;
	case 'A':
	    if (strcmp(val, "ALL") == 0) {
		m->type = ALL;
		break;
	    }
	    /* FALLTHROUGH */
	default:
	    m->type = WORD;
	    m->name = strdup(val);
	    if (m->name == NULL) {
		free(m);
		goto bad;
	    }
	    break;
	}
	TAILQ_INSERT_TAIL(members, m, entries);
    }
    debug_return_ptr(members);
bad:
    while ((m = TAILQ_FIRST(members)) != NULL) {
	TAILQ_REMOVE(members, m, entries);
	free(m->name);
	free(m);
    }
    free(members);
    debug_return_ptr(NULL);
}

/*
 * Convert an LDAP sudoRole to a sudoers privilege.
 * Pass in struct berval ** for LDAP or char *** for SSSD.
 */
struct privilege *
sudo_ldap_role_to_priv(const char *cn, void *runasusers, void *runasgroups,
    void *cmnds, void *opts, const char *notbefore,
    const char *notafter, sudo_ldap_iter_t iter)
{
    struct cmndspec *cmndspec = NULL;
    struct cmndspec *prev_cmndspec = NULL;
    struct sudo_command *c;
    struct privilege *priv;
    struct member *m;
    char *cmnd;
    debug_decl(sudo_ldap_role_to_priv, SUDOERS_DEBUG_LDAP)

    if ((priv = calloc(1, sizeof(*priv))) == NULL)
	goto oom;
    TAILQ_INIT(&priv->hostlist);
    TAILQ_INIT(&priv->cmndlist);
    TAILQ_INIT(&priv->defaults);

    priv->ldap_role = strdup(cn ? cn : "UNKNOWN");
    if (priv->ldap_role == NULL)
	goto oom;

    /* The host has already matched, use ALL as wildcard. */
    if ((m = calloc(1, sizeof(*m))) == NULL)
	goto oom;
    m->type = ALL;
    TAILQ_INSERT_TAIL(&priv->hostlist, m, entries);

    /*
     * Parse sudoCommands and add to cmndlist.
     */
    while ((cmnd = iter(&cmnds)) != NULL) {
	char *args;

	/* Allocate storage upfront. */
	cmndspec = calloc(1, sizeof(*cmndspec));
	c = calloc(1, sizeof(*c));
	m = calloc(1, sizeof(*m));
	if (cmndspec == NULL || c == NULL || m == NULL) {
	    free(cmndspec);
	    free(c);
	    free(m);
	    goto oom;
	}
	TAILQ_INSERT_TAIL(&priv->cmndlist, cmndspec, entries);

	/* Initialize cmndspec */
	TAGS_INIT(cmndspec->tags);
	cmndspec->notbefore = UNSPEC;
	cmndspec->notafter = UNSPEC;
	cmndspec->timeout = UNSPEC;

	/* Fill in command. */
	if ((args = strpbrk(cmnd, " \t")) != NULL) {
	    *args++ = '\0';
	    if ((c->args = strdup(args)) == NULL) {
		free(c);
		free(m);
		goto oom;
	    }
	}
	if ((c->cmnd = strdup(cmnd)) == NULL) {
	    free(c->args);
	    free(c);
	    free(m);
	    goto oom;
	}
	m->type = COMMAND;
	m->name = (char *)c;
	cmndspec->cmnd = m;

	if (prev_cmndspec != NULL) {
	    /* Inherit values from prior cmndspec */
	    cmndspec->runasuserlist = prev_cmndspec->runasuserlist;
	    cmndspec->runasgrouplist = prev_cmndspec->runasgrouplist;
	    cmndspec->notbefore = prev_cmndspec->notbefore;
	    cmndspec->notafter = prev_cmndspec->notafter;
	    cmndspec->tags = prev_cmndspec->tags;
	} else {
	    /* Parse sudoRunAsUser / sudoRunAs */
	    if (runasusers != NULL) {
		cmndspec->runasuserlist =
		    array_to_member_list(runasusers, iter);
		if (cmndspec->runasuserlist == NULL)
		    goto oom;
	    }

	    /* Parse sudoRunAsGroup */
	    if (runasgroups != NULL) {
		cmndspec->runasgrouplist =
		    array_to_member_list(runasgroups, iter);
		if (cmndspec->runasgrouplist == NULL)
		    goto oom;
	    }

	    /* Parse sudoNotBefore / sudoNotAfter */
	    if (notbefore != NULL)
		cmndspec->notbefore = parse_gentime(notbefore);
	    if (notafter != NULL)
		cmndspec->notbefore = parse_gentime(notafter);

	    /* Parse sudoOptions. */
	    if (opts != NULL) {
		char *opt;

		while ((opt = iter(&opts)) != NULL) {
		    char *var, *val;
		    int op;

		    op = sudo_ldap_parse_option(opt, &var, &val);
		    if (strcmp(var, "command_timeout") == 0) {
			if (op == '=')
			    cmndspec->timeout = parse_timeout(val);
#ifdef HAVE_SELINUX
		    } else if (strcmp(var, "role") == 0) {
			if (op == '=') {
			    if ((cmndspec->role = strdup(val)) == NULL)
				goto oom;
			}
		    } else if (strcmp(var, "type") == 0) {
			if (op == '=') {
			    if ((cmndspec->type = strdup(val)) == NULL)
				goto oom;
			}
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
		    } else if (strcmp(var, "privs") == 0) {
			if (op == '=') {
			    if ((cmndspec->privs = strdup(val)) == NULL)
				goto oom;
			}
		    } else if (strcmp(val, "limitprivs") == 0) {
			if (op == '=') {
			    if ((cmndspec->limitprivs = strdup(val)) == NULL)
				goto oom;
			}
#endif /* HAVE_PRIV_SET */
		    } else if (long_list) {
			struct defaults *def = calloc(1, sizeof(*def));
			if (def == NULL)
			    goto oom;
			def->op = op;
			if ((def->var = strdup(var)) == NULL) {
			    free(def);
			    goto oom;
			}
			if (val != NULL) {
			    if ((def->val = strdup(val)) == NULL) {
				free(def->var);
				free(def);
				goto oom;
			    }
			}
			TAILQ_INSERT_TAIL(&priv->defaults, def, entries);
		    } else {
			/* Convert to tags. */
			if (op != true && op != false)
			    continue;
			if (strcmp(var, "authenticate") == 0) {
			    cmndspec->tags.nopasswd = op == false;
			} else if (strcmp(var, "sudoedit_follow") == 0) {
			    cmndspec->tags.follow = op == true;
			} else if (strcmp(var, "noexec") == 0) {
			    cmndspec->tags.noexec = op == true;
			} else if (strcmp(var, "setenv") == 0) {
			    cmndspec->tags.setenv = op == true;
			} else if (strcmp(var, "mail_all_cmnds") == 0 ||
			    strcmp(var, "mail_always") == 0) {
			    cmndspec->tags.send_mail = op == true;
			}
		    }
		}
	    }

	    /* So we can inherit previous values. */
	    prev_cmndspec = cmndspec;
	}
    }
    debug_return_ptr(priv);

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    if (priv != NULL)
	free_privilege(priv);
    debug_return_ptr(NULL);
}

/*
 * If a digest prefix is present, fills in struct sudo_digest
 * and returns a pointer to it, updating cmnd to point to the
 * command after the digest.
 */
struct sudo_digest *
sudo_ldap_extract_digest(char **cmnd, struct sudo_digest *digest)
{
    char *ep, *cp = *cmnd;
    int digest_type = SUDO_DIGEST_INVALID;
    debug_decl(sudo_ldap_check_command, SUDOERS_DEBUG_LDAP)

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
			digest_type_to_name(digest_type),
			digest->digest_str, cp);
		    debug_return_ptr(digest);
		}
	    }
	}
    }
    debug_return_ptr(NULL);
}
