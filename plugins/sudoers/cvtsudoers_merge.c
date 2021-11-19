/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2021 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "sudoers.h"
#include "redblack.h"
#include "cvtsudoers.h"
#include <gram.h>

/*
 * Compare two digest lists.
 * Returns true if they are the same, else false.
 * XXX - should not care about order
 */
static bool
digest_list_equivalent(struct command_digest_list *cdl1,
    struct command_digest_list *cdl2)
{
    struct command_digest *cd1 = TAILQ_FIRST(cdl1);
    struct command_digest *cd2 = TAILQ_FIRST(cdl2);
    debug_decl(digest_list_equivalent, SUDOERS_DEBUG_PARSER);

    while (cd1 != NULL && cd2 != NULL) {
	if (cd1->digest_type != cd2->digest_type)
	    debug_return_bool(false);
	if (strcmp(cd1->digest_str, cd2->digest_str) != 0)
	    debug_return_bool(false);
	cd1 = TAILQ_NEXT(cd1, entries);
	cd2 = TAILQ_NEXT(cd2, entries);
    }

    if (cd1 != NULL || cd2 != NULL)
	debug_return_bool(false);
    debug_return_bool(true);
}

/*
 * Compare two members.
 * Returns true if they are the same, else false.
 */
static bool
member_equivalent(struct member *m1, struct member *m2)
{
    debug_decl(member_equivalent, SUDOERS_DEBUG_PARSER);

    if (m1->type != m2->type || m1->negated != m2->negated)
	debug_return_bool(false);

    if (m1->type == COMMAND) {
	struct sudo_command *c1 = (struct sudo_command *)m1->name;
	struct sudo_command *c2 = (struct sudo_command *)m2->name;
	if (c1->cmnd != NULL && c2->cmnd != NULL) {
	    if (strcmp(c1->cmnd, c2->cmnd) != 0)
		debug_return_bool(false);
	} else if (c1->cmnd != c2->cmnd) {
	    debug_return_bool(false);
	}

	if (c1->args != NULL && c2->args != NULL) {
	    if (strcmp(c1->args, c2->args) != 0)
		debug_return_bool(false);
	} else if (c1->args != c2->args) {
	    debug_return_bool(false);
	}

	if (!digest_list_equivalent(&c1->digests, &c2->digests)) {
	    debug_return_bool(false);
	}
    } else {
	if (m1->name != NULL && m2->name != NULL) {
	    if (strcmp(m1->name, m2->name) != 0)
		debug_return_bool(false);
	} else if (m1->name != m2->name) {
	    debug_return_bool(false);
	}
    }

    debug_return_bool(true);
}

/*
 * Compare two member lists.
 * Returns true if they are the same, else false.
 * XXX - should not care about order if things are not negated.
 */
static bool
member_list_equivalent(struct member_list *ml1, struct member_list *ml2)
{
    struct member *m1 = TAILQ_FIRST(ml1);
    struct member *m2 = TAILQ_FIRST(ml2);
    debug_decl(member_list_equivalent, SUDOERS_DEBUG_PARSER);

    while (m1 != NULL && m2 != NULL) {
	if (!member_equivalent(m1, m2))
	    debug_return_bool(false);
	m1 = TAILQ_NEXT(m1, entries);
	m2 = TAILQ_NEXT(m2, entries);
    }

    if (m1 != NULL || m2 != NULL)
	debug_return_bool(false);
    debug_return_bool(true);
}

/*
 * Generate a unique name from old_name that is not used in parse_tree,
 * subsequent parse_trees or merged_tree.
 */
static char *
alias_make_unique(const char *old_name, int type,
    struct sudoers_parse_tree *parse_tree0,
    struct sudoers_parse_tree *merged_tree)
{
    struct sudoers_parse_tree *parse_tree = parse_tree0;
    char *cp, *new_name = NULL;
    struct alias *a;
    long long suffix;
    size_t namelen;
    debug_decl(alias_make_unique, SUDOERS_DEBUG_ALIAS);

    /* If old_name already has a suffix, increment it, else start with "_1". */
    suffix = 0;
    namelen = strlen(old_name);
    cp = strrchr(old_name, '_');
    if (cp != NULL && isdigit((unsigned char)cp[1])) {
	suffix = sudo_strtonum(cp + 1, 0, LLONG_MAX, NULL);
	if (suffix != 0) {
	    namelen = (size_t)(cp - old_name);
	}
    }

    for (;;) {
	suffix++;
	free(new_name);
	if (asprintf(&new_name, "%.*s_%lld", (int)namelen, old_name, suffix) == -1)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	/* Make sure new_name is not already in use. */
	a = alias_get(merged_tree, new_name, type);
	if (a != NULL) {
	    alias_put(a);
	    continue;
	}
	parse_tree = parse_tree0;
	while ((parse_tree = TAILQ_NEXT(parse_tree, entries)) != NULL) {
	    a = alias_get(parse_tree, new_name, type);
	    if (a != NULL) {
		alias_put(a);
		break;
	    }
	}
	if (a == NULL) {
	    /* Must be unique. */
	    break;
	}
    }

    debug_return_ptr(new_name);
}

struct alias_rename_closure {
    const char *old_name;
    const char *new_name;
    int type;
};

static int
alias_rename_members(struct sudoers_parse_tree *parse_tree, struct alias *a,
    void *v)
{
    struct alias_rename_closure *closure = v;
    struct member *m;
    debug_decl(alias_rename_members, SUDOERS_DEBUG_ALIAS);

    if (a->type != closure->type)
	debug_return_int(0);

    /* Replace old_name in member list, if present. */
    TAILQ_FOREACH(m, &a->members, entries) {
	if (m->type == ALIAS && strcmp(m->name, closure->old_name) == 0) {
	    char *copy = strdup(closure->new_name);
	    if (copy == NULL)
		sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    free(m->name);
	    m->name = copy;
	}
    }

    debug_return_int(0);
}

static void
alias_rename_defaults(const char *old_name, const char *new_name,
    int alias_type, struct defaults_list *defaults)
{
    struct defaults *def;
    struct member_list *prev_binding = NULL;
    struct member *m;
    debug_decl(alias_rename_defaults, SUDOERS_DEBUG_ALIAS);

    TAILQ_FOREACH(def, defaults, entries) {
	if (def->binding == prev_binding)
	    continue;
	switch (def->type) {
	case DEFAULTS_USER:
	    if (alias_type != USERALIAS)
		goto wrong_type;
	    break;
	case DEFAULTS_RUNAS:
	    if (alias_type != RUNASALIAS)
		goto wrong_type;
	    break;
	case DEFAULTS_HOST:
	    if (alias_type != HOSTALIAS)
		goto wrong_type;
	    break;
	default:
	wrong_type:
	    prev_binding = NULL;
	    continue;
	}
	if (def->binding != NULL) {
	    TAILQ_FOREACH(m, def->binding, entries) {
		if (m->type != ALIAS)
		    continue;
		if (strcmp(m->name, old_name) == 0) {
		    char *copy = strdup(new_name);
		    if (copy == NULL) {
			sudo_fatalx(U_("%s: %s"), __func__,
			    U_("unable to allocate memory"));
		    }
		    free(m->name);
		    m->name = copy;
		}
	    }
	}
	prev_binding = def->binding;
    }

    debug_return;
}

static void
alias_rename_member(const char *old_name, const char *new_name,
    struct member *m)
{
    debug_decl(alias_rename_member, SUDOERS_DEBUG_ALIAS);

    if (m->type == ALIAS && strcmp(m->name, old_name) == 0) {
	char *copy = strdup(new_name);
	if (copy == NULL) {
	    sudo_fatalx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	}
	free(m->name);
	m->name = copy;
    }

    debug_return;
}

static void
alias_rename_member_list(const char *old_name, const char *new_name,
    struct member_list *members)
{
    struct member *m;
    debug_decl(alias_rename_member_list, SUDOERS_DEBUG_ALIAS);

    TAILQ_FOREACH(m, members, entries) {
	alias_rename_member(old_name, new_name, m);
    }

    debug_return;
}

static bool
alias_rename_userspecs(const char *old_name, const char *new_name,
    int alias_type, struct userspec_list *userspecs)
{
    struct privilege *priv;
    struct cmndspec *cs;
    struct userspec *us;
    bool ret = true;
    debug_decl(alias_rename_userspecs, SUDOERS_DEBUG_ALIAS);

    TAILQ_FOREACH(us, userspecs, entries) {
	if (alias_type == USERALIAS) {
	    alias_rename_member_list(old_name, new_name, &us->users);
	}
	TAILQ_FOREACH(priv, &us->privileges, entries) {
	    alias_rename_defaults(old_name, new_name, alias_type, &priv->defaults);
	    if (alias_type == HOSTALIAS) {
		alias_rename_member_list(old_name, new_name, &priv->hostlist);
		continue;
	    }
	    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		if (alias_type == CMNDALIAS) {
		    alias_rename_member(old_name, new_name, cs->cmnd);
		    continue;
		}
		if (alias_type == RUNASALIAS) {
		    if (cs->runasuserlist != NULL) {
			alias_rename_member_list(old_name, new_name, cs->runasuserlist);
		    }
		    if (cs->runasgrouplist != NULL) {
			alias_rename_member_list(old_name, new_name, cs->runasgrouplist);
		    }
		}
	    }
	}
    }

    debug_return_bool(ret);
}

/*
 * Rename an alias in parse_tree and all the places where it is used.
 */
static bool
alias_rename(const char *old_name, const char *new_name, int alias_type,
    struct sudoers_parse_tree *parse_tree)
{
    struct alias_rename_closure closure = { old_name, new_name, alias_type };
    struct alias *a;
    debug_decl(alias_rename, SUDOERS_DEBUG_ALIAS);

    /* Remove under old name and add via new to maintain tree properties. */
    a = alias_remove(parse_tree, old_name, alias_type);
    if (a == NULL) {
	/* Should not happen. */
	sudo_warnx(U_("unable to find alias %s"), old_name);
	debug_return_bool(false);
    }
    free(a->name);
    a->name = strdup(new_name);
    if (a->name == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    switch (rbinsert(parse_tree->aliases, a, NULL)) {
    case 0:
	/* success */
	break;
    case 1:
	/* Already present, should not happen. */
	errno = EEXIST;
	sudo_warn(U_("%s: %s"), __func__, a->name);
	break;
    default:
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }

    /* Rename it in the aliases tree itself (aliases can be nested). */
    alias_apply(parse_tree, alias_rename_members, &closure);

    /* Rename it in the Defaults list. */
    alias_rename_defaults(old_name, new_name, alias_type, &parse_tree->defaults);

    /* Rename it in the userspecs list. */
    alias_rename_userspecs(old_name, new_name, alias_type, &parse_tree->userspecs);

    debug_return_bool(true);
}

static int
alias_resolve_conflicts(struct sudoers_parse_tree *parse_tree0, struct alias *a,
    void *v)
{
    struct sudoers_parse_tree *parse_tree = parse_tree0;
    struct sudoers_parse_tree *merged_tree = v;
    char *new_name;
    int ret;
    debug_decl(alias_resolve_conflicts, SUDOERS_DEBUG_ALIAS);

    /*
     * Check for conflicting alias names in the subsequent sudoers files.
     * Duplicates are removed and conflicting aliases are renamed.
     * We cannot modify the alias tree that we are traversing.
     */
    while ((parse_tree = TAILQ_NEXT(parse_tree, entries)) != NULL) {
	struct alias *b = alias_get(parse_tree, a->name, a->type);
	if (b == NULL)
	    continue;

	/* If alias 'b' is equivalent, remove it. */
	alias_put(b);
	if (member_list_equivalent(&a->members, &b->members)) {
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"removing duplicate alias %s from %p", a->name, parse_tree);
	    b = alias_remove(parse_tree, a->name, a->type);
	    alias_free(b);
	    continue;
	}

	/* Rename alias 'b' to avoid a naming conflict. */
	new_name = alias_make_unique(a->name, a->type, parse_tree, merged_tree);
	alias_rename(a->name, new_name, a->type, parse_tree);
	free(new_name);
    }

    /*
     * The alias will exist in both the original and merged trees.
     * This is not a problem as the caller will delete the old trees
     * (without freeing the data).
     */
    ret = rbinsert(merged_tree->aliases, a, NULL);
    switch (ret) {
    case 0:
	/* success */
	break;
    case 1:
	/* already present, should not happen. */
	errno = EEXIST;
	sudo_warn(U_("%s: %s"), __func__, a->name);
	break;
    default:
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }

    debug_return_int(0);
}

static bool
merge_aliases(struct sudoers_parse_tree_list *parse_trees,
    struct sudoers_parse_tree *merged_tree)
{
    struct sudoers_parse_tree *parse_tree;
    debug_decl(merge_aliases, SUDOERS_DEBUG_ALIAS);

    /*
     * For each parse_tree, check for collisions with alias names
     * in subsequent parse trees.  On collision, add a numbered
     * suffix (e.g. ALIAS_1) to make the name unique and rename
     * any uses of that alias in the affected parse_tree.
     */
    TAILQ_FOREACH(parse_tree, parse_trees, entries) {
	if (parse_tree->aliases == NULL)
	    continue;

	/*
	 * Resolve any conflicts in alias names, renaming aliases as
	 * needed and eliminating duplicates.
	 */
	alias_apply(parse_tree, alias_resolve_conflicts, merged_tree);

	/*
	 * Destroy the old alias tree without freeing the alias data
	 * which has been copied to merged_tree.
	 */
	rbdestroy(parse_tree->aliases, NULL);
	parse_tree->aliases = NULL;
    }

    debug_return_bool(true);
}

static bool
merge_defaults(struct sudoers_parse_tree_list *parse_trees,
    struct sudoers_parse_tree *merged_tree)
{
    struct sudoers_parse_tree *parse_tree;
    debug_decl(merge_defaults, SUDOERS_DEBUG_DEFAULTS);

    /* XXX - implement */
    TAILQ_FOREACH(parse_tree, parse_trees, entries) {
	TAILQ_CONCAT(&merged_tree->defaults, &parse_tree->defaults, entries);
    }

    debug_return_bool(true);
}

static bool
merge_userspecs(struct sudoers_parse_tree_list *parse_trees,
    struct sudoers_parse_tree *merged_tree)
{
    struct sudoers_parse_tree *parse_tree;
    debug_decl(merge_userspecs, SUDOERS_DEBUG_PARSER);

    /* XXX - implement */
    TAILQ_FOREACH(parse_tree, parse_trees, entries) {
	TAILQ_CONCAT(&merged_tree->userspecs, &parse_tree->userspecs, entries);
    }

    debug_return_bool(true);
}

struct sudoers_parse_tree *
merge_sudoers(struct sudoers_parse_tree_list *parse_trees,
    struct sudoers_parse_tree *merged_tree)
{
    debug_decl(merge_sudoers, SUDOERS_DEBUG_UTIL);

    memset(merged_tree, 0, sizeof(*merged_tree));
    TAILQ_INIT(&merged_tree->userspecs);
    TAILQ_INIT(&merged_tree->defaults);
    if ((merged_tree->aliases = alloc_aliases()) == NULL)
	sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

    if (!merge_aliases(parse_trees, merged_tree))
	debug_return_ptr(NULL);

    if (!merge_defaults(parse_trees, merged_tree))
	debug_return_ptr(NULL);

    if (!merge_userspecs(parse_trees, merged_tree))
	debug_return_ptr(NULL);

    debug_return_ptr(merged_tree);
}
