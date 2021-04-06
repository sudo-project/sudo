/*
 * SPDX-License-Identifier: ISC
 *
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sudoers.h"
#include <gram.h>

static int
check_alias(struct sudoers_parse_tree *parse_tree, char *name, int type,
    char *file, int line, int column, bool strict, bool quiet)
{
    struct member *m;
    struct alias *a;
    int errors = 0;
    debug_decl(check_alias, SUDOERS_DEBUG_ALIAS);

    if ((a = alias_get(parse_tree, name, type)) != NULL) {
	/* check alias contents */
	TAILQ_FOREACH(m, &a->members, entries) {
	    if (m->type != ALIAS)
		continue;
	    errors += check_alias(parse_tree, m->name, type, a->file, a->line,
		a->column, strict, quiet);
	}
	alias_put(a);
    } else {
	if (!quiet) {
	    if (errno == ELOOP) {
		fprintf(stderr, strict ?
		    U_("Error: %s:%d:%d: cycle in %s \"%s\"") :
		    U_("Warning: %s:%d:%d: cycle in %s \"%s\""),
		    file, line, column, alias_type_to_string(type), name);
	    } else {
		fprintf(stderr, strict ?
		    U_("Error: %s:%d:%d: %s \"%s\" referenced but not defined") :
		    U_("Warning: %s:%d:%d: %s \"%s\" referenced but not defined"),
		    file, line, column, alias_type_to_string(type), name);
	    }
	    fputc('\n', stderr);
	    if (strict && errorfile == NULL) {
		errorfile = sudo_rcstr_addref(file);
		errorlineno = line;
	    }
	}
	errors++;
    }

    debug_return_int(errors);
}

/*
 * Iterate through the sudoers datastructures looking for undefined
 * aliases or unused aliases.
 */
int
check_aliases(struct sudoers_parse_tree *parse_tree, bool strict, bool quiet,
    int (*cb_unused)(struct sudoers_parse_tree *, struct alias *, void *))
{
    struct rbtree *used_aliases;
    struct cmndspec *cs;
    struct member *m;
    struct privilege *priv;
    struct userspec *us;
    int errors = 0;
    debug_decl(check_aliases, SUDOERS_DEBUG_ALIAS);

    used_aliases = alloc_aliases();
    if (used_aliases == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_int(-1);
    }

    /* Forward check. */
    TAILQ_FOREACH(us, &parse_tree->userspecs, entries) {
	TAILQ_FOREACH(m, &us->users, entries) {
	    if (m->type == ALIAS) {
		errors += check_alias(parse_tree, m->name, USERALIAS,
		    us->file, us->line, us->column, strict, quiet);
	    }
	}
	TAILQ_FOREACH(priv, &us->privileges, entries) {
	    TAILQ_FOREACH(m, &priv->hostlist, entries) {
		if (m->type == ALIAS) {
		    errors += check_alias(parse_tree, m->name, HOSTALIAS,
			us->file, us->line, us->column, strict, quiet);
		}
	    }
	    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m->type == ALIAS) {
			    errors += check_alias(parse_tree, m->name, RUNASALIAS,
				us->file, us->line, us->column, strict, quiet);
			}
		    }
		}
		if (cs->runasgrouplist != NULL) {
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m->type == ALIAS) {
			    errors += check_alias(parse_tree, m->name, RUNASALIAS,
				us->file, us->line, us->column, strict, quiet);
			}
		    }
		}
		if ((m = cs->cmnd)->type == ALIAS) {
		    errors += check_alias(parse_tree, m->name, CMNDALIAS,
			us->file, us->line, us->column, strict, quiet);
		}
	    }
	}
    }

    /* Reverse check (destructive) */
    if (!alias_find_used(parse_tree, used_aliases))
	errors++;
    free_aliases(used_aliases);

    /* If all aliases were referenced we will have an empty tree. */
    if (!no_aliases(parse_tree))
	alias_apply(parse_tree, cb_unused, &quiet);

    debug_return_int(strict ? errors : 0);
}
