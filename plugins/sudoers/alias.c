/*
 * Copyright (c) 2004-2005, 2007-2016
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#endif /* HAVE_STRING_H */
#include <unistd.h>
#include <errno.h>

#include "sudoers.h"
#include "parse.h"
#include "redblack.h"
#include <gram.h>

/*
 * Globals
 */
static struct rbtree *aliases;

/*
 * Comparison function for the red-black tree.
 * Aliases are sorted by name with the type used as a tie-breaker.
 */
int
alias_compare(const void *v1, const void *v2)
{
    const struct alias *a1 = (const struct alias *)v1;
    const struct alias *a2 = (const struct alias *)v2;
    int res;
    debug_decl(alias_compare, SUDOERS_DEBUG_ALIAS)

    if (a1 == NULL)
	res = -1;
    else if (a2 == NULL)
	res = 1;
    else if ((res = strcmp(a1->name, a2->name)) == 0)
	res = a1->type - a2->type;
    debug_return_int(res);
}

/*
 * Search the tree for an alias with the specified name and type.
 * Returns a pointer to the alias structure or NULL if not found.
 * Caller is responsible for calling alias_put() on the returned
 * alias to mark it as unused.
 */
struct alias *
alias_get(char *name, int type)
{
    struct alias key;
    struct rbnode *node;
    struct alias *a = NULL;
    debug_decl(alias_get, SUDOERS_DEBUG_ALIAS)

    key.name = name;
    key.type = type;
    if ((node = rbfind(aliases, &key)) != NULL) {
	/*
	 * Check whether this alias is already in use.
	 * If so, we've detected a loop.  If not, set the flag,
	 * which the caller should clear with a call to alias_put().
	 */
	a = node->data;
	if (a->used) {
	    errno = ELOOP;
	    debug_return_ptr(NULL);
	}
	a->used = true;
    } else {
	errno = ENOENT;
    }
    debug_return_ptr(a);
}

/*
 * Clear the "used" flag in an alias once the caller is done with it.
 */
void
alias_put(struct alias *a)
{
    debug_decl(alias_put, SUDOERS_DEBUG_ALIAS)
    a->used = false;
    debug_return;
}

/*
 * Add an alias to the aliases redblack tree.
 * Note that "file" must be a reference-counted string.
 * Returns NULL on success and an error string on failure.
 */
const char *
alias_add(char *name, int type, char *file, int lineno, struct member *members)
{
    static char errbuf[512];
    struct alias *a;
    debug_decl(alias_add, SUDOERS_DEBUG_ALIAS)

    a = calloc(1, sizeof(*a));
    if (a == NULL) {
	strlcpy(errbuf, N_("unable to allocate memory"), sizeof(errbuf));
	debug_return_str(errbuf);
    }
    a->name = name;
    a->type = type;
    /* a->used = false; */
    a->file = rcstr_addref(file);
    a->lineno = lineno;
    HLTQ_TO_TAILQ(&a->members, members, entries);
    switch (rbinsert(aliases, a, NULL)) {
    case 1:
	snprintf(errbuf, sizeof(errbuf), N_("Alias \"%s\" already defined"), name);
	alias_free(a);
	debug_return_str(errbuf);
    case -1:
	strlcpy(errbuf, N_("unable to allocate memory"), sizeof(errbuf));
	alias_free(a);
	debug_return_str(errbuf);
    }
    debug_return_str(NULL);
}

/*
 * Apply a function to each alias entry and pass in a cookie.
 */
void
alias_apply(int (*func)(void *, void *), void *cookie)
{
    debug_decl(alias_apply, SUDOERS_DEBUG_ALIAS)

    rbapply(aliases, func, cookie, inorder);

    debug_return;
}

/*
 * Returns true if there are no aliases, else false.
 */
bool
no_aliases(void)
{
    debug_decl(no_aliases, SUDOERS_DEBUG_ALIAS)
    debug_return_bool(rbisempty(aliases));
}

/*
 * Replace the aliases tree with a new one, returns the old.
 */
struct rbtree *
replace_aliases(struct rbtree *new_aliases)
{
    struct rbtree *old_aliases = aliases;
    debug_decl(replace_aliases, SUDOERS_DEBUG_ALIAS)

    aliases = new_aliases;

    debug_return_ptr(old_aliases);
}

/*
 * Free memory used by an alias struct and its members.
 */
void
alias_free(void *v)
{
    struct alias *a = (struct alias *)v;
    debug_decl(alias_free, SUDOERS_DEBUG_ALIAS)

    free(a->name);
    rcstr_delref(a->file);
    free_members(&a->members);
    free(a);

    debug_return;
}

/*
 * Find the named alias, remove it from the tree and return it.
 */
struct alias *
alias_remove(char *name, int type)
{
    struct rbnode *node;
    struct alias key;
    debug_decl(alias_remove, SUDOERS_DEBUG_ALIAS)

    key.name = name;
    key.type = type;
    if ((node = rbfind(aliases, &key)) == NULL) {
	errno = ENOENT;
	return NULL;
    }
    debug_return_ptr(rbdelete(aliases, node));
}

bool
init_aliases(void)
{
    debug_decl(init_aliases, SUDOERS_DEBUG_ALIAS)

    if (aliases != NULL)
	rbdestroy(aliases, alias_free);
    aliases = rbcreate(alias_compare);

    debug_return_bool(aliases != NULL);
}

const char *
alias_type_to_string(int alias_type)
{
    return alias_type == HOSTALIAS ? "Host_Alias" :
	alias_type == CMNDALIAS ? "Cmnd_Alias" :
	alias_type == USERALIAS ? "User_Alias" :
	alias_type == RUNASALIAS ? "Runas_Alias" :
	"Invalid_Alias";
}

/*
 * Remove the alias of the specified type as well as any other aliases
 * referenced by that alias.  Stores removed aliases in a freelist.
 */
static bool
alias_remove_recursive(char *name, int type, struct rbtree *freelist)
{
    struct member *m;
    struct alias *a;
    bool ret = true;
    debug_decl(alias_remove_recursive, SUDOERS_DEBUG_ALIAS)

    if ((a = alias_remove(name, type)) != NULL) {
	TAILQ_FOREACH(m, &a->members, entries) {
	    if (m->type == ALIAS) {
		if (!alias_remove_recursive(m->name, type, freelist))
		    ret = false;
	    }
	}
	if (rbinsert(freelist, a, NULL) != 0)
	    ret = false;
    }
    debug_return_bool(ret);
}

/*
 * Move all aliases referenced by userspecs to used_aliases.
 */
bool
alias_find_used(struct rbtree *used_aliases)
{
    struct privilege *priv;
    struct userspec *us;
    struct cmndspec *cs;
    struct defaults *d;
    struct member *m;
    int atype, errors = 0;
    debug_decl(alias_find_used, SUDOERS_DEBUG_ALIAS)

    /* Move referenced aliases to used_aliases. */
    TAILQ_FOREACH(us, &userspecs, entries) {
	TAILQ_FOREACH(m, &us->users, entries) {
	    if (m->type == ALIAS) {
		if (!alias_remove_recursive(m->name, USERALIAS, used_aliases))
		    errors++;
	    }
	}
	TAILQ_FOREACH(priv, &us->privileges, entries) {
	    TAILQ_FOREACH(m, &priv->hostlist, entries) {
		if (m->type == ALIAS) {
		    if (!alias_remove_recursive(m->name, HOSTALIAS, used_aliases))
			errors++;
		}
	    }
	    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m->type == ALIAS) {
			    if (!alias_remove_recursive(m->name, RUNASALIAS, used_aliases))
				errors++;
			}
		    }
		}
		if (cs->runasgrouplist != NULL) {
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m->type == ALIAS) {
			    if (!alias_remove_recursive(m->name, RUNASALIAS, used_aliases))
				errors++;
			}
		    }
		}
		if ((m = cs->cmnd)->type == ALIAS) {
		    if (!alias_remove_recursive(m->name, CMNDALIAS, used_aliases))
			errors++;
		}
	    }
	}
    }
    TAILQ_FOREACH(d, &defaults, entries) {
	switch (d->type) {
	    case DEFAULTS_HOST:
		atype = HOSTALIAS;
		break;
	    case DEFAULTS_USER:
		atype = USERALIAS;
		break;
	    case DEFAULTS_RUNAS:
		atype = RUNASALIAS;
		break;
	    case DEFAULTS_CMND:
		atype = CMNDALIAS;
		break;
	    default:
		continue; /* not an alias */
	}
	TAILQ_FOREACH(m, d->binding, entries) {
	    if (m->type == ALIAS) {
		if (!alias_remove_recursive(m->name, atype, used_aliases))
		    errors++;
	    }
	}
    }

    debug_return_int(errors ? false : true);
}
