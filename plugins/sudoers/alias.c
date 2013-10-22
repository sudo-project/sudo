/*
 * Copyright (c) 2004-2005, 2007-2013
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <errno.h>

#include "sudoers.h"
#include "parse.h"
#include "redblack.h"
#include <gram.h>

/*
 * Globals
 */
struct rbtree *aliases;

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
    debug_decl(alias_compare, SUDO_DEBUG_ALIAS)

    if (v1 == NULL)
	res = -1;
    else if (v2 == NULL)
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
    debug_decl(alias_get, SUDO_DEBUG_ALIAS)

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
    debug_decl(alias_put, SUDO_DEBUG_ALIAS)
    a->used = false;
    debug_return;
}

/*
 * Add an alias to the aliases redblack tree.
 * Returns NULL on success and an error string on failure.
 */
char *
alias_add(char *name, int type, struct member *members)
{
    static char errbuf[512];
    struct alias *a;
    debug_decl(alias_add, SUDO_DEBUG_ALIAS)

    a = ecalloc(1, sizeof(*a));
    a->name = name;
    a->type = type;
    /* a->used = false; */
    HLTQ_TO_TAILQ(&a->members, members, entries);
    if (rbinsert(aliases, a)) {
	snprintf(errbuf, sizeof(errbuf), N_("Alias `%s' already defined"), name);
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
    debug_decl(alias_apply, SUDO_DEBUG_ALIAS)

    rbapply(aliases, func, cookie, inorder);

    debug_return;
}

/*
 * Returns true if there are no aliases, else false.
 */
bool
no_aliases(void)
{
    debug_decl(no_aliases, SUDO_DEBUG_ALIAS)
    debug_return_bool(rbisempty(aliases));
}

/*
 * Free memory used by an alias struct and its members.
 */
void
alias_free(void *v)
{
    struct alias *a = (struct alias *)v;
    struct member *m;
    struct sudo_command *c;
    void *next;
    debug_decl(alias_free, SUDO_DEBUG_ALIAS)

    efree(a->name);
    TAILQ_FOREACH_SAFE(m, &a->members, entries, next) {
	if (m->type == COMMAND) {
		c = (struct sudo_command *) m->name;
		efree(c->cmnd);
		efree(c->args);
	}
	efree(m->name);
	efree(m);
    }
    efree(a);

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
    debug_decl(alias_remove, SUDO_DEBUG_ALIAS)

    key.name = name;
    key.type = type;
    if ((node = rbfind(aliases, &key)) == NULL) {
	errno = ENOENT;
	return NULL;
    }
    debug_return_ptr(rbdelete(aliases, node));
}

void
init_aliases(void)
{
    debug_decl(init_aliases, SUDO_DEBUG_ALIAS)

    if (aliases != NULL)
	rbdestroy(aliases, alias_free);
    aliases = rbcreate(alias_compare);

    debug_return;
}
