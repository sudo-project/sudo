/*
 * Copyright (c) 1996, 1998-2005, 2007-2016
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#ifdef HAVE_SETAUTHDB
# include <usersec.h>
#endif /* HAVE_SETAUTHDB */
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "redblack.h"
#include "pwutil.h"

/*
 * The passwd and group caches.
 */
static struct rbtree *pwcache_byuid, *pwcache_byname;
static struct rbtree *grcache_bygid, *grcache_byname;
static struct rbtree *grlist_cache;

static int  cmp_pwuid(const void *, const void *);
static int  cmp_pwnam(const void *, const void *);
static int  cmp_grgid(const void *, const void *);

#define cmp_grnam	cmp_pwnam

/*
 * AIX has the concept of authentication registries (files, NIS, LDAP, etc).
 * This allows you to have separate ID <-> name mappings based on which
 * authentication registries the user was looked up in.
 * We store the registry as part of the key and use it when matching.
 */
#ifdef HAVE_SETAUTHDB
# define getauthregistry(u, r)	aix_getauthregistry((u), (r))
#else
# define getauthregistry(u, r)	((r)[0] = '\0')
#endif

/*
 * Compare by uid.
 */
static int
cmp_pwuid(const void *v1, const void *v2)
{
    const struct cache_item *ci1 = (const struct cache_item *) v1;
    const struct cache_item *ci2 = (const struct cache_item *) v2;
    if (ci1->k.uid == ci2->k.uid)
	return strcmp(ci1->registry, ci2->registry);
    return ci1->k.uid - ci2->k.uid;
}

/*
 * Compare by user name.
 */
static int
cmp_pwnam(const void *v1, const void *v2)
{
    const struct cache_item *ci1 = (const struct cache_item *) v1;
    const struct cache_item *ci2 = (const struct cache_item *) v2;
    int rval = strcmp(ci1->k.name, ci2->k.name);
    if (rval == 0)
	rval = strcmp(ci1->registry, ci2->registry);
    return rval;
}

void
sudo_pw_addref(struct passwd *pw)
{
    debug_decl(sudo_pw_addref, SUDOERS_DEBUG_NSS)
    ptr_to_item(pw)->refcnt++;
    debug_return;
}

static void
sudo_pw_delref_item(void *v)
{
    struct cache_item *item = v;
    debug_decl(sudo_pw_delref_item, SUDOERS_DEBUG_NSS)

    if (--item->refcnt == 0)
	free(item);

    debug_return;
}

void
sudo_pw_delref(struct passwd *pw)
{
    debug_decl(sudo_pw_delref, SUDOERS_DEBUG_NSS)
    sudo_pw_delref_item(ptr_to_item(pw));
    debug_return;
}

/*
 * Get a password entry by uid and allocate space for it.
 */
struct passwd *
sudo_getpwuid(uid_t uid)
{
    struct cache_item key, *item;
    struct rbnode *node;
    debug_decl(sudo_getpwuid, SUDOERS_DEBUG_NSS)

    if (pwcache_byuid == NULL) {
	pwcache_byuid = rbcreate(cmp_pwuid);
	if (pwcache_byuid == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_ptr(NULL);
	}
    }

    key.k.uid = uid;
    getauthregistry(IDtouser(uid), key.registry);
    if ((node = rbfind(pwcache_byuid, &key)) != NULL) {
	item = node->data;
	goto done;
    }
    /*
     * Cache passwd db entry if it exists or a negative response if not.
     */
#ifdef HAVE_SETAUTHDB
    aix_setauthdb(IDtouser(uid), key.registry);
#endif
    item = sudo_make_pwitem(uid, NULL);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
    if (item == NULL) {
	if (errno != ENOENT || (item = calloc(1, sizeof(*item))) == NULL) {
	    sudo_warnx(U_("unable to cache uid %u, out of memory"),
		(unsigned int) uid);
	    debug_return_ptr(NULL);
	}
	item->refcnt = 1;
	item->k.uid = uid;
	/* item->d.pw = NULL; */
    }
    strlcpy(item->registry, key.registry, sizeof(item->registry));
    switch (rbinsert(pwcache_byuid, item, NULL)) {
    case 1:
	/* should not happen */
	sudo_warnx(U_("unable to cache uid %u, already exists"),
	    (unsigned int) uid);
	item->refcnt = 0;
	break;
    case -1:
	/* can't cache item, just return it */
	sudo_warnx(U_("unable to cache uid %u, out of memory"),
	    (unsigned int) uid);
	item->refcnt = 0;
	break;
    }
done:
    if (item->refcnt != 0) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "%s: uid %u [%s] -> user %s [%s] (%s)", __func__,
	    (unsigned int)uid, key.registry,
	    item->d.pw ? item->d.pw->pw_name : "unknown",
	    item->registry, node ? "cache hit" : "cached");
    }
    item->refcnt++;
    debug_return_ptr(item->d.pw);
}

/*
 * Get a password entry by name and allocate space for it.
 */
struct passwd *
sudo_getpwnam(const char *name)
{
    struct cache_item key, *item;
    struct rbnode *node;
    debug_decl(sudo_getpwnam, SUDOERS_DEBUG_NSS)

    if (pwcache_byname == NULL) {
	pwcache_byname = rbcreate(cmp_pwnam);
	if (pwcache_byname == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_ptr(NULL);
	}
    }

    key.k.name = (char *) name;
    getauthregistry((char *) name, key.registry);
    if ((node = rbfind(pwcache_byname, &key)) != NULL) {
	item = node->data;
	goto done;
    }
    /*
     * Cache passwd db entry if it exists or a negative response if not.
     */
#ifdef HAVE_SETAUTHDB
    aix_setauthdb((char *) name, key.registry);
#endif
    item = sudo_make_pwitem((uid_t)-1, name);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
    if (item == NULL) {
	const size_t len = strlen(name) + 1;
	if (errno != ENOENT || (item = calloc(1, sizeof(*item) + len)) == NULL) {
	    sudo_warnx(U_("unable to cache user %s, out of memory"), name);
	    debug_return_ptr(NULL);
	}
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, name, len);
	/* item->d.pw = NULL; */
    }
    strlcpy(item->registry, key.registry, sizeof(item->registry));
    switch (rbinsert(pwcache_byname, item, NULL)) {
    case 1:
	/* should not happen */
	sudo_warnx(U_("unable to cache user %s, already exists"), name);
	item->refcnt = 0;
	break;
    case -1:
	/* can't cache item, just return it */
	sudo_warnx(U_("unable to cache user %s, out of memory"), name);
	item->refcnt = 0;
	break;
    }
done:
    if (item->refcnt != 0) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "%s: user %s [%s] -> uid %d [%s] (%s)", __func__, name,
	    key.registry, item->d.pw ? (int)item->d.pw->pw_uid : -1,
	    item->registry, node ? "cache hit" : "cached");
    }
    item->refcnt++;
    debug_return_ptr(item->d.pw);
}

/*
 * Take a user, uid, gid, home and shell and return a faked up passwd struct.
 * If home or shell are NULL default values will be used.
 */
struct passwd *
sudo_mkpwent(const char *user, uid_t uid, gid_t gid, const char *home,
    const char *shell)
{
    struct cache_item_pw *pwitem;
    struct cache_item *item;
    struct passwd *pw;
    size_t len, name_len, home_len, shell_len;
    int i;
    debug_decl(sudo_mkpwent, SUDOERS_DEBUG_NSS)

    if (pwcache_byuid == NULL)
	pwcache_byuid = rbcreate(cmp_pwuid);
    if (pwcache_byname == NULL)
	pwcache_byname = rbcreate(cmp_pwnam);
    if (pwcache_byuid == NULL || pwcache_byname == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_ptr(NULL);
    }

    /* Optional arguments. */
    if (home == NULL)
	home = "/";
    if (shell == NULL)
	shell = _PATH_BSHELL;

    sudo_debug_printf(SUDO_DEBUG_DEBUG,
	"%s: creating and caching passwd struct for %s:%u:%u:%s:%s", __func__,
	user, (unsigned int)uid, (unsigned int)gid, home, shell);

    name_len = strlen(user);
    home_len = strlen(home);
    shell_len = strlen(shell);
    len = sizeof(*pwitem) + name_len + 1 /* pw_name */ +
	sizeof("*") /* pw_passwd */ + sizeof("") /* pw_gecos */ +
	home_len + 1 /* pw_dir */ + shell_len + 1 /* pw_shell */;

    for (i = 0; i < 2; i++) {
	struct rbtree *pwcache;
	struct rbnode *node;

	pwitem = calloc(1, len);
	if (pwitem == NULL) {
	    sudo_warnx(U_("unable to cache user %s, out of memory"), user);
	    debug_return_ptr(NULL);
	}
	pw = &pwitem->pw;
	pw->pw_uid = uid;
	pw->pw_gid = gid;
	pw->pw_name = (char *)(pwitem + 1);
	memcpy(pw->pw_name, user, name_len + 1);
	pw->pw_passwd = pw->pw_name + name_len + 1;
	memcpy(pw->pw_passwd, "*", 2);
	pw->pw_gecos = pw->pw_passwd + 2;
	pw->pw_gecos[0] = '\0';
	pw->pw_dir = pw->pw_gecos + 1;
	memcpy(pw->pw_dir, home, home_len + 1);
	pw->pw_shell = pw->pw_dir + home_len + 1;
	memcpy(pw->pw_shell, shell, shell_len + 1);

	item = &pwitem->cache;
	item->refcnt = 1;
	item->d.pw = pw;
	if (i == 0) {
	    /* Store by uid. */
	    item->k.uid = pw->pw_uid;
	    pwcache = pwcache_byuid;
	} else {
	    /* Store by name. */
	    item->k.name = pw->pw_name;
	    pwcache = pwcache_byname;
	}
	getauthregistry(NULL, item->registry);
	switch (rbinsert(pwcache, item, &node)) {
	case 1:
	    /* Already exists. */
	    item = node->data;
	    if (item->d.pw == NULL) {
		/* Negative cache entry, replace with ours. */
		sudo_pw_delref_item(item);
		item = node->data = &pwitem->cache;
	    } else {
		/* Good entry, discard our fake one. */
		free(pwitem);
	    }
	    break;
	case -1:
	    /* can't cache item, just return it */
	    sudo_warnx(U_("unable to cache user %s, out of memory"), user);
	    item->refcnt = 0;
	    break;
	}
    }
    item->refcnt++;
    debug_return_ptr(item->d.pw);
}

/*
 * Take a uid in string form "#123" and return a faked up passwd struct.
 */
struct passwd *
sudo_fakepwnam(const char *user, gid_t gid)
{
    const char *errstr;
    uid_t uid;
    debug_decl(sudo_fakepwnam, SUDOERS_DEBUG_NSS)

    uid = (uid_t) sudo_strtoid(user + 1, NULL, NULL, &errstr);
    if (errstr != NULL) {
	sudo_debug_printf(SUDO_DEBUG_DIAG|SUDO_DEBUG_LINENO,
	    "uid %s %s", user, errstr);
	debug_return_ptr(NULL);
    }
    debug_return_ptr(sudo_mkpwent(user, uid, gid, NULL, NULL));
}

void
sudo_freepwcache(void)
{
    debug_decl(sudo_freepwcache, SUDOERS_DEBUG_NSS)

    if (pwcache_byuid != NULL) {
	rbdestroy(pwcache_byuid, sudo_pw_delref_item);
	pwcache_byuid = NULL;
    }
    if (pwcache_byname != NULL) {
	rbdestroy(pwcache_byname, sudo_pw_delref_item);
	pwcache_byname = NULL;
    }

    debug_return;
}

/*
 * Compare by gid.
 */
static int
cmp_grgid(const void *v1, const void *v2)
{
    const struct cache_item *ci1 = (const struct cache_item *) v1;
    const struct cache_item *ci2 = (const struct cache_item *) v2;
    if (ci1->k.gid == ci2->k.gid)
	return strcmp(ci1->registry, ci2->registry);
    return ci1->k.gid - ci2->k.gid;
}

void
sudo_gr_addref(struct group *gr)
{
    debug_decl(sudo_gr_addref, SUDOERS_DEBUG_NSS)
    ptr_to_item(gr)->refcnt++;
    debug_return;
}

static void
sudo_gr_delref_item(void *v)
{
    struct cache_item *item = v;
    debug_decl(sudo_gr_delref_item, SUDOERS_DEBUG_NSS)

    if (--item->refcnt == 0)
	free(item);

    debug_return;
}

void
sudo_gr_delref(struct group *gr)
{
    debug_decl(sudo_gr_delref, SUDOERS_DEBUG_NSS)
    sudo_gr_delref_item(ptr_to_item(gr));
    debug_return;
}

/*
 * Get a group entry by gid and allocate space for it.
 */
struct group *
sudo_getgrgid(gid_t gid)
{
    struct cache_item key, *item;
    struct rbnode *node;
    debug_decl(sudo_getgrgid, SUDOERS_DEBUG_NSS)

    if (grcache_bygid == NULL) {
	grcache_bygid = rbcreate(cmp_grgid);
	if (grcache_bygid == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_ptr(NULL);
	}
    }

    key.k.gid = gid;
    getauthregistry(NULL, key.registry);
    if ((node = rbfind(grcache_bygid, &key)) != NULL) {
	item = node->data;
	goto done;
    }
    /*
     * Cache group db entry if it exists or a negative response if not.
     */
    item = sudo_make_gritem(gid, NULL);
    if (item == NULL) {
	if (errno != ENOENT || (item = calloc(1, sizeof(*item))) == NULL) {
	    sudo_warnx(U_("unable to cache gid %u, out of memory"),
		(unsigned int) gid);
	    debug_return_ptr(NULL);
	}
	item->refcnt = 1;
	item->k.gid = gid;
	/* item->d.gr = NULL; */
    }
    strlcpy(item->registry, key.registry, sizeof(item->registry));
    switch (rbinsert(grcache_bygid, item, NULL)) {
    case 1:
	/* should not happen */
	sudo_warnx(U_("unable to cache gid %u, already exists"),
	    (unsigned int) gid);
	item->refcnt = 0;
	break;
    case -1:
	/* can't cache item, just return it */
	sudo_warnx(U_("unable to cache gid %u, out of memory"),
	    (unsigned int) gid);
	item->refcnt = 0;
	break;
    }
done:
    if (item->refcnt != 0) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "%s: gid %u [%s] -> group %s [%s] (%s)", __func__,
	    (unsigned int)gid, key.registry,
	    item->d.gr ? item->d.gr->gr_name : "unknown",
	    item->registry, node ? "cache hit" : "cached");
    }
    item->refcnt++;
    debug_return_ptr(item->d.gr);
}

/*
 * Get a group entry by name and allocate space for it.
 */
struct group *
sudo_getgrnam(const char *name)
{
    struct cache_item key, *item;
    struct rbnode *node;
    debug_decl(sudo_getgrnam, SUDOERS_DEBUG_NSS)

    if (grcache_byname == NULL) {
	grcache_byname = rbcreate(cmp_grnam);
	if (grcache_byname == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_ptr(NULL);
	}
    }

    key.k.name = (char *) name;
    getauthregistry(NULL, key.registry);
    if ((node = rbfind(grcache_byname, &key)) != NULL) {
	item = node->data;
	goto done;
    }
    /*
     * Cache group db entry if it exists or a negative response if not.
     */
    item = sudo_make_gritem((gid_t)-1, name);
    if (item == NULL) {
	const size_t len = strlen(name) + 1;
	if (errno != ENOENT || (item = calloc(1, sizeof(*item) + len)) == NULL) {
	    sudo_warnx(U_("unable to cache group %s, out of memory"), name);
	    debug_return_ptr(NULL);
	}
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, name, len);
	/* item->d.gr = NULL; */
    }
    strlcpy(item->registry, key.registry, sizeof(item->registry));
    switch (rbinsert(grcache_byname, item, NULL)) {
    case 1:
	/* should not happen */
	sudo_warnx(U_("unable to cache group %s, already exists"), name);
	item->refcnt = 0;
	break;
    case -1:
	/* can't cache item, just return it */
	sudo_warnx(U_("unable to cache group %s, out of memory"), name);
	item->refcnt = 0;
	break;
    }
done:
    if (item->refcnt != 0) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG,
	    "%s: group %s [%s] -> gid %d [%s] (%s)", __func__, name,
	    key.registry, item->d.gr ? (int)item->d.gr->gr_gid : -1,
	    item->registry, node ? "cache hit" : "cached");
    }
    item->refcnt++;
    debug_return_ptr(item->d.gr);
}

/*
 * Take a gid in string form "#123" and return a faked up group struct.
 */
struct group *
sudo_fakegrnam(const char *group)
{
    struct cache_item_gr *gritem;
    struct cache_item *item;
    const char *errstr;
    struct group *gr;
    size_t len, name_len;
    int i;
    debug_decl(sudo_fakegrnam, SUDOERS_DEBUG_NSS)

    if (grcache_bygid == NULL)
	grcache_bygid = rbcreate(cmp_grgid);
    if (grcache_byname == NULL)
	grcache_byname = rbcreate(cmp_grnam);
    if (grcache_bygid == NULL || grcache_byname == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_ptr(NULL);
    }

    name_len = strlen(group);
    len = sizeof(*gritem) + name_len + 1;

    for (i = 0; i < 2; i++) {
	struct rbtree *grcache;
	struct rbnode *node;

	gritem = calloc(1, len);
	if (gritem == NULL) {
	    sudo_warnx(U_("unable to cache group %s, out of memory"), group);
	    debug_return_ptr(NULL);
	}
	gr = &gritem->gr;
	gr->gr_gid = (gid_t) sudo_strtoid(group + 1, NULL, NULL, &errstr);
	gr->gr_name = (char *)(gritem + 1);
	memcpy(gr->gr_name, group, name_len + 1);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_DIAG|SUDO_DEBUG_LINENO,
		"gid %s %s", group, errstr);
	    free(gritem);
	    debug_return_ptr(NULL);
	}

	item = &gritem->cache;
	item->refcnt = 1;
	item->d.gr = gr;
	if (i == 0) {
	    /* Store by gid if it doesn't already exist. */
	    item->k.gid = gr->gr_gid;
	    grcache = grcache_bygid;
	} else {
	    /* Store by name, overwriting cached version. */
	    gritem->cache.k.name = gr->gr_name;
	    grcache = grcache_byname;
	}
	getauthregistry(NULL, item->registry);
	switch (rbinsert(grcache, item, &node)) {
	case 1:
	    /* Already exists. */
	    item = node->data;
	    if (item->d.gr == NULL) {
		/* Negative cache entry, replace with ours. */
		sudo_gr_delref_item(item);
		item = node->data = &gritem->cache;
	    } else {
		/* Good entry, discard our fake one. */
		free(gritem);
	    }
	    break;
	case -1:
	    /* can't cache item, just return it */
	    sudo_warnx(U_("unable to cache group %s, out of memory"), group);
	    item->refcnt = 0;
	    break;
	}
    }
    item->refcnt++;
    debug_return_ptr(item->d.gr);
}

void
sudo_grlist_addref(struct group_list *grlist)
{
    debug_decl(sudo_gr_addref, SUDOERS_DEBUG_NSS)
    ptr_to_item(grlist)->refcnt++;
    debug_return;
}

static void
sudo_grlist_delref_item(void *v)
{
    struct cache_item *item = v;
    debug_decl(sudo_gr_delref_item, SUDOERS_DEBUG_NSS)

    if (--item->refcnt == 0)
	free(item);

    debug_return;
}

void
sudo_grlist_delref(struct group_list *grlist)
{
    debug_decl(sudo_gr_delref, SUDOERS_DEBUG_NSS)
    sudo_grlist_delref_item(ptr_to_item(grlist));
    debug_return;
}

void
sudo_freegrcache(void)
{
    debug_decl(sudo_freegrcache, SUDOERS_DEBUG_NSS)

    if (grcache_bygid != NULL) {
	rbdestroy(grcache_bygid, sudo_gr_delref_item);
	grcache_bygid = NULL;
    }
    if (grcache_byname != NULL) {
	rbdestroy(grcache_byname, sudo_gr_delref_item);
	grcache_byname = NULL;
    }
    if (grlist_cache != NULL) {
	rbdestroy(grlist_cache, sudo_grlist_delref_item);
	grlist_cache = NULL;
    }

    debug_return;
}

struct group_list *
sudo_get_grlist(const struct passwd *pw)
{
    struct cache_item key, *item;
    struct rbnode *node;
    debug_decl(sudo_get_grlist, SUDOERS_DEBUG_NSS)

    if (grlist_cache == NULL) {
	grlist_cache = rbcreate(cmp_grnam);
	if (grlist_cache == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_ptr(NULL);
	}
    }

    key.k.name = pw->pw_name;
    getauthregistry(pw->pw_name, key.registry);
    if ((node = rbfind(grlist_cache, &key)) != NULL) {
	item = node->data;
	goto done;
    }
    /*
     * Cache group db entry if it exists or a negative response if not.
     */
    item = sudo_make_grlist_item(pw, NULL, NULL);
    if (item == NULL) {
	/* Out of memory? */
	debug_return_ptr(NULL);
    }
    strlcpy(item->registry, key.registry, sizeof(item->registry));
    switch (rbinsert(grlist_cache, item, NULL)) {
    case 1:
	/* should not happen */
	sudo_warnx(U_("unable to cache group list for %s, already exists"),
	    pw->pw_name);
	item->refcnt = 0;
	break;
    case -1:
	/* can't cache item, just return it */
	sudo_warnx(U_("unable to cache group list for %s, out of memory"),
	    pw->pw_name);
	item->refcnt = 0;
	break;
    }
    if (item->d.grlist != NULL) {
	int i;
	for (i = 0; i < item->d.grlist->ngroups; i++) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG,
		"%s: user %s is a member of group %s", __func__,
		pw->pw_name, item->d.grlist->groups[i]);
	}
    }
done:
    item->refcnt++;
    debug_return_ptr(item->d.grlist);
}

int
sudo_set_grlist(struct passwd *pw, char * const *groups, char * const *gids)
{
    struct cache_item key, *item;
    struct rbnode *node;
    debug_decl(sudo_set_grlist, SUDOERS_DEBUG_NSS)

    if (grlist_cache == NULL) {
	grlist_cache = rbcreate(cmp_grnam);
	if (grlist_cache == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    debug_return_int(-1);
	}
    }

    /*
     * Cache group db entry if it doesn't already exist
     */
    key.k.name = pw->pw_name;
    getauthregistry(NULL, key.registry);
    if ((node = rbfind(grlist_cache, &key)) == NULL) {
	if ((item = sudo_make_grlist_item(pw, groups, gids)) == NULL) {
	    sudo_warnx(U_("unable to parse groups for %s"), pw->pw_name);
	    debug_return_int(-1);
	}
	strlcpy(item->registry, key.registry, sizeof(item->registry));
	switch (rbinsert(grlist_cache, item, NULL)) {
	case 1:
	    sudo_warnx(U_("unable to cache group list for %s, already exists"),
		pw->pw_name);
	    sudo_grlist_delref_item(item);
	    break;
	case -1:
	    sudo_warnx(U_("unable to cache group list for %s, out of memory"),
		pw->pw_name);
	    sudo_grlist_delref_item(item);
	    debug_return_int(-1);
	}
    }
    debug_return_int(0);
}

bool
user_in_group(const struct passwd *pw, const char *group)
{
    struct group_list *grlist;
    struct group *grp = NULL;
    const char *errstr;
    int i;
    bool matched = false;
    debug_decl(user_in_group, SUDOERS_DEBUG_NSS)

    if ((grlist = sudo_get_grlist(pw)) != NULL) {
	/*
	 * If it could be a sudo-style group ID check gids first.
	 */
	if (group[0] == '#') {
	    gid_t gid = (gid_t) sudo_strtoid(group + 1, NULL, NULL, &errstr);
	    if (errstr != NULL) {
		sudo_debug_printf(SUDO_DEBUG_DIAG|SUDO_DEBUG_LINENO,
		    "gid %s %s", group, errstr);
	    } else {
		if (gid == pw->pw_gid) {
		    matched = true;
		    goto done;
		}
		for (i = 0; i < grlist->ngids; i++) {
		    if (gid == grlist->gids[i]) {
			matched = true;
			goto done;
		    }
		}
	    }
	}

	/*
	 * Next check the supplementary group vector.
	 * It usually includes the password db group too.
	 */
	for (i = 0; i < grlist->ngroups; i++) {
	    if (strcasecmp(group, grlist->groups[i]) == 0) {
		matched = true;
		goto done;
	    }
	}

	/* Finally check against user's primary (passwd file) group. */
	if ((grp = sudo_getgrgid(pw->pw_gid)) != NULL) {
	    if (strcasecmp(group, grp->gr_name) == 0) {
		matched = true;
		goto done;
	    }
	}
done:
	if (grp != NULL)
	    sudo_gr_delref(grp);
	sudo_grlist_delref(grlist);
    }
    sudo_debug_printf(SUDO_DEBUG_DEBUG, "%s: user %s %sin group %s",
	__func__, pw->pw_name, matched ? "" : "NOT ", group);
    debug_return_bool(matched);
}
