/*
 * Copyright (c) 1996, 1998-2005, 2007-2013
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
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STRING_H
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_SETAUTHDB
# include <usersec.h>
#endif /* HAVE_SETAUTHDB */
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
 * Compare by uid.
 */
static int
cmp_pwuid(const void *v1, const void *v2)
{
    const struct cache_item *ci1 = (const struct cache_item *) v1;
    const struct cache_item *ci2 = (const struct cache_item *) v2;
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
    return strcmp(ci1->k.name, ci2->k.name);
}

void
sudo_pw_addref(struct passwd *pw)
{
    debug_decl(sudo_pw_addref, SUDO_DEBUG_NSS)
    ptr_to_item(pw)->refcnt++;
    debug_return;
}

static void
sudo_pw_delref_item(void *v)
{
    struct cache_item *item = v;
    debug_decl(sudo_pw_delref_item, SUDO_DEBUG_NSS)

    if (--item->refcnt == 0)
	efree(item);

    debug_return;
}

void
sudo_pw_delref(struct passwd *pw)
{
    debug_decl(sudo_pw_delref, SUDO_DEBUG_NSS)
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
    debug_decl(sudo_getpwuid, SUDO_DEBUG_NSS)

    key.k.uid = uid;
    if ((node = rbfind(pwcache_byuid, &key)) != NULL) {
	item = (struct cache_item *) node->data;
	goto done;
    }
    /*
     * Cache passwd db entry if it exists or a negative response if not.
     */
#ifdef HAVE_SETAUTHDB
    aix_setauthdb(IDtouser(uid));
#endif
    item = sudo_make_pwitem(uid, NULL);
    if (item == NULL) {
	item = ecalloc(1, sizeof(*item));
	item->refcnt = 1;
	item->k.uid = uid;
	/* item->d.pw = NULL; */
    }
    if (rbinsert(pwcache_byuid, item) != NULL)
	fatalx(U_("unable to cache uid %u, already exists"),
	    (unsigned int) uid);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
done:
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
    size_t len;
    debug_decl(sudo_getpwnam, SUDO_DEBUG_NSS)

    key.k.name = (char *) name;
    if ((node = rbfind(pwcache_byname, &key)) != NULL) {
	item = (struct cache_item *) node->data;
	goto done;
    }
    /*
     * Cache passwd db entry if it exists or a negative response if not.
     */
#ifdef HAVE_SETAUTHDB
    aix_setauthdb((char *) name);
#endif
    item = sudo_make_pwitem((uid_t)-1, name);
    if (item == NULL) {
	len = strlen(name) + 1;
	item = ecalloc(1, sizeof(*item) + len);
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, name, len);
	/* item->d.pw = NULL; */
    }
    if (rbinsert(pwcache_byname, item) != NULL)
	fatalx(U_("unable to cache user %s, already exists"), name);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
done:
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
    struct passwd *pw;
    struct rbnode *node;
    size_t len, name_len, home_len, shell_len;
    int i;
    debug_decl(sudo_mkpwent, SUDO_DEBUG_NSS)

    /* Optional arguments. */
    if (home == NULL)
	home = "/";
    if (shell == NULL)
	shell = _PATH_BSHELL;

    name_len = strlen(user);
    home_len = strlen(home);
    shell_len = strlen(shell);
    len = sizeof(*pwitem) + name_len + 1 /* pw_name */ +
	sizeof("*") /* pw_passwd */ + sizeof("") /* pw_gecos */ +
	home_len + 1 /* pw_dir */ + shell_len + 1 /* pw_shell */;

    for (i = 0; i < 2; i++) {
	pwitem = ecalloc(1, len);
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

	pwitem->cache.refcnt = 1;
	pwitem->cache.d.pw = pw;
	if (i == 0) {
	    /* Store by uid if it doesn't already exist. */
	    pwitem->cache.k.uid = pw->pw_uid;
	    if ((node = rbinsert(pwcache_byuid, &pwitem->cache)) != NULL) {
		/* Already exists, free the item we created. */
		efree(pwitem);
		pwitem = (struct cache_item_pw *) node->data;
	    }
	} else {
	    /* Store by name if it doesn't already exist. */
	    pwitem->cache.k.name = pw->pw_name;
	    if ((node = rbinsert(pwcache_byname, &pwitem->cache)) != NULL) {
		/* Already exists, free the item we created. */
		efree(pwitem);
		pwitem = (struct cache_item_pw *) node->data;
	    }
	}
    }
    pwitem->cache.refcnt++;
    debug_return_ptr(&pwitem->pw);
}

/*
 * Take a uid in string form "#123" and return a faked up passwd struct.
 */
struct passwd *
sudo_fakepwnam(const char *user, gid_t gid)
{
    const char *errstr;
    uid_t uid;
    debug_decl(sudo_fakepwnam, SUDO_DEBUG_NSS)

    uid = (uid_t) atoid(user + 1, NULL, NULL, &errstr);
    if (errstr != NULL) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_DIAG,
	    "uid %s %s", user, errstr);
	debug_return_ptr(NULL);
    }
    debug_return_ptr(sudo_mkpwent(user, uid, gid, NULL, NULL));
}

void
sudo_setpwent(void)
{
    debug_decl(sudo_setpwent, SUDO_DEBUG_NSS)

    setpwent();
    if (pwcache_byuid == NULL)
	pwcache_byuid = rbcreate(cmp_pwuid);
    if (pwcache_byname == NULL)
	pwcache_byname = rbcreate(cmp_pwnam);

    debug_return;
}

void
sudo_freepwcache(void)
{
    debug_decl(sudo_freepwcache, SUDO_DEBUG_NSS)

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

void
sudo_endpwent(void)
{
    debug_decl(sudo_endpwent, SUDO_DEBUG_NSS)

    endpwent();
    sudo_freepwcache();

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
    return ci1->k.gid - ci2->k.gid;
}

void
sudo_gr_addref(struct group *gr)
{
    debug_decl(sudo_gr_addref, SUDO_DEBUG_NSS)
    ptr_to_item(gr)->refcnt++;
    debug_return;
}

static void
sudo_gr_delref_item(void *v)
{
    struct cache_item *item = v;
    debug_decl(sudo_gr_delref_item, SUDO_DEBUG_NSS)

    if (--item->refcnt == 0)
	efree(item);

    debug_return;
}

void
sudo_gr_delref(struct group *gr)
{
    debug_decl(sudo_gr_delref, SUDO_DEBUG_NSS)
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
    debug_decl(sudo_getgrgid, SUDO_DEBUG_NSS)

    key.k.gid = gid;
    if ((node = rbfind(grcache_bygid, &key)) != NULL) {
	item = (struct cache_item *) node->data;
	goto done;
    }
    /*
     * Cache group db entry if it exists or a negative response if not.
     */
    item = sudo_make_gritem(gid, NULL);
    if (item == NULL) {
	item = ecalloc(1, sizeof(*item));
	item->refcnt = 1;
	item->k.gid = gid;
	/* item->d.gr = NULL; */
    }
    if (rbinsert(grcache_bygid, item) != NULL)
	fatalx(U_("unable to cache gid %u, already exists"),
	    (unsigned int) gid);
done:
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
    size_t len;
    debug_decl(sudo_getgrnam, SUDO_DEBUG_NSS)

    key.k.name = (char *) name;
    if ((node = rbfind(grcache_byname, &key)) != NULL) {
	item = (struct cache_item *) node->data;
	goto done;
    }
    /*
     * Cache group db entry if it exists or a negative response if not.
     */
    item = sudo_make_gritem((gid_t)-1, name);
    if (item == NULL) {
	len = strlen(name) + 1;
	item = ecalloc(1, sizeof(*item) + len);
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, name, len);
	/* item->d.gr = NULL; */
    }
    if (rbinsert(grcache_byname, item) != NULL)
	fatalx(U_("unable to cache group %s, already exists"), name);
done:
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
    const char *errstr;
    struct group *gr;
    struct rbnode *node;
    size_t len, name_len;
    int i;
    debug_decl(sudo_fakegrnam, SUDO_DEBUG_NSS)

    name_len = strlen(group);
    len = sizeof(*gritem) + name_len + 1;

    for (i = 0; i < 2; i++) {
	gritem = ecalloc(1, len);
	gr = &gritem->gr;
	gr->gr_gid = (gid_t) atoid(group + 1, NULL, NULL, &errstr);
	gr->gr_name = (char *)(gritem + 1);
	memcpy(gr->gr_name, group, name_len + 1);
	if (errstr != NULL) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_DIAG,
		"gid %s %s", group, errstr);
	    efree(gritem);
	    debug_return_ptr(NULL);
	}

	gritem->cache.refcnt = 1;
	gritem->cache.d.gr = gr;
	if (i == 0) {
	    /* Store by gid if it doesn't already exist. */
	    gritem->cache.k.gid = gr->gr_gid;
	    if ((node = rbinsert(grcache_bygid, &gritem->cache)) != NULL) {
		/* Already exists, free the item we created. */
		efree(gritem);
		gritem = (struct cache_item_gr *) node->data;
	    }
	} else {
	    /* Store by name, overwriting cached version. */
	    gritem->cache.k.name = gr->gr_name;
	    if ((node = rbinsert(grcache_byname, &gritem->cache)) != NULL) {
		/* Already exists, free the item we created. */
		efree(gritem);
		gritem = (struct cache_item_gr *) node->data;
	    }
	}
    }
    gritem->cache.refcnt++;
    debug_return_ptr(&gritem->gr);
}

void
sudo_grlist_addref(struct group_list *grlist)
{
    debug_decl(sudo_gr_addref, SUDO_DEBUG_NSS)
    ptr_to_item(grlist)->refcnt++;
    debug_return;
}

static void
sudo_grlist_delref_item(void *v)
{
    struct cache_item *item = v;
    debug_decl(sudo_gr_delref_item, SUDO_DEBUG_NSS)

    if (--item->refcnt == 0)
	efree(item);

    debug_return;
}

void
sudo_grlist_delref(struct group_list *grlist)
{
    debug_decl(sudo_gr_delref, SUDO_DEBUG_NSS)
    sudo_grlist_delref_item(ptr_to_item(grlist));
    debug_return;
}

void
sudo_setgrent(void)
{
    debug_decl(sudo_setgrent, SUDO_DEBUG_NSS)

    setgrent();
    if (grcache_bygid == NULL)
	grcache_bygid = rbcreate(cmp_grgid);
    if (grcache_byname == NULL)
	grcache_byname = rbcreate(cmp_grnam);
    if (grlist_cache == NULL)
	grlist_cache = rbcreate(cmp_grnam);

    debug_return;
}

void
sudo_freegrcache(void)
{
    debug_decl(sudo_freegrcache, SUDO_DEBUG_NSS)

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

void
sudo_endgrent(void)
{
    debug_decl(sudo_endgrent, SUDO_DEBUG_NSS)

    endgrent();
    sudo_freegrcache();

    debug_return;
}

struct group_list *
sudo_get_grlist(const struct passwd *pw)
{
    struct cache_item key, *item;
    struct rbnode *node;
    size_t len;
    debug_decl(sudo_get_grlist, SUDO_DEBUG_NSS)

    key.k.name = pw->pw_name;
    if ((node = rbfind(grlist_cache, &key)) != NULL) {
	item = (struct cache_item *) node->data;
	goto done;
    }
    /*
     * Cache group db entry if it exists or a negative response if not.
     */
    item = sudo_make_grlist_item(pw, NULL, NULL);
    if (item == NULL) {
	/* Should not happen. */
	len = strlen(pw->pw_name) + 1;
	item = ecalloc(1, sizeof(*item) + len);
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, pw->pw_name, len);
	/* item->d.grlist = NULL; */
    }
    if (rbinsert(grlist_cache, item) != NULL)
	fatalx(U_("unable to cache group list for %s, already exists"),
	    pw->pw_name);
done:
    item->refcnt++;
    debug_return_ptr(item->d.grlist);
}

void
sudo_set_grlist(struct passwd *pw, char * const *groups, char * const *gids)
{
    struct cache_item key, *item;
    struct rbnode *node;
    debug_decl(sudo_set_grlist, SUDO_DEBUG_NSS)

    /*
     * Cache group db entry if it doesn't already exist
     */
    key.k.name = pw->pw_name;
    if ((node = rbfind(grlist_cache, &key)) == NULL) {
	if ((item = sudo_make_grlist_item(pw, groups, gids)) == NULL)
	    fatalx(U_("unable to parse groups for %s"), pw->pw_name);
	if (rbinsert(grlist_cache, item) != NULL)
	    fatalx(U_("unable to cache group list for %s, already exists"),
		pw->pw_name);
    }
    debug_return;
}

bool
user_in_group(const struct passwd *pw, const char *group)
{
    struct group_list *grlist;
    struct group *grp = NULL;
    const char *errstr;
    int i;
    bool matched = false;
    debug_decl(user_in_group, SUDO_DEBUG_NSS)

    if ((grlist = sudo_get_grlist(pw)) != NULL) {
	/*
	 * If it could be a sudo-style group ID check gids first.
	 */
	if (group[0] == '#') {
	    gid_t gid = (gid_t) atoid(group + 1, NULL, NULL, &errstr);
	    if (errstr != NULL) {
		sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_DIAG,
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
    debug_return_bool(matched);
}
