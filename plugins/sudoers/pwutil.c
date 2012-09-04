/*
 * Copyright (c) 1996, 1998-2005, 2007-2012
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
#include <sys/stat.h>
#include <sys/param.h>
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
#ifdef HAVE_UTMPX_H
# include <utmpx.h>
#else
# include <utmp.h>
#endif /* HAVE_UTMPX_H */
#include <limits.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "redblack.h"

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

#define ptr_to_item(p) ((struct cache_item *)((char *)p - offsetof(struct cache_item_##p, p)))

/*
 * Generic cache element.
 */
struct cache_item {
    unsigned int refcnt;
    /* key */
    union {
	uid_t uid;
	gid_t gid;
	char *name;
    } k;
    /* datum */
    union {
	struct passwd *pw;
	struct group *gr;
	struct group_list *grlist;
    } d;
};

/*
 * Container structs to simpify size and offset calculations and guarantee
 * proper aligment of struct passwd, group and group_list.
 */
struct cache_item_pw {
    struct cache_item cache;
    struct passwd pw;
};

struct cache_item_gr {
    struct cache_item cache;
    struct group gr;
};

struct cache_item_grlist {
    struct cache_item cache;
    struct group_list grlist;
    /* actually bigger */
};

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

#define FIELD_SIZE(src, name, size)			\
do {							\
	if (src->name) {				\
		size = strlen(src->name) + 1;		\
		total += size;				\
	}                                               \
} while (0)

#define FIELD_COPY(src, dst, name, size)		\
do {							\
	if (src->name) {				\
		memcpy(cp, src->name, size);		\
		dst->name = cp;				\
		cp += size;				\
	}						\
} while (0)

/*
 * Dynamically allocate space for a struct item plus the key and data
 * elements.  If name is non-NULL it is used as the key, else the
 * uid is the key.  Fills in datum from struct password.
 */
static struct cache_item *
make_pwitem(const struct passwd *pw, const char *name)
{
    char *cp;
    const char *pw_shell;
    size_t nsize, psize, csize, gsize, dsize, ssize, total;
    struct cache_item_pw *pwitem;
    struct passwd *newpw;
    debug_decl(make_pwitem, SUDO_DEBUG_NSS)

    /* If shell field is empty, expand to _PATH_BSHELL. */
    pw_shell = (pw->pw_shell == NULL || pw->pw_shell[0] == '\0')
	? _PATH_BSHELL : pw->pw_shell;

    /* Allocate in one big chunk for easy freeing. */
    nsize = psize = csize = gsize = dsize = ssize = 0;
    total = sizeof(*pwitem);
    FIELD_SIZE(pw, pw_name, nsize);
    FIELD_SIZE(pw, pw_passwd, psize);
#ifdef HAVE_LOGIN_CAP_H
    FIELD_SIZE(pw, pw_class, csize);
#endif
    FIELD_SIZE(pw, pw_gecos, gsize);
    FIELD_SIZE(pw, pw_dir, dsize);
    /* Treat shell specially since we expand "" -> _PATH_BSHELL */
    ssize = strlen(pw_shell) + 1;
    total += ssize;
    if (name != NULL)
	total += strlen(name) + 1;

    /* Allocate space for struct item, struct passwd and the strings. */
    pwitem = ecalloc(1, total);
    newpw = &pwitem->pw;

    /*
     * Copy in passwd contents and make strings relative to space
     * at the end of the struct.
     */
    memcpy(newpw, pw, sizeof(*pw));
    cp = (char *)(pwitem + 1);
    FIELD_COPY(pw, newpw, pw_name, nsize);
    FIELD_COPY(pw, newpw, pw_passwd, psize);
#ifdef HAVE_LOGIN_CAP_H
    FIELD_COPY(pw, newpw, pw_class, csize);
#endif
    FIELD_COPY(pw, newpw, pw_gecos, gsize);
    FIELD_COPY(pw, newpw, pw_dir, dsize);
    /* Treat shell specially since we expand "" -> _PATH_BSHELL */
    memcpy(cp, pw_shell, ssize);
    newpw->pw_shell = cp;
    cp += ssize;

    /* Set key and datum. */
    if (name != NULL) {
	memcpy(cp, name, strlen(name) + 1);
	pwitem->cache.k.name = cp;
    } else {
	pwitem->cache.k.uid = pw->pw_uid;
    }
    pwitem->cache.d.pw = newpw;
    pwitem->cache.refcnt = 1;

    debug_return_ptr(&pwitem->cache);
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
    if ((key.d.pw = getpwuid(uid)) != NULL) {
	item = make_pwitem(key.d.pw, NULL);
	if (rbinsert(pwcache_byuid, item) != NULL)
	    errorx(1, _("unable to cache uid %u (%s), already exists"),
		(unsigned int) uid, item->d.pw->pw_name);
    } else {
	item = ecalloc(1, sizeof(*item));
	item->refcnt = 1;
	item->k.uid = uid;
	/* item->d.pw = NULL; */
	if (rbinsert(pwcache_byuid, item) != NULL)
	    errorx(1, _("unable to cache uid %u, already exists"),
		(unsigned int) uid);
    }
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
    if ((key.d.pw = getpwnam(name)) != NULL) {
	item = make_pwitem(key.d.pw, name);
	if (rbinsert(pwcache_byname, item) != NULL)
	    errorx(1, _("unable to cache user %s, already exists"), name);
    } else {
	len = strlen(name) + 1;
	item = ecalloc(1, sizeof(*item) + len);
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, name, len);
	/* item->d.pw = NULL; */
	if (rbinsert(pwcache_byname, item) != NULL)
	    errorx(1, _("unable to cache user %s, already exists"), name);
    }
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
done:
    item->refcnt++;
    debug_return_ptr(item->d.pw);
}

/*
 * Take a user, uid and gid and return a faked up passwd struct.
 */
struct passwd *
sudo_fakepwnamid(const char *user, uid_t uid, gid_t gid)
{
    struct cache_item_pw *pwitem;
    struct passwd *pw;
    struct rbnode *node;
    size_t len, namelen;
    int i;
    debug_decl(sudo_fakepwnam, SUDO_DEBUG_NSS)

    namelen = strlen(user);
    len = sizeof(*pwitem) + namelen + 1 /* pw_name */ +
	sizeof("*") /* pw_passwd */ + sizeof("") /* pw_gecos */ +
	sizeof("/") /* pw_dir */ + sizeof(_PATH_BSHELL);

    for (i = 0; i < 2; i++) {
	pwitem = ecalloc(1, len);
	pw = &pwitem->pw;
	pw->pw_uid = uid;
	pw->pw_gid = gid;
	pw->pw_name = (char *)(pwitem + 1);
	memcpy(pw->pw_name, user, namelen + 1);
	pw->pw_passwd = pw->pw_name + namelen + 1;
	memcpy(pw->pw_passwd, "*", 2);
	pw->pw_gecos = pw->pw_passwd + 2;
	pw->pw_gecos[0] = '\0';
	pw->pw_dir = pw->pw_gecos + 1;
	memcpy(pw->pw_dir, "/", 2);
	pw->pw_shell = pw->pw_dir + 2;
	memcpy(pw->pw_shell, _PATH_BSHELL, sizeof(_PATH_BSHELL));

	pwitem->cache.refcnt = 1;
	pwitem->cache.d.pw = pw;
	if (i == 0) {
	    /* Store by uid, overwriting cached version. */
	    pwitem->cache.k.uid = pw->pw_uid;
	    if ((node = rbinsert(pwcache_byuid, &pwitem->cache)) != NULL) {
		sudo_pw_delref_item(node->data);
		node->data = &pwitem->cache;
	    }
	} else {
	    /* Store by name, overwriting cached version. */
	    pwitem->cache.k.name = pw->pw_name;
	    if ((node = rbinsert(pwcache_byname, &pwitem->cache)) != NULL) {
		sudo_pw_delref_item(node->data);
		node->data = &pwitem->cache;
	    }
	}
    }
    pwitem->cache.refcnt++;
    debug_return_ptr(pw);
}

/*
 * Take a uid in string form "#123" and return a faked up passwd struct.
 */
struct passwd *
sudo_fakepwnam(const char *user, gid_t gid)
{
    uid_t uid;

    uid = (uid_t) atoi(user + 1);
    return sudo_fakepwnamid(user, uid, gid);
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

/*
 * Dynamically allocate space for a struct item plus the key and data
 * elements.  If name is non-NULL it is used as the key, else the
 * gid is the key.  Fills in datum from struct group.
 */
static struct cache_item *
make_gritem(const struct group *gr, const char *name)
{
    char *cp;
    size_t nsize, psize, nmem, total, len;
    struct cache_item_gr *gritem;
    struct group *newgr;
    debug_decl(make_gritem, SUDO_DEBUG_NSS)

    /* Allocate in one big chunk for easy freeing. */
    nsize = psize = nmem = 0;
    total = sizeof(*gritem);
    FIELD_SIZE(gr, gr_name, nsize);
    FIELD_SIZE(gr, gr_passwd, psize);
    if (gr->gr_mem) {
	for (nmem = 0; gr->gr_mem[nmem] != NULL; nmem++)
	    total += strlen(gr->gr_mem[nmem]) + 1;
	nmem++;
	total += sizeof(char *) * nmem;
    }
    if (name != NULL)
	total += strlen(name) + 1;

    gritem = ecalloc(1, total);

    /*
     * Copy in group contents and make strings relative to space
     * at the end of the buffer.  Note that gr_mem must come
     * immediately after struct group to guarantee proper alignment.
     */
    newgr = &gritem->gr;
    memcpy(newgr, gr, sizeof(*gr));
    cp = (char *)(gritem + 1);
    if (gr->gr_mem) {
	newgr->gr_mem = (char **)cp;
	cp += sizeof(char *) * nmem;
	for (nmem = 0; gr->gr_mem[nmem] != NULL; nmem++) {
	    len = strlen(gr->gr_mem[nmem]) + 1;
	    memcpy(cp, gr->gr_mem[nmem], len);
	    newgr->gr_mem[nmem] = cp;
	    cp += len;
	}
	newgr->gr_mem[nmem] = NULL;
    }
    FIELD_COPY(gr, newgr, gr_passwd, psize);
    FIELD_COPY(gr, newgr, gr_name, nsize);

    /* Set key and datum. */
    if (name != NULL) {
	memcpy(cp, name, strlen(name) + 1);
	gritem->cache.k.name = cp;
    } else {
	gritem->cache.k.gid = gr->gr_gid;
    }
    gritem->cache.d.gr = newgr;
    gritem->cache.refcnt = 1;

    debug_return_ptr(&gritem->cache);
}

#ifdef HAVE_UTMPX_H
# define GROUPNAME_LEN	(sizeof((struct utmpx *)0)->ut_user + 1)
#else
# ifdef HAVE_STRUCT_UTMP_UT_USER
#  define GROUPNAME_LEN	(sizeof((struct utmp *)0)->ut_user + 1)
# else
#  define GROUPNAME_LEN	(sizeof((struct utmp *)0)->ut_name + 1)
# endif
#endif /* HAVE_UTMPX_H */

/*
 * Dynamically allocate space for a struct item plus the key and data
 * elements.  Fills in datum from the groups and gids arrays.
 */
static struct cache_item *
make_grlist_item(const char *user, GETGROUPS_T *gids, int ngids)
{
    char *cp;
    size_t i, nsize, ngroups, total, len;
    struct cache_item_grlist *grlitem;
    struct group_list *grlist;
    struct group *grp;
    debug_decl(make_grlist_item, SUDO_DEBUG_NSS)

#ifdef HAVE_SETAUTHDB
    aix_setauthdb((char *) user);
#endif

    /* Allocate in one big chunk for easy freeing. */
    nsize = strlen(user) + 1;
    total = sizeof(*grlitem) + nsize;
    total += sizeof(char *) * ngids;
    total += sizeof(gid_t *) * ngids;
    total += GROUPNAME_LEN * ngids;

again:
    grlitem = ecalloc(1, total);

    /*
     * Copy in group list and make pointers relative to space
     * at the end of the buffer.  Note that the groups array must come
     * immediately after struct group to guarantee proper alignment.
     */
    grlist = &grlitem->grlist;
    cp = (char *)(grlitem + 1);
    grlist->groups = (char **)cp;
    cp += sizeof(char *) * ngids;
    grlist->gids = (gid_t *)cp;
    cp += sizeof(gid_t) * ngids;

    /* Set key and datum. */
    memcpy(cp, user, nsize);
    grlitem->cache.k.name = cp;
    grlitem->cache.d.grlist = grlist;
    grlitem->cache.refcnt = 1;
    cp += nsize;

    /*
     * Store group IDs.
     */
    for (i = 0; i < ngids; i++)
	grlist->gids[i] = gids[i];
    grlist->ngids = ngids;

    /*
     * Resolve and store group names by ID.
     */
    ngroups = 0;
    for (i = 0; i < ngids; i++) {
	if ((grp = sudo_getgrgid(gids[i])) != NULL) {
	    len = strlen(grp->gr_name) + 1;
	    if (cp - (char *)grlitem + len > total) {
		total += len + GROUPNAME_LEN;
		efree(grlitem);
		sudo_gr_delref(grp);
		goto again;
	    }
	    memcpy(cp, grp->gr_name, len);
	    grlist->groups[ngroups++] = cp;
	    cp += len;
	    sudo_gr_delref(grp);
	}
    }
    grlist->ngroups = ngroups;

#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif

    debug_return_ptr(&grlitem->cache);
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
    if ((key.d.gr = getgrgid(gid)) != NULL) {
	item = make_gritem(key.d.gr, NULL);
	if (rbinsert(grcache_bygid, item) != NULL)
	    errorx(1, _("unable to cache gid %u (%s), already exists"),
		(unsigned int) gid, key.d.gr->gr_name);
    } else {
	item = ecalloc(1, sizeof(*item));
	item->refcnt = 1;
	item->k.gid = gid;
	/* item->d.gr = NULL; */
	if (rbinsert(grcache_bygid, item) != NULL)
	    errorx(1, _("unable to cache gid %u, already exists"),
		(unsigned int) gid);
    }
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
    if ((key.d.gr = getgrnam(name)) != NULL) {
	item = make_gritem(key.d.gr, name);
	if (rbinsert(grcache_byname, item) != NULL)
	    errorx(1, _("unable to cache group %s, already exists"), name);
    } else {
	len = strlen(name) + 1;
	item = ecalloc(1, sizeof(*item) + len);
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, name, len);
	/* item->d.gr = NULL; */
	if (rbinsert(grcache_byname, item) != NULL)
	    errorx(1, _("unable to cache group %s, already exists"), name);
    }
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
    struct group *gr;
    struct rbnode *node;
    size_t len, namelen;
    int i;
    debug_decl(sudo_fakegrnam, SUDO_DEBUG_NSS)

    namelen = strlen(group);
    len = sizeof(*gritem) + namelen + 1;

    for (i = 0; i < 2; i++) {
	gritem = ecalloc(1, len);
	gr = &gritem->gr;
	gr->gr_gid = (gid_t) atoi(group + 1);
	gr->gr_name = (char *)(gritem + 1);
	memcpy(gr->gr_name, group, namelen + 1);

	gritem->cache.refcnt = 1;
	gritem->cache.d.gr = gr;
	if (i == 0) {
	    /* Store by gid, overwriting cached version. */
	    gritem->cache.k.gid = gr->gr_gid;
	    if ((node = rbinsert(grcache_bygid, &gritem->cache)) != NULL) {
		sudo_gr_delref_item(node->data);
		node->data = &gritem->cache;
	    }
	} else {
	    /* Store by name, overwriting cached version. */
	    gritem->cache.k.name = gr->gr_name;
	    if ((node = rbinsert(grcache_byname, &gritem->cache)) != NULL) {
		sudo_gr_delref_item(node->data);
		node->data = &gritem->cache;
	    }
	}
    }
    gritem->cache.refcnt++;
    debug_return_ptr(gr);
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
sudo_get_grlist(struct passwd *pw)
{
    struct cache_item key, *item;
    struct rbnode *node;
    size_t len;
    GETGROUPS_T *gids;
    int ngids;
    debug_decl(sudo_get_grlist, SUDO_DEBUG_NSS)

    key.k.name = pw->pw_name;
    if ((node = rbfind(grlist_cache, &key)) != NULL) {
	item = (struct cache_item *) node->data;
	goto done;
    }
    /*
     * Cache group db entry if it exists or a negative response if not.
     * Use gids list from front-end if possible, otherwise getgrouplist().
     */
    if (pw == sudo_user.pw && sudo_user.gids != NULL) {
	gids = user_gids;
	ngids = user_ngids;
	user_gids = NULL;
	user_ngids = 0;
    } else {
#if defined(HAVE_SYSCONF) && defined(_SC_NGROUPS_MAX)
	ngids = (int)sysconf(_SC_NGROUPS_MAX) * 2;
	if (ngids < 0)
#endif
	    ngids = NGROUPS_MAX * 2;
	gids = emalloc2(ngids, sizeof(GETGROUPS_T));
	if (getgrouplist(pw->pw_name, pw->pw_gid, gids, &ngids) == -1) {
	    efree(gids);
	    gids = emalloc2(ngids, sizeof(GETGROUPS_T));
	    if (getgrouplist(pw->pw_name, pw->pw_gid, gids, &ngids) == -1) {
		efree(gids);
		debug_return_ptr(NULL);
	    }
	}
    }
    if (ngids > 0) {
	if ((item = make_grlist_item(pw->pw_name, gids, ngids)) == NULL)
	    errorx(1, "unable to parse group list for %s", pw->pw_name);
	efree(gids);
	if (rbinsert(grlist_cache, item) != NULL)
	    errorx(1, "unable to cache group list for %s, already exists",
		pw->pw_name);
    } else {
	/* Should not happen. */
	len = strlen(pw->pw_name) + 1;
	item = ecalloc(1, sizeof(*item) + len);
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, pw->pw_name, len);
	/* item->d.grlist = NULL; */
	if (rbinsert(grlist_cache, item) != NULL)
	    errorx(1, "unable to cache group list for %s, already exists",
		pw->pw_name);
    }
done:
    item->refcnt++;
    debug_return_ptr(item->d.grlist);
}

bool
user_in_group(struct passwd *pw, const char *group)
{
    struct group_list *grlist;
    struct group *grp = NULL;
    int i;
    bool matched = false;
    debug_decl(user_in_group, SUDO_DEBUG_NSS)

    if ((grlist = sudo_get_grlist(pw)) != NULL) {
	/*
	 * If it could be a sudo-style group ID check gids first.
	 */
	if (group[0] == '#') {
	    gid_t gid = atoi(group + 1);
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
