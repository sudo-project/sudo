/*
 * Copyright (c) 1996, 1998-2005, 2007-2011
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
#include <pwd.h>
#include <grp.h>

#include "sudo.h"
#include "redblack.h"

/*
 * The passwd and group caches.
 */
static struct rbtree *pwcache_byuid, *pwcache_byname;
static struct rbtree *grcache_bygid, *grcache_byname;

static int  cmp_pwuid	__P((const void *, const void *));
static int  cmp_pwnam	__P((const void *, const void *));
static int  cmp_grgid	__P((const void *, const void *));

#define cmp_grnam	cmp_pwnam

#ifdef __STDC__
# define ptr_to_item(p) ((struct cache_item *)((char *)p - offsetof(struct cache_item_##p, p)))
#else
# define ptr_to_item(p) ((struct cache_item *)((char *)p - offsetof(struct cache_item_/**/p, p)))
#endif

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

/*
 * Compare by uid.
 */
static int
cmp_pwuid(v1, v2)
    const void *v1;
    const void *v2;
{
    const struct cache_item *ci1 = (const struct cache_item *) v1;
    const struct cache_item *ci2 = (const struct cache_item *) v2;
    return ci1->k.uid - ci2->k.uid;
}

/*
 * Compare by user name.
 */
static int
cmp_pwnam(v1, v2)
    const void *v1;
    const void *v2;
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
make_pwitem(pw, name)
    const struct passwd *pw;
    const char *name;
{
    char *cp;
    const char *pw_shell;
    size_t nsize, psize, csize, gsize, dsize, ssize, total;
    struct cache_item_pw *pwitem;
    struct passwd *newpw;

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

    /*
     * Copy in passwd contents and make strings relative to space
     * at the end of the buffer.
     */
    newpw = &pwitem->pw;
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

    return &pwitem->cache;
}

void
pw_addref(pw)
    struct passwd *pw;
{
    ptr_to_item(pw)->refcnt++;
}

static void
pw_delref_item(v)
    void *v;
{
    struct cache_item *item = v;

    if (--item->refcnt == 0)
	efree(item);
}

void
pw_delref(pw)
    struct passwd *pw;
{
    pw_delref_item(ptr_to_item(pw));
}

/*
 * Get a password entry by uid and allocate space for it.
 */
struct passwd *
sudo_getpwuid(uid)
    uid_t uid;
{
    struct cache_item key, *item;
    struct rbnode *node;

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
	    errorx(1, "unable to cache uid %u (%s), already exists",
		(unsigned int) uid, item->d.pw->pw_name);
    } else {
	item = ecalloc(1, sizeof(*item));
	item->refcnt = 1;
	item->k.uid = uid;
	/* item->d.pw = NULL; */
	if (rbinsert(pwcache_byuid, item) != NULL)
	    errorx(1, "unable to cache uid %u, already exists",
		(unsigned int) uid);
    }
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
done:
    item->refcnt++;
    return item->d.pw;
}

/*
 * Get a password entry by name and allocate space for it.
 */
struct passwd *
sudo_getpwnam(name)
    const char *name;
{
    struct cache_item key, *item;
    struct rbnode *node;
    size_t len;

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
	    errorx(1, "unable to cache user %s, already exists", name);
    } else {
	len = strlen(name) + 1;
	item = ecalloc(1, sizeof(*item) + len);
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, name, len);
	/* item->d.pw = NULL; */
	if (rbinsert(pwcache_byname, item) != NULL)
	    errorx(1, "unable to cache user %s, already exists", name);
    }
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
done:
    item->refcnt++;
    return item->d.pw;
}

static struct passwd *
sudo_fakepwnamid(user, uid, gid)
    const char *user;
    uid_t uid;
    gid_t gid;
{
    struct cache_item_pw *pwitem;
    struct passwd *pw;
    struct rbnode *node;
    size_t len, namelen;
    int i;

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
		pw_delref_item(node->data);
		node->data = &pwitem->cache;
	    }
	} else {
	    /* Store by name, overwriting cached version. */
	    pwitem->cache.k.name = pw->pw_name;
	    if ((node = rbinsert(pwcache_byname, &pwitem->cache)) != NULL) {
		pw_delref_item(node->data);
		node->data = &pwitem->cache;
	    }
	}
    }
    pwitem->cache.refcnt++;
    return pw;
}

/*
 * Take a uid in string form "#123" and return a faked up passwd struct.
 */
struct passwd *
sudo_fakepwnam(user, gid)
    const char *user;
    gid_t gid;
{
    uid_t uid;

    uid = (uid_t) atoi(user + 1);
    return sudo_fakepwnamid(user, uid, gid);
}

/*
 * Take a uid and gid and return a faked up passwd struct.
 */
struct passwd *
sudo_fakepwuid(uid, gid)
    uid_t uid;
    gid_t gid;
{
    char user[MAX_UID_T_LEN + 1];

    (void) snprintf(user, sizeof(user), "#%u", (unsigned int) uid);
    return sudo_fakepwnamid(user, uid, gid);
}

void
sudo_setpwent()
{
    setpwent();
    if (pwcache_byuid == NULL)
	pwcache_byuid = rbcreate(cmp_pwuid);
    if (pwcache_byname == NULL)
	pwcache_byname = rbcreate(cmp_pwnam);
}

void
sudo_freepwcache()
{
    if (pwcache_byuid != NULL) {
	rbdestroy(pwcache_byuid, pw_delref_item);
	pwcache_byuid = NULL;
    }
    if (pwcache_byname != NULL) {
	rbdestroy(pwcache_byname, pw_delref_item);
	pwcache_byname = NULL;
    }
}

void
sudo_endpwent()
{
    endpwent();
    sudo_freepwcache();
}

/*
 * Compare by gid.
 */
static int
cmp_grgid(v1, v2)
    const void *v1;
    const void *v2;
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
make_gritem(gr, name)
    const struct group *gr;
    const char *name;
{
    char *cp;
    size_t nsize, psize, nmem, total, len;
    struct cache_item_gr *gritem;
    struct group *newgr;

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

    return &gritem->cache;
}

void
gr_addref(gr)
    struct group *gr;
{
    ptr_to_item(gr)->refcnt++;
}

static void
gr_delref_item(v)
    void *v;
{
    struct cache_item *item = v;

    if (--item->refcnt == 0)
	efree(item);
}

void
gr_delref(gr)
    struct group *gr;
{
    gr_delref_item(ptr_to_item(gr));
}

/*
 * Get a group entry by gid and allocate space for it.
 */
struct group *
sudo_getgrgid(gid)
    gid_t gid;
{
    struct cache_item key, *item;
    struct rbnode *node;

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
	    errorx(1, "unable to cache gid %u (%s), already exists",
		(unsigned int) gid, key.d.gr->gr_name);
    } else {
	item = ecalloc(1, sizeof(*item));
	item->refcnt = 1;
	item->k.gid = gid;
	/* item->d.gr = NULL; */
	if (rbinsert(grcache_bygid, item) != NULL)
	    errorx(1, "unable to cache gid %u, already exists",
		(unsigned int) gid);
    }
done:
    item->refcnt++;
    return item->d.gr;
}

/*
 * Get a group entry by name and allocate space for it.
 */
struct group *
sudo_getgrnam(name)
    const char *name;
{
    struct cache_item key, *item;
    struct rbnode *node;
    size_t len;

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
	    errorx(1, "unable to cache group %s, already exists", name);
    } else {
	len = strlen(name) + 1;
	item = ecalloc(1, sizeof(*item) + len);
	item->refcnt = 1;
	item->k.name = (char *) item + sizeof(*item);
	memcpy(item->k.name, name, len);
	/* item->d.gr = NULL; */
	if (rbinsert(grcache_byname, item) != NULL)
	    errorx(1, "unable to cache group %s, already exists", name);
    }
done:
    item->refcnt++;
    return item->d.gr;
}

/*
 * Take a gid in string form "#123" and return a faked up group struct.
 */
struct group *
sudo_fakegrnam(group)
    const char *group;
{
    struct cache_item_gr *gritem;
    struct group *gr;
    struct rbnode *node;
    size_t len, namelen;
    int i;

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
		gr_delref_item(node->data);
		node->data = &gritem->cache;
	    }
	} else {
	    /* Store by name, overwriting cached version. */
	    gritem->cache.k.name = gr->gr_name;
	    if ((node = rbinsert(grcache_byname, &gritem->cache)) != NULL) {
		gr_delref_item(node->data);
		node->data = &gritem->cache;
	    }
	}
    }
    gritem->cache.refcnt++;
    return gr;
}

void
sudo_setgrent()
{
    setgrent();
    if (grcache_bygid == NULL)
	grcache_bygid = rbcreate(cmp_grgid);
    if (grcache_byname == NULL)
	grcache_byname = rbcreate(cmp_grnam);
}

void
sudo_freegrcache()
{
    if (grcache_bygid != NULL) {
	rbdestroy(grcache_bygid, gr_delref_item);
	grcache_bygid = NULL;
    }
    if (grcache_byname != NULL) {
	rbdestroy(grcache_byname, gr_delref_item);
	grcache_byname = NULL;
    }
}

void
sudo_endgrent()
{
    endgrent();
    sudo_freegrcache();
}

int
user_in_group(pw, group)
    struct passwd *pw;
    const char *group;
{
#ifdef HAVE_MBR_CHECK_MEMBERSHIP
    uuid_t gu, uu;
    int ismember;
#else
    char **gr_mem;
    int i;
#endif
    struct group *grp;
    int retval = FALSE;

#ifdef HAVE_SETAUTHDB
    aix_setauthdb(pw->pw_name);
#endif
    /* A group name that begins with a '#' may be a gid. */
    if ((grp = sudo_getgrnam(group)) == NULL && *group == '#')
	grp = sudo_getgrgid(atoi(group + 1));
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
    if (grp == NULL)
	goto done;

    /* check against user's primary (passwd file) gid */
    if (grp->gr_gid == pw->pw_gid) {
	retval = TRUE;
	goto done;
    }

#ifdef HAVE_MBR_CHECK_MEMBERSHIP
    /* If we are matching the invoking user use the stashed uuid. */
    if (strcmp(pw->pw_name, user_name) == 0) {
	if (mbr_gid_to_uuid(grp->gr_gid, gu) == 0 &&
	    mbr_check_membership(user_uuid, gu, &ismember) == 0 && ismember) {
	    retval = TRUE;
	    goto done;
	}
    } else {
	if (mbr_uid_to_uuid(pw->pw_uid, uu) == 0 &&
	    mbr_gid_to_uuid(grp->gr_gid, gu) == 0 &&
	    mbr_check_membership(uu, gu, &ismember) == 0 && ismember) {
	    retval = TRUE;
	    goto done;
	}
    }
#else /* HAVE_MBR_CHECK_MEMBERSHIP */
# ifdef HAVE_GETGROUPS
    /*
     * If we are matching the invoking or list user and that user has a
     * supplementary group vector, check it.
     */
    if (user_ngroups > 0 &&
	strcmp(pw->pw_name, list_pw ? list_pw->pw_name : user_name) == 0) {
	for (i = 0; i < user_ngroups; i++) {
	    if (grp->gr_gid == user_groups[i]) {
		retval = TRUE;
		goto done;
	    }
	}
    } else
# endif /* HAVE_GETGROUPS */
    {
	if (grp != NULL && grp->gr_mem != NULL) {
	    for (gr_mem = grp->gr_mem; *gr_mem; gr_mem++) {
		if (strcmp(*gr_mem, pw->pw_name) == 0) {
		    retval = TRUE;
		    goto done;
		}
	    }
	}
    }
#endif /* HAVE_MBR_CHECK_MEMBERSHIP */

done:
    if (grp != NULL)
	gr_delref(grp);
    return retval;
}
