/*
 * Copyright (c) 1996, 1998-2005 Todd C. Miller <Todd.Miller@courtesan.com>
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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <pwd.h>
#include <grp.h>

#include "sudo.h"
#include "redblack.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * The passwd and group caches.
 */
static struct rbtree *pwcache_byuid, *pwcache_byname;
static struct rbtree *grcache_bygid, *grcache_byname;

static int  cmp_pwuid		__P((const VOID *, const VOID *));
static int  cmp_pwnam		__P((const VOID *, const VOID *));
static int  cmp_grgid		__P((const VOID *, const VOID *));
static int  cmp_grnam		__P((const VOID *, const VOID *));
static void pw_free		__P((VOID *));
       VOID *pwcache_get	__P((enum cmptype, VOID *));
       int  pwcache_put		__P((enum cmptype, VOID *));

void
pwcache_init()
{
    pwcache_byuid = rbcreate(cmp_pwuid);
    pwcache_byname = rbcreate(cmp_pwnam);
    grcache_bygid = rbcreate(cmp_grgid);
    grcache_byname = rbcreate(cmp_grnam);
}

void
pwcache_destroy()
{
    if (pwcache_byuid) {
	rbdestroy(pwcache_byuid, pw_free);
	pwcache_byuid = NULL;
    }
    if (pwcache_byname) {
	rbdestroy(pwcache_byname, NULL);
	pwcache_byname = NULL;
    }
    if (grcache_bygid) {
	rbdestroy(grcache_bygid, free);
	grcache_bygid = NULL;
    }
    if (grcache_byname) {
	rbdestroy(grcache_byname, NULL);
	grcache_byname = NULL;
    }
}

/*
 * Get an entry in the passwd/group cache.
 */
VOID *
pwcache_get(how, key)
    enum cmptype how;
    VOID *key;
{
    struct rbnode *node;
    struct passwd *pw;
    struct group *gr;

    switch (how) {
	case bypwnam:
	    if ((node = rbfind(pwcache_byname, key)) != NULL) {
		pw = (struct passwd *) node->data;
		return(pw->pw_uid != (uid_t) -1 ? pw : NULL);
	    }
	    break;
	case byuid:
	    if ((node = rbfind(pwcache_byuid, key)) != NULL) {
		pw = (struct passwd *) node->data;
		return(pw->pw_name != NULL ? pw : NULL);
	    }
	    break;
	case bygrnam:
	    if ((node = rbfind(grcache_bygid, key)) != NULL) {
		gr = (struct group *) node->data;
		return(gr->gr_gid != (gid_t) -1 ? gr : NULL);
	    }
	    break;
	case bygid:
	    if ((node = rbfind(grcache_bygid, key)) != NULL) {
		gr = (struct group *) node->data;
		return(gr->gr_name != NULL ? gr : NULL);
	    }
	    break;
    }
    return(NULL);
}

/*
 * Store an entry in the passwd/group cache.
 * Returns TRUE on success and FALSE if the entry already exists.
 */
int
pwcache_put(how, data)
    enum cmptype how;
    VOID *data;
{
    switch (how) {
	case bypwnam:
	    return(rbinsert(pwcache_byname, data) == NULL);
	    break;
	case byuid:
	    return(rbinsert(pwcache_byuid, data) == NULL);
	    break;
	case bygrnam:
	    return(rbinsert(grcache_byname, data) == NULL);
	    break;
	case bygid:
	    return(rbinsert(grcache_bygid, data) == NULL);
	    break;
    }
    return(FALSE);
}

/*
 * Compare by uid.
 */
static int
cmp_pwuid(v1, v2)
    const VOID *v1;
    const VOID *v2;
{
    const struct passwd *pw1 = (const struct passwd *) v1;
    const struct passwd *pw2 = (const struct passwd *) v2;
    return(pw1->pw_uid - pw2->pw_uid);
}

/*
 * Compare by user name.
 */
static int
cmp_pwnam(v1, v2)
    const VOID *v1;
    const VOID *v2;
{
    const struct passwd *pw1 = (const struct passwd *) v1;
    const struct passwd *pw2 = (const struct passwd *) v2;
    return(strcmp(pw1->pw_name, pw2->pw_name));
}

/*
 * Dynamically allocate space for a struct password and the constituent parts
 * that we care about.  Fills in pw_passwd from shadow file.
 */
struct passwd *
sudo_pwdup(pw)
    const struct passwd *pw;
{
    char *cp;
    const char *pw_passwd, *pw_shell;
    size_t nsize, psize, csize, gsize, dsize, ssize, total;
    struct passwd *newpw;

    /* Get shadow password if available. */
    pw_passwd = sudo_getepw(pw);

    /* If shell field is empty, expand to _PATH_BSHELL. */
    pw_shell = (pw->pw_shell == NULL || pw->pw_shell[0] == '\0')
	? _PATH_BSHELL : pw->pw_shell;

    /* Allocate in one big chunk for easy freeing. */
    nsize = psize = csize = gsize = dsize = ssize = 0;
    total = sizeof(struct passwd);
    if (pw->pw_name) {
	    nsize = strlen(pw->pw_name) + 1;
	    total += nsize;
    }
    if (pw_passwd) {
	    psize = strlen(pw_passwd) + 1;
	    total += psize;
    }
#ifdef HAVE_LOGIN_CAP_H
    if (pw->pw_class) {
	    csize = strlen(pw->pw_class) + 1;
	    total += csize;
    }
#endif
    if (pw->pw_gecos) {
	    gsize = strlen(pw->pw_gecos) + 1;
	    total += gsize;
    }
    if (pw->pw_dir) {
	    dsize = strlen(pw->pw_dir) + 1;
	    total += dsize;
    }
    if (pw_shell) {
	    ssize = strlen(pw_shell) + 1;
	    total += ssize;
    }
    if ((cp = malloc(total)) == NULL)
	    return(NULL);
    newpw = (struct passwd *)cp;

    /*
     * Copy in passwd contents and make strings relative to space
     * at the end of the buffer.
     */
    (void)memcpy(newpw, pw, sizeof(struct passwd));
    cp += sizeof(struct passwd);
    if (nsize) {
	    (void)memcpy(cp, pw->pw_name, nsize);
	    newpw->pw_name = cp;
	    cp += nsize;
    }
    if (psize) {
	    (void)memcpy(cp, pw_passwd, psize);
	    newpw->pw_passwd = cp;
	    cp += psize;
    }
#ifdef HAVE_LOGIN_CAP_H
    if (csize) {
	    (void)memcpy(cp, pw->pw_class, csize);
	    newpw->pw_class = cp;
	    cp += csize;
    }
#endif
    if (gsize) {
	    (void)memcpy(cp, pw->pw_gecos, gsize);
	    newpw->pw_gecos = cp;
	    cp += gsize;
    }
    if (dsize) {
	    (void)memcpy(cp, pw->pw_dir, dsize);
	    newpw->pw_dir = cp;
	    cp += dsize;
    }
    if (ssize) {
	    (void)memcpy(cp, pw_shell, ssize);
	    newpw->pw_shell = cp;
	    cp += ssize;
    }

    return(newpw);
}

/*
 * Take a uid and return a faked up passwd struct.
 */
struct passwd *
sudo_fakepwuid(uid)
    uid_t uid;
{
    struct passwd *pw;
    struct rbnode *node;

    pw = emalloc(sizeof(struct passwd) + MAX_UID_T_LEN + 1);
    memset(pw, 0, sizeof(struct passwd));
    pw->pw_uid = uid;
    pw->pw_name = (char *)pw + sizeof(struct passwd);
    (void) snprintf(pw->pw_name, MAX_UID_T_LEN + 1, "#%lu",
	(unsigned long) uid);

    /* Store by uid and by name, overwriting cached version. */
    if ((node = rbinsert(pwcache_byuid, pw)) != NULL) {
	free(node->data);
	node->data = (VOID *) pw;
    }
    if ((node = rbinsert(pwcache_byname, pw)) != NULL) {
	free(node->data);
	node->data = (VOID *) pw;
    }
    return(pw);
}

/*
 * Take a uid in string form "#123" and return a faked up passwd struct.
 */
struct passwd *
sudo_fakepwnam(user)
    const char *user;
{
    struct passwd *pw;
    struct rbnode *node;
    size_t len;

    len = strlen(user);
    pw = emalloc(sizeof(struct passwd) + len + 1);
    memset(pw, 0, sizeof(struct passwd));
    pw->pw_uid = (uid_t) atoi(user + 1);
    pw->pw_name = (char *)pw + sizeof(struct passwd);
    strlcpy(pw->pw_name, user, len + 1);

    /* Store by uid and by name, overwriting cached version. */
    if ((node = rbinsert(pwcache_byuid, pw)) != NULL) {
	free(node->data);
	node->data = (VOID *) pw;
    }
    if ((node = rbinsert(pwcache_byname, pw)) != NULL) {
	free(node->data);
	node->data = (VOID *) pw;
    }
    return(pw);
}

static void
pw_free(v)
    VOID *v;
{
    struct passwd *pw = (struct passwd *) v;

    if (pw->pw_passwd != NULL)
	zero_bytes(pw->pw_passwd, strlen(pw->pw_passwd));
    free(pw);
}

/*
 * Compare by gid.
 */
static int
cmp_grgid(v1, v2)
    const VOID *v1;
    const VOID *v2;
{
    const struct group *grp1 = (const struct group *) v1;
    const struct group *grp2 = (const struct group *) v2;
    return(grp1->gr_gid - grp2->gr_gid);
}

/*
 * Compare by group name.
 */
static int
cmp_grnam(v1, v2)
    const VOID *v1;
    const VOID *v2;
{
    const struct group *grp1 = (const struct group *) v1;
    const struct group *grp2 = (const struct group *) v2;
    return(strcmp(grp1->gr_name, grp2->gr_name));
}

struct group *
sudo_grdup(gr)
    const struct group *gr;
{
    char *cp;
    size_t nsize, psize, csize, num, total, len;
    struct group *newgr;

    /* Allocate in one big chunk for easy freeing. */
    nsize = psize = csize = num = 0;
    total = sizeof(struct group);
    if (gr->gr_name) {
	    nsize = strlen(gr->gr_name) + 1;
	    total += nsize;
    }
    if (gr->gr_passwd) {
	    psize = strlen(gr->gr_passwd) + 1;
	    total += psize;
    }
    if (gr->gr_mem) {
	for (num = 0; gr->gr_mem[num] != NULL; num++)
	    total += strlen(gr->gr_mem[num]) + 1;
	num++;
	total += sizeof(char *) * num;
    }
    if ((cp = malloc(total)) == NULL)
	    return(NULL);
    newgr = (struct group *)cp;

    /*
     * Copy in group contents and make strings relative to space
     * at the end of the buffer.
     */
    (void)memcpy(newgr, gr, sizeof(struct group));
    cp += sizeof(struct group);
    if (nsize) {
	(void)memcpy(cp, gr->gr_name, nsize);
	newgr->gr_name = cp;
	cp += nsize;
    }
    if (psize) {
	(void)memcpy(cp, gr->gr_passwd, psize);
	newgr->gr_passwd = cp;
	cp += psize;
    }
    if (gr->gr_mem) {
	newgr->gr_mem = (char **)cp;
	cp += sizeof(char *) * num;
	for (num = 0; gr->gr_mem[num] != NULL; num++) {
	    len = strlen(gr->gr_mem[num]) + 1;
	    memcpy(cp, gr->gr_mem[num], len);
	    newgr->gr_mem[num] = cp;
	    cp += len;
	}
	newgr->gr_mem[num] = NULL;
    }

    return(newgr);
}
