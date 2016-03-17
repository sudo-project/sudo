/*
 * Copyright (c) 2010, 2011, 2013, 2014
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
 */

#include <config.h>

#ifndef HAVE_GETGROUPLIST

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <grp.h>
#ifdef HAVE_NSS_SEARCH
# include <errno.h>
# include <limits.h>
# include <nsswitch.h>
# ifdef HAVE_NSS_DBDEFS_H
#  include <nss_dbdefs.h>
# else
#  include "compat/nss_dbdefs.h"
# endif
#endif

#include "sudo_compat.h"
#include "sudo_util.h"

#if defined(HAVE_GETGRSET)
/*
 * BSD-compatible getgrouplist(3) using AIX getgrset(3)
 */
int
sudo_getgrouplist(const char *name, gid_t basegid, gid_t *groups, int *ngroupsp)
{
    char *cp, *grset = NULL;
    int ngroups = 1;
    int grpsize = *ngroupsp;
    int rval = -1;
    gid_t gid;

    /* We support BSD semantics where the first element is the base gid */
    if (grpsize <= 0)
	return -1;
    groups[0] = basegid;

#ifdef HAVE_SETAUTHDB
    aix_setauthdb((char *) name, NULL);
#endif
    if ((grset = getgrset(name)) != NULL) {
	char *last;
	const char *errstr;

	for (cp = strtok_r(grset, ",", &last); cp != NULL; cp = strtok_r(NULL, ",", &last)) {
	    gid = sudo_strtoid(cp, NULL, NULL, &errstr);
	    if (errstr == NULL && gid != basegid) {
		if (ngroups == grpsize)
		    goto done;
		groups[ngroups++] = gid;
	    }
	}
    }
    rval = 0;

done:
    free(grset);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
    *ngroupsp = ngroups;

    return rval;
}

#elif defined(HAVE_NSS_SEARCH)

#ifndef ALIGNBYTES
# define ALIGNBYTES	(sizeof(long) - 1L)
#endif
#ifndef ALIGN
# define ALIGN(p)	(((unsigned long)(p) + ALIGNBYTES) & ~ALIGNBYTES)
#endif

#if defined(HAVE__NSS_INITF_GROUP) || defined(HAVE___NSS_INITF_GROUP)
extern void _nss_initf_group(nss_db_params_t *params);
#else
static void
_nss_initf_group(nss_db_params_t *params)
{
    params->name = NSS_DBNAM_GROUP;
    params->default_config = NSS_DEFCONF_GROUP;
}
#endif

/*
 * Convert a groups file string (instr) to a struct group (ent) using
 * buf for storage.  
 */
static int
str2grp(const char *instr, int inlen, void *ent, char *buf, int buflen)
{
    struct group *grp = ent;
    char *cp, *fieldsep = buf;
    char **gr_mem, **gr_end;
    const char *errstr;
    int yp = 0;
    id_t id;

    /* Must at least have space to copy instr -> buf. */
    if (inlen >= buflen)
	return NSS_STR_PARSE_ERANGE;

    /* Paranoia: buf and instr should be distinct. */
    if (buf != instr) {
	memmove(buf, instr, inlen);
	buf[inlen] = '\0';
    }

    if ((fieldsep = strchr(cp = fieldsep, ':')) == NULL)
	return NSS_STR_PARSE_PARSE;
    *fieldsep++ = '\0';
    grp->gr_name = cp;

    /* Check for YP inclusion/exclusion entries. */
    if (*cp == '+' || *cp == '-') {
	/* Only the name is required for YP inclusion/exclusion entries. */
	grp->gr_passwd = "";
	grp->gr_gid = 0;
	grp->gr_mem = NULL;
	yp = 1;
    }

    if ((fieldsep = strchr(cp = fieldsep, ':')) == NULL)
	return yp ? NSS_STR_PARSE_SUCCESS : NSS_STR_PARSE_PARSE;
    *fieldsep++ = '\0';
    grp->gr_passwd = cp;

    if ((fieldsep = strchr(cp = fieldsep, ':')) == NULL)
	return yp ? NSS_STR_PARSE_SUCCESS : NSS_STR_PARSE_PARSE;
    *fieldsep++ = '\0';
    id = sudo_strtoid(cp, NULL, NULL, &errstr);
    if (errstr != NULL) {
	/*
	 * A range error is always a fatal error, but ignore garbage
	 * at the end of YP entries since it has no meaning.
	 */
	if (errno == ERANGE)
	    return NSS_STR_PARSE_ERANGE;
	return yp ? NSS_STR_PARSE_SUCCESS : NSS_STR_PARSE_PARSE;
    }
#ifdef GID_NOBODY
    /* Negative gids get mapped to nobody on Solaris. */
    if (*cp == '-' && id != 0)
	grp->gr_gid = GID_NOBODY;
    else
#endif
	grp->gr_gid = (gid_t)id;

    /* Store group members, taking care to use proper alignment. */
    grp->gr_mem = NULL;
    if (*fieldsep != '\0') {
	grp->gr_mem = gr_mem = (char **)ALIGN(buf + inlen + 1);
	gr_end = (char **)((unsigned long)(buf + buflen) & ~ALIGNBYTES);
	for (;;) {
	    if (gr_mem == gr_end)
		return NSS_STR_PARSE_ERANGE;	/* out of space! */
	    *gr_mem++ = cp;
	    if (fieldsep == NULL)
		break;
	    if ((fieldsep = strchr(cp = fieldsep, ',')) != NULL)
		*fieldsep++ = '\0';
	}
	*gr_mem = NULL;
    }
    return NSS_STR_PARSE_SUCCESS;
}

static nss_status_t
process_cstr(const char *instr, int inlen, struct nss_groupsbymem *gbm)
{
    const char *user = gbm->username;
    nss_status_t rval = NSS_NOTFOUND;
    nss_XbyY_buf_t *buf;
    struct group *grp;
    char **gr_mem;
    int	error, i;

    buf = _nss_XbyY_buf_alloc(sizeof(struct group), NSS_BUFLEN_GROUP);
    if (buf == NULL)
	return NSS_UNAVAIL;

    /* Parse groups file string -> struct group. */
    grp = buf->result;
    error = (*gbm->str2ent)(instr, inlen, grp, buf->buffer, buf->buflen);
    if (error || grp->gr_mem == NULL)
	goto done;

    for (gr_mem = grp->gr_mem; *gr_mem != NULL; gr_mem++) {
	if (strcmp(*gr_mem, user) == 0) {
	    /* Append to gid_array unless gr_gid is a dupe. */
	    for (i = 0; i < gbm->numgids; i++) {
		if (gbm->gid_array[i] == grp->gr_gid)
		    goto done;			/* already present */
	    }
	    /* Store gid if there is space. */
	    if (i < gbm->maxgids)
		gbm->gid_array[i] = grp->gr_gid;
	    /* Always increment numgids so we can detect when out of space. */
	    gbm->numgids++;
	    goto done;
	}
    }
done:
    _nss_XbyY_buf_free(buf);
    return rval;
}

/*
 * BSD-compatible getgrouplist(3) using nss_search(3)
 */
int
sudo_getgrouplist(const char *name, gid_t basegid, gid_t *groups, int *ngroupsp)
{
    struct nss_groupsbymem gbm;
    static DEFINE_NSS_DB_ROOT(db_root);

    /* We support BSD semantics where the first element is the base gid */
    if (*ngroupsp <= 0)
	return -1;
    groups[0] = basegid;

    memset(&gbm, 0, sizeof(gbm));
    gbm.username = name;
    gbm.gid_array = groups;
    gbm.maxgids = *ngroupsp;
    gbm.numgids = 1; /* for basegid */
    gbm.force_slow_way = 1;
    gbm.str2ent = str2grp;
    gbm.process_cstr = process_cstr;

    /*
     * Can't use nss_search return value since it may return NSS_UNAVAIL
     * when no nsswitch.conf entry (e.g. compat mode).
     */
    (void)nss_search(&db_root, _nss_initf_group, NSS_DBOP_GROUP_BYMEMBER, &gbm);

    if (gbm.numgids <= gbm.maxgids) {
        *ngroupsp = gbm.numgids;
        return 0;
    }
    *ngroupsp = gbm.maxgids;
    return -1;
}

#else /* !HAVE_GETGRSET && !HAVE__GETGROUPSBYMEMBER */

/*
 * BSD-compatible getgrouplist(3) using getgrent(3)
 */
int
sudo_getgrouplist(const char *name, gid_t basegid, gid_t *groups, int *ngroupsp)
{
    int i, ngroups = 1;
    int grpsize = *ngroupsp;
    int rval = -1;
    struct group *grp;

    /* We support BSD semantics where the first element is the base gid */
    if (grpsize <= 0)
	return -1;
    groups[0] = basegid;

    setgrent();
    while ((grp = getgrent()) != NULL) {
	if (grp->gr_gid == basegid || grp->gr_mem == NULL)
	    continue;

	for (i = 0; grp->gr_mem[i] != NULL; i++) {
	    if (strcmp(name, grp->gr_mem[i]) == 0)
		break;
	}
	if (grp->gr_mem[i] == NULL)
	    continue; /* user not found */

	/* Only add if it is not the same as an existing gid */
	for (i = 0; i < ngroups; i++) {
	    if (grp->gr_gid == groups[i])
		break;
	}
	if (i == ngroups) {
	    if (ngroups == grpsize)
		goto done;
	    groups[ngroups++] = grp->gr_gid;
	}
    }
    rval = 0;

done:
    endgrent();
    *ngroupsp = ngroups;

    return rval;
}
#endif /* !HAVE_GETGRSET && !HAVE__GETGROUPSBYMEMBER */
#endif /* HAVE_GETGROUPLIST */
