/*
 * Copyright (c) 2005 Todd C. Miller <Todd.Miller@courtesan.com>
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
 * Trivial replacements for the libc get{gr,pw}{uid,nam}() routines
 * for use by testsudoers in the sudo test harness.
 * We need our own since many platforms don't provide set{pw,gr}file().
 */

#include <config.h>

#include <sys/types.h>
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
#include <limits.h>
#include <pwd.h>
#include <grp.h>

#include "sudo.h"

#ifndef LINE_MAX
# define LINE_MAX 2048
#endif

static const char *pwfile = "/etc/passwd";
static FILE *pwf;
static int pw_stayopen;

static FILE *grf;
static const char *grfile = "/etc/group";
static int gr_stayopen;

extern VOID *pwcache_get		__P((enum cmptype, VOID *));
extern int  pwcache_put			__P((enum cmptype, VOID *));
extern struct passwd *sudo_pwdup	__P((const struct passwd *));
extern struct group  *sudo_grdup	__P((const struct group *));

void
sudo_setpwfile(file)
    const char *file;
{
    pwfile = file;
    if (pwf != NULL)
	sudo_endpwent();
}

void
sudo_setpwent()
{
    if (pwf == NULL)
	pwf = fopen(pwfile, "r");
    else
	rewind(pwf);
    pw_stayopen = 1;
}

void
sudo_endpwent()
{
    if (pwf != NULL) {
	fclose(pwf);
	pwf = NULL;
    }
    pw_stayopen = 0;
}

struct passwd *
sudo_getpwnam(name)
    const char *name;
{
    struct passwd tpw, *pw = NULL;
    size_t len, nlen;
    char buf[LINE_MAX], *cp;

    tpw.pw_name = (char *) name;
    if ((pw = pwcache_get(bypwnam, &tpw)) != NULL)
	return(pw);

    /* No cached entry, try the passwd file. */
    if (pwf != NULL)
	rewind(pwf);
    else if ((pwf = fopen(pwfile, "r")) == NULL)
	return(NULL);

    nlen = strlen(name);
    while (fgets(buf, sizeof(buf), pwf)) {
	if (strncmp(buf, name, nlen) != 0 || buf[nlen] != ':')
	    continue;
	if ((tpw.pw_name = strtok(buf, ":")) == NULL)
	    continue;
	if ((tpw.pw_passwd = strtok(NULL, ":")) == NULL)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	tpw.pw_uid = atoi(cp);
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	tpw.pw_gid = atoi(cp);
	if ((tpw.pw_gecos = strtok(NULL, ":")) == NULL)
	    continue;
	if ((tpw.pw_dir = strtok(NULL, ":")) == NULL)
	    continue;
	if ((tpw.pw_shell = strtok(NULL, ":")) != NULL) {
	    len = strlen(tpw.pw_shell);
	    if (tpw.pw_shell[len - 1] == '\n')
		tpw.pw_shell[len - 1] = '\0';
	}
	pw = sudo_pwdup(&tpw);
	break;
    }
    if (!pw_stayopen) {
	fclose(pwf);
	pwf = NULL;
    }
    if (pw != NULL) {
	if (!pwcache_put(bypwnam, (VOID *) pw))
	    errorx(1, "unable to cache user name, already exists");
	if (!pwcache_put(byuid, (VOID *) pw))
	    errorx(1, "unable to cache uid, already exists");
	return(pw);
    } else {
	len = strlen(name) + 1;
	cp = emalloc(sizeof(*pw) + len);
	memset(cp, 0, sizeof(*pw));
	pw = (struct passwd *) cp;
	cp += sizeof(*pw);
	memcpy(cp, name, len);
	pw->pw_name = cp;
	pw->pw_uid = (uid_t) -1;
	if (!pwcache_put(bypwnam, (VOID *) pw))
	    errorx(1, "unable to cache user name, already exists");
	return(NULL);
    }
}

struct passwd *
sudo_getpwuid(uid)
    uid_t uid;
{
    struct passwd tpw, *pw = NULL;
    size_t len;
    char buf[LINE_MAX], *cp;

    tpw.pw_uid = uid;
    if ((pw = pwcache_get(byuid, &tpw)) != NULL)
	return(pw);

    /* No cached entry, try the passwd file. */
    if (pwf != NULL)
	rewind(pwf);
    else if ((pwf = fopen(pwfile, "r")) == NULL)
	return(NULL);

    while (fgets(buf, sizeof(buf), pwf)) {
	if ((tpw.pw_name = strtok(buf, ":")) == NULL)
	    continue;
	if ((tpw.pw_passwd = strtok(NULL, ":")) == NULL)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	tpw.pw_uid = atoi(cp);
	if (tpw.pw_uid != uid)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	tpw.pw_gid = atoi(cp);
	if ((tpw.pw_gecos = strtok(NULL, ":")) == NULL)
	    continue;
	if ((tpw.pw_dir = strtok(NULL, ":")) == NULL)
	    continue;
	if ((tpw.pw_shell = strtok(NULL, ":")) != NULL) {
	    len = strlen(tpw.pw_shell);
	    if (tpw.pw_shell[len - 1] == '\n')
		tpw.pw_shell[len - 1] = '\0';
	}
	pw = sudo_pwdup(&tpw);
	break;
    }
    if (!pw_stayopen) {
	fclose(pwf);
	pwf = NULL;
    }
    if (pw != NULL) {
	if (!pwcache_put(bypwnam, (VOID *) pw))
	    errorx(1, "unable to cache user name, already exists");
	if (!pwcache_put(byuid, (VOID *) pw))
	    errorx(1, "unable to cache uid, already exists");
	return(pw);
    } else {
	pw = emalloc(sizeof(*pw));
	memset(pw, 0, sizeof(*pw));
	pw->pw_uid = uid;
	if (!pwcache_put(byuid, (VOID *) pw))
	    errorx(1, "unable to cache uid, already exists");
	return(NULL);
    }
}

char *
sudo_getepw(pw)
    const struct passwd *pw;
{
    return(pw->pw_passwd);
}

void
sudo_setgrfile(file)
    const char *file;
{
    grfile = file;
    if (grf != NULL)
	sudo_endgrent();
}

void
sudo_setgrent()
{
    if (grf == NULL)
	grf = fopen(grfile, "r");
    else
	rewind(grf);
    gr_stayopen = 1;
}

void
sudo_endgrent()
{
    if (grf != NULL) {
	fclose(grf);
	grf = NULL;
    }
    gr_stayopen = 0;
}

struct group *
sudo_getgrnam(name)
    const char *name;
{
    struct group tgr, *gr = NULL;
    size_t len, nlen;
    char buf[LINE_MAX], *cp, *m;
    int n;

    tgr.gr_name = (char *) name;
    if ((gr = pwcache_get(bygrnam, &tgr)) != NULL)
	return(gr);

    /* No cached entry, try the group file. */
    if (grf != NULL)
	rewind(grf);
    else if ((grf = fopen(grfile, "r")) == NULL)
	return(NULL);

    nlen = strlen(name);
    while (fgets(buf, sizeof(buf), grf)) {
	if (strncmp(buf, name, nlen) != 0 || buf[nlen] != ':')
	    continue;
	if ((tgr.gr_name = strtok(buf, ":")) == NULL)
	    continue;
	if ((tgr.gr_passwd = strtok(NULL, ":")) == NULL)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	tgr.gr_gid = atoi(cp);
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	len = strlen(cp);
	if (cp[len - 1] == '\n')
	    cp[len - 1] = '\0';
	/* Fill in group members */
	if (*cp != '\0') {
	    for (n = 1, m = cp; (m = strchr(m, ',')) != NULL; m++, n++)
		continue;
	    tgr.gr_mem = emalloc2(n + 1, sizeof(char *));
	    n = 0;
	    for ((m = strtok(cp, ",")); m != NULL; (m = strtok(NULL, ",")))
		tgr.gr_mem[n++] = m;
	    tgr.gr_mem[n++] = NULL;
	} else
	    tgr.gr_mem = NULL;
	gr = sudo_grdup(&tgr);
	if (tgr.gr_mem != NULL)
	    free(tgr.gr_mem);
	break;
    }
    if (!gr_stayopen) {
	fclose(grf);
	grf = NULL;
    }
    if (gr != NULL) {
	if (!pwcache_put(bygrnam, (VOID *) gr))
	    errorx(1, "unable to cache group name, already exists");
	if (!pwcache_put(bygid, (VOID *) gr))
	    errorx(1, "unable to cache gid, already exists");
	return(gr);
    } else {
	len = strlen(name) + 1;
	cp = emalloc(sizeof(*gr) + len);
	memset(cp, 0, sizeof(*gr));
	gr = (struct group *) cp;
	cp += sizeof(*gr);
	memcpy(cp, name, len);
	gr->gr_name = cp;
	gr->gr_gid = (gid_t) -1;
	if (!pwcache_put(bygrnam, (VOID *) gr))
	    errorx(1, "unable to cache group name, already exists");
	return(NULL);
    }
}

struct group *
sudo_getgrgid(gid)
    gid_t gid;
{
    struct group tgr, *gr = NULL;
    size_t len;
    char buf[LINE_MAX], *cp, *m;
    int n;

    tgr.gr_gid = gid;
    if ((gr = pwcache_get(bygid, &tgr)) != NULL)
	return(gr);

    /* No cached entry, try the group file. */
    if (grf != NULL)
	rewind(grf);
    else if ((grf = fopen(grfile, "r")) == NULL)
	return(NULL);

    while (fgets(buf, sizeof(buf), grf)) {
	if ((tgr.gr_name = strtok(buf, ":")) == NULL)
	    continue;
	if ((tgr.gr_passwd = strtok(NULL, ":")) == NULL)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	tgr.gr_gid = atoi(cp);
	if (tgr.gr_gid != gid)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	len = strlen(cp);
	if (cp[len - 1] == '\n')
	    cp[len - 1] = '\0';
	/* Fill in group members */
	if (*cp != '\0') {
	    for (n = 1, m = cp; (m = strchr(m, ',')) != NULL; m++, n++)
		continue;
	    tgr.gr_mem = emalloc2(n + 1, sizeof(char *));
	    n = 0;
	    for ((m = strtok(cp, ",")); m != NULL; (m = strtok(NULL, ",")))
		tgr.gr_mem[n++] = m;
	    tgr.gr_mem[n++] = NULL;
	} else
	    tgr.gr_mem = NULL;
	gr = sudo_grdup(&tgr);
	if (tgr.gr_mem != NULL)
	    free(tgr.gr_mem);
	break;
    }
    if (!gr_stayopen) {
	fclose(grf);
	grf = NULL;
    }
    if (gr != NULL) {
	if (!pwcache_put(bygrnam, (VOID *) gr))
	    errorx(1, "unable to cache group name, already exists");
	if (!pwcache_put(bygid, (VOID *) gr))
	    errorx(1, "unable to cache gid, already exists");
	return(gr);
    } else {
	gr = emalloc(sizeof(*gr));
	memset(gr, 0, sizeof(*gr));
	gr->gr_gid = gid;
	if (!pwcache_put(bygid, (VOID *) gr))
	    errorx(1, "unable to cache gid, already exists");
	return(NULL);
    }
}
