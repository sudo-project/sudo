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

#undef GRMEM_MAX
#define GRMEM_MAX 200

static FILE *pwf;
static const char *pwfile = "/etc/passwd";
static int pw_stayopen;
static struct passwd pwbuf;

static FILE *grf;
static const char *grfile = "/etc/group";
static int gr_stayopen;
static struct group grbuf;
static char *gr_mem[GRMEM_MAX+1];

void my_setgrfile __P((const char *));
void my_setgrent __P((void));
void my_endgrent __P((void));
struct group *my_getgrnam __P((const char *));
struct group *my_getgruid __P((gid_t));

void my_setpwfile __P((const char *));
void my_setpwent __P((void));
void my_endpwent __P((void));
struct passwd *my_getpwnam __P((const char *));
struct passwd *my_getpwuid __P((uid_t));

void
my_setpwfile(file)
    const char *file;
{
    pwfile = file;
    if (pwf != NULL)
	my_endpwent();
}

void
my_setpwent()
{
    if (pwf == NULL)
	pwf = fopen(pwfile, "r");
    else
	rewind(pwf);
    pw_stayopen = 1;
}

void
my_endpwent()
{
    if (pwf != NULL) {
	fclose(pwf);
	pwf = NULL;
    }
    pw_stayopen = 0;
}

struct passwd *
my_getpwnam(name)
    const char *name;
{
    struct passwd *pw = NULL;
    size_t len, nlen;
    char buf[LINE_MAX], *cp;

    if (pwf != NULL)
	rewind(pwf);
    else if ((pwf = fopen(pwfile, "r")) == NULL)
	return(NULL);

    memset(&pwbuf, 0, sizeof(pwbuf));
    nlen = strlen(name);
    while (fgets(buf, sizeof(buf), pwf)) {
	if (strncmp(buf, name, nlen) != 0 || buf[nlen] != ':')
	    continue;
	if ((pwbuf.pw_name = strtok(buf, ":")) == NULL)
	    continue;
	if ((pwbuf.pw_passwd = strtok(NULL, ":")) == NULL)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	pwbuf.pw_uid = atoi(cp);
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	pwbuf.pw_gid = atoi(cp);
	if ((pwbuf.pw_gecos = strtok(NULL, ":")) == NULL)
	    continue;
	if ((pwbuf.pw_dir = strtok(NULL, ":")) == NULL)
	    continue;
	if ((pwbuf.pw_shell = strtok(NULL, ":")) != NULL) {
	    len = strlen(pwbuf.pw_shell);
	    if (pwbuf.pw_shell[len - 1] == '\n')
		pwbuf.pw_shell[len - 1] = '\0';
	}
	pw = &pwbuf;
	break;
    }
    if (!pw_stayopen) {
	fclose(pwf);
	pwf = NULL;
    }
    return(pw);
}

struct passwd *
my_getpwuid(uid)
    uid_t uid;
{
    struct passwd *pw = NULL;
    size_t len;
    char buf[LINE_MAX], *cp;

    if (pwf != NULL)
	rewind(pwf);
    else if ((pwf = fopen(pwfile, "r")) == NULL)
	return(NULL);

    memset(&pwbuf, 0, sizeof(pwbuf));
    while (fgets(buf, sizeof(buf), pwf)) {
	if ((pwbuf.pw_name = strtok(buf, ":")) == NULL)
	    continue;
	if ((pwbuf.pw_passwd = strtok(NULL, ":")) == NULL)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	pwbuf.pw_uid = atoi(cp);
	if (pwbuf.pw_uid != uid)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	pwbuf.pw_gid = atoi(cp);
	if ((pwbuf.pw_gecos = strtok(NULL, ":")) == NULL)
	    continue;
	if ((pwbuf.pw_dir = strtok(NULL, ":")) == NULL)
	    continue;
	if ((pwbuf.pw_shell = strtok(NULL, ":")) != NULL) {
	    len = strlen(pwbuf.pw_shell);
	    if (pwbuf.pw_shell[len - 1] == '\n')
		pwbuf.pw_shell[len - 1] = '\0';
	}
	pw = &pwbuf;
	break;
    }
    if (!pw_stayopen) {
	fclose(pwf);
	pwf = NULL;
    }
    return(pw);
}

void
my_setgrfile(file)
    const char *file;
{
    grfile = file;
    if (grf != NULL)
	my_endgrent();
}

void
my_setgrent()
{
    if (grf == NULL)
	grf = fopen(grfile, "r");
    else
	rewind(grf);
    gr_stayopen = 1;
}

void
my_endgrent()
{
    if (grf != NULL) {
	fclose(grf);
	grf = NULL;
    }
    gr_stayopen = 0;
}

struct group *
my_getgrnam(name)
    const char *name;
{
    struct group *gr = NULL;
    size_t len, nlen;
    char buf[LINE_MAX], *cp, *m;
    int n;

    if (grf != NULL)
	rewind(grf);
    else if ((grf = fopen(grfile, "r")) == NULL)
	return(NULL);

    nlen = strlen(name);
    memset(&grbuf, 0, sizeof(grbuf));
    while (fgets(buf, sizeof(buf), grf)) {
	if (strncmp(buf, name, nlen) != 0 || buf[nlen] != ':')
	    continue;
	if ((grbuf.gr_name = strtok(buf, ":")) == NULL)
	    continue;
	if ((grbuf.gr_passwd = strtok(NULL, ":")) == NULL)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	grbuf.gr_gid = atoi(cp);
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	len = strlen(cp);
	if (cp[len - 1] == '\n')
	    cp[len - 1] = '\0';
	/* Fill in group members */
	if (*cp != '\0') {
	    grbuf.gr_mem = gr_mem;
	    m = strtok(cp, ",");
	    for (n = 0; m != NULL && n < GRMEM_MAX; n++) {
		grbuf.gr_mem[n++] = m;
		m = strtok(NULL, ",");
	    }
	    grbuf.gr_mem[n++] = NULL;
	} else
	    grbuf.gr_mem = NULL;
	gr = &grbuf;
	break;
    }
    if (!gr_stayopen) {
	fclose(grf);
	grf = NULL;
    }
    return(gr);
}

struct group *
my_getgrgid(gid)
    gid_t gid;
{
    struct group *gr = NULL;
    size_t len;
    char buf[LINE_MAX], *cp, *m;
    int n;

    if (grf != NULL)
	rewind(grf);
    else if ((grf = fopen(grfile, "r")) == NULL)
	return(NULL);

    memset(&grbuf, 0, sizeof(grbuf));
    while (fgets(buf, sizeof(buf), grf)) {
	if ((grbuf.gr_name = strtok(buf, ":")) == NULL)
	    continue;
	if ((grbuf.gr_passwd = strtok(NULL, ":")) == NULL)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	grbuf.gr_gid = atoi(cp);
	if (grbuf.gr_gid != gid)
	    continue;
	if ((cp = strtok(NULL, ":")) == NULL)
	    continue;
	len = strlen(cp);
	if (cp[len - 1] == '\n')
	    cp[len - 1] = '\0';
	/* Fill in group members */
	if (*cp != '\0') {
	    grbuf.gr_mem = gr_mem;
	    m = strtok(cp, ",");
	    for (n = 0; m != NULL && n < GRMEM_MAX; n++) {
		grbuf.gr_mem[n++] = m;
		m = strtok(NULL, ",");
	    }
	    grbuf.gr_mem[n++] = NULL;
	} else
	    grbuf.gr_mem = NULL;
	gr = &grbuf;
	break;
    }
    if (!gr_stayopen) {
	fclose(grf);
	grf = NULL;
    }
    return(gr);
}
