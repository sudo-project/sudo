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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_FNMATCH
# include <fnmatch.h>
#endif /* HAVE_FNMATCH */
#ifdef HAVE_EXTENDED_GLOB
# include <glob.h>
#endif /* HAVE_EXTENDED_GLOB */
#ifdef HAVE_NETGROUP_H
# include <netgroup.h>
#endif /* HAVE_NETGROUP_H */
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include "sudoers.h"
#include "interfaces.h"
#include "parse.h"
#include <gram.h>

#ifndef HAVE_FNMATCH
# include "compat/fnmatch.h"
#endif /* HAVE_FNMATCH */
#ifndef HAVE_EXTENDED_GLOB
# include "compat/glob.h"
#endif /* HAVE_EXTENDED_GLOB */

static struct member_list empty;

static int command_matches_dir(char *, size_t);
static int command_matches_glob(char *, char *);
static int command_matches_fnmatch(char *, char *);
static int command_matches_normal(char *, char *);

/*
 * Returns TRUE if string 's' contains meta characters.
 */
#define has_meta(s)	(strpbrk(s, "\\?*[]") != NULL)

/*
 * Check for user described by pw in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
static int
_userlist_matches(struct passwd *pw, struct member_list *list)
{
    struct member *m;
    struct alias *a;
    int rval, matched = UNSPEC;

    tq_foreach_rev(list, m) {
	switch (m->type) {
	    case ALL:
		matched = !m->negated;
		break;
	    case NETGROUP:
		if (netgr_matches(m->name, NULL, NULL, pw->pw_name))
		    matched = !m->negated;
		break;
	    case USERGROUP:
		if (usergr_matches(m->name, pw->pw_name, pw))
		    matched = !m->negated;
		break;
	    case ALIAS:
		if ((a = alias_find(m->name, USERALIAS)) != NULL) {
		    rval = _userlist_matches(pw, &a->members);
		    if (rval != UNSPEC)
			matched = m->negated ? !rval : rval;
		    break;
		}
		/* FALLTHROUGH */
	    case WORD:
		if (userpw_matches(m->name, pw->pw_name, pw))
		    matched = !m->negated;
		break;
	}
	if (matched != UNSPEC)
	    break;
    }
    return matched;
}

int
userlist_matches(struct passwd *pw, struct member_list *list)
{
    alias_seqno++;
    return _userlist_matches(pw, list);
}

/*
 * Check for user described by pw in a list of members.
 * If both lists are empty compare against def_runas_default.
 * Returns ALLOW, DENY or UNSPEC.
 */
static int
_runaslist_matches(struct member_list *user_list, struct member_list *group_list)
{
    struct member *m;
    struct alias *a;
    int rval;
    int user_matched = UNSPEC;
    int group_matched = UNSPEC;

    if (runas_pw != NULL) {
	/* If no runas user or runas group listed in sudoers, use default. */
	if (tq_empty(user_list) && tq_empty(group_list))
	    return userpw_matches(def_runas_default, runas_pw->pw_name, runas_pw);

	tq_foreach_rev(user_list, m) {
	    switch (m->type) {
		case ALL:
		    user_matched = !m->negated;
		    break;
		case NETGROUP:
		    if (netgr_matches(m->name, NULL, NULL, runas_pw->pw_name))
			user_matched = !m->negated;
		    break;
		case USERGROUP:
		    if (usergr_matches(m->name, runas_pw->pw_name, runas_pw))
			user_matched = !m->negated;
		    break;
		case ALIAS:
		    if ((a = alias_find(m->name, RUNASALIAS)) != NULL) {
			rval = _runaslist_matches(&a->members, &empty);
			if (rval != UNSPEC)
			    user_matched = m->negated ? !rval : rval;
			break;
		    }
		    /* FALLTHROUGH */
		case WORD:
		    if (userpw_matches(m->name, runas_pw->pw_name, runas_pw))
			user_matched = !m->negated;
		    break;
	    }
	    if (user_matched != UNSPEC)
		break;
	}
    }

    if (runas_gr != NULL) {
	if (user_matched == UNSPEC) {
	    if (runas_pw == NULL || strcmp(runas_pw->pw_name, user_name) == 0)
		user_matched = ALLOW;	/* only changing group */
	}
	tq_foreach_rev(group_list, m) {
	    switch (m->type) {
		case ALL:
		    group_matched = !m->negated;
		    break;
		case ALIAS:
		    if ((a = alias_find(m->name, RUNASALIAS)) != NULL) {
			rval = _runaslist_matches(&a->members, &empty);
			if (rval != UNSPEC)
			    group_matched = m->negated ? !rval : rval;
			break;
		    }
		    /* FALLTHROUGH */
		case WORD:
		    if (group_matches(m->name, runas_gr))
			group_matched = !m->negated;
		    break;
	    }
	    if (group_matched != UNSPEC)
		break;
	}
    }

    if (user_matched == DENY || group_matched == DENY)
	return DENY;
    if (user_matched == group_matched || runas_gr == NULL)
	return user_matched;
    return UNSPEC;
}

int
runaslist_matches(struct member_list *user_list, struct member_list *group_list)
{
    alias_seqno++;
    return _runaslist_matches(user_list ? user_list : &empty,
	group_list ? group_list : &empty);
}

/*
 * Check for host and shost in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
static int
_hostlist_matches(struct member_list *list)
{
    struct member *m;
    struct alias *a;
    int rval, matched = UNSPEC;

    tq_foreach_rev(list, m) {
	switch (m->type) {
	    case ALL:
		matched = !m->negated;
		break;
	    case NETGROUP:
		if (netgr_matches(m->name, user_host, user_shost, NULL))
		    matched = !m->negated;
		break;
	    case NTWKADDR:
		if (addr_matches(m->name))
		    matched = !m->negated;
		break;
	    case ALIAS:
		if ((a = alias_find(m->name, HOSTALIAS)) != NULL) {
		    rval = _hostlist_matches(&a->members);
		    if (rval != UNSPEC)
			matched = m->negated ? !rval : rval;
		    break;
		}
		/* FALLTHROUGH */
	    case WORD:
		if (hostname_matches(user_shost, user_host, m->name))
		    matched = !m->negated;
		break;
	}
	if (matched != UNSPEC)
	    break;
    }
    return matched;
}

int
hostlist_matches(struct member_list *list)
{
    alias_seqno++;
    return _hostlist_matches(list);
}

/*
 * Check for cmnd and args in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
static int
_cmndlist_matches(struct member_list *list)
{
    struct member *m;
    int matched = UNSPEC;

    tq_foreach_rev(list, m) {
	matched = cmnd_matches(m);
	if (matched != UNSPEC)
	    break;
    }
    return matched;
}

int
cmndlist_matches(struct member_list *list)
{
    alias_seqno++;
    return _cmndlist_matches(list);
}

/*
 * Check cmnd and args.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
cmnd_matches(struct member *m)
{
    struct alias *a;
    struct sudo_command *c;
    int rval, matched = UNSPEC;

    switch (m->type) {
	case ALL:
	    matched = !m->negated;
	    break;
	case ALIAS:
	    alias_seqno++;
	    if ((a = alias_find(m->name, CMNDALIAS)) != NULL) {
		rval = _cmndlist_matches(&a->members);
		if (rval != UNSPEC)
		    matched = m->negated ? !rval : rval;
	    }
	    break;
	case COMMAND:
	    c = (struct sudo_command *)m->name;
	    if (command_matches(c->cmnd, c->args))
		matched = !m->negated;
	    break;
    }
    return matched;
}

static int
command_args_match(sudoers_cmnd, sudoers_args)
    char *sudoers_cmnd;
    char *sudoers_args;
{
    int flags = 0;

    /*
     * If no args specified in sudoers, any user args are allowed.
     * If the empty string is specified in sudoers, no user args are allowed.
     */
    if (!sudoers_args ||
	(!user_args && sudoers_args && !strcmp("\"\"", sudoers_args)))
	return TRUE;
    /*
     * If args are specified in sudoers, they must match the user args.
     * If running as sudoedit, all args are assumed to be paths.
     */
    if (sudoers_args) {
	/* For sudoedit, all args are assumed to be pathnames. */
	if (strcmp(sudoers_cmnd, "sudoedit") == 0)
	    flags = FNM_PATHNAME;
	if (fnmatch(sudoers_args, user_args ? user_args : "", flags) == 0)
	    return TRUE;
    }
    return FALSE;
}

/*
 * If path doesn't end in /, return TRUE iff cmnd & path name the same inode;
 * otherwise, return TRUE if user_cmnd names one of the inodes in path.
 */
int
command_matches(char *sudoers_cmnd, char *sudoers_args)
{
    /* Check for pseudo-commands */
    if (sudoers_cmnd[0] != '/') {
	/*
	 * Return true if both sudoers_cmnd and user_cmnd are "sudoedit" AND
	 *  a) there are no args in sudoers OR
	 *  b) there are no args on command line and none req by sudoers OR
	 *  c) there are args in sudoers and on command line and they match
	 */
	if (strcmp(sudoers_cmnd, "sudoedit") != 0 ||
	    strcmp(user_cmnd, "sudoedit") != 0)
	    return FALSE;
	if (command_args_match(sudoers_cmnd, sudoers_args)) {
	    efree(safe_cmnd);
	    safe_cmnd = estrdup(sudoers_cmnd);
	    return TRUE;
	} else
	    return FALSE;
    }

    if (has_meta(sudoers_cmnd)) {
	/*
	 * If sudoers_cmnd has meta characters in it, we need to
	 * use glob(3) and/or fnmatch(3) to do the matching.
	 */
	if (def_fast_glob)
	    return command_matches_fnmatch(sudoers_cmnd, sudoers_args);
	return command_matches_glob(sudoers_cmnd, sudoers_args);
    }
    return command_matches_normal(sudoers_cmnd, sudoers_args);
}

static int
command_matches_fnmatch(char *sudoers_cmnd, char *sudoers_args)
{
    /*
     * Return true if fnmatch(3) succeeds AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none required by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     * else return false.
     */
    if (fnmatch(sudoers_cmnd, user_cmnd, FNM_PATHNAME) != 0)
	return FALSE;
    if (command_args_match(sudoers_cmnd, sudoers_args)) {
	if (safe_cmnd)
	    free(safe_cmnd);
	safe_cmnd = estrdup(user_cmnd);
	return TRUE;
    } else
	return FALSE;
}

static int
command_matches_glob(char *sudoers_cmnd, char *sudoers_args)
{
    struct stat sudoers_stat;
    size_t dlen;
    char **ap, *base, *cp;
    glob_t gl;

    /*
     * First check to see if we can avoid the call to glob(3).
     * Short circuit if there are no meta chars in the command itself
     * and user_base and basename(sudoers_cmnd) don't match.
     */
    dlen = strlen(sudoers_cmnd);
    if (sudoers_cmnd[dlen - 1] != '/') {
	if ((base = strrchr(sudoers_cmnd, '/')) != NULL) {
	    base++;
	    if (!has_meta(base) && strcmp(user_base, base) != 0)
		return FALSE;
	}
    }
    /*
     * Return true if we find a match in the glob(3) results AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none required by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     * else return false.
     */
#define GLOB_FLAGS	(GLOB_NOSORT | GLOB_MARK | GLOB_BRACE | GLOB_TILDE)
    if (glob(sudoers_cmnd, GLOB_FLAGS, NULL, &gl) != 0 || gl.gl_pathc == 0) {
	globfree(&gl);
	return FALSE;
    }
    /* For each glob match, compare basename, st_dev and st_ino. */
    for (ap = gl.gl_pathv; (cp = *ap) != NULL; ap++) {
	/* If it ends in '/' it is a directory spec. */
	dlen = strlen(cp);
	if (cp[dlen - 1] == '/') {
	    if (command_matches_dir(cp, dlen))
		return TRUE;
	    continue;
	}

	/* Only proceed if user_base and basename(cp) match */
	if ((base = strrchr(cp, '/')) != NULL)
	    base++;
	else
	    base = cp;
	if (strcmp(user_base, base) != 0 ||
	    stat(cp, &sudoers_stat) == -1)
	    continue;
	if (user_stat == NULL ||
	    (user_stat->st_dev == sudoers_stat.st_dev &&
	    user_stat->st_ino == sudoers_stat.st_ino)) {
	    efree(safe_cmnd);
	    safe_cmnd = estrdup(cp);
	    break;
	}
    }
    globfree(&gl);
    if (cp == NULL)
	return FALSE;

    if (command_args_match(sudoers_cmnd, sudoers_args)) {
	efree(safe_cmnd);
	safe_cmnd = estrdup(user_cmnd);
	return TRUE;
    }
    return FALSE;
}

static int
command_matches_normal(char *sudoers_cmnd, char *sudoers_args)
{
    struct stat sudoers_stat;
    char *base;
    size_t dlen;

    /* If it ends in '/' it is a directory spec. */
    dlen = strlen(sudoers_cmnd);
    if (sudoers_cmnd[dlen - 1] == '/')
	return command_matches_dir(sudoers_cmnd, dlen);

    /* Only proceed if user_base and basename(sudoers_cmnd) match */
    if ((base = strrchr(sudoers_cmnd, '/')) == NULL)
	base = sudoers_cmnd;
    else
	base++;
    if (strcmp(user_base, base) != 0 ||
	stat(sudoers_cmnd, &sudoers_stat) == -1)
	return FALSE;

    /*
     * Return true if inode/device matches AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none req by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     */
    if (user_stat != NULL &&
	(user_stat->st_dev != sudoers_stat.st_dev ||
	user_stat->st_ino != sudoers_stat.st_ino))
	return FALSE;
    if (command_args_match(sudoers_cmnd, sudoers_args)) {
	efree(safe_cmnd);
	safe_cmnd = estrdup(sudoers_cmnd);
	return TRUE;
    }
    return FALSE;
}

/*
 * Return TRUE if user_cmnd names one of the inodes in dir, else FALSE.
 */
static int
command_matches_dir(char *sudoers_dir, size_t dlen)
{
    struct stat sudoers_stat;
    struct dirent *dent;
    char buf[PATH_MAX];
    DIR *dirp;

    /*
     * Grot through directory entries, looking for user_base.
     */
    dirp = opendir(sudoers_dir);
    if (dirp == NULL)
	return FALSE;

    if (strlcpy(buf, sudoers_dir, sizeof(buf)) >= sizeof(buf)) {
	closedir(dirp);
	return FALSE;
    }
    while ((dent = readdir(dirp)) != NULL) {
	/* ignore paths > PATH_MAX (XXX - log) */
	buf[dlen] = '\0';
	if (strlcat(buf, dent->d_name, sizeof(buf)) >= sizeof(buf))
	    continue;

	/* only stat if basenames are the same */
	if (strcmp(user_base, dent->d_name) != 0 ||
	    stat(buf, &sudoers_stat) == -1)
	    continue;
	if (user_stat->st_dev == sudoers_stat.st_dev &&
	    user_stat->st_ino == sudoers_stat.st_ino) {
	    efree(safe_cmnd);
	    safe_cmnd = estrdup(buf);
	    break;
	}
    }

    closedir(dirp);
    return dent != NULL;
}

static int
addr_matches_if(char *n)
{
    union sudo_in_addr_un addr;
    struct interface *ifp;
#ifdef HAVE_IN6_ADDR
    int j;
#endif
    int family;

#ifdef HAVE_IN6_ADDR
    if (inet_pton(AF_INET6, n, &addr.ip6) > 0) {
	family = AF_INET6;
    } else
#endif
    {
	family = AF_INET;
	addr.ip4.s_addr = inet_addr(n);
    }

    for (ifp = interfaces; ifp != NULL; ifp = ifp->next) {
	if (ifp->family != family)
	    continue;
	switch(family) {
	    case AF_INET:
		if (ifp->addr.ip4.s_addr == addr.ip4.s_addr ||
		    (ifp->addr.ip4.s_addr & ifp->netmask.ip4.s_addr)
		    == addr.ip4.s_addr)
		    return TRUE;
		break;
#ifdef HAVE_IN6_ADDR
	    case AF_INET6:
		if (memcmp(ifp->addr.ip6.s6_addr, addr.ip6.s6_addr,
		    sizeof(addr.ip6.s6_addr)) == 0)
		    return TRUE;
		for (j = 0; j < sizeof(addr.ip6.s6_addr); j++) {
		    if ((ifp->addr.ip6.s6_addr[j] & ifp->netmask.ip6.s6_addr[j]) != addr.ip6.s6_addr[j])
			break;
		}
		if (j == sizeof(addr.ip6.s6_addr))
		    return TRUE;
#endif
	}
    }

    return FALSE;
}

static int
addr_matches_if_netmask(char *n, char *m)
{
    int i;
    union sudo_in_addr_un addr, mask;
    struct interface *ifp;
#ifdef HAVE_IN6_ADDR
    int j;
#endif
    int family;

#ifdef HAVE_IN6_ADDR
    if (inet_pton(AF_INET6, n, &addr.ip6) > 0)
	family = AF_INET6;
    else
#endif
    {
	family = AF_INET;
	addr.ip4.s_addr = inet_addr(n);
    }

    if (family == AF_INET) {
	if (strchr(m, '.'))
	    mask.ip4.s_addr = inet_addr(m);
	else {
	    i = 32 - atoi(m);
	    mask.ip4.s_addr = 0xffffffff;
	    mask.ip4.s_addr >>= i;
	    mask.ip4.s_addr <<= i;
	    mask.ip4.s_addr = htonl(mask.ip4.s_addr);
	}
    }
#ifdef HAVE_IN6_ADDR
    else {
	if (inet_pton(AF_INET6, m, &mask.ip6) <= 0) {
	    j = atoi(m);
	    for (i = 0; i < 16; i++) {
		if (j < i * 8)
		    mask.ip6.s6_addr[i] = 0;
		else if (i * 8 + 8 <= j)
		    mask.ip6.s6_addr[i] = 0xff;
		else
		    mask.ip6.s6_addr[i] = 0xff00 >> (j - i * 8);
	    }
	}
    }
#endif /* HAVE_IN6_ADDR */

    for (ifp = interfaces; ifp != NULL; ifp = ifp->next) {
	if (ifp->family != family)
	    continue;
	switch(family) {
	    case AF_INET:
		if ((ifp->addr.ip4.s_addr & mask.ip4.s_addr) == addr.ip4.s_addr)
		    return TRUE;
#ifdef HAVE_IN6_ADDR
	    case AF_INET6:
		for (j = 0; j < sizeof(addr.ip6.s6_addr); j++) {
		    if ((ifp->addr.ip6.s6_addr[j] & mask.ip6.s6_addr[j]) != addr.ip6.s6_addr[j])
			break;
		}
		if (j == sizeof(addr.ip6.s6_addr))
		    return TRUE;
#endif /* HAVE_IN6_ADDR */
	}
    }

    return FALSE;
}

/*
 * Returns TRUE if "n" is one of our ip addresses or if
 * "n" is a network that we are on, else returns FALSE.
 */
int
addr_matches(char *n)
{
    char *m;
    int retval;

    /* If there's an explicit netmask, use it. */
    if ((m = strchr(n, '/'))) {
	*m++ = '\0';
	retval = addr_matches_if_netmask(n, m);
	*(m - 1) = '/';
    } else
	retval = addr_matches_if(n);

    return retval;
}

/*
 * Returns TRUE if the hostname matches the pattern, else FALSE
 */
int
hostname_matches(char *shost, char *lhost, char *pattern)
{
    if (has_meta(pattern)) {
	if (strchr(pattern, '.'))
	    return !fnmatch(pattern, lhost, FNM_CASEFOLD);
	else
	    return !fnmatch(pattern, shost, FNM_CASEFOLD);
    } else {
	if (strchr(pattern, '.'))
	    return !strcasecmp(lhost, pattern);
	else
	    return !strcasecmp(shost, pattern);
    }
}

/*
 *  Returns TRUE if the user/uid from sudoers matches the specified user/uid,
 *  else returns FALSE.
 */
int
userpw_matches(char *sudoers_user, char *user, struct passwd *pw)
{
    if (pw != NULL && *sudoers_user == '#') {
	uid_t uid = (uid_t) atoi(sudoers_user + 1);
	if (uid == pw->pw_uid)
	    return TRUE;
    }
    return strcmp(sudoers_user, user) == 0;
}

/*
 *  Returns TRUE if the group/gid from sudoers matches the specified group/gid,
 *  else returns FALSE.
 */
int
group_matches(char *sudoers_group, struct group *gr)
{
    if (*sudoers_group == '#') {
	gid_t gid = (gid_t) atoi(sudoers_group + 1);
	if (gid == gr->gr_gid)
	    return TRUE;
    }
    return strcmp(gr->gr_name, sudoers_group) == 0;
}

/*
 *  Returns TRUE if the given user belongs to the named group,
 *  else returns FALSE.
 */
int
usergr_matches(char *group, char *user, struct passwd *pw)
{
    int matched = FALSE;
    struct passwd *pw0 = NULL;

    /* make sure we have a valid usergroup, sudo style */
    if (*group++ != '%')
	goto done;

    if (*group == ':' && def_group_plugin) {
	matched = group_plugin_query(user, group + 1, pw);
	goto done;
    }

    /* look up user's primary gid in the passwd file */
    if (pw == NULL) {
	if ((pw0 = sudo_getpwnam(user)) == NULL)
	    goto done;
	pw = pw0;
    }

    if (user_in_group(pw, group)) {
	matched = TRUE;
	goto done;
    }

    /* not a Unix group, could be an external group */
    if (def_group_plugin && group_plugin_query(user, group, pw)) {
	matched = TRUE;
	goto done;
    }

done:
    if (pw0 != NULL)
	pw_delref(pw0);

    return matched;
}

/*
 * Returns TRUE if "host" and "user" belong to the netgroup "netgr",
 * else return FALSE.  Either of "host", "shost" or "user" may be NULL
 * in which case that argument is not checked...
 *
 * XXX - swap order of host & shost
 */
int
netgr_matches(char *netgr, char *lhost, char *shost, char *user)
{
    static char *domain;
#ifdef HAVE_GETDOMAINNAME
    static int initialized;
#endif

    /* make sure we have a valid netgroup, sudo style */
    if (*netgr++ != '+')
	return FALSE;

#ifdef HAVE_GETDOMAINNAME
    /* get the domain name (if any) */
    if (!initialized) {
	domain = (char *) emalloc(MAXHOSTNAMELEN + 1);
	if (getdomainname(domain, MAXHOSTNAMELEN + 1) == -1 || *domain == '\0') {
	    efree(domain);
	    domain = NULL;
	}
	initialized = 1;
    }
#endif /* HAVE_GETDOMAINNAME */

#ifdef HAVE_INNETGR
    if (innetgr(netgr, lhost, user, domain))
	return TRUE;
    else if (lhost != shost && innetgr(netgr, shost, user, domain))
	return TRUE;
#endif /* HAVE_INNETGR */

    return FALSE;
}
