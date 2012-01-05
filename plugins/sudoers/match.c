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
#include "parse.h"
#include <gram.h>

#ifndef HAVE_FNMATCH
# include "compat/fnmatch.h"
#endif /* HAVE_FNMATCH */
#ifndef HAVE_EXTENDED_GLOB
# include "compat/glob.h"
#endif /* HAVE_EXTENDED_GLOB */

static struct member_list empty;

static bool command_matches_dir(char *, size_t);
static bool command_matches_glob(char *, char *);
static bool command_matches_fnmatch(char *, char *);
static bool command_matches_normal(char *, char *);

/*
 * Returns true if string 's' contains meta characters.
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
    debug_decl(_userlist_matches, SUDO_DEBUG_MATCH)

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
    debug_return_bool(matched);
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
    debug_decl(_runaslist_matches, SUDO_DEBUG_MATCH)

    if (runas_pw != NULL) {
	/* If no runas user or runas group listed in sudoers, use default. */
	if (tq_empty(user_list) && tq_empty(group_list))
	    debug_return_int(userpw_matches(def_runas_default, runas_pw->pw_name, runas_pw));

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
			rval = _runaslist_matches(&empty, &a->members);
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
	if (group_matched == UNSPEC) {
	    if (runas_pw != NULL && runas_pw->pw_gid == runas_gr->gr_gid)
		group_matched = ALLOW;	/* runas group matches passwd db */
	}
    }

    if (user_matched == DENY || group_matched == DENY)
	debug_return_int(DENY);
    if (user_matched == group_matched || runas_gr == NULL)
	debug_return_int(user_matched);
    debug_return_int(UNSPEC);
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
    debug_decl(_hostlist_matches, SUDO_DEBUG_MATCH)

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
    debug_return_bool(matched);
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
    debug_decl(_cmndlist_matches, SUDO_DEBUG_MATCH)

    tq_foreach_rev(list, m) {
	matched = cmnd_matches(m);
	if (matched != UNSPEC)
	    break;
    }
    debug_return_bool(matched);
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
    debug_decl(cmnd_matches, SUDO_DEBUG_MATCH)

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
    debug_return_bool(matched);
}

static bool
command_args_match(sudoers_cmnd, sudoers_args)
    char *sudoers_cmnd;
    char *sudoers_args;
{
    int flags = 0;
    debug_decl(command_args_match, SUDO_DEBUG_MATCH)

    /*
     * If no args specified in sudoers, any user args are allowed.
     * If the empty string is specified in sudoers, no user args are allowed.
     */
    if (!sudoers_args ||
	(!user_args && sudoers_args && !strcmp("\"\"", sudoers_args)))
	debug_return_bool(true);
    /*
     * If args are specified in sudoers, they must match the user args.
     * If running as sudoedit, all args are assumed to be paths.
     */
    if (sudoers_args) {
	/* For sudoedit, all args are assumed to be pathnames. */
	if (strcmp(sudoers_cmnd, "sudoedit") == 0)
	    flags = FNM_PATHNAME;
	if (fnmatch(sudoers_args, user_args ? user_args : "", flags) == 0)
	    debug_return_bool(true);
    }
    debug_return_bool(false);
}

/*
 * If path doesn't end in /, return true iff cmnd & path name the same inode;
 * otherwise, return true if user_cmnd names one of the inodes in path.
 */
bool
command_matches(char *sudoers_cmnd, char *sudoers_args)
{
    debug_decl(command_matches, SUDO_DEBUG_MATCH)

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
	    debug_return_bool(false);
	if (command_args_match(sudoers_cmnd, sudoers_args)) {
	    efree(safe_cmnd);
	    safe_cmnd = estrdup(sudoers_cmnd);
	    debug_return_bool(true);
	} else
	    debug_return_bool(false);
    }

    if (has_meta(sudoers_cmnd)) {
	/*
	 * If sudoers_cmnd has meta characters in it, we need to
	 * use glob(3) and/or fnmatch(3) to do the matching.
	 */
	if (def_fast_glob)
	    debug_return_bool(command_matches_fnmatch(sudoers_cmnd, sudoers_args));
	debug_return_bool(command_matches_glob(sudoers_cmnd, sudoers_args));
    }
    debug_return_bool(command_matches_normal(sudoers_cmnd, sudoers_args));
}

static bool
command_matches_fnmatch(char *sudoers_cmnd, char *sudoers_args)
{
    debug_decl(command_matches_fnmatch, SUDO_DEBUG_MATCH)

    /*
     * Return true if fnmatch(3) succeeds AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none required by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     * else return false.
     */
    if (fnmatch(sudoers_cmnd, user_cmnd, FNM_PATHNAME) != 0)
	debug_return_bool(false);
    if (command_args_match(sudoers_cmnd, sudoers_args)) {
	if (safe_cmnd)
	    free(safe_cmnd);
	safe_cmnd = estrdup(user_cmnd);
	debug_return_bool(true);
    }
    debug_return_bool(false);
}

static bool
command_matches_glob(char *sudoers_cmnd, char *sudoers_args)
{
    struct stat sudoers_stat;
    size_t dlen;
    char **ap, *base, *cp;
    glob_t gl;
    debug_decl(command_matches_glob, SUDO_DEBUG_MATCH)

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
		debug_return_bool(false);
	}
    }
    /*
     * Return true if we find a match in the glob(3) results AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none required by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     * else return false.
     */
#define GLOB_FLAGS	(GLOB_NOSORT | GLOB_BRACE | GLOB_TILDE)
    if (glob(sudoers_cmnd, GLOB_FLAGS, NULL, &gl) != 0 || gl.gl_pathc == 0) {
	globfree(&gl);
	debug_return_bool(false);
    }
    /* For each glob match, compare basename, st_dev and st_ino. */
    for (ap = gl.gl_pathv; (cp = *ap) != NULL; ap++) {
	/* If it ends in '/' it is a directory spec. */
	dlen = strlen(cp);
	if (cp[dlen - 1] == '/') {
	    if (command_matches_dir(cp, dlen))
		debug_return_bool(true);
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
	debug_return_bool(false);

    if (command_args_match(sudoers_cmnd, sudoers_args)) {
	efree(safe_cmnd);
	safe_cmnd = estrdup(user_cmnd);
	debug_return_bool(true);
    }
    debug_return_bool(false);
}

static bool
command_matches_normal(char *sudoers_cmnd, char *sudoers_args)
{
    struct stat sudoers_stat;
    char *base;
    size_t dlen;
    debug_decl(command_matches_normal, SUDO_DEBUG_MATCH)

    /* If it ends in '/' it is a directory spec. */
    dlen = strlen(sudoers_cmnd);
    if (sudoers_cmnd[dlen - 1] == '/')
	debug_return_bool(command_matches_dir(sudoers_cmnd, dlen));

    /* Only proceed if user_base and basename(sudoers_cmnd) match */
    if ((base = strrchr(sudoers_cmnd, '/')) == NULL)
	base = sudoers_cmnd;
    else
	base++;
    if (strcmp(user_base, base) != 0 ||
	stat(sudoers_cmnd, &sudoers_stat) == -1)
	debug_return_bool(false);

    /*
     * Return true if inode/device matches AND
     *  a) there are no args in sudoers OR
     *  b) there are no args on command line and none req by sudoers OR
     *  c) there are args in sudoers and on command line and they match
     */
    if (user_stat != NULL &&
	(user_stat->st_dev != sudoers_stat.st_dev ||
	user_stat->st_ino != sudoers_stat.st_ino))
	debug_return_bool(false);
    if (command_args_match(sudoers_cmnd, sudoers_args)) {
	efree(safe_cmnd);
	safe_cmnd = estrdup(sudoers_cmnd);
	debug_return_bool(true);
    }
    debug_return_bool(false);
}

/*
 * Return true if user_cmnd names one of the inodes in dir, else false.
 */
static bool
command_matches_dir(char *sudoers_dir, size_t dlen)
{
    struct stat sudoers_stat;
    struct dirent *dent;
    char buf[PATH_MAX];
    DIR *dirp;
    debug_decl(command_matches_dir, SUDO_DEBUG_MATCH)

    /*
     * Grot through directory entries, looking for user_base.
     */
    dirp = opendir(sudoers_dir);
    if (dirp == NULL)
	debug_return_bool(false);

    if (strlcpy(buf, sudoers_dir, sizeof(buf)) >= sizeof(buf)) {
	closedir(dirp);
	debug_return_bool(false);
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
	if (user_stat == NULL ||
	    (user_stat->st_dev == sudoers_stat.st_dev &&
	    user_stat->st_ino == sudoers_stat.st_ino)) {
	    efree(safe_cmnd);
	    safe_cmnd = estrdup(buf);
	    break;
	}
    }

    closedir(dirp);
    debug_return_bool(dent != NULL);
}

/*
 * Returns true if the hostname matches the pattern, else false
 */
bool
hostname_matches(char *shost, char *lhost, char *pattern)
{
    debug_decl(hostname_matches, SUDO_DEBUG_MATCH)

    if (has_meta(pattern)) {
	if (strchr(pattern, '.'))
	    debug_return_bool(!fnmatch(pattern, lhost, FNM_CASEFOLD));
	else
	    debug_return_bool(!fnmatch(pattern, shost, FNM_CASEFOLD));
    } else {
	if (strchr(pattern, '.'))
	    debug_return_bool(!strcasecmp(lhost, pattern));
	else
	    debug_return_bool(!strcasecmp(shost, pattern));
    }
}

/*
 *  Returns true if the user/uid from sudoers matches the specified user/uid,
 *  else returns false.
 */
bool
userpw_matches(char *sudoers_user, char *user, struct passwd *pw)
{
    debug_decl(userpw_matches, SUDO_DEBUG_MATCH)

    if (pw != NULL && *sudoers_user == '#') {
	uid_t uid = (uid_t) atoi(sudoers_user + 1);
	if (uid == pw->pw_uid)
	    debug_return_bool(true);
    }
    debug_return_bool(strcmp(sudoers_user, user) == 0);
}

/*
 *  Returns true if the group/gid from sudoers matches the specified group/gid,
 *  else returns false.
 */
bool
group_matches(char *sudoers_group, struct group *gr)
{
    debug_decl(group_matches, SUDO_DEBUG_MATCH)

    if (*sudoers_group == '#') {
	gid_t gid = (gid_t) atoi(sudoers_group + 1);
	if (gid == gr->gr_gid)
	    debug_return_bool(true);
    }
    debug_return_bool(strcmp(gr->gr_name, sudoers_group) == 0);
}

/*
 *  Returns true if the given user belongs to the named group,
 *  else returns false.
 */
bool
usergr_matches(char *group, char *user, struct passwd *pw)
{
    int matched = false;
    struct passwd *pw0 = NULL;
    debug_decl(usergr_matches, SUDO_DEBUG_MATCH)

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
	matched = true;
	goto done;
    }

    /* not a Unix group, could be an external group */
    if (def_group_plugin && group_plugin_query(user, group, pw)) {
	matched = true;
	goto done;
    }

done:
    if (pw0 != NULL)
	pw_delref(pw0);

    debug_return_bool(matched);
}

/*
 * Returns true if "host" and "user" belong to the netgroup "netgr",
 * else return false.  Either of "host", "shost" or "user" may be NULL
 * in which case that argument is not checked...
 *
 * XXX - swap order of host & shost
 */
bool
netgr_matches(char *netgr, char *lhost, char *shost, char *user)
{
    static char *domain;
#ifdef HAVE_GETDOMAINNAME
    static int initialized;
#endif
    debug_decl(netgr_matches, SUDO_DEBUG_MATCH)

    /* make sure we have a valid netgroup, sudo style */
    if (*netgr++ != '+')
	debug_return_bool(false);

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
	debug_return_bool(true);
    else if (lhost != shost && innetgr(netgr, shost, user, domain))
	debug_return_bool(true);
#endif /* HAVE_INNETGR */

    debug_return_bool(false);
}
