/*
 * Copyright (c) 1996, 1998-2004 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include "config.h"

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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_FNMATCH
# include <fnmatch.h>
#endif /* HAVE_FNMATCH */
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

#include "sudo.h"
#include "parse.h"
#include "interfaces.h"

#ifndef HAVE_FNMATCH
# include "emul/fnmatch.h"
#endif /* HAVE_FNMATCH */

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Globals
 */
int parse_error = FALSE;
extern int keepall;
extern FILE *yyin, *yyout;

/*
 * Prototypes
 */
static int has_meta	__P((char *));
       void init_parser	__P((void));

/*
 * Look up the user in the sudoers file and check to see if they are
 * allowed to run the specified command on this host as the target user.
 */
int
sudoers_lookup(pwflag)
    int pwflag;
{
    int error, nopass;
    enum def_tupple pwcheck;

    /* Become sudoers file owner */
    set_perms(PERM_SUDOERS);

    /* We opened _PATH_SUDOERS in check_sudoers() so just rewind it. */
    rewind(sudoers_fp);
    yyin = sudoers_fp;
    yyout = stdout;

    /* Allocate space for data structures in the parser. */
    init_parser();

    /* If pwcheck *could* be "all" or "any", keep more state. */
    if (pwflag > 0)
	keepall = TRUE;

    /* Need to be root while stat'ing things in the parser. */
    set_perms(PERM_ROOT);
    error = yyparse();

    /* Close the sudoers file now that we are done with it. */
    (void) fclose(sudoers_fp);
    sudoers_fp = NULL;

    if (error || parse_error)
	return(VALIDATE_ERROR);

    /*
     * The pw options may have changed during sudoers parse so we
     * wait until now to set this.
     */
    if (pwflag)
	pwcheck = (pwflag == -1) ? never : sudo_defs_table[pwflag].sd_un.tuple;
    else
	pwcheck = 0;

    /*
     * Assume the worst.  If the stack is empty the user was
     * not mentioned at all.
     */
    if (def_authenticate)
	error = VALIDATE_NOT_OK;
    else
	error = VALIDATE_NOT_OK | FLAG_NOPASS;
    if (pwcheck) {
	SET(error, FLAG_NO_CHECK);
    } else {
	SET(error, FLAG_NO_HOST);
	if (!top)
	    SET(error, FLAG_NO_USER);
    }

    /*
     * Only check the actual command if pwflag is not set.
     * It is set for the "validate", "list" and "kill" pseudo-commands.
     * Always check the host and user.
     */
    nopass = -1;
    if (pwflag) {
	int found;

	if (pwcheck == always && def_authenticate)
	    nopass = FLAG_CHECK_USER;
	else if (pwcheck == never || !def_authenticate)
	    nopass = FLAG_NOPASS;
	found = 0;
	while (top) {
	    if (host_matches == TRUE) {
		found = 1;
		if (pwcheck == any && no_passwd == TRUE)
		    nopass = FLAG_NOPASS;
		else if (pwcheck == all && nopass != 0)
		    nopass = (no_passwd == TRUE) ? FLAG_NOPASS : 0;
	    }
	    top--;
	}
	if (found) {
	    if (nopass == -1)
		nopass = 0;
	    return(VALIDATE_OK | nopass);
	}
    } else {
	while (top) {
	    if (host_matches == TRUE) {
		CLR(error, FLAG_NO_HOST);
		if (runas_matches == TRUE && cmnd_matches == TRUE) {
		    /*
		     * User was granted access to cmnd on host as user.
		     */
		    return(VALIDATE_OK |
			(no_passwd == TRUE ? FLAG_NOPASS : 0) |
			(no_execve == TRUE ? FLAG_NOEXEC : 0));
		} else if ((runas_matches == TRUE && cmnd_matches == FALSE) ||
		    (runas_matches == FALSE && cmnd_matches == TRUE)) {
		    /*
		     * User was explicitly denied access to cmnd on host.
		     */
		    return(VALIDATE_NOT_OK |
			(no_passwd == TRUE ? FLAG_NOPASS : 0) |
			(no_execve == TRUE ? FLAG_NOEXEC : 0));
		}
	    }
	    top--;
	}
    }

    /*
     * The user was neither explicitly granted nor denied access.
     */
    if (nopass == -1)
	nopass = 0;
    return(error | nopass);
}

/*
 * If path doesn't end in /, return TRUE iff cmnd & path name the same inode;
 * otherwise, return TRUE if cmnd names one of the inodes in path.
 */
int
command_matches(cmnd, cmnd_args, path, sudoers_args)
    char *cmnd;
    char *cmnd_args;
    char *path;
    char *sudoers_args;
{
    int plen, error;
    static struct stat cst;
    struct stat pst;
    DIR *dirp;
    struct dirent *dent;
    char buf[PATH_MAX];
    static char *cmnd_base;

    /* Check for pseudo-commands */
    if (*cmnd != '/') {
	/*
	 * Return true if cmnd is "sudoedit" AND
	 *  a) there are no args in sudoers OR
	 *  b) there are no args on command line and none req by sudoers OR
	 *  c) there are args in sudoers and on command line and they match
	 */
	if (strcmp(cmnd, "sudoedit") != 0)
	    return(FALSE);
	if (!sudoers_args ||
	    (!cmnd_args && sudoers_args && !strcmp("\"\"", sudoers_args)) ||
	    (sudoers_args &&
	     fnmatch(sudoers_args, cmnd_args ? cmnd_args : "", 0) == 0)) {
	    if (safe_cmnd)
		free(safe_cmnd);
	    safe_cmnd = estrdup(path);
	    return(TRUE);
	} else
	    return(FALSE);
    }

    plen = strlen(path);

    /* Only need to stat cmnd once since it never changes */
    if (cst.st_dev == 0) {
	if ((error = stat(cmnd, &cst))) {
	    if (runas_pw->pw_uid != 0) {
		set_perms(PERM_RUNAS);
		error = stat(cmnd, &cst);
		set_perms(PERM_ROOT);
	    }
	    if (error)
		return(FALSE);
	}
	if ((cmnd_base = strrchr(cmnd, '/')) == NULL)
	    cmnd_base = cmnd;
	else
	    cmnd_base++;
    }

    /*
     * If the pathname has meta characters in it use fnmatch(3)
     * to do the matching
     */
    if (has_meta(path)) {
	/*
	 * Return true if fnmatch(3) succeeds AND
	 *  a) there are no args in sudoers OR
	 *  b) there are no args on command line and none required by sudoers OR
	 *  c) there are args in sudoers and on command line and they match
	 * else return false.
	 */
	if (fnmatch(path, cmnd, FNM_PATHNAME) != 0)
	    return(FALSE);
	if (!sudoers_args ||
	    (!cmnd_args && sudoers_args && !strcmp("\"\"", sudoers_args)) ||
	    (sudoers_args &&
	     fnmatch(sudoers_args, cmnd_args ? cmnd_args : "", 0) == 0)) {
	    if (safe_cmnd)
		free(safe_cmnd);
	    safe_cmnd = estrdup(user_cmnd);
	    return(TRUE);
	} else
	    return(FALSE);
    } else {
	/*
	 * No meta characters
	 * Check to make sure this is not a directory spec (doesn't end in '/')
	 */
	if (path[plen - 1] != '/') {
	    char *p;

	    /* Only proceed if the basenames of cmnd and path are the same */
	    if ((p = strrchr(path, '/')) == NULL)
		p = path;
	    else
		p++;
	    if (strcmp(cmnd_base, p) != 0 || stat(path, &pst) == -1)
		return(FALSE);

	    /*
	     * Return true if inode/device matches AND
	     *  a) there are no args in sudoers OR
	     *  b) there are no args on command line and none req by sudoers OR
	     *  c) there are args in sudoers and on command line and they match
	     */
	    if (cst.st_dev != pst.st_dev || cst.st_ino != pst.st_ino)
		return(FALSE);
	    if (!sudoers_args ||
		(!cmnd_args && sudoers_args && !strcmp("\"\"", sudoers_args)) ||
		(sudoers_args &&
		 fnmatch(sudoers_args, cmnd_args ? cmnd_args : "", 0) == 0)) {
		if (safe_cmnd)
		    free(safe_cmnd);
		safe_cmnd = estrdup(path);
		return(TRUE);
	    } else
		return(FALSE);
	}

	/*
	 * Grot through path's directory entries, looking for cmnd.
	 */
	dirp = opendir(path);
	if (dirp == NULL)
	    return(FALSE);

	while ((dent = readdir(dirp)) != NULL) {
	    /* ignore paths > PATH_MAX (XXX - log) */
	    if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf) ||
		strlcat(buf, dent->d_name, sizeof(buf)) >= sizeof(buf))
		continue;

	    /* only stat if basenames are the same */
	    if (strcmp(cmnd_base, dent->d_name) != 0 || stat(buf, &pst) == -1)
		continue;
	    if (cst.st_dev == pst.st_dev && cst.st_ino == pst.st_ino) {
		if (safe_cmnd)
		    free(safe_cmnd);
		safe_cmnd = estrdup(buf);
		break;
	    }
	}

	closedir(dirp);
	return(dent != NULL);
    }
}

/*
 * Returns TRUE if "n" is one of our ip addresses or if
 * "n" is a network that we are on, else returns FALSE.
 */
int
addr_matches(n)
    char *n;
{
    int i;
    char *m;
    struct in_addr addr, mask;

    /* If there's an explicit netmask, use it. */
    if ((m = strchr(n, '/'))) {
	*m++ = '\0';
	addr.s_addr = inet_addr(n);
	if (strchr(m, '.'))
	    mask.s_addr = inet_addr(m);
	else {
	    i = 32 - atoi(m);
	    mask.s_addr = 0xffffffff;
	    mask.s_addr >>= i;
	    mask.s_addr <<= i;
	    mask.s_addr = htonl(mask.s_addr);
	}
	*(m - 1) = '/';

	for (i = 0; i < num_interfaces; i++)
	    if ((interfaces[i].addr.s_addr & mask.s_addr) == addr.s_addr)
		return(TRUE);
    } else {
	addr.s_addr = inet_addr(n);

	for (i = 0; i < num_interfaces; i++)
	    if (interfaces[i].addr.s_addr == addr.s_addr ||
		(interfaces[i].addr.s_addr & interfaces[i].netmask.s_addr)
		== addr.s_addr)
		return(TRUE);
    }

    return(FALSE);
}

/*
 * Returns 0 if the hostname matches the pattern and non-zero otherwise.
 */
int
hostname_matches(shost, lhost, pattern)
    char *shost;
    char *lhost;
    char *pattern;
{
    if (has_meta(pattern)) {
	if (strchr(pattern, '.'))
	    return(fnmatch(pattern, lhost, FNM_CASEFOLD));
	else
	    return(fnmatch(pattern, shost, FNM_CASEFOLD));
    } else {
	if (strchr(pattern, '.'))
	    return(strcasecmp(lhost, pattern));
	else
	    return(strcasecmp(shost, pattern));
    }
}

/*
 *  Returns TRUE if the user/uid from sudoers matches the specified user/uid,
 *  else returns FALSE.
 */
int
userpw_matches(sudoers_user, user, pw)
    char *sudoers_user;
    char *user;
    struct passwd *pw;
{
    if (pw != NULL && *sudoers_user == '#') {
	uid_t uid = atoi(sudoers_user + 1);
	if (uid == pw->pw_uid)
	    return(1);
    }
    return(strcmp(sudoers_user, user) == 0);
}

/*
 *  Returns TRUE if the given user belongs to the named group,
 *  else returns FALSE.
 *  XXX - reduce the number of passwd/group lookups
 */
int
usergr_matches(group, user, pw)
    char *group;
    char *user;
    struct passwd *pw;
{
    struct group *grp;
    gid_t pw_gid;
    char **cur;

    /* make sure we have a valid usergroup, sudo style */
    if (*group++ != '%')
	return(FALSE);

    /* look up user's primary gid in the passwd file */
    if (pw == NULL && (pw = getpwnam(user)) == NULL)
	return(FALSE);
    pw_gid = pw->pw_gid;

    if ((grp = getgrnam(group)) == NULL) 
	return(FALSE);

    /* check against user's primary (passwd file) gid */
    if (grp->gr_gid == pw_gid)
	return(TRUE);

    /* check to see if user is explicitly listed in the group */
    for (cur = grp->gr_mem; *cur; cur++) {
	if (strcmp(*cur, user) == 0)
	    return(TRUE);
    }

    return(FALSE);
}

/*
 * Returns TRUE if "host" and "user" belong to the netgroup "netgr",
 * else return FALSE.  Either of "host", "shost" or "user" may be NULL
 * in which case that argument is not checked...
 */
int
netgr_matches(netgr, host, shost, user)
    char *netgr;
    char *host;
    char *shost;
    char *user;
{
#ifdef HAVE_GETDOMAINNAME
    static char *domain = (char *) -1;
#else
    static char *domain = NULL;
#endif /* HAVE_GETDOMAINNAME */

    /* make sure we have a valid netgroup, sudo style */
    if (*netgr++ != '+')
	return(FALSE);

#ifdef HAVE_GETDOMAINNAME
    /* get the domain name (if any) */
    if (domain == (char *) -1) {
	domain = (char *) emalloc(MAXHOSTNAMELEN);
	if (getdomainname(domain, MAXHOSTNAMELEN) == -1 || *domain == '\0') {
	    free(domain);
	    domain = NULL;
	}
    }
#endif /* HAVE_GETDOMAINNAME */

#ifdef HAVE_INNETGR
    if (innetgr(netgr, host, user, domain))
	return(TRUE);
    else if (host != shost && innetgr(netgr, shost, user, domain))
	return(TRUE);
#endif /* HAVE_INNETGR */

    return(FALSE);
}

/*
 * Returns TRUE if "s" has shell meta characters in it,
 * else returns FALSE.
 */
static int
has_meta(s)
    char *s;
{
    char *t;
    
    for (t = s; *t; t++) {
	if (*t == '\\' || *t == '?' || *t == '*' || *t == '[' || *t == ']')
	    return(TRUE);
    }
    return(FALSE);
}
