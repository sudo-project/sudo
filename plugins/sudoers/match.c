/*
 * Copyright (c) 1996, 1998-2005, 2007-2016
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
#include <sys/stat.h>
#ifdef HAVE_SYS_SYSTEMINFO_H
# include <sys/systeminfo.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <unistd.h>
#ifndef SUDOERS_NAME_MATCH
# ifdef HAVE_GLOB
#  include <glob.h>
# else
#  include "compat/glob.h"
# endif /* HAVE_GLOB */
#endif /* SUDOERS_NAME_MATCH */
#ifdef HAVE_NETGROUP_H
# include <netgroup.h>
#else
# include <netdb.h>
#endif /* HAVE_NETGROUP_H */
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#include "sudoers.h"
#include "parse.h"
#include <gram.h>

#ifdef HAVE_FNMATCH
# include <fnmatch.h>
#else
# include "compat/fnmatch.h"
#endif /* HAVE_FNMATCH */
#ifdef HAVE_SHA224UPDATE
# include <sha2.h>
#else
# include "compat/sha2.h"
#endif

static struct member_list empty = TAILQ_HEAD_INITIALIZER(empty);

static bool command_matches_dir(const char *sudoers_dir, size_t dlen);
#ifndef SUDOERS_NAME_MATCH
static bool command_matches_glob(const char *sudoers_cmnd, const char *sudoers_args);
#endif
static bool command_matches_fnmatch(const char *sudoers_cmnd, const char *sudoers_args);
static bool command_matches_normal(const char *sudoers_cmnd, const char *sudoers_args, const struct sudo_digest *digest);

/*
 * Returns true if string 's' contains meta characters.
 */
#define has_meta(s)	(strpbrk(s, "\\?*[]") != NULL)

/*
 * Check for user described by pw in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
userlist_matches(const struct passwd *pw, const struct member_list *list)
{
    struct member *m;
    struct alias *a;
    int rval, matched = UNSPEC;
    debug_decl(userlist_matches, SUDOERS_DEBUG_MATCH)

    TAILQ_FOREACH_REVERSE(m, list, member_list, entries) {
	switch (m->type) {
	    case ALL:
		matched = !m->negated;
		break;
	    case NETGROUP:
		if (netgr_matches(m->name,
		    def_netgroup_tuple ? user_runhost : NULL,
		    def_netgroup_tuple ? user_srunhost : NULL, pw->pw_name))
		    matched = !m->negated;
		break;
	    case USERGROUP:
		if (usergr_matches(m->name, pw->pw_name, pw))
		    matched = !m->negated;
		break;
	    case ALIAS:
		if ((a = alias_get(m->name, USERALIAS)) != NULL) {
		    rval = userlist_matches(pw, &a->members);
		    if (rval != UNSPEC)
			matched = m->negated ? !rval : rval;
		    alias_put(a);
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
    debug_return_int(matched);
}

/*
 * Check for user described by pw in a list of members.
 * If both lists are empty compare against def_runas_default.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
runaslist_matches(const struct member_list *user_list,
    const struct member_list *group_list, struct member **matching_user,
    struct member **matching_group)
{
    struct member *m;
    struct alias *a;
    int rval;
    int user_matched = UNSPEC;
    int group_matched = UNSPEC;
    debug_decl(runaslist_matches, SUDOERS_DEBUG_MATCH)

    if (runas_pw != NULL) {
	/* If no runas user or runas group listed in sudoers, use default. */
	if (user_list == NULL && group_list == NULL)
	    debug_return_int(userpw_matches(def_runas_default, runas_pw->pw_name, runas_pw));

	if (user_list != NULL) {
	    TAILQ_FOREACH_REVERSE(m, user_list, member_list, entries) {
		switch (m->type) {
		    case ALL:
			user_matched = !m->negated;
			break;
		    case NETGROUP:
			if (netgr_matches(m->name,
			    def_netgroup_tuple ? user_runhost : NULL,
			    def_netgroup_tuple ? user_srunhost : NULL,
			    runas_pw->pw_name))
			    user_matched = !m->negated;
			break;
		    case USERGROUP:
			if (usergr_matches(m->name, runas_pw->pw_name, runas_pw))
			    user_matched = !m->negated;
			break;
		    case ALIAS:
			if ((a = alias_get(m->name, RUNASALIAS)) != NULL) {
			    rval = runaslist_matches(&a->members, &empty,
				matching_user, NULL);
			    if (rval != UNSPEC)
				user_matched = m->negated ? !rval : rval;
			    alias_put(a);
			    break;
			}
			/* FALLTHROUGH */
		    case WORD:
			if (userpw_matches(m->name, runas_pw->pw_name, runas_pw))
			    user_matched = !m->negated;
			break;
		    case MYSELF:
			if (!ISSET(sudo_user.flags, RUNAS_USER_SPECIFIED) ||
			    strcmp(user_name, runas_pw->pw_name) == 0)
			    user_matched = !m->negated;
			break;
		}
		if (user_matched != UNSPEC) {
		    if (matching_user != NULL && m->type != ALIAS)
			*matching_user = m;
		    break;
		}
	    }
	}
    }

    if (runas_gr != NULL) {
	if (user_matched == UNSPEC) {
	    if (runas_pw == NULL || strcmp(runas_pw->pw_name, user_name) == 0)
		user_matched = ALLOW;	/* only changing group */
	}
	if (group_list != NULL) {
	    TAILQ_FOREACH_REVERSE(m, group_list, member_list, entries) {
		switch (m->type) {
		    case ALL:
			group_matched = !m->negated;
			break;
		    case ALIAS:
			if ((a = alias_get(m->name, RUNASALIAS)) != NULL) {
			    rval = runaslist_matches(&empty, &a->members,
				NULL, matching_group);
			    if (rval != UNSPEC)
				group_matched = m->negated ? !rval : rval;
			    alias_put(a);
			    break;
			}
			/* FALLTHROUGH */
		    case WORD:
			if (group_matches(m->name, runas_gr))
			    group_matched = !m->negated;
			break;
		}
		if (group_matched != UNSPEC) {
		    if (matching_group != NULL && m->type != ALIAS)
			*matching_group = m;
		    break;
		}
	    }
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

/*
 * Check for host and shost in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
hostlist_matches(const struct passwd *pw, const struct member_list *list)
{
    struct member *m;
    struct alias *a;
    int rval, matched = UNSPEC;
    debug_decl(hostlist_matches, SUDOERS_DEBUG_MATCH)

    TAILQ_FOREACH_REVERSE(m, list, member_list, entries) {
	switch (m->type) {
	    case ALL:
		matched = !m->negated;
		break;
	    case NETGROUP:
		if (netgr_matches(m->name, user_runhost, user_srunhost,
		    pw->pw_name))
		    matched = !m->negated;
		break;
	    case NTWKADDR:
		if (addr_matches(m->name))
		    matched = !m->negated;
		break;
	    case ALIAS:
		if ((a = alias_get(m->name, HOSTALIAS)) != NULL) {
		    rval = hostlist_matches(pw, &a->members);
		    if (rval != UNSPEC)
			matched = m->negated ? !rval : rval;
		    alias_put(a);
		    break;
		}
		/* FALLTHROUGH */
	    case WORD:
		if (hostname_matches(user_srunhost, user_runhost, m->name))
		    matched = !m->negated;
		break;
	}
	if (matched != UNSPEC)
	    break;
    }
    debug_return_int(matched);
}

/*
 * Check for cmnd and args in a list of members.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
cmndlist_matches(const struct member_list *list)
{
    struct member *m;
    int matched = UNSPEC;
    debug_decl(cmndlist_matches, SUDOERS_DEBUG_MATCH)

    TAILQ_FOREACH_REVERSE(m, list, member_list, entries) {
	matched = cmnd_matches(m);
	if (matched != UNSPEC)
	    break;
    }
    debug_return_int(matched);
}

/*
 * Check cmnd and args.
 * Returns ALLOW, DENY or UNSPEC.
 */
int
cmnd_matches(const struct member *m)
{
    struct alias *a;
    struct sudo_command *c;
    int rval, matched = UNSPEC;
    debug_decl(cmnd_matches, SUDOERS_DEBUG_MATCH)

    switch (m->type) {
	case ALL:
	    matched = !m->negated;
	    break;
	case ALIAS:
	    if ((a = alias_get(m->name, CMNDALIAS)) != NULL) {
		rval = cmndlist_matches(&a->members);
		if (rval != UNSPEC)
		    matched = m->negated ? !rval : rval;
		alias_put(a);
	    }
	    break;
	case COMMAND:
	    c = (struct sudo_command *)m->name;
	    if (command_matches(c->cmnd, c->args, c->digest))
		matched = !m->negated;
	    break;
    }
    debug_return_int(matched);
}

static bool
command_args_match(const char *sudoers_cmnd, const char *sudoers_args)
{
    int flags = 0;
    debug_decl(command_args_match, SUDOERS_DEBUG_MATCH)

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
command_matches(const char *sudoers_cmnd, const char *sudoers_args, const struct sudo_digest *digest)
{
    bool rc = false;
    debug_decl(command_matches, SUDOERS_DEBUG_MATCH)

    /* Check for pseudo-commands */
    if (sudoers_cmnd[0] != '/') {
	/*
	 * Return true if both sudoers_cmnd and user_cmnd are "sudoedit" AND
	 *  a) there are no args in sudoers OR
	 *  b) there are no args on command line and none req by sudoers OR
	 *  c) there are args in sudoers and on command line and they match
	 */
	if (strcmp(sudoers_cmnd, "sudoedit") == 0 &&
	    strcmp(user_cmnd, "sudoedit") == 0 &&
	    command_args_match(sudoers_cmnd, sudoers_args)) {
	    /* No need to set safe_cmnd since user_cmnd matches sudoers_cmnd */
	    rc = true;
	}
	goto done;
    }

    if (has_meta(sudoers_cmnd)) {
	/*
	 * If sudoers_cmnd has meta characters in it, we need to
	 * use glob(3) and/or fnmatch(3) to do the matching.
	 */
#ifdef SUDOERS_NAME_MATCH
	rc = command_matches_fnmatch(sudoers_cmnd, sudoers_args);
#else
	if (def_fast_glob)
	    rc = command_matches_fnmatch(sudoers_cmnd, sudoers_args);
	else
	    rc = command_matches_glob(sudoers_cmnd, sudoers_args);
#endif
    } else {
	rc = command_matches_normal(sudoers_cmnd, sudoers_args, digest);
    }
done:
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"user command \"%s%s%s\" matches sudoers command \"%s%s%s\": %s",
	user_cmnd, user_args ? " " : "", user_args ? user_args : "",
	sudoers_cmnd, sudoers_args ? " " : "", sudoers_args ? sudoers_args : "",
	rc ? "true" : "false");
    debug_return_bool(rc);
}

static bool
command_matches_fnmatch(const char *sudoers_cmnd, const char *sudoers_args)
{
    debug_decl(command_matches_fnmatch, SUDOERS_DEBUG_MATCH)

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
	/* No need to set safe_cmnd since user_cmnd matches sudoers_cmnd */
	debug_return_bool(true);
    }
    debug_return_bool(false);
}

#ifndef SUDOERS_NAME_MATCH
static bool
command_matches_glob(const char *sudoers_cmnd, const char *sudoers_args)
{
    struct stat sudoers_stat;
    size_t dlen;
    char **ap, *base, *cp;
    glob_t gl;
    debug_decl(command_matches_glob, SUDOERS_DEBUG_MATCH)

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
    if (glob(sudoers_cmnd, GLOB_NOSORT, NULL, &gl) != 0 || gl.gl_pathc == 0) {
	globfree(&gl);
	debug_return_bool(false);
    }
    /* If user_cmnd is fully-qualified, check for an exact match. */
    if (user_cmnd[0] == '/') {
	for (ap = gl.gl_pathv; (cp = *ap) != NULL; ap++) {
	    if (strcmp(cp, user_cmnd) != 0 || stat(cp, &sudoers_stat) == -1)
		continue;
	    if (user_stat == NULL ||
		(user_stat->st_dev == sudoers_stat.st_dev &&
		user_stat->st_ino == sudoers_stat.st_ino)) {
		free(safe_cmnd);
		if ((safe_cmnd = strdup(cp)) == NULL) {
		    sudo_warnx(U_("%s: %s"), __func__,
			U_("unable to allocate memory"));
		    cp = NULL;		/* fail closed */
		}
	    } else {
		/* Paths match, but st_dev and st_ino are different. */
		cp = NULL;		/* fail closed */
	    }
	    goto done;
	}
    }
    /* No exact match, compare basename, st_dev and st_ino. */
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
	    free(safe_cmnd);
	    if ((safe_cmnd = strdup(cp)) == NULL) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		cp = NULL;		/* fail closed */
	    }
	    goto done;
	}
    }
done:
    globfree(&gl);
    if (cp == NULL)
	debug_return_bool(false);

    if (command_args_match(sudoers_cmnd, sudoers_args)) {
	/* safe_cmnd was set above. */
	debug_return_bool(true);
    }
    debug_return_bool(false);
}
#endif /* SUDOERS_NAME_MATCH */

#ifdef SUDOERS_NAME_MATCH
static bool
command_matches_normal(const char *sudoers_cmnd, const char *sudoers_args, const struct sudo_digest *digest)
{
    size_t dlen;
    debug_decl(command_matches_normal, SUDOERS_DEBUG_MATCH)

    dlen = strlen(sudoers_cmnd);

    /* If it ends in '/' it is a directory spec. */
    if (sudoers_cmnd[dlen - 1] == '/')
	debug_return_bool(command_matches_dir(sudoers_cmnd, dlen));

    if (strcmp(user_cmnd, sudoers_cmnd) == 0) {
	if (command_args_match(sudoers_cmnd, sudoers_args)) {
	    free(safe_cmnd);
	    if ((safe_cmnd = strdup(sudoers_cmnd)) != NULL)
		debug_return_bool(true);
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	}
    }
    debug_return_bool(false);
}
#else /* !SUDOERS_NAME_MATCH */

static struct digest_function {
    const char *digest_name;
    const unsigned int digest_len;
    void (*init)(SHA2_CTX *);
#ifdef SHA2_VOID_PTR
    void (*update)(SHA2_CTX *, const void *, size_t);
    void (*final)(void *, SHA2_CTX *);
#else
    void (*update)(SHA2_CTX *, const unsigned char *, size_t);
    void (*final)(unsigned char *, SHA2_CTX *);
#endif
} digest_functions[] = {
    {
	"SHA224",
	SHA224_DIGEST_LENGTH,
	SHA224Init,
	SHA224Update,
	SHA224Final
    }, {
	"SHA256",
	SHA256_DIGEST_LENGTH,
	SHA256Init,
	SHA256Update,
	SHA256Final
    }, {
	"SHA384",
	SHA384_DIGEST_LENGTH,
	SHA384Init,
	SHA384Update,
	SHA384Final
    }, {
	"SHA512",
	SHA512_DIGEST_LENGTH,
	SHA512Init,
	SHA512Update,
	SHA512Final
    }, {
	NULL
    }
};

static bool
digest_matches(const char *file, const struct sudo_digest *sd, int *fd)
{
    unsigned char file_digest[SHA512_DIGEST_LENGTH];
    unsigned char sudoers_digest[SHA512_DIGEST_LENGTH];
    unsigned char buf[32 * 1024];
    struct digest_function *func = NULL;
#ifdef HAVE_FEXECVE
    bool first = true;
    bool is_script = false;
#endif /* HAVE_FEXECVE */
    size_t nread;
    SHA2_CTX ctx;
    FILE *fp;
    unsigned int i;
    debug_decl(digest_matches, SUDOERS_DEBUG_MATCH)

    for (i = 0; digest_functions[i].digest_name != NULL; i++) {
	if (sd->digest_type == i) {
	    func = &digest_functions[i];
	    break;
	}
    }
    if (func == NULL) {
	sudo_warnx(U_("unsupported digest type %d for %s"), sd->digest_type, file);
	debug_return_bool(false);
    }
    if (strlen(sd->digest_str) == func->digest_len * 2) {
	/* Convert the command digest from ascii hex to binary. */
	for (i = 0; i < func->digest_len; i++) {
	    const int h = hexchar(&sd->digest_str[i + i]);
	    if (h == -1)
		goto bad_format;
	    sudoers_digest[i] = (unsigned char)h;
	}
    } else {
	size_t len = base64_decode(sd->digest_str, sudoers_digest,
	    sizeof(sudoers_digest));
	if (len != func->digest_len) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"incorrect length for digest, expected %u, got %zu",
		func->digest_len, len);
	    goto bad_format;
	}
    }

    if ((fp = fopen(file, "r")) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "unable to open %s: %s",
	    file, strerror(errno));
	debug_return_bool(false);
    }

    func->init(&ctx);
    while ((nread = fread(buf, 1, sizeof(buf), fp)) != 0) {
#ifdef HAVE_FEXECVE
	/* Check for #! cookie and set is_script. */
	if (first) {
	    first = false;
	    if (nread >= 2 && buf[0] == '#' && buf[1] == '!')
		is_script = true;
	}
#endif /* HAVE_FEXECVE */
	func->update(&ctx, buf, nread);
    }
    if (ferror(fp)) {
	sudo_warnx(U_("%s: read error"), file);
	fclose(fp);
	debug_return_bool(false);
    }
    func->final(file_digest, &ctx);

    if (memcmp(file_digest, sudoers_digest, func->digest_len) != 0) {
	fclose(fp);
	sudo_debug_printf(SUDO_DEBUG_DIAG|SUDO_DEBUG_LINENO,
	    "%s digest mismatch for %s, expecting %s",
	    func->digest_name, file, sd->digest_str);
	debug_return_bool(false);
    }

#ifdef HAVE_FEXECVE
    /*
     * On systems with fexecve(2) we can use that to execute the
     * matching command even when the directory is writable.
     */
    if ((*fd = dup(fileno(fp))) == -1) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "unable to dup %s: %s",
	    file, strerror(errno));
	fclose(fp);
	debug_return_bool(false);
    }
    /*
     * Shell scripts go through namei twice and so we can't set the close
     * on exec flag on the fd for fexecve(2).
     */
    if (!is_script)
	(void)fcntl(*fd, F_SETFD, FD_CLOEXEC);
#endif /* HAVE_FEXECVE */
    fclose(fp);
    debug_return_bool(true);
bad_format:
    sudo_warnx(U_("digest for %s (%s) is not in %s form"), file,
	sd->digest_str, func->digest_name);
    debug_return_bool(false);
}

static bool
command_matches_normal(const char *sudoers_cmnd, const char *sudoers_args, const struct sudo_digest *digest)
{
    struct stat sudoers_stat;
    const char *base;
    size_t dlen;
    debug_decl(command_matches_normal, SUDOERS_DEBUG_MATCH)

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
     *  d) there is a digest and it matches
     */
    if (user_stat != NULL &&
	(user_stat->st_dev != sudoers_stat.st_dev ||
	user_stat->st_ino != sudoers_stat.st_ino))
	debug_return_bool(false);
    if (!command_args_match(sudoers_cmnd, sudoers_args))
	debug_return_bool(false);
    if (cmnd_fd != -1) {
	close(cmnd_fd);
	cmnd_fd = -1;
    }
    if (digest != NULL && !digest_matches(sudoers_cmnd, digest, &cmnd_fd)) {
	/* XXX - log functions not available but we should log very loudly */
	debug_return_bool(false);
    }
    free(safe_cmnd);
    if ((safe_cmnd = strdup(sudoers_cmnd)) == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	debug_return_bool(false);
    }
    debug_return_bool(true);
}
#endif /* SUDOERS_NAME_MATCH */

#ifdef SUDOERS_NAME_MATCH
/*
 * Return true if user_cmnd begins with sudoers_dir, else false.
 * Note that sudoers_dir include the trailing '/'
 */
static bool
command_matches_dir(const char *sudoers_dir, size_t dlen)
{
    debug_decl(command_matches_dir, SUDOERS_DEBUG_MATCH)
    debug_return_bool(strncmp(user_cmnd, sudoers_dir, dlen) == 0);
}
#else /* !SUDOERS_NAME_MATCH */
/*
 * Return true if user_cmnd names one of the inodes in dir, else false.
 */
static bool
command_matches_dir(const char *sudoers_dir, size_t dlen)
{
    struct stat sudoers_stat;
    struct dirent *dent;
    char buf[PATH_MAX];
    DIR *dirp;
    debug_decl(command_matches_dir, SUDOERS_DEBUG_MATCH)

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
	    free(safe_cmnd);
	    if ((safe_cmnd = strdup(buf)) == NULL) {
		sudo_warnx(U_("%s: %s"), __func__,
		    U_("unable to allocate memory"));
		dent = NULL;
	    }
	    break;
	}
    }

    closedir(dirp);
    debug_return_bool(dent != NULL);
}
#endif /* SUDOERS_NAME_MATCH */

/*
 * Returns true if the hostname matches the pattern, else false
 */
bool
hostname_matches(const char *shost, const char *lhost, const char *pattern)
{
    const char *host;
    bool rc;
    debug_decl(hostname_matches, SUDOERS_DEBUG_MATCH)

    host = strchr(pattern, '.') != NULL ? lhost : shost;
    if (has_meta(pattern)) {
	rc = !fnmatch(pattern, host, FNM_CASEFOLD);
    } else {
	rc = !strcasecmp(host, pattern);
    }
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"host %s matches sudoers pattern %s: %s",
	host, pattern, rc ? "true" : "false");
    debug_return_bool(rc);
}

/*
 * Returns true if the user/uid from sudoers matches the specified user/uid,
 * else returns false.
 */
bool
userpw_matches(const char *sudoers_user, const char *user, const struct passwd *pw)
{
    const char *errstr;
    uid_t uid;
    bool rc;
    debug_decl(userpw_matches, SUDOERS_DEBUG_MATCH)

    if (pw != NULL && *sudoers_user == '#') {
	uid = (uid_t) sudo_strtoid(sudoers_user + 1, NULL, NULL, &errstr);
	if (errstr == NULL && uid == pw->pw_uid) {
	    rc = true;
	    goto done;
	}
    }
    rc = strcmp(sudoers_user, user) == 0;
done:
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"user %s matches sudoers user %s: %s",
	user, sudoers_user, rc ? "true" : "false");
    debug_return_bool(rc);
}

/*
 * Returns true if the group/gid from sudoers matches the specified group/gid,
 * else returns false.
 */
bool
group_matches(const char *sudoers_group, const struct group *gr)
{
    const char *errstr;
    gid_t gid;
    bool rc;
    debug_decl(group_matches, SUDOERS_DEBUG_MATCH)

    if (*sudoers_group == '#') {
	gid = (gid_t) sudo_strtoid(sudoers_group + 1, NULL, NULL, &errstr);
	if (errstr == NULL && gid == gr->gr_gid) {
	    rc = true;
	    goto done;
	}
    }
    rc = strcmp(gr->gr_name, sudoers_group) == 0;
done:
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"group %s matches sudoers group %s: %s",
	gr->gr_name, sudoers_group, rc ? "true" : "false");
    debug_return_bool(rc);
}

/*
 * Returns true if the given user belongs to the named group,
 * else returns false.
 */
bool
usergr_matches(const char *group, const char *user, const struct passwd *pw)
{
    bool matched = false;
    struct passwd *pw0 = NULL;
    debug_decl(usergr_matches, SUDOERS_DEBUG_MATCH)

    /* Make sure we have a valid usergroup, sudo style */
    if (*group++ != '%') {
	sudo_debug_printf(SUDO_DEBUG_DIAG, "user group %s has no leading '%%'",
	    group);
	goto done;
    }

    /* Query group plugin for %:name groups. */
    if (*group == ':' && def_group_plugin) {
	if (group_plugin_query(user, group + 1, pw) == true)
	    matched = true;
	goto done;
    }

    /* Look up user's primary gid in the passwd file. */
    if (pw == NULL) {
	if ((pw0 = sudo_getpwnam(user)) == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_DIAG, "unable to find %s in passwd db",
		user);
	    goto done;
	}
	pw = pw0;
    }

    if (user_in_group(pw, group)) {
	matched = true;
	goto done;
    }

    /* Query the group plugin for Unix groups too? */
    if (def_group_plugin && def_always_query_group_plugin) {
	if (group_plugin_query(user, group, pw) == true) {
	    matched = true;
	    goto done;
	}
    }

done:
    if (pw0 != NULL)
	sudo_pw_delref(pw0);

    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"user %s matches group %s: %s", user, group, matched ? "true" : "false");
    debug_return_bool(matched);
}

/*
 * Get NIS-style domain name and copy from static storage or NULL if none.
 */
#if defined(HAVE_GETDOMAINNAME) || defined(SI_SRPC_DOMAIN)
const char *
sudo_getdomainname(void)
{
    static char *domain;
    static bool initialized;
    debug_decl(sudo_getdomainname, SUDOERS_DEBUG_MATCH)

    if (!initialized) {
	size_t host_name_max;
	int rval;

# ifdef _SC_HOST_NAME_MAX
	host_name_max = (size_t)sysconf(_SC_HOST_NAME_MAX);
	if (host_name_max == (size_t)-1)
# endif
	    host_name_max = 255;    /* POSIX and historic BSD */

	domain = malloc(host_name_max + 1);
	if (domain != NULL) {
# ifdef SI_SRPC_DOMAIN
	    domain[0] = '\0';
	    rval = sysinfo(SI_SRPC_DOMAIN, domain, host_name_max + 1);
# else
	    rval = getdomainname(domain, host_name_max + 1);
# endif
	    if (rval != -1 && domain[0] != '\0') {
		const char *cp;

		for (cp = domain; *cp != '\0'; cp++) {
		    /* Check for illegal characters, Linux may use "(none)". */
		    if (*cp == '(' || *cp == ')' || *cp == ',' || *cp == ' ') {
			free(domain);
			domain = NULL;
			break;
		    }
		}
	    }
	} else {
	    /* XXX - want to pass error back to caller */
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to allocate memory");
	}
	initialized = true;
    }
    debug_return_str(domain);
}
#else
const char *
sudo_getdomainname(void)
{
    debug_decl(sudo_getdomainname, SUDOERS_DEBUG_MATCH)
    debug_return_ptr(NULL);
}
#endif /* HAVE_GETDOMAINNAME || SI_SRPC_DOMAIN */

/*
 * Returns true if "host" and "user" belong to the netgroup "netgr",
 * else return false.  Either of "lhost", "shost" or "user" may be NULL
 * in which case that argument is not checked...
 */
bool
netgr_matches(const char *netgr, const char *lhost, const char *shost, const char *user)
{
#ifdef HAVE_INNETGR
    const char *domain;
#endif
    bool rc = false;
    debug_decl(netgr_matches, SUDOERS_DEBUG_MATCH)

    if (!def_use_netgroups) {
	sudo_debug_printf(SUDO_DEBUG_INFO, "netgroups are disabled");
	debug_return_bool(false);
    }

#ifdef HAVE_INNETGR
    /* make sure we have a valid netgroup, sudo style */
    if (*netgr++ != '+') {
	sudo_debug_printf(SUDO_DEBUG_DIAG, "netgroup %s has no leading '+'",
	    netgr);
	debug_return_bool(false);
    }

    /* get the domain name (if any) */
    domain = sudo_getdomainname();

    if (innetgr(netgr, lhost, user, domain))
	rc = true;
    else if (lhost != shost && innetgr(netgr, shost, user, domain))
	rc = true;

    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"netgroup %s matches (%s|%s, %s, %s): %s", netgr, lhost ? lhost : "",
	shost ? shost : "", user ? user : "", domain ? domain : "",
	rc ? "true" : "false");
#endif /* HAVE_INNETGR */

    debug_return_bool(rc);
}
