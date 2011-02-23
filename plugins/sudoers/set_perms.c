/*
 * Copyright (c) 1994-1996,1998-2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include <pwd.h>
#include <errno.h>
#include <grp.h>
#ifdef HAVE_LOGIN_CAP_H
# include <login_cap.h>
#endif

#include "sudoers.h"

/*
 * Prototypes
 */
static void runas_setgroups(void);

/*
 * We keep track of the current permisstions and use a stack to restore
 * the old permissions.  A depth of 16 is overkill.
 */
struct perm_state {
    uid_t ruid;
    uid_t euid;
#ifdef HAVE_SETRESUID
    uid_t suid;
#endif
    gid_t rgid;
    gid_t egid;
#ifdef HAVE_SETRESUID
    gid_t sgid;
#endif
    GETGROUPS_T *groups;
    int ngroups;
};

#define PERM_STACK_MAX	16
static struct perm_state perm_stack[PERM_STACK_MAX];
static int perm_stack_depth = 0;

/* XXX - make a runas_user struct? */
int runas_ngroups = -1;
#ifdef HAVE_GETGROUPS
GETGROUPS_T *runas_groups;
#endif

#undef ID
#define ID(x) (state->x == ostate->x ? -1 : state->x)
#undef OID
#define OID(x) (ostate->x == state->x ? -1 : ostate->x)

void
rewind_perms(void)
{
    while (perm_stack_depth > 1)
	restore_perms();
}

#ifdef HAVE_SETRESUID

/*
 * Set real and effective and saved uids and gids based on perm.
 * We always retain a saved uid of 0 unless we are headed for an exec().
 * We only flip the effective gid since it only changes for PERM_SUDOERS.
 * This version of set_perms() works fine with the "stay_setuid" option.
 */
int
set_perms(int perm)
{
    struct perm_state *state, *ostate = NULL;
    const char *errstr;
    int noexit;

    noexit = ISSET(perm, PERM_NOEXIT);
    CLR(perm, PERM_MASK);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = "perm stack overflow";
	errno = EINVAL;
	goto bad;
    }

    state = &perm_stack[perm_stack_depth];
    if (perm_stack_depth)
	ostate = &perm_stack[perm_stack_depth - 1];

    if (perm != PERM_INITIAL && memcmp(state, ostate, sizeof(*state)) == 0)
	goto done;

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
#ifdef HAVE_GETRESUID
	if (getresuid(&state->ruid, &state->euid, &state->suid)) {
	    errstr = "getresuid";
	    goto bad;

	}
	if (getresgid(&state->rgid, &state->egid, &state->sgid)) {
	    errstr = "getresgid";
	    goto bad;
	}
#else
	state->ruid = getuid();
	state->euid = geteuid();
	state->suid = state->euid; /* in case we are setuid */

	state->rgid = getgid();
	state->egid = getegid();
	state->sgid = state->egid; /* in case we are setgid */
#endif
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	break;

    case PERM_ROOT:
	state->ruid = ROOT_UID;
	state->euid = ROOT_UID;
	state->suid = ROOT_UID;
	if (setresuid(ID(ruid), ID(euid), ID(suid))) {
	    errstr = "setresuid(ROOT_UID, ROOT_UID, ROOT_UID)";
	    goto bad;
	}
	state->rgid = -1;
	state->egid = -1;
	state->sgid = -1;
	state->groups = NULL;
	state->ngroups = -1;
	break;

    case PERM_USER:
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	if (state->ngroups != -1 && state->groups != ostate->groups) {
	    if (setgroups(state->ngroups, state->groups)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->rgid = -1;
	state->egid = user_gid;
	state->sgid = -1;
	if (setresgid(-1, ID(egid), -1)) {
	    errstr = "setresgid(-1, user_gid, -1)";
	    goto bad;
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	state->suid = ROOT_UID;
	if (setresuid(ID(ruid), ID(euid), ID(suid))) {
	    errstr = "setresuid(user_uid, user_uid, ROOT_UID)";
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	/* headed for exec() */
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	if (state->ngroups != -1 && state->groups != ostate->groups) {
	    if (setgroups(state->ngroups, state->groups)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->rgid = user_gid;
	state->egid = user_gid;
	state->sgid = user_gid;
	if (setresgid(ID(rgid), ID(egid), ID(sgid))) {
	    errstr = "setresgid(user_gid, user_gid, user_gid)";
	    goto bad;
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	state->suid = user_uid;
	if (setresuid(ID(ruid), ID(euid), ID(suid))) {
	    errstr = "setresuid(user_uid, user_uid, user_uid)";
	    goto bad;
	}
	break;

    case PERM_RUNAS:
	runas_setgroups();
	state->groups = runas_groups;
	state->ngroups = runas_ngroups;

	state->rgid = -1;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	state->sgid = -1;
	if (setresgid(-1, ID(egid), -1)) {
	    errstr = "unable to change to runas gid";
	    goto bad;
	}
	state->ruid = -1;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	state->suid = -1;
	if (setresuid(-1, ID(euid), -1)) {
	    errstr = "unable to change to runas uid";
	    goto bad;
	}
	break;

    case PERM_SUDOERS:
	state->groups = NULL;
	state->ngroups = -1;

	/* assumes euid == ROOT_UID, ruid == user */
	state->rgid = -1;
	state->egid = sudoers_gid;
	state->sgid = -1;
	if (setresgid(-1, ID(egid), -1))
	    error(1, "unable to change to sudoers gid");

	state->ruid = ROOT_UID;
	/*
	 * If sudoers_uid == ROOT_UID and sudoers_mode is group readable
	 * we use a non-zero uid in order to avoid NFS lossage.
	 * Using uid 1 is a bit bogus but should work on all OS's.
	 */
	if (sudoers_uid == ROOT_UID && (sudoers_mode & 040))
	    state->euid = 1;
	else
	    state->euid = sudoers_uid;
	state->suid = ROOT_UID;
	if (setresuid(ID(ruid), ID(euid), ID(suid))) {
	    errstr = "setresuid(ROOT_UID, SUDOERS_UID, ROOT_UID)";
	    goto bad;
	}
	break;

    case PERM_TIMESTAMP:
	state->groups = NULL;
	state->ngroups = -1;
	state->rgid = -1;
	state->egid = -1;
	state->sgid = -1;
	state->ruid = ROOT_UID;
	state->euid = timestamp_uid;
	state->suid = ROOT_UID;
	if (setresuid(ID(ruid), ID(euid), ID(suid))) {
	    errstr = "setresuid(ROOT_UID, timestamp_uid, ROOT_UID)";
	    goto bad;
	}
	break;
    }

done:
    perm_stack_depth++;
    return 1;
bad:
    /* XXX - better warnings inline */
    warningx("%s: %s", errstr,
	errno == EAGAIN ? "too many processes" : strerror(errno));
    if (noexit)
	return 0;
    exit(1);
}

void
restore_perms(void)
{
    struct perm_state *state, *ostate;

    if (perm_stack_depth < 2)
	return;

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    /* XXX - more cases here where euid != ruid */
    if (OID(euid) == ROOT_UID && state->euid != ROOT_UID) {
	if (setresuid(-1, ROOT_UID, -1)) {
	    warning("setresuid() [%d, %d, %d] -> [%d, %d, %d]", state->ruid,
		state->euid, state->suid, -1, ROOT_UID, -1);
	    goto bad;
	}
    }
    if (setresuid(OID(ruid), OID(euid), OID(suid))) {
	warning("setresuid() [%d, %d, %d] -> [%d, %d, %d]", state->ruid,
	    state->euid, state->suid, OID(ruid), OID(euid), OID(suid));
	goto bad;
    }
    if (setresgid(OID(rgid), OID(egid), OID(sgid))) {
	warning("setresgid() [%d, %d, %d] -> [%d, %d, %d]", state->rgid,
	    state->egid, state->sgid, OID(rgid), OID(egid), OID(sgid));
	goto bad;
    }
    if (state->ngroups != -1 && state->groups != ostate->groups) {
	if (setgroups(ostate->ngroups, ostate->groups)) {
	    warning("setgroups()");
	    goto bad;
	}
    }
    return;

bad:
    exit(1);
}

#else
# ifdef HAVE_SETREUID

/*
 * Set real and effective uids and gids based on perm.
 * We always retain a real or effective uid of ROOT_UID unless
 * we are headed for an exec().
 * This version of set_perms() works fine with the "stay_setuid" option.
 */
int
set_perms(int perm)
{
    struct perm_state *state, *ostate = NULL;
    const char *errstr;
    int noexit;

    noexit = ISSET(perm, PERM_NOEXIT);
    CLR(perm, PERM_MASK);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = "perm stack overflow";
	errno = EINVAL;
	goto bad;
    }

    state = &perm_stack[perm_stack_depth];
    if (perm_stack_depth)
	ostate = &perm_stack[perm_stack_depth - 1];

    if (perm != PERM_INITIAL && memcmp(state, ostate, sizeof(*state)) == 0)
	goto done;

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
	state->ruid = getuid();
	state->euid = geteuid();
	state->rgid = getgid();
	state->egid = getegid();
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	break;

    case PERM_ROOT:
	/*
	 * setreuid(0, 0) may fail on some systems
	 * when the euid is not already 0.
	 */
	state->ruid = -1;
	state->euid = ROOT_UID;
	if (setreuid(ID(ruid), ID(euid))) {
	    errstr = "setreuid(-1, ROOT_UID)";
	    goto bad;
	}
	if (setuid(ROOT_UID)) {
	    errstr = "setuid(ROOT_UID)";
	    goto bad;
	}
	state->ruid = ROOT_UID;
	state->rgid = -1;
	state->egid = -1;
	state->groups = NULL;
	state->ngroups = -1;
	break;

    case PERM_USER:
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	if (state->ngroups != -1 && state->groups != ostate->groups) {
	    if (setgroups(state->ngroups, state->groups)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->rgid = -1;
	state->egid = user_gid;
	if (setregid(-1, ID(egid))) {
	    errstr = "setregid(-1, user_gid)";
	    goto bad;
	}
	state->ruid = ROOT_UID;
	state->euid = user_uid;
	if (setreuid(ID(ruid), ID(euid))) {
	    errstr = "setreuid(ROOT_UID, user_uid)";
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	/* headed for exec() */
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	if (state->ngroups != -1 && state->groups != ostate->groups) {
	    if (setgroups(state->ngroups, state->groups)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->rgid = user_gid;
	state->egid = user_gid;
	if (setregid(ID(rgid), ID(egid))) {
	    errstr = "setregid(user_gid, user_gid)";
	    goto bad;
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	if (setreuid(ID(ruid), ID(euid))) {
	    errstr = "setreuid(user_uid, user_uid)";
	    goto bad;
	}
	break;

    case PERM_RUNAS:
	runas_setgroups();
	state->groups = runas_groups;
	state->ngroups = runas_ngroups;

	state->rgid = -1;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	if (setregid(-1, ID(egid))) {
	    errstr = "unable to change to runas gid";
	    goto bad;
	}
	state->ruid = -1;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	if (setreuid(-1, ID(euid))) {
	    errstr = "unable to change to runas uid";
	    goto bad;
	}
	break;

    case PERM_SUDOERS:
	state->groups = NULL;
	state->ngroups = -1;

	/* assume euid == ROOT_UID, ruid == user */
	state->rgid = -1;
	state->egid = sudoers_gid;
	if (setregid(-1, ID(egid)))
	    error(1, "unable to change to sudoers gid");

	state->ruid = ROOT_UID;
	/*
	 * If sudoers_uid == ROOT_UID and sudoers_mode is group readable
	 * we use a non-zero uid in order to avoid NFS lossage.
	 * Using uid 1 is a bit bogus but should work on all OS's.
	 */
	if (sudoers_uid == ROOT_UID && (sudoers_mode & 040))
	    state->euid = 1;
	else
	    state->euid = sudoers_uid;
	if (setreuid(ID(ruid), ID(euid))) {
	    errstr = "setreuid(ROOT_UID, SUDOERS_UID)";
	    goto bad;
	}
	break;

    case PERM_TIMESTAMP:
	state->groups = NULL;
	state->ngroups = -1;
	state->rgid = -1;
	state->egid = -1;
	state->ruid = ROOT_UID;
	state->euid = timestamp_uid;
	if (setreuid(ID(ruid), ID(euid))) {
	    errstr = "setreuid(ROOT_UID, timestamp_uid)";
	    goto bad;
	}
	break;
    }

done:
    perm_stack_depth++;
    return 1;
bad:
    /* XXX - better warnings inline */
    warningx("%s: %s", errstr,
	errno == EAGAIN ? "too many processes" : strerror(errno));
    if (noexit)
	return 0;
    exit(1);
}

void
restore_perms(void)
{
    struct perm_state *state, *ostate;

    if (perm_stack_depth < 2)
	return;

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    /*
     * When changing euid to ROOT_UID, setreuid() may fail even if
     * the ruid is ROOT_UID so call setuid() first.
     */
    if (OID(euid) == ROOT_UID) {
	if (setuid(ROOT_UID)) {
	    warning("setuid()");
	    goto bad;
	}
    }
    if (setreuid(OID(ruid), OID(euid))) {
	warning("setreuid() [%d, %d] -> [%d, %d]", state->ruid,
	    state->euid, OID(ruid), OID(euid));
	goto bad;
    }
    if (setregid(OID(rgid), OID(egid))) {
	warning("setregid() [%d, %d] -> [%d, %d]", state->rgid,
	    state->egid, OID(rgid), OID(egid));
	goto bad;
    }
    if (state->ngroups != -1 && state->groups != ostate->groups) {
	if (setgroups(ostate->ngroups, ostate->groups)) {
	    warning("setgroups()");
	    goto bad;
	}
    }
    return;

bad:
    exit(1);
}

# else /* !HAVE_SETRESUID && !HAVE_SETREUID */
# ifdef HAVE_SETEUID

/*
 * Set real and effective uids and gids based on perm.
 * We always retain a real or effective uid of ROOT_UID unless
 * we are headed for an exec().
 * This version of set_perms() works fine with the "stay_setuid" option.
 */
int
set_perms(int perm)
{
    struct perm_state *state, *ostate = NULL;
    const char *errstr;
    int noexit;

    noexit = ISSET(perm, PERM_NOEXIT);
    CLR(perm, PERM_MASK);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = "perm stack overflow";
	errno = EINVAL;
	goto bad;
    }

    state = &perm_stack[perm_stack_depth];
    if (perm_stack_depth)
	ostate = &perm_stack[perm_stack_depth - 1];

    if (perm != PERM_INITIAL && memcmp(state, ostate, sizeof(*state)) == 0)
	goto done;

    /*
     * Since we only have setuid() and seteuid() and semantics
     * for these calls differ on various systems, we set
     * real and effective uids to ROOT_UID initially to be safe.
     */
    if (perm != PERM_INITIAL) {
	if (seteuid(ROOT_UID)) {
	    errstr = "seteuid(ROOT_UID)";
	    goto bad;
	}
	if (setuid(ROOT_UID)) {
	    errstr = "setuid(ROOT_UID)";
	    goto bad;
	}
    }

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
	state->ruid = getuid();
	state->euid = geteuid();
	state->rgid = getgid();
	state->egid = getegid();
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	break;

    case PERM_ROOT:
	/* We already set ruid/euid above. */
	state->ruid = ROOT_UID;
	state->euid = ROOT_UID;
	state->rgid = -1;
	state->egid = -1;
	state->groups = NULL;
	state->ngroups = -1;
	break;

    case PERM_USER:
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	if (state->ngroups != -1 && state->groups != ostate->groups) {
	    if (setgroups(state->ngroups, state->groups)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->rgid = -1;
	state->egid = user_gid;
	if (setegid(ID(egid))) {
	    errstr = "setegid(user_gid)";
	    goto bad;
	}
	state->ruid = ROOT_UID;
	state->euid = user_uid;
	if (seteuid(ID(euid))) {
	    errstr = "seteuid(user_uid)";
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	/* headed for exec() */
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	if (state->ngroups != -1 && state->groups != ostate->groups) {
	    if (setgroups(state->ngroups, state->groups)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->rgid = user_gid;
	state->egid = user_gid;
	if (setgid(user_gid)) {
	    errstr = "setgid(user_gid)";
	    goto bad;
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	if (setuid(user_uid)) {
	    errstr = "setuid(user_uid)";
	    goto bad;
	}
	break;

    case PERM_RUNAS:
	runas_setgroups();
	state->groups = runas_groups;
	state->ngroups = runas_ngroups;

	state->rgid = -1;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	if (setegid(ID(egid))) {
	    errstr = "unable to change to runas gid";
	    goto bad;
	}
	state->ruid = -1;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	if (seteuid(ID(euid))) {
	    errstr = "unable to change to runas uid";
	    goto bad;
	}
	break;

    case PERM_SUDOERS:
	state->groups = NULL;
	state->ngroups = -1;

	/* assume euid == ROOT_UID, ruid == user */
	state->rgid = -1;
	state->egid = sudoers_gid;
	if (setegid(ID(egid)))
	    error(1, "unable to change to sudoers gid");

	state->ruid = ROOT_UID;
	/*
	 * If sudoers_uid == ROOT_UID and sudoers_mode is group readable
	 * we use a non-zero uid in order to avoid NFS lossage.
	 * Using uid 1 is a bit bogus but should work on all OS's.
	 */
	if (sudoers_uid == ROOT_UID && (sudoers_mode & 040))
	    state->euid = 1;
	else
	    state->euid = sudoers_uid;
	if (seteuid(ID(euid))) {
	    errstr = "seteuid(SUDOERS_UID)";
	    goto bad;
	}
	break;

    case PERM_TIMESTAMP:
	state->groups = NULL;
	state->ngroups = -1;
	state->rgid = -1;
	state->egid = -1;
	state->ruid = ROOT_UID;
	state->euid = timestamp_uid;
	if (seteuid(ID(euid))) {
	    errstr = "seteuid(timestamp_uid)";
	    goto bad;
	}
	break;
    }

done:
    perm_stack_depth++;
    return 1;
bad:
    /* XXX - better warnings inline */
    warningx("%s: %s", errstr,
	errno == EAGAIN ? "too many processes" : strerror(errno));
    if (noexit)
	return 0;
    exit(1);
}

void
restore_perms(void)
{
    struct perm_state *state, *ostate;

    if (perm_stack_depth < 2)
	return;

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    /*
     * Since we only have setuid() and seteuid() and semantics
     * for these calls differ on various systems, we set
     * real and effective uids to ROOT_UID initially to be safe.
     */
    if (seteuid(ROOT_UID)) {
	errstr = "seteuid(ROOT_UID)";
	goto bad;
    }
    if (setuid(ROOT_UID)) {
	errstr = "setuid(ROOT_UID)";
	goto bad;
    }

    if (setegid(OID(egid))) {
	warning("setegid(%d)", OID(egid));
	goto bad;
    }
    if (state->ngroups != -1 && state->groups != ostate->groups) {
	if (setgroups(ostate->ngroups, ostate->groups)) {
	    warning("setgroups()");
	    goto bad;
	}
    }
    if (seteuid(OID(euid))) {
	warning("seteuid(%d)", OID(euid));
	goto bad;
    }
    return;

bad:
    exit(1);
}

# else /* !HAVE_SETRESUID && !HAVE_SETREUID && !HAVE_SETEUID */

/*
 * Set uids and gids based on perm via setuid() and setgid().
 * NOTE: does not support the "stay_setuid" or timestampowner options.
 *       Also, sudoers_uid and sudoers_gid are not used.
 */
int
set_perms(int perm)
{
    struct perm_state *state, *ostate = NULL;
    const char *errstr;
    int noexit;

    noexit = ISSET(perm, PERM_NOEXIT);
    CLR(perm, PERM_MASK);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = "perm stack overflow";
	errno = EINVAL;
	goto bad;
    }

    state = &perm_stack[perm_stack_depth];
    if (perm_stack_depth)
	ostate = &perm_stack[perm_stack_depth - 1];

    if (perm != PERM_INITIAL && memcmp(state, ostate, sizeof(*state)) == 0)
	goto done;

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
	state->ruid = getuid();
	state->rgid = getgid();
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	break;

    case PERM_ROOT:
	state->ruid = ROOT_UID;
	state->rgid = -1;
	state->groups = NULL;
	state->ngroups = -1;
	if (setuid(ROOT_UID)) {
	    errstr = "setuid(ROOT_UID)";
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	state->groups = user_groups;
	state->ngroups = user_ngroups;
	if (state->ngroups != -1 && state->groups != ostate->groups) {
	    if (setgroups(state->ngroups, state->groups)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->rgid = user_gid;
	(void) setgid(user_gid);
	state->ruid = user_uid;
	if (setuid(user_uid)) {
	    errstr = "setuid(user_uid)";
	    goto bad;
	}
	break;

    case PERM_USER:
    case PERM_SUDOERS:
    case PERM_RUNAS:
    case PERM_TIMESTAMP:
	/* Unsupported since we can't set euid. */
	break;
    }

done:
    perm_stack_depth++;
    return 1;
bad:
    /* XXX - better warnings inline */
    warningx("%s: %s", errstr,
	errno == EAGAIN ? "too many processes" : strerror(errno));
    if (noexit)
	return 0;
    exit(1);
}

void
restore_perms(void)
{
    struct perm_state *state, *ostate;

    if (perm_stack_depth < 2)
	return;

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    if (state->ngroups != -1 && state->groups != ostate->groups) {
	if (setgroups(ostate->ngroups, ostate->groups)) {
	    warning("setgroups()");
	    goto bad;
	}
    }
    if (OID(rgid) != -1 && setgid(ostate->rgid)) {
	warning("setgid(%d)", ostate->rgid);
	goto bad;
    }
    if (OID(ruid) != -1 && setuid(ostate->ruid)) {
	warning("setuid(%d)", ostate->ruid);
	goto bad;
    }
    return;

bad:
    exit(1);
}
#  endif /* HAVE_SETEUID */
# endif /* HAVE_SETREUID */
#endif /* HAVE_SETRESUID */

#ifdef HAVE_INITGROUPS
static void
runas_setgroups()
{
    static struct passwd *pw;
    struct passwd *opw = pw;

    if (def_preserve_groups)
	return;

    /*
     * Use stashed copy of runas groups if available, else initgroups and stash.
     */
    pw = runas_pw ? runas_pw : sudo_user.pw;
    if (pw != opw) {
	pw = runas_pw ? runas_pw : sudo_user.pw;
# ifdef HAVE_SETAUTHDB
	aix_setauthdb(pw->pw_name);
# endif
	if (initgroups(pw->pw_name, pw->pw_gid) < 0)
	    log_error(USE_ERRNO|MSG_ONLY, "can't set runas group vector");
# ifdef HAVE_GETGROUPS
	if (runas_groups) {
	    efree(runas_groups);
	    runas_groups = NULL;
	}
	if ((runas_ngroups = getgroups(0, NULL)) > 0) {
	    runas_groups = emalloc2(runas_ngroups, sizeof(GETGROUPS_T));
	    if (getgroups(runas_ngroups, runas_groups) < 0)
		log_error(USE_ERRNO|MSG_ONLY, "can't get runas group vector");
	}
#  ifdef HAVE_SETAUTHDB
	aix_restoreauthdb();
#  endif
    } else {
	if (setgroups(runas_ngroups, runas_groups) < 0)
	    log_error(USE_ERRNO|MSG_ONLY, "can't set runas group vector");
# endif /* HAVE_GETGROUPS */
    }
}

#else

static void
runas_setgroups()
{
    /* STUB */
}

#endif /* HAVE_INITGROUPS */
