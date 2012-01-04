/*
 * Copyright (c) 1994-1996,1998-2011 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include "sudoers.h"

/*
 * Prototypes
 */
static struct group_list *runas_setgroups(void);

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
    struct group_list *grlist;
};

#define PERM_STACK_MAX	16
static struct perm_state perm_stack[PERM_STACK_MAX];
static int perm_stack_depth = 0;

#undef ID
#define ID(x) (state->x == ostate->x ? -1 : state->x)
#undef OID
#define OID(x) (ostate->x == state->x ? -1 : ostate->x)

void
rewind_perms(void)
{
    debug_decl(rewind_perms, SUDO_DEBUG_PERMS)

    while (perm_stack_depth > 1)
	restore_perms();
    grlist_delref(perm_stack[0].grlist);

    debug_return;
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
    debug_decl(set_perms, SUDO_DEBUG_PERMS)

    noexit = ISSET(perm, PERM_NOEXIT);
    CLR(perm, PERM_MASK);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = _("perm stack overflow");
	errno = EINVAL;
	goto bad;
    }

    state = &perm_stack[perm_stack_depth];
    if (perm != PERM_INITIAL) {
	if (perm_stack_depth == 0) {
	    errstr = _("perm stack underflow");
	    errno = EINVAL;
	    goto bad;
	}
	ostate = &perm_stack[perm_stack_depth - 1];
	if (memcmp(state, ostate, sizeof(*state)) == 0)
	    goto done;
    }

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
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
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
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);
	break;

    case PERM_USER:
	state->rgid = -1;
	state->egid = user_gid;
	state->sgid = -1;
	if (setresgid(-1, ID(egid), -1)) {
	    errstr = "setresgid(-1, user_gid, -1)";
	    goto bad;
	}
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	if (state->grlist != ostate->grlist) {
	    if (sudo_setgroups(state->grlist->ngids, state->grlist->gids)) {
		errstr = "setgroups()";
		goto bad;
	    }
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
	state->rgid = user_gid;
	state->egid = user_gid;
	state->sgid = user_gid;
	if (setresgid(ID(rgid), ID(egid), ID(sgid))) {
	    errstr = "setresgid(user_gid, user_gid, user_gid)";
	    goto bad;
	}
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	if (state->grlist != ostate->grlist) {
	    if (sudo_setgroups(state->grlist->ngids, state->grlist->gids)) {
		errstr = "setgroups()";
		goto bad;
	    }
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
	state->rgid = -1;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	state->sgid = -1;
	if (setresgid(-1, ID(egid), -1)) {
	    errstr = _("unable to change to runas gid");
	    goto bad;
	}
	state->grlist = runas_setgroups();
	state->ruid = -1;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	state->suid = -1;
	if (setresuid(-1, ID(euid), -1)) {
	    errstr = _("unable to change to runas uid");
	    goto bad;
	}
	break;

    case PERM_SUDOERS:
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);

	/* assumes euid == ROOT_UID, ruid == user */
	state->rgid = -1;
	state->egid = sudoers_gid;
	state->sgid = -1;
	if (setresgid(-1, ID(egid), -1))
	    error(1, _("unable to change to sudoers gid"));

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
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);
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
    debug_return_bool(1);
bad:
    /* XXX - better warnings inline */
    warningx("%s: %s", errstr,
	errno == EAGAIN ? _("too many processes") : strerror(errno));
    if (noexit)
	debug_return_bool(0);
    exit(1);
}

void
restore_perms(void)
{
    struct perm_state *state, *ostate;
    debug_decl(restore_perms, SUDO_DEBUG_PERMS)

    if (perm_stack_depth < 2)
	debug_return;

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    /* XXX - more cases here where euid != ruid */
    if (OID(euid) == ROOT_UID && state->euid != ROOT_UID) {
	if (setresuid(-1, ROOT_UID, -1)) {
	    warning("setresuid() [%d, %d, %d] -> [%d, %d, %d]",
		(int)state->ruid, (int)state->euid, (int)state->suid,
		-1, ROOT_UID, -1);
	    goto bad;
	}
    }
    if (setresuid(OID(ruid), OID(euid), OID(suid))) {
	warning("setresuid() [%d, %d, %d] -> [%d, %d, %d]",
	    (int)state->ruid, (int)state->euid, (int)state->suid,
	    (int)OID(ruid), (int)OID(euid), (int)OID(suid));
	goto bad;
    }
    if (setresgid(OID(rgid), OID(egid), OID(sgid))) {
	warning("setresgid() [%d, %d, %d] -> [%d, %d, %d]",
	    (int)state->rgid, (int)state->egid, (int)state->sgid,
	    (int)OID(rgid), (int)OID(egid), (int)OID(sgid));
	goto bad;
    }
    if (state->grlist != ostate->grlist) {
	if (sudo_setgroups(ostate->grlist->ngids, ostate->grlist->gids)) {
	    warning("setgroups()");
	    goto bad;
	}
    }
    grlist_delref(state->grlist);
    debug_return;

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
    debug_decl(set_perms, SUDO_DEBUG_PERMS)

    noexit = ISSET(perm, PERM_NOEXIT);
    CLR(perm, PERM_MASK);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = _("perm stack overflow");
	errno = EINVAL;
	goto bad;
    }

    state = &perm_stack[perm_stack_depth];
    if (perm != PERM_INITIAL) {
	if (perm_stack_depth == 0) {
	    errstr = _("perm stack underflow");
	    errno = EINVAL;
	    goto bad;
	}
	ostate = &perm_stack[perm_stack_depth - 1];
	if (memcmp(state, ostate, sizeof(*state)) == 0)
	    goto done;
    }

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
	state->ruid = getuid();
	state->euid = geteuid();
	state->rgid = getgid();
	state->egid = getegid();
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	break;

    case PERM_ROOT:
	/*
	 * setreuid(0, 0) may fail on some systems
	 * when the euid is not already 0.
	 */
	if (setreuid(-1, ROOT_UID)) {
	    errstr = "setreuid(-1, ROOT_UID)";
	    goto bad;
	}
	if (setuid(ROOT_UID)) {
	    errstr = "setuid(ROOT_UID)";
	    goto bad;
	}
	state->ruid = ROOT_UID;
	state->euid = ROOT_UID;
	state->rgid = -1;
	state->egid = -1;
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);
	break;

    case PERM_USER:
	state->rgid = -1;
	state->egid = user_gid;
	if (setregid(-1, ID(egid))) {
	    errstr = "setregid(-1, user_gid)";
	    goto bad;
	}
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	if (state->grlist != ostate->grlist) {
	    if (sudo_setgroups(state->grlist->ngids, state->grlist->gids)) {
		errstr = "setgroups()";
		goto bad;
	    }
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
	state->rgid = user_gid;
	state->egid = user_gid;
	if (setregid(ID(rgid), ID(egid))) {
	    errstr = "setregid(user_gid, user_gid)";
	    goto bad;
	}
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	if (state->grlist != ostate->grlist) {
	    if (sudo_setgroups(state->grlist->ngids, state->grlist->gids)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	if (setreuid(ID(ruid), ID(euid))) {
	    errstr = "setreuid(user_uid, user_uid)";
	    goto bad;
	}
	break;

    case PERM_RUNAS:
	state->rgid = -1;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	if (setregid(ID(rgid), ID(egid))) {
	    errstr = _("unable to change to runas gid");
	    goto bad;
	}
	state->grlist = runas_setgroups();
	state->ruid = ROOT_UID;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	if (setreuid(ID(ruid), ID(euid))) {
	    errstr = _("unable to change to runas uid");
	    goto bad;
	}
	break;

    case PERM_SUDOERS:
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);

	/* assume euid == ROOT_UID, ruid == user */
	state->rgid = -1;
	state->egid = sudoers_gid;
	if (setregid(-1, ID(egid)))
	    error(1, _("unable to change to sudoers gid"));

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
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);
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
    debug_return_bool(1);
bad:
    /* XXX - better warnings inline */
    warningx("%s: %s", errstr,
	errno == EAGAIN ? _("too many processes") : strerror(errno));
    if (noexit)
	debug_return_bool(0);
    exit(1);
}

void
restore_perms(void)
{
    struct perm_state *state, *ostate;
    debug_decl(restore_perms, SUDO_DEBUG_PERMS)

    if (perm_stack_depth < 2)
	debug_return;

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    /*
     * When changing euid to ROOT_UID, setreuid() may fail even if
     * the ruid is ROOT_UID so call setuid() first.
     */
    if (OID(euid) == ROOT_UID) {
	/* setuid() may not set the saved ID unless the euid is ROOT_UID */
	if (ID(euid) != ROOT_UID)
	    (void)setreuid(-1, ROOT_UID);
	if (setuid(ROOT_UID)) {
	    warning("setuid() [%d, %d] -> %d)", (int)state->ruid,
		(int)state->euid, ROOT_UID);
	    goto bad;
	}
    }
    if (setreuid(OID(ruid), OID(euid))) {
	warning("setreuid() [%d, %d] -> [%d, %d]", (int)state->ruid,
	    (int)state->euid, (int)OID(ruid), (int)OID(euid));
	goto bad;
    }
    if (setregid(OID(rgid), OID(egid))) {
	warning("setregid() [%d, %d] -> [%d, %d]", (int)state->rgid,
	    (int)state->egid, (int)OID(rgid), (int)OID(egid));
	goto bad;
    }
    if (state->grlist != ostate->grlist) {
	if (sudo_setgroups(ostate->grlist->ngids, ostate->grlist->gids)) {
	    warning("setgroups()");
	    goto bad;
	}
    }
    grlist_delref(state->grlist);
    debug_return;

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
    debug_decl(set_perms, SUDO_DEBUG_PERMS)

    noexit = ISSET(perm, PERM_NOEXIT);
    CLR(perm, PERM_MASK);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = _("perm stack overflow");
	errno = EINVAL;
	goto bad;
    }

    state = &perm_stack[perm_stack_depth];
    if (perm != PERM_INITIAL) {
	if (perm_stack_depth == 0) {
	    errstr = _("perm stack underflow");
	    errno = EINVAL;
	    goto bad;
	}
	ostate = &perm_stack[perm_stack_depth - 1];
	if (memcmp(state, ostate, sizeof(*state)) == 0)
	    goto done;
    }

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
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	break;

    case PERM_ROOT:
	/* We already set ruid/euid above. */
	state->ruid = ROOT_UID;
	state->euid = ROOT_UID;
	state->rgid = -1;
	state->egid = -1;
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);
	break;

    case PERM_USER:
	state->egid = user_gid;
	if (setegid(ID(egid))) {
	    errstr = "setegid(user_gid)";
	    goto bad;
	}
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	if (state->grlist != ostate->grlist) {
	    if (sudo_setgroups(state->grlist->ngids, state->grlist->gids)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->rgid = -1;
	state->ruid = ROOT_UID;
	state->euid = user_uid;
	if (seteuid(ID(euid))) {
	    errstr = "seteuid(user_uid)";
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	/* headed for exec() */
	state->rgid = user_gid;
	state->egid = user_gid;
	if (setgid(user_gid)) {
	    errstr = "setgid(user_gid)";
	    goto bad;
	}
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	if (state->grlist != ostate->grlist) {
	    if (sudo_setgroups(state->grlist->ngids, state->grlist->gids)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	if (setuid(user_uid)) {
	    errstr = "setuid(user_uid)";
	    goto bad;
	}
	break;

    case PERM_RUNAS:
	state->rgid = -1;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	if (setegid(ID(egid))) {
	    errstr = _("unable to change to runas gid");
	    goto bad;
	}
	state->grlist = runas_setgroups();
	state->ruid = -1;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	if (seteuid(ID(euid))) {
	    errstr = _("unable to change to runas uid");
	    goto bad;
	}
	break;

    case PERM_SUDOERS:
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);

	/* assume euid == ROOT_UID, ruid == user */
	state->rgid = -1;
	state->egid = sudoers_gid;
	if (setegid(ID(egid)))
	    error(1, _("unable to change to sudoers gid"));

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
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);
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
    debug_return_bool(1);
bad:
    /* XXX - better warnings inline */
    warningx("%s: %s", errstr,
	errno == EAGAIN ? _("too many processes") : strerror(errno));
    if (noexit)
	debug_return_bool(0);
    exit(1);
}

void
restore_perms(void)
{
    struct perm_state *state, *ostate;
    debug_decl(restore_perms, SUDO_DEBUG_PERMS)

    if (perm_stack_depth < 2)
	debug_return;

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
	warning("setegid(%d)", (int)OID(egid));
	goto bad;
    }
    if (state->grlist != ostate->grlist) {
	if (sudo_setgroups(ostate->grlist->ngids, ostate->grlist->gids)) {
	    warning("setgroups()");
	    goto bad;
	}
    }
    if (seteuid(OID(euid))) {
	warning("seteuid(%d)", (int)OID(euid));
	goto bad;
    }
    grlist_delref(state->grlist);
    debug_return;

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
    debug_decl(set_perms, SUDO_DEBUG_PERMS)

    noexit = ISSET(perm, PERM_NOEXIT);
    CLR(perm, PERM_MASK);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = _("perm stack overflow");
	errno = EINVAL;
	goto bad;
    }

    state = &perm_stack[perm_stack_depth];
    if (perm != PERM_INITIAL) {
	if (perm_stack_depth == 0) {
	    errstr = _("perm stack underflow");
	    errno = EINVAL;
	    goto bad;
	}
	ostate = &perm_stack[perm_stack_depth - 1];
	if (memcmp(state, ostate, sizeof(*state)) == 0)
	    goto done;
    }

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
	state->ruid = getuid();
	state->rgid = getgid();
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	break;

    case PERM_ROOT:
	state->ruid = ROOT_UID;
	state->rgid = -1;
	state->grlist = ostate->grlist;
	grlist_addref(state->grlist);
	if (setuid(ROOT_UID)) {
	    errstr = "setuid(ROOT_UID)";
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	state->rgid = user_gid;
	(void) setgid(user_gid);
	state->grlist = user_group_list;
	grlist_addref(state->grlist);
	if (state->grlist != ostate->grlist) {
	    if (sudo_setgroups(state->grlist->ngids, state->grlist->gids)) {
		errstr = "setgroups()";
		goto bad;
	    }
	}
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
    debug_return_bool(1);
bad:
    /* XXX - better warnings inline */
    warningx("%s: %s", errstr,
	errno == EAGAIN ? _("too many processes") : strerror(errno));
    if (noexit)
	debug_return_bool(0);
    exit(1);
}

void
restore_perms(void)
{
    struct perm_state *state, *ostate;
    debug_decl(restore_perms, SUDO_DEBUG_PERMS)

    if (perm_stack_depth < 2)
	debug_return;

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    if (OID(rgid) != -1 && setgid(ostate->rgid)) {
	warning("setgid(%d)", (int)ostate->rgid);
	goto bad;
    }
    if (state->grlist != ostate->grlist) {
	if (sudo_setgroups(ostate->grlist->ngids, ostate->grlist->gids)) {
	    warning("setgroups()");
	    goto bad;
	}
    }
    grlist_delref(state->grlist);
    if (OID(ruid) != -1 && setuid(ostate->ruid)) {
	warning("setuid(%d)", (int)ostate->ruid);
	goto bad;
    }
    debug_return;

bad:
    exit(1);
}
#  endif /* HAVE_SETEUID */
# endif /* HAVE_SETREUID */
#endif /* HAVE_SETRESUID */

static struct group_list *
runas_setgroups(void)
{
    struct passwd *pw;
    struct group_list *grlist;
    debug_decl(runas_setgroups, SUDO_DEBUG_PERMS)

    if (def_preserve_groups) {
	grlist_addref(user_group_list);
	debug_return_ptr(user_group_list);
    }

    pw = runas_pw ? runas_pw : sudo_user.pw;
#ifdef HAVE_SETAUTHDB
    aix_setauthdb(pw->pw_name);
#endif
    grlist = get_group_list(pw);
#ifdef HAVE_SETAUTHDB
    aix_restoreauthdb();
#endif
    if (sudo_setgroups(grlist->ngids, grlist->gids) < 0)
	log_error(USE_ERRNO|MSG_ONLY, _("unable to set runas group vector"));
    debug_return_ptr(grlist);
}
