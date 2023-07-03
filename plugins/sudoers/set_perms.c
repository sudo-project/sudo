/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1994-1996, 1998-2020 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef _AIX
# include <sys/id.h>
#endif
#include <pwd.h>
#include <errno.h>
#include <grp.h>

#include "sudoers.h"
#include "check.h"

/*
 * Prototypes
 */
#if defined(HAVE_SETRESUID) || defined(HAVE_SETREUID) || defined(HAVE_SETEUID)
static struct gid_list *runas_setgroups(void);
#endif

/*
 * We keep track of the current permisstions and use a stack to restore
 * the old permissions.  A depth of 16 is overkill.
 */
struct perm_state {
    uid_t ruid;
    uid_t euid;
#if defined(HAVE_SETRESUID) || defined(ID_SAVED)
    uid_t suid;
#endif
    gid_t rgid;
    gid_t egid;
#if defined(HAVE_SETRESUID) || defined(ID_SAVED)
    gid_t sgid;
#endif
    struct gid_list *gidlist;
};

#define PERM_STACK_MAX	16
static struct perm_state perm_stack[PERM_STACK_MAX];
static int perm_stack_depth = 0;

#undef ID
#define ID(x) (state->x == ostate->x ? (uid_t)-1 : state->x)
#undef OID
#define OID(x) (ostate->x == state->x ? (uid_t)-1 : ostate->x)

bool
rewind_perms(void)
{
    debug_decl(rewind_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth > 0) {
	while (perm_stack_depth > 1) {
	    if (!restore_perms())
		debug_return_bool(false);
	}
	sudo_gidlist_delref(perm_stack[0].gidlist);
    }

    debug_return_bool(true);
}

#if defined(HAVE_SETRESUID)

#define UID_CHANGED (state->ruid != ostate->ruid || state->euid != ostate->euid || state->suid != ostate->suid)
#define GID_CHANGED (state->rgid != ostate->rgid || state->egid != ostate->egid || state->sgid != ostate->sgid)

/*
 * Set real and effective and saved uids and gids based on perm.
 * We always retain a saved uid of 0 unless we are headed for an exec().
 * We only flip the effective gid since it only changes for PERM_SUDOERS.
 * This version of set_perms() works fine with the "stay_setuid" option.
 */
bool
set_perms(int perm)
{
    struct perm_state *state, *ostate = NULL;
    char errbuf[1024];
    const char *errstr = errbuf;
    debug_decl(set_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = N_("perm stack overflow");
	errno = EINVAL;
	goto bad;
    }

    if (perm == PERM_INITIAL) {
	if (perm_stack_depth > 1)
	    rewind_perms();
	perm_stack_depth = 0;
    } else {
	if (perm_stack_depth == 0) {
	    errstr = N_("perm stack underflow");
	    errno = EINVAL;
	    goto bad;
	}
	ostate = &perm_stack[perm_stack_depth - 1];
    }
    state = &perm_stack[perm_stack_depth];

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
#ifdef HAVE_GETRESUID
	if (getresuid(&state->ruid, &state->euid, &state->suid)) {
	    errstr = "PERM_INITIAL: getresuid";
	    goto bad;

	}
	if (getresgid(&state->rgid, &state->egid, &state->sgid)) {
	    errstr = "PERM_INITIAL: getresgid";
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
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_INITIAL: "
	    "ruid: %u, euid: %u, suid: %u, rgid: %u, egid: %u, sgid: %u",
	    __func__, (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	break;

    case PERM_ROOT:
	state->ruid = ROOT_UID;
	state->euid = ROOT_UID;
	state->suid = ROOT_UID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED && setresuid(ID(ruid), ID(euid), ID(suid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_ROOT: setresuid(%u, %u, %u)",
		(unsigned int)ID(ruid), (unsigned int)ID(euid), (unsigned int)ID(suid));
	    goto bad;
	}
	state->rgid = ostate->rgid;
	state->egid = ROOT_GID;
	state->sgid = ostate->sgid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setresgid(ID(rgid), ID(egid), ID(sgid))) {
	    errstr = N_("unable to change to root gid");
	    goto bad;
	}
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	break;

    case PERM_USER:
	state->rgid = ostate->rgid;
	state->egid = user_gid;
	state->sgid = ostate->sgid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_USER: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setresgid(ID(rgid), ID(egid), ID(sgid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_USER: setresgid(%u, %u, %u)",
		(unsigned int)ID(rgid), (unsigned int)ID(egid), (unsigned int)ID(sgid));
	    goto bad;
	}
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	if (state->gidlist != ostate->gidlist) {
	    if (sudo_setgroups(state->gidlist->ngids, state->gidlist->gids)) {
		errstr = "PERM_USER: setgroups";
		goto bad;
	    }
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	state->suid = ROOT_UID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_USER: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED && setresuid(ID(ruid), ID(euid), ID(suid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_USER: setresuid(%u, %u, %u)",
		(unsigned int)ID(ruid), (unsigned int)ID(euid), (unsigned int)ID(suid));
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	/* headed for exec() */
	state->rgid = user_gid;
	state->egid = user_gid;
	state->sgid = user_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setresgid(ID(rgid), ID(egid), ID(sgid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_FULL_USER: setresgid(%u, %u, %u)",
		(unsigned int)ID(rgid), (unsigned int)ID(egid), (unsigned int)ID(sgid));
	    goto bad;
	}
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	if (state->gidlist != ostate->gidlist) {
	    if (sudo_setgroups(state->gidlist->ngids, state->gidlist->gids)) {
		errstr = "PERM_FULL_USER: setgroups";
		goto bad;
	    }
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	state->suid = user_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED && setresuid(ID(ruid), ID(euid), ID(suid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_FULL_USER: setresuid(%u, %u, %u)",
		(unsigned int)ID(ruid), (unsigned int)ID(euid), (unsigned int)ID(suid));
	    goto bad;
	}
	break;

    case PERM_RUNAS:
	state->rgid = ostate->rgid;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	state->sgid = ostate->sgid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_RUNAS: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setresgid(ID(rgid), ID(egid), ID(sgid))) {
	    errstr = N_("unable to change to runas gid");
	    goto bad;
	}
	state->gidlist = runas_setgroups();
	if (state->gidlist == NULL) {
	    errstr = N_("unable to set runas group vector");
	    goto bad;
	}
	state->ruid = ostate->ruid;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	state->suid = ostate->suid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_RUNAS: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED && setresuid(ID(ruid), ID(euid), ID(suid))) {
	    errstr = N_("unable to change to runas uid");
	    goto bad;
	}
	break;

    case PERM_SUDOERS: {
	const uid_t sudoers_uid = sudoers_file_uid();
	const gid_t sudoers_gid = sudoers_file_gid();
	const mode_t sudoers_mode = sudoers_file_mode();

	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);

	/* assumes euid == ROOT_UID, ruid == user */
	state->rgid = ostate->rgid;
	state->egid = sudoers_gid;
	state->sgid = ostate->sgid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_SUDOERS: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setresgid(ID(rgid), ID(egid), ID(sgid))) {
	    errstr = N_("unable to change to sudoers gid");
	    goto bad;
	}

	state->ruid = ROOT_UID;
	/*
	 * If sudoers_uid == ROOT_UID and sudoers_mode is group readable
	 * we use a non-zero uid in order to avoid NFS lossage.
	 * Using uid 1 is a bit bogus but should work on all OS's.
	 */
	if (sudoers_uid == ROOT_UID && (sudoers_mode & S_IRGRP))
	    state->euid = 1;
	else
	    state->euid = sudoers_uid;
	state->suid = ROOT_UID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_SUDOERS: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED && setresuid(ID(ruid), ID(euid), ID(suid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_SUDOERS: setresuid(%u, %u, %u)",
		(unsigned int)ID(ruid), (unsigned int)ID(euid), (unsigned int)ID(suid));
	    goto bad;
	}
	break;
    }

    case PERM_TIMESTAMP:
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	state->rgid = ostate->rgid;
	state->egid = ostate->egid;
	state->sgid = ostate->sgid;
	state->ruid = ROOT_UID;
	state->euid = timestamp_get_uid();
	state->suid = ROOT_UID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_TIMESTAMP: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED && setresuid(ID(ruid), ID(euid), ID(suid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_TIMESTAMP: setresuid(%u, %u, %u)",
		(unsigned int)ID(ruid), (unsigned int)ID(euid), (unsigned int)ID(suid));
	    goto bad;
	}
	break;
    }

    perm_stack_depth++;
    debug_return_bool(true);
bad:
    if (errno == EAGAIN)
	sudo_warnx(U_("%s: %s"), U_(errstr), U_("too many processes"));
    else
	sudo_warn("%s", U_(errstr));
    debug_return_bool(false);
}

bool
restore_perms(void)
{
    struct perm_state *state, *ostate;
    debug_decl(restore_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth < 2) {
	sudo_warnx("%s", U_("perm stack underflow"));
	debug_return_bool(true);
    }

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: uid: [%u, %u, %u] -> [%u, %u, %u]",
	__func__, (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
	(unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: gid: [%u, %u, %u] -> [%u, %u, %u]",
	__func__, (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid,
	(unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid);

    /* XXX - more cases here where euid != ruid */
    if (OID(euid) == ROOT_UID) {
	if (setresuid(-1, ROOT_UID, -1)) {
	    sudo_warn("setresuid() [%u, %u, %u] -> [-1, %u, -1]",
		(unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
		ROOT_UID);
	    goto bad;
	}
    }
    if (setresgid(OID(rgid), OID(egid), OID(sgid))) {
	sudo_warn("setresgid() [%u, %u, %u] -> [%u, %u, %u]",
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid,
	    (unsigned int)OID(rgid), (unsigned int)OID(egid), (unsigned int)OID(sgid));
	goto bad;
    }
    if (state->gidlist != ostate->gidlist) {
	if (sudo_setgroups(ostate->gidlist->ngids, ostate->gidlist->gids)) {
	    sudo_warn("setgroups()");
	    goto bad;
	}
    }
    if (setresuid(OID(ruid), OID(euid), OID(suid))) {
	sudo_warn("setresuid() [%u, %u, %u] -> [%u, %u, %u]",
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
	    (unsigned int)OID(ruid), (unsigned int)OID(euid), (unsigned int)OID(suid));
	goto bad;
    }
    sudo_gidlist_delref(state->gidlist);
    debug_return_bool(true);

bad:
    debug_return_bool(false);
}

#elif defined(_AIX) && defined(ID_SAVED)

#define UID_CHANGED (state->ruid != ostate->ruid || state->euid != ostate->euid || state->suid != ostate->suid)
#define GID_CHANGED (state->rgid != ostate->rgid || state->egid != ostate->egid || state->sgid != ostate->sgid)

/*
 * Set real and effective and saved uids and gids based on perm.
 * We always retain a saved uid of 0 unless we are headed for an exec().
 * We only flip the effective gid since it only changes for PERM_SUDOERS.
 * This version of set_perms() works fine with the "stay_setuid" option.
 */
bool
set_perms(int perm)
{
    struct perm_state *state, *ostate = NULL;
    char errbuf[1024];
    const char *errstr = errbuf;
    debug_decl(set_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = N_("perm stack overflow");
	errno = EINVAL;
	goto bad;
    }

    if (perm == PERM_INITIAL) {
	if (perm_stack_depth > 1)
	    rewind_perms();
	perm_stack_depth = 0;
    } else {
	if (perm_stack_depth == 0) {
	    errstr = N_("perm stack underflow");
	    errno = EINVAL;
	    goto bad;
	}
	ostate = &perm_stack[perm_stack_depth - 1];
    }
    state = &perm_stack[perm_stack_depth];

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
	state->ruid = getuidx(ID_REAL);
	state->euid = getuidx(ID_EFFECTIVE);
	state->suid = getuidx(ID_SAVED);
	state->rgid = getgidx(ID_REAL);
	state->egid = getgidx(ID_EFFECTIVE);
	state->sgid = getgidx(ID_SAVED);
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_INITIAL: "
	    "ruid: %u, euid: %u, suid: %u, rgid: %u, egid: %u, sgid: %u",
	    __func__, (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	break;

    case PERM_ROOT:
	state->ruid = ROOT_UID;
	state->euid = ROOT_UID;
	state->suid = ROOT_UID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED && setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, ROOT_UID)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_ROOT: setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, %u)",
		ROOT_UID);
	    goto bad;
	}
	state->rgid = ostate->rgid;
	state->egid = ROOT_GID;
	state->sgid = ostate->sgid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setgidx(ID_EFFECTIVE, ROOT_GID)) {
	    errstr = N_("unable to change to root gid");
	    goto bad;
	}
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	break;

    case PERM_USER:
	state->rgid = ostate->rgid;
	state->egid = user_gid;
	state->sgid = ostate->sgid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_USER: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setgidx(ID_EFFECTIVE, user_gid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_USER: setgidx(ID_EFFECTIVE, %u)", (unsigned int)user_gid);
	    goto bad;
	}
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	if (state->gidlist != ostate->gidlist) {
	    if (sudo_setgroups(state->gidlist->ngids, state->gidlist->gids)) {
		errstr = "PERM_USER: setgroups";
		goto bad;
	    }
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	state->suid = ROOT_UID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_USER: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (ostate->euid != ROOT_UID || ostate->suid != ROOT_UID) {
	    if (setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, ROOT_UID)) {
		(void)snprintf(errbuf, sizeof(errbuf),
		    "PERM_USER: setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, %u)",
		    ROOT_UID);
		goto bad;
	    }
	}
	if (setuidx(ID_EFFECTIVE|ID_REAL, user_uid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_USER: setuidx(ID_EFFECTIVE|ID_REAL, %u)", (unsigned int)user_uid);
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	/* headed for exec() */
	state->rgid = user_gid;
	state->egid = user_gid;
	state->sgid = user_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setgidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, user_gid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_FULL_USER: setgidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, %u)",
		(unsigned int)user_gid);
	    goto bad;
	}
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	if (state->gidlist != ostate->gidlist) {
	    if (sudo_setgroups(state->gidlist->ngids, state->gidlist->gids)) {
		errstr = "PERM_FULL_USER: setgroups";
		goto bad;
	    }
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	state->suid = user_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED && setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, user_uid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_FULL_USER: setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, %u)",
		(unsigned int)user_uid);
	    goto bad;
	}
	break;

    case PERM_RUNAS:
	state->rgid = ostate->rgid;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	state->sgid = ostate->sgid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_RUNAS: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setgidx(ID_EFFECTIVE, state->egid)) {
	    errstr = N_("unable to change to runas gid");
	    goto bad;
	}
	state->gidlist = runas_setgroups();
	if (state->gidlist == NULL) {
	    errstr = N_("unable to set runas group vector");
	    goto bad;
	}
	state->ruid = ostate->ruid;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	state->suid = ostate->suid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_RUNAS: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED && setuidx(ID_EFFECTIVE, state->euid)) {
	    errstr = N_("unable to change to runas uid");
	    goto bad;
	}
	break;

    case PERM_SUDOERS: {
	const uid_t sudoers_uid = sudoers_file_uid();
	const gid_t sudoers_gid = sudoers_file_gid();
	const mode_t sudoers_mode = sudoers_file_mode();

	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);

	/* assume euid == ROOT_UID, ruid == user */
	state->rgid = ostate->rgid;
	state->egid = sudoers_gid;
	state->sgid = ostate->sgid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_SUDOERS: gid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid,
	    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid);
	if (GID_CHANGED && setgidx(ID_EFFECTIVE, sudoers_gid)) {
	    errstr = N_("unable to change to sudoers gid");
	    goto bad;
	}

	state->ruid = ROOT_UID;
	/*
	 * If sudoers_uid == ROOT_UID and sudoers_mode is group readable
	 * we use a non-zero uid in order to avoid NFS lossage.
	 * Using uid 1 is a bit bogus but should work on all OS's.
	 */
	if (sudoers_uid == ROOT_UID && (sudoers_mode & S_IRGRP))
	    state->euid = 1;
	else
	    state->euid = sudoers_uid;
	state->suid = ROOT_UID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_SUDOERS: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED) {
	    if (ostate->ruid != ROOT_UID || ostate->suid != ROOT_UID) {
		if (setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, ROOT_UID)) {
		    (void)snprintf(errbuf, sizeof(errbuf),
			"PERM_SUDOERS: setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, %u)",
			ROOT_UID);
		    goto bad;
		}
	    }
	    if (setuidx(ID_EFFECTIVE, state->euid)) {
		(void)snprintf(errbuf, sizeof(errbuf),
		    "PERM_SUDOERS: setuidx(ID_EFFECTIVE, %u)", (unsigned int)sudoers_uid);
		goto bad;
	    }
	}
	break;
    }

    case PERM_TIMESTAMP:
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	state->rgid = ostate->rgid;
	state->egid = ostate->egid;
	state->sgid = ostate->sgid;
	state->ruid = ROOT_UID;
	state->euid = timestamp_get_uid();
	state->suid = ROOT_UID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_TIMESTAMP: uid: "
	    "[%u, %u, %u] -> [%u, %u, %u]", __func__,
	    (unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid,
	    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid);
	if (UID_CHANGED) {
	    if (ostate->ruid != ROOT_UID || ostate->suid != ROOT_UID) {
		if (setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, ROOT_UID)) {
		    (void)snprintf(errbuf, sizeof(errbuf),
			"PERM_TIMESTAMP: setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, %u)",
			ROOT_UID);
		    goto bad;
		}
	    }
	    if (setuidx(ID_EFFECTIVE, state->euid)) {
		(void)snprintf(errbuf, sizeof(errbuf),
		    "PERM_TIMESTAMP: setuidx(ID_EFFECTIVE, %u)",
		    (unsigned int)state->euid);
		goto bad;
	    }
	}
	break;
    }

    perm_stack_depth++;
    debug_return_bool(true);
bad:
    if (errno == EAGAIN)
	sudo_warnx(U_("%s: %s"), U_(errstr), U_("too many processes"));
    else
	sudo_warn("%s", U_(errstr));
    debug_return_bool(false);
}

bool
restore_perms(void)
{
    struct perm_state *state, *ostate;
    debug_decl(restore_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth < 2) {
	sudo_warnx("%s", U_("perm stack underflow"));
	debug_return_bool(true);
    }

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: uid: [%u, %u, %u] -> [%u, %u, %u]",
	__func__, (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
	(unsigned int)ostate->ruid, (unsigned int)ostate->euid, (unsigned int)ostate->suid);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: gid: [%u, %u, %u] -> [%u, %u, %u]",
	__func__, (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid,
	(unsigned int)ostate->rgid, (unsigned int)ostate->egid, (unsigned int)ostate->sgid);

    if (OID(ruid) != (uid_t)-1 || OID(euid) != (uid_t)-1 || OID(suid) != (uid_t)-1) {
	if (OID(euid) == ROOT_UID) {
	    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: setuidx(ID_EFFECTIVE, %u)",
		__func__, ROOT_UID);
	    if (setuidx(ID_EFFECTIVE, ROOT_UID)) {
		sudo_warn("setuidx(ID_EFFECTIVE) [%u, %u, %u] -> [-1, %u, -1]",
		    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
		    ROOT_UID);
		goto bad;
	    }
	}
	if (OID(ruid) == OID(euid) && OID(euid) == OID(suid)) {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"%s: setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, %u)",
		__func__, (unsigned int)OID(ruid));
	    if (setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, OID(ruid))) {
		sudo_warn("setuidx(ID_EFFECTIVE|ID_REAL|ID_SAVED) [%u, %u, %u] -> [%u, %u, %u]",
		    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
		    (unsigned int)OID(ruid), (unsigned int)OID(euid), (unsigned int)OID(suid));
		goto bad;
	    }
	} else if (OID(ruid) == (uid_t)-1 && OID(suid) == (uid_t)-1) {
	    /* May have already changed euid to ROOT_UID above. */
	    if (OID(euid) != ROOT_UID) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: setuidx(ID_EFFECTIVE, %u)", __func__, (unsigned int)OID(euid));
		if (setuidx(ID_EFFECTIVE, OID(euid))) {
		    sudo_warn("setuidx(ID_EFFECTIVE) [%u, %u, %u] -> [%u, %u, %u]",
			(unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
			(unsigned int)OID(ruid), (unsigned int)OID(euid), (unsigned int)OID(suid));
		    goto bad;
		}
	    }
	} else if (OID(suid) == (uid_t)-1) {
	    /* Cannot set the real uid alone. */
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"%s: setuidx(ID_REAL|ID_EFFECTIVE, %u)", __func__, (unsigned int)OID(ruid));
	    if (setuidx(ID_REAL|ID_EFFECTIVE, OID(ruid))) {
		sudo_warn("setuidx(ID_REAL|ID_EFFECTIVE) [%u, %u, %u] -> [%u, %u, %u]",
		    (unsigned int)state->ruid, (unsigned int)state->euid, (unsigned int)state->suid,
		    (unsigned int)OID(ruid), (unsigned int)OID(euid), (unsigned int)OID(suid));
		goto bad;
	    }
	    /* Restore the effective euid if it doesn't match the ruid. */
	    if (OID(euid) != OID(ruid)) {
		sudo_debug_printf(SUDO_DEBUG_INFO,
		    "%s: setuidx(ID_EFFECTIVE, %u)", __func__, (unsigned int)ostate->euid);
		if (setuidx(ID_EFFECTIVE, ostate->euid)) {
		    sudo_warn("setuidx(ID_EFFECTIVE, %u)", (unsigned int)ostate->euid);
		    goto bad;
		}
	    }
	}
    }
    if (OID(rgid) != (gid_t)-1 || OID(egid) != (gid_t)-1 || OID(sgid) != (gid_t)-1) {
	if (OID(rgid) == OID(egid) && OID(egid) == OID(sgid)) {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"%s: setgidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, %u)",
		__func__, (unsigned int)OID(rgid));
	    if (setgidx(ID_EFFECTIVE|ID_REAL|ID_SAVED, OID(rgid))) {
		sudo_warn("setgidx(ID_EFFECTIVE|ID_REAL|ID_SAVED) [%u, %u, %u] -> [%u, %u, %u]",
		    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid,
		    (unsigned int)OID(rgid), (unsigned int)OID(egid), (unsigned int)OID(sgid));
		goto bad;
	    }
	} else if (OID(rgid) == (gid_t)-1 && OID(sgid) == (gid_t)-1) {
	    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: setgidx(ID_EFFECTIVE, %u)",
		__func__, (unsigned int)OID(egid));
	    if (setgidx(ID_EFFECTIVE, OID(egid))) {
		sudo_warn("setgidx(ID_EFFECTIVE) [%u, %u, %u] -> [%u, %u, %u]",
		    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid,
		    (unsigned int)OID(rgid), (unsigned int)OID(egid), (unsigned int)OID(sgid));
		goto bad;
	    }
	} else if (OID(sgid) == (gid_t)-1) {
	    sudo_debug_printf(SUDO_DEBUG_INFO,
		"%s: setgidx(ID_EFFECTIVE|ID_REAL, %u)", __func__, OID(rgid));
	    if (setgidx(ID_REAL|ID_EFFECTIVE, OID(rgid))) {
		sudo_warn("setgidx(ID_REAL|ID_EFFECTIVE) [%u, %u, %u] -> [%u, %u, %u]",
		    (unsigned int)state->rgid, (unsigned int)state->egid, (unsigned int)state->sgid,
		    (unsigned int)OID(rgid), (unsigned int)OID(egid), (unsigned int)OID(sgid));
		goto bad;
	    }
	}
    }
    if (state->gidlist != ostate->gidlist) {
	if (sudo_setgroups(ostate->gidlist->ngids, ostate->gidlist->gids)) {
	    sudo_warn("setgroups()");
	    goto bad;
	}
    }
    sudo_gidlist_delref(state->gidlist);
    debug_return_bool(true);

bad:
    debug_return_bool(false);
}

#elif defined(HAVE_SETREUID)

#define UID_CHANGED (state->ruid != ostate->ruid || state->euid != ostate->euid)
#define GID_CHANGED (state->rgid != ostate->rgid || state->egid != ostate->egid)

/*
 * Set real and effective and saved uids and gids based on perm.
 * We always retain a saved uid of 0 unless we are headed for an exec().
 * We only flip the effective gid since it only changes for PERM_SUDOERS.
 * This version of set_perms() works fine with the "stay_setuid" option.
 */
bool
set_perms(int perm)
{
    struct perm_state *state, *ostate = NULL;
    char errbuf[1024];
    const char *errstr = errbuf;
    debug_decl(set_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = N_("perm stack overflow");
	errno = EINVAL;
	goto bad;
    }

    if (perm == PERM_INITIAL) {
	if (perm_stack_depth > 1)
	    rewind_perms();
	perm_stack_depth = 0;
    } else {
	if (perm_stack_depth == 0) {
	    errstr = N_("perm stack underflow");
	    errno = EINVAL;
	    goto bad;
	}
	ostate = &perm_stack[perm_stack_depth - 1];
    }
    state = &perm_stack[perm_stack_depth];

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
	state->ruid = getuid();
	state->euid = geteuid();
	state->rgid = getgid();
	state->egid = getegid();
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_INITIAL: "
	    "ruid: %u, euid: %u, rgid: %u, egid: %u", __func__,
	    (unsigned int)state->ruid, (unsigned int)state->euid,
	    (unsigned int)state->rgid, (unsigned int)state->egid);
	break;

    case PERM_ROOT:
	state->ruid = ROOT_UID;
	state->euid = ROOT_UID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	/*
	 * setreuid(0, 0) may fail on some systems if euid is not already 0.
	 */
	if (ostate->euid != ROOT_UID) {
	    if (setreuid(-1, ROOT_UID)) {
		(void)snprintf(errbuf, sizeof(errbuf),
		    "PERM_ROOT: setreuid(-1, %u)", ROOT_UID);
		goto bad;
	    }
	}
	if (ostate->ruid != ROOT_UID) {
	    if (setreuid(ROOT_UID, -1)) {
		(void)snprintf(errbuf, sizeof(errbuf),
		    "PERM_ROOT: setreuid(%u, -1)", ROOT_UID);
		goto bad;
	    }
	}
	state->rgid = ostate->rgid;
	state->egid = ROOT_GID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, (unsigned int)state->rgid, (unsigned int)state->egid);
	if (GID_CHANGED && setregid(ID(rgid), ID(egid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_ROOT: setregid(%u, %u)", (unsigned int)ID(rgid), (unsigned int)ID(egid));
	    goto bad;
	}
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	break;

    case PERM_USER:
	state->rgid = ostate->rgid;
	state->egid = user_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_USER: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, (unsigned int)state->rgid, (unsigned int)state->egid);
	if (GID_CHANGED && setregid(ID(rgid), ID(egid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_USER: setregid(%u, %u)", (unsigned int)ID(rgid), (unsigned int)ID(egid));
	    goto bad;
	}
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	if (state->gidlist != ostate->gidlist) {
	    if (sudo_setgroups(state->gidlist->ngids, state->gidlist->gids)) {
		errstr = "PERM_USER: setgroups";
		goto bad;
	    }
	}
	state->ruid = ROOT_UID;
	state->euid = user_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_USER: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (UID_CHANGED && setreuid(ID(ruid), ID(euid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_USER: setreuid(%u, %u)", (unsigned int)ID(ruid), (unsigned int)ID(euid));
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	/* headed for exec() */
	state->rgid = user_gid;
	state->egid = user_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, (unsigned int)state->rgid, (unsigned int)state->egid);
	if (GID_CHANGED && setregid(ID(rgid), ID(egid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_FULL_USER: setregid(%u, %u)",
		(unsigned int)ID(rgid), (unsigned int)ID(egid));
	    goto bad;
	}
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	if (state->gidlist != ostate->gidlist) {
	    if (sudo_setgroups(state->gidlist->ngids, state->gidlist->gids)) {
		errstr = "PERM_FULL_USER: setgroups";
		goto bad;
	    }
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (UID_CHANGED && setreuid(ID(ruid), ID(euid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_FULL_USER: setreuid(%u, %u)",
		(unsigned int)ID(ruid), (unsigned int)ID(euid));
	    goto bad;
	}
	break;

    case PERM_RUNAS:
	state->rgid = ostate->rgid;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_RUNAS: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, (unsigned int)state->rgid, (unsigned int)state->egid);
	if (GID_CHANGED && setregid(ID(rgid), ID(egid))) {
	    errstr = N_("unable to change to runas gid");
	    goto bad;
	}
	state->gidlist = runas_setgroups();
	if (state->gidlist == NULL) {
	    errstr = N_("unable to set runas group vector");
	    goto bad;
	}
	state->ruid = ROOT_UID;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_RUNAS: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (UID_CHANGED && setreuid(ID(ruid), ID(euid))) {
	    errstr = N_("unable to change to runas uid");
	    goto bad;
	}
	break;

    case PERM_SUDOERS: {
	const uid_t sudoers_uid = sudoers_file_uid();
	const gid_t sudoers_gid = sudoers_file_gid();
	const mode_t sudoers_mode = sudoers_file_mode();

	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);

	/* assume euid == ROOT_UID, ruid == user */
	state->rgid = ostate->rgid;
	state->egid = sudoers_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_SUDOERS: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, (unsigned int)state->rgid, (unsigned int)state->egid);
	if (GID_CHANGED && setregid(ID(rgid), ID(egid))) {
	    errstr = N_("unable to change to sudoers gid");
	    goto bad;
	}

	state->ruid = ROOT_UID;
	/*
	 * If sudoers_uid == ROOT_UID and sudoers_mode is group readable
	 * we use a non-zero uid in order to avoid NFS lossage.
	 * Using uid 1 is a bit bogus but should work on all OS's.
	 */
	if (sudoers_uid == ROOT_UID && (sudoers_mode & S_IRGRP))
	    state->euid = 1;
	else
	    state->euid = sudoers_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_SUDOERS: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (UID_CHANGED && setreuid(ID(ruid), ID(euid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_SUDOERS: setreuid(%u, %u)",
		(unsigned int)ID(ruid), (unsigned int)ID(euid));
	    goto bad;
	}
	break;
    }

    case PERM_TIMESTAMP:
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	state->rgid = ostate->rgid;
	state->egid = ostate->egid;
	state->ruid = ROOT_UID;
	state->euid = timestamp_get_uid();
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_TIMESTAMP: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (UID_CHANGED && setreuid(ID(ruid), ID(euid))) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_TIMESTAMP: setreuid(%u, %u)",
		(unsigned int)ID(ruid), (unsigned int)ID(euid));
	    goto bad;
	}
	break;
    }

    perm_stack_depth++;
    debug_return_bool(true);
bad:
    if (errno == EAGAIN)
	sudo_warnx(U_("%s: %s"), U_(errstr), U_("too many processes"));
    else
	sudo_warn("%s", U_(errstr));
    debug_return_bool(false);
}

bool
restore_perms(void)
{
    struct perm_state *state, *ostate;
    debug_decl(restore_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth < 2) {
	sudo_warnx("%s", U_("perm stack underflow"));
	debug_return_bool(true);
    }

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: uid: [%u, %u] -> [%u, %u]",
	__func__, (unsigned int)state->ruid, (unsigned int)state->euid,
	(unsigned int)ostate->ruid, (unsigned int)ostate->euid);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: gid: [%u, %u] -> [%u, %u]",
	__func__, (unsigned int)state->rgid, (unsigned int)state->egid,
	(unsigned int)ostate->rgid, (unsigned int)ostate->egid);

    /*
     * When changing euid to ROOT_UID, setreuid() may fail even if
     * the ruid is ROOT_UID so call setuid() first.
     */
    if (OID(euid) == ROOT_UID) {
	/* setuid() may not set the saved ID unless the euid is ROOT_UID */
	if (ID(euid) != ROOT_UID) {
	    if (setreuid(-1, ROOT_UID) != 0) {
		sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_ERRNO,
		    "setreuid() [%u, %u] -> [-1, %u)", (unsigned int)state->ruid,
		    (unsigned int)state->euid, ROOT_UID);
	    }
	}
	if (setuid(ROOT_UID)) {
	    sudo_warn("setuid() [%u, %u] -> %u)", (unsigned int)state->ruid,
		(unsigned int)state->euid, ROOT_UID);
	    goto bad;
	}
    }
    if (setreuid(OID(ruid), OID(euid))) {
	sudo_warn("setreuid() [%u, %u] -> [%u, %u]", (unsigned int)state->ruid,
	    (unsigned int)state->euid, (unsigned int)OID(ruid), (unsigned int)OID(euid));
	goto bad;
    }
    if (setregid(OID(rgid), OID(egid))) {
	sudo_warn("setregid() [%u, %u] -> [%u, %u]", (unsigned int)state->rgid,
	    (unsigned int)state->egid, (unsigned int)OID(rgid), (unsigned int)OID(egid));
	goto bad;
    }
    if (state->gidlist != ostate->gidlist) {
	if (sudo_setgroups(ostate->gidlist->ngids, ostate->gidlist->gids)) {
	    sudo_warn("setgroups()");
	    goto bad;
	}
    }
    sudo_gidlist_delref(state->gidlist);
    debug_return_bool(true);

bad:
    debug_return_bool(false);
}

#elif defined(HAVE_SETEUID)

#define GID_CHANGED (state->rgid != ostate->rgid || state->egid != ostate->egid)

/*
 * Set real and effective uids and gids based on perm.
 * We always retain a real or effective uid of ROOT_UID unless
 * we are headed for an exec().
 * This version of set_perms() works fine with the "stay_setuid" option.
 */
bool
set_perms(int perm)
{
    struct perm_state *state, *ostate = NULL;
    char errbuf[1024];
    const char *errstr = errbuf;
    debug_decl(set_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = N_("perm stack overflow");
	errno = EINVAL;
	goto bad;
    }

    if (perm == PERM_INITIAL) {
	if (perm_stack_depth > 1)
	    rewind_perms();
	perm_stack_depth = 0;
    } else {
	if (perm_stack_depth == 0) {
	    errstr = N_("perm stack underflow");
	    errno = EINVAL;
	    goto bad;
	}
	ostate = &perm_stack[perm_stack_depth - 1];
    }
    state = &perm_stack[perm_stack_depth];

    /*
     * Since we only have setuid() and seteuid() and semantics
     * for these calls differ on various systems, we set
     * real and effective uids to ROOT_UID initially to be safe.
     */
    if (perm != PERM_INITIAL) {
	if (ostate->euid != ROOT_UID && seteuid(ROOT_UID)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"set_perms: seteuid(%u)", ROOT_UID);
	    goto bad;
	}
	if (ostate->ruid != ROOT_UID && setuid(ROOT_UID)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"set_perms: setuid(%u)", ROOT_UID);
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
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_INITIAL: "
	    "ruid: %u, euid: %u, rgid: %u, egid: %u", __func__,
	    (unsigned int)state->ruid, (unsigned int)state->euid,
	    (unsigned int)state->rgid, (unsigned int)state->egid);
	break;

    case PERM_ROOT:
	/* We already set ruid/euid above. */
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, ROOT_UID, ROOT_UID);
	state->ruid = ROOT_UID;
	state->euid = ROOT_UID;
	state->rgid = ostate->rgid;
	state->egid = ROOT_GID;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, ROOT_GID, ROOT_GID);
	if (GID_CHANGED && setegid(ROOT_GID)) {
	    errstr = N_("unable to change to root gid");
	    goto bad;
	}
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	break;

    case PERM_USER:
	state->egid = user_gid;
	state->rgid = ostate->rgid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_USER: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, (unsigned int)state->rgid, (unsigned int)state->egid);
	if (GID_CHANGED && setegid(user_gid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_USER: setegid(%u)", (unsigned int)user_gid);
	    goto bad;
	}
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	if (state->gidlist != ostate->gidlist) {
	    if (sudo_setgroups(state->gidlist->ngids, state->gidlist->gids)) {
		errstr = "PERM_USER: setgroups";
		goto bad;
	    }
	}
	state->ruid = ROOT_UID;
	state->euid = user_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_USER: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (seteuid(user_uid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_USER: seteuid(%u)", (unsigned int)user_uid);
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	/* headed for exec() */
	state->rgid = user_gid;
	state->egid = user_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, (unsigned int)state->rgid, (unsigned int)state->egid);
	if (GID_CHANGED && setgid(user_gid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_FULL_USER: setgid(%u)", (unsigned int)user_gid);
	    goto bad;
	}
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	if (state->gidlist != ostate->gidlist) {
	    if (sudo_setgroups(state->gidlist->ngids, state->gidlist->gids)) {
		errstr = "PERM_FULL_USER: setgroups";
		goto bad;
	    }
	}
	state->ruid = user_uid;
	state->euid = user_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (setuid(user_uid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_FULL_USER: setuid(%u)", (unsigned int)user_uid);
	    goto bad;
	}
	break;

    case PERM_RUNAS:
	state->rgid = ostate->rgid;
	state->egid = runas_gr ? runas_gr->gr_gid : runas_pw->pw_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_RUNAS: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, (unsigned int)state->rgid, (unsigned int)state->egid);
	if (GID_CHANGED && setegid(state->egid)) {
	    errstr = N_("unable to change to runas gid");
	    goto bad;
	}
	state->gidlist = runas_setgroups();
	if (state->gidlist == NULL) {
	    errstr = N_("unable to set runas group vector");
	    goto bad;
	}
	state->ruid = ostate->ruid;
	state->euid = runas_pw ? runas_pw->pw_uid : user_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_RUNAS: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (seteuid(state->euid)) {
	    errstr = N_("unable to change to runas uid");
	    goto bad;
	}
	break;

    case PERM_SUDOERS: {
	const uid_t sudoers_uid = sudoers_file_uid();
	const gid_t sudoers_gid = sudoers_file_gid();
	const mode_t sudoers_mode = sudoers_file_mode();

	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);

	/* assume euid == ROOT_UID, ruid == user */
	state->rgid = ostate->rgid;
	state->egid = sudoers_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_SUDOERS: gid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->rgid,
	    (unsigned int)ostate->egid, (unsigned int)state->rgid, (unsigned int)state->egid);
	if (GID_CHANGED && setegid(sudoers_gid)) {
	    errstr = N_("unable to change to sudoers gid");
	    goto bad;
	}

	state->ruid = ROOT_UID;
	/*
	 * If sudoers_uid == ROOT_UID and sudoers_mode is group readable
	 * we use a non-zero uid in order to avoid NFS lossage.
	 * Using uid 1 is a bit bogus but should work on all OS's.
	 */
	if (sudoers_uid == ROOT_UID && (sudoers_mode & S_IRGRP))
	    state->euid = 1;
	else
	    state->euid = sudoers_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_SUDOERS: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (seteuid(state->euid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_SUDOERS: seteuid(%u)", (unsigned int)state->euid);
	    goto bad;
	}
	break;
    }

    case PERM_TIMESTAMP:
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	state->rgid = ostate->rgid;
	state->egid = ostate->egid;
	state->ruid = ROOT_UID;
	state->euid = timestamp_get_uid();
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_TIMESTAMP: uid: "
	    "[%u, %u] -> [%u, %u]", __func__, (unsigned int)ostate->ruid,
	    (unsigned int)ostate->euid, (unsigned int)state->ruid, (unsigned int)state->euid);
	if (seteuid(state->euid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_TIMESTAMP: seteuid(%u)", (unsigned int)state->euid);
	    goto bad;
	}
	break;
    }

    perm_stack_depth++;
    debug_return_bool(true);
bad:
    if (errno == EAGAIN)
	sudo_warnx(U_("%s: %s"), U_(errstr), U_("too many processes"));
    else
	sudo_warn("%s", U_(errstr));
    debug_return_bool(false);
}

bool
restore_perms(void)
{
    struct perm_state *state, *ostate;
    debug_decl(restore_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth < 2) {
	sudo_warnx("%s", U_("perm stack underflow"));
	debug_return_bool(true);
    }

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: uid: [%u, %u] -> [%u, %u]",
	__func__, (unsigned int)state->ruid, (unsigned int)state->euid,
	(unsigned int)ostate->ruid, (unsigned int)ostate->euid);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: gid: [%u, %u] -> [%u, %u]",
	__func__, (unsigned int)state->rgid, (unsigned int)state->egid,
	(unsigned int)ostate->rgid, (unsigned int)ostate->egid);

    /*
     * Since we only have setuid() and seteuid() and semantics
     * for these calls differ on various systems, we set
     * real and effective uids to ROOT_UID initially to be safe.
     */
    if (seteuid(ROOT_UID)) {
	sudo_warn("seteuid() [%u] -> [%u]", (unsigned int)state->euid, ROOT_UID);
	goto bad;
    }
    if (setuid(ROOT_UID)) {
	sudo_warn("setuid() [%u, %u] -> [%u, %u]", (unsigned int)state->ruid, ROOT_UID,
	    ROOT_UID, ROOT_UID);
	goto bad;
    }

    if (OID(egid) != (gid_t)-1 && setegid(ostate->egid)) {
	sudo_warn("setegid(%u)", (unsigned int)ostate->egid);
	goto bad;
    }
    if (state->gidlist != ostate->gidlist) {
	if (sudo_setgroups(ostate->gidlist->ngids, ostate->gidlist->gids)) {
	    sudo_warn("setgroups()");
	    goto bad;
	}
    }
    if (OID(euid) != (uid_t)-1 && seteuid(ostate->euid)) {
	sudo_warn("seteuid(%u)", (unsigned int)ostate->euid);
	goto bad;
    }
    sudo_gidlist_delref(state->gidlist);
    debug_return_bool(true);

bad:
    debug_return_bool(false);
}

#else /* !HAVE_SETRESUID && !HAVE_SETREUID && !HAVE_SETEUID */

/*
 * Set uids and gids based on perm via setuid() and setgid().
 * NOTE: does not support the "stay_setuid" or timestampowner options.
 *       Also, sudoers_uid and sudoers_gid are not used.
 */
bool
set_perms(int perm)
{
    struct perm_state *state, *ostate = NULL;
    char errbuf[1024];
    const char *errstr = errbuf;
    debug_decl(set_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth == PERM_STACK_MAX) {
	errstr = N_("perm stack overflow");
	errno = EINVAL;
	goto bad;
    }

    if (perm == PERM_INITIAL) {
	if (perm_stack_depth > 1)
	    rewind_perms();
	perm_stack_depth = 0;
    } else {
	if (perm_stack_depth == 0) {
	    errstr = N_("perm stack underflow");
	    errno = EINVAL;
	    goto bad;
	}
	ostate = &perm_stack[perm_stack_depth - 1];
    }
    state = &perm_stack[perm_stack_depth];

    switch (perm) {
    case PERM_INITIAL:
	/* Stash initial state */
	state->ruid = geteuid() == ROOT_UID ? ROOT_UID : getuid();
	state->rgid = getgid();
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_INITIAL: "
	    "ruid: %u, rgid: %u", __func__, (unsigned int)state->ruid, (unsigned int)state->rgid);
	break;

    case PERM_ROOT:
	state->ruid = ROOT_UID;
	state->rgid = ROOT_GID;
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: uid: "
	    "[%u] -> [%u]", __func__, (unsigned int)ostate->ruid, (unsigned int)state->ruid);
	if (setuid(ROOT_UID)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_ROOT: setuid(%u)", ROOT_UID);
	    goto bad;
	}
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_ROOT: gid: "
	    "[%u] -> [%u]", __func__, (unsigned int)ostate->rgid, (unsigned int)state->rgid);
	if (setgid(ROOT_GID)) {
	    errstr = N_("unable to change to root gid");
	    goto bad;
	}
	break;

    case PERM_FULL_USER:
	state->rgid = user_gid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: gid: "
	    "[%u] -> [%u]", __func__, (unsigned int)ostate->rgid, (unsigned int)state->rgid);
	(void) setgid(user_gid);
	state->gidlist = user_gid_list;
	sudo_gidlist_addref(state->gidlist);
	if (state->gidlist != ostate->gidlist) {
	    if (sudo_setgroups(state->gidlist->ngids, state->gidlist->gids)) {
		errstr = "PERM_FULL_USER: setgroups";
		goto bad;
	    }
	}
	state->ruid = user_uid;
	sudo_debug_printf(SUDO_DEBUG_INFO, "%s: PERM_FULL_USER: uid: "
	    "[%u] -> [%u]", __func__, (unsigned int)ostate->ruid, (unsigned int)state->ruid);
	if (setuid(user_uid)) {
	    (void)snprintf(errbuf, sizeof(errbuf),
		"PERM_FULL_USER: setuid(%u)", (unsigned int)user_uid);
	    goto bad;
	}
	break;

    case PERM_USER:
    case PERM_SUDOERS:
    case PERM_RUNAS:
    case PERM_TIMESTAMP:
	/* Unsupported since we can't set euid. */
	state->ruid = ostate->ruid;
	state->rgid = ostate->rgid;
	state->gidlist = ostate->gidlist;
	sudo_gidlist_addref(state->gidlist);
	break;
    }

    perm_stack_depth++;
    debug_return_bool(true);
bad:
    if (errno == EAGAIN)
	sudo_warnx(U_("%s: %s"), U_(errstr), U_("too many processes"));
    else
	sudo_warn("%s", U_(errstr));
    debug_return_bool(false);
}

bool
restore_perms(void)
{
    struct perm_state *state, *ostate;
    debug_decl(restore_perms, SUDOERS_DEBUG_PERMS);

    if (perm_stack_depth < 2) {
	sudo_warnx("%s", U_("perm stack underflow"));
	debug_return_bool(true);
    }

    state = &perm_stack[perm_stack_depth - 1];
    ostate = &perm_stack[perm_stack_depth - 2];
    perm_stack_depth--;

    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: uid: [%u] -> [%u]",
	__func__, (unsigned int)state->ruid, (unsigned int)ostate->ruid);
    sudo_debug_printf(SUDO_DEBUG_INFO, "%s: gid: [%u] -> [%u]",
	__func__, (unsigned int)state->rgid, (unsigned int)ostate->rgid);

    if (OID(rgid) != (gid_t)-1 && setgid(ostate->rgid)) {
	sudo_warn("setgid(%u)", (unsigned int)ostate->rgid);
	goto bad;
    }
    if (state->gidlist != ostate->gidlist) {
	if (sudo_setgroups(ostate->gidlist->ngids, ostate->gidlist->gids)) {
	    sudo_warn("setgroups()");
	    goto bad;
	}
    }
    sudo_gidlist_delref(state->gidlist);
    if (OID(ruid) != (uid_t)-1 && setuid(ostate->ruid)) {
	sudo_warn("setuid(%u)", (unsigned int)ostate->ruid);
	goto bad;
    }
    debug_return_bool(true);

bad:
    debug_return_bool(false);
}
#endif /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */

#if defined(HAVE_SETRESUID) || defined(HAVE_SETREUID) || defined(HAVE_SETEUID)
static struct gid_list *
runas_setgroups(void)
{
    struct gid_list *gidlist;
    debug_decl(runas_setgroups, SUDOERS_DEBUG_PERMS);

    gidlist = runas_getgroups();
    if (gidlist != NULL && !def_preserve_groups) {
	if (sudo_setgroups(gidlist->ngids, gidlist->gids) < 0) {
	    sudo_gidlist_delref(gidlist);
	    gidlist = NULL;
	}
    }
    debug_return_ptr(gidlist);
}
#endif /* HAVE_SETRESUID || HAVE_SETREUID || HAVE_SETEUID */
