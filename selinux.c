/*
 * Copyright (c) 2009-2010 Todd C. Miller <Todd.Miller@courtesan.com>
 * Copyright (c) 2008 Dan Walsh <dwalsh@redhat.com>
 *
 * Borrowed heavily from newrole source code
 * Authors:
 *	Anthony Colatrella
 *	Tim Fraser
 *	Steve Grubb <sgrubb@redhat.com>
 *	Darrel Goeddel <DGoeddel@trustedcs.com>
 *	Michael Thompson <mcthomps@us.ibm.com>
 *	Dan Walsh <dwalsh@redhat.com>
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

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#ifdef HAVE_LINUX_AUDIT
#include <libaudit.h>
#endif

#include <selinux/flask.h>             /* for SECCLASS_CHR_FILE */
#include <selinux/selinux.h>           /* for is_selinux_enabled() */
#include <selinux/context.h>           /* for context-mangling functions */
#include <selinux/get_default_type.h>
#include <selinux/get_context_list.h>

#include "sudo.h"
#include "linux_audit.h"

static struct selinux_state {
    security_context_t old_context;
    security_context_t new_context;
    security_context_t tty_context;
    security_context_t new_tty_context;
    const char *ttyn;
    int ttyfd;
    int enforcing;
} se_state;

/*
 * This function attempts to revert the relabeling done to the tty.
 * fd		   - referencing the opened ttyn
 * ttyn		   - name of tty to restore
 *
 * Returns zero on success, non-zero otherwise
 */
int
selinux_restore_tty(void)
{
    int retval = 0;
    security_context_t chk_tty_context = NULL;

    if (se_state.ttyfd == -1 || se_state.new_tty_context == NULL)
	goto skip_relabel;

    /* Verify that the tty still has the context set by sudo. */
    if ((retval = fgetfilecon(se_state.ttyfd, &chk_tty_context)) < 0) {
	warning("unable to fgetfilecon %s", se_state.ttyn);
	goto skip_relabel;
    }

    if ((retval = strcmp(chk_tty_context, se_state.new_tty_context))) {
	warningx("%s changed labels.", se_state.ttyn);
	goto skip_relabel;
    }

    if ((retval = fsetfilecon(se_state.ttyfd, se_state.tty_context)) < 0)
	warning("unable to restore context for %s", se_state.ttyn);

skip_relabel:
    if (se_state.ttyfd != -1) {
	close(se_state.ttyfd);
	se_state.ttyfd = -1;
    }
    if (chk_tty_context != NULL) {
	freecon(chk_tty_context);
	chk_tty_context = NULL;
    }
    return retval;
}

/*
 * This function attempts to relabel the tty. If this function fails, then
 * the contexts are free'd and -1 is returned. On success, 0 is returned
 * and tty_context and new_tty_context are set.
 *
 * This function will not fail if it can not relabel the tty when selinux is
 * in permissive mode.
 */
static int
relabel_tty(const char *ttyn, int ptyfd)
{
    security_context_t tty_con = NULL;
    security_context_t new_tty_con = NULL;
    int fd;

    se_state.ttyfd = ptyfd;

    /* It is perfectly legal to have no tty. */
    if (ptyfd == -1 && ttyn == NULL)
	return 0;

    /* If sudo is not allocating a pty for the command, open current tty. */
    if (ptyfd == -1) {
	se_state.ttyfd = open(ttyn, O_RDWR|O_NONBLOCK);
	if (se_state.ttyfd == -1) {
	    warning("unable to open %s, not relabeling tty", ttyn);
	    if (se_state.enforcing)
		goto bad;
	}
	(void)fcntl(se_state.ttyfd, F_SETFL,
	    fcntl(se_state.ttyfd, F_GETFL, 0) & ~O_NONBLOCK);
    }

    if (fgetfilecon(se_state.ttyfd, &tty_con) < 0) {
	warning("unable to get current tty context, not relabeling tty");
	if (se_state.enforcing)
	    goto bad;
    }

    if (tty_con && (security_compute_relabel(se_state.new_context, tty_con,
	SECCLASS_CHR_FILE, &new_tty_con) < 0)) {
	warning("unable to get new tty context, not relabeling tty");
	if (se_state.enforcing)
	    goto bad;
    }

    if (new_tty_con != NULL) {
	if (fsetfilecon(se_state.ttyfd, new_tty_con) < 0) {
	    warning("unable to set new tty context");
	    if (se_state.enforcing)
		goto bad;
	}
    }

    if (ptyfd != -1) {
	/* Reopen pty that was relabeled, std{in,out,err} are reset later. */
	se_state.ttyfd = open(ttyn, O_RDWR|O_NOCTTY, 0);
	if (se_state.ttyfd == -1) {
	    warning("cannot open %s", ttyn);
	    if (se_state.enforcing)
		goto bad;
	}
	if (dup2(se_state.ttyfd, ptyfd) == -1) {
	    warning("dup2");
	    goto bad;
	}
    } else {
	/* Re-open tty to get new label and reset std{in,out,err} */
	close(se_state.ttyfd);
	se_state.ttyfd = open(ttyn, O_RDWR|O_NONBLOCK);
	if (se_state.ttyfd == -1) {
	    warning("unable to open %s", ttyn);
	    goto bad;
	}
	(void)fcntl(se_state.ttyfd, F_SETFL,
	    fcntl(se_state.ttyfd, F_GETFL, 0) & ~O_NONBLOCK);
	for (fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
	    if (isatty(fd) && dup2(se_state.ttyfd, fd) == -1) {
		warning("dup2");
		goto bad;
	    }
	}
    }
    /* Retain se_state.ttyfd so we can restore label when command finishes. */
    (void)fcntl(se_state.ttyfd, F_SETFD, FD_CLOEXEC);

    se_state.ttyn = ttyn;
    se_state.tty_context = tty_con;
    se_state.new_tty_context = new_tty_con;
    return 0;

bad:
    if (se_state.ttyfd != -1 && se_state.ttyfd != ptyfd) {
	close(se_state.ttyfd);
	se_state.ttyfd = -1;
    }
    freecon(tty_con);
    return -1;
}

/*
 * Returns a new security context based on the old context and the
 * specified role and type.
 */
security_context_t
get_exec_context(security_context_t old_context, const char *role, const char *type)
{
    security_context_t new_context = NULL;
    context_t context = NULL;
    char *typebuf = NULL;
    
    /* We must have a role, the type is optional (we can use the default). */
    if (!role) {
	warningx("you must specify a role for type %s", type);
	errno = EINVAL;
	return NULL;
    }
    if (!type) {
	if (get_default_type(role, &typebuf)) {
	    warningx("unable to get default type for role %s", role);
	    errno = EINVAL;
	    return NULL;
	}
	type = typebuf;
    }
    
    /* 
     * Expand old_context into a context_t so that we extract and modify 
     * its components easily. 
     */
    context = context_new(old_context);
    
    /*
     * Replace the role and type in "context" with the role and
     * type we will be running the command as.
     */
    if (context_role_set(context, role)) {
	warning("failed to set new role %s", role);
	goto bad;
    }
    if (context_type_set(context, type)) {
	warning("failed to set new type %s", type);
	goto bad;
    }
      
    /*
     * Convert "context" back into a string and verify it.
     */
    new_context = estrdup(context_str(context));
    if (security_check_context(new_context) < 0) {
	warningx("%s is not a valid context", new_context);
	errno = EINVAL;
	goto bad;
    }

#ifdef DEBUG
    warningx("Your new context is %s", new_context);
#endif

    context_free(context);
    return new_context;

bad:
    free(typebuf);
    context_free(context);
    freecon(new_context);
    return NULL;
}

/* 
 * Set the exec and tty contexts in preparation for fork/exec.
 * Must run as root, before the uid change.
 * If ptyfd is not -1, it indicates we are running
 * in a pty and do not need to reset std{in,out,err}.
 * Returns 0 on success and -1 on failure.
 */
int
selinux_setup(const char *role, const char *type, const char *ttyn,
    int ptyfd)
{
    int rval = -1;

    /* Store the caller's SID in old_context. */
    if (getprevcon(&se_state.old_context)) {
	warning("failed to get old_context");
	goto done;
    }

    se_state.enforcing = security_getenforce();
    if (se_state.enforcing < 0) {
	warning("unable to determine enforcing mode.");
	goto done;
    }

#ifdef DEBUG
    warningx("your old context was %s", se_state.old_context);
#endif
    se_state.new_context = get_exec_context(se_state.old_context, role, type);
    if (!se_state.new_context)
	goto done;
    
    if (relabel_tty(ttyn, ptyfd) < 0) {
	warning("unable to setup tty context for %s", se_state.new_context);
	goto done;
    }

#ifdef DEBUG
    if (se_state.ttyfd != -1) {
	warningx("your old tty context is %s", se_state.tty_context);
	warningx("your new tty context is %s", se_state.new_tty_context);
    }
#endif

#ifdef HAVE_LINUX_AUDIT
    linux_audit_role_change(se_state.old_context, se_state.new_context,
	se_state.ttyn);
#endif

    rval = 0;

done:
    return rval;
}

void
selinux_execve(const char *path, char *argv[], char *envp[])
{
    if (setexeccon(se_state.new_context)) {
	warning("unable to set exec context to %s", se_state.new_context);
	if (se_state.enforcing)
	    return;
    }

#ifdef HAVE_SETKEYCREATECON
    if (setkeycreatecon(se_state.new_context)) {
	warning("unable to set key creation context to %s", se_state.new_context);
	if (se_state.enforcing)
	    return;
    }
#endif /* HAVE_SETKEYCREATECON */

    /* We use the "spare" slot in argv to store sesh. */
    --argv;
    argv[0] = *argv[1] == '-' ? "-sesh" : "sesh";
    argv[1] = (char *)path;

    execve(_PATH_SUDO_SESH, argv, envp);
}
