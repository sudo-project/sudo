/*
 * Copyright (c) 2004 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include "config.h"

#include <sys/param.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_ERR_H
# include <err.h>
#else
# include "emul/err.h"
#endif /* HAVE_ERR_H */
#ifdef HAVE_DEV_SYSTRACE_H
# include <dev/systrace.h>
#else
# ifdef HAVE_SYS_SYSTRACE_H
#  include <sys/systrace.h>
# else
#  ifdef HAVE_LINUX_SYSTRACE_H
#   include <linux/systrace.h>
#  else
#   include <systrace.h>
#  endif
# endif
#endif

#include "sudo.h"
#include "trace_systrace.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Open the systrace device and return the fd or -1 on failure.
 */
static int
systrace_open()
{
    int serrno, fd;

    fd = open(_PATH_DEV_SYSTRACE, O_RDONLY, 0644);
    if (fd == -1)
	return(-1);
    serrno = errno;

#ifdef SYSTR_CLONE
    {
	int tfd;
	if (ioctl(fd, STRIOCCLONE, &tfd) == -1)
	    goto bad;
	close(fd);
	fd = tfd;
    }
#endif
    if (fcntl(fd, F_SETFD, 1) == -1)	/* really needed? */
    	goto bad;

    return(fd);
bad:
    close(fd);
    errno = serrno;
    return(-1);
}

static void
sigusr1(signo)
    int signo;
{
    return;
}

/*
 * Fork a process that traces the command to be run and its descendents.
 *
 * TODO:
 *	set SUDO_* env variables for sub-execs
 */
void
systrace_attach(pid)
    pid_t pid;
{
    schandler_t handler;
    struct systrace_answer ans;
    struct str_message msg;
    sigaction_t sa, osa;
    sigset_t set, oset;
    ssize_t nread;
    int fd, cookie;

    if ((fd = systrace_open()) == -1)
	err(1, "unable to open systrace");
    fflush(stdout);

    /*
     * Do signal setup early so there is no race between when the tracer
     * kill()s the tracee and when the tracee calls sigsuspend().
     */ 
    sigfillset(&set);
    if (sigprocmask(SIG_BLOCK, &set, &oset) != 0)
	err(1, "sigprocmask");
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = sigusr1;
    if (sigaction(SIGUSR1, &sa, &osa) != 0)
	err(1, "sigaction");

    switch (fork()) {
    case -1:
	err(1, "can't fork");
    case 0:
	/* tracer */
	break;
    default:
	/* tracee, sleep until the tracer process wakes us up. */
	close(fd);
	sigdelset(&set, SIGUSR1);
	(void) sigsuspend(&set);
	if (sigprocmask(SIG_SETMASK, &oset, NULL) != 0) {
	    warn("sigprocmask");
	    exit(1);
	}
	return;
    }

    /* reset signal state for tracer */
    if (sigaction(SIGUSR1, &osa, NULL) != 0 ||
	sigprocmask(SIG_SETMASK, &oset, NULL) != 0) {
	warn("unable to setup signals for %s", user_cmnd);
	goto fail;
    }

    /* become a daemon */
    if (setsid() == -1) {
	warn("setsid");
	kill(pid, SIGKILL);
	_exit(1);
    }
    (void) chdir("/");
#ifdef HAVE_SETPROCTITLE
    setproctitle("systrace %s%s%s", user_base, user_args ? " " : "",
	user_args ? user_args : "");
#endif

    if (ioctl(fd, STRIOCATTACH, &pid) == -1) {
	if (errno == EBUSY) {
	    /* already being traced, nothing to do */
	    (void) kill(pid, SIGUSR1);
	    _exit(0);
	}
	warn("unable to systrace %s", user_cmnd);
	goto fail;
    }

    new_child(-1, pid);
    if (set_policy(fd, children.first) != 0) {
	warn("failed to set policy for %s", user_cmnd);
	goto fail;
    }

    if (kill(pid, SIGUSR1) != 0) {
	warn("unable to wake up sleeping child");
	_exit(1);
    }

    /* handle systrace events until the child finishes */
    for (;;) {
	nread = read(fd, &msg, sizeof(msg));
	if (nread != sizeof(msg)) {
	    if (nread == -1 && (errno == EINTR || errno == EAGAIN))
		continue;
	    killall(&children, SIGKILL);
	    _exit(nread != 0);	/* shouldn't happen */
	}

	switch (msg.msg_type) {
	    case SYSTR_MSG_CHILD:
		/* either a fork or an exit */
		if (msg.msg_data.msg_child.new_pid != -1) {
			new_child(msg.msg_pid, msg.msg_data.msg_child.new_pid);
		} else {
			rm_child(msg.msg_pid);
			if (children.first == NULL)
			    _exit(0);
		}
		break;

	    case SYSTR_MSG_UGID:
		/* uid/gid change */
		memset(&ans, 0, sizeof(ans));
		ans.stra_pid = msg.msg_pid;
		ans.stra_seqnr = msg.msg_seqnr;
		ans.stra_policy = SYSTR_POLICY_PERMIT;
		if ((ioctl(fd, STRIOCANSWER, &ans)) == 0)
		    update_child(msg.msg_pid, msg.msg_data.msg_ugid.uid);
		break;

	    case SYSTR_MSG_ASK:
		memset(&ans, 0, sizeof(ans));
		ans.stra_pid = msg.msg_pid;
		ans.stra_seqnr = msg.msg_seqnr;
		ans.stra_policy = SYSTR_POLICY_PERMIT;
		handler = find_handler(msg.msg_pid, msg.msg_data.msg_ask.code);
		if (handler != NULL) {
		    /*
		     * The handler is run twice, once before we answer and
		     * once after.  We only want to log attempts when our
		     * answer is accepted; otherwise we can get dupes.
		     */
		    cookie = handler(fd, msg.msg_pid, &msg.msg_data.msg_ask, -1,
			&ans.stra_policy, &ans.stra_error);
			if (ioctl(fd, STRIOCANSWER, &ans) == 0)
			    handler(fd, msg.msg_pid, &msg.msg_data.msg_ask,
				cookie, &ans.stra_policy, &ans.stra_error);
		} else
		    (void) ioctl(fd, STRIOCANSWER, &ans);
		break;

	    case SYSTR_MSG_EMUL:
		/* Change in emulation. */
		memset(&ans, 0, sizeof(ans));
		ans.stra_pid = msg.msg_pid;
		ans.stra_seqnr = msg.msg_seqnr;
		if (switch_emulation(fd, &msg) == 0)
		    ans.stra_policy = SYSTR_POLICY_PERMIT;
		else {
		    warnx("unsupported emulation \"%s\"",
			msg.msg_data.msg_emul.emul);
		    ans.stra_policy = SYSTR_POLICY_NEVER;
		}
		(void) ioctl(fd, STRIOCANSWER, &ans);
		break;

#ifdef SYSTR_MSG_POLICYFREE
	    case SYSTR_MSG_POLICYFREE:
		break;
#endif

	    default:
#ifdef SUDO_DEVEL
		warnx("unexpected message type %d", msg.msg_type);
#endif
		memset(&ans, 0, sizeof(ans));
		ans.stra_pid = msg.msg_pid;
		ans.stra_seqnr = msg.msg_seqnr;
		ans.stra_policy = SYSTR_POLICY_PERMIT;
		(void) ioctl(fd, STRIOCANSWER, &ans);
		break;
	}
    }

fail:
    killall(&children, SIGKILL);
    _exit(1);
}

/*
 * Push a new child to the head of the list, inheriting the struct pw
 * of its parent.
 */
static void
new_child(ppid, pid)
    pid_t ppid;
    pid_t pid;
{
    struct childinfo *entry;
    struct passwd *pw;
    struct syscallaction *action;
    struct emulation *emul;

    if (ppid != -1 && (entry = find_child(ppid)) != NULL) {
	pw = entry->pw;
	action = entry->action;
    } else {
	pw = runas_pw;
	for (emul = emulations; emul != NULL; emul++)
	    if (strcmp(emul->name, "native") == 0) {
		action = emul->action;
		break;
	    }
	if (emul == NULL)
	    errx(1, "unable to find native emulation!");
    }
    entry = (struct childinfo *) emalloc(sizeof(*entry));
    entry->pid = pid;
    entry->pw = sudo_pwdup(pw, 0);
    entry->action = action;
    entry->next = children.first;
    children.first = entry;
}

static int
switch_emulation(fd, msgp)
    int fd;
    struct str_message *msgp;
{
    struct childinfo *entry;
    struct emulation *emul;

    if ((entry = find_child(msgp->msg_pid)) == NULL)
	return(-1);
    for (emul = emulations; emul != NULL; emul++)
	if (strcmp(emul->name, msgp->msg_data.msg_emul.emul) == 0) {
	    entry->action = emul->action;
	    return(set_policy(fd, entry));
	}
    return(-1);
}

/*
 * Remove the named pid from the list.
 */
static void
rm_child(pid)
    pid_t pid;
{
    struct childinfo *cur, *prev;

    for (prev = NULL, cur = children.first; cur != NULL; cur = cur->next) {
	if (cur->pid == pid) {
	    if (prev != NULL)
		prev->next = cur->next;
	    else
		children.first = cur->next;
	    free(cur->pw);
	    free(cur);
	    break;
	}
	prev = cur;
    }
}

/*
 * Find a child by pid.
 */
static struct childinfo *
find_child(pid)
    pid_t pid;
{
    struct childinfo *cur;

    for (cur = children.first; cur != NULL; cur = cur->next) {
	if (cur->pid == pid)
	    return(cur);
    }
    return(NULL);
}

/*
 * Update the uid associated with a pid.
 */
static void
update_child(pid, uid)
    pid_t pid;
    uid_t uid;
{
    struct childinfo *child;

    if ((child = find_child(pid)) == NULL)
	return;		/* cannot happen */

    if (child->pw->pw_uid != uid) {
	free(child->pw);
	/* lookup uid in passwd db, using a stub on failure */
	if ((child->pw = sudo_getpwuid(uid)) == NULL) {
	    child->pw = emalloc(sizeof(struct passwd) + MAX_UID_T_LEN + 1);
	    memset(child->pw, 0, sizeof(struct passwd));
	    child->pw->pw_uid = uid;
	    child->pw->pw_name = (char *)child->pw + sizeof(struct passwd);
	    (void) snprintf(child->pw->pw_name, MAX_UID_T_LEN + 1, "%lu",
		(unsigned long) uid);
	}
    }
}

/*
 * Create a policy that intercepts execve and lets all others go free.
 */
static int
set_policy(fd, child)
    int fd;
    struct childinfo *child;
{
    struct syscallaction *sca;
    struct systrace_policy pol;
    int i;

    pol.strp_op = SYSTR_POLICY_NEW;
    pol.strp_num = -1;
    pol.strp_maxents = SYSTRACE_MAXENTS;
    if (ioctl(fd, STRIOCPOLICY, &pol) == -1)
	return(-1);

    pol.strp_op = SYSTR_POLICY_ASSIGN;
    pol.strp_pid = child->pid;
    if (ioctl(fd, STRIOCPOLICY, &pol) == -1)
	return(-1);

    for (i = 0; i < SYSTRACE_MAXENTS; i++) {
	pol.strp_op = SYSTR_POLICY_MODIFY;
	pol.strp_policy = SYSTR_POLICY_PERMIT;
	pol.strp_code = i;
	for (sca = child->action; sca->code != -1; sca++) {
	    if (sca->code == i) {
		pol.strp_policy = sca->policy;
		break;
	    }
	}
	if (ioctl(fd, STRIOCPOLICY, &pol) == -1)
	    return(-1);
    }
    return(0);
}

/*
 * Read from an address and store in buf.
 * XXX - should deal with EBUSY from STRIOCIO
 */
static int
systrace_read(fd, pid, addr, buf, bufsiz)
    int fd;
    pid_t pid;
    void *addr;
    void *buf;
    size_t bufsiz;
{
    struct systrace_io io;

    memset(&io, 0, sizeof(io));
    io.strio_pid = pid;
    io.strio_addr = buf;
    io.strio_len = bufsiz;
    io.strio_offs = addr;
    io.strio_op = SYSTR_READ;
    return(ioctl(fd, STRIOCIO, &io));
}

/*
 * Read up to bufsiz bytes from addr into buf, stopping when we hit
 * a NUL byte.  Reads are done in chunks since STRIOCIO cannot
 * handle a strio_len > the actual kernel buffer.  It might be nice
 * to pass a starting chunksize though.
 */
static ssize_t
read_string(fd, pid, addr, buf, bufsiz)
    int fd;
    pid_t pid;
    void *addr;
    char *buf;
    size_t bufsiz;
{
    size_t chunksiz = 32;
    char *cp = buf, *ep;

    while (bufsiz >= chunksiz) {
	if (systrace_read(fd, pid, addr, cp, chunksiz) == 0) {
	    if ((ep = memchr(cp, '\0', chunksiz)) != NULL) {
		cp = ep;	/* found NUL byte in chunk, done */
		break;
	    }
	    cp += chunksiz;
	    addr += chunksiz;
	    bufsiz -= chunksiz;
	} else {
	    if (errno != EINVAL || chunksiz == 4)
		    return(-1);
	    chunksiz >>= 1;	/* chunksiz too big, half it */
	}
    }
    *cp = '\0';
    return(bufsiz >= chunksiz ? cp - buf : -1);
}

static schandler_t
find_handler(pid, code)
    pid_t pid;
    int code;
{
    struct syscallaction *sca;
    struct childinfo *child;

    if ((child = find_child(pid)) == NULL) {
	warnx("unable to find child with pid %d", pid);
	return(NULL);
    }
    for (sca = child->action; sca->code != -1; sca++) {
	if (sca->code == code)
	    return(sca->handler);
    }
    return(NULL);
}

/*
 * Decode path and argv from systrace and fill in user_cmnd,
 * user_base and user_args.
 */
static int
decode_args(fd, pid, askp)
    int fd;
    pid_t pid;
    struct str_msg_ask *askp;
{
    ssize_t len;
    char *off, *ap, *cp, *ep;
    static char pbuf[PATH_MAX], abuf[ARG_MAX];

    memset(pbuf, 0, sizeof(pbuf));
    if (read_string(fd, pid, (void *)askp->args[0], pbuf, sizeof(pbuf)) == -1)
	return(-1);
    if ((user_base = strrchr(user_cmnd = pbuf, '/')) != NULL)
	user_base++;
    else
	user_base = user_cmnd;
    user_args = NULL;

    /*
     * Loop through argv, collapsing it into a single string and reading
     * until we hit the terminating NULL.  We skip argv[0].
     */
    off = (char *)askp->args[1];
    for (cp = abuf, ep = abuf + sizeof(abuf); cp < ep; off += sizeof(char *)) {
	if (systrace_read(fd, pid, off, &ap, sizeof(ap)) != 0) {
	    warn("STRIOCIO");
	    return(-1);
	}
	if (ap == NULL) {
	    if (cp != abuf) {
		cp[-1] = '\0';	/* replace final space with a NUL */
		user_args = abuf;
	    }
	    break;
	}
	if (off == (char *)askp->args[1])
	    continue;			/* skip argv[0] */
	if ((len = read_string(fd, pid, ap, cp, ep - cp)) == -1)
	    return(-1);
	cp += len;
	*cp++ = ' ';		/* replace NUL with a space */
    }
    /* XXX - detect cp >= ep */
    return(0);
}

/*
 * Decode the args to exec and check the command in sudoers.
 */
static int
check_exec(fd, pid, askp, cookie, policyp, errorp)
    int fd;
    pid_t pid;
    struct str_msg_ask *askp;
    int cookie;
    int *policyp;
    int *errorp;
{
    int validated;
    struct childinfo *info;

    /* If we have a cookie we take special action. */
    if (cookie != -1) {
	if (cookie != 0)
	    log_auth(cookie, 1);
	return(0);
    }

    /* We're not really initialized until the first exec finishes. */
    if (initialized == 0) {
	initialized = 1;
	*policyp = SYSTR_POLICY_PERMIT;
	return(0);
    }

    /* Failure should not be possible. */
    if ((info = find_child(pid)) == NULL) {
	*policyp = SYSTR_POLICY_NEVER;
	*errorp = ECHILD;
	return(0);
    }

    /* Fill in user_cmnd, user_base, user_args and user_stat.  */
    decode_args(fd, pid, askp);
    if (user_cmnd[0] != '/' || !sudo_goodpath(user_cmnd, user_stat)) {
	*policyp = SYSTR_POLICY_NEVER;
	*errorp = EACCES;
	return(0);
    }

    /* Get processes's cwd. */
    if (ioctl(fd, STRIOCGETCWD, &pid) == -1 ||
	!getcwd(user_cwd, sizeof(user_cwd))) {
	warnx("cannot get working directory");
	(void) strlcpy(user_cwd, "unknown", sizeof(user_cwd));
    } else
	(void) ioctl(fd, STRIOCRESCWD, 0);

    /* Check sudoers and log the result. */
    init_defaults();
    def_authenticate = FALSE;
    runas_pw = info->pw;
    user_runas = &info->pw->pw_name;
    rewind(sudoers_fp);
    validated = sudoers_lookup(0);
    if (ISSET(validated, VALIDATE_OK)) {
	*policyp = SYSTR_POLICY_PERMIT;
    } else {
	*policyp = SYSTR_POLICY_NEVER;
	*errorp = EACCES;
    }
    return(validated);
}

/*
 * Kill all pids in the list
 */
static void
killall(head, sig)
    struct listhead *head;
    int sig;
{
    struct childinfo *child;

    for (child = head->first; child != NULL; child = child->next)
	(void) kill(child->pid, sig);
}
