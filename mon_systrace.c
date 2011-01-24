/*
 * Copyright (c) 2004-2005 Todd C. Miller <Todd.Miller@courtesan.com>
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
#include "mon_systrace.h"

/*
 * Open the systrace device and return the fd or -1 on failure.
 */
static int
systrace_open()
{
    int serrno, fd;

    fd = open(_PATH_DEV_SYSTRACE, O_RDONLY, 0644);
    if (fd == -1)
	return -1;
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

    return fd;
bad:
    close(fd);
    errno = serrno;
    return -1;
}

static void
catchsig(signo)
    int signo;
{
    dodetach = signo;
    return;
}

/*
 * Fork a process that monitors the command to be run and its descendents.
 * The monitoring process will detach upon receipt of SIGHUP, SIGINT or SIGTERM.
 */
void
systrace_attach(pid)
    pid_t pid;
{
    struct syscallhandler *handler;
    struct systrace_answer ans;
    struct str_message msg;
    sigaction_t sa, osa;
    sigset_t set, oset;
    ssize_t nread;
    int fd, status;

    if ((fd = systrace_open()) == -1)
	error(1, "unable to open systrace");
    fflush(stdout);

    /*
     * Do signal setup early so there is no race between when the tracer
     * kill()s the tracee and when the tracee calls sigsuspend().
     */ 
    sigfillset(&set);
    if (sigprocmask(SIG_BLOCK, &set, &oset) != 0)
	error(1, "sigprocmask");
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT;
    sa.sa_handler = catchsig;
    if (sigaction(SIGUSR1, &sa, &osa) != 0)
	error(1, "sigaction");

    switch (fork()) {
    case -1:
	error(1, "can't fork");
    case 0:
	/* tracer, fork again to completely disassociate */
	switch (fork()) {
	    case -1:
		warning("can't fork");
		kill(pid, SIGKILL);
		_exit(1);
	    case 0:
		break;
	    default:
		/* the main sudo process will wait for us */
		_exit(0);
	}
	break;
    default:
	/* tracee, sleep until the tracer process wakes us up. */
	close(fd);
	sigdelset(&set, SIGUSR1);
	(void) sigsuspend(&set);
	if (sigprocmask(SIG_SETMASK, &oset, NULL) != 0) {
	    warning("sigprocmask");
	    exit(1);
	}
	return;
    }

    /* set signal state for tracer */
    dodetach = 0;
    zero_bytes(&sa, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_INTERRUPT;
    sa.sa_handler = catchsig;
    if (sigaction(SIGUSR1, &osa, NULL) != 0 ||
	sigaction(SIGHUP, &sa, NULL) != 0 ||
	sigaction(SIGINT, &sa, NULL) != 0 ||
	sigaction(SIGTERM, &sa, NULL) != 0 ||
	sigprocmask(SIG_SETMASK, &oset, NULL) != 0) {
	warning("unable to setup signals for %s", user_cmnd);
	goto fail;
    }

    /* become a daemon */
    set_perms(PERM_ROOT);
    if (setsid() == -1) {
	warning("setsid");
	kill(pid, SIGKILL);
	_exit(1);
    }
    (void) chdir("/");
#ifdef HAVE_SETPROCTITLE
    setproctitle("monitor %s%s%s", user_base, user_args ? " " : "",
	user_args ? user_args : "");
#endif

    if (ioctl(fd, STRIOCATTACH, &pid) == -1) {
	if (errno == EBUSY) {
	    /* already being traced, nothing to do */
	    (void) kill(pid, SIGUSR1);
	    _exit(0);
	}
	warning("unable to systrace %s", user_cmnd);
	goto fail;
    }

    new_child(-1, pid);
    if (set_policy(fd, children.first) != 0) {
	warning("failed to set policy for %s", user_cmnd);
	goto fail;
    }

    if (kill(pid, SIGUSR1) != 0) {
	warning("unable to wake up sleeping child");
	_exit(1);
    }

    /* handle systrace events until the child finishes */
    for (;;) {
	if ((nread = read(fd, &msg, sizeof(msg))) != sizeof(msg)) {
	    if (dodetach) {
		detachall(fd);
		_exit(0);
	    }
	    if (nread == -1 && (errno == EINTR || errno == EAGAIN))
		continue;
	    killall(SIGKILL);
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
		if (handler != NULL && handler->checker != NULL) {
		    status = handler->checker(fd, msg.msg_pid, msg.msg_seqnr,
			&msg.msg_data.msg_ask, &ans.stra_policy,
			&ans.stra_error);
		    if (status >= 0 && ioctl(fd, STRIOCANSWER, &ans) == 0) {
			if (handler->logger != NULL)
			    handler->logger(status);
		    }
		} else
		    if (ioctl(fd, STRIOCANSWER, &ans) == -1)
			warning("STRIOCANSWER");
		break;

	    case SYSTR_MSG_EMUL:
		/* Change in emulation. */
		memset(&ans, 0, sizeof(ans));
		ans.stra_pid = msg.msg_pid;
		ans.stra_seqnr = msg.msg_seqnr;
		if (switch_emulation(fd, &msg) == 0)
		    ans.stra_policy = SYSTR_POLICY_PERMIT;
		else {
		    warningx("unsupported emulation \"%s\"",
			msg.msg_data.msg_emul.emul);
		    ans.stra_policy = SYSTR_POLICY_NEVER;
		}
		if (ioctl(fd, STRIOCANSWER, &ans) == -1)
		    warning("STRIOCANSWER");
		break;

#ifdef SYSTR_MSG_POLICYFREE
	    case SYSTR_MSG_POLICYFREE:
		break;
#endif

	    default:
#ifdef SUDO_DEVEL
		warningx("unexpected message type %d", msg.msg_type);
#endif
		memset(&ans, 0, sizeof(ans));
		ans.stra_pid = msg.msg_pid;
		ans.stra_seqnr = msg.msg_seqnr;
		ans.stra_policy = SYSTR_POLICY_PERMIT;
		if (ioctl(fd, STRIOCANSWER, &ans) == -1)
		    warning("STRIOCANSWER");
		break;
	}
    }

fail:
    killall(SIGKILL);
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
	    errorx(1, "unable to find native emulation!");
    }
    entry = (struct childinfo *) emalloc(sizeof(*entry));
    entry->pid = pid;
    entry->pw = pw;
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
	return -1;
    for (emul = emulations; emul != NULL; emul++)
	if (strcmp(emul->name, msgp->msg_data.msg_emul.emul) == 0) {
	    entry->action = emul->action;
	    return set_policy(fd, entry);
	}
    return -1;
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
	    efree(cur);
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
	    return cur;
    }
    return NULL;
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
	/* look up uid in passwd db, using a stub on failure */
	if ((child->pw = sudo_getpwuid(uid)) == NULL)
	    child->pw = sudo_fakepwuid(uid);
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
	return -1;

    pol.strp_op = SYSTR_POLICY_ASSIGN;
    pol.strp_pid = child->pid;
    if (ioctl(fd, STRIOCPOLICY, &pol) == -1)
	return -1;

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
	    return -1;
    }
    return 0;
}

/*
 * Read from an address and store in buf.
 * XXX - should deal with EBUSY from STRIOCIO
 */
static ssize_t
systrace_read(fd, pid, addr, buf, bufsiz)
    int fd;
    pid_t pid;
    void *addr;
    void *buf;
    size_t bufsiz;
{
    struct systrace_io io;
    int rval;

    memset(&io, 0, sizeof(io));
    io.strio_pid = pid;
    io.strio_addr = buf;
    io.strio_len = bufsiz;
    io.strio_offs = addr;
    io.strio_op = SYSTR_READ;
    if ((rval = ioctl(fd, STRIOCIO, &io)) != 0)
	warning("systrace_read: STRIOCIO");
    return rval ? -1 : (ssize_t)io.strio_len;
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
    ssize_t nread;
    char *cp = buf, *ep;

    while (bufsiz >= chunksiz) {
	if ((nread = systrace_read(fd, pid, addr, cp, chunksiz)) != -1) {
	    if ((ep = memchr(cp, '\0', nread)) != NULL) {
		cp = ep;	/* found NUL byte in chunk, done */
		break;
	    }
	    cp += nread;
	    addr += nread;
	    bufsiz -= nread;
	} else {
	    if (errno != EINVAL || chunksiz == 1)
		    return -1;
	    chunksiz >>= 1;	/* chunksiz too big, halve it */
	}
    }
#ifdef  SUDO_DEVEL
    if (cp == buf)
	warningx("read empty string, chunksize == %d", chunksiz); /* XXX, should not happen but does */
#endif
    return bufsiz >= chunksiz ? cp - buf : -1;
}

static struct syscallhandler *
find_handler(pid, code)
    pid_t pid;
    int code;
{
    struct syscallaction *sca;
    struct childinfo *child;

    if ((child = find_child(pid)) == NULL) {
	warningx("unable to find child with pid %d", pid);
	return NULL;
    }
    for (sca = child->action; sca->code != -1; sca++) {
	if (sca->code == code)
	    return &sca->handler;
    }
    return NULL;
}

#define SUDO_USER	0
#define SUDO_COMMAND	1
#define SUDO_UID	2
#define SUDO_GID	3

#ifdef STRIOCINJECT
/*
 * Write buf to a kernel address.
 * XXX - should deal with EBUSY from STRIOCIO
 */
static ssize_t
systrace_write(fd, pid, addr, buf, len)
    int fd;
    pid_t pid;
    void *addr;
    void *buf;
    size_t len;
{
    struct systrace_io io;
    int rval;

    memset(&io, 0, sizeof(io));
    io.strio_pid = pid;
    io.strio_addr = buf;
    io.strio_len = len;
    io.strio_offs = addr;
    io.strio_op = SYSTR_WRITE;
    if ((rval = ioctl(fd, STRIOCIO, &io)) != 0)
	warning("systrace_write: STRIOCIO");
    return rval ? -1 : (ssize_t)io.strio_len;
}

/*
 * Update SUDO_* variables in the process's environment.
 */
static int
update_env(fd, pid, seqnr, askp)
    int fd;
    pid_t pid;
    u_int16_t seqnr;
    struct str_msg_ask *askp;
{
    struct systrace_replace repl;
    ssize_t len;
    char *envbuf[ARG_MAX / sizeof(char *)], **envp, **envep;
    char buf[ARG_MAX], *ap, *cp, *off, *envptrs[4], *offsets[4], *replace[4];
    int n;

    /*
     * Iterate through the environment, copying the data pointers and
     * attempting to update the SUDO_* variables (space permitting).
     */
    memset(offsets, 0, sizeof(offsets));
    memset(replace, 1, sizeof(replace));
    off = (char *)askp->args[2];
    envep = envbuf + (sizeof(envbuf) / sizeof(char *));
    for (envp = envbuf; envp < envep; envp++, off += sizeof(char *)) {
	if (systrace_read(fd, pid, off, &ap, sizeof(ap)) == -1)
	    return -1;
	if ((*envp = ap) == NULL)
	    break;
	memset(buf, 0, sizeof(buf));
	if ((len = read_string(fd, pid, ap, buf, sizeof(buf))) == -1)
	    return -1;
	if (buf[0] == 'S') {
	    if (strncmp(buf, "SUDO_USER=", 10) == 0) {
		offsets[SUDO_USER] = off;
		envptrs[SUDO_USER] = ap;
		if (strcmp(&buf[10], user_name) == 0)
		    replace[SUDO_USER] = NULL;
		else {
		    len = strlen(buf);
		    n = snprintf(buf, len + 1, "SUDO_USER=%s", user_name);
		    if (n > 0 && n <= len &&
			systrace_write(fd, pid, ap, buf, len + 1) != -1)
			replace[SUDO_USER] = NULL;
		}
	    } else if (strncmp(buf, "SUDO_COMMAND=", 13) == 0) {
		offsets[SUDO_COMMAND] = off;
		envptrs[SUDO_COMMAND] = ap;
		len = strlen(user_cmnd);
		if (strncmp(&buf[13], user_cmnd, len) == 0) {
		    if (user_args == NULL) {
			if (buf[13 + len] == '\0')
			    replace[SUDO_COMMAND] = NULL;
		    } else if (buf[13 + len] == ' ') {
			if (strcmp(&buf[14 + len], user_args) == 0)
			    replace[SUDO_COMMAND] = NULL;
		    }
		}
		if (replace[SUDO_COMMAND] != NULL) {
		    len = strlen(buf);
		    n = snprintf(buf, len + 1, "SUDO_COMMAND=%s%s%s",
			user_cmnd, user_args ? " " : "",
			user_args ? user_args : "");
		    if (n > 0 && n <= len &&
			systrace_write(fd, pid, ap, buf, len + 1) != -1)
			replace[SUDO_COMMAND] = NULL;
		}
	    } else if (strncmp(buf, "SUDO_UID=", 9) == 0) {
		offsets[SUDO_UID] = off;
		envptrs[SUDO_UID] = ap;
		if ((uid_t) atoi(&buf[9]) == user_uid)
		    replace[SUDO_UID] = NULL;
		else {
		    len = strlen(buf);
		    n = snprintf(buf, len + 1,
			"SUDO_UID=%lu", (unsigned long) user_uid);
		    if (n > 0 && n <= len &&
			systrace_write(fd, pid, ap, buf, len + 1) != -1)
			replace[SUDO_UID] = NULL;
		}
	    } else if (strncmp(buf, "SUDO_GID=", 9) == 0) {
		offsets[SUDO_GID] = off;
		envptrs[SUDO_GID] = ap;
		if ((gid_t) atoi(&buf[9]) == user_gid)
		    replace[SUDO_GID] = NULL;
		else {
		    len = strlen(buf);
		    n = snprintf(buf, len + 1,
			"SUDO_GID=%lu", (unsigned long) user_gid);
		    if (n > 0 && n <= len &&
			systrace_write(fd, pid, ap, buf, len + 1) != -1)
			replace[SUDO_GID] = NULL;
		}
	    }
	}
    }

    /*
     * Allocate space for any SUDO_* variables we didn't have room for
     * or that weren't present.
     */
    cp = buf;
    if (replace[SUDO_USER]) {
	n = snprintf(cp, sizeof(buf) - (cp - buf), "SUDO_USER=%s", user_name);
	if (n < 0 || n >= sizeof(buf) - (cp - buf))
	    return -1;
	replace[SUDO_USER] = cp;
	cp += n + 1;
    }
    if (replace[SUDO_COMMAND]) {
	n = snprintf(cp, sizeof(buf) - (cp - buf), "SUDO_COMMAND=%s%s%s",
	    user_cmnd, user_args ? " " : "", user_args ? user_args : "");
	if (n < 0 || n >= sizeof(buf) - (cp - buf))
	    return -1;
	replace[SUDO_COMMAND] = cp;
	cp += n + 1;
    }
    if (replace[SUDO_UID]) {
	n = snprintf(cp, sizeof(buf) - (cp - buf), "SUDO_UID=%lu",
	    (unsigned long) user_uid);
	if (n < 0 || n >= sizeof(buf) - (cp - buf))
	    return -1;
	replace[SUDO_UID] = cp;
	cp += n + 1;
    }
    if (replace[SUDO_GID]) {
	n = snprintf(cp, sizeof(buf) - (cp - buf), "SUDO_GID=%lu",
	    (unsigned long) user_gid);
	if (n < 0 || n >= sizeof(buf) - (cp - buf))
	    return -1;
	replace[SUDO_GID] = cp;
	cp += n + 1;
    }
    if (cp != buf) {
	struct systrace_inject inject;
	memset(&inject, 0, sizeof(inject));
	inject.stri_pid = pid;
	inject.stri_addr = buf;
	inject.stri_len = cp - buf;
	if (ioctl(fd, STRIOCINJECT, &inject) != 0)
	    return -1;
	n = (offsets[SUDO_USER] == NULL) + (offsets[SUDO_COMMAND] == NULL) +
	    (offsets[SUDO_UID] == NULL) + (offsets[SUDO_GID] == NULL);
	/*
	 * If there were SUDO_* variables missing in the environment we
	 * need to add them to our copy of envp and replace the envp in
	 * the user process.  If no, we just update the addresses
	 * of the modified environment variables in the process's envp.
	 */
	if (n == 0) {
	    /* No missing variables, just update addresses in user process. */
	    for (n = 0; n < 4; n++) {
		if (replace[n] == NULL)
		    continue;
		ap = inject.stri_addr + (replace[n] - buf);
		if (systrace_write(fd, pid, offsets[n], &ap, sizeof(ap)) == -1)
		    return -1;
	    }
	} else {
	    /*
	     * There were missing variables; make existing variables
	     * relative to inject.stri_addr and add missing one.
	     */
	    for (envp = envbuf; *envp != NULL; envp++) {
		if (replace[SUDO_USER] != NULL && *envp == envptrs[SUDO_USER])
		    *envp = inject.stri_addr + (replace[SUDO_USER] - buf);
		else if (replace[SUDO_COMMAND] != NULL && *envp == envptrs[SUDO_COMMAND])
		    *envp = inject.stri_addr + (replace[SUDO_COMMAND] - buf);
		else if (replace[SUDO_UID] != NULL && *envp == envptrs[SUDO_UID])
		    *envp = inject.stri_addr + (replace[SUDO_UID] - buf);
		else if (replace[SUDO_GID] != NULL && *envp == envptrs[SUDO_GID])
		    *envp = inject.stri_addr + (replace[SUDO_GID] - buf);
	    }
	    if (envp + n >= envep)
		return -1;
	    if (offsets[SUDO_USER] == NULL)
		*envp++ = inject.stri_addr + (replace[SUDO_USER] - buf);
	    if (offsets[SUDO_COMMAND] == NULL)
		*envp++ = inject.stri_addr + (replace[SUDO_COMMAND] - buf);
	    if (offsets[SUDO_UID] == NULL)
		*envp++ = inject.stri_addr + (replace[SUDO_UID] - buf);
	    if (offsets[SUDO_GID] == NULL)
		*envp++ = inject.stri_addr + (replace[SUDO_GID] - buf);
	    *envp++ = NULL;

	    /* Replace existing envp with our new one. */
	    memset(&repl, 0, sizeof(repl));
	    repl.strr_pid = pid;
	    repl.strr_seqnr = seqnr;
	    repl.strr_nrepl = 1;
	    repl.strr_base = (char *)envbuf;
	    repl.strr_len = (char *)envp - (char *)envbuf;
	    repl.strr_argind[0] = 2;
	    repl.strr_off[0] = 0;
	    repl.strr_offlen[0] = (char *)envp - (char *)envbuf;
	    if (ioctl(fd, STRIOCREPLACE, &repl) != 0)
		return -1;
	}
    }
    return 0;
}
#endif /* STRIOCINJECT */

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
    int i, argc, argc_max;
    char *off, *ap, *cp, *ep, **argv;
    static char pbuf[PATH_MAX], abuf[ARG_MAX];

    /*
     * Fill in user_cmnd and user_base from the 1st arg to execve().
     * Note that this is the path the kernel will execute, which
     * may be different from argv[0].
     */
    memset(pbuf, 0, sizeof(pbuf));
    if (read_string(fd, pid, (void *)askp->args[0], pbuf, sizeof(pbuf)) == -1)
	return -1;
    if ((user_base = strrchr(user_cmnd = pbuf, '/')) != NULL)
	user_base++;
    else
	user_base = user_cmnd;
    user_args = NULL;

    /* XXX - write exec path back to stack gap */

    /*
     * Make a local copy of argv, looping until we hit the
     * terminating NULL pointer.
     */
    argc = 0;
    argc_max = 16;
    argv = emalloc2(argc_max, sizeof(char *));
    memset(abuf, 0, sizeof(abuf));
    off = (char *)askp->args[1];
    for (cp = abuf, ep = abuf + sizeof(abuf); cp < ep; off += sizeof(char *)) {
	if (systrace_read(fd, pid, off, &ap, sizeof(ap)) == -1)
	    return -1;
	if (ap == NULL)
	    break;		/* end of args */
	if (argc + 1 >= argc_max) {
	    argc_max *= 2;
	    argv = erealloc3(argv, argc_max, sizeof(char *));
	}
	if ((len = read_string(fd, pid, ap, cp, ep - cp)) == -1)
	    return -1;
	argv[argc++] = cp;
	cp += len;
    }
    ep = cp;
    argv[argc] = NULL;

    /* XXX - now write argv back into stack gap. */

    /*
     * Collapse argv into user_args, skipping argv[0].
     * Since argv strings are contiguous (in abuf) we can
     * just replace the previous char in each string with a
     * space.
     */
    if (argc > 1) {
	user_args = argv[1];
	for (i = 2; i < argc; i++)
	    argv[i][-1] = ' ';		/* replace NUL with a space */
    }

    efree(argv);
    return 0;
}

static void
log_exec(status)
    int status;
{
    if (status > 0)
	log_auth(status, TRUE);
}

/*
 * Decode the args to exec and check the command in sudoers.
 */
static int
check_execv(fd, pid, seqnr, askp, policyp, errorp)
    int fd;
    pid_t pid;
    u_int16_t seqnr;
    struct str_msg_ask *askp;
    int *policyp;
    int *errorp;
{
    int rval, validated;
    struct childinfo *info;
#ifdef HAVE_LDAP
    void *ld;
#endif

    /* We're not really initialized until the first exec finishes. */
    if (initialized == 0) {
	initialized = 1;
	*policyp = SYSTR_POLICY_PERMIT;
	return 0;
    }

    /* Failure should not be possible. */
    if ((info = find_child(pid)) == NULL) {
	*policyp = SYSTR_POLICY_NEVER;
	*errorp = ECHILD;
	return 0;
    }

    /* Fill in user_cmnd, user_base, user_args and user_stat.  */
    if (decode_args(fd, pid, askp) != 0) {
	if (errno == EBUSY)
	    return -1;
	*policyp = SYSTR_POLICY_NEVER;
	*errorp = errno;
	return 0;
    }

    /* Get process cwd. */
    rval = ioctl(fd, STRIOCGETCWD, &pid);
    if (rval == -1 || getcwd(user_cwd, sizeof(user_cwd)) == NULL) {
	if (rval == -1 && errno == EBUSY)
	    return -1;
	warningx("cannot get working directory");
	(void) strlcpy(user_cwd, "unknown", sizeof(user_cwd));
    }

    /*
     * Stat user_cmnd and restore cwd
     */
    if (sudo_goodpath(user_cmnd, user_stat) == NULL) {
	if (rval != -1 && ioctl(fd, STRIOCRESCWD, 0) != 0)
	    warning("can't restore cwd");
	*policyp = SYSTR_POLICY_NEVER;
	*errorp = EACCES;
	return 0;
    }
    if (rval != -1 && ioctl(fd, STRIOCRESCWD, 0) != 0)
	warning("can't restore cwd");

    /* Check sudoers and log the result. */
    init_defaults();
    def_authenticate = FALSE;
    runas_pw = info->pw;
    validated = VALIDATE_NOT_OK;
#ifdef HAVE_LDAP
    if ((ld = sudo_ldap_open()) != NULL) {
	sudo_ldap_update_defaults(ld);
	validated = sudo_ldap_check(ld, 0);
	sudo_ldap_close(ld);
    }
    if (!def_ignore_local_sudoers && !ISSET(validated, VALIDATE_OK))
#endif
    {
	(void) update_defaults(SET_ALL);
	validated = sudoers_lookup(0);
    }
    if (ISSET(validated, VALIDATE_OK)) {
	*policyp = SYSTR_POLICY_PERMIT;
    } else {
	*policyp = SYSTR_POLICY_NEVER;
	*errorp = EACCES;
    }
    return validated;
}

/*
 * Call check_execv() and, if the command it permitted, set
 * the SUDO_* environment variables.
 */
static int
check_execve(fd, pid, seqnr, askp, policyp, errorp)
    int fd;
    u_int16_t seqnr;
    pid_t pid;
    struct str_msg_ask *askp;
    int *policyp;
    int *errorp;
{
    int rval;

    rval = check_execv(fd, pid, seqnr, askp, policyp, errorp);
#ifdef STRIOCINJECT
    if (rval > 0 && *policyp == SYSTR_POLICY_PERMIT) {
	/* read environment into buf, munge, and bung it back */
	if (update_env(fd, pid, seqnr, askp) != 0)
	    rval = -1;
    }
#endif
    return rval;
}

/*
 * Kill all pids in the list
 */
static void
killall(sig)
    int sig;
{
    struct childinfo *child;

    for (child = children.first; child != NULL; child = child->next)
	(void) kill(child->pid, sig);
}

/*
 * Detach all traced processes.
 */
static void
detachall(fd)
    int fd;
{
    struct childinfo *child;

    for (child = children.first; child != NULL; child = child->next)
	(void) ioctl(fd, STRIOCDETACH, &child->pid);
}
