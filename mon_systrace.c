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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#ifdef HAVE_DEV_SYSTRACE_H
# include <dev/systrace.h>
#else
# ifdef HAVE_SYS_SYSTRACE_H
#  include <sys/systrace.h>
# else
#  include <systrace.h>
# endif
#endif
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
#ifdef HAVE_ERR_H
# include <err.h>
#else
# include "emul/err.h"
#endif /* HAVE_ERR_H */
#include <pwd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "sudo.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

struct listhead {
    void *first;
};
struct childinfo {
    pid_t pid;
    uid_t uid;
    struct childinfo *next;
};
struct syscallhandler {
    int num;
    int (*handler) __P((int, int *, struct str_message *));
    struct syscallhandler *next;
};

int check_exec		__P((int, int *, struct str_message *));
int check_syscall	__P((int, int *, int, struct str_message *,
			    struct listhead *));
int decode_args		__P((int, struct str_message *));
int set_policy		__P((int, pid_t, struct listhead *));
int systrace_open	__P((void));
int systrace_read	__P((int, pid_t, void *, void *, size_t));
int systrace_run	__P((char *, char **, int));
ssize_t read_string	__P((int, pid_t, void *, char *, size_t));
void new_child		__P((struct listhead *, pid_t, uid_t));
void new_handler	__P((struct listhead *, int,
			    int (*)(int, int *, struct str_message *)));
void rm_child		__P((struct listhead *, pid_t));
void update_child	__P((struct listhead *, pid_t, uid_t));

/*
 * Open the systrace device and return the fd or -1 on failure.
 * XXX - warn here on error or in caller?
 */
int
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

void
sigusr1(signo)
    int signo;
{
    return;
}

/*
 * Fork a process that traces the command to be run and its descendents.
 *
 * TODO:
 *	note euid changes and update runas info
 *	set SUDO_* env variables for sub-execs
 */
void
systrace_attach(pid)
    pid_t pid;
{
    struct systrace_answer ans;
    struct str_message msg;
    struct listhead children, handlers;
    sigaction_t sa, osa;
    sigset_t set, oset;
    ssize_t nread;
    int fd, initialized = 0;

    fflush(stdout);
    if ((fd = systrace_open()) == -1)
	err(1, "unable to open systrace");

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
	sigprocmask(SIG_SETMASK, &oset, NULL) != 0)
	goto fail;

    /* become a daemon */
    if (setsid() == -1) {
	warn("setsid");
	kill(pid, SIGKILL);
	_exit(1);
    }
    (void) chdir("/");
#ifdef HAVE_SETPROCTITLE
    setproctitle("systrace %s %s", user_base, user_args);
#endif

    children.first = NULL;
    new_child(&children, pid, runas_pw->pw_uid);

    /*
     * Open systrace device and set a policy to generate
     * ask events when the traced process does an exec.
     */
    if (ioctl(fd, STRIOCATTACH, &pid) == -1 || set_policy(fd, pid, &handlers) != 0)
	goto fail;

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
	    kill(pid, SIGKILL);	/* XXX - kill all pids in list */
	    _exit(nread != 0);	/* shouldn't happen */
	}

	switch (msg.msg_type) {
	    case SYSTR_MSG_CHILD:
		/* either a fork or an exit */
		if (msg.msg_data.msg_child.new_pid != -1) {
			/* XXX - runas_pw->pw_uid may be wrong */
			new_child(&children, msg.msg_data.msg_child.new_pid,
			    runas_pw->pw_uid);
		} else {
			rm_child(&children, msg.msg_pid);
			if (children.first == NULL)
			    _exit(0);
		}
		break;

	    case SYSTR_MSG_UGID:
		/* uid/gid change */
		/* XXX - how is this triggered? */
		warn("new uid %d", msg.msg_data.msg_ugid.uid);
		update_child(&children, msg.msg_pid, msg.msg_data.msg_ugid.uid);
		break;

	    case SYSTR_MSG_ASK:
		memset(&ans, 0, sizeof(ans));
		ans.stra_pid = msg.msg_pid;
		ans.stra_seqnr = msg.msg_seqnr;
		ans.stra_policy = check_syscall(fd, &initialized,
		    msg.msg_data.msg_ask.code, &msg, &handlers);
		if ((ioctl(fd, STRIOCANSWER, &ans)) == -1)
		    goto fail;
		break;

	    case SYSTR_MSG_EMUL:
		/*
		 * XXX - need to redo policy if we change emulation.
		 *       that means we need to know in advance what
		 *       the various emulations are.
		 */
		warnx("change in emul");
		break;
#ifdef SUDO_DEVEL
	    default:
		warnx("unexpected message type %d", msg.msg_type);
		break;
#endif
	}
    }

fail:
    warn("unable to systrace %s", user_cmnd);
    kill(pid, SIGKILL);	/* XXX - kill all pids in list */
    _exit(1);
}

/*
 * Push a new handler to the head of the list.
 */
void
new_handler(head, num, handler)
    struct listhead *head;
    int num;
    int (*handler) __P((int, int *, struct str_message *));
{
    struct syscallhandler *entry;

    entry = (struct syscallhandler *) emalloc(sizeof(*entry));
    entry->num = num;
    entry->handler = handler;
    entry->next = head->first;
    head->first = entry;
}

/*
 * Push a new child to the head of the list.
 */
void
new_child(head, pid, uid)
    struct listhead *head;
    pid_t pid;
    uid_t uid;
{
    struct childinfo *entry;

    entry = (struct childinfo *) emalloc(sizeof(*entry));
    entry->pid = pid;
    entry->uid = uid;
    entry->next = head->first;
    head->first = entry;
}

/*
 * Remove the named pid from the list.
 */
void
rm_child(head, pid)
    struct listhead *head;
    pid_t pid;
{
    struct childinfo *cur, *prev;

    for (prev = NULL, cur = head->first; cur != NULL; cur = cur->next) {
	if (cur->pid == pid) {
	    if (prev != NULL)
		prev->next = cur->next;
	    else
		head->first = cur->next;
	    free(cur);
	    break;
	}
	prev = cur;
    }
}

/*
 * Update the uid associated with a pid.
 */
void
update_child(head, pid, uid)
    struct listhead *head;
    pid_t pid;
    uid_t uid;
{
    struct childinfo *cur;

    for (cur = head->first; cur != NULL; cur = cur->next) {
	if (cur->pid == pid) {
	    cur->uid = uid;
	    break;
	}
    }
}

/*
 * Create a policy that intercepts execve and lets all others go free.
 */
int
set_policy(fd, pid, handlers)
    int fd;
    pid_t pid;
    struct listhead *handlers;
{
    int i;
    struct systrace_policy pol;

    pol.strp_op = SYSTR_POLICY_NEW;
    pol.strp_num = -1;
    pol.strp_maxents = SYS_MAXSYSCALL;
    if (ioctl(fd, STRIOCPOLICY, &pol) == -1)
	return(-1);

    for (i = 0; i < SYS_MAXSYSCALL; i++) {
	pol.strp_op = SYSTR_POLICY_ASSIGN;
	pol.strp_pid = pid;
	if (ioctl(fd, STRIOCPOLICY, &pol) == -1)
	    return(-1);

	pol.strp_op = SYSTR_POLICY_MODIFY;
	pol.strp_code = i;
#ifdef SYS_exec
	if (i == SYS_exec) {
	    pol.strp_policy = SYSTR_POLICY_ASK;
	    new_handler(handlers, i, check_exec);
	} else
#endif
#ifdef SYS_execv
	if (i == SYS_execv) {
	    pol.strp_policy = SYSTR_POLICY_ASK;
	    new_handler(handlers, i, check_exec);
	} else
#endif
#ifdef SYS_execve
	if (i == SYS_execve) {
	    pol.strp_policy = SYSTR_POLICY_ASK;
	    new_handler(handlers, i, check_exec);
	} else
#endif
#ifdef SYS_fexecve
	if (i == SYS_fexecve)
	    pol.strp_policy = SYSTR_POLICY_NEVER;	/* not checkable */
	else
#endif
	    pol.strp_policy = SYSTR_POLICY_PERMIT;
	if (ioctl(fd, STRIOCPOLICY, &pol) == -1)
	    return(-1);
    }
    return(0);
}

/*
 * Read from an address and store in buf.
 * XXX - should deal with EBUSY from STRIOCIO
 */
int
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
 * handle a strio_len > the actual kernel buffer.
 * XXX - could pass a hint for chunksiz
 * XXX - need to indicate oflow
 */
ssize_t
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
	    bufsiz -= chunksiz;
	} else {
	    if (errno != EINVAL || chunksiz == 4)
		    return(-1);
	    chunksiz >>= 1;	/* chunksiz too big, half it */
	}
    }
    *cp = '\0';
    return(cp - buf);
}

int
check_syscall(fd, initialized, num, msgp, handlers)
    int fd;
    int *initialized;
    int num;
    struct str_message *msgp;
    struct listhead *handlers;
{
    struct syscallhandler *h;

    for (h = handlers->first; h != NULL; h = h->next) {
	if (h->num == num)
	    return(h->handler(fd, initialized, msgp));
    }
    return(SYSTR_POLICY_PERMIT);	/* accept unhandled syscalls */
}

/*
 * Decode path and argv from systrace and fill in user_cmnd,
 * user_base and user_args.
 */
int
decode_args(fd, msgp)
    int fd;
    struct str_message *msgp;
{
    size_t len;
    char *off, *ap, *cp, *ep;
    static char pbuf[PATH_MAX], abuf[ARG_MAX];

    memset(pbuf, 0, sizeof(pbuf));
    if (read_string(fd, msgp->msg_pid, (void *)msgp->msg_data.msg_ask.args[0],
	pbuf, sizeof(pbuf)) == -1)
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
    off = (char *)msgp->msg_data.msg_ask.args[1];
    for (cp = abuf, ep = abuf + sizeof(abuf); cp < ep; off += sizeof(char *)) {
	if (systrace_read(fd, msgp->msg_pid, off, &ap, sizeof(ap)) != 0) {
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
	if (off == (char *)msgp->msg_data.msg_ask.args[1])
	    continue;			/* skip argv[0] */
	if ((len = read_string(fd, msgp->msg_pid, ap, cp, ep - cp)) == -1) {
	    warn("STRIOCIO");
	    return(-1);
	}
	cp += len;
	*cp++ = ' ';		/* replace NUL with a space */
    }
    /* XXX - detect cp >= ep */
    return(0);
}

/*
 * Decode the args to exec and check the command in sudoers.
 */
int
check_exec(fd, initialized, msgp)
    int fd;
    int *initialized;
    struct str_message *msgp;
{
    int validated;

    /* We're not really initialized until the first exec finishes. */
    if (*initialized == 0) {
	*initialized = 1;
	return(SYSTR_POLICY_PERMIT);
    }

    /* Fill in user_cmnd, user_base, user_args and user_stat.  */
    decode_args(fd, msgp);
    if (user_cmnd[0] != '/' || !sudo_goodpath(user_cmnd, user_stat))
	return(SYSTR_POLICY_NEVER);

    /* Get processes's cwd. */
    if (ioctl(fd, STRIOCGETCWD, &msgp->msg_pid) == -1 ||
	!getcwd(user_cwd, sizeof(user_cwd))) {
	warnx("cannot get working directory");
	(void) strlcpy(user_cwd, "unknown", sizeof(user_cwd));
    } else
	(void) ioctl(fd, STRIOCRESCWD, 0);

    /* XXX - should update user_runas and _runas_pw too! */

    /* Check sudoers and log the result. */
    init_defaults();
    def_authenticate = FALSE;
    validated = sudoers_lookup(0);
#ifdef DEBUG
    warnx("intercepted: %s %s in %s -> 0x%x", user_cmnd, user_args, user_cwd, validated);
#endif
    log_auth(validated, 1);
    if (ISSET(validated, VALIDATE_OK))
	return(SYSTR_POLICY_PERMIT);
    else
	return(SYSTR_POLICY_NEVER);
}
