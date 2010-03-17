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

#define	SYSTRACE_MAXENTS	1024

struct childinfo;
struct listhead;
struct syscallhandler;

static int check_execv(int, pid_t, u_int16_t, struct str_msg_ask *, int *, int *);
static int check_execve(int, pid_t, u_int16_t, struct str_msg_ask *, int *, int *);
static void log_exec(int);
static int decode_args(int, pid_t, struct str_msg_ask *);
static int set_policy(int, struct childinfo *);
static int switch_emulation(int, struct str_message *);
static int systrace_open(void);
static ssize_t systrace_read(int, pid_t, void *, void *, size_t);
#ifdef STRIOCINJECT
static ssize_t systrace_write(int, pid_t, void *, void *, size_t);
static int update_env(int, pid_t, u_int16_t, struct str_msg_ask *);
#endif
static struct syscallhandler *find_handler(pid_t, int);
static ssize_t read_string(int, pid_t, void *, char *, size_t);
static struct childinfo *find_child(pid_t);
static void catchsig(int);
static void detachall(int);
static void killall(int);
static void new_child(pid_t, pid_t);
static void rm_child(pid_t);
static void update_child(pid_t, uid_t);


static struct listhead children;	/* list of children being traced */
static int initialized;			/* set to true when we are inited */
static volatile sig_atomic_t dodetach;	/* caught signal */

struct listhead {
    void *first;
};

struct childinfo {
    pid_t pid;
    struct passwd *pw;
    struct syscallaction *action;
    struct childinfo *next;
};

struct syscallhandler {
    int (*checker)(int, pid_t, u_int16_t, struct str_msg_ask *, int *, int *);
    void (*logger)(int);
};

/*
 * Each emulation has a list of actionable syscalls.
 */
struct syscallaction {
    int code;
    int policy;
    struct syscallhandler handler;
};

static struct syscallaction syscalls_openbsd[] = {
	{  23, SYSTR_POLICY_ASK },		/* OPENBSD_SYS_setuid */
	{  59, SYSTR_POLICY_ASK, { check_execve, log_exec } }, /* OPENBSD_SYS_execve */
	{ 126, SYSTR_POLICY_ASK },		/* OPENBSD_SYS_setreuid */
	{ 183, SYSTR_POLICY_ASK },		/* OPENBSD_SYS_seteuid */
	{ 282, SYSTR_POLICY_ASK },		/* OPENBSD_SYS_setresuid */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_bsdos[] = {
	{ 23, SYSTR_POLICY_ASK },		/* BSDOS_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* BSDOS_SYS_execve */
	{ 126, SYSTR_POLICY_ASK },		/* BSDOS_SYS_setreuid */
	{ 183, SYSTR_POLICY_ASK },		/* BSDOS_SYS_seteuid */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_freebsd[] = {
	{ 23, SYSTR_POLICY_ASK },		/* FREEBSD_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* FREEBSD_SYS_execve */
	{ 126, SYSTR_POLICY_ASK },		/* FREEBSD_SYS_setreuid */
	{ 183, SYSTR_POLICY_ASK },		/* FREEBSD_SYS_seteuid */
	{ 311, SYSTR_POLICY_ASK },		/* FREEBSD_SYS_setresuid */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_netbsd[] = {
	{ 23, SYSTR_POLICY_ASK },		/* NETBSD_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* NETBSD_SYS_execve */
	{ 126, SYSTR_POLICY_ASK },		/* NETBSD_SYS_setreuid */
	{ 183, SYSTR_POLICY_ASK },		/* NETBSD_SYS_seteuid */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_hpux[] = {
	{ 11, SYSTR_POLICY_ASK, { check_execv, log_exec } },	/* HPUX_SYS_execv */
	{ 23, SYSTR_POLICY_ASK },		/* HPUX_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* HPUX_SYS_execve */
	{ 126, SYSTR_POLICY_ASK },		/* HPUX_SYS_setresuid */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_ibsc2[] = {
	{ 11, SYSTR_POLICY_ASK, { check_execv, log_exec } },	/* ISCS2_SYS_execv */
	{ 23, SYSTR_POLICY_ASK },		/* ISCS2_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* ISCS2_SYS_execve */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_linux[] = {
	{ 11, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* LINUX_SYS_execve */
	{ 23, SYSTR_POLICY_ASK },		/* LINUX_SYS_setuid16 */
	{ 70, SYSTR_POLICY_ASK },		/* LINUX_SYS_setreuid16 */
	{ 138, SYSTR_POLICY_ASK },		/* LINUX_SYS_setfsuid16 */
	{ 164, SYSTR_POLICY_ASK },		/* LINUX_SYS_setresuid16 */
	{ 203, SYSTR_POLICY_ASK },		/* LINUX_SYS_setreuid */
	{ 208, SYSTR_POLICY_ASK },		/* LINUX_SYS_setresuid */
	{ 213, SYSTR_POLICY_ASK },		/* LINUX_SYS_setuid */
	{ 215, SYSTR_POLICY_ASK },		/* LINUX_SYS_setfsuid */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_osf1[] = {
	{ 23, SYSTR_POLICY_ASK },		/* OSF1_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* OSF1_SYS_execve */
	{ 126, SYSTR_POLICY_ASK },		/* OSF1_SYS_setreuid */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_sunos[] = {
	{ 11, SYSTR_POLICY_ASK, { check_execv, log_exec } },	/* SUNOS_SYS_execv */
	{ 23, SYSTR_POLICY_ASK },		/* SUNOS_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* SUNOS_SYS_execve */
	{ 126, SYSTR_POLICY_ASK },		/* SUNOS_SYS_setreuid */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_svr4[] = {
	{ 11, SYSTR_POLICY_ASK, { check_execv, log_exec } },	/* SVR4_SYS_execv */
	{ 23, SYSTR_POLICY_ASK },		/* SVR4_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* SVR4_SYS_execve */
	{ 141, SYSTR_POLICY_ASK },		/* SVR4_SYS_seteuid */
	{ 202, SYSTR_POLICY_ASK },		/* SVR4_SYS_setreuid */
	{ -1, -1 } 
};

static struct syscallaction syscalls_ultrix[] = {
	{ 11, SYSTR_POLICY_ASK, { check_execv, log_exec } },	/* ULTRIX_SYS_execv */
	{ 23, SYSTR_POLICY_ASK },		/* ULTRIX_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* ULTRIX_SYS_execve */
	{ 126, SYSTR_POLICY_ASK },		/* ULTRIX_SYS_setreuid */
	{ -1, -1 } 
};
 
static struct syscallaction syscalls_irix[] = {
	{ 11, SYSTR_POLICY_ASK, { check_execv, log_exec } },	/* IRIX_SYS_execv */
	{ 23, SYSTR_POLICY_ASK },		/* IRIX_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* IRIX_SYS_execve */
	{ 124, SYSTR_POLICY_ASK },		/* IRIX_SYS_setreuid */
	{ -1, -1 } 
};

static struct syscallaction syscalls_darwin[] = {
	{ 23, SYSTR_POLICY_ASK },		/* DARWIN_SYS_setuid */
	{ 59, SYSTR_POLICY_ASK, { check_execve, log_exec } },	/* DARWIN_SYS_execve */
	{ 126, SYSTR_POLICY_ASK },		/* DARWIN_SYS_setreuid */
	{ 183, SYSTR_POLICY_ASK },		/* DARWIN_SYS_seteuid */
	{ -1, -1 } 
};

/*
 * List of emulations we support.  Not all OSes support all emulations but
 * they are all listed here to make things simpler.
 * Attempts to run programs with unknown emulations will be rejected.
 */
static struct emulation {
    const char *name;
    struct syscallaction *action;
} emulations[] = {
    { "bsdos", syscalls_bsdos },
#if defined(__darwin__) || defined(__APPLE__)
    { "native", syscalls_darwin },
#else
    { "darwin", syscalls_darwin },
#endif
#ifdef __FreeBSD__
    { "native", syscalls_freebsd },
#else
    { "freebsd", syscalls_freebsd },
#endif
    { "hpux", syscalls_hpux },
    { "ibsc2", syscalls_ibsc2 },
    { "irix", syscalls_irix },
#if defined(__linux__)
    { "native", syscalls_linux },
#else
    { "linux", syscalls_linux },
#endif
#ifdef __NetBSD__
    { "native", syscalls_netbsd },
#else
    { "netbsd", syscalls_netbsd },
#endif
    { "netbsd32", syscalls_netbsd },
#ifdef __OpenBSD__
    { "native", syscalls_openbsd },
#else
    { "openbsd", syscalls_openbsd },
#endif
    { "osf1", syscalls_osf1 },
    { "pecoff", syscalls_netbsd },
    { "sunos", syscalls_sunos },
    { "sunos32", syscalls_sunos },
    { "svr4", syscalls_svr4 },
    { "svr4_32", syscalls_svr4 },
    { "ultrix", syscalls_ultrix },
    { NULL, NULL }
};
