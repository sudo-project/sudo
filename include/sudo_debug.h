/*
 * Copyright (c) 2011-2014 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_DEBUG_H
#define _SUDO_DEBUG_H

#include <stdarg.h>
#include "sudo_queue.h"

/*
 * List of debug files and flags for use in registration.
 */
struct sudo_debug_file {
    TAILQ_ENTRY(sudo_debug_file) entries;
    char *debug_file;
    char *debug_flags;
};
struct sudo_conf_debug_file_list;

/*
 * The priority, instance and subsystem are encoded in a single 32-bit value.
 * The first byte holds the priority and flags:
 *  nybble one is priority, nybble two is flags (errno or lineno).
 * The second byte is for the instance index (way more than we need).
 * The upper two bytes are the subsystem.
 * This allows for 16 priorities, 3 flags, 256 instances, 65535 subsystems.
 */

/*
 * Sudo debug priorities, ordered least to most verbose,
 * in other words, highest to lowest priority.  Max pri is 15.
 * Note: order must match sudo_debug_priorities[]
 */
#define SUDO_DEBUG_CRIT		1	/* critical errors */
#define SUDO_DEBUG_ERROR	2	/* non-critical errors */
#define SUDO_DEBUG_WARN		3	/* non-fatal warnings */
#define SUDO_DEBUG_NOTICE	4	/* non-error condition notices */
#define SUDO_DEBUG_DIAG		5	/* diagnostic messages */
#define SUDO_DEBUG_INFO		6	/* informational message */
#define SUDO_DEBUG_TRACE	7	/* log function enter/exit */
#define SUDO_DEBUG_DEBUG	8	/* very verbose debugging */

/* Flag to include string version of errno in debug info. */
#define SUDO_DEBUG_ERRNO	(1<<4)

/* Flag to include function, file and line number in debug info. */
#define SUDO_DEBUG_LINENO	(1<<5)

/*
 * Sudo debug subsystems.
 * This includes subsystems in the sudoers plugin.
 * Note: order must match sudo_debug_subsystems[]
 */
#define SUDO_DEBUG_MAIN		( 1<<16)  /* sudo main() */
#define SUDO_DEBUG_ARGS		( 2<<16)  /* command line argument processing */
#define SUDO_DEBUG_EXEC		( 3<<16)  /* command execution */
#define SUDO_DEBUG_PTY		( 4<<16)  /* pseudo-tty */
#define SUDO_DEBUG_UTMP		( 5<<16)  /* utmp file ops */
#define SUDO_DEBUG_CONV		( 6<<16)  /* user conversation */
#define SUDO_DEBUG_PCOMM	( 7<<16)  /* plugin communications */
#define SUDO_DEBUG_UTIL		( 8<<16)  /* utility functions */
#define SUDO_DEBUG_NETIF	( 9<<16)  /* network interface functions */
#define SUDO_DEBUG_AUDIT	(10<<16)  /* audit */
#define SUDO_DEBUG_EDIT		(11<<16)  /* sudoedit */
#define SUDO_DEBUG_SELINUX	(12<<16)  /* selinux */
#define SUDO_DEBUG_LDAP		(13<<16)  /* sudoers LDAP */
#define SUDO_DEBUG_MATCH	(14<<16)  /* sudoers matching */
#define SUDO_DEBUG_PARSER	(15<<16)  /* sudoers parser */
#define SUDO_DEBUG_ALIAS	(16<<16)  /* sudoers alias functions */
#define SUDO_DEBUG_DEFAULTS	(17<<16)  /* sudoers defaults settings */
#define SUDO_DEBUG_AUTH		(18<<16)  /* authentication functions */
#define SUDO_DEBUG_ENV		(19<<16)  /* environment handling */
#define SUDO_DEBUG_LOGGING	(20<<16)  /* logging functions */
#define SUDO_DEBUG_NSS		(21<<16)  /* network service switch */
#define SUDO_DEBUG_RBTREE	(22<<16)  /* red-black tree functions */
#define SUDO_DEBUG_PERMS	(23<<16)  /* uid/gid swapping functions */
#define SUDO_DEBUG_PLUGIN	(24<<16)  /* main plugin functions */
#define SUDO_DEBUG_HOOKS	(25<<16)  /* hook functions */
#define SUDO_DEBUG_SSSD		(26<<16)  /* sudoers SSSD */
#define SUDO_DEBUG_EVENT	(27<<16)  /* event handling */
#define SUDO_DEBUG_ALL		0xffff0000  /* all subsystems */

/* Initializer for instance index to indicate that debugging is not setup. */
#define SUDO_DEBUG_INSTANCE_INITIALIZER	SUDO_DEBUG_MKINSTANCE(-1)

/* The 'default' instance logs to the currently selected debug instance. */
#define SUDO_DEBUG_INSTANCE_DEFAULT	SUDO_DEBUG_MKINSTANCE(-2)

/* Extract priority number and convert to an index. */
#define SUDO_DEBUG_PRI(n) (((n) & 0x0f) - 1)

/* Extract instance number and convert to an index. */
#define SUDO_DEBUG_INSTANCE(n) ((((n) & 0xff00) >> 8) - 2)
#define SUDO_DEBUG_MKINSTANCE(n) (((n) + 2) << 8)

/* Extract subsystem number and convert to an index. */
#define SUDO_DEBUG_SUBSYS(n) (((n) >> 16) - 1)

/*
 * Wrapper for sudo_debug_enter() that declares __func__ as needed
 * and sets sudo_debug_subsys for sudo_debug_exit().
 */
#ifdef HAVE___FUNC__
# define debug_decl(funcname, subsys, instance)				       \
    const int sudo_debug_subsys = (subsys)|(instance);			       \
    sudo_debug_enter(__func__, __FILE__, __LINE__, sudo_debug_subsys);
#else
# define debug_decl(funcname, subsys, instance)				       \
    const int sudo_debug_subsys = (subsys)|(instance);			       \
    const char __func__[] = #funcname;					       \
    sudo_debug_enter(__func__, __FILE__, __LINE__, sudo_debug_subsys);
#endif

/*
 * Wrappers for sudo_debug_exit() and friends.
 */
#define debug_return							       \
    do {								       \
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);      \
	return;								       \
    } while (0)

#define debug_return_int(rval)						       \
    do {								       \
	int sudo_debug_rval = (rval);					       \
	sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys,   \
	    sudo_debug_rval);						       \
	return sudo_debug_rval;						       \
    } while (0)

#define debug_return_size_t(rval)					       \
    do {								       \
	size_t sudo_debug_rval = (rval);				       \
	sudo_debug_exit_size_t(__func__, __FILE__, __LINE__, sudo_debug_subsys,\
	    sudo_debug_rval);						       \
	return sudo_debug_rval;						       \
    } while (0)

#define debug_return_long(rval)						       \
    do {								       \
	long sudo_debug_rval = (rval);					       \
	sudo_debug_exit_long(__func__, __FILE__, __LINE__, sudo_debug_subsys,  \
	    sudo_debug_rval);						       \
	return sudo_debug_rval;						       \
    } while (0)

#define debug_return_bool(rval)						       \
    do {								       \
	int sudo_debug_rval = (rval);					       \
	sudo_debug_exit_bool(__func__, __FILE__, __LINE__, sudo_debug_subsys,  \
	    sudo_debug_rval);						       \
	return sudo_debug_rval;						       \
    } while (0)

#define debug_return_str(rval)						       \
    do {								       \
	char *sudo_debug_rval = (rval);					       \
	sudo_debug_exit_str(__func__, __FILE__, __LINE__, sudo_debug_subsys,   \
	    sudo_debug_rval);						       \
	return sudo_debug_rval;						       \
    } while (0)

#define debug_return_const_str(rval)					       \
    do {								       \
	const char *sudo_debug_rval = (rval);				       \
	sudo_debug_exit_str(__func__, __FILE__, __LINE__, sudo_debug_subsys,   \
	    sudo_debug_rval);						       \
	return sudo_debug_rval;						       \
    } while (0)

#define debug_return_str_masked(rval)					       \
    do {								       \
	char *sudo_debug_rval = (rval);					       \
	sudo_debug_exit_str_masked(__func__, __FILE__, __LINE__,	       \
	    sudo_debug_subsys, sudo_debug_rval);			       \
	return sudo_debug_rval;						       \
    } while (0)

#define debug_return_ptr(rval)						       \
    do {								       \
	void *sudo_debug_rval = (rval);					       \
	sudo_debug_exit_ptr(__func__, __FILE__, __LINE__, sudo_debug_subsys,   \
	    sudo_debug_rval);						       \
	return sudo_debug_rval;						       \
    } while (0)

#define debug_return_const_ptr(rval)					       \
    do {								       \
	const void *sudo_debug_rval = (rval);				       \
	sudo_debug_exit_ptr(__func__, __FILE__, __LINE__, sudo_debug_subsys,   \
	    sudo_debug_rval);						       \
	return sudo_debug_rval;						       \
    } while (0)

/*
 * Variadic macros are a C99 feature but GNU cpp has supported
 * a (different) version of them for a long time.
 */
#if defined(NO_VARIADIC_MACROS)
# define sudo_debug_printf sudo_debug_printf_nvm
#elif defined(__GNUC__) && __GNUC__ == 2
# define sudo_debug_printf(pri, fmt...) \
    sudo_debug_printf2(__func__, __FILE__, __LINE__, (pri)|sudo_debug_subsys, \
    fmt)
#else
# define sudo_debug_printf(pri, ...) \
    sudo_debug_printf2(__func__, __FILE__, __LINE__, (pri)|sudo_debug_subsys, \
    __VA_ARGS__)
#endif

#define sudo_debug_execve(pri, path, argv, envp) \
    sudo_debug_execve2((pri)|sudo_debug_subsys, (path), (argv), (envp))

#define sudo_debug_write(fd, str, len, errnum) \
    sudo_debug_write2(fd, NULL, NULL, 0, (str), (len), (errnum))

__dso_public int sudo_debug_deregister(int instance_id);
__dso_public void sudo_debug_enter(const char *func, const char *file, int line, int subsys);
__dso_public void sudo_debug_execve2(int level, const char *path, char *const argv[], char *const envp[]);
__dso_public void sudo_debug_exit(const char *func, const char *file, int line, int subsys);
__dso_public void sudo_debug_exit_bool(const char *func, const char *file, int line, int subsys, int rval);
__dso_public void sudo_debug_exit_int(const char *func, const char *file, int line, int subsys, int rval);
__dso_public void sudo_debug_exit_long(const char *func, const char *file, int line, int subsys, long rval);
__dso_public void sudo_debug_exit_ptr(const char *func, const char *file, int line, int subsys, const void *rval);
__dso_public void sudo_debug_exit_size_t(const char *func, const char *file, int line, int subsys, size_t rval);
__dso_public void sudo_debug_exit_str(const char *func, const char *file, int line, int subsys, const char *rval);
__dso_public void sudo_debug_exit_str_masked(const char *func, const char *file, int line, int subsys, const char *rval);
__dso_public pid_t sudo_debug_fork(void);
__dso_public int sudo_debug_get_default_instance(void);
__dso_public int sudo_debug_get_fds(fd_set **fdsetp);
__dso_public int sudo_debug_get_instance(const char *program);
__dso_public void sudo_debug_printf2(const char *func, const char *file, int line, int level, const char *fmt, ...) __printf0like(5, 6);
__dso_public void sudo_debug_printf_nvm(int pri, const char *fmt, ...) __printf0like(2, 3);
__dso_public int sudo_debug_register(const char *program, const char *const subsystems[], int num_subsystems, struct sudo_conf_debug_file_list *debug_files);
__dso_public int sudo_debug_set_default_instance(int inst);
__dso_public void sudo_debug_update_fd(int ofd, int nfd);
__dso_public void sudo_debug_vprintf2(const char *func, const char *file, int line, int level, const char *fmt, va_list ap) __printf0like(5, 0);
__dso_public void sudo_debug_write2(int fd, const char *func, const char *file, int line, const char *str, int len, int errnum);

#endif /* _SUDO_DEBUG_H */
