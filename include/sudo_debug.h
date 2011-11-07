/*
 * Copyright (c) 2011 Todd C. Miller <Todd.Miller@courtesan.com>
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

/*
 * The priority and subsystem are encoded in a single 32-bit value.
 * The lower 4 bits are the priority and the top 28 bits are the subsystem.
 * This allows for 16 priorities and a very large number of subsystems.
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

/*
 * Sudo debug subsystems.
 * This includes subsystems in the sudoers plugin.
 * Note: order must match sudo_debug_subsystems[]
 */
#define SUDO_DEBUG_MAIN		(1<<4)	/* sudo main() */
#define SUDO_DEBUG_MEMORY	(2<<4)	/* memory subsystems */
#define SUDO_DEBUG_ARGS		(3<<4)	/* command line argument processing */
#define SUDO_DEBUG_EXEC		(4<<4)	/* command execution */
#define SUDO_DEBUG_PTY		(5<<4)	/* pseudo-tty */
#define SUDO_DEBUG_UTMP		(6<<4)	/* utmp file ops */
#define SUDO_DEBUG_CONV		(7<<4)	/* user conversation */
#define SUDO_DEBUG_PCOMM	(8<<4)	/* plugin communications */
#define SUDO_DEBUG_UTIL		(9<<4)	/* utility functions */
#define SUDO_DEBUG_LIST		(10<<4)	/* linked list functions */
#define SUDO_DEBUG_NETIF	(11<<4)	/* network interface functions */
#define SUDO_DEBUG_AUDIT	(12<<4)	/* audit */
#define SUDO_DEBUG_EDIT		(13<<4)	/* sudoedit */
#define SUDO_DEBUG_SELINUX	(14<<4)	/* selinux */
#define SUDO_DEBUG_LDAP		(15<<4)	/* sudoers LDAP */
#define SUDO_DEBUG_MATCH	(16<<4)	/* sudoers matching */
#define SUDO_DEBUG_PARSER	(17<<4)	/* sudoers parser */
#define SUDO_DEBUG_ALIAS	(18<<4)	/* sudoers alias functions */
#define SUDO_DEBUG_DEFAULTS	(19<<4)	/* sudoers defaults settings */
#define SUDO_DEBUG_AUTH		(20<<4)	/* authentication functions */
#define SUDO_DEBUG_ENV		(21<<4)	/* environment handling */
#define SUDO_DEBUG_LOGGING	(22<<4)	/* logging functions */
#define SUDO_DEBUG_NSS		(23<<4)	/* network service switch */
#define SUDO_DEBUG_RBTREE	(24<<4)	/* red-black tree functions */
#define SUDO_DEBUG_PERMS	(25<<4)	/* uid/gid swapping functions */
#define SUDO_DEBUG_PLUGIN	(26<<4)	/* main plugin functions */
#define SUDO_DEBUG_ALL		0xfff0	/* all subsystems */

/* Extract priority and convert to an index. */
#define SUDO_DEBUG_PRI(n) (((n) & 0xf) - 1)

/* Extract subsystem and convert to an index. */
#define SUDO_DEBUG_SUBSYS(n) (((n) >> 4) - 1)

/*
 * Wrapper for sudo_debug_enter() that declares __func__ as needed
 * and sets sudo_debug_subsys for sudo_debug_exit().
 */
#ifdef HAVE___FUNC__
# define debug_decl(funcname, subsys)					       \
    const int sudo_debug_subsys = (subsys);				       \
    sudo_debug_enter(__func__, __FILE__, __LINE__, sudo_debug_subsys);
#else
# define debug_decl(funcname, subsys)					       \
    const int sudo_debug_subsys = (subsys);				       \
    const char *__func__ = #funcname;					       \
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
	const char *sudo_debug_rval = (rval);				       \
	sudo_debug_exit_str(__func__, __FILE__, __LINE__, sudo_debug_subsys,   \
	    sudo_debug_rval);						       \
	return (char *)sudo_debug_rval;					       \
    } while (0)

#define debug_return_str_masked(rval)						       \
    do {								       \
	const char *sudo_debug_rval = (rval);				       \
	sudo_debug_exit_str_masked(__func__, __FILE__, __LINE__,	       \
	    sudo_debug_subsys, sudo_debug_rval);			       \
	return (char *)sudo_debug_rval;					       \
    } while (0)

#define debug_return_ptr(rval)						       \
    do {								       \
	const void *sudo_debug_rval = (rval);				       \
	sudo_debug_exit_ptr(__func__, __FILE__, __LINE__, sudo_debug_subsys,   \
	    sudo_debug_rval);						       \
	return (void *)sudo_debug_rval;					       \
    } while (0)

/*
 * Variadic macros are a C99 feature but GNU cpp has supported
 * a (different) version of them for a long time.
 */
#if defined(__GNUC__) && __GNUC__ == 2
# define sudo_debug_printf(pri, fmt...) \
    sudo_debug_printf2((pri)|sudo_debug_subsys, (fmt))
#else
# define sudo_debug_printf(pri, ...) \
    sudo_debug_printf2((pri)|sudo_debug_subsys, __VA_ARGS__)
#endif

#define sudo_debug_execve(pri, path, argv, envp) \
    sudo_debug_execve2((pri)|sudo_debug_subsys, (path), (argv), (envp))

/*
 * NULL-terminated string lists of priorities and subsystems.
 */
extern const char *const sudo_debug_priorities[];
extern const char *const sudo_debug_subsystems[];

void sudo_debug_enter(const char *func, const char *file, int line, int subsys);
void sudo_debug_exit(const char *func, const char *file, int line, int subsys);
void sudo_debug_exit_int(const char *func, const char *file, int line, int subsys, int rval);
void sudo_debug_exit_long(const char *func, const char *file, int line, int subsys, long rval);
void sudo_debug_exit_size_t(const char *func, const char *file, int line, int subsys, size_t rval);
void sudo_debug_exit_bool(const char *func, const char *file, int line, int subsys, int rval);
void sudo_debug_exit_str(const char *func, const char *file, int line, int subsys, const char *rval);
void sudo_debug_exit_str_masked(const char *func, const char *file, int line, int subsys, const char *rval);
void sudo_debug_exit_ptr(const char *func, const char *file, int line, int subsys, const void *rval);
int sudo_debug_init(const char *debugfile, const char *settings);
void sudo_debug_printf2(int level, const char *format, ...) __printflike(2, 3);
void sudo_debug_write(const char *str, int len);
void sudo_debug_execve2(int level, const char *path, char *const argv[], char *const envp[]);

#endif /* _SUDO_DEBUG_H */
