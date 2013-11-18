/*
 * Copyright (c) 2004, 2010-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_FATAL_H_
#define	_SUDO_FATAL_H_

#include <stdarg.h>
#include <setjmp.h>

/*
 * We wrap fatal/fatalx and warning/warningx so that the same output can
 * go to the debug file, if there is one.
 */
#if (defined(SUDO_ERROR_WRAP) && SUDO_ERROR_WRAP == 0) || defined(NO_VARIADIC_MACROS)
# define fatal fatal_nodebug
# define fatalx fatalx_nodebug
# define warning warning_nodebug
# define warningx warningx_nodebug
# define vfatal(fmt, ap) fatal_nodebug((fmt), (ap))
# define vfatalx(fmt, ap) fatalx_nodebug((fmt), (ap))
# define vwarning(fmt, ap) warning_nodebug((fmt), (ap))
# define vwarningx(fmt, ap) warningx_nodebug((fmt), (ap))
#else /* SUDO_ERROR_WRAP */
# if defined(__GNUC__) && __GNUC__ == 2
#  define fatal(fmt...) do {					       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys, \
	fmt);								       \
    fatal_nodebug(fmt);						       \
} while (0)
#  define fatalx(fmt...) do {					       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|sudo_debug_subsys, fmt);	       \
    fatalx_nodebug(fmt);					       \
} while (0)
#  define warning(fmt...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys, \
	fmt);								       \
    warning_nodebug(fmt);						       \
} while (0)
#  define warningx(fmt...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|sudo_debug_subsys, fmt);	       \
    warningx_nodebug(fmt);						       \
} while (0)
# else
#  define fatal(...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys, \
	__VA_ARGS__);							       \
    fatal_nodebug(__VA_ARGS__);					       \
} while (0)
#  define fatalx(...) do {					       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|sudo_debug_subsys, __VA_ARGS__);    \
    fatalx_nodebug(__VA_ARGS__);				       \
} while (0)
#  define warning(...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys,  \
	__VA_ARGS__);							       \
    warning_nodebug(__VA_ARGS__);					       \
} while (0)
#  define warningx(...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|sudo_debug_subsys, __VA_ARGS__);     \
    warningx_nodebug(__VA_ARGS__);					       \
} while (0)
# endif /* __GNUC__ == 2 */
# define vfatal(fmt, ap) do {						       \
    va_list ap2;							       \
    va_copy(ap2, (ap));							       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys, \
	(fmt), ap2);							       \
    vfatal_nodebug((fmt), (ap));				       \
} while (0)
# define vfatalx(fmt, ap) do {					       \
    va_list ap2;							       \
    va_copy(ap2, (ap));							       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|sudo_debug_subsys, (fmt), ap2);     \
    vfatalx_nodebug((fmt), (ap));				       \
} while (0)
# define vwarning(fmt, ap) do {						       \
    va_list ap2;							       \
    va_copy(ap2, (ap));							       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys,  \
	(fmt), ap2);							       \
    vwarning_nodebug((fmt), (ap));					       \
} while (0)
# define vwarningx(fmt, ap) do {					       \
    va_list ap2;							       \
    va_copy(ap2, (ap));							       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|sudo_debug_subsys, (fmt), ap2);      \
    vwarningx_nodebug((fmt), (ap));					       \
} while (0)
#endif /* SUDO_ERROR_WRAP */

#define fatal_setjmp()		(fatal_enable_setjmp(), sigsetjmp(fatal_jmp, 1))
#define fatal_longjmp(val)	siglongjmp(fatal_jmp, val)

extern int (*sudo_printf)(int msg_type, const char *fmt, ...);
extern sigjmp_buf fatal_jmp;

int	fatal_callback_register(void (*func)(void));
char   *warning_gettext(const char *msgid) __format_arg(1);
void	fatal_disable_setjmp(void);
void	fatal_enable_setjmp(void);
void	fatal_nodebug(const char *, ...) __printf0like(1, 2) __attribute__((__noreturn__));
void	fatalx_nodebug(const char *, ...) __printflike(1, 2) __attribute__((__noreturn__));
void	vfatal_nodebug(const char *, va_list ap) __printf0like(1, 0) __attribute__((__noreturn__));
void	vfatalx_nodebug(const char *, va_list ap) __printflike(1, 0) __attribute__((__noreturn__));
void	warning_nodebug(const char *, ...) __printf0like(1, 2);
void	warningx_nodebug(const char *, ...) __printflike(1, 2);
void	vwarning_nodebug(const char *, va_list ap) __printf0like(1, 0);
void	vwarningx_nodebug(const char *, va_list ap) __printflike(1, 0);

#endif /* _SUDO_FATAL_H_ */
