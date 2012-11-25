/*
 * Copyright (c) 2004, 2010-2012 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_ERROR_H_
#define	_SUDO_ERROR_H_

#include <stdarg.h>
#include <sudo_plugin.h>

/*
 * We wrap error/errorx and warn/warnx so that the same output can
 * go to the debug file, if there is one.
 */
#if defined(SUDO_ERROR_WRAP) && SUDO_ERROR_WRAP == 0
# if defined(__GNUC__) && __GNUC__ == 2
#  define error(rval, fmt...) error_nodebug((rval), fmt)
#  define errorx(rval, fmt...) errorx_nodebug((rval), fmt)
#  define warning(fmt...) warning_nodebug(fmt)
#  define warningx(fmt...) warningx_nodebug(fmt)
# else
#  define error(rval, ...) error_nodebug((rval), __VA_ARGS__)
#  define errorx(rval, ...) errorx_nodebug((rval), __VA_ARGS__)
#  define warning(...) warning_nodebug(__VA_ARGS__)
#  define warningx(...) warningx_nodebug(__VA_ARGS__)
# endif /* __GNUC__ == 2 */
# define verror(rval, fmt, ap) error_nodebug((rval), (fmt), (ap))
# define verrorx(rval, fmt, ap) errorx_nodebug((rval), (fmt), (ap))
# define vwarning(fmt, ap) warning_nodebug((fmt), (ap))
# define vwarningx(fmt, ap) warningx_nodebug((fmt), (ap))
#else /* SUDO_ERROR_WRAP */
# if defined(__GNUC__) && __GNUC__ == 2
#  define error(rval, fmt...) do {					       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys, \
	fmt);								       \
    error_nodebug((rval), fmt);						       \
} while (0)
#  define errorx(rval, fmt...) do {					       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|sudo_debug_subsys, fmt);	       \
    errorx_nodebug((rval), fmt);					       \
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
#  define error(rval, ...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys, \
	__VA_ARGS__);							       \
    error_nodebug((rval), __VA_ARGS__);					       \
} while (0)
#  define errorx(rval, ...) do {					       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|sudo_debug_subsys, __VA_ARGS__);    \
    errorx_nodebug((rval), __VA_ARGS__);				       \
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
# define verror(rval, fmt, ap) do {					       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys, \
	(fmt), (ap));							       \
    verror_nodebug((rval), (fmt), (ap));				       \
} while (0)
# define verrorx(rval, fmt, ap) do {					       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|sudo_debug_subsys, (fmt), (ap));    \
    verrorx_nodebug((rval), (fmt), (ap));				       \
} while (0)
# define vwarning(fmt, ap) do {						       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys,  \
	(fmt), (ap));							       \
    vwarning_nodebug((fmt), (ap));					       \
    warning_restore_locale();						       \
} while (0)
# define vwarningx(fmt, ap) do {					       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|sudo_debug_subsys, (fmt), (ap));     \
    vwarningx_nodebug((fmt), (ap));					       \
} while (0)
#endif /* SUDO_ERROR_WRAP */

#if defined(__GNUC__) && __GNUC__ == 2
# define error_nodebug(rval, fmt...) do {				       \
    warning_set_locale();						       \
    error2((rval), fmt);						       \
} while (0)
# define errorx_nodebug(rval, fmt...) do {				       \
    warning_set_locale();						       \
    errorx2((rval), fmt);						       \
} while (0)
# define warning_nodebug(fmt...) do {					       \
    warning_set_locale();						       \
    warning2(fmt);							       \
    warning_restore_locale();						       \
} while (0)
# define warningx_nodebug(fmt...) do {					       \
    warning_set_locale();						       \
    warningx2(fmt);							       \
    warning_restore_locale();						       \
} while (0)
#else
# define error_nodebug(rval, ...) do {					       \
    warning_set_locale();						       \
    error2((rval), __VA_ARGS__);					       \
} while (0)
# define errorx_nodebug(rval, ...) do {					       \
    warning_set_locale();						       \
    errorx2((rval), __VA_ARGS__);					       \
} while (0)
# define warning_nodebug(...) do {					       \
    warning_set_locale();						       \
    warning2(__VA_ARGS__);						       \
    warning_restore_locale();						       \
} while (0)
# define warningx_nodebug(...) do {					       \
    warning_set_locale();						       \
    warningx2(__VA_ARGS__);						       \
    warning_restore_locale();						       \
} while (0)
#endif /* __GNUC__ == 2 */
#define verror_nodebug(rval, fmt, ap) do {				       \
    warning_set_locale();						       \
    verror2((rval), (fmt), (ap));					       \
} while (0)
#define verrorx_nodebug(rval, fmt, ap) do {				       \
    warning_set_locale();						       \
    verrorx2((rval), (fmt), (ap));					       \
} while (0)
#define vwarning_nodebug(fmt, ap) do {					       \
    warning_set_locale();						       \
    vwarning2((fmt), (ap));						       \
    warning_restore_locale();						       \
} while (0)
#define vwarningx_nodebug(fmt, ap) do {					       \
    warning_set_locale();						       \
    vwarningx2((fmt), (ap));						       \
    warning_restore_locale();						       \
} while (0)

extern sudo_printf_t sudo_printf;

void	error2(int, const char *, ...) __printflike(2, 3) __attribute__((__noreturn__));
void	errorx2(int, const char *, ...) __printflike(2, 3) __attribute__((__noreturn__));
void	verror2(int, const char *, va_list ap) __attribute__((__noreturn__));
void	verrorx2(int, const char *, va_list ap) __attribute__((__noreturn__));
void	warning2(const char *, ...) __printflike(1, 2);
void	warningx2(const char *, ...) __printflike(1, 2);
void	vwarning2(const char *, va_list ap);
void	vwarningx2(const char *, va_list ap);
void    warning_set_locale(void);
void    warning_restore_locale(void);

#endif /* _SUDO_ERROR_H_ */
