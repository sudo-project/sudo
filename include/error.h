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
    errorx_nodebug((rval), fmt);						       \
} while (0)
#  define warning(fmt...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys, \
	fmt);								       \
    warning_nodebug(fmt);							       \
} while (0)
#  define warningx(fmt...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|sudo_debug_subsys, fmt);	       \
    warningx_nodebug(fmt);							       \
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
    errorx_nodebug((rval), __VA_ARGS__);					       \
} while (0)
#  define warning(...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys,  \
	__VA_ARGS__);							       \
    warning_nodebug(__VA_ARGS__);						       \
} while (0)
#  define warningx(...) do {						       \
    sudo_debug_printf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|sudo_debug_subsys, __VA_ARGS__);     \
    warningx_nodebug(__VA_ARGS__);						       \
} while (0)
# endif /* __GNUC__ == 2 */
# define verror(rval, fmt, ap) do {						       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys, \
	(fmt), (ap));							       \
    verror_nodebug((rval), (fmt), (ap));					       \
} while (0)
# define verrorx(rval, fmt, ap) do {					       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO|sudo_debug_subsys, (fmt), (ap));    \
    verrorx_nodebug((rval), (fmt), (ap));					       \
} while (0)
# define vwarning(fmt, ap) do {						       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|SUDO_DEBUG_ERRNO|sudo_debug_subsys,  \
	(fmt), (ap));							       \
    vwarning_nodebug((fmt), (ap));						       \
} while (0)
# define vwarningx(fmt, ap) do {						       \
    sudo_debug_vprintf2(__func__, __FILE__, __LINE__,			       \
	SUDO_DEBUG_WARN|SUDO_DEBUG_LINENO|sudo_debug_subsys, (fmt), (ap));     \
    vwarningx_nodebug((fmt), (ap));						       \
} while (0)
#endif /* SUDO_ERROR_WRAP */

void	error_nodebug(int, const char *, ...) __printflike(2, 3) __attribute__((__noreturn__));
void	errorx_nodebug(int, const char *, ...) __printflike(2, 3) __attribute__((__noreturn__));
void	verror_nodebug(int, const char *, va_list ap) __attribute__((__noreturn__));
void	verrorx_nodebug(int, const char *, va_list ap) __attribute__((__noreturn__));
void	warning_nodebug(const char *, ...) __printflike(1, 2);
void	warningx_nodebug(const char *, ...) __printflike(1, 2);
void	vwarning_nodebug(const char *, va_list ap);
void	vwarningx_nodebug(const char *, va_list ap);

#endif /* _SUDO_ERROR_H_ */
