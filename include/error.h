/*
 * Copyright (c) 2004, 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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
#  define error(rval, fmt...) error2((rval), (fmt))
#  define errorx(rval, fmt...) errorx2((rval), (fmt))
#  define warning(fmt...) warning2((fmt))
#  define warningx(fmt...) warningx2((fmt))
# else
#  define error(rval, ...) error2((rval), __VA_ARGS__)
#  define errorx(rval, ...) errorx2((rval), __VA_ARGS__)
#  define warning(...) warning2(__VA_ARGS__)
#  define warningx(...) warningx2(__VA_ARGS__)
# endif /* __GNUC__ == 2 */
#else /* SUDO_ERROR_WRAP */
# if defined(__GNUC__) && __GNUC__ == 2
#  define error(rval, fmt...) do {					       \
    sudo_debug_printf2(SUDO_DEBUG_SYSERR|sudo_debug_subsys, (fmt));	       \
    error2((rval), (fmt));						       \
} while (0)
#  define errorx(rval, fmt...) do {					       \
    sudo_debug_printf2(SUDO_DEBUG_PROGERR|sudo_debug_subsys, (fmt));	       \
    errorx2((rval), (fmt));						       \
} while (0)
#  define warning(fmt...) do {						       \
    sudo_debug_printf2(SUDO_DEBUG_SYSERR|sudo_debug_subsys, (fmt));	       \
    warning2((fmt));							       \
} while (0)
#  define warningx(fmt...) do {						       \
    sudo_debug_printf2(SUDO_DEBUG_PROGERR|sudo_debug_subsys, (fmt));	       \
    warningx2((fmt));							       \
} while (0)
# else
#  define error(rval, ...) do {						       \
    sudo_debug_printf2(SUDO_DEBUG_SYSERR|sudo_debug_subsys, __VA_ARGS__);      \
    error2((rval), __VA_ARGS__);					       \
} while (0)
#  define errorx(rval, ...) do {					       \
    sudo_debug_printf2(SUDO_DEBUG_PROGERR|sudo_debug_subsys, __VA_ARGS__);     \
    errorx2((rval), __VA_ARGS__);					       \
} while (0)
#  define warning(...) do {						       \
    sudo_debug_printf2(SUDO_DEBUG_SYSERR|sudo_debug_subsys, __VA_ARGS__);      \
    warning2(__VA_ARGS__);						       \
} while (0)
#  define warningx(...) do {						       \
    sudo_debug_printf2(SUDO_DEBUG_PROGERR|sudo_debug_subsys, __VA_ARGS__);     \
    warningx2(__VA_ARGS__);						       \
} while (0)
# endif /* __GNUC__ == 2 */
#endif /* SUDO_ERROR_WRAP */

void	error2(int, const char *, ...)  __printflike(2, 3) __attribute__((__noreturn__));
void	errorx2(int, const char *, ...)  __printflike(2, 3) __attribute__((__noreturn__));
void	warning2(const char *, ...) __printflike(1, 2);
void	warningx2(const char *, ...) __printflike(1, 2);

#endif /* _SUDO_ERROR_H_ */
