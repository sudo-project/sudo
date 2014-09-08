/*
 * Copyright (c) 2009-2010, 2012-1014
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_ALLOC_H
#define _SUDO_ALLOC_H

#include <stdarg.h>

#undef sudo_efree
#define sudo_efree(x)	free((void *)(x))

__dso_public int  sudo_easprintf_v1(char **ret, const char *fmt, ...) __printflike(2, 3);
__dso_public int  sudo_evasprintf_v1(char **ret, const char *fmt, va_list) __printflike(2, 0);
__dso_public void *sudo_ecalloc_v1(size_t nmemb, size_t size) __malloc_like;
__dso_public void *sudo_emalloc_v1(size_t size) __malloc_like;
__dso_public void *sudo_emallocarray_v1(size_t nmemb, size_t size) __malloc_like;
__dso_public void *sudo_erealloc_v1(void *ptr, size_t size);
__dso_public void *sudo_ereallocarray_v1(void *ptr, size_t nmemb, size_t size);
__dso_public void *sudo_erecalloc_v1(void *ptr, size_t onmemb, size_t nmemb, size_t msize);
__dso_public char *sudo_estrdup_v1(const char *src) __malloc_like;
__dso_public char *sudo_estrndup_v1(const char *src, size_t maxlen) __malloc_like;

#define sudo_easprintf	sudo_easprintf_v1
#define sudo_evasprintf(_a, _b, _c) sudo_evasprintf_v1((_a), (_b), (_c))
#define sudo_ecalloc(_a, _b) sudo_ecalloc_v1((_a), (_b))
#define sudo_emalloc(_a) sudo_emalloc_v1((_a))
#define sudo_emallocarray(_a, _b) sudo_emallocarray_v1((_a), (_b))
#define sudo_erealloc(_a, _b) sudo_erealloc_v1((_a), (_b))
#define sudo_ereallocarray(_a, _b, _c) sudo_ereallocarray_v1((_a), (_b), (_c))
#define sudo_erecalloc(_a, _b, _c, _d) sudo_erecalloc_v1((_a), (_b), (_c), (_d))
#define sudo_estrdup(_a) sudo_estrdup_v1((_a))
#define sudo_estrndup(_a, _b) sudo_estrndup_v1((_a), (_b))

#endif /* _SUDO_ALLOC_H */
