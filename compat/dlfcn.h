/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _DLFCN_H_
#define _DLFCN_H_

/* Emulated functions. */
void *sudo_dlopen(const char *path, int mode);
int sudo_dlclose(void *handle);
void *sudo_dlsym(void *handle, const char *symbol);
char *sudo_dlerror(void);

/* Map emulated functions to standard names. */
#define dlopen(p, m)	sudo_dlopen(p, m)
#define dlclose(h)	sudo_dlclose(h)
#define dlsym(h, s)	sudo_dlsym(h, s)
#define dlerror()	sudo_dlerror()

/* Values for dlopen() mode. */
#define RTLD_LAZY	0x1
#define RTLD_NOW	0x2
#define RTLD_GLOBAL	0x4
#define RTLD_LOCAL	0x8

/* Special handle arguments for dlsym(). */
#define	RTLD_NEXT	((void *) -1)	/* Search subsequent objects. */
#define	RTLD_DEFAULT	((void *) -2)	/* Use default search algorithm. */
#define	RTLD_SELF	((void *) -3)	/* Search the caller itself. */

#endif /* !_DLFCN_H_ */
