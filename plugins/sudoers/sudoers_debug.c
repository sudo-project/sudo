/*
 * Copyright (c) 2014 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif /* STDC_HEADERS */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <ctype.h>

#include "sudoers.h"

int sudoers_debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;

/*
 * Parse the "filename flags,..." debug_flags entry and insert a new
 * sudo_debug_file struct into debug_files.
 */
void
sudoers_debug_parse_flags(struct sudo_conf_debug_file_list *debug_files,
    const char *entry)
{
    struct sudo_debug_file *debug_file;
    const char *filename, *flags;
    size_t namelen;

    /* Already initialized? */
    if (sudoers_debug_instance != SUDO_DEBUG_INSTANCE_INITIALIZER)
	return;

    /* Process new-style debug flags: filename flags,... */
    filename = entry;
    if (*filename != '/' || (flags = strpbrk(filename, " \t")) == NULL)
	return;
    namelen = (size_t)(flags - filename);
    while (isblank((unsigned char)*flags))
	flags++;
    if (*flags == '\0')
	return;

    debug_file = sudo_emalloc(sizeof(*debug_file));
    debug_file->debug_file = sudo_estrndup(filename, namelen);
    debug_file->debug_flags = sudo_estrdup(flags);
    TAILQ_INSERT_TAIL(debug_files, debug_file, entries);
}

/*
 * Register the specified debug files and plugin_path with the
 * debug subsystem.
 */
void
sudoers_debug_register(struct sudo_conf_debug_file_list *debug_files,
    const char *plugin_path)
{
    struct sudo_debug_file *debug_file, *debug_next;

    /* Setup debugging if indicated. */
    if (!TAILQ_EMPTY(debug_files)) {
	if (plugin_path != NULL) {
	    sudoers_debug_instance =
		sudo_debug_register(plugin_path, NULL, 0, debug_files);
	}
	TAILQ_FOREACH_SAFE(debug_file, debug_files, entries, debug_next) {
	    TAILQ_REMOVE(debug_files, debug_file, entries);
	    sudo_efree(debug_file->debug_file);
	    sudo_efree(debug_file->debug_flags);
	    sudo_efree(debug_file);
	}
    }
}
