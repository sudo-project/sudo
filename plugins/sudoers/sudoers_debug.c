/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2014-2015 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
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
#include <unistd.h>
#include <ctype.h>

#include "sudoers.h"

static int sudoers_debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;
static unsigned int sudoers_debug_refcnt;

static const char *const sudoers_subsystem_names[] = {
    "alias",
    "audit",
    "auth",
    "defaults",
    "env",
    "event",
    "ldap",
    "logging",
    "main",
    "match",
    "netif",
    "nss",
    "parser",
    "perms",
    "plugin",
    "rbtree",
    "sssd",
    "util",
    NULL
};

#define NUM_SUBSYSTEMS  (nitems(sudoers_subsystem_names) - 1)

/* Subsystem IDs assigned at registration time. */
unsigned int sudoers_subsystem_ids[NUM_SUBSYSTEMS];

/*
 * Parse the "filename flags,..." debug_flags entry and insert a new
 * sudo_debug_file struct into debug_files.
 */
bool
sudoers_debug_parse_flags(struct sudo_conf_debug_file_list *debug_files,
    const char *entry)
{
    struct sudo_debug_file *debug_file;
    const char *filename, *flags;
    size_t namelen;

    /* Already initialized? */
    if (sudoers_debug_instance != SUDO_DEBUG_INSTANCE_INITIALIZER)
	return true;

    /* Only process new-style debug flags: filename flags,... */
    filename = entry;
    if (*filename != '/' || (flags = strpbrk(filename, " \t")) == NULL)
	return true;
    namelen = (size_t)(flags - filename);
    while (isblank((unsigned char)*flags))
	flags++;
    if (*flags != '\0') {
	if ((debug_file = calloc(1, sizeof(*debug_file))) == NULL)
	    goto oom;
	if ((debug_file->debug_file = strndup(filename, namelen)) == NULL)
	    goto oom;
	if ((debug_file->debug_flags = strdup(flags)) == NULL)
	    goto oom;
	TAILQ_INSERT_TAIL(debug_files, debug_file, entries);
    }
    return true;
oom:
    if (debug_file != NULL) {
	free(debug_file->debug_file);
	free(debug_file->debug_flags);
	free(debug_file);
    }
    sudo_warnx_nodebug(U_("%s: %s"), "sudoers_debug_parse_flags",
	U_("unable to allocate memory"));
    return false;
}

/*
 * Register the specified debug files and program with the
 * debug subsystem, freeing the debug list when done.
 * Sets the active debug instance as a side effect.
 */
bool
sudoers_debug_register(const char *program,
    struct sudo_conf_debug_file_list *debug_files)
{
    struct sudo_debug_file *debug_file, *debug_next;

    /* Already initialized? */
    if (sudoers_debug_instance != SUDO_DEBUG_INSTANCE_INITIALIZER)
	sudo_debug_set_active_instance(sudoers_debug_instance);

    /* Setup debugging if indicated. */
    if (debug_files != NULL && !TAILQ_EMPTY(debug_files)) {
	if (program != NULL) {
	    sudoers_debug_instance = sudo_debug_register(program,
		sudoers_subsystem_names, sudoers_subsystem_ids, debug_files);
	    if (sudoers_debug_instance == SUDO_DEBUG_INSTANCE_ERROR)
		return false;

	    sudoers_debug_refcnt++;
	}
	TAILQ_FOREACH_SAFE(debug_file, debug_files, entries, debug_next) {
	    TAILQ_REMOVE(debug_files, debug_file, entries);
	    free(debug_file->debug_file);
	    free(debug_file->debug_flags);
	    free(debug_file);
	}
    }
    return true;
}

/*
 * Deregister sudoers_debug_instance if it is registered.
 */
void
sudoers_debug_deregister(void)
{
    debug_decl(sudoers_debug_deregister, SUDOERS_DEBUG_PLUGIN);

    if (sudoers_debug_refcnt != 0) {
	sudo_debug_exit(__func__, __FILE__, __LINE__, sudo_debug_subsys);
	if (--sudoers_debug_refcnt == 0) {
	    if (sudo_debug_deregister(sudoers_debug_instance) < 1)
		sudoers_debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;
	}
    }
}
