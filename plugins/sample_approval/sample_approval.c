/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2020 Todd C. Miller <Todd.Miller@sudo.ws>
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
#endif /* HAVE_STDBOOL_H */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include "sudo_gettext.h"	/* must be included before sudo_compat.h */

#include "sudo_compat.h"
#include "sudo_conf.h"
#include "sudo_debug.h"
#include "sudo_fatal.h"
#include "sudo_plugin.h"
#include "sudo_util.h"

static int approval_debug_instance = SUDO_DEBUG_INSTANCE_INITIALIZER;

/*
 * Parse the "filename flags,..." debug_flags entry and insert a new
 * sudo_debug_file struct into debug_files.
 * XXX - move to libsudoutil
 */
static bool
sudo_debug_parse_flags(struct sudo_conf_debug_file_list *debug_files,
    const char *entry)
{
    struct sudo_debug_file *debug_file;
    const char *filename, *flags;
    size_t namelen;

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
    return false;
}

static int
approval_check(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[],
    char * const user_info[], int submit_optind, char * const submit_argv[],
    char * const submit_envp[], char * const command_info[],
    char * const run_argv[], char * const run_envp[],
    char * const plugin_options[], const char **errstr)
{
    struct sudo_conf_debug_file_list debug_files =
	TAILQ_HEAD_INITIALIZER(debug_files);
    struct sudo_debug_file *debug_file;
    const char *cp, *plugin_path = NULL;
    char * const *cur;
    struct tm *tm;
    time_t now;
    int ret = -1;
    debug_decl(approval_check, SUDO_DEBUG_PLUGIN);

    /* Initialize the debug subsystem.  */
    for (cur = settings; (cp = *cur) != NULL; cur++) {
        if (strncmp(cp, "debug_flags=", sizeof("debug_flags=") - 1) == 0) {
            cp += sizeof("debug_flags=") - 1;
            if (!sudo_debug_parse_flags(&debug_files, cp)) {
                goto oom;
	    }
            continue;
        }
        if (strncmp(cp, "plugin_path=", sizeof("plugin_path=") - 1) == 0) {
            plugin_path = cp + sizeof("plugin_path=") - 1;
            continue;
        }
    }
    if (plugin_path != NULL && !TAILQ_EMPTY(&debug_files)) {
	approval_debug_instance =
	    sudo_debug_register(plugin_path, NULL, NULL, &debug_files);
	if (approval_debug_instance == SUDO_DEBUG_INSTANCE_ERROR) {
	    *errstr = U_("unable to initialize debugging");
	    goto bad;
	}
    }

    /*
     * Only approve requests that are within business hours,
     * which are 9am - 5pm local time.  Does not check holidays.
     */
    ret = 0;
    time(&now);
    tm = localtime(&now);
    if (tm->tm_wday < 1 || tm->tm_wday > 5) {
	/* bad weekday */
	goto bad;
    }
    if (tm->tm_hour < 9 || tm->tm_hour > 17 ||
	    (tm->tm_hour == 17 && tm->tm_min > 0)) {
	/* bad hour */
	goto bad;
    }

    ret = 1;
    goto done;

oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    *errstr = U_("unable to allocate memory");

bad:
    if (ret == 0) {
	*errstr = U_("You are not allowed to use sudo outside business hours");
	plugin_printf(SUDO_CONV_ERROR_MSG, "%s\n", *errstr);
    }

done:
    while ((debug_file = TAILQ_FIRST(&debug_files))) {
	TAILQ_REMOVE(&debug_files, debug_file, entries);
	free(debug_file->debug_file);
	free(debug_file->debug_flags);
	free(debug_file);
    }

    debug_return_int(ret);
}

static int
approval_show_version(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, int verbose)
{
    debug_decl(approval_show_version, SUDO_DEBUG_PLUGIN);

    plugin_printf(SUDO_CONV_INFO_MSG, "sample approval plugin version %s\n",
        PACKAGE_VERSION);

    debug_return_int(true);
}

__dso_public struct approval_plugin sample_approval = {
    SUDO_APPROVAL_PLUGIN,
    SUDO_API_VERSION,
    approval_check,
    approval_show_version
};
