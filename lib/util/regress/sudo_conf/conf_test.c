/*
 * Copyright (c) 2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef HAVE_STRING_H
# if defined(HAVE_MEMORY_H) && !defined(STDC_HEADERS)
#  include <memory.h>
# endif
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif

#include "missing.h"
#include "sudo_conf.h"
#include "sudo_util.h"

static void sudo_conf_dump(void);

__dso_public int main(int argc, char *argv[]);

/*
 * Simple test driver for sudo_conf().
 * Parses the given configuration file and dumps the resulting
 * sudo_conf_data struct to the standard output.
 */
int
main(int argc, char *argv[])
{
    initprogname(argc > 0 ? argv[0] : "conf_test");
    if (argc != 2) {
	fprintf(stderr, "usage: %s conf_file\n", getprogname());
	exit(1);
    }
    sudo_conf_read(argv[1]);
    sudo_conf_dump();

    exit(0);
}

static void
sudo_conf_dump(void)
{
    struct plugin_info_list *plugins = sudo_conf_plugins();
    struct plugin_info *info;

    printf("Set disable_coredump %s\n",
	sudo_conf_disable_coredump() ? "true" : "false");
    printf("Set group_source %s\n",
	sudo_conf_group_source() == GROUP_SOURCE_ADAPTIVE ? "adaptive" :
	sudo_conf_group_source() == GROUP_SOURCE_STATIC ? "static" : "dynamic");
    printf("Set max_groups %d\n", sudo_conf_max_groups());
    if (sudo_conf_debug_flags() != NULL)
	printf("Debug %s %s\n", getprogname(), sudo_conf_debug_flags());
    if (sudo_conf_askpass_path() != NULL)
	printf("Path askpass %s\n", sudo_conf_askpass_path());
#ifdef _PATH_SUDO_NOEXEC
    if (sudo_conf_noexec_path() != NULL)
	printf("Path noexec %s\n", sudo_conf_noexec_path());
#endif
    TAILQ_FOREACH(info, plugins, entries) {
	printf("Plugin %s %s", info->symbol_name, info->path);
	if (info->options) {
	    char * const * op;
	    for (op = info->options; *op != NULL; op++)
		printf(" %s", *op);
	}
	putchar('\n');
    }
}
