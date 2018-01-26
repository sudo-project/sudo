/*
 * Copyright (c) 2018 Todd C. Miller <Todd.Miller@sudo.ws>
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
 * Stub versions of functions needed by the parser.
 * Required to link cvtsudoers and visudo.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#include <netinet/in.h>
#include <arpa/inet.h>

#include "sudoers.h"
#include "interfaces.h"

/* STUB */
bool
init_envtables(void)
{
    return true;
}

/* STUB */
bool
user_is_exempt(void)
{
    return false;
}

/* STUB */
void
sudo_setspent(void)
{
    return;
}

/* STUB */
void
sudo_endspent(void)
{
    return;
}

/* STUB */
int
group_plugin_query(const char *user, const char *group, const struct passwd *pw)
{
    return false;
}

/* STUB */
struct interface_list *
get_interfaces(void)
{
    static struct interface_list dummy = SLIST_HEAD_INITIALIZER(interfaces);
    return &dummy;
}

/*
 * Look up the hostname and set user_host and user_shost.
 */
void
get_hostname(void)
{
    char *cp;
    debug_decl(get_hostname, SUDOERS_DEBUG_UTIL)

    if ((user_host = sudo_gethostname()) != NULL) {
	if ((cp = strchr(user_host, '.'))) {
	    *cp = '\0';
	    if ((user_shost = strdup(user_host)) == NULL)
		sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    *cp = '.';
	} else {
	    user_shost = user_host;
	}
    } else {
	user_host = user_shost = strdup("localhost");
	if (user_host == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
    }
    user_runhost = user_host;
    user_srunhost = user_shost;

    debug_return;
}

/*
 * Parse sudoers plugin options.
 * May set sudoers_file, sudoers_uid, sudoers_gid or sudoers_mode globals.
 */
void
parse_sudoers_options(void)
{
    struct plugin_info_list *plugins;
    debug_decl(parse_sudoers_options, SUDOERS_DEBUG_UTIL)

    plugins = sudo_conf_plugins();
    if (plugins) {
	struct plugin_info *info;

	TAILQ_FOREACH(info, plugins, entries) {
	    if (strcmp(info->symbol_name, "sudoers_policy") == 0)
		break;
	}
	if (info != NULL && info->options != NULL) {
	    char * const *cur;

#define MATCHES(s, v)	\
    (strncmp((s), (v), sizeof(v) - 1) == 0 && (s)[sizeof(v) - 1] != '\0')

	    for (cur = info->options; *cur != NULL; cur++) {
		const char *errstr, *p;
		id_t id;

		if (MATCHES(*cur, "sudoers_file=")) {
		    sudoers_file = *cur + sizeof("sudoers_file=") - 1;
		    continue;
		}
		if (MATCHES(*cur, "sudoers_uid=")) {
		    p = *cur + sizeof("sudoers_uid=") - 1;
		    id = sudo_strtoid(p, NULL, NULL, &errstr);
		    if (errstr == NULL)
			sudoers_uid = (uid_t) id;
		    continue;
		}
		if (MATCHES(*cur, "sudoers_gid=")) {
		    p = *cur + sizeof("sudoers_gid=") - 1;
		    id = sudo_strtoid(p, NULL, NULL, &errstr);
		    if (errstr == NULL)
			sudoers_gid = (gid_t) id;
		    continue;
		}
		if (MATCHES(*cur, "sudoers_mode=")) {
		    p = *cur + sizeof("sudoers_mode=") - 1;
		    id = (id_t) sudo_strtomode(p, &errstr);
		    if (errstr == NULL)
			sudoers_mode = (mode_t) id;
		    continue;
		}
	    }
#undef MATCHES
	}
    }
    debug_return;
}
