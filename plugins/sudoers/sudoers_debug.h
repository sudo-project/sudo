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

#ifndef _SUDOERS_DEBUG_H
#define _SUDOERS_DEBUG_H

#include "sudo_debug.h"

/*
 * Sudoers debug subsystems.
 * The first five entries must match the sudo front end.
 * Note: order must match sudoers_debug_subsystems[]
 */
#define SUDOERS_DEBUG_MAIN	( 1<<16)   /* main() */
#define SUDOERS_DEBUG_UTIL	( 2<<16)   /* utility functions */
#define SUDOERS_DEBUG_NETIF	( 3<<16)   /* network interface functions */
#define SUDOERS_DEBUG_PLUGIN	( 4<<16)   /* main plugin functions */
#define SUDOERS_DEBUG_EVENT	( 5<<16)   /* event handling */
#define SUDOERS_DEBUG_AUDIT	( 6<<16)   /* audit */
#define SUDOERS_DEBUG_LDAP	( 7<<16)   /* sudoers LDAP */
#define SUDOERS_DEBUG_MATCH	( 8<<16)   /* sudoers matching */
#define SUDOERS_DEBUG_PARSER	( 9<<16)   /* sudoers parser */
#define SUDOERS_DEBUG_ALIAS	(10<<16)   /* sudoers alias functions */
#define SUDOERS_DEBUG_DEFAULTS	(11<<16)   /* sudoers defaults settings */
#define SUDOERS_DEBUG_AUTH	(12<<16)   /* authentication functions */
#define SUDOERS_DEBUG_ENV	(13<<16)   /* environment handling */
#define SUDOERS_DEBUG_LOGGING	(14<<16)   /* logging functions */
#define SUDOERS_DEBUG_NSS	(15<<16)   /* network service switch */
#define SUDOERS_DEBUG_RBTREE	(16<<16)   /* red-black tree functions */
#define SUDOERS_DEBUG_PERMS	(17<<16)   /* uid/gid swapping functions */
#define SUDOERS_DEBUG_SSSD	(18<<16)   /* sudoers SSSD */
#define SUDOERS_DEBUG_ALL	0xffff0000 /* all subsystems */

#endif /* _SUDOERS_DEBUG_H */
