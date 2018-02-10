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

#ifndef SUDOERS_LDAP_H
#define SUDOERS_LDAP_H

typedef char * (*sudo_ldap_iter_t)(void *, void **);

bool sudo_ldap_is_negated(char **valp);
int sudo_ldap_parse_option(char *optstr, char **varp, char **valp);
struct privilege *sudo_ldap_role_to_priv(const char *cn, void *runasusers, void *runasgroups, void *cmnds, void *opts, const char *notbefore, const char *notafter, sudo_ldap_iter_t iter);
struct sudo_digest *sudo_ldap_extract_digest(char **cmnd, struct sudo_digest *digest);

#endif /* SUDOERS_LDAP_H */
