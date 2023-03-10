/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2018, 2021, 2023 Todd C. Miller <Todd.Miller@sudo.ws>
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

#ifndef LDAP_OPT_RESULT_CODE
# define LDAP_OPT_RESULT_CODE LDAP_OPT_ERROR_NUMBER
#endif

#if !defined(LDAP_OPT_NETWORK_TIMEOUT) && defined(LDAP_OPT_CONNECT_TIMEOUT)
# define LDAP_OPT_NETWORK_TIMEOUT LDAP_OPT_CONNECT_TIMEOUT
#endif

#ifndef LDAP_OPT_SUCCESS
# define LDAP_OPT_SUCCESS LDAP_SUCCESS
#endif

#ifndef HAVE_LDAP_SEARCH_EXT_S
# ifdef HAVE_LDAP_SEARCH_ST
#  define ldap_search_ext_s(a, b, c, d, e, f, g, h, i, j, k)		\
	ldap_search_st(a, b, c, d, e, f, i, k)
# else
#  define ldap_search_ext_s(a, b, c, d, e, f, g, h, i, j, k)		\
	ldap_search_s(a, b, c, d, e, f, k)
# endif
#endif

#define LDAP_FOREACH(var, ld, res)					\
    for ((var) = ldap_first_entry((ld), (res));				\
	(var) != NULL;							\
	(var) = ldap_next_entry((ld), (var)))

/* Iterators used by sudo_ldap_role_to_priv() to handle bervar ** or char ** */
typedef char * (*sudo_ldap_iter_t)(void **);

/* ldap_util.c */
bool sudo_ldap_is_negated(char **valp);
size_t sudo_ldap_value_len(const char *value);
size_t sudo_ldap_value_cat(char *dst, const char *src, size_t size);
char *sudo_ldap_value_dup(const char *src);
int sudo_ldap_parse_option(char *optstr, char **varp, char **valp);
struct privilege *sudo_ldap_role_to_priv(const char *cn, void *hosts, void *runasusers, void *runasgroups, void *cmnds, void *opts, const char *notbefore, const char *notafter, bool warnings, bool store_options, sudo_ldap_iter_t iter);
struct member *sudo_ldap_new_member_all(void);

#endif /* SUDOERS_LDAP_H */
