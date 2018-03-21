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

#ifndef SUDOERS_CVTSUDOERS_H
#define SUDOERS_CVTSUDOERS_H

/* Supported input/output formats. */
enum sudoers_formats {
    format_json,
    format_ldif,
    format_sudoers
};

/*
 * Simple string list with optional reference count.
 */
struct cvtsudoers_string {
    STAILQ_ENTRY(cvtsudoers_string) entries;
    char *str;
};
struct cvtsudoers_str_list {
    struct cvtsudoers_string *stqh_first;
    struct cvtsudoers_string **stqh_last;
    unsigned int refcnt;
};

/* cvtsudoers.conf settings */
struct cvtsudoers_config {
    char *sudoers_base;
    char *input_format;
    char *output_format;
    char *filter;
    unsigned int sudo_order;
    unsigned int order_increment;
    bool expand_aliases;
    bool store_options;
};

/* Initial config settings for above. */
#define INITIAL_CONFIG { NULL, NULL, NULL, NULL, 1, 1, false, true }

#define CONF_BOOL	0
#define CONF_UINT	1
#define CONF_STR	2

struct cvtsudoers_conf_table {
    const char *conf_str;	/* config file string */
    int type;			/* CONF_BOOL, CONF_UINT, CONF_STR */
    void *valp;			/* pointer into cvtsudoers_config */
};

struct cvtsudoers_filter {
    struct cvtsudoers_str_list users;
    struct cvtsudoers_str_list groups;
    struct cvtsudoers_str_list hosts;
};

bool convert_sudoers_json(const char *output_file, struct cvtsudoers_config *conf);
bool convert_sudoers_ldif(const char *output_file, struct cvtsudoers_config *conf);
bool parse_ldif(const char *input_file, struct cvtsudoers_config *conf);
void get_hostname(void);

struct member_list;
struct userspec_list;
bool userlist_matches_filter(struct member_list *userlist);
bool hostlist_matches_filter(struct member_list *hostlist);

struct cvtsudoers_str_list *str_list_alloc(void);
void str_list_free(void *v);
struct cvtsudoers_string *cvtsudoers_string_alloc(const char *s);
void cvtsudoers_string_free(struct cvtsudoers_string *ls);

extern struct cvtsudoers_filter *filters;

#endif /* SUDOERS_CVTSUDOERS_H */
