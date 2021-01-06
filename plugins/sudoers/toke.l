%{
/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 1996, 1998-2005, 2007-2020
 *	Todd C. Miller <Todd.Miller@sudo.ws>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <ctype.h>
#include "sudoers.h"
#include "toke.h"
#include <gram.h>
#include "sudo_digest.h"
#include "sudo_lbuf.h"

#if defined(HAVE_STRUCT_DIRENT_D_NAMLEN) && HAVE_STRUCT_DIRENT_D_NAMLEN
# define NAMLEN(dirent)	(dirent)->d_namlen
#else
# define NAMLEN(dirent)	strlen((dirent)->d_name)
#endif

// PVS Studio suppression
// -V::519, 1004, 1037

int sudolineno;			/* current sudoers line number. */
char *sudoers;			/* sudoers file being parsed. */
struct sudolinebuf sudolinebuf;	/* sudoers line being parsed. */

/* Default sudoers path, mode and owner (may be set via sudo.conf) */
const char *sudoers_file = _PATH_SUDOERS;
mode_t sudoers_mode = SUDOERS_MODE;
uid_t sudoers_uid = SUDOERS_UID;
gid_t sudoers_gid = SUDOERS_GID;

static bool continued, sawspace;
static int prev_state;
static int digest_type = -1;

static bool pop_include(void);
static yy_size_t sudoers_input(char *buf, yy_size_t max_size);

int (*trace_print)(const char *msg) = sudoers_trace_print;

#define ECHO	ignore_result(fwrite(sudoerstext, sudoersleng, 1, sudoersout))

#define YY_INPUT(buf, result, max_size)	(result) = sudoers_input(buf, max_size)

#define YY_USER_ACTION do {					\
	sudolinebuf.toke_start = sudolinebuf.toke_end;		\
	sudolinebuf.toke_end += sudoersleng;			\
} while (0);

#define sudoersless(n) do {					\
	sudolinebuf.toke_end = sudolinebuf.toke_start + (n);	\
	yyless(n);						\
} while (0);

%}

HEX16			[0-9A-Fa-f]{1,4}
OCTET			(1?[0-9]{1,2})|(2[0-4][0-9])|(25[0-5])
IPV4ADDR		{OCTET}(\.{OCTET}){3}
IPV6ADDR		({HEX16}?:){2,7}{HEX16}?|({HEX16}?:){2,6}:{IPV4ADDR}

HOSTNAME		[[:alnum:]_-]+
WORD			([^#>!=:,\(\) \t\r\n\\\"]|\\[^\t\n])+
ID			#-?[0-9]+
PATH			\/(\\[\,:= \t#]|[^\,:=\\ \t\r\n#])+
ENVAR			([^#!=, \t\r\n\\\"]|\\[^\r\n])([^#=, \t\r\n\\\"]|\\[^\r\n])*
DEFVAR			[a-z_]+

%option noinput
%option nounput
%option noyywrap
%option prefix="sudoers"

%s	GOTDEFS
%x	GOTCMND
%x	STARTDEFS
%x	INDEFS
%x	INSTR
%s	WANTDIGEST
%x	GOTINC
%s	EXPECTPATH

%%
<GOTDEFS>[[:blank:]]*,[[:blank:]]* {
			    LEXTRACE(", ");
			    return ',';
			}			/* return ',' */

<GOTDEFS>[[:blank:]]+	BEGIN STARTDEFS;

<STARTDEFS>{DEFVAR}	{
			    BEGIN INDEFS;
			    LEXTRACE("DEFVAR ");
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    return DEFVAR;
			}

<INDEFS>{
    ,			{
			    BEGIN STARTDEFS;
			    LEXTRACE(", ");
			    return ',';
			}			/* return ',' */

    =			{
			    LEXTRACE("= ");
			    return '=';
			}			/* return '=' */

    \+=			{
			    LEXTRACE("+= ");
			    return '+';
			}			/* return '+' */

    -=			{
			    LEXTRACE("-= ");
			    return '-';
			}			/* return '-' */

    \"			{
			    LEXTRACE("BEGINSTR ");
			    sudoerslval.string = NULL;
			    prev_state = YY_START;
			    BEGIN INSTR;
			}

    {ENVAR}		{
			    LEXTRACE("WORD(2) ");
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    return WORD;
			}
}

<INSTR>{
    \\[[:blank:]]*\r?\n[[:blank:]]*	{
			    /* Line continuation char followed by newline. */
			    sudolineno++;
			    continued = true;
			}

    \"			{
			    LEXTRACE("ENDSTR ");
			    BEGIN prev_state;

			    if (sudoerslval.string == NULL) {
				sudoerserror(N_("empty string"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }
			    if (prev_state == INITIAL || prev_state == GOTDEFS) {
				switch (sudoerslval.string[0]) {
				case '%':
				    if (sudoerslval.string[1] == '\0' ||
					(sudoerslval.string[1] == ':' &&
					sudoerslval.string[2] == '\0')) {
					sudoerserror(N_("empty group"));
					LEXTRACE("ERROR ");
					return ERROR;
				    }
				    LEXTRACE("USERGROUP ");
				    return USERGROUP;
				case '+':
				    if (sudoerslval.string[1] == '\0') {
					sudoerserror(N_("empty netgroup"));
					LEXTRACE("ERROR ");
					return ERROR;
				    }
				    LEXTRACE("NETGROUP ");
				    return NETGROUP;
				}
			    }
			    LEXTRACE("WORD(4) ");
			    return WORD;
			}

    \\			{
			    LEXTRACE("BACKSLASH ");
			    if (!append(sudoerstext, sudoersleng))
				yyterminate();
			}

    ([^\"\r\n\\]|\\\")+	{
			    LEXTRACE("STRBODY ");
			    if (!append(sudoerstext, sudoersleng))
				yyterminate();
			}
}

<GOTCMND>{
    \\[\*\?\[\]\!]	{
			    /* quoted fnmatch glob char, pass verbatim */
			    LEXTRACE("QUOTEDCHAR ");
			    if (!fill_args(sudoerstext, 2, sawspace))
				yyterminate();
			    sawspace = false;
			}

    \\[:\\,= \t#]	{
			    /* quoted sudoers special char, strip backslash */
			    LEXTRACE("QUOTEDCHAR ");
			    if (!fill_args(sudoerstext + 1, 1, sawspace))
				yyterminate();
			    sawspace = false;
			}

    [#:\,=\r\n]		{
			    BEGIN INITIAL;
			    sudoersless(0);
			    yy_set_bol(0);
			    return COMMAND;
			}			/* end of command line args */

    [^#\\:, \t\r\n]+ 	{
			    LEXTRACE("ARG ");
			    if (!fill_args(sudoerstext, sudoersleng, sawspace))
				yyterminate();
			    sawspace = false;
			}			/* a command line arg */
}

<WANTDIGEST>[[:xdigit:]]+ {
			    /* Only return DIGEST if the length is correct. */
			    yy_size_t digest_len =
				sudo_digest_getlen(digest_type);
			    if ((yy_size_t)sudoersleng == digest_len * 2) {
				if (!fill(sudoerstext, sudoersleng))
				    yyterminate();
				BEGIN INITIAL;
				LEXTRACE("DIGEST ");
				return DIGEST;
			    }
			    BEGIN INITIAL;
			    sudoersless(sudoersleng);
			} /* hex digest */

<WANTDIGEST>[A-Za-z0-9\+/=]+ {
			    /* Only return DIGEST if the length is correct. */
			    yy_size_t len, digest_len =
				sudo_digest_getlen(digest_type);
			    if (sudoerstext[sudoersleng - 1] == '=') {
				/* use padding */
				len = 4 * ((digest_len + 2) / 3);
			    } else {
				/* no padding */
				len = (4 * digest_len + 2) / 3;
			    }
			    if ((yy_size_t)sudoersleng == len) {
				if (!fill(sudoerstext, sudoersleng))
				    yyterminate();
				BEGIN INITIAL;
				LEXTRACE("DIGEST ");
				return DIGEST;
			    }
			    BEGIN INITIAL;
			    sudoersless(sudoersleng);
			} /* base64 digest */

<INITIAL>@include	{
			    if (continued) {
				sudoerserror(N_("invalid line continuation"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }

			    BEGIN GOTINC;
			    LEXTRACE("INCLUDE ");
			    return INCLUDE;
			}

<INITIAL>@includedir	{
			    if (continued) {
				sudoerserror(N_("invalid line continuation"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }

			    BEGIN GOTINC;
			    LEXTRACE("INCLUDEDIR ");
			    return INCLUDEDIR;
			}

<INITIAL>^#include[[:blank:]]+.*(\r\n|\n)? {
			    if (continued) {
				sudoerserror(N_("invalid line continuation"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }

			    /* only consume #include */
			    sudoersless(sizeof("#include") - 1);
			    yy_set_bol(0);

			    BEGIN GOTINC;
			    LEXTRACE("INCLUDE ");
			    return INCLUDE;
			}

<INITIAL>^#includedir[[:blank:]]+.*(\r\n|\n)? {
			    if (continued) {
				sudoerserror(N_("invalid line continuation"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }

			    /* only consume #includedir */
			    sudoersless(sizeof("#includedir") - 1);
			    yy_set_bol(0);

			    BEGIN GOTINC;
			    LEXTRACE("INCLUDEDIR ");
			    return INCLUDEDIR;
			}

<INITIAL>^[[:blank:]]*Defaults([:@>\!][[:blank:]]*\!*\"?({ID}|{WORD}))? {
			    char deftype;
			    int n;

			    if (continued) {
				sudoerserror(N_("invalid line continuation"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }

			    for (n = 0; isblank((unsigned char)sudoerstext[n]); n++)
				continue;
			    n += sizeof("Defaults") - 1;
			    if ((deftype = sudoerstext[n++]) != '\0') {
				while (isblank((unsigned char)sudoerstext[n]))
				    n++;
			    }
			    BEGIN GOTDEFS;
			    switch (deftype) {
				case ':':
				    sudoersless(n);
				    LEXTRACE("DEFAULTS_USER ");
				    return DEFAULTS_USER;
				case '>':
				    sudoersless(n);
				    LEXTRACE("DEFAULTS_RUNAS ");
				    return DEFAULTS_RUNAS;
				case '@':
				    sudoersless(n);
				    LEXTRACE("DEFAULTS_HOST ");
				    return DEFAULTS_HOST;
				case '!':
				    sudoersless(n);
				    LEXTRACE("DEFAULTS_CMND ");
				    return DEFAULTS_CMND;
				default:
				    LEXTRACE("DEFAULTS ");
				    return DEFAULTS;
			    }
			}

<INITIAL>^[[:blank:]]*(Host|Cmnd|Cmd|User|Runas)_Alias	{
			    int n;

			    if (continued) {
				sudoerserror(N_("invalid line continuation"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }

			    for (n = 0; isblank((unsigned char)sudoerstext[n]); n++)
				continue;
			    switch (sudoerstext[n]) {
				case 'H':
				    LEXTRACE("HOSTALIAS ");
				    return HOSTALIAS;
				case 'C':
				    LEXTRACE("CMNDALIAS ");
				    return CMNDALIAS;
				case 'U':
				    LEXTRACE("USERALIAS ");
				    return USERALIAS;
				case 'R':
				    LEXTRACE("RUNASALIAS ");
				    return RUNASALIAS;
			    }
			}

NOPASSWD[[:blank:]]*:	{
				/* cmnd does not require passwd for this user */
			    	LEXTRACE("NOPASSWD ");
			    	return NOPASSWD;
			}

PASSWD[[:blank:]]*:	{
				/* cmnd requires passwd for this user */
			    	LEXTRACE("PASSWD ");
			    	return PASSWD;
			}

NOEXEC[[:blank:]]*:	{
			    	LEXTRACE("NOEXEC ");
			    	return NOEXEC;
			}

EXEC[[:blank:]]*:	{
			    	LEXTRACE("EXEC ");
			    	return EXEC;
			}

SETENV[[:blank:]]*:	{
			    	LEXTRACE("SETENV ");
			    	return SETENV;
			}

NOSETENV[[:blank:]]*:	{
			    	LEXTRACE("NOSETENV ");
			    	return NOSETENV;
			}

LOG_OUTPUT[[:blank:]]*:	{
			    	LEXTRACE("LOG_OUTPUT ");
			    	return LOG_OUTPUT;
			}

NOLOG_OUTPUT[[:blank:]]*:	{
			    	LEXTRACE("NOLOG_OUTPUT ");
			    	return NOLOG_OUTPUT;
			}

LOG_INPUT[[:blank:]]*:	{
			    	LEXTRACE("LOG_INPUT ");
			    	return LOG_INPUT;
			}

NOLOG_INPUT[[:blank:]]*:	{
			    	LEXTRACE("NOLOG_INPUT ");
			    	return NOLOG_INPUT;
			}

MAIL[[:blank:]]*:	{
			    	LEXTRACE("MAIL ");
			    	return MAIL;
			}

NOMAIL[[:blank:]]*:	{
			    	LEXTRACE("NOMAIL ");
			    	return NOMAIL;
			}

FOLLOW[[:blank:]]*:	{
			    	LEXTRACE("FOLLOW ");
			    	return FOLLOWLNK;
			}

NOFOLLOW[[:blank:]]*:	{
			    	LEXTRACE("NOFOLLOW ");
			    	return NOFOLLOWLNK;
			}

<INITIAL,GOTDEFS>(\+|\%|\%:) {
			    if (sudoerstext[0] == '+')
				sudoerserror(N_("empty netgroup"));
			    else
				sudoerserror(N_("empty group"));
			    LEXTRACE("ERROR ");
			    return ERROR;
			}

\+{WORD}		{
			    /* netgroup */
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NETGROUP ");
			    return NETGROUP;
			}

\%:?({WORD}|{ID})	{
			    /* group */
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("USERGROUP ");
			    return USERGROUP;
			}

{IPV4ADDR}(\/{IPV4ADDR})? {
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    return NTWKADDR;
			}

{IPV4ADDR}\/([12]?[0-9]|3[0-2]) {
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    return NTWKADDR;
			}

{IPV6ADDR}(\/{IPV6ADDR})? {
			    if (!ipv6_valid(sudoerstext)) {
				sudoerserror(N_("invalid IPv6 address"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    return NTWKADDR;
			}

{IPV6ADDR}\/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]) {
			    if (!ipv6_valid(sudoerstext)) {
				sudoerserror(N_("invalid IPv6 address"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    return NTWKADDR;
			}

ALL {
			    LEXTRACE("ALL ");
			    return ALL;

			}

<INITIAL>TIMEOUT {
			    LEXTRACE("CMND_TIMEOUT ");
			    return CMND_TIMEOUT;
			}

<INITIAL>NOTBEFORE {
			    LEXTRACE("NOTBEFORE ");
			    return NOTBEFORE;
			}

<INITIAL>NOTAFTER {
			    LEXTRACE("NOTAFTER ");
			    return NOTAFTER;
			}

<INITIAL>CWD {
			    LEXTRACE("CWD ");
			    prev_state = YY_START;
			    BEGIN EXPECTPATH;
			    return CWD;
			}

<INITIAL>CHROOT {
			    LEXTRACE("CHROOT ");
			    prev_state = YY_START;
			    BEGIN EXPECTPATH;
			    return CHROOT;
			}

<INITIAL>ROLE {
#ifdef HAVE_SELINUX
			    LEXTRACE("ROLE ");
			    return ROLE;
#else
			    goto got_alias;
#endif
			}

<INITIAL>TYPE {
#ifdef HAVE_SELINUX
			    LEXTRACE("TYPE ");
			    return TYPE;
#else
			    goto got_alias;
#endif
			}
<INITIAL>PRIVS {
#ifdef HAVE_PRIV_SET
			    LEXTRACE("PRIVS ");
			    return PRIVS;
#else
			    goto got_alias;
#endif
			}

<INITIAL>LIMITPRIVS {
#ifdef HAVE_PRIV_SET
			    LEXTRACE("LIMITPRIVS ");
			    return LIMITPRIVS;
#else
			    goto got_alias;
#endif
			}

[[:upper:]][[:upper:][:digit:]_]* {
			got_alias:
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("ALIAS ");
			    return ALIAS;
			}

<GOTDEFS>({PATH}|sudoedit) {
			    /* XXX - no way to specify digest for command */
			    /* no command args allowed for Defaults!/path */
			    if (!fill_cmnd(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("COMMAND ");
			    return COMMAND;
			}

sha224			{
			    digest_type = SUDO_DIGEST_SHA224;
			    BEGIN WANTDIGEST;
			    LEXTRACE("SHA224_TOK ");
			    return SHA224_TOK;
			}

sha256			{
			    digest_type = SUDO_DIGEST_SHA256;
			    BEGIN WANTDIGEST;
			    LEXTRACE("SHA256_TOK ");
			    return SHA256_TOK;
			}

sha384			{
			    digest_type = SUDO_DIGEST_SHA384;
			    BEGIN WANTDIGEST;
			    LEXTRACE("SHA384_TOK ");
			    return SHA384_TOK;
			}

sha512			{
			    digest_type = SUDO_DIGEST_SHA512;
			    BEGIN WANTDIGEST;
			    LEXTRACE("SHA512_TOK ");
			    return SHA512_TOK;
			}

sudoedit		{
			    BEGIN GOTCMND;
			    LEXTRACE("COMMAND ");
			    if (!fill_cmnd(sudoerstext, sudoersleng))
				yyterminate();
			}			/* sudo -e */

<EXPECTPATH>({PATH}|{WORD}) {
				BEGIN prev_state;
				if (!fill(sudoerstext, sudoersleng))
				    yyterminate();
				LEXTRACE("WORD(5) ");
				return WORD;
			}

{PATH}			{
			    /* directories can't have args... */
			    if (sudoerstext[sudoersleng - 1] == '/') {
				LEXTRACE("COMMAND ");
				if (!fill_cmnd(sudoerstext, sudoersleng))
				    yyterminate();
				return COMMAND;
			    }
			    BEGIN GOTCMND;
			    LEXTRACE("COMMAND ");
			    if (!fill_cmnd(sudoerstext, sudoersleng))
				yyterminate();
			}			/* a pathname */

<INITIAL,GOTDEFS>\"	{
			    LEXTRACE("BEGINSTR ");
			    sudoerslval.string = NULL;
			    prev_state = YY_START;
			    BEGIN INSTR;
			}

<INITIAL,GOTDEFS>({ID}|{WORD}) {
			    /* a word */
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("WORD(6) ");
			    return WORD;
			}

<GOTINC>{
    [^\"[:space:]]([^[:space:]]|\\[[:blank:]])*	{
			    /* include file/directory */
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    BEGIN INITIAL;
			    LEXTRACE("WORD(7) ");
			    return WORD;
			}

    \"			{
			    LEXTRACE("BEGINSTR ");
			    sudoerslval.string = NULL;
			    prev_state = INITIAL;
			    BEGIN INSTR;
			}
}

\(			{
			    LEXTRACE("( ");
			    return '(';
			}

\)			{
			    LEXTRACE(") ");
			    return ')';
			}

,			{
			    LEXTRACE(", ");
			    return ',';
			}			/* return ',' */

=			{
			    LEXTRACE("= ");
			    return '=';
			}			/* return '=' */

:			{
			    LEXTRACE(": ");
			    return ':';
			}			/* return ':' */

<*>!+			{
			    if (sudoersleng & 1) {
				LEXTRACE("!");
				return '!';	/* return '!' */
			    }
			}

<*>\r?\n		{
			    if (YY_START == INSTR) {
				/* re-scan after changing state */
				BEGIN INITIAL;
				sudoersless(0);
				sudoerserror(N_("unexpected line break in string"));
				LEXTRACE("ERROR ");
				return ERROR;
			    }
			    BEGIN INITIAL;
			    sudolineno++;
			    continued = false;
			    LEXTRACE("\n");
			    return '\n';
			}			/* return newline */

<*>[[:blank:]]+		{			/* throw away space/tabs */
			    sawspace = true;	/* but remember for fill_args */
			}

<*>\\[[:blank:]]*\r?\n	{
			    sawspace = true;	/* remember for fill_args */
			    sudolineno++;
			    continued = true;
			}			/* throw away EOL after \ */

<INITIAL,STARTDEFS,INDEFS>#(-[^\r\n0-9].*|[^\r\n0-9-].*)?(\r\n|\n)?	{
			    if (sudoerstext[sudoersleng - 1] == '\n') {
				/* comment ending in a newline */
				BEGIN INITIAL;
				sudolineno++;
				continued = false;
			    } else if (!feof(sudoersin)) {
				sudoerserror(strerror(errno));
				LEXTRACE("ERROR ");
				return ERROR;
			    }
			    LEXTRACE("#\n");
			    return '\n';
			}			/* comment, not uid/gid */

<*>.			{
			    LEXTRACE("NOMATCH ");
			    return NOMATCH;
			}	/* parse error, no matching token */

<*><<EOF>>		{
			    if (!pop_include())
				yyterminate();
			}

%%
struct path_list {
    SLIST_ENTRY(path_list) entries;
    char *path;
};

SLIST_HEAD(path_list_head, path_list);

struct include_stack {
    struct sudolinebuf line;
    YY_BUFFER_STATE bs;
    char *path;
    struct path_list_head more; /* more files in case of includedir */
    int lineno;
    bool keepopen;
};

/*
 * Compare two struct path_list structs in reverse order.
 */
static int
pl_compare(const void *v1, const void *v2)
{
    const struct path_list * const *p1 = v1;
    const struct path_list * const *p2 = v2;

    return strcmp((*p2)->path, (*p1)->path);
}

/*
 * Open dirpath and fill in pathsp with an array of regular files
 * that do not end in '~' or contain a '.'.
 * Returns the number of files or -1 on error.
 * If zero files are found, NULL is stored in pathsp.
 */
static int
read_dir_files(const char *dirpath, struct path_list ***pathsp)
{
    DIR *dir;
    int i, count = 0;
    int max_paths = 32;
    struct dirent *dent;
    struct path_list **paths = NULL;
    debug_decl(read_dir_files, SUDOERS_DEBUG_PARSER);

    dir = opendir(dirpath);
    if (dir == NULL) {
	if (errno == ENOENT)
	    goto done;
	sudo_warn("%s", dirpath);
	goto bad;
    }
    paths = reallocarray(NULL, max_paths, sizeof(*paths));
    if (paths == NULL)
	goto oom;
    while ((dent = readdir(dir)) != NULL) {
	struct path_list *pl;
	struct stat sb;
	size_t len;
	char *path;

	/* Ignore files that end in '~' or have a '.' in them. */
	if (dent->d_name[0] == '\0' || dent->d_name[NAMLEN(dent) - 1] == '~'
	    || strchr(dent->d_name, '.') != NULL) {
	    continue;
	}
	len = strlen(dirpath) + 1 + NAMLEN(dent);
	if ((path = rcstr_alloc(len)) == NULL)
	    goto oom;
	(void)snprintf(path, len + 1, "%s/%s", dirpath, dent->d_name);
	if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) {
	    rcstr_delref(path);
	    continue;
	}
	pl = malloc(sizeof(*pl));
	if (pl == NULL) {
	    rcstr_delref(path);
	    goto oom;
	}
	pl->path = path;
	if (count >= max_paths) {
	    struct path_list **tmp;
	    max_paths <<= 1;
	    tmp = reallocarray(paths, max_paths, sizeof(*paths));
	    if (tmp == NULL) {
		rcstr_delref(path);
		free(pl);
		goto oom;
	    }
	    paths = tmp;
	}
	paths[count++] = pl;
    }
    closedir(dir);
    if (count == 0) {
	free(paths);
	paths = NULL;
    }
done:
    *pathsp = paths;
    debug_return_int(count);
oom:
    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
bad:
    sudoerserror(NULL);
    if (dir != NULL)
	closedir(dir);
    for (i = 0; i < count; i++) {
	rcstr_delref(paths[i]->path);
	free(paths[i]);
    }
    free(paths);
    debug_return_int(-1);
}

/*
 * Push a list of all files in dirpath onto stack.
 * Returns the number of files or -1 on error.
 */
static int
switch_dir(struct include_stack *stack, char *dirpath)
{
    struct path_list **paths = NULL;
    int count, i;
    debug_decl(switch_dir, SUDOERS_DEBUG_PARSER);

    count = read_dir_files(dirpath, &paths);
    if (count > 0) {
	/* Sort the list as an array in reverse order. */
	qsort(paths, count, sizeof(*paths), pl_compare);

	/* Build up the list in sorted order. */
	for (i = 0; i < count; i++) {
	    SLIST_INSERT_HEAD(&stack->more, paths[i], entries);
	}
	free(paths);
    }

    debug_return_int(count);
}

#define MAX_SUDOERS_DEPTH	128
#define SUDOERS_STACK_INCREMENT	16

static size_t istacksize, idepth;
static struct include_stack *istack;
static bool keepopen;

void
init_lexer(void)
{
    struct path_list *pl;
    debug_decl(init_lexer, SUDOERS_DEBUG_PARSER);

    while (idepth) {
	idepth--;
	while ((pl = SLIST_FIRST(&istack[idepth].more)) != NULL) {
	    SLIST_REMOVE_HEAD(&istack[idepth].more, entries);
	    rcstr_delref(pl->path);
	    free(pl);
	}
	rcstr_delref(istack[idepth].path);
	if (idepth && !istack[idepth].keepopen)
	    fclose(istack[idepth].bs->yy_input_file);
	sudoers_delete_buffer(istack[idepth].bs);
	free(istack[idepth].line.buf);
    }
    free(istack);
    istack = NULL;
    istacksize = idepth = 0;
    free(sudolinebuf.buf);
    memset(&sudolinebuf, 0, sizeof(sudolinebuf));
    sudolineno = 1;
    keepopen = false;
    sawspace = false;
    continued = false;
    digest_type = -1;
    prev_state = INITIAL;

    debug_return;
}

/*
 * Expand any embedded %h (host) escapes in the given path and makes
 * a relative path fully-qualified based on the current sudoers file.
 * Returns a reference-counted string.
 */
static char *
expand_include(const char *opath, size_t olen)
{
    const char *cp, *ep;
    char *path, *pp;
    int dirlen = 0, len;
    size_t shost_len = 0;
    bool subst = false;
    debug_decl(expand_include, SUDOERS_DEBUG_PARSER);

    /* Strip double quotes if present. */
    if (*opath == '"') {
	opath++;
	olen -= 2;
    }

    /* Relative paths are located in the same dir as the sudoers file. */
    if (*opath != '/') {
	char *dirend = strrchr(sudoers, '/');
	if (dirend != NULL)
	    dirlen = (int)(dirend - sudoers) + 1;
    }

    len = olen;
    for (cp = opath, ep = opath + olen; cp < ep; cp++) {
	if (cp[0] == '%' && cp[1] == 'h') {
	    shost_len = strlen(user_shost);
	    len += shost_len - 2;
	    subst = true;
	}
    }

    /* Make a copy of the fully-qualified path and return it. */
    path = pp = rcstr_alloc(len + dirlen);
    if (path == NULL) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	sudoerserror(NULL);
	debug_return_str(NULL);
    }
    if (dirlen) {
	memcpy(path, sudoers, dirlen);
	pp += dirlen;
    }
    if (subst) {
	/* substitute for %h */
	cp = opath;
	while (cp < ep) {
	    if (cp[0] == '%' && cp[1] == 'h') {
		memcpy(pp, user_shost, shost_len);
		pp += shost_len;
		cp += 2;
		continue;
	    }
	    *pp++ = *cp++;
	}
	*pp = '\0';
    } else {
	memcpy(pp, opath, len);
	pp[len] = '\0';
    }

    debug_return_str(path);
}

/*
 * Open an include file (or file from a directory), push the old
 * sudoers file buffer and switch to the new one.
 * A missing or insecure include dir is simply ignored.
 * Returns false on error, else true.
 */
bool
push_include(const char *opath, bool isdir)
{
    struct path_list *pl;
    char *path;
    FILE *fp;
    debug_decl(push_include, SUDOERS_DEBUG_PARSER);

    if ((path = expand_include(opath, strlen(opath))) == NULL)
	debug_return_bool(false);

    /* push current state onto stack */
    if (idepth >= istacksize) {
	struct include_stack *new_istack;

	if (idepth > MAX_SUDOERS_DEPTH) {
	    sudoerserror(N_("too many levels of includes"));
	    rcstr_delref(path);
	    debug_return_bool(false);
	}
	istacksize += SUDOERS_STACK_INCREMENT;
	new_istack = reallocarray(istack, istacksize, sizeof(*istack));
	if (new_istack == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    sudoerserror(NULL);
	    rcstr_delref(path);
	    debug_return_bool(false);
	}
	istack = new_istack;
    }
    SLIST_INIT(&istack[idepth].more);
    if (isdir) {
	struct stat sb;
	int count, status;

	status = sudo_secure_dir(path, sudoers_uid, sudoers_gid, &sb);
	if (status != SUDO_PATH_SECURE) {
	    if (sudoers_warnings) {
		switch (status) {
		case SUDO_PATH_BAD_TYPE:
		    errno = ENOTDIR;
		    sudo_warn("%s", path);
		    break;
		case SUDO_PATH_WRONG_OWNER:
		    sudo_warnx(U_("%s is owned by uid %u, should be %u"),   
			path, (unsigned int) sb.st_uid,
			(unsigned int) sudoers_uid);
		    break;
		case SUDO_PATH_WORLD_WRITABLE:
		    sudo_warnx(U_("%s is world writable"), path);
		    break;
		case SUDO_PATH_GROUP_WRITABLE:
		    sudo_warnx(U_("%s is owned by gid %u, should be %u"),
			path, (unsigned int) sb.st_gid,
			(unsigned int) sudoers_gid);
		    break;
		default:
		    break;
		}
	    }
	    /* A missing or insecure include dir is not a fatal error. */
	    rcstr_delref(path);
	    debug_return_bool(true);
	}
	count = switch_dir(&istack[idepth], path);
	if (count <= 0) {
	    /* switch_dir() called sudoerserror() for us */
	    rcstr_delref(path);
	    debug_return_bool(count ? false : true);
	}

	/* Parse the first dir entry we can open, leave the rest for later. */
	do {
	    rcstr_delref(path);
	    if ((pl = SLIST_FIRST(&istack[idepth].more)) == NULL) {
		/* Unable to open any files in include dir, not an error. */
		debug_return_bool(true);
	    }
	    SLIST_REMOVE_HEAD(&istack[idepth].more, entries);
	    path = pl->path;
	    free(pl);
	} while ((fp = open_sudoers(path, false, &keepopen)) == NULL);
    } else {
	if ((fp = open_sudoers(path, true, &keepopen)) == NULL) {
	    /* The error was already printed by open_sudoers() */
	    sudoerserror(NULL);
	    rcstr_delref(path);
	    debug_return_bool(false);
	}
    }
    /* Push the old (current) file and open the new one. */
    istack[idepth].path = sudoers; /* push old path (and its ref) */
    istack[idepth].line = sudolinebuf;
    istack[idepth].bs = YY_CURRENT_BUFFER;
    istack[idepth].lineno = sudolineno;
    istack[idepth].keepopen = keepopen;
    idepth++;
    sudolineno = 1;
    sudoers = path;
    sudoers_switch_to_buffer(sudoers_create_buffer(fp, YY_BUF_SIZE));
    memset(&sudolinebuf, 0, sizeof(sudolinebuf));

    debug_return_bool(true);
}

/*
 * Restore the previous sudoers file and buffer, or, in the case
 * of an includedir, switch to the next file in the dir.
 * Returns false if there is nothing to pop, else true.
 */
static bool
pop_include(void)
{
    struct path_list *pl;
    FILE *fp;
    debug_decl(pop_include, SUDOERS_DEBUG_PARSER);

    if (idepth == 0 || YY_CURRENT_BUFFER == NULL)
	debug_return_bool(false);

    if (!keepopen)
	fclose(YY_CURRENT_BUFFER->yy_input_file);
    sudoers_delete_buffer(YY_CURRENT_BUFFER);
    /* If we are in an include dir, move to the next file. */
    while ((pl = SLIST_FIRST(&istack[idepth - 1].more)) != NULL) {
	SLIST_REMOVE_HEAD(&istack[idepth - 1].more, entries);
	fp = open_sudoers(pl->path, false, &keepopen);
	if (fp != NULL) {
	    sudolinebuf.len = sudolinebuf.off = 0;
	    sudolinebuf.toke_start = sudolinebuf.toke_end = 0;
	    rcstr_delref(sudoers);
	    sudoers = pl->path;
	    sudolineno = 1;
	    sudoers_switch_to_buffer(sudoers_create_buffer(fp, YY_BUF_SIZE));
	    free(pl);
	    break;
	}
	/* Unable to open path in include dir, go to next one. */
	rcstr_delref(pl->path);
	free(pl);
    }
    /* If no path list, just pop the last dir on the stack. */
    if (pl == NULL) {
	idepth--;
	sudoers_switch_to_buffer(istack[idepth].bs);
	free(sudolinebuf.buf);
	sudolinebuf = istack[idepth].line;
	rcstr_delref(sudoers);
	sudoers = istack[idepth].path;
	sudolineno = istack[idepth].lineno;
	keepopen = istack[idepth].keepopen;
    }
    debug_return_bool(true);
}

#ifdef TRACELEXER
int
sudoers_trace_print(const char *msg)
{
    return fputs(msg, stderr);
}
#else
int
sudoers_trace_print(const char *msg)
{
    static bool initialized;
    static struct sudo_lbuf lbuf;

    if (!initialized) {
	initialized = true;
	sudo_lbuf_init(&lbuf, NULL, 0, NULL, 0);
    }

    sudo_lbuf_append(&lbuf, "%s", msg);
    /* XXX - assumes a final newline */
    if (strchr(msg, '\n') != NULL)
    {
	sudo_debug_printf2(NULL, NULL, 0, SUDOERS_DEBUG_PARSER|SUDO_DEBUG_DEBUG,
	    "%s:%d: %s", sudoers, sudolineno, lbuf.buf);
	lbuf.len = 0;
    }
    return 0;
}
#endif /* TRACELEXER */

static yy_size_t
sudoers_input(char *buf, yy_size_t max_size)
{
    size_t avail = sudolinebuf.len - sudolinebuf.off;

    /* Refill line buffer if needed. */
    if (avail == 0) {
	avail = getdelim(&sudolinebuf.buf, &sudolinebuf.size, '\n', sudoersin);
	if (avail == (size_t)-1) {
	    /* EOF or error. */
	    if (ferror(sudoersin) && errno != EINTR)
		YY_FATAL_ERROR("input in flex scanner failed");
	    return 0;
	}

	/* Add trailing newline if it is missing. */
	if (sudolinebuf.buf[avail - 1] != '\n') {
	    if (avail == sudolinebuf.size) {
		char *cp = realloc(sudolinebuf.buf, avail + 1);
		if (cp == NULL) {
		    YY_FATAL_ERROR("unable to allocate memory");
		    return 0;
		}
		sudolinebuf.buf = cp;
		sudolinebuf.size++;
	    }
	    sudolinebuf.buf[avail++] = '\n';
	}

	sudolinebuf.len = avail;
	sudolinebuf.off = 0;
	sudolinebuf.toke_start = sudolinebuf.toke_end = 0;
    }

    if (avail > max_size)
	avail = max_size;
    memcpy(buf, sudolinebuf.buf + sudolinebuf.off, avail);
    sudolinebuf.off += avail;

    return avail;
}
