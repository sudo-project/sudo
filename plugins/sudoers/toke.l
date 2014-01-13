%{
/*
 * Copyright (c) 1996, 1998-2005, 2007-2013
 *	Todd C. Miller <Todd.Miller@courtesan.com>
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
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
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
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
# include <malloc.h>
#endif /* HAVE_MALLOC_H && !STDC_HEADERS */
#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
#include <errno.h>
#include <ctype.h>
#include "sudoers.h"
#include "parse.h"
#include "toke.h"
#include <gram.h>
#include "lbuf.h"
#include "sha2.h"
#include "secure_path.h"

int sudolineno;			/* current sudoers line number. */
int last_token;			/* last token that was parsed. */
char *sudoers;			/* sudoers file being parsed. */

/* Default sudoers path, mode and owner (may be set via sudo.conf) */
const char *sudoers_file = _PATH_SUDOERS;
mode_t sudoers_mode = SUDOERS_MODE;
uid_t sudoers_uid = SUDOERS_UID;
gid_t sudoers_gid = SUDOERS_GID;

static bool continued, sawspace;
static int prev_state;
static int digest_len;

static bool _push_include(char *, bool);
static bool pop_include(void);
static char *parse_include(char *);

int (*trace_print)(const char *msg) = sudoers_trace_print;

#define LEXRETURN(n)	do {	\
	last_token = (n);	\
	return (n);		\
} while (0)

#define ECHO	ignore_result(fwrite(sudoerstext, sudoersleng, 1, sudoersout))

#define	push_include(_p)	(_push_include((_p), false))
#define	push_includedir(_p)	(_push_include((_p), true))
%}

HEX16			[0-9A-Fa-f]{1,4}
OCTET			(1?[0-9]{1,2})|(2[0-4][0-9])|(25[0-5])
IPV4ADDR		{OCTET}(\.{OCTET}){3}
IPV6ADDR		({HEX16}?:){2,7}{HEX16}?|({HEX16}?:){2,6}:{IPV4ADDR}

HOSTNAME		[[:alnum:]_-]+
WORD			([^#>!=:,\(\) \t\n\\\"]|\\[^\n])+
ID			#-?[0-9]+
PATH			\/(\\[\,:= \t#]|[^\,:=\\ \t\n#])+
ENVAR			([^#!=, \t\n\\\"]|\\[^\n])([^#=, \t\n\\\"]|\\[^\n])*
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

%%
<GOTDEFS>[[:blank:]]*,[[:blank:]]* {
			    LEXTRACE(", ");
			    LEXRETURN(',');
			}			/* return ',' */

<GOTDEFS>[[:blank:]]+	BEGIN STARTDEFS;

<STARTDEFS>{DEFVAR}	{
			    BEGIN INDEFS;
			    LEXTRACE("DEFVAR ");
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXRETURN(DEFVAR);
			}

<INDEFS>{
    ,			{
			    BEGIN STARTDEFS;
			    LEXTRACE(", ");
			    LEXRETURN(',');
			}			/* return ',' */

    =			{
			    LEXTRACE("= ");
			    LEXRETURN('=');
			}			/* return '=' */

    \+=			{
			    LEXTRACE("+= ");
			    LEXRETURN('+');
			}			/* return '+' */

    -=			{
			    LEXTRACE("-= ");
			    LEXRETURN('-');
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
			    LEXRETURN(WORD);
			}
}

<INSTR>{
    \\[[:blank:]]*\n[[:blank:]]*	{
			    /* Line continuation char followed by newline. */
			    sudolineno++;
			    continued = true;
			}

    \"			{
			    LEXTRACE("ENDSTR ");
			    BEGIN prev_state;

			    if (sudoerslval.string == NULL) {
				LEXTRACE("ERROR "); /* empty string */
				LEXRETURN(ERROR);
			    }
			    if (prev_state == INITIAL) {
				switch (sudoerslval.string[0]) {
				case '%':
				    if (sudoerslval.string[1] == '\0' ||
					(sudoerslval.string[1] == ':' &&
					sudoerslval.string[2] == '\0')) {
					LEXTRACE("ERROR "); /* empty group */
					LEXRETURN(ERROR);
				    }
				    LEXTRACE("USERGROUP ");
				    LEXRETURN(USERGROUP);
				case '+':
				    if (sudoerslval.string[1] == '\0') {
					LEXTRACE("ERROR "); /* empty netgroup */
					LEXRETURN(ERROR);
				    }
				    LEXTRACE("NETGROUP ");
				    LEXRETURN(NETGROUP);
				}
			    }
			    LEXTRACE("WORD(4) ");
			    LEXRETURN(WORD);
			}

    \\			{
			    LEXTRACE("BACKSLASH ");
			    if (!append(sudoerstext, sudoersleng))
				yyterminate();
			}

    ([^\"\n\\]|\\\")+	{
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

    [#:\,=\n]		{
			    BEGIN INITIAL;
			    yyless(0);
			    LEXRETURN(COMMAND);
			}			/* end of command line args */

    [^#\\:, \t\n]+ 	{
			    LEXTRACE("ARG ");
			    if (!fill_args(sudoerstext, sudoersleng, sawspace))
				yyterminate();
			    sawspace = false;
			}			/* a command line arg */
}

<WANTDIGEST>[[:xdigit:]]+ {
			    /* Only return DIGEST if the length is correct. */
			    if (sudoersleng == digest_len * 2) {
				if (!fill(sudoerstext, sudoersleng))
				    yyterminate();
				BEGIN INITIAL;
				LEXTRACE("DIGEST ");
				LEXRETURN(DIGEST);
			    }
			    BEGIN INITIAL;
			    yyless(sudoersleng);
			} /* hex digest */

<WANTDIGEST>[A-Za-z0-9\+/=]+ {
			    /* Only return DIGEST if the length is correct. */
			    int len;
			    if (sudoerstext[sudoersleng - 1] == '=') {
				/* use padding */
				len = 4 * ((digest_len + 2) / 3);
			    } else {
				/* no padding */
				len = (4 * digest_len + 2) / 3;
			    }
			    if (sudoersleng == len) {
				if (!fill(sudoerstext, sudoersleng))
				    yyterminate();
				BEGIN INITIAL;
				LEXTRACE("DIGEST ");
				LEXRETURN(DIGEST);
			    }
			    BEGIN INITIAL;
			    yyless(sudoersleng);
			} /* base64 digest */

<INITIAL>^#include[[:blank:]]+.*\n {
			    char *path;

			    if (continued) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }

			    if ((path = parse_include(sudoerstext)) == NULL)
				yyterminate();

			    LEXTRACE("INCLUDE\n");

			    /* Push current buffer and switch to include file */
			    if (!push_include(path))
				yyterminate();
			}

<INITIAL>^#includedir[[:blank:]]+.*\n {
			    char *path;

			    if (continued) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }

			    if ((path = parse_include(sudoerstext)) == NULL)
				yyterminate();

			    LEXTRACE("INCLUDEDIR\n");

			    /*
			     * Push current buffer and switch to include file.
			     * We simply ignore empty directories.
			     */
			    if (!push_includedir(path) && parse_error)
				yyterminate();
			}

<INITIAL>^[[:blank:]]*Defaults([:@>\!][[:blank:]]*\!*\"?({ID}|{WORD}))? {
			    char deftype;
			    int n;

			    if (continued) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
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
				    yyless(n);
				    LEXTRACE("DEFAULTS_USER ");
				    LEXRETURN(DEFAULTS_USER);
				case '>':
				    yyless(n);
				    LEXTRACE("DEFAULTS_RUNAS ");
				    LEXRETURN(DEFAULTS_RUNAS);
				case '@':
				    yyless(n);
				    LEXTRACE("DEFAULTS_HOST ");
				    LEXRETURN(DEFAULTS_HOST);
				case '!':
				    yyless(n);
				    LEXTRACE("DEFAULTS_CMND ");
				    LEXRETURN(DEFAULTS_CMND);
				default:
				    LEXTRACE("DEFAULTS ");
				    LEXRETURN(DEFAULTS);
			    }
			}

<INITIAL>^[[:blank:]]*(Host|Cmnd|User|Runas)_Alias	{
			    int n;

			    if (continued) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }

			    for (n = 0; isblank((unsigned char)sudoerstext[n]); n++)
				continue;
			    switch (sudoerstext[n]) {
				case 'H':
				    LEXTRACE("HOSTALIAS ");
				    LEXRETURN(HOSTALIAS);
				case 'C':
				    LEXTRACE("CMNDALIAS ");
				    LEXRETURN(CMNDALIAS);
				case 'U':
				    LEXTRACE("USERALIAS ");
				    LEXRETURN(USERALIAS);
				case 'R':
				    LEXTRACE("RUNASALIAS ");
				    LEXRETURN(RUNASALIAS);
			    }
			}

NOPASSWD[[:blank:]]*:	{
				/* cmnd does not require passwd for this user */
			    	LEXTRACE("NOPASSWD ");
			    	LEXRETURN(NOPASSWD);
			}

PASSWD[[:blank:]]*:	{
				/* cmnd requires passwd for this user */
			    	LEXTRACE("PASSWD ");
			    	LEXRETURN(PASSWD);
			}

NOEXEC[[:blank:]]*:	{
			    	LEXTRACE("NOEXEC ");
			    	LEXRETURN(NOEXEC);
			}

EXEC[[:blank:]]*:	{
			    	LEXTRACE("EXEC ");
			    	LEXRETURN(EXEC);
			}

SETENV[[:blank:]]*:	{
			    	LEXTRACE("SETENV ");
			    	LEXRETURN(SETENV);
			}

NOSETENV[[:blank:]]*:	{
			    	LEXTRACE("NOSETENV ");
			    	LEXRETURN(NOSETENV);
			}

LOG_OUTPUT[[:blank:]]*:	{
			    	LEXTRACE("LOG_OUTPUT ");
			    	LEXRETURN(LOG_OUTPUT);
			}

NOLOG_OUTPUT[[:blank:]]*:	{
			    	LEXTRACE("NOLOG_OUTPUT ");
			    	LEXRETURN(NOLOG_OUTPUT);
			}

LOG_INPUT[[:blank:]]*:	{
			    	LEXTRACE("LOG_INPUT ");
			    	LEXRETURN(LOG_INPUT);
			}

NOLOG_INPUT[[:blank:]]*:	{
			    	LEXTRACE("NOLOG_INPUT ");
			    	LEXRETURN(NOLOG_INPUT);
			}

<INITIAL,GOTDEFS>(\+|\%|\%:) {
			    /* empty group or netgroup */
			    LEXTRACE("ERROR ");
			    LEXRETURN(ERROR);
			}

\+{WORD}		{
			    /* netgroup */
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NETGROUP ");
			    LEXRETURN(NETGROUP);
			}

\%:?({WORD}|{ID})	{
			    /* group */
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("USERGROUP ");
			    LEXRETURN(USERGROUP);
			}

{IPV4ADDR}(\/{IPV4ADDR})? {
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    LEXRETURN(NTWKADDR);
			}

{IPV4ADDR}\/([12]?[0-9]|3[0-2]) {
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    LEXRETURN(NTWKADDR);
			}

{IPV6ADDR}(\/{IPV6ADDR})? {
			    if (!ipv6_valid(sudoerstext)) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    LEXRETURN(NTWKADDR);
			}

{IPV6ADDR}\/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]) {
			    if (!ipv6_valid(sudoerstext)) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("NTWKADDR ");
			    LEXRETURN(NTWKADDR);
			}

ALL {
			    LEXTRACE("ALL ");
			    LEXRETURN(ALL);

			}

<INITIAL>ROLE {
#ifdef HAVE_SELINUX
			    LEXTRACE("ROLE ");
			    LEXRETURN(ROLE);
#else
			    goto got_alias;
#endif
			}

<INITIAL>TYPE {
#ifdef HAVE_SELINUX
			    LEXTRACE("TYPE ");
			    LEXRETURN(TYPE);
#else
			    goto got_alias;
#endif
			}
<INITIAL>PRIVS {
#ifdef HAVE_PRIV_SET
			    LEXTRACE("PRIVS ");
			    LEXRETURN(PRIVS);
#else
			    goto got_alias;
#endif
			}

<INITIAL>LIMITPRIVS {
#ifdef HAVE_PRIV_SET
			    LEXTRACE("LIMITPRIVS ");
			    LEXRETURN(LIMITPRIVS);
#else
			    goto got_alias;
#endif
			}

[[:upper:]][[:upper:][:digit:]_]* {
			got_alias:
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("ALIAS ");
			    LEXRETURN(ALIAS);
			}

<GOTDEFS>({PATH}|sudoedit) {
			    /* XXX - no way to specify digest for command */
			    /* no command args allowed for Defaults!/path */
			    if (!fill_cmnd(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("COMMAND ");
			    LEXRETURN(COMMAND);
			}

sha224			{
			    digest_len = SHA224_DIGEST_LENGTH;
			    BEGIN WANTDIGEST;
			    LEXTRACE("SHA224 ");
			    LEXRETURN(SHA224);
			}

sha256			{
			    digest_len = SHA256_DIGEST_LENGTH;
			    BEGIN WANTDIGEST;
			    LEXTRACE("SHA256 ");
			    LEXRETURN(SHA256);
			}

sha384			{
			    digest_len = SHA384_DIGEST_LENGTH;
			    BEGIN WANTDIGEST;
			    LEXTRACE("SHA384 ");
			    LEXRETURN(SHA384);
			}

sha512			{
			    digest_len = SHA512_DIGEST_LENGTH;
			    BEGIN WANTDIGEST;
			    LEXTRACE("SHA512 ");
			    LEXRETURN(SHA512);
			}

sudoedit		{
			    BEGIN GOTCMND;
			    LEXTRACE("COMMAND ");
			    if (!fill_cmnd(sudoerstext, sudoersleng))
				yyterminate();
			}			/* sudo -e */

{PATH}			{
			    /* directories can't have args... */
			    if (sudoerstext[sudoersleng - 1] == '/') {
				LEXTRACE("COMMAND ");
				if (!fill_cmnd(sudoerstext, sudoersleng))
				    yyterminate();
				LEXRETURN(COMMAND);
			    } else {
				BEGIN GOTCMND;
				LEXTRACE("COMMAND ");
				if (!fill_cmnd(sudoerstext, sudoersleng))
				    yyterminate();
			    }
			}			/* a pathname */

<INITIAL,GOTDEFS>\" {
			    LEXTRACE("BEGINSTR ");
			    sudoerslval.string = NULL;
			    prev_state = YY_START;
			    BEGIN INSTR;
			}

<INITIAL,GOTDEFS>({ID}|{WORD}) {
			    /* a word */
			    if (!fill(sudoerstext, sudoersleng))
				yyterminate();
			    LEXTRACE("WORD(5) ");
			    LEXRETURN(WORD);
			}

\(			{
			    LEXTRACE("( ");
			    LEXRETURN('(');
			}

\)			{
			    LEXTRACE(") ");
			    LEXRETURN(')');
			}

,			{
			    LEXTRACE(", ");
			    LEXRETURN(',');
			}			/* return ',' */

=			{
			    LEXTRACE("= ");
			    LEXRETURN('=');
			}			/* return '=' */

:			{
			    LEXTRACE(": ");
			    LEXRETURN(':');
			}			/* return ':' */

<*>!+			{
			    if (sudoersleng & 1) {
				LEXTRACE("!");
				LEXRETURN('!');	/* return '!' */
			    }
			}

<*>\n			{
			    if (YY_START == INSTR) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);	/* line break in string */
			    }
			    BEGIN INITIAL;
			    sudolineno++;
			    continued = false;
			    LEXTRACE("\n");
			    LEXRETURN(COMMENT);
			}			/* return newline */

<*>[[:blank:]]+		{			/* throw away space/tabs */
			    sawspace = true;	/* but remember for fill_args */
			}

<*>\\[[:blank:]]*\n	{
			    sawspace = true;	/* remember for fill_args */
			    sudolineno++;
			    continued = true;
			}			/* throw away EOL after \ */

<INITIAL,STARTDEFS,INDEFS>#(-[^\n0-9].*|[^\n0-9-].*)?\n?	{
			    if (sudoerstext[sudoersleng - 1] == '\n') {
				/* comment ending in a newline */
				BEGIN INITIAL;
				sudolineno++;
				continued = false;
			    } else if (!feof(yyin)) {
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }
			    LEXTRACE("#\n");
			    LEXRETURN(COMMENT);
			}			/* comment, not uid/gid */

<*>.			{
			    LEXTRACE("ERROR ");
			    LEXRETURN(ERROR);
			}	/* parse error */

<*><<EOF>>		{
			    if (YY_START != INITIAL) {
			    	BEGIN INITIAL;
				LEXTRACE("ERROR ");
				LEXRETURN(ERROR);
			    }
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

static char *
switch_dir(struct include_stack *stack, char *dirpath)
{
    DIR *dir;
    unsigned int i, count = 0;
    unsigned int max_paths = 32;
    char *path = NULL;
    struct dirent *dent;
    struct stat sb;
    struct path_list *pl, **paths = NULL;
    debug_decl(switch_dir, SUDO_DEBUG_PARSER)

    if (!(dir = opendir(dirpath))) {
	if (errno != ENOENT) {
	    warning("%s", dirpath);
	    sudoerserror(NULL);
	}
	goto done;
    }
    paths = malloc(sizeof(*paths) * max_paths);
    if (paths == NULL) {
	closedir(dir);
	goto bad;
    }
    while ((dent = readdir(dir))) {
	/* Ignore files that end in '~' or have a '.' in them. */
	if (dent->d_name[0] == '\0' || dent->d_name[NAMLEN(dent) - 1] == '~'
	    || strchr(dent->d_name, '.') != NULL) {
	    continue;
	}
	if (asprintf(&path, "%s/%s", dirpath, dent->d_name) == -1) {
	    closedir(dir);
	    goto bad;
	}
	if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) {
	    efree(path);
	    path = NULL;
	    continue;
	}
	pl = malloc(sizeof(*pl));
	if (pl == NULL)
	    goto bad;
	pl->path = path;
	if (count >= max_paths) {
	    struct path_list **tmp;
	    max_paths <<= 1;
	    tmp = realloc(paths, sizeof(*paths) * max_paths);
	    if (tmp == NULL) {
		closedir(dir);
		goto bad;
	    }
	    paths = tmp;
	}
	paths[count++] = pl;
	path = NULL;
    }
    closedir(dir);

    if (count == 0)
	goto done;

    /* Sort the list as an array in reverse order. */
    qsort(paths, count, sizeof(*paths), pl_compare);

    /* Build up the list in sorted order. */
    for (i = 0; i < count; i++) {
	SLIST_INSERT_HEAD(&stack->more, paths[i], entries);
    }

    /* Pull out the first element for parsing, leave the rest for later. */
    pl = SLIST_FIRST(&stack->more);
    SLIST_REMOVE_HEAD(&stack->more, entries);
    path = pl->path;
    efree(pl);
done:
    efree(paths);
    efree(dirpath);
    debug_return_str(path);
bad:
    for (i = 0; i < count; i++) {
	efree(paths[i]->path);
	efree(paths[i]);
    }
    efree(paths);
    efree(dirpath);
    efree(path);
    debug_return_str(NULL);
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
    debug_decl(init_lexer, SUDO_DEBUG_PARSER)

    while (idepth) {
	idepth--;
	while ((pl = SLIST_FIRST(&istack[idepth].more)) != NULL) {
	    SLIST_REMOVE_HEAD(&istack[idepth].more, entries);
	    efree(pl->path);
	    efree(pl);
	}
	efree(istack[idepth].path);
	if (idepth && !istack[idepth].keepopen)
	    fclose(istack[idepth].bs->yy_input_file);
	sudoers_delete_buffer(istack[idepth].bs);
    }
    efree(istack);
    istack = NULL;
    istacksize = idepth = 0;
    sudolineno = 1;
    keepopen = false;
    sawspace = false;
    continued = false;
    prev_state = INITIAL;

    debug_return;
}

static bool
_push_include(char *path, bool isdir)
{
    struct path_list *pl;
    FILE *fp;
    debug_decl(_push_include, SUDO_DEBUG_PARSER)

    /* push current state onto stack */
    if (idepth >= istacksize) {
	struct include_stack *new_istack;

	if (idepth > MAX_SUDOERS_DEPTH) {
	    sudoerserror(N_("too many levels of includes"));
	    debug_return_bool(false);
	}
	istacksize += SUDOERS_STACK_INCREMENT;
	new_istack = (struct include_stack *) realloc(istack,
	    sizeof(*istack) * istacksize);
	if (new_istack == NULL) {
	    warning(NULL);
	    sudoerserror(NULL);
	    debug_return_bool(false);
	}
	istack = new_istack;
    }
    SLIST_INIT(&istack[idepth].more);
    if (isdir) {
	struct stat sb;
	switch (sudo_secure_dir(path, sudoers_uid, sudoers_gid, &sb)) {
	    case SUDO_PATH_SECURE:
		break;
	    case SUDO_PATH_MISSING:
		debug_return_bool(false);
	    case SUDO_PATH_BAD_TYPE:
		errno = ENOTDIR;
		if (sudoers_warnings) {
		    warning("%s", path);
		}
		debug_return_bool(false);
	    case SUDO_PATH_WRONG_OWNER:
		if (sudoers_warnings) {
		    warningx(U_("%s is owned by uid %u, should be %u"),   
			path, (unsigned int) sb.st_uid,
			(unsigned int) sudoers_uid);
		}
		debug_return_bool(false);
	    case SUDO_PATH_WORLD_WRITABLE:
		if (sudoers_warnings) {
		    warningx(U_("%s is world writable"), path);
		}
		debug_return_bool(false);
	    case SUDO_PATH_GROUP_WRITABLE:
		if (sudoers_warnings) {
		    warningx(U_("%s is owned by gid %u, should be %u"),
			path, (unsigned int) sb.st_gid,
			(unsigned int) sudoers_gid);
		}
		debug_return_bool(false);
	    default:
		/* NOTREACHED */
		debug_return_bool(false);
	}
	if (!(path = switch_dir(&istack[idepth], path))) {
	    /* switch_dir() called sudoerserror() for us */
	    debug_return_bool(false);
	}
	while ((fp = open_sudoers(path, false, &keepopen)) == NULL) {
	    /* Unable to open path in includedir, go to next one, if any. */
	    efree(path);
	    if ((pl = SLIST_FIRST(&istack[idepth].more)) == NULL)
		debug_return_bool(false);
	    SLIST_REMOVE_HEAD(&istack[idepth].more, entries);
	    path = pl->path;
	    efree(pl);
	}
    } else {
	if ((fp = open_sudoers(path, true, &keepopen)) == NULL) {
	    /* The error was already printed by open_sudoers() */
	    sudoerserror(NULL);
	    debug_return_bool(false);
	}
    }
    /* Push the old (current) file and open the new one. */
    istack[idepth].path = sudoers; /* push old path */
    istack[idepth].bs = YY_CURRENT_BUFFER;
    istack[idepth].lineno = sudolineno;
    istack[idepth].keepopen = keepopen;
    idepth++;
    sudolineno = 1;
    sudoers = path;
    sudoers_switch_to_buffer(sudoers_create_buffer(fp, YY_BUF_SIZE));

    debug_return_bool(true);
}

static bool
pop_include(void)
{
    struct path_list *pl;
    FILE *fp;
    debug_decl(pop_include, SUDO_DEBUG_PARSER)

    if (idepth == 0)
	debug_return_bool(false);

    if (!keepopen)
	fclose(YY_CURRENT_BUFFER->yy_input_file);
    sudoers_delete_buffer(YY_CURRENT_BUFFER);
    /* If we are in an include dir, move to the next file. */
    while ((pl = SLIST_FIRST(&istack[idepth - 1].more)) != NULL) {
	SLIST_REMOVE_HEAD(&istack[idepth - 1].more, entries);
	fp = open_sudoers(pl->path, false, &keepopen);
	if (fp != NULL) {
	    efree(sudoers);
	    sudoers = pl->path;
	    sudolineno = 1;
	    sudoers_switch_to_buffer(sudoers_create_buffer(fp, YY_BUF_SIZE));
	    efree(pl);
	    break;
	}
	/* Unable to open path in include dir, go to next one. */
	efree(pl->path);
	efree(pl);
    }
    /* If no path list, just pop the last dir on the stack. */
    if (pl == NULL) {
	idepth--;
	sudoers_switch_to_buffer(istack[idepth].bs);
	efree(sudoers);
	sudoers = istack[idepth].path;
	sudolineno = istack[idepth].lineno;
	keepopen = istack[idepth].keepopen;
    }
    debug_return_bool(true);
}

static char *
parse_include(char *base)
{
    char *cp, *ep, *path, *pp;
    int dirlen = 0, len = 0, subst = 0;
    size_t shost_len = 0;
    debug_decl(parse_include, SUDO_DEBUG_PARSER)

    /* Pull out path from #include line. */
    cp = base + sizeof("#include");
    if (*cp == 'i')
	cp += 3; /* includedir */
    while (isblank((unsigned char) *cp))
	cp++;
    ep = cp;
    while (*ep != '\0' && !isspace((unsigned char) *ep)) {
	if (ep[0] == '%' && ep[1] == 'h') {
	    shost_len = strlen(user_shost);
	    len += shost_len - 2;
	    subst = 1;
	}
	ep++;
    }

    /* Relative paths are located in the same dir as the sudoers file. */
    if (*cp != '/') {
	char *dirend = strrchr(sudoers, '/');
	if (dirend != NULL)
	    dirlen = (int)(dirend - sudoers) + 1;
    }

    /* Make a copy of the fully-qualified path and return it. */
    len += (int)(ep - cp);
    path = pp = malloc(len + dirlen + 1);
    if (path == NULL) {
	warning(NULL);
	sudoerserror(NULL);
	debug_return_str(NULL);
    }
    if (dirlen) {
	memcpy(path, sudoers, dirlen);
	pp += dirlen;
    }
    if (subst) {
	/* substitute for %h */
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
	memcpy(pp, cp, len);
	pp[len] = '\0';
    }

    /* Push any excess characters (e.g. comment, newline) back to the lexer */
    if (*ep != '\0')
	yyless((int)(ep - base));

    debug_return_str(path);
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
    static struct lbuf lbuf;

    if (!initialized) {
	initialized = true;
	lbuf_init(&lbuf, NULL, 0, NULL, 0);
    }

    lbuf_append(&lbuf, "%s", msg);
    /* XXX - assumes a final newline */
    if (strchr(msg, '\n') != NULL)
    {
	sudo_debug_printf2(NULL, NULL, 0, SUDO_DEBUG_PARSER|SUDO_DEBUG_DEBUG,
	    "%s:%d %s", sudoers, sudolineno, lbuf.buf);
	lbuf.len = 0;
    }
    return 0;
}
#endif /* TRACELEXER */
