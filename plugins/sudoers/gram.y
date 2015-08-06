%{
/*
 * Copyright (c) 1996, 1998-2005, 2007-2013, 2014-2015
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
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

#include <config.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <unistd.h>
#if defined(HAVE_STDINT_H)
# include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
# include <inttypes.h>
#endif
#if defined(YYBISON) && defined(HAVE_ALLOCA_H) && !defined(__GNUC__)
# include <alloca.h>
#endif /* YYBISON && HAVE_ALLOCA_H && !__GNUC__ */
#include <limits.h>

#include "sudoers.h" /* XXX */
#include "parse.h"
#include "toke.h"

/*
 * Globals
 */
bool sudoers_warnings = true;
bool parse_error = false;
int errorlineno = -1;
const char *errorfile = NULL;

struct defaults_list defaults = TAILQ_HEAD_INITIALIZER(defaults);
struct userspec_list userspecs = TAILQ_HEAD_INITIALIZER(userspecs);

/*
 * Local protoypes
 */
static bool add_defaults(int, struct member *, struct defaults *);
static bool add_userspec(struct member *, struct privilege *);
static struct defaults *new_default(char *, char *, int);
static struct member *new_member(char *, int);
static struct sudo_digest *new_digest(int, const char *);
%}

%union {
    struct cmndspec *cmndspec;
    struct defaults *defaults;
    struct member *member;
    struct runascontainer *runas;
    struct privilege *privilege;
    struct sudo_digest *digest;
    struct sudo_command command;
    struct cmndtag tag;
    struct selinux_info seinfo;
    struct solaris_privs_info privinfo;
    char *string;
    int tok;
}

%start file				/* special start symbol */
%token <command> COMMAND		/* absolute pathname w/ optional args */
%token <string>  ALIAS			/* an UPPERCASE alias name */
%token <string>	 DEFVAR			/* a Defaults variable name */
%token <string>  NTWKADDR		/* ipv4 or ipv6 address */
%token <string>  NETGROUP		/* a netgroup (+NAME) */
%token <string>  USERGROUP		/* a usergroup (%NAME) */
%token <string>  WORD			/* a word */
%token <string>  DIGEST			/* a SHA-2 digest */
%token <tok>	 DEFAULTS		/* Defaults entry */
%token <tok>	 DEFAULTS_HOST		/* Host-specific defaults entry */
%token <tok>	 DEFAULTS_USER		/* User-specific defaults entry */
%token <tok>	 DEFAULTS_RUNAS		/* Runas-specific defaults entry */
%token <tok>	 DEFAULTS_CMND		/* Command-specific defaults entry */
%token <tok> 	 NOPASSWD		/* no passwd req for command */
%token <tok> 	 PASSWD			/* passwd req for command (default) */
%token <tok> 	 NOEXEC			/* preload dummy execve() for cmnd */
%token <tok> 	 EXEC			/* don't preload dummy execve() */
%token <tok>	 SETENV			/* user may set environment for cmnd */
%token <tok>	 NOSETENV		/* user may not set environment */
%token <tok>	 LOG_INPUT		/* log user's cmnd input */
%token <tok>	 NOLOG_INPUT		/* don't log user's cmnd input */
%token <tok>	 LOG_OUTPUT		/* log cmnd output */
%token <tok>	 NOLOG_OUTPUT		/* don't log cmnd output */
%token <tok>	 MAIL			/* mail log message */
%token <tok>	 NOMAIL			/* don't mail log message */
%token <tok>	 FOLLOW			/* follow symbolic links */
%token <tok>	 NOFOLLOW		/* don't follow symbolic links */
%token <tok>	 ALL			/* ALL keyword */
%token <tok>	 COMMENT		/* comment and/or carriage return */
%token <tok>	 HOSTALIAS		/* Host_Alias keyword */
%token <tok>	 CMNDALIAS		/* Cmnd_Alias keyword */
%token <tok>	 USERALIAS		/* User_Alias keyword */
%token <tok>	 RUNASALIAS		/* Runas_Alias keyword */
%token <tok>	 ':' '=' ',' '!' '+' '-' /* union member tokens */
%token <tok>	 '(' ')'		/* runas tokens */
%token <tok>	 ERROR
%token <tok>	 TYPE			/* SELinux type */
%token <tok>	 ROLE			/* SELinux role */
%token <tok>	 PRIVS			/* Solaris privileges */
%token <tok>	 LIMITPRIVS		/* Solaris limit privileges */
%token <tok>	 MYSELF			/* run as myself, not another user */
%token <tok>	 SHA224_TOK		/* sha224 token */
%token <tok>	 SHA256_TOK		/* sha256 token */
%token <tok>	 SHA384_TOK		/* sha384 token */
%token <tok>	 SHA512_TOK		/* sha512 token */

%type <cmndspec>  cmndspec
%type <cmndspec>  cmndspeclist
%type <defaults>  defaults_entry
%type <defaults>  defaults_list
%type <member>	  cmnd
%type <member>	  opcmnd
%type <member>	  digcmnd
%type <member>	  cmndlist
%type <member>	  host
%type <member>	  hostlist
%type <member>	  ophost
%type <member>	  opuser
%type <member>	  user
%type <member>	  userlist
%type <member>	  opgroup
%type <member>	  group
%type <member>	  grouplist
%type <runas>	  runasspec
%type <runas>	  runaslist
%type <privilege> privilege
%type <privilege> privileges
%type <tag>	  cmndtag
%type <seinfo>	  selinux
%type <string>	  rolespec
%type <string>	  typespec
%type <privinfo>  solarisprivs
%type <string>	  privsspec
%type <string>	  limitprivsspec
%type <digest>	  digest

%%

file		:	{ ; }
		|	line
		;

line		:	entry
		|	line entry
		;

entry		:	COMMENT {
			    ;
			}
                |       error COMMENT {
			    yyerrok;
			}
		|	userlist privileges {
			    if (!add_userspec($1, $2)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	USERALIAS useraliases {
			    ;
			}
		|	HOSTALIAS hostaliases {
			    ;
			}
		|	CMNDALIAS cmndaliases {
			    ;
			}
		|	RUNASALIAS runasaliases {
			    ;
			}
		|	DEFAULTS defaults_list {
			    if (!add_defaults(DEFAULTS, NULL, $2)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	DEFAULTS_USER userlist defaults_list {
			    if (!add_defaults(DEFAULTS_USER, $2, $3)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	DEFAULTS_RUNAS userlist defaults_list {
			    if (!add_defaults(DEFAULTS_RUNAS, $2, $3)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	DEFAULTS_HOST hostlist defaults_list {
			    if (!add_defaults(DEFAULTS_HOST, $2, $3)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	DEFAULTS_CMND cmndlist defaults_list {
			    if (!add_defaults(DEFAULTS_CMND, $2, $3)) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		;

defaults_list	:	defaults_entry
		|	defaults_list ',' defaults_entry {
			    HLTQ_CONCAT($1, $3, entries);
			    $$ = $1;
			}
		;

defaults_entry	:	DEFVAR {
			    $$ = new_default($1, NULL, true);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	'!' DEFVAR {
			    $$ = new_default($2, NULL, false);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	DEFVAR '=' WORD {
			    $$ = new_default($1, $3, true);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	DEFVAR '+' WORD {
			    $$ = new_default($1, $3, '+');
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	DEFVAR '-' WORD {
			    $$ = new_default($1, $3, '-');
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		;

privileges	:	privilege
		|	privileges ':' privilege {
			    HLTQ_CONCAT($1, $3, entries);
			    $$ = $1;
			}
		;

privilege	:	hostlist '=' cmndspeclist {
			    struct privilege *p = calloc(1, sizeof(*p));
			    if (p == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    HLTQ_TO_TAILQ(&p->hostlist, $1, entries);
			    HLTQ_TO_TAILQ(&p->cmndlist, $3, entries);
			    HLTQ_INIT(p, entries);
			    $$ = p;
			}
		;

ophost		:	host {
			    $$ = $1;
			    $$->negated = false;
			}
		|	'!' host {
			    $$ = $2;
			    $$->negated = true;
			}
		;

host		:	ALIAS {
			    $$ = new_member($1, ALIAS);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	ALL {
			    $$ = new_member(NULL, ALL);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	NETGROUP {
			    $$ = new_member($1, NETGROUP);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	NTWKADDR {
			    $$ = new_member($1, NTWKADDR);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	WORD {
			    $$ = new_member($1, WORD);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		;

cmndspeclist	:	cmndspec
		|	cmndspeclist ',' cmndspec {
			    struct cmndspec *prev;
			    prev = HLTQ_LAST($1, cmndspec, entries);
			    HLTQ_CONCAT($1, $3, entries);
#ifdef HAVE_SELINUX
			    /* propagate role and type */
			    if ($3->role == NULL)
				$3->role = prev->role;
			    if ($3->type == NULL)
				$3->type = prev->type;
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
			    /* propagate privs & limitprivs */
			    if ($3->privs == NULL)
			        $3->privs = prev->privs;
			    if ($3->limitprivs == NULL)
			        $3->limitprivs = prev->limitprivs;
#endif /* HAVE_PRIV_SET */
			    /* propagate tags and runas list */
			    if ($3->tags.nopasswd == UNSPEC)
				$3->tags.nopasswd = prev->tags.nopasswd;
			    if ($3->tags.noexec == UNSPEC)
				$3->tags.noexec = prev->tags.noexec;
			    if ($3->tags.setenv == UNSPEC &&
				prev->tags.setenv != IMPLIED)
				$3->tags.setenv = prev->tags.setenv;
			    if ($3->tags.log_input == UNSPEC)
				$3->tags.log_input = prev->tags.log_input;
			    if ($3->tags.log_output == UNSPEC)
				$3->tags.log_output = prev->tags.log_output;
			    if ($3->tags.send_mail == UNSPEC)
				$3->tags.send_mail = prev->tags.send_mail;
			    if ($3->tags.follow == UNSPEC)
				$3->tags.follow = prev->tags.follow;
			    if (($3->runasuserlist == NULL &&
				 $3->runasgrouplist == NULL) &&
				(prev->runasuserlist != NULL ||
				 prev->runasgrouplist != NULL)) {
				$3->runasuserlist = prev->runasuserlist;
				$3->runasgrouplist = prev->runasgrouplist;
			    }
			    $$ = $1;
			}
		;

cmndspec	:	runasspec selinux solarisprivs cmndtag digcmnd {
			    struct cmndspec *cs = calloc(1, sizeof(*cs));
			    if (cs == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    if ($1 != NULL) {
				if ($1->runasusers != NULL) {
				    cs->runasuserlist =
					malloc(sizeof(*cs->runasuserlist));
				    if (cs->runasuserlist == NULL) {
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasuserlist,
					$1->runasusers, entries);
				}
				if ($1->runasgroups != NULL) {
				    cs->runasgrouplist =
					malloc(sizeof(*cs->runasgrouplist));
				    if (cs->runasgrouplist == NULL) {
					sudoerserror(N_("unable to allocate memory"));
					YYERROR;
				    }
				    HLTQ_TO_TAILQ(cs->runasgrouplist,
					$1->runasgroups, entries);
				}
				free($1);
			    }
#ifdef HAVE_SELINUX
			    cs->role = $2.role;
			    cs->type = $2.type;
#endif
#ifdef HAVE_PRIV_SET
			    cs->privs = $3.privs;
			    cs->limitprivs = $3.limitprivs;
#endif
			    cs->tags = $4;
			    cs->cmnd = $5;
			    HLTQ_INIT(cs, entries);
			    /* sudo "ALL" implies the SETENV tag */
			    if (cs->cmnd->type == ALL && !cs->cmnd->negated &&
				cs->tags.setenv == UNSPEC)
				cs->tags.setenv = IMPLIED;
			    $$ = cs;
			}
		;

digest		:	SHA224_TOK ':' DIGEST {
			    $$ = new_digest(SUDO_DIGEST_SHA224, $3);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	SHA256_TOK ':' DIGEST {
			    $$ = new_digest(SUDO_DIGEST_SHA256, $3);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	SHA384_TOK ':' DIGEST {
			    $$ = new_digest(SUDO_DIGEST_SHA384, $3);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	SHA512_TOK ':' DIGEST {
			    $$ = new_digest(SUDO_DIGEST_SHA512, $3);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		;

digcmnd		:	opcmnd {
			    $$ = $1;
			}
		|	digest opcmnd {
			    if ($2->type != COMMAND) {
				sudoerserror(N_("a digest requires a path name"));
				YYERROR;
			    }
			    /* XXX - yuck */
			    ((struct sudo_command *) $2->name)->digest = $1;
			    $$ = $2;
			}
		;

opcmnd		:	cmnd {
			    $$ = $1;
			    $$->negated = false;
			}
		|	'!' cmnd {
			    $$ = $2;
			    $$->negated = true;
			}
		;

rolespec	:	ROLE '=' WORD {
			    $$ = $3;
			}
		;

typespec	:	TYPE '=' WORD {
			    $$ = $3;
			}
		;

selinux		:	/* empty */ {
			    $$.role = NULL;
			    $$.type = NULL;
			}
		|	rolespec {
			    $$.role = $1;
			    $$.type = NULL;
			}
		|	typespec {
			    $$.type = $1;
			    $$.role = NULL;
			}
		|	rolespec typespec {
			    $$.role = $1;
			    $$.type = $2;
			}
		|	typespec rolespec {
			    $$.type = $1;
			    $$.role = $2;
			}
		;

privsspec	:	PRIVS '=' WORD {
			    $$ = $3;
			}
		;
limitprivsspec	:	LIMITPRIVS '=' WORD {
			    $$ = $3;
			}
		;

solarisprivs	:	/* empty */ {
			    $$.privs = NULL;
			    $$.limitprivs = NULL;
			}
		|	privsspec {
			    $$.privs = $1;
			    $$.limitprivs = NULL;
			}
		|	limitprivsspec {
			    $$.privs = NULL;
			    $$.limitprivs = $1;
			}
		|	privsspec limitprivsspec {
			    $$.privs = $1;
			    $$.limitprivs = $2;
			}
		|	limitprivsspec privsspec {
			    $$.limitprivs = $1;
			    $$.privs = $2;
			}
		;

runasspec	:	/* empty */ {
			    $$ = NULL;
			}
		|	'(' runaslist ')' {
			    $$ = $2;
			}
		;

runaslist	:	/* empty */ {
			    $$ = calloc(1, sizeof(struct runascontainer));
			    if ($$ != NULL) {
				$$->runasusers = new_member(NULL, MYSELF);
				/* $$->runasgroups = NULL; */
				if ($$->runasusers == NULL) {
				    free($$);
				    $$ = NULL;
				}
			    }
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	userlist {
			    $$ = calloc(1, sizeof(struct runascontainer));
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    $$->runasusers = $1;
			    /* $$->runasgroups = NULL; */
			}
		|	userlist ':' grouplist {
			    $$ = calloc(1, sizeof(struct runascontainer));
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    $$->runasusers = $1;
			    $$->runasgroups = $3;
			}
		|	':' grouplist {
			    $$ = calloc(1, sizeof(struct runascontainer));
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    /* $$->runasusers = NULL; */
			    $$->runasgroups = $2;
			}
		|	':' {
			    $$ = calloc(1, sizeof(struct runascontainer));
			    if ($$ != NULL) {
				$$->runasusers = new_member(NULL, MYSELF);
				/* $$->runasgroups = NULL; */
				if ($$->runasusers == NULL) {
				    free($$);
				    $$ = NULL;
				}
			    }
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		;

cmndtag		:	/* empty */ {
			    TAGS_INIT($$);
			}
		|	cmndtag NOPASSWD {
			    $$.nopasswd = true;
			}
		|	cmndtag PASSWD {
			    $$.nopasswd = false;
			}
		|	cmndtag NOEXEC {
			    $$.noexec = true;
			}
		|	cmndtag EXEC {
			    $$.noexec = false;
			}
		|	cmndtag SETENV {
			    $$.setenv = true;
			}
		|	cmndtag NOSETENV {
			    $$.setenv = false;
			}
		|	cmndtag LOG_INPUT {
			    $$.log_input = true;
			}
		|	cmndtag NOLOG_INPUT {
			    $$.log_input = false;
			}
		|	cmndtag LOG_OUTPUT {
			    $$.log_output = true;
			}
		|	cmndtag NOLOG_OUTPUT {
			    $$.log_output = false;
			}
		|	cmndtag FOLLOW {
			    $$.follow = true;
			}
		|	cmndtag NOFOLLOW {
			    $$.follow = false;
			}
		|	cmndtag MAIL {
			    $$.send_mail = true;
			}
		|	cmndtag NOMAIL {
			    $$.send_mail = false;
			}
		;

cmnd		:	ALL {
			    $$ = new_member(NULL, ALL);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	ALIAS {
			    $$ = new_member($1, ALIAS);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	COMMAND {
			    struct sudo_command *c = calloc(1, sizeof(*c));
			    if (c == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			    c->cmnd = $1.cmnd;
			    c->args = $1.args;
			    $$ = new_member((char *)c, COMMAND);
			    if ($$ == NULL) {
				free(c);
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		;

hostaliases	:	hostalias
		|	hostaliases ':' hostalias
		;

hostalias	:	ALIAS '=' hostlist {
			    const char *s;
			    if ((s = alias_add($1, HOSTALIAS, $3)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
		;

hostlist	:	ophost
		|	hostlist ',' ophost {
			    HLTQ_CONCAT($1, $3, entries);
			    $$ = $1;
			}
		;

cmndaliases	:	cmndalias
		|	cmndaliases ':' cmndalias
		;

cmndalias	:	ALIAS '=' cmndlist {
			    const char *s;
			    if ((s = alias_add($1, CMNDALIAS, $3)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
		;

cmndlist	:	digcmnd
		|	cmndlist ',' digcmnd {
			    HLTQ_CONCAT($1, $3, entries);
			    $$ = $1;
			}
		;

runasaliases	:	runasalias
		|	runasaliases ':' runasalias
		;

runasalias	:	ALIAS '=' userlist {
			    const char *s;
			    if ((s = alias_add($1, RUNASALIAS, $3)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
		;

useraliases	:	useralias
		|	useraliases ':' useralias
		;

useralias	:	ALIAS '=' userlist {
			    const char *s;
			    if ((s = alias_add($1, USERALIAS, $3)) != NULL) {
				sudoerserror(s);
				YYERROR;
			    }
			}
		;

userlist	:	opuser
		|	userlist ',' opuser {
			    HLTQ_CONCAT($1, $3, entries);
			    $$ = $1;
			}
		;

opuser		:	user {
			    $$ = $1;
			    $$->negated = false;
			}
		|	'!' user {
			    $$ = $2;
			    $$->negated = true;
			}
		;

user		:	ALIAS {
			    $$ = new_member($1, ALIAS);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	ALL {
			    $$ = new_member(NULL, ALL);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	NETGROUP {
			    $$ = new_member($1, NETGROUP);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	USERGROUP {
			    $$ = new_member($1, USERGROUP);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	WORD {
			    $$ = new_member($1, WORD);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		;

grouplist	:	opgroup
		|	grouplist ',' opgroup {
			    HLTQ_CONCAT($1, $3, entries);
			    $$ = $1;
			}
		;

opgroup		:	group {
			    $$ = $1;
			    $$->negated = false;
			}
		|	'!' group {
			    $$ = $2;
			    $$->negated = true;
			}
		;

group		:	ALIAS {
			    $$ = new_member($1, ALIAS);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	ALL {
			    $$ = new_member(NULL, ALL);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		|	WORD {
			    $$ = new_member($1, WORD);
			    if ($$ == NULL) {
				sudoerserror(N_("unable to allocate memory"));
				YYERROR;
			    }
			}
		;

%%
void
sudoerserror(const char *s)
{
    debug_decl(sudoerserror, SUDOERS_DEBUG_PARSER)

    /* If we last saw a newline the error is on the preceding line. */
    if (last_token == COMMENT)
	sudolineno--;

    /* Save the line the first error occurred on. */
    if (errorlineno == -1) {
	errorlineno = sudolineno;
	errorfile = sudoers;
    }
    if (sudoers_warnings && s != NULL) {
	LEXTRACE("<*> ");
#ifndef TRACELEXER
	if (trace_print == NULL || trace_print == sudoers_trace_print) {
	    const char fmt[] = ">>> %s: %s near line %d <<<\n";
	    int oldlocale;

	    /* Warnings are displayed in the user's locale. */
	    sudoers_setlocale(SUDOERS_LOCALE_USER, &oldlocale);
	    sudo_printf(SUDO_CONV_ERROR_MSG, _(fmt), sudoers, _(s), sudolineno);
	    sudoers_setlocale(oldlocale, NULL);
	}
#endif
    }
    parse_error = true;
    debug_return;
}

static struct defaults *
new_default(char *var, char *val, int op)
{
    struct defaults *d;
    debug_decl(new_default, SUDOERS_DEBUG_PARSER)

    if ((d = calloc(1, sizeof(struct defaults))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    d->var = var;
    d->val = val;
    /* d->type = 0; */
    d->op = op;
    /* d->binding = NULL */
    HLTQ_INIT(d, entries);

    debug_return_ptr(d);
}

static struct member *
new_member(char *name, int type)
{
    struct member *m;
    debug_decl(new_member, SUDOERS_DEBUG_PARSER)

    if ((m = calloc(1, sizeof(struct member))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    m->name = name;
    m->type = type;
    HLTQ_INIT(m, entries);

    debug_return_ptr(m);
}

struct sudo_digest *
new_digest(int digest_type, const char *digest_str)
{
    struct sudo_digest *dig;
    debug_decl(new_digest, SUDOERS_DEBUG_PARSER)

    if ((dig = malloc(sizeof(*dig))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_ptr(NULL);
    }

    dig->digest_type = digest_type;
    dig->digest_str = strdup(digest_str);
    if (dig->digest_str == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	free(dig);
	dig = NULL;
    }

    debug_return_ptr(dig);
}

/*
 * Add a list of defaults structures to the defaults list.
 * The binding, if non-NULL, specifies a list of hosts, users, or
 * runas users the entries apply to (specified by the type).
 */
static bool
add_defaults(int type, struct member *bmem, struct defaults *defs)
{
    struct defaults *d;
    struct member_list *binding;
    debug_decl(add_defaults, SUDOERS_DEBUG_PARSER)

    if (defs != NULL) {
	/*
	 * We use a single binding for each entry in defs.
	 */
	if ((binding = malloc(sizeof(*binding))) == NULL) {
	    sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
		"unable to allocate memory");
	    debug_return_bool(false);
	}
	if (bmem != NULL)
	    HLTQ_TO_TAILQ(binding, bmem, entries);
	else
	    TAILQ_INIT(binding);

	/*
	 * Set type and binding (who it applies to) for new entries.
	 * Then add to the global defaults list.
	 */
	HLTQ_FOREACH(d, defs, entries) {
	    d->type = type;
	    d->binding = binding;
	}
	TAILQ_CONCAT_HLTQ(&defaults, defs, entries);
    }

    debug_return_bool(true);
}

/*
 * Allocate a new struct userspec, populate it, and insert it at the
 * end of the userspecs list.
 */
static bool
add_userspec(struct member *members, struct privilege *privs)
{
    struct userspec *u;
    debug_decl(add_userspec, SUDOERS_DEBUG_PARSER)

    if ((u = calloc(1, sizeof(*u))) == NULL) {
	sudo_debug_printf(SUDO_DEBUG_ERROR|SUDO_DEBUG_LINENO,
	    "unable to allocate memory");
	debug_return_bool(false);
    }
    HLTQ_TO_TAILQ(&u->users, members, entries);
    HLTQ_TO_TAILQ(&u->privileges, privs, entries);
    TAILQ_INSERT_TAIL(&userspecs, u, entries);

    debug_return_bool(true);
}

/*
 * Free up space used by data structures from a previous parser run and sets
 * the current sudoers file to path.
 */
bool
init_parser(const char *path, bool quiet)
{
    struct member_list *binding;
    struct defaults *d, *d_next;
    struct userspec *us, *us_next;
    bool rval = true;
    debug_decl(init_parser, SUDOERS_DEBUG_PARSER)

    TAILQ_FOREACH_SAFE(us, &userspecs, entries, us_next) {
	struct member *m, *m_next;
	struct privilege *priv, *priv_next;

	TAILQ_FOREACH_SAFE(m, &us->users, entries, m_next) {
	    free(m->name);
	    free(m);
	}
	TAILQ_FOREACH_SAFE(priv, &us->privileges, entries, priv_next) {
	    struct member_list *runasuserlist = NULL, *runasgrouplist = NULL;
	    struct cmndspec *cs, *cs_next;
#ifdef HAVE_SELINUX
	    char *role = NULL, *type = NULL;
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
	    char *privs = NULL, *limitprivs = NULL;
#endif /* HAVE_PRIV_SET */

	    TAILQ_FOREACH_SAFE(m, &priv->hostlist, entries, m_next) {
		free(m->name);
		free(m);
	    }
	    TAILQ_FOREACH_SAFE(cs, &priv->cmndlist, entries, cs_next) {
#ifdef HAVE_SELINUX
		/* Only free the first instance of a role/type. */
		if (cs->role != role) {
		    role = cs->role;
		    free(cs->role);
		}
		if (cs->type != type) {
		    type = cs->type;
		    free(cs->type);
		}
#endif /* HAVE_SELINUX */
#ifdef HAVE_PRIV_SET
		/* Only free the first instance of privs/limitprivs. */
		if (cs->privs != privs) {
		    privs = cs->privs;
		    free(cs->privs);
		}
		if (cs->limitprivs != limitprivs) {
		    limitprivs = cs->limitprivs;
		    free(cs->limitprivs);
		}
#endif /* HAVE_PRIV_SET */
		/* Only free the first instance of runas user/group lists. */
		if (cs->runasuserlist && cs->runasuserlist != runasuserlist) {
		    runasuserlist = cs->runasuserlist;
		    TAILQ_FOREACH_SAFE(m, runasuserlist, entries, m_next) {
			free(m->name);
			free(m);
		    }
		    free(runasuserlist);
		}
		if (cs->runasgrouplist && cs->runasgrouplist != runasgrouplist) {
		    runasgrouplist = cs->runasgrouplist;
		    TAILQ_FOREACH_SAFE(m, runasgrouplist, entries, m_next) {
			free(m->name);
			free(m);
		    }
		    free(runasgrouplist);
		}
		if (cs->cmnd->type == COMMAND) {
			struct sudo_command *c =
			    (struct sudo_command *) cs->cmnd->name;
			free(c->cmnd);
			free(c->args);
		}
		free(cs->cmnd->name);
		free(cs->cmnd);
		free(cs);
	    }
	    free(priv);
	}
	free(us);
    }
    TAILQ_INIT(&userspecs);

    binding = NULL;
    TAILQ_FOREACH_SAFE(d, &defaults, entries, d_next) {
	if (d->binding != binding) {
	    struct member *m, *m_next;

	    binding = d->binding;
	    TAILQ_FOREACH_SAFE(m, d->binding, entries, m_next) {
		if (m->type == COMMAND) {
			struct sudo_command *c =
			    (struct sudo_command *) m->name;
			free(c->cmnd);
			free(c->args);
		}
		free(m->name);
		free(m);
	    }
	    free(d->binding);
	}
	free(d->var);
	free(d->val);
	free(d);
    }
    TAILQ_INIT(&defaults);

    init_lexer();

    if (!init_aliases()) {
	sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	rval = false;
    }

    free(sudoers);
    if (path != NULL) {
	if ((sudoers = strdup(path)) == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__, U_("unable to allocate memory"));
	    rval = false;
	}
    } else {
	sudoers = NULL;
    }

    parse_error = false;
    errorlineno = -1;
    errorfile = sudoers;
    sudoers_warnings = !quiet;

    debug_return_bool(rval);
}
