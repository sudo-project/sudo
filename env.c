/*
 * Copyright (c) 2000 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * 4. Products derived from this software may not be called "Sudo" nor
 *    may "Sudo" appear in their names without specific prior written
 *    permission from the author.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#ifdef STDC_HEADERS
#include <stdlib.h>
#endif /* STDC_HEADERS */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */
#include <pwd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include "sudo.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Local type declarations
 */
struct env_table {
    char *name;
    int len;
    int check;
};

/*
 * Prototypes
 */
char **rebuild_env		__P((int, char **));
char **zero_env			__P((char **));
static void insert_env		__P((char **, char *));
static char *format_env		__P((char *, char *));

/*
 * Table of "bad" envariables to remove and len for strncmp()
 */
static struct env_table sudo_badenv_table[] = {
    { "IFS=", 4, 0 },
    { "LOCALDOMAIN=", 12, 0 },
    { "RES_OPTIONS=", 12, 0 },
    { "HOSTALIASES=", 12, 0 },
    { "NLSPATH=", 8, 0 },
    { "PATH_LOCALE=", 12, 0 },
    { "LD_", 3, 0 },
    { "_RLD", 4, 0 },
#ifdef __hpux
    { "SHLIB_PATH=", 11, 0 },
#endif /* __hpux */
#ifdef _AIX
    { "LIBPATH=", 8, 0 },
#endif /* _AIX */
#ifdef HAVE_KERB4
    { "KRB_CONF", 8, 0 },
    { "KRBCONFDIR=", 11, 0 },
    { "KRBTKFILE=", 10, 0 },
#endif /* HAVE_KERB4 */
#ifdef HAVE_KERB5
    { "KRB5_CONFIG", 11, 0 },
#endif /* HAVE_KERB5 */
#ifdef HAVE_SECURID
    { "VAR_ACE=", 8, 0 },
    { "USR_ACE=", 8, 0 },
    { "DLC_ACE=", 8, 0 },
#endif /* HAVE_SECURID */
    { "TERMINFO=", 9, 0 },
    { "TERMINFO_DIRS=", 14, 0 },
    { "TERMPATH=", 9, 0 },
    { "TERMCAP=/", 9, 0 },
    { "ENV=", 4, 0 },
    { "BASH_ENV=", 9, 0 },
    { "LC_", 3, 1 },
    { "LANG=", 5, 1 },
    { "LANGUAGE=", 5, 1 },
    { (char *) NULL, 0, 0 }
};
static struct env_table *badenv_table;


/*
 * Zero out environment and replace with a minimal set of
 * USER, LOGNAME, HOME, TZ, PATH (XXX - should just set path to default)
 * May set user_path, user_shell, and/or user_prompt as side effects.
 */
char **
zero_env(envp)
    char **envp;
{
    char **ep, **nep;
    static char *newenv[7];

    for (ep = envp; *ep; ep++) {
	switch (**ep) {
	    case 'H':
		if (strncmp("HOME=", *ep, 5) == 0)
		    break;
	    case 'L':
		if (strncmp("LOGNAME=", *ep, 8) == 0)
		    break;
	    case 'P':
		if (strncmp("PATH=", *ep, 5) == 0) {
		    user_path = *ep + 5;
		    /* XXX - set to sane default instead of user's? */
		    break;
		}
	    case 'S':
		if (strncmp("SHELL=", *ep, 6) == 0) {
		    user_shell = *ep + 6;
		    continue;
		} else if (!user_prompt && !strncmp("SUDO_PROMPT=", *ep, 12)) {
		    user_prompt = *ep + 12;
		    continue;
		}
	    case 'T':
		if (strncmp("TZ=", *ep, 3) == 0)
		    break;
	    case 'U':
		if (strncmp("USER=", *ep, 5) == 0)
		    break;
	    default:
		continue;
	}

	/* Deal with multiply defined variables (take first instantiation) */
	for (nep = newenv; *nep; nep++) {
	    if (**nep == **ep)
		break;
	}
	if (*nep == NULL)
	    *nep++ = *ep;
    }
    return(&newenv[0]);
}

/*
 * Given a variable and value, allocate and format an environment string.
 */
static char *
format_env(var, val)
    char *var;
    char *val;
{
    char *estring, *p;
    size_t varlen, vallen;

    varlen = strlen(var);
    vallen = strlen(val);
    p = estring = (char *) emalloc(varlen + vallen + 2);
    strcpy(p, var);
    p += varlen;
    *p++ = '=';
    strcpy(p, val);

    return(estring);
}

/*
 * Insert str into envp.
 * Assumes str has an '=' in it and does not check for available space!
 */
static void
insert_env(envp, str)
    char **envp;
    char *str;
{
    char **ep;
    size_t varlen;

    varlen = (strchr(str, '=') - str) + 1;

    for (ep = envp; *ep; ep++) {
	if (strncmp(str, *ep, varlen) == 0) {
	    *ep = str;
	    break;
	}
    }
    if (*ep == NULL) {
	*ep++ = str;
	*ep = NULL;
    }
}

/*
 * Build a new environment and ether clear potentially dangerous
 * variables from the old one or starts with a clean slate.
 * Also adds sudo-specific variables (SUDO_*).
 */
char **
rebuild_env(sudo_mode, envp)
    int sudo_mode;
    char **envp;
{
    char **newenvp, **ep, **nep, **ek, *cp;
    char *ekflat, *ps1, **env_keep;
    int okvar, iswild;
    size_t env_size, eklen;
    struct env_table *entry;

    eklen = 0;
    ekflat = ps1 = NULL;
    env_keep = NULL;
    if (def_str(I_ENV_KEEP)) {
	/* XXX - start eklen at 1 instead? */
	for (cp = def_str(I_ENV_KEEP), eklen = 2; *cp; cp++)
	    if (*cp == ' ' || *cp == '\t')
		eklen++;
	env_keep = emalloc(sizeof(char *) * eklen);
	cp = ekflat = estrdup(def_str(I_ENV_KEEP));
	eklen = 0;
	if ((cp = strtok(cp, " \t"))) {
	    do {
		/* XXX - hack due to assumption in rebuild_env */
		if (strcmp("PATH", cp) && strcmp("TERM", cp))
		    env_keep[eklen++] = cp;
	    } while ((cp = strtok(NULL, " \t")));
	}
	env_keep[eklen] = NULL;
    }

    /*
     * If sudoers overrides or adds to the badenv_table, rebuild it.
     */
    if ((cp = def_str(I_ENV_DELETE))) {
	int i;
	size_t len;
	char *env_delete, *end;

	env_delete = def_str(I_ENV_DELETE);
	if (*env_delete == '+')
	    env_delete++;

	/*
	 * Calculate number of entries in new badenv_table.
	 * If defined we have at least two entries (including a NULL entry).
	 */
	for (i = 2, cp = env_delete; (cp = strpbrk(cp, " \t")); i++) {
	    while (*cp == ' ' || *cp == '\t')
		cp++;
	}
	if (*def_str(I_ENV_DELETE) == '+') {
	    for (entry = sudo_badenv_table; entry->name; entry++, i++)
		;
	}
	badenv_table = emalloc(sizeof(struct env_table) * i);

	/*
	 * Copy in user entries.
	 */
	for (i = 0, cp = env_delete; cp; i++) {
	    while (*cp == ' ' || *cp == '\t')
		cp++;
	    end = strpbrk(cp, " \t");
	    if (end == NULL)
		len = strlen(cp);
	    else
		len = end - cp;
	    if ((iswild = cp[len - 1] == '*'))		/* wildcard */
		len--;
	    entry = &badenv_table[i];
	    entry->name = emalloc(len + 1 + !iswild);
	    memcpy(entry->name, cp, len);
	    if (!iswild)
		entry->name[len++] = '=';
	    entry->name[len] = '\0';
	    entry->len = len;
	    entry->check = 0;
	    cp = end;
	}

	/*
	 * Copy in default entries if user is appending.
	 */
	if (*def_str(I_ENV_DELETE) == '+') {
	    for (entry = sudo_badenv_table; entry->name; entry++, i++) {
		badenv_table[i].name = entry->name;
		badenv_table[i].len = entry->len;
		badenv_table[i].check = entry->check;
	    }
	}
	memset(&badenv_table[i], 0, sizeof(badenv_table[i]));
    } else
	badenv_table = sudo_badenv_table;

    /*
     * Either clean out the environment or reset to a safe default.
     */
    if (def_flag(I_ENV_RESET)) {
	int didterm;

	/* Alloc space for new environment. */
	env_size = 32 + eklen;
	nep = newenvp = (char **) emalloc(env_size * sizeof(char *));

	/* XXX - set all to target user instead for -S */
	*nep++ = format_env("HOME", user_dir);
	*nep++ = format_env("SHELL", user_shell);
	if (def_flag(I_SET_LOGNAME) && runas_pw->pw_name) {
	    *nep++ = format_env("LOGNAME", runas_pw->pw_name);
	    *nep++ = format_env("USER", runas_pw->pw_name);
	} else {
	    *nep++ = format_env("LOGNAME", user_name);
	    *nep++ = format_env("USER", user_name);
	}

	/* Pull in vars we want to keep from the old environment */
	didterm = 0;
	for (ep = envp; *ep; ep++) {
	    if (env_keep) {
		for (ek = env_keep; *ek; ek++) {
		    eklen = strlen(*ek);
		    /* Deal with '*' wildcard */
		    if ((*ek)[eklen - 1] == '*') {
			eklen--;
			iswild = 1;
		    } else
			iswild = 0;
		    if (strncmp(*ek, *ep, eklen) == 0 &&
			(iswild || (*ep)[eklen] == '=')) {
			*nep++ = *ep;
			break;
		    }
		}
	    }

	    /* We assume PATH and TERM are not listed in env_keep. */
	    if (!def_str(I_SECURE_PATH) && strncmp(*ep, "PATH=", 5) == 0) {
		*nep++ = *ep;
	    } else if (!didterm && strncmp(*ep, "TERM=", 5) == 0) {
		*nep++ = *ep;
		didterm = 1;
	    } else if (strncmp(*ep, "SUDO_PS1=", 8) == 0)
		ps1 = *ep + 5;
	}

#if 0
	/* XXX - set to _PATH_DEFPATH if no secure path? */
	if (!def_str(I_SECURE_PATH))
	    *nep++ = "PATH" _PATH_DEFPATH); /* XXX - concat macro? */
#endif
	if (!didterm)
	    *nep++ = "TERM=unknown";
    } else {
	/* Alloc space for new environment. */
	for (env_size = 16 + eklen, ep = envp; *ep; ep++, env_size++)
	    ;
	nep = newenvp = (char **) emalloc(env_size * sizeof(char *));

	/*
	 * Copy envp entries as long as they don't match badenv_table
	 * (unless excepted by env_keep).
	 */
	for (ep = envp; *ep; ep++) {
	    okvar = 0;
	    /* env_keep overrides badenv_table */
	    if (env_keep) {
		for (ek = env_keep; *ek; ek++) {
		    eklen = strlen(*ek);
		    /* Deal with '*' wildcard */
		    if ((*ek)[eklen - 1] == '*') {
			eklen--;
			iswild = 1;
		    } else
			iswild = 0;
		    if (strncmp(*ek, *ep, eklen) == 0 &&
			(iswild || (*ep)[eklen] == '=')) {
			okvar = 1;
			break;
		    }
		}
	    }
	    if (!okvar) {
		for (okvar = 1, entry = badenv_table; entry->name; entry++) {
		    if (strncmp(*ep, entry->name, entry->len) == 0 &&
			(!entry->check || strpbrk(*ep, "/%"))) {
			okvar = 0;
			break;
		    }
		}
	    }
	    if (okvar) {
		if (strncmp(*ep, "SUDO_PS1=", 9) == 0)
		    ps1 = *ep + 5;
		*nep++ = *ep;
	    }
	}
    }
    *nep = NULL;

    /*
     * At this point we must use insert_env() to modify newenvp.
     * Access via 'nep' is not allowed (since we must check for dupes).
     */

    /* Replace the PATH envariable with a secure one. */
    if (def_str(I_SECURE_PATH) && !user_is_exempt())
	insert_env(newenvp, format_env("PATH", def_str(I_SECURE_PATH)));

    /* Set $HOME for `sudo -H'.  Only valid at PERM_RUNAS. */
    if ((sudo_mode & MODE_RESET_HOME) && runas_pw->pw_dir)
	insert_env(newenvp, format_env("HOME", runas_pw->pw_dir));

    /* Set PS1 if SUDO_PS1 is set. */
    if (ps1)
	insert_env(newenvp, ps1);

    /* Add the SUDO_COMMAND envariable (cmnd + args). */
    if (user_args) {
	cp = emalloc(strlen(user_cmnd) + strlen(user_args) + 14);
	sprintf(cp, "SUDO_COMMAND=%s %s", user_cmnd, user_args);
	insert_env(newenvp, cp);
    } else
	insert_env(newenvp, format_env("SUDO_COMMAND", user_cmnd));

    /* Add the SUDO_USER, SUDO_UID, SUDO_GID environment variables. */
    insert_env(newenvp, format_env("SUDO_USER", user_name));
    cp = emalloc(MAX_UID_T_LEN + 10);
    sprintf(cp, "SUDO_UID=%ld", (long) user_uid);
    insert_env(newenvp, cp);
    cp = emalloc(MAX_UID_T_LEN + 10);
    sprintf(cp, "SUDO_GID=%ld", (long) user_gid);
    insert_env(newenvp, cp);

    if (env_keep) {
	free(env_keep);
	free(ekflat);
    }
    return(newenvp);
}
