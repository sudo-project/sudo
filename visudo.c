/*
 * Copyright (c) 1996, 1998-2004 Todd C. Miller <Todd.Miller@courtesan.com>
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

/*
 * Lock the sudoers file for safe editing (ala vipw) and check for parse errors.
 */

#define _SUDO_MAIN

#ifdef __TANDEM
# include <floss.h>
#endif

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#ifndef __TANDEM
# include <sys/file.h>
#endif
#include <sys/wait.h>
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
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif
#endif /* HAVE_STRING_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_ERR_H
# include <err.h>
#else
# include "emul/err.h"
#endif /* HAVE_ERR_H */
#include <ctype.h>
#include <pwd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef __STDC__
# include <stdarg.h>
#else
# include <varargs.h>
#endif

#include "sudo.h"
#include "interfaces.h"
#include "parse.h"
#include "gram.h"
#include "version.h"

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

struct sudoersfile {
    char *path;
    int fd;
    char *tpath;
    int tfd;
    int modified;
    struct sudoersfile *next;
};

/*
 * Function prototypes
 */
static RETSIGTYPE Exit		__P((int)) __attribute__((__noreturn__));
static char *get_editor		__P((void));
static char whatnow		__P((void));
static int check_aliases	__P((int));
static int check_syntax		__P((char *, int));
static int edit_sudoers		__P((struct sudoersfile *, char *, int));
static int install_sudoers	__P((struct sudoersfile *));
static int print_unused		__P((VOID *, VOID *));
static int reparse_sudoers	__P((char *, int, int));
static int run_command		__P((char *, char **));
static void setup_signals	__P((void));
static void usage		__P((void)) __attribute__((__noreturn__));
    VOID *v2;

void yyerror			__P((const char *));
void yyrestart			__P((FILE *));
void Err			__P((int, const char *, ...))
				    __attribute__((__noreturn__));
void Errx			__P((int, const char *, ...))
				    __attribute__((__noreturn__));

/*
 * External globals exported by the parser
 */
extern FILE *yyin;
extern char *sudoers, *errorfile;
extern int errorlineno, parse_error;
/* For getopt(3) */
extern char *optarg;
extern int optind;

extern struct defaults *defaults;
extern struct userspec *userspecs;

/*
 * Globals
 */
int Argc;
char **Argv;
int num_interfaces;
struct interface *interfaces;
struct sudo_user sudo_user;
static struct sudoerslist {
    struct sudoersfile *first, *last;
} sudoerslist;

int
main(argc, argv)
    int argc;
    char **argv;
{
    struct sudoersfile *sp;
    char *editor, *sudoers_path;
    int ch, checkonly, quiet, strict;

    Argv = argv;
    if ((Argc = argc) < 1)
	usage();

    /*
     * Arg handling.
     */
    checkonly = quiet = strict = 0;
    sudoers_path = _PATH_SUDOERS;
    while ((ch = getopt(argc, argv, "Vcf:sq")) != -1) {
	switch (ch) {
	    case 'V':
		(void) printf("%s version %s\n", getprogname(), version);
		exit(0);
	    case 'c':
		checkonly++;		/* check mode */
		break;
	    case 'f':
		sudoers_path = optarg;	/* sudoers file path */
		break;
	    case 's':
		strict++;		/* strict mode */
		break;
	    case 'q':
		quiet++;		/* quiet mode */
		break;
	    default:
		usage();
	}
    }
    argc -= optind;
    argv += optind;
    if (argc)
	usage();

    /* Mock up a fake sudo_user struct. */
    user_host = user_shost = user_cmnd = "";
    if ((sudo_user.pw = getpwuid(getuid())) == NULL)
	Errx(1, "you don't exist in the passwd database");

    /* Setup defaults data structures. */
    init_defaults();

    if (checkonly)
	exit(check_syntax(sudoers_path, quiet));

    /*
     * Parse the existing sudoers file(s) in quiet mode to highlight any
     * existing errors and to pull in editor and env_editor conf values.
     */
    if ((yyin = open_sudoers(sudoers_path, NULL)) == NULL)
	Err(1, "%s", sudoers_path);
    if (!lock_file(fileno(yyin), SUDO_TLOCK))
	Errx(1, "%s busy, try again later", sudoers_path);
    init_parser(sudoers_path, 0);
    yyparse();
    (void) update_defaults();

    editor = get_editor();

    /* Install signal handlers to clean up temp files if we are killed. */
    setup_signals();

    /* Edit the sudoers file(s) */
    for (sp = sudoerslist.first; sp != NULL; sp = sp->next) {
	if (sp != sudoerslist.first) {
	    printf("press return to edit %s: ", sp->path);
	    while ((ch = getchar()) != EOF && ch != '\n')
		    continue;
	}
	edit_sudoers(sp, editor, -1);
    }

    /* Check edited files for a parse error and re-edit any that fail. */
    reparse_sudoers(editor, strict, quiet);

    /* Install the sudoers temp files. */
    for (sp = sudoerslist.first; sp != NULL; sp = sp->next) {
	if (!sp->modified)
	    (void) unlink(sp->tpath);
	else
	    (void) install_sudoers(sp);
    }

    exit(0);
}

/*
 * Edit each sudoers file.
 * Returns TRUE on success, else FALSE.
 */
static int
edit_sudoers(sp, editor, lineno)
    struct sudoersfile *sp;
    char *editor;
    int lineno;
{
    int tfd;				/* sudoers temp file descriptor */
    int n;				/* length parameter */
    int modified;			/* was the file modified? */
    char buf[PATH_MAX*2];		/* buffer used for copying files */
    char linestr[64];			/* string version of lineno */
    char *av[4];			/* argument vector for run_command */
    struct timespec ts1, ts2;		/* time before and after edit */
    struct timespec orig_mtim;		/* starting mtime of sudoers file */
    off_t orig_size;			/* starting size of sudoers file */
    struct stat sb;			/* stat buffer */

#ifdef HAVE_FSTAT
    if (fstat(sp->fd, &sb) == -1)
#else
    if (stat(sp->path, &sb) == -1)
#endif
	Err(1, "can't stat %s", sp->path);
    orig_size = sb.st_size;
    orig_mtim.tv_sec = mtim_getsec(sb);
    orig_mtim.tv_nsec = mtim_getnsec(sb);

    /* Create the temp file if needed and set timestamp. */
    if (sp->tpath == NULL) {
	easprintf(&sp->tpath, "%s.tmp", sp->path);
	tfd = open(sp->tpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (tfd < 0)
	    Err(1, "%s", sp->tpath);

	/* Copy sp->path -> sp->tpath and reset the mtime. */
	if (orig_size != 0) {
	    (void) lseek(sp->fd, (off_t)0, SEEK_SET);
	    while ((n = read(sp->fd, buf, sizeof(buf))) > 0)
		if (write(tfd, buf, n) != n)
		    Err(1, "write error");

	    /* Add missing newline at EOF if needed. */
	    if (n > 0 && buf[n - 1] != '\n') {
		buf[0] = '\n';
		write(tfd, buf, 1);
	    }
	}
	(void) close(tfd);
    }
    (void) touch(-1, sp->tpath, &orig_mtim);

    /* Build up argument vector for the command */
    if ((av[0] = strrchr(editor, '/')) != NULL)
	av[0]++;
    else
	av[0] = editor;
    n = 1;
    if (lineno > 0) {
	(void) snprintf(linestr, sizeof(linestr), "+%d", lineno);
	av[n++] = linestr;
    }
    av[n++] = sp->tpath;
    av[n++] = NULL;

    /*
     * Do the edit:
     *  We cannot check the editor's exit value against 0 since
     *  XPG4 specifies that vi's exit value is a function of the
     *  number of errors during editing (?!?!).
     */
    gettime(&ts1);
    if (run_command(editor, av) != -1) {
	gettime(&ts2);
	/*
	 * Sanity checks.
	 */
	if (stat(sp->tpath, &sb) < 0) {
	    warnx("cannot stat temporary file (%s), %s unchanged",
		sp->tpath, sp->path);
	    return(FALSE);
	}
	if (sb.st_size == 0 && orig_size != 0) {
	    warnx("zero length temporary file (%s), %s unchanged",
		sp->tpath, sp->path);
	    sp->modified = TRUE;
	    return(FALSE);
	}
    } else {
	warnx("editor (%s) failed, %s unchanged", editor, sp->path);
	return(FALSE);
    }

    /* Set modified bit if use changed the file. */
    modified = TRUE;
    if (orig_size == sb.st_size &&
	orig_mtim.tv_sec == mtim_getsec(sb) &&
	orig_mtim.tv_nsec == mtim_getnsec(sb)) {
	/*
	 * If mtime and size match but the user spent no measurable
	 * time in the editor we can't tell if the file was changed.
	 */
	timespecsub(&ts1, &ts2, &ts2);
	if (timespecisset(&ts2))
	    modified = FALSE;
    }

    /*
     * If modified in this edit session, mark as modified.
     */
    if (modified)
	sp->modified = modified;
    else
	warnx("%s unchanged", sp->tpath);

    return(TRUE);
}

/*
 * Parse sudoers after editing and re-edit any ones that caused a parse error.
 * Returns TRUE on success, else FALSE.
 */
static int
reparse_sudoers(editor, strict, quiet)
    char *editor;
    int strict, quiet;
{
    struct sudoersfile *sp, *last;
    FILE *fp;
    int ch;

    /*
     * Parse the edited sudoers files and do sanity checking
     */
    do {
	sp = sudoerslist.first;
	last = sudoerslist.last;
	fp = fopen(sp->tpath, "r+");
	if (fp == NULL) {
	    warnx("can't re-open temporary file (%s), %s unchanged.",
		sp->tpath, sp->path);
	    Exit(-1);
	}

	/* Clean slate for each parse */
	user_runas = NULL;
	init_defaults();
	init_parser(sp->path, quiet);

	/* Parse the sudoers temp file */
	yyrestart(fp);
	if (yyparse() && parse_error != TRUE) {
	    warnx("unabled to parse temporary file (%s), unknown error",
		sp->tpath);
	    parse_error = TRUE;
	}
	fclose(yyin);
	if (check_aliases(strict) != 0)
	    parse_error = TRUE;

	/*
	 * Got an error, prompt the user for what to do now
	 */
	if (parse_error) {
	    switch (whatnow()) {
		case 'Q' :	parse_error = FALSE;	/* ignore parse error */
				break;
		case 'x' :	Exit(0);
				break;
	    }
	}
	if (parse_error) {
	    /* Edit file with the parse error */
	    for (sp = sudoerslist.first; sp != NULL; sp = sp->next) {
		if (errorfile == NULL || strcmp(sp->path, errorfile) == 0) {
		    edit_sudoers(sp, editor, errorlineno);
		    break;
		}
	    }
	    if (sp == NULL)
		Errx(1, "internal error, can't find %s in list!", sudoers);
	}

	/* If any new #include directives were added, edit them too. */
	for (sp = last->next; sp != NULL; sp = sp->next) {
	    printf("press return to edit %s: ", sp->path);
	    while ((ch = getchar()) != EOF && ch != '\n')
		    continue;
	    edit_sudoers(sp, editor, errorlineno);
	}
    } while (parse_error);

    return(TRUE);
}

/*
 * Set the owner and mode on a sudoers temp file and
 * move it into place.  Returns TRUE on success, else FALSE.
 */
static int
install_sudoers(sp)
    struct sudoersfile *sp;
{
    /*
     * Change mode and ownership of temp file so when
     * we move it to sp->path things are kosher.
     */
    if (chown(sp->tpath, SUDOERS_UID, SUDOERS_GID) != 0) {
	warn("unable to set (uid, gid) of %s to (%d, %d)",
	    sp->tpath, SUDOERS_UID, SUDOERS_GID);
	return(FALSE);
    }
    if (chmod(sp->tpath, SUDOERS_MODE) != 0) {
	warn("unable to change mode of %s to 0%o", sp->tpath, SUDOERS_MODE);
	return(FALSE);
    }

    /*
     * Now that sp->tpath is sane (parses ok) it needs to be
     * rename(2)'d to sp->path.  If the rename(2) fails we try using
     * mv(1) in case sp->tpath and sp->path are on different file systems.
     */
    if (rename(sp->tpath, sp->path) == 0) {
	free(sp->tpath);
	sp->tpath = NULL;
    } else {
	if (errno == EXDEV) {
	    char *av[4];
	    warnx("%s and %s not on the same file system, using mv to rename",
	      sp->tpath, sp->path);

	    /* Build up argument vector for the command */
	    if ((av[0] = strrchr(_PATH_MV, '/')) != NULL)
		av[0]++;
	    else
		av[0] = _PATH_MV;
	    av[1] = sp->tpath;
	    av[2] = sp->path;
	    av[3] = NULL;

	    /* And run it... */
	    if (run_command(_PATH_MV, av)) {
		warnx("command failed: '%s %s %s', %s unchanged",
		    _PATH_MV, sp->tpath, sp->path, sp->path);
		(void) unlink(sp->tpath);
		free(sp->tpath);
		sp->tpath = NULL;
		return(FALSE);
	    }
	    free(sp->tpath);
	    sp->tpath = NULL;
	} else {
	    warn("error renaming %s, %s unchanged", sp->tpath, sp->path);
	    (void) unlink(sp->tpath);
	    return(FALSE);
	}
    }
    return(TRUE);
}

/* STUB */
void
set_fqdn()
{
    return;
}

/* STUB */
int
set_runaspw(user)
    char *user;
{
    return(TRUE);
}

/* STUB */
void
init_envtables()
{
    return;
}

/* STUB */
int
user_is_exempt()
{
    return(FALSE);
}

/*
 * Assuming a parse error occurred, prompt the user for what they want
 * to do now.  Returns the first letter of their choice.
 */
static char
whatnow()
{
    int choice, c;

    for (;;) {
	(void) fputs("What now? ", stdout);
	choice = getchar();
	for (c = choice; c != '\n' && c != EOF;)
	    c = getchar();

	switch (choice) {
	    case EOF:
		choice = 'x';
		/* FALLTHROUGH */
	    case 'e':
	    case 'x':
	    case 'Q':
		return(choice);
	    default:
		(void) puts("Options are:");
		(void) puts("  (e)dit sudoers file again");
		(void) puts("  e(x)it without saving changes to sudoers file");
		(void) puts("  (Q)uit and save changes to sudoers file (DANGER!)\n");
	}
    }
}

/*
 * Install signal handlers for visudo.
 */
static void
setup_signals()
{
	sigaction_t sa;

	/*
	 * Setup signal handlers to cleanup nicely.
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = Exit;
	(void) sigaction(SIGTERM, &sa, NULL);
	(void) sigaction(SIGHUP, &sa, NULL);
	(void) sigaction(SIGINT, &sa, NULL);
	(void) sigaction(SIGQUIT, &sa, NULL);
}

static int
run_command(path, argv)
    char *path;
    char **argv;
{
    int status;
    pid_t pid;
    sigset_t set, oset;

    (void) sigemptyset(&set);
    (void) sigaddset(&set, SIGCHLD);
    (void) sigprocmask(SIG_BLOCK, &set, &oset);

    switch (pid = fork()) {
	case -1:
	    warn("unable to run %s", path);
	    Exit(-1);
	    break;	/* NOTREACHED */
	case 0:
	    (void) sigprocmask(SIG_SETMASK, &oset, NULL);
	    execv(path, argv);
	    warn("unable to run %s", path);
	    _exit(127);
	    break;	/* NOTREACHED */
    }

#ifdef sudo_waitpid
    pid = sudo_waitpid(pid, &status, 0);
#else
    pid = wait(&status);
#endif

    (void) sigprocmask(SIG_SETMASK, &oset, NULL);

    if (pid == -1 || !WIFEXITED(status))
	return(-1);
    return(WEXITSTATUS(status));
}

static int
check_syntax(sudoers_path, quiet)
    char *sudoers_path;
    int quiet;
{

    if ((yyin = fopen(sudoers_path, "r")) == NULL) {
	if (!quiet)
	    warn("unable to open %s", sudoers_path);
	exit(1);
    }
    init_parser(sudoers_path, quiet);
    if (yyparse() && parse_error != TRUE) {
	if (!quiet)
	    warnx("failed to parse %s file, unknown error", sudoers_path);
	parse_error = TRUE;
    }
    if (!quiet){
	if (parse_error)
	    (void) printf("parse error in %s near line %d\n", sudoers_path,
		errorlineno);
	else
	    (void) printf("%s file parsed OK\n", sudoers_path);
    }

    return(parse_error == TRUE);
}

FILE *
open_sudoers(path, keepopen)
    const char *path;
    int *keepopen;
{
    struct sudoersfile *entry;
    FILE *fp;

    /* Check for existing entry */
    for (entry = sudoerslist.first; entry != NULL; entry = entry->next) {
	if (strcmp(path, entry->path) == 0)
	    break;
    }
    if (entry == NULL) {
	entry = emalloc(sizeof(*entry));
	entry->path = estrdup(path);
	entry->modified = 0;
	entry->next = NULL;
	entry->fd = open(entry->path, O_RDWR | O_CREAT, SUDOERS_MODE);
	entry->tpath = NULL;
	if (entry->fd == -1) {
	    warn("%s", entry->path);
	    free(entry);
	    return(NULL);
	}
	if (!lock_file(entry->fd, SUDO_TLOCK))
	    Errx(1, "%s busy, try again later", entry->path);
	if ((fp = fdopen(entry->fd, "r")) == NULL)
	    Err(1, "%s", entry->path);
	if (sudoerslist.last == NULL)
	    sudoerslist.first = sudoerslist.last = entry;
	else {
	    sudoerslist.last->next = entry;
	    sudoerslist.last = entry;
	}
	if (keepopen != NULL)
	    *keepopen = TRUE;
    } else {
	/* Already exists, open .tmp version if there is one. */
	if (entry->tpath != NULL) {
	    if ((fp = fopen(entry->tpath, "r")) == NULL)
		Err(1, "%s", entry->tpath);
	} else {
	    if ((fp = fdopen(entry->fd, "r")) == NULL)
		Err(1, "%s", entry->path);
	}
    }
    return(fp);
}

static char *
get_editor()
{
    char *Editor, *UserEditor, *EditorPath;

    /*
     * Check VISUAL and EDITOR environment variables to see which editor
     * the user wants to use (we may not end up using it though).
     * If the path is not fully-qualified, make it so and check that
     * the specified executable actually exists.
     */
    if ((UserEditor = getenv("VISUAL")) == NULL || *UserEditor == '\0')
	UserEditor = getenv("EDITOR");
    if (UserEditor && *UserEditor == '\0')
	UserEditor = NULL;
    else if (UserEditor) {
	if (find_path(UserEditor, &Editor, NULL, getenv("PATH")) == FOUND) {
	    UserEditor = Editor;
	} else {
	    if (def_env_editor) {
		/* If we are honoring $EDITOR this is a fatal error. */
		warnx("specified editor (%s) doesn't exist!", UserEditor);
		Exit(-1);
	    } else {
		/* Otherwise, just ignore $EDITOR. */
		UserEditor = NULL;
	    }
	}
    }

    /*
     * See if we can use the user's choice of editors either because
     * we allow any $EDITOR or because $EDITOR is in the allowable list.
     */
    Editor = EditorPath = NULL;
    if (def_env_editor && UserEditor)
	Editor = UserEditor;
    else if (UserEditor) {
	struct stat editor_sb;
	struct stat user_editor_sb;
	char *base, *userbase;

	if (stat(UserEditor, &user_editor_sb) != 0) {
	    /* Should never happen since we already checked above. */
	    warn("unable to stat editor (%s)", UserEditor);
	    Exit(-1);
	}
	EditorPath = estrdup(def_editor);
	Editor = strtok(EditorPath, ":");
	do {
	    /*
	     * Both Editor and UserEditor should be fully qualified but
	     * check anyway...
	     */
	    if ((base = strrchr(Editor, '/')) == NULL)
		continue;
	    if ((userbase = strrchr(UserEditor, '/')) == NULL) {
		Editor = NULL;
		break;
	    }
	    base++, userbase++;

	    /*
	     * We compare the basenames first and then use stat to match
	     * for sure.
	     */
	    if (strcmp(base, userbase) == 0) {
		if (stat(Editor, &editor_sb) == 0 && S_ISREG(editor_sb.st_mode)
		    && (editor_sb.st_mode & 0000111) &&
		    editor_sb.st_dev == user_editor_sb.st_dev &&
		    editor_sb.st_ino == user_editor_sb.st_ino)
		    break;
	    }
	} while ((Editor = strtok(NULL, ":")));
    }

    /*
     * Can't use $EDITOR, try each element of def_editor until we
     * find one that exists, is regular, and is executable.
     */
    if (Editor == NULL || *Editor == '\0') {
	if (EditorPath != NULL)
	    free(EditorPath);
	EditorPath = estrdup(def_editor);
	Editor = strtok(EditorPath, ":");
	do {
	    if (sudo_goodpath(Editor, NULL))
		break;
	} while ((Editor = strtok(NULL, ":")));

	/* Bleah, none of the editors existed! */
	if (Editor == NULL || *Editor == '\0') {
	    warnx("no editor found (editor path = %s)", def_editor);
	    Exit(-1);
	}
    }
    return(Editor);
}

/*
 * Iterate through the sudoers datastructures looking for undefined
 * aliases or unused aliases.
 */
static int
check_aliases(strict)
    int strict;
{
    struct cmndspec *cs;
    struct member *m;
    struct privilege *priv;
    struct userspec *us;
    int error = 0;

    /* Forward check. */
    for (us = userspecs; us != NULL; us = us->next) {
	for (m = us->user; m != NULL; m = m->next) {
	    if (m->type == USERALIAS) {
		if (find_alias(m->name, m->type) == NULL) {
		    fprintf(stderr,
			"%s: User_Alias `%s' referenced but not defined\n",
			strict ? "Error" : "Warning", m->name);
		    error++;
		}
	    }
	}
	for (priv = us->privileges; priv != NULL; priv = priv->next) {
	    for (m = priv->hostlist; m != NULL; m = m->next) {
		if (m->type == HOSTALIAS) {
		    if (find_alias(m->name, m->type) == NULL) {
			fprintf(stderr,
			    "%s: Host_Alias `%s' referenced but not defined\n",
			    strict ? "Error" : "Warning", m->name);
			error++;
		    }
		}
	    }
	    for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
		for (m = cs->runaslist; m != NULL; m = m->next) {
		    if (m->type == RUNASALIAS) {
			if (find_alias(m->name, m->type) == NULL) {
			    fprintf(stderr,
				"%s: Runas_Alias `%s' referenced but not defined\n",
				strict ? "Error" : "Warning", m->name);
			    error++;
			}
		    }
		}
		if ((m = cs->cmnd)->type == CMNDALIAS) {
		    if (find_alias(m->name, m->type) == NULL) {
			fprintf(stderr,
			    "%s: Cmnd_Alias `%s' referenced but not defined\n",
			    strict ? "Error" : "Warning", m->name);
			error++;
		    }
		}
	    }
	}
    }

    /* Reverse check (destructive) */
    for (us = userspecs; us != NULL; us = us->next) {
	for (m = us->user; m != NULL; m = m->next) {
	    if (m->type == USERALIAS)
		(void) alias_remove(m->name, m->type);
	}
	for (priv = us->privileges; priv != NULL; priv = priv->next) {
	    for (m = priv->hostlist; m != NULL; m = m->next) {
		if (m->type == HOSTALIAS)
		    (void) alias_remove(m->name, m->type);
	    }
	    for (cs = priv->cmndlist; cs != NULL; cs = cs->next) {
		for (m = cs->runaslist; m != NULL; m = m->next) {
		    if (m->type == RUNASALIAS)
			(void) alias_remove(m->name, m->type);
		}
		if ((m = cs->cmnd)->type == CMNDALIAS)
		    (void) alias_remove(m->name, m->type);
	    }
	}
    }
    /* If all aliases were referenced we will have an empty tree. */
    if (no_aliases())
	return(0);
    alias_apply(print_unused, strict ? "Error" : "Warning");
    return (strict ? 1 : 0);
}

int
print_unused(v1, v2)
    VOID *v1;
    VOID *v2;
{
    struct alias *a = (struct alias *)v1;
    char *prefix = (char *)v2;

    fprintf(stderr, "%s: unused %s_Alias %s\n", prefix,
	a->type == HOSTALIAS ? "Host" : a->type == CMNDALIAS ? "Cmnd" :
	a->type == USERALIAS ? "User" : a->type == RUNASALIAS ? "Runas" :
	"Unknown", a->name);
    return(0);
}

/*
 * Unlink the sudoers temp file (if it exists) and exit.
 * Used in place of a normal exit() and as a signal handler.
 * A positive parameter indicates we were called as a signal handler.
 */
static RETSIGTYPE
Exit(sig)
    int sig;
{
    struct sudoersfile *sp;

    for (sp = sudoerslist.first; sp != NULL; sp = sp->next) {
	if (sp->tpath != NULL)
	    (void) unlink(sp->tpath);
    }

#define	emsg	 " exiting due to signal.\n"
    if (sig > 0) {
	write(STDERR_FILENO, getprogname(), strlen(getprogname()));
	write(STDERR_FILENO, emsg, sizeof(emsg) - 1);
	_exit(sig);
    }
    exit(-sig);
}

/*
 * Like err() but calls Exit()
 */
void
#ifdef __STDC__
Err(int eval, const char *fmt, ...)
#else
Err(eval, fmt, va_alist)
	int eval;
	const char *fmt;
	va_dcl
#endif
{
	va_list ap;
#ifdef __STDC__
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	vwarn(fmt, ap);
	va_end(ap);
	Exit(-eval);
}

/*
 * Like errx() but calls Exit()
 */
void
#ifdef __STDC__
Errx(int eval, const char *fmt, ...)
#else
Errx(eval, fmt, va_alist)
	int eval;
	const char *fmt;
	va_dcl
#endif
{
	va_list ap;
#ifdef __STDC__
	va_start(ap, fmt);
#else
	va_start(ap);
#endif
	vwarnx(fmt, ap);
	va_end(ap);
	Exit(-eval);
}

static void
usage()
{
    (void) fprintf(stderr, "usage: %s [-c] [-f sudoers] [-q] [-s] [-V]\n",
	getprogname());
    exit(1);
}
