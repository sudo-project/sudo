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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
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
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <stdarg.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifdef HAVE_GETOPT_LONG
# include <getopt.h>
# else
# include "compat/getopt.h"
#endif /* HAVE_GETOPT_LONG */

#include "sudoers.h"
#include "parse.h"
#include "redblack.h"
#include "sudoers_version.h"
#include "sudo_conf.h"
#include <gram.h>

struct sudoersfile {
    TAILQ_ENTRY(sudoersfile) entries;
    char *path;
    char *tpath;
    int fd;
    int modified;
    int doedit;
};
TAILQ_HEAD(sudoersfile_list, sudoersfile);

/*
 * Function prototypes
 */
static void quit(int);
static char *get_args(char *);
static char *get_editor(char **);
static void get_hostname(void);
static int whatnow(void);
static int check_aliases(bool, bool);
static bool check_syntax(char *, bool, bool, bool);
static bool edit_sudoers(struct sudoersfile *, char *, char *, int);
static bool install_sudoers(struct sudoersfile *, bool);
static int print_unused(void *, void *);
static bool reparse_sudoers(char *, char *, bool, bool);
static int run_command(char *, char **);
static void setup_signals(void);
static void help(void) __attribute__((__noreturn__));
static void usage(int);
static void visudo_cleanup(void);

extern bool export_sudoers(const char *, const char *, bool, bool);

extern void sudoerserror(const char *);
extern void sudoersrestart(FILE *);

/*
 * Globals
 */
struct sudo_user sudo_user;
struct passwd *list_pw;
static struct sudoersfile_list sudoerslist = TAILQ_HEAD_INITIALIZER(sudoerslist);
static struct rbtree *alias_freelist;
static bool checkonly;
static const char short_opts[] =  "cf:hqsVx:";
static struct option long_opts[] = {
    { "check",		no_argument,		NULL,	'c' },
    { "export",		required_argument,	NULL,	'x' },
    { "file",		required_argument,	NULL,	'f' },
    { "help",		no_argument,		NULL,	'h' },
    { "quiet",		no_argument,		NULL,	'q' },
    { "strict",		no_argument,		NULL,	's' },
    { "version",	no_argument,		NULL,	'V' },
    { NULL,		no_argument,		NULL,	'\0' },
};

__dso_public int main(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
    struct sudoersfile *sp;
    char *args, *editor, *sudoers_path;
    int ch, exitcode = 0;
    bool quiet, strict, oldperms;
    const char *export_path;
    debug_decl(main, SUDO_DEBUG_MAIN)

#if defined(SUDO_DEVEL) && defined(__OpenBSD__)
    {
	extern char *malloc_options;
	malloc_options = "AFGJPR";
    }
#endif

    initprogname(argc > 0 ? argv[0] : "visudo");
    sudoers_initlocale(setlocale(LC_ALL, ""), def_sudoers_locale);
    bindtextdomain("sudoers", LOCALEDIR); /* XXX - should have visudo domain */
    textdomain("sudoers");

    if (argc < 1)
	usage(1);

    /* Register fatal/fatalx callback. */
    fatal_callback_register(visudo_cleanup);

    /* Read sudo.conf. */
    sudo_conf_read(NULL);

    /*
     * Arg handling.
     */
    checkonly = oldperms = quiet = strict = false;
    export_path = NULL;
    sudoers_path = _PATH_SUDOERS;
    while ((ch = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
	switch (ch) {
	    case 'V':
		(void) printf(_("%s version %s\n"), getprogname(),
		    PACKAGE_VERSION);
		(void) printf(_("%s grammar version %d\n"), getprogname(),
		    SUDOERS_GRAMMAR_VERSION);
		goto done;
	    case 'c':
		checkonly = true;	/* check mode */
		break;
	    case 'f':
		sudoers_path = optarg;	/* sudoers file path */
		oldperms = true;
		break;
	    case 'h':
		help();
		break;
	    case 's':
		strict = true;		/* strict mode */
		break;
	    case 'q':
		quiet = true;		/* quiet mode */
		break;
	    case 'x':
		export_path = optarg;	/* export mode */
		break;
	    default:
		usage(1);
	}
    }
    /* There should be no other command line arguments. */
    if (argc - optind != 0)
	usage(1);

    sudo_setpwent();
    sudo_setgrent();

    /* Mock up a fake sudo_user struct. */
    user_cmnd = user_base = "";
    if ((sudo_user.pw = sudo_getpwuid(getuid())) == NULL)
	fatalx(U_("you do not exist in the %s database"), "passwd");
    get_hostname();

    /* Setup defaults data structures. */
    init_defaults();

    if (checkonly) {
	exitcode = check_syntax(sudoers_path, quiet, strict, oldperms) ? 0 : 1;
	goto done;
    }
    if (export_path != NULL) {
	exitcode = export_sudoers(sudoers_path, export_path, quiet, strict) ? 0 : 1;
	goto done;
    }

    /*
     * Parse the existing sudoers file(s) to highlight any existing
     * errors and to pull in editor and env_editor conf values.
     */
    if ((sudoersin = open_sudoers(sudoers_path, true, NULL)) == NULL)
	exit(1);
    init_parser(sudoers_path, false);
    sudoersparse();
    (void) update_defaults(SETDEF_GENERIC|SETDEF_HOST|SETDEF_USER);

    editor = get_editor(&args);

    /* Install signal handlers to clean up temp files if we are killed. */
    setup_signals();

    /* Edit the sudoers file(s) */
    TAILQ_FOREACH(sp, &sudoerslist, entries) {
	if (!sp->doedit)
	    continue;
	if (sp != TAILQ_FIRST(&sudoerslist)) {
	    printf(_("press return to edit %s: "), sp->path);
	    while ((ch = getchar()) != EOF && ch != '\n')
		    continue;
	}
	edit_sudoers(sp, editor, args, -1);
    }

    /*
     * Check edited files for a parse error, re-edit any that fail
     * and install the edited files as needed.
     */
    if (reparse_sudoers(editor, args, strict, quiet)) {
	TAILQ_FOREACH(sp, &sudoerslist, entries) {
	    (void) install_sudoers(sp, oldperms);
	}
    }

done:
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, exitcode);
    exit(exitcode);
}

/*
 * List of editors that support the "+lineno" command line syntax.
 * If an entry starts with '*' the tail end of the string is matched.
 * No other wild cards are supported.
 */
static char *lineno_editors[] = {
    "ex",
    "nex",
    "vi",
    "nvi",
    "vim",
    "elvis",
    "*macs",
    "mg",
    "vile",
    "jove",
    "pico",
    "nano",
    "ee",
    "joe",
    "zile",
    NULL
};

/*
 * Edit each sudoers file.
 * Returns true on success, else false.
 */
static bool
edit_sudoers(struct sudoersfile *sp, char *editor, char *args, int lineno)
{
    int tfd;				/* sudoers temp file descriptor */
    bool modified;			/* was the file modified? */
    int ac;				/* argument count */
    char **av;				/* argument vector for run_command */
    char *cp;				/* scratch char pointer */
    char buf[PATH_MAX*2];		/* buffer used for copying files */
    char linestr[64];			/* string version of lineno */
    struct timeval tv, tv1, tv2;	/* time before and after edit */
    struct timeval orig_mtim;		/* starting mtime of sudoers file */
    off_t orig_size;			/* starting size of sudoers file */
    ssize_t nread;			/* number of bytes read */
    struct stat sb;			/* stat buffer */
    bool rval = false;			/* return value */
    debug_decl(edit_sudoers, SUDO_DEBUG_UTIL)

    if (fstat(sp->fd, &sb) == -1)
	fatal(U_("unable to stat %s"), sp->path);
    orig_size = sb.st_size;
    mtim_get(&sb, &orig_mtim);

    /* Create the temp file if needed and set timestamp. */
    if (sp->tpath == NULL) {
	easprintf(&sp->tpath, "%s.tmp", sp->path);
	tfd = open(sp->tpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (tfd < 0)
	    fatal("%s", sp->tpath);

	/* Copy sp->path -> sp->tpath and reset the mtime. */
	if (orig_size != 0) {
	    (void) lseek(sp->fd, (off_t)0, SEEK_SET);
	    while ((nread = read(sp->fd, buf, sizeof(buf))) > 0)
		if (write(tfd, buf, nread) != nread)
		    fatal(U_("write error"));

	    /* Add missing newline at EOF if needed. */
	    if (nread > 0 && buf[nread - 1] != '\n') {
		buf[0] = '\n';
		if (write(tfd, buf, 1) != 1)
		    fatal(U_("write error"));
	    }
	}
	(void) close(tfd);
    }
    (void) touch(-1, sp->tpath, &orig_mtim);

    /* Does the editor support +lineno? */
    if (lineno > 0)
    {
	char *editor_base = strrchr(editor, '/');
	if (editor_base != NULL)
	    editor_base++;
	else
	    editor_base = editor;
	if (*editor_base == 'r')
	    editor_base++;

	for (av = lineno_editors; (cp = *av) != NULL; av++) {
	    /* We only handle a leading '*' wildcard. */
	    if (*cp == '*') {
		size_t blen = strlen(editor_base);
		size_t clen = strlen(++cp);
		if (blen >= clen) {
		    if (strcmp(cp, editor_base + blen - clen) == 0)
			break;
		}
	    } else if (strcmp(cp, editor_base) == 0)
		break;
	}
	/* Disable +lineno if editor doesn't support it. */
	if (cp == NULL)
	    lineno = -1;
    }

    /* Find the length of the argument vector */
    ac = 3 + (lineno > 0);
    if (args) {
        bool wasblank;

        ac++;
        for (wasblank = false, cp = args; *cp; cp++) {
            if (isblank((unsigned char) *cp))
                wasblank = true;
            else if (wasblank) {
                wasblank = false;
                ac++;
            }
        }
    }

    /* Build up argument vector for the command */
    av = emalloc2(ac, sizeof(char *));
    if ((av[0] = strrchr(editor, '/')) != NULL)
	av[0]++;
    else
	av[0] = editor;
    ac = 1;
    if (lineno > 0) {
	(void) snprintf(linestr, sizeof(linestr), "+%d", lineno);
	av[ac++] = linestr;
    }
    if (args) {
	for ((cp = strtok(args, " \t")); cp; (cp = strtok(NULL, " \t")))
	    av[ac++] = cp;
    }
    av[ac++] = sp->tpath;
    av[ac++] = NULL;

    /*
     * Do the edit:
     *  We cannot check the editor's exit value against 0 since
     *  XPG4 specifies that vi's exit value is a function of the
     *  number of errors during editing (?!?!).
     */
    gettimeofday(&tv1, NULL);
    if (run_command(editor, av) != -1) {
	gettimeofday(&tv2, NULL);
	/*
	 * Sanity checks.
	 */
	if (stat(sp->tpath, &sb) < 0) {
	    warningx(U_("unable to stat temporary file (%s), %s unchanged"),
		sp->tpath, sp->path);
	    goto done;
	}
	if (sb.st_size == 0 && orig_size != 0) {
	    warningx(U_("zero length temporary file (%s), %s unchanged"),
		sp->tpath, sp->path);
	    sp->modified = true;
	    goto done;
	}
    } else {
	warningx(U_("editor (%s) failed, %s unchanged"), editor, sp->path);
	goto done;
    }

    /* Set modified bit if the user changed the file. */
    modified = true;
    mtim_get(&sb, &tv);
    if (orig_size == sb.st_size && sudo_timevalcmp(&orig_mtim, &tv, ==)) {
	/*
	 * If mtime and size match but the user spent no measurable
	 * time in the editor we can't tell if the file was changed.
	 */
	if (sudo_timevalcmp(&tv1, &tv2, !=))
	    modified = false;
    }

    /*
     * If modified in this edit session, mark as modified.
     */
    if (modified)
	sp->modified = modified;
    else
	warningx(U_("%s unchanged"), sp->tpath);

    rval = true;
done:
    debug_return_bool(rval);
}

/*
 * Parse sudoers after editing and re-edit any ones that caused a parse error.
 */
static bool
reparse_sudoers(char *editor, char *args, bool strict, bool quiet)
{
    struct sudoersfile *sp, *last;
    FILE *fp;
    int ch;
    debug_decl(reparse_sudoers, SUDO_DEBUG_UTIL)

    /*
     * Parse the edited sudoers files and do sanity checking
     */
    while ((sp = TAILQ_FIRST(&sudoerslist)) != NULL) {
	last = TAILQ_LAST(&sudoerslist, sudoersfile_list);
	fp = fopen(sp->tpath, "r+");
	if (fp == NULL)
	    fatalx(U_("unable to re-open temporary file (%s), %s unchanged."),
		sp->tpath, sp->path);

	/* Clean slate for each parse */
	init_defaults();
	init_parser(sp->path, quiet);

	/* Parse the sudoers temp file(s) */
	sudoersrestart(fp);
	if (sudoersparse() && !parse_error) {
	    warningx(U_("unabled to parse temporary file (%s), unknown error"),
		sp->tpath);
	    parse_error = true;
	    errorfile = sp->path;
	}
	fclose(sudoersin);
	if (!parse_error) {
	    if (!check_defaults(SETDEF_ALL, quiet) ||
		check_aliases(strict, quiet) != 0) {
		parse_error = true;
		errorfile = NULL;
	    }
	}

	/*
	 * Got an error, prompt the user for what to do now.
	 */
	if (parse_error) {
	    switch (whatnow()) {
	    case 'Q':
		parse_error = false;	/* ignore parse error */
		break;
	    case 'x':
		visudo_cleanup();	/* discard changes */
		debug_return_bool(false);
	    case 'e':
	    default:
		/* Edit file with the parse error */
		TAILQ_FOREACH(sp, &sudoerslist, entries) {
		    if (errorfile == NULL || strcmp(sp->path, errorfile) == 0) {
			edit_sudoers(sp, editor, args, errorlineno);
			if (errorfile != NULL)
			    break;
		    }
		}
		if (errorfile != NULL && sp == NULL) {
		    fatalx(U_("internal error, unable to find %s in list!"),
			sudoers);
		}
		break;
	    }
	}

	/* If any new #include directives were added, edit them too. */
	for (sp = TAILQ_NEXT(last, entries); sp != NULL; sp = TAILQ_NEXT(sp, entries)) {
	    printf(_("press return to edit %s: "), sp->path);
	    while ((ch = getchar()) != EOF && ch != '\n')
		    continue;
	    edit_sudoers(sp, editor, args, errorlineno);
	}

	/* If all sudoers files parsed OK we are done. */
	if (!parse_error)
	    break;
    }

    debug_return_bool(true);
}

/*
 * Set the owner and mode on a sudoers temp file and
 * move it into place.  Returns true on success, else false.
 */
static bool
install_sudoers(struct sudoersfile *sp, bool oldperms)
{
    struct stat sb;
    bool rval = false;
    debug_decl(install_sudoers, SUDO_DEBUG_UTIL)

    if (!sp->modified) {
	/*
	 * No changes but fix owner/mode if needed.
	 */
	(void) unlink(sp->tpath);
	if (!oldperms && fstat(sp->fd, &sb) != -1) {
	    if (sb.st_uid != SUDOERS_UID || sb.st_gid != SUDOERS_GID)
		ignore_result(chown(sp->path, SUDOERS_UID, SUDOERS_GID));
	    if ((sb.st_mode & 0777) != SUDOERS_MODE)
		ignore_result(chmod(sp->path, SUDOERS_MODE));
	}
	rval = true;
	goto done;
    }

    /*
     * Change mode and ownership of temp file so when
     * we move it to sp->path things are kosher.
     */
    if (oldperms) {
	/* Use perms of the existing file.  */
	if (fstat(sp->fd, &sb) == -1)
	    fatal(U_("unable to stat %s"), sp->path);
	if (chown(sp->tpath, sb.st_uid, sb.st_gid) != 0) {
	    warning(U_("unable to set (uid, gid) of %s to (%u, %u)"),
		sp->tpath, (unsigned int)sb.st_uid, (unsigned int)sb.st_gid);
	}
	if (chmod(sp->tpath, sb.st_mode & 0777) != 0) {
	    warning(U_("unable to change mode of %s to 0%o"), sp->tpath,
		(unsigned int)(sb.st_mode & 0777));
	}
    } else {
	if (chown(sp->tpath, SUDOERS_UID, SUDOERS_GID) != 0) {
	    warning(U_("unable to set (uid, gid) of %s to (%u, %u)"),
		sp->tpath, SUDOERS_UID, SUDOERS_GID);
	    goto done;
	}
	if (chmod(sp->tpath, SUDOERS_MODE) != 0) {
	    warning(U_("unable to change mode of %s to 0%o"), sp->tpath,
		SUDOERS_MODE);
	    goto done;
	}
    }

    /*
     * Now that sp->tpath is sane (parses ok) it needs to be
     * rename(2)'d to sp->path.  If the rename(2) fails we try using
     * mv(1) in case sp->tpath and sp->path are on different file systems.
     */
    if (rename(sp->tpath, sp->path) == 0) {
	efree(sp->tpath);
	sp->tpath = NULL;
    } else {
	if (errno == EXDEV) {
	    char *av[4];
	    warningx(U_("%s and %s not on the same file system, using mv to rename"),
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
		warningx(U_("command failed: '%s %s %s', %s unchanged"),
		    _PATH_MV, sp->tpath, sp->path, sp->path);
		(void) unlink(sp->tpath);
		efree(sp->tpath);
		sp->tpath = NULL;
		goto done;
	    }
	    efree(sp->tpath);
	    sp->tpath = NULL;
	} else {
	    warning(U_("error renaming %s, %s unchanged"), sp->tpath, sp->path);
	    (void) unlink(sp->tpath);
	    goto done;
	}
    }
    rval = true;
done:
    debug_return_bool(rval);
}

/* STUB */
void
init_envtables(void)
{
    return;
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
struct interface *get_interfaces(void)
{
    return NULL;
}

/*
 * Assuming a parse error occurred, prompt the user for what they want
 * to do now.  Returns the first letter of their choice.
 */
static int
whatnow(void)
{
    int choice, c;
    debug_decl(whatnow, SUDO_DEBUG_UTIL)

    for (;;) {
	(void) fputs(_("What now? "), stdout);
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
		debug_return_int(choice);
	    default:
		(void) puts(_("Options are:\n"
		    "  (e)dit sudoers file again\n"
		    "  e(x)it without saving changes to sudoers file\n"
		    "  (Q)uit and save changes to sudoers file (DANGER!)\n"));
	}
    }
}

/*
 * Install signal handlers for visudo.
 */
static void
setup_signals(void)
{
    sigaction_t sa;
    debug_decl(setup_signals, SUDO_DEBUG_UTIL)

    /*
     * Setup signal handlers to cleanup nicely.
     */
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = quit;
    (void) sigaction(SIGTERM, &sa, NULL);
    (void) sigaction(SIGHUP, &sa, NULL);
    (void) sigaction(SIGINT, &sa, NULL);
    (void) sigaction(SIGQUIT, &sa, NULL);

    debug_return;
}

static int
run_command(char *path, char **argv)
{
    int status;
    pid_t pid, rv;
    debug_decl(run_command, SUDO_DEBUG_UTIL)

    switch (pid = sudo_debug_fork()) {
	case -1:
	    fatal(U_("unable to execute %s"), path);
	    break;	/* NOTREACHED */
	case 0:
	    sudo_endpwent();
	    sudo_endgrent();
	    closefrom(STDERR_FILENO + 1);
	    execv(path, argv);
	    warning(U_("unable to run %s"), path);
	    _exit(127);
	    break;	/* NOTREACHED */
    }

    do {
	rv = waitpid(pid, &status, 0);
    } while (rv == -1 && errno == EINTR);

    if (rv != -1)
	rv = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    debug_return_int(rv);
}

static bool
check_owner(const char *path, bool quiet)
{
    struct stat sb;
    bool ok = true;
    debug_decl(check_owner, SUDO_DEBUG_UTIL)

    if (stat(path, &sb) == 0) {
	if (sb.st_uid != SUDOERS_UID || sb.st_gid != SUDOERS_GID) {
	    ok = false;
	    if (!quiet) {
		fprintf(stderr,
		    _("%s: wrong owner (uid, gid) should be (%u, %u)\n"),
		    path, SUDOERS_UID, SUDOERS_GID);
		}
	}
	if ((sb.st_mode & 07777) != SUDOERS_MODE) {
	    ok = false;
	    if (!quiet) {
		fprintf(stderr, _("%s: bad permissions, should be mode 0%o\n"),
		    path, SUDOERS_MODE);
	    }
	}
    }
    debug_return_bool(ok);
}

static bool
check_syntax(char *sudoers_path, bool quiet, bool strict, bool oldperms)
{
    bool ok = false;
    debug_decl(check_syntax, SUDO_DEBUG_UTIL)

    if (strcmp(sudoers_path, "-") == 0) {
	sudoersin = stdin;
	sudoers_path = "stdin";
    } else if ((sudoersin = fopen(sudoers_path, "r")) == NULL) {
	if (!quiet)
	    warning(U_("unable to open %s"), sudoers_path);
	goto done;
    }
    init_parser(sudoers_path, quiet);
    if (sudoersparse() && !parse_error) {
	if (!quiet)
	    warningx(U_("failed to parse %s file, unknown error"), sudoers_path);
	parse_error = true;
	errorfile = sudoers_path;
    }
    if (!parse_error) {
	if (!check_defaults(SETDEF_ALL, quiet) ||
	    check_aliases(strict, quiet) != 0) {
	    parse_error = true;
	    errorfile = NULL;
	}
    }
    ok = !parse_error;

    if (parse_error) {
	if (!quiet) {
	    if (errorlineno != -1)
		(void) printf(_("parse error in %s near line %d\n"),
		    errorfile, errorlineno);
	    else if (errorfile != NULL)
		(void) printf(_("parse error in %s\n"), errorfile);
	}
    } else {
	struct sudoersfile *sp;

	/* Parsed OK, check mode and owner. */
	if (oldperms || check_owner(sudoers_path, quiet)) {
	    if (!quiet)
		(void) printf(_("%s: parsed OK\n"), sudoers_path);
	} else {
	    ok = false;
	}
	TAILQ_FOREACH(sp, &sudoerslist, entries) {
	    if (oldperms || check_owner(sp->path, quiet)) {
		if (!quiet)
		    (void) printf(_("%s: parsed OK\n"), sp->path);
	    } else {
		ok = false;
	    }
	}
    }

done:
    debug_return_bool(ok);
}

/*
 * Used to open (and lock) the initial sudoers file and to also open
 * any subsequent files #included via a callback from the parser.
 */
FILE *
open_sudoers(const char *path, bool doedit, bool *keepopen)
{
    struct sudoersfile *entry;
    FILE *fp;
    int open_flags;
    debug_decl(open_sudoers, SUDO_DEBUG_UTIL)

    if (checkonly)
	open_flags = O_RDONLY;
    else
	open_flags = O_RDWR | O_CREAT;

    /* Check for existing entry */
    TAILQ_FOREACH(entry, &sudoerslist, entries) {
	if (strcmp(path, entry->path) == 0)
	    break;
    }
    if (entry == NULL) {
	entry = ecalloc(1, sizeof(*entry));
	entry->path = estrdup(path);
	/* entry->modified = 0; */
	entry->fd = open(entry->path, open_flags, SUDOERS_MODE);
	/* entry->tpath = NULL; */
	entry->doedit = doedit;
	if (entry->fd == -1) {
	    warning("%s", entry->path);
	    efree(entry);
	    debug_return_ptr(NULL);
	}
	if (!checkonly && !lock_file(entry->fd, SUDO_TLOCK))
	    fatalx(U_("%s busy, try again later"), entry->path);
	if ((fp = fdopen(entry->fd, "r")) == NULL)
	    fatal("%s", entry->path);
	TAILQ_INSERT_TAIL(&sudoerslist, entry, entries);
    } else {
	/* Already exists, open .tmp version if there is one. */
	if (entry->tpath != NULL) {
	    if ((fp = fopen(entry->tpath, "r")) == NULL)
		fatal("%s", entry->tpath);
	} else {
	    if ((fp = fdopen(entry->fd, "r")) == NULL)
		fatal("%s", entry->path);
	    rewind(fp);
	}
    }
    if (keepopen != NULL)
	*keepopen = true;
    debug_return_ptr(fp);
}

static char *
get_editor(char **args)
{
    char *Editor, *EditorArgs, *EditorPath, *UserEditor, *UserEditorArgs;
    debug_decl(get_editor, SUDO_DEBUG_UTIL)

    /*
     * Check VISUAL and EDITOR environment variables to see which editor
     * the user wants to use (we may not end up using it though).
     * If the path is not fully-qualified, make it so and check that
     * the specified executable actually exists.
     */
    UserEditorArgs = NULL;
    if ((UserEditor = getenv("VISUAL")) == NULL || *UserEditor == '\0')
	UserEditor = getenv("EDITOR");
    if (UserEditor && *UserEditor == '\0')
	UserEditor = NULL;
    else if (UserEditor) {
	UserEditorArgs = get_args(UserEditor);
	if (find_path(UserEditor, &Editor, NULL, getenv("PATH"), 0) == FOUND) {
	    UserEditor = Editor;
	} else {
	    if (def_env_editor) {
		/* If we are honoring $EDITOR this is a fatal error. */
		fatalx(U_("specified editor (%s) doesn't exist"), UserEditor);
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
    Editor = EditorArgs = EditorPath = NULL;
    if (def_env_editor && UserEditor) {
	Editor = UserEditor;
	EditorArgs = UserEditorArgs;
    } else if (UserEditor) {
	struct stat editor_sb;
	struct stat user_editor_sb;
	char *base, *userbase;

	if (stat(UserEditor, &user_editor_sb) != 0) {
	    /* Should never happen since we already checked above. */
	    fatal(U_("unable to stat editor (%s)"), UserEditor);
	}
	EditorPath = estrdup(def_editor);
	Editor = strtok(EditorPath, ":");
	do {
	    EditorArgs = get_args(Editor);
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
	efree(EditorPath);
	EditorPath = estrdup(def_editor);
	Editor = strtok(EditorPath, ":");
	do {
	    EditorArgs = get_args(Editor);
	    if (sudo_goodpath(Editor, NULL))
		break;
	} while ((Editor = strtok(NULL, ":")));

	/* Bleah, none of the editors existed! */
	if (Editor == NULL || *Editor == '\0')
	    fatalx(U_("no editor found (editor path = %s)"), def_editor);
    }
    *args = EditorArgs;
    debug_return_str(Editor);
}

/*
 * Split out any command line arguments and return them.
 */
static char *
get_args(char *cmnd)
{
    char *args;
    debug_decl(get_args, SUDO_DEBUG_UTIL)

    args = cmnd;
    while (*args && !isblank((unsigned char) *args))
	args++;
    if (*args) {
	*args++ = '\0';
	while (*args && isblank((unsigned char) *args))
	    args++;
    }
    debug_return_str(*args ? args : NULL);
}

/*
 * Look up the hostname and set user_host and user_shost.
 */
static void
get_hostname(void)
{
    char *p, thost[HOST_NAME_MAX + 1];
    debug_decl(get_hostname, SUDO_DEBUG_UTIL)

    if (gethostname(thost, sizeof(thost)) != -1) {
	thost[sizeof(thost) - 1] = '\0';
	user_host = estrdup(thost);

	if ((p = strchr(user_host, '.'))) {
	    *p = '\0';
	    user_shost = estrdup(user_host);
	    *p = '.';
	} else {
	    user_shost = user_host;
	}
    } else {
	user_host = user_shost = "localhost";
    }
    user_runhost = user_host;
    user_srunhost = user_shost;
    debug_return;
}

static bool
alias_remove_recursive(char *name, int type)
{
    struct member *m;
    struct alias *a;
    bool rval = true;
    debug_decl(alias_remove_recursive, SUDO_DEBUG_ALIAS)

    if ((a = alias_remove(name, type)) != NULL) {
	TAILQ_FOREACH(m, &a->members, entries) {
	    if (m->type == ALIAS) {
		if (!alias_remove_recursive(m->name, type))
		    rval = false;
	    }
	}
	rbinsert(alias_freelist, a);
    }
    debug_return_bool(rval);
}

static int
check_alias(char *name, int type, int strict, int quiet)
{
    struct member *m;
    struct alias *a;
    int errors = 0;
    debug_decl(check_alias, SUDO_DEBUG_ALIAS)

    if ((a = alias_get(name, type)) != NULL) {
	/* check alias contents */
	TAILQ_FOREACH(m, &a->members, entries) {
	    if (m->type == ALIAS)
		errors += check_alias(m->name, type, strict, quiet);
	}
	alias_put(a);
    } else {
	if (!quiet) {
	    if (errno == ELOOP) {
		warningx(strict ?
		    U_("Error: cycle in %s_Alias `%s'") :
		    U_("Warning: cycle in %s_Alias `%s'"),
		    type == HOSTALIAS ? "Host" : type == CMNDALIAS ? "Cmnd" :
		    type == USERALIAS ? "User" : type == RUNASALIAS ? "Runas" :
		    "Unknown", name);
	    } else {
		warningx(strict ?
		    U_("Error: %s_Alias `%s' referenced but not defined") :
		    U_("Warning: %s_Alias `%s' referenced but not defined"),
		    type == HOSTALIAS ? "Host" : type == CMNDALIAS ? "Cmnd" :
		    type == USERALIAS ? "User" : type == RUNASALIAS ? "Runas" :
		    "Unknown", name);
	    }
	}
	errors++;
    }

    debug_return_int(errors);
}

/*
 * Iterate through the sudoers datastructures looking for undefined
 * aliases or unused aliases.
 */
static int
check_aliases(bool strict, bool quiet)
{
    struct cmndspec *cs;
    struct member *m;
    struct privilege *priv;
    struct userspec *us;
    struct defaults *d;
    int atype, errors = 0;
    debug_decl(check_aliases, SUDO_DEBUG_ALIAS)

    alias_freelist = rbcreate(alias_compare);

    /* Forward check. */
    TAILQ_FOREACH(us, &userspecs, entries) {
	TAILQ_FOREACH(m, &us->users, entries) {
	    if (m->type == ALIAS) {
		errors += check_alias(m->name, USERALIAS, strict, quiet);
	    }
	}
	TAILQ_FOREACH(priv, &us->privileges, entries) {
	    TAILQ_FOREACH(m, &priv->hostlist, entries) {
		if (m->type == ALIAS) {
		    errors += check_alias(m->name, HOSTALIAS, strict, quiet);
		}
	    }
	    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m->type == ALIAS) {
			    errors += check_alias(m->name, RUNASALIAS, strict, quiet);
			}
		    }
		}
		if (cs->runasgrouplist != NULL) {
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m->type == ALIAS) {
			    errors += check_alias(m->name, RUNASALIAS, strict, quiet);
			}
		    }
		}
		if ((m = cs->cmnd)->type == ALIAS) {
		    errors += check_alias(m->name, CMNDALIAS, strict, quiet);
		}
	    }
	}
    }

    /* Reverse check (destructive) */
    TAILQ_FOREACH(us, &userspecs, entries) {
	TAILQ_FOREACH(m, &us->users, entries) {
	    if (m->type == ALIAS) {
		if (!alias_remove_recursive(m->name, USERALIAS))
		    errors++;
	    }
	}
	TAILQ_FOREACH(priv, &us->privileges, entries) {
	    TAILQ_FOREACH(m, &priv->hostlist, entries) {
		if (m->type == ALIAS) {
		    if (!alias_remove_recursive(m->name, HOSTALIAS))
			errors++;
		}
	    }
	    TAILQ_FOREACH(cs, &priv->cmndlist, entries) {
		if (cs->runasuserlist != NULL) {
		    TAILQ_FOREACH(m, cs->runasuserlist, entries) {
			if (m->type == ALIAS) {
			    if (!alias_remove_recursive(m->name, RUNASALIAS))
				errors++;
			}
		    }
		}
		if (cs->runasgrouplist != NULL) {
		    TAILQ_FOREACH(m, cs->runasgrouplist, entries) {
			if (m->type == ALIAS) {
			    if (!alias_remove_recursive(m->name, RUNASALIAS))
				errors++;
			}
		    }
		}
		if ((m = cs->cmnd)->type == ALIAS) {
		    if (!alias_remove_recursive(m->name, CMNDALIAS))
			errors++;
		}
	    }
	}
    }
    TAILQ_FOREACH(d, &defaults, entries) {
	switch (d->type) {
	    case DEFAULTS_HOST:
		atype = HOSTALIAS;
		break;
	    case DEFAULTS_USER:
		atype = USERALIAS;
		break;
	    case DEFAULTS_RUNAS:
		atype = RUNASALIAS;
		break;
	    case DEFAULTS_CMND:
		atype = CMNDALIAS;
		break;
	    default:
		continue; /* not an alias */
	}
	TAILQ_FOREACH(m, d->binding, entries) {
	    if (m->type == ALIAS) {
		if (!alias_remove_recursive(m->name, atype))
		    errors++;
	    }
	}
    }
    rbdestroy(alias_freelist, alias_free);

    /* If all aliases were referenced we will have an empty tree. */
    if (!no_aliases() && !quiet)
	alias_apply(print_unused, strict ? "Error" : "Warning");

    debug_return_int(strict ? errors : 0);
}

static int
print_unused(void *v1, void *v2)
{
    struct alias *a = (struct alias *)v1;
    char *prefix = (char *)v2;

    warningx_nodebug(U_("%s: unused %s_Alias %s"), prefix,
	a->type == HOSTALIAS ? "Host" : a->type == CMNDALIAS ? "Cmnd" :
	a->type == USERALIAS ? "User" : a->type == RUNASALIAS ? "Runas" :
	"Unknown", a->name);
    return 0;
}

/*
 * Unlink any sudoers temp files that remain.
 */
static void
visudo_cleanup(void)
{
    struct sudoersfile *sp;

    TAILQ_FOREACH(sp, &sudoerslist, entries) {
	if (sp->tpath != NULL)
	    (void) unlink(sp->tpath);
    }
    sudo_endpwent();
    sudo_endgrent();
}

/*
 * Unlink sudoers temp files (if any) and exit.
 */
static void
quit(int signo)
{
    struct sudoersfile *sp;
    struct iovec iov[4];

    TAILQ_FOREACH(sp, &sudoerslist, entries) {
	if (sp->tpath != NULL)
	    (void) unlink(sp->tpath);
    }

#define	emsg	 " exiting due to signal: "
    iov[0].iov_base = (char *)getprogname();
    iov[0].iov_len = strlen(iov[0].iov_base);
    iov[1].iov_base = emsg;
    iov[1].iov_len = sizeof(emsg) - 1;
    iov[2].iov_base = strsignal(signo);
    iov[2].iov_len = strlen(iov[2].iov_base);
    iov[3].iov_base = "\n";
    iov[3].iov_len = 1;
    ignore_result(writev(STDERR_FILENO, iov, 4));
    _exit(signo);
}

static void
usage(int fatal)
{
    (void) fprintf(fatal ? stderr : stdout,
	"usage: %s [-chqsV] [-f sudoers] [-x file]\n", getprogname());
    if (fatal)
	exit(1);
}

static void
help(void)
{
    (void) printf(_("%s - safely edit the sudoers file\n\n"), getprogname());
    usage(0);
    (void) puts(_("\nOptions:\n"
	"  -c, --check       check-only mode\n"
	"  -f, --file=file   specify sudoers file location\n"
	"  -h, --help        display help message and exit\n"
	"  -q, --quiet       less verbose (quiet) syntax error messages\n"
	"  -s, --strict      strict syntax checking\n"
	"  -V, --version     display version information and exit\n"
	"  -x, --export=file export sudoers in JSON format"));
    exit(0);
}
