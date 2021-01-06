/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2008, 2010-2018, 2020-2021 Todd C. Miller <Todd.Miller@sudo.ws>
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

/*
 * This is an open source non-commercial project. Dear PVS-Studio, please check it.
 * PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
 */

#include <config.h>

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# include "compat/stdbool.h"
#endif /* HAVE_STDBOOL_H */

#include "sudo.h"
#include "sudo_exec.h"
#include "sudo_edit.h"

sudo_dso_public int main(int argc, char *argv[], char *envp[]);

static int sesh_sudoedit(int argc, char *argv[]);

/*
 * Exit codes defined in sudo_exec.h:
 *  SESH_SUCCESS (0)         ... successful operation
 *  SESH_ERR_FAILURE (1)     ... unspecified error
 *  SESH_ERR_INVALID (30)    ... invalid -e arg value
 *  SESH_ERR_BAD_PATHS (31)  ... odd number of paths
 *  SESH_ERR_NO_FILES (32)   ... copy error, no files copied
 *  SESH_ERR_SOME_FILES (33) ... copy error, no files copied
 */
int
main(int argc, char *argv[], char *envp[])
{
    int ret;
    debug_decl(main, SUDO_DEBUG_MAIN);

    initprogname(argc > 0 ? argv[0] : "sesh");

    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE_NAME, LOCALEDIR);
    textdomain(PACKAGE_NAME);

    if (argc < 2)
	sudo_fatalx("%s", U_("requires at least one argument"));

    /* Read sudo.conf and initialize the debug subsystem. */
    if (sudo_conf_read(NULL, SUDO_CONF_DEBUG) == -1)
	exit(EXIT_FAILURE);
    sudo_debug_register(getprogname(), NULL, NULL,
	sudo_conf_debug_files(getprogname()));

    if (strcmp(argv[1], "-e") == 0) {
	ret = sesh_sudoedit(argc, argv);
    } else {
	bool login_shell, noexec = false;
	char *cp, *cmnd;
	int fd = -1;

	/* If the first char of argv[0] is '-', we are running a login shell. */
	login_shell = argv[0][0] == '-';

	/* If argv[0] ends in -noexec, pass the flag to sudo_execve() */
	if ((cp = strrchr(argv[0], '-')) != NULL && cp != argv[0])
	    noexec = strcmp(cp, "-noexec") == 0;

	/* If argv[1] is --execfd=%d, extract the fd to exec with. */
	if (strncmp(argv[1], "--execfd=", 9) == 0) {
	    const char *errstr;

	    cp = argv[1] + 9;
	    fd = sudo_strtonum(cp, 0, INT_MAX, &errstr);
	    if (errstr != NULL)
		sudo_fatalx(U_("invalid file descriptor number: %s"), cp);
	    argv++;
	    argc--;
	}

	/* Shift argv and make a copy of the command to execute. */
	argv++;
	argc--;
	if ((cmnd = strdup(argv[0])) == NULL)
	    sudo_fatalx(U_("%s: %s"), __func__, U_("unable to allocate memory"));

	/* If invoked as a login shell, modify argv[0] accordingly. */
	if (login_shell) {
	    if ((cp = strrchr(argv[0], '/')) == NULL)
		sudo_fatal(U_("unable to run %s as a login shell"), argv[0]);
	    *cp = '-';
	    argv[0] = cp;
	}
	sudo_execve(fd, cmnd, argv, envp, noexec);
	sudo_warn(U_("unable to execute %s"), cmnd);
	ret = SESH_ERR_FAILURE;
    }
    sudo_debug_exit_int(__func__, __FILE__, __LINE__, sudo_debug_subsys, ret);
    _exit(ret);
}

/*
 * Destructively parse a string in the format:
 *  uid:gid:groups,...
 *
 * On success, fills in ud and returns true, else false.
 */
static bool
parse_user(char *userstr, struct sudo_cred *cred)
{
    char *cp, *ep;
    const char *errstr;
    debug_decl(parse_user, SUDO_DEBUG_EDIT);

    /* UID */
    cp = userstr;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warnx(U_("%s: %s"), cp, U_("invalid value"));
	debug_return_bool(false);
    }
    *ep++ = '\0';
    cred->uid = cred->euid = sudo_strtoid(cp, &errstr);
    if (errstr != NULL) {
	sudo_warnx(U_("%s: %s"), cp, errstr);
	debug_return_bool(false);
    }

    /* GID */
    cp = ep;
    if ((ep = strchr(cp, ':')) == NULL) {
	sudo_warnx(U_("%s: %s"), cp, U_("invalid value"));
	debug_return_bool(false);
    }
    *ep++ = '\0';
    cred->gid = cred->egid = sudo_strtoid(cp, &errstr);
    if (errstr != NULL) {
	sudo_warnx(U_("%s: %s"), cp, errstr);
	debug_return_bool(false);
    }

    /* group vector */
    cp = ep;
    cred->ngroups = sudo_parse_gids(cp, NULL, &cred->groups);
    if (cred->ngroups == -1)
	debug_return_bool(false);

    debug_return_bool(true);
}

static int
sesh_edit_create_tfiles(int edit_flags, struct sudo_cred *user_cred,
    struct sudo_cred *run_cred, int argc, char *argv[])
{
    int i, fd_src = -1, fd_dst = -1;
    struct timespec times[2];
    struct stat sb;
    debug_decl(sesh_edit_create_tfiles, SUDO_DEBUG_EDIT);

    for (i = 0; i < argc - 1; i += 2) {
	char *path_src = argv[i];
	const char *path_dst = argv[i + 1];

	/*
	 * Try to open the source file for reading.
	 * If it doesn't exist, we'll create an empty destination file.
	 */
	fd_src = sudo_edit_open(path_src, O_RDONLY,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, edit_flags, user_cred, run_cred);
	if (fd_src == -1) {
	    if (errno != ENOENT) {
		if (errno == ELOOP) {
		    sudo_warnx(U_("%s: editing symbolic links is not "
			"permitted"), path_src);
		} else if (errno == EISDIR) {
		    sudo_warnx(U_("%s: editing files in a writable directory "
			"is not permitted"), path_src);
		} else {
		    sudo_warn("%s", path_src);
		}
		goto cleanup;
	    }
	    /* New file, verify parent dir exists and is not writable. */
	    if (!sudo_edit_parent_valid(path_src, edit_flags, user_cred, run_cred))
		goto cleanup;
	}
	if (fd_src == -1) {
	    /* New file. */
	    memset(&sb, 0, sizeof(sb));
	} else if (fstat(fd_src, &sb) == -1 || !S_ISREG(sb.st_mode)) {
	    sudo_warnx(U_("%s: not a regular file"), path_src);
	    goto cleanup;
	}

	/*
	 * Create temporary file using O_EXCL to ensure that temporary
	 * files are created by us and that we do not open any symlinks.
	 */
	fd_dst = open(path_dst, O_WRONLY|O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
	if (fd_dst == -1) {
	    sudo_warn("%s", path_dst);
	    goto cleanup;
	}

	if (fd_src != -1) {
	    if (sudo_copy_file(path_src, fd_src, -1, path_dst, fd_dst, -1) == -1)
		goto cleanup;
	    close(fd_src);
	}

	/* Make mtime on temp file match src (sb filled in above). */
	mtim_get(&sb, times[0]);
	times[1].tv_sec = times[0].tv_sec;
	times[1].tv_nsec = times[0].tv_nsec;
	if (futimens(fd_dst, times) == -1) {
	    if (utimensat(AT_FDCWD, path_dst, times, 0) == -1)
		sudo_warn("%s", path_dst);
	}
	close(fd_dst);
	fd_dst = -1;
    }
    debug_return_int(SESH_SUCCESS);

cleanup:
    /* Remove temporary files. */
    for (i = 0; i < argc - 1; i += 2)
	unlink(argv[i + 1]);
    if (fd_src != -1)
	close(fd_src);
    if (fd_dst != -1)
	close(fd_dst);
    debug_return_int(SESH_ERR_NO_FILES);
}

static int
sesh_edit_copy_tfiles(int edit_flags, struct sudo_cred *user_cred,
    struct sudo_cred *run_cred, int argc, char *argv[])
{
    int i, ret = SESH_SUCCESS;
    int fd_src = -1, fd_dst = -1;
    debug_decl(sesh_edit_copy_tfiles, SUDO_DEBUG_EDIT);

    for (i = 0; i < argc - 1; i += 2) {
	const char *path_src = argv[i];
	char *path_dst = argv[i + 1];
	off_t len_src, len_dst;
	struct stat sb;

	/* Open temporary file for reading. */
	if (fd_src != -1)
	    close(fd_src);
	fd_src = open(path_src, O_RDONLY|O_NONBLOCK|O_NOFOLLOW);
	if (fd_src == -1) {
	    sudo_warn("%s", path_src);
	    ret = SESH_ERR_SOME_FILES;
	    continue;
	}
	/* Make sure the temporary file is safe and has the proper owner. */
	if (!sudo_check_temp_file(fd_src, path_src, run_cred->uid, &sb)) {
	    sudo_warnx(U_("contents of edit session left in %s"), path_src);
	    ret = SESH_ERR_SOME_FILES;
	    continue;
	}
	(void) fcntl(fd_src, F_SETFL, fcntl(fd_src, F_GETFL, 0) & ~O_NONBLOCK);

	/* Create destination file. */
	if (fd_dst != -1)
	    close(fd_dst);
	fd_dst = sudo_edit_open(path_dst, O_WRONLY|O_CREAT,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH, edit_flags, user_cred, run_cred);
	if (fd_dst == -1) {
	    if (errno == ELOOP) {
		sudo_warnx(U_("%s: editing symbolic links is not "
		    "permitted"), path_dst);
	    } else if (errno == EISDIR) {
		sudo_warnx(U_("%s: editing files in a writable directory "
		    "is not permitted"), path_dst);
	    } else {
		sudo_warn("%s", path_dst);
	    }
	    sudo_warnx(U_("contents of edit session left in %s"), path_src);
	    ret = SESH_ERR_SOME_FILES;
	    continue;
	}

	/* sudo_check_temp_file() filled in sb for us. */
	len_src = sb.st_size;
	if (fstat(fd_dst, &sb) != 0) {
	    sudo_warn("%s", path_dst);
	    sudo_warnx(U_("contents of edit session left in %s"), path_src);
	    ret = SESH_ERR_SOME_FILES;
	    continue;
	}
	len_dst = sb.st_size;

	if (sudo_copy_file(path_src, fd_src, len_src, path_dst, fd_dst,
		len_dst) == -1) {
	    sudo_warnx(U_("contents of edit session left in %s"), path_src);
	    ret = SESH_ERR_SOME_FILES;
	    continue;
	}
	unlink(path_src);
    }
    if (fd_src != -1)
	close(fd_src);
    if (fd_dst != -1)
	close(fd_dst);

    debug_return_int(ret);
}

static int
sesh_sudoedit(int argc, char *argv[])
{
    int edit_flags, post, ret;
    struct sudo_cred user_cred, run_cred;
    debug_decl(sesh_sudoedit, SUDO_DEBUG_EDIT);

    memset(&user_cred, 0, sizeof(user_cred));
    memset(&run_cred, 0, sizeof(run_cred));
    edit_flags = CD_SUDOEDIT_FOLLOW;

    /* Check for -h flag (don't follow links). */
    if (argv[2] != NULL && strcmp(argv[2], "-h") == 0) {
	argv++;
	argc--;
	CLR(edit_flags, CD_SUDOEDIT_FOLLOW); // -V753
    }

    /* Check for -w flag (disallow directories writable by the user). */
    if (argv[2] != NULL && strcmp(argv[2], "-w") == 0) {
	SET(edit_flags, CD_SUDOEDIT_CHECKDIR);

	/* Parse uid:gid:gid1,gid2,... */
	if (argv[3] == NULL || !parse_user(argv[3], &user_cred))
	    debug_return_int(SESH_ERR_FAILURE);
	argv += 2;
	argc -= 2;
    }

    if (argc < 3)
	debug_return_int(SESH_ERR_FAILURE);

    /*
     * We need to know whether we are performing the copy operation
     * before or after the editing. Without this we would not know
     * which files are temporary and which are the originals.
     *  post = 0 ... before
     *  post = 1 ... after
     */
    if (strcmp(argv[2], "0") == 0)
	post = 0;
    else if (strcmp(argv[2], "1") == 0)
	post = 1;
    else /* invalid value */
	debug_return_int(SESH_ERR_INVALID);

    /* Align argv & argc to the beginning of the file list. */
    argv += 3;
    argc -= 3;

    /* no files specified, nothing to do */
    if (argc == 0)
	debug_return_int(SESH_SUCCESS);
    /* odd number of paths specified */
    if (argc & 1)
	debug_return_int(SESH_ERR_BAD_PATHS);

    /* Masquerade as sudoedit so the user gets consistent error messages. */
    setprogname("sudoedit");

    /*
     * sudoedit runs us with the effective user-ID and group-ID of
     * the target user as well as with the target user's group list.
     */
    run_cred.uid = run_cred.euid = geteuid();
    run_cred.gid = run_cred.egid = getegid();
    run_cred.ngroups = getgroups(0, NULL); // -V575
    if (run_cred.ngroups > 0) {
	run_cred.groups = reallocarray(NULL, run_cred.ngroups,
	    sizeof(GETGROUPS_T));
	if (run_cred.groups == NULL) {
	    sudo_warnx(U_("%s: %s"), __func__,
		U_("unable to allocate memory"));
	    debug_return_int(SESH_ERR_FAILURE);
	}
	if (getgroups(run_cred.ngroups, run_cred.groups) < 0) {
	    sudo_warn("%s", U_("unable to get group list"));
	    debug_return_int(SESH_ERR_FAILURE);
	}
    } else {
	run_cred.ngroups = 0;
	run_cred.groups = NULL;
    }

    ret = post ?
	sesh_edit_copy_tfiles(edit_flags, &user_cred, &run_cred, argc, argv) :
	sesh_edit_create_tfiles(edit_flags, &user_cred, &run_cred, argc, argv);
    debug_return_int(ret);
}
