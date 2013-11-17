/*
 * Copyright (c) 1993-1996,1998-2005, 2007-2013
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

#include <config.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#ifndef __TANDEM
# include <sys/file.h>
#endif
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
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "check.h"

static struct sudo_tty_info tty_info;
static char timestampdir[PATH_MAX];
static char timestampfile[PATH_MAX];

/*
 * Fills in timestampdir as well as timestampfile if using tty tickets.
 */
int
build_timestamp(struct passwd *pw)
{
    char *dirparent;
    struct stat sb;
    int len;
    debug_decl(build_timestamp, SUDO_DEBUG_AUTH)

    /* Stash the tty's device, session ID and ctime for ticket comparison. */
    if (def_tty_tickets) {
	if (user_ttypath && stat(user_ttypath, &sb) == 0) {
	    tty_info.dev = sb.st_dev;
	    tty_info.ino = sb.st_ino;
	    tty_info.rdev = sb.st_rdev;
	    tty_info.uid = sb.st_uid;
	    tty_info.gid = sb.st_gid;
	}
	tty_info.sid = user_sid;
    }

    dirparent = def_timestampdir;
    timestampfile[0] = '\0';
    len = snprintf(timestampdir, sizeof(timestampdir), "%s/%s", dirparent,
	user_name);
    if (len <= 0 || (size_t)len >= sizeof(timestampdir))
	goto bad;

    /*
     * Timestamp file may be a file in the directory or NUL to use
     * the directory as the timestamp.
     */
    if (def_tty_tickets) {
	char pidbuf[sizeof("pid") + (((sizeof(pid_t) * 8) + 2) / 3)];
	char *p;

	if (user_ttypath == NULL) {
	    /* No tty, use parent pid. */
	    len = snprintf(pidbuf, sizeof(pidbuf), "pid%u",
		(unsigned int)getppid());
	    if (len <= 0 || (size_t)len >= sizeof(pidbuf))
		goto bad;
	    p = pidbuf;
	} else if ((p = strrchr(user_tty, '/'))) {
	    p++;
	} else {
	    p = user_tty;
	}
	if (def_targetpw) {
	    len = snprintf(timestampfile, sizeof(timestampfile), "%s/%s/%s:%s",
		dirparent, user_name, p, runas_pw->pw_name);
	} else {
	    len = snprintf(timestampfile, sizeof(timestampfile), "%s/%s/%s",
		dirparent, user_name, p);
	}
	if (len <= 0 || (size_t)len >= sizeof(timestampfile))
	    goto bad;
    } else if (def_targetpw) {
	len = snprintf(timestampfile, sizeof(timestampfile), "%s/%s/%s",
	    dirparent, user_name, runas_pw->pw_name);
	if (len <= 0 || (size_t)len >= sizeof(timestampfile))
	    goto bad;
    }
    sudo_debug_printf(SUDO_DEBUG_INFO, "using timestamp file %s", timestampfile);

    debug_return_int(len);
bad:
    log_fatal(0, N_("timestamp path too long: %s"),
	*timestampfile ? timestampfile : timestampdir);
    /* NOTREACHED */
    debug_return_int(-1);
}

/*
 * Update the time on the timestamp file/dir or create it if necessary.
 */
bool
update_timestamp(struct passwd *pw)
{
    debug_decl(update_timestamp, SUDO_DEBUG_AUTH)

    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);
    if (*timestampfile) {
	/*
	 * Store tty info in timestamp file
	 */
	int fd = open(timestampfile, O_WRONLY|O_CREAT, 0600);
	if (fd == -1)
	    log_warning(USE_ERRNO, N_("unable to open %s"), timestampfile);
	else {
	    lock_file(fd, SUDO_LOCK);
	    if (write(fd, &tty_info, sizeof(tty_info)) != sizeof(tty_info))
		log_warning(USE_ERRNO, N_("unable to write to %s"), timestampfile);
	    close(fd);
	}
    } else {
	if (touch(-1, timestampdir, NULL) == -1) {
	    if (mkdir(timestampdir, 0700) == -1) {
		log_warning(USE_ERRNO, N_("unable to mkdir %s"),
		    timestampdir);
	    }
	}
    }
    if (timestamp_uid != 0)
	restore_perms();
    debug_return_bool(true);
}

/*
 * Check the timestamp file and directory and return their status.
 */
static int
timestamp_status_internal(bool removing)
{
    struct stat sb;
    struct timeval boottime, mtime;
    time_t now;
    char *dirparent = def_timestampdir;
    int status = TS_ERROR;		/* assume the worst */
    debug_decl(timestamp_status_internal, SUDO_DEBUG_AUTH)

    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);

    /*
     * Sanity check dirparent and make it if it doesn't already exist.
     * We start out assuming the worst (that the dir is not sane) and
     * if it is ok upgrade the status to ``no timestamp file''.
     * Note that we don't check the parent(s) of dirparent for
     * sanity since the sudo dir is often just located in /tmp.
     */
    if (lstat(dirparent, &sb) == 0) {
	if (!S_ISDIR(sb.st_mode))
	    log_warning(0, N_("%s exists but is not a directory (0%o)"),
		dirparent, (unsigned int) sb.st_mode);
	else if (sb.st_uid != timestamp_uid)
	    log_warning(0, N_("%s owned by uid %u, should be uid %u"),
		dirparent, (unsigned int) sb.st_uid,
		(unsigned int) timestamp_uid);
	else if ((sb.st_mode & 0000022))
	    log_warning(0,
		N_("%s writable by non-owner (0%o), should be mode 0700"),
		dirparent, (unsigned int) sb.st_mode);
	else {
	    if ((sb.st_mode & 0000777) != 0700)
		(void) chmod(dirparent, 0700);
	    status = TS_MISSING;
	}
    } else if (errno != ENOENT) {
	log_warning(USE_ERRNO, N_("unable to stat %s"), dirparent);
    } else {
	/* No dirparent, try to make one. */
	if (!removing) {
	    if (mkdir(dirparent, S_IRWXU))
		log_warning(USE_ERRNO, N_("unable to mkdir %s"),
		    dirparent);
	    else
		status = TS_MISSING;
	}
    }
    if (status == TS_ERROR)
	goto done;

    /*
     * Sanity check the user's ticket dir.  We start by downgrading
     * the status to TS_ERROR.  If the ticket dir exists and is sane
     * this will be upgraded to TS_OLD.  If the dir does not exist,
     * it will be upgraded to TS_MISSING.
     */
    status = TS_ERROR;			/* downgrade status again */
    if (lstat(timestampdir, &sb) == 0) {
	if (!S_ISDIR(sb.st_mode)) {
	    if (S_ISREG(sb.st_mode)) {
		/* convert from old style */
		if (unlink(timestampdir) == 0)
		    status = TS_MISSING;
	    } else
		log_warning(0, N_("%s exists but is not a directory (0%o)"),
		    timestampdir, (unsigned int) sb.st_mode);
	} else if (sb.st_uid != timestamp_uid)
	    log_warning(0, N_("%s owned by uid %u, should be uid %u"),
		timestampdir, (unsigned int) sb.st_uid,
		(unsigned int) timestamp_uid);
	else if ((sb.st_mode & 0000022))
	    log_warning(0,
		N_("%s writable by non-owner (0%o), should be mode 0700"),
		timestampdir, (unsigned int) sb.st_mode);
	else {
	    if ((sb.st_mode & 0000777) != 0700)
		(void) chmod(timestampdir, 0700);
	    status = TS_OLD;		/* do date check later */
	}
    } else if (errno != ENOENT) {
	log_warning(USE_ERRNO, N_("unable to stat %s"), timestampdir);
    } else
	status = TS_MISSING;

    /*
     * If there is no user ticket dir, AND we are in tty ticket mode,
     * AND we are not just going to remove it, create the user ticket dir.
     */
    if (status == TS_MISSING && *timestampfile && !removing) {
	if (mkdir(timestampdir, S_IRWXU) == -1) {
	    status = TS_ERROR;
	    log_warning(USE_ERRNO, N_("unable to mkdir %s"), timestampdir);
	}
    }

    /*
     * Sanity check the tty ticket file if it exists.
     */
    if (*timestampfile && status != TS_ERROR) {
	if (status != TS_MISSING)
	    status = TS_NOFILE;			/* dir there, file missing */
	if (lstat(timestampfile, &sb) == 0) {
	    if (!S_ISREG(sb.st_mode)) {
		status = TS_ERROR;
		log_warning(0, N_("%s exists but is not a regular file (0%o)"),
		    timestampfile, (unsigned int) sb.st_mode);
	    } else {
		/* If bad uid or file mode, complain and kill the bogus file. */
		if (sb.st_uid != timestamp_uid) {
		    log_warning(0,
			N_("%s owned by uid %u, should be uid %u"),
			timestampfile, (unsigned int) sb.st_uid,
			(unsigned int) timestamp_uid);
		    (void) unlink(timestampfile);
		} else if ((sb.st_mode & 0000022)) {
		    log_warning(0,
			N_("%s writable by non-owner (0%o), should be mode 0600"),
			timestampfile, (unsigned int) sb.st_mode);
		    (void) unlink(timestampfile);
		} else {
		    /* If not mode 0600, fix it. */
		    if ((sb.st_mode & 0000777) != 0600)
			(void) chmod(timestampfile, 0600);

		    /*
		     * Check for stored tty info.  If the file is zero-sized
		     * it is an old-style timestamp with no tty info in it.
		     * If removing, we don't care about the contents.
		     * The actual mtime check is done later.
		     */
		    if (removing) {
			status = TS_OLD;
		    } else if (sb.st_size != 0) {
			struct sudo_tty_info info;
			int fd = open(timestampfile, O_RDONLY, 0644);
			if (fd != -1) {
			    if (read(fd, &info, sizeof(info)) == sizeof(info) &&
				memcmp(&info, &tty_info, sizeof(info)) == 0) {
				status = TS_OLD;
			    }
			    close(fd);
			}
		    }
		}
	    }
	} else if (errno != ENOENT) {
	    log_warning(USE_ERRNO, N_("unable to stat %s"), timestampfile);
	    status = TS_ERROR;
	}
    }

    /*
     * If the file/dir exists and we are not removing it, check its mtime.
     */
    if (status == TS_OLD && !removing) {
	mtim_get(&sb, &mtime);
	if (timevalisset(&mtime)) {
	    /* Negative timeouts only expire manually (sudo -k). */
	    if (def_timestamp_timeout < 0) {
		status = TS_CURRENT;
	    } else {
		time(&now);
		if (def_timestamp_timeout &&
		    now - mtime.tv_sec < 60 * def_timestamp_timeout) {
		    /*
		     * Check for bogus time on the stampfile.  The clock may
		     * have been set back or user could be trying to spoof us.
		     */
		    if (mtime.tv_sec > now + 60 * def_timestamp_timeout * 2) {
			time_t tv_sec = (time_t)mtime.tv_sec;
			log_warning(0,
			    N_("timestamp too far in the future: %20.20s"),
			    4 + ctime(&tv_sec));
			if (*timestampfile)
			    (void) unlink(timestampfile);
			else
			    (void) rmdir(timestampdir);
			status = TS_MISSING;
		    } else if (get_boottime(&boottime) &&
			timevalcmp(&mtime, &boottime, <)) {
			status = TS_OLD;
		    } else {
			status = TS_CURRENT;
		    }
		}
	    }
	}
    }

done:
    if (timestamp_uid != 0)
	restore_perms();
    debug_return_int(status);
}

int
timestamp_status(struct passwd *pw)
{
    return timestamp_status_internal(false);
}

/*
 * Remove the timestamp ticket file/dir.
 */
void
remove_timestamp(bool remove)
{
    struct timeval tv;
    char *path;
    int status;
    debug_decl(remove_timestamp, SUDO_DEBUG_AUTH)

    if (build_timestamp(NULL) == -1)
	debug_return;

    status = timestamp_status_internal(true);
    if (status != TS_MISSING && status != TS_ERROR) {
	path = *timestampfile ? timestampfile : timestampdir;
	if (remove) {
	    if (*timestampfile)
		status = unlink(timestampfile);
	    else
		status = rmdir(timestampdir);
	    if (status == -1 && errno != ENOENT) {
		log_warning(0,
		    N_("unable to remove %s, will reset to the Unix epoch"),
		    path);
		remove = false;
	    }
	}
	if (!remove) {
	    timevalclear(&tv);
	    if (touch(-1, path, &tv) == -1 && errno != ENOENT)
		fatal(_("unable to reset %s to the Unix epoch"), path);
	}
    }

    debug_return;
}

/*
 * Lecture status is currently implied by the timestamp status but
 * may be stored separately in a future release.
 */
bool
set_lectured(void)
{
    return true;
}
