/*
 * Copyright (c) 2014 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <config.h>

#include <sys/types.h>
#include <sys/time.h>
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
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef TIME_WITH_SYS_TIME
# include <time.h>
#endif
#ifndef HAVE_STRUCT_TIMESPEC
# include "compat/timespec.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include "sudoers.h"
#include "secure_path.h"
#include "check.h"

/* On Linux, CLOCK_MONOTONIC does not run while suspended. */
#if defined(CLOCK_BOOTTIME)
# define SUDO_CLOCK_MONOTONIC	CLOCK_BOOTTIME
#elif defined(CLOCK_MONOTONIC)
# define SUDO_CLOCK_MONOTONIC	CLOCK_MONOTONIC
#else
# define SUDO_CLOCK_MONOTONIC	CLOCK_REALTIME
#endif

static char timestamp_file[PATH_MAX];
static off_t timestamp_hint = (off_t)-1;
static struct timestamp_entry timestamp_key;

/*
 * Returns true if entry matches key, else false.
 */
static bool
ts_match_record(struct timestamp_entry *key, struct timestamp_entry *entry)
{
    debug_decl(ts_match_record, SUDO_DEBUG_AUTH)

    if (entry->version != key->version)
	debug_return_bool(false);
    if (!ISSET(key->flags, TS_ANYUID) && entry->auth_uid != key->auth_uid)
	debug_return_bool(false);
    if (entry->type != key->type)
	debug_return_bool(false);
    switch (entry->type) {
    case TS_GLOBAL:
	/* no ppid or tty to match */
	break;
    case TS_PPID:
	/* verify parent pid */
	if (entry->u.ppid != key->u.ppid)
	    debug_return_bool(false);
	break;
    case TS_TTY:
	if (entry->u.ttydev != key->u.ttydev)
	    debug_return_bool(false);
	break;
    default:
	/* unknown record type, ignore it */
	debug_return_bool(false);
    }
    debug_return_bool(true);
}

/*
 * Searches the time stamp file descriptor for a record that matches key.
 * On success, fills in entry with the matching record and returns true.
 * On failure, returns false.
 *
 * Note that records are searched starting at the current file offset,
 * which may not be the beginning of the file.
 */
static bool
ts_find_record(int fd, struct timestamp_entry *key, struct timestamp_entry *entry)
{
    struct timestamp_entry cur;
    debug_decl(ts_find_record, SUDO_DEBUG_AUTH)

    /*
     * Look for a matching record.
     * We don't match on the sid or actual time stamp.
     */
    while (read(fd, &cur, sizeof(cur)) == sizeof(cur)) {
	if (cur.size != sizeof(cur)) {
	    /* wrong size, seek to start of next record */
	    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO,
		"wrong sized record, got %hu, expected %zu",
		cur.size, sizeof(cur));
	    lseek(fd, (off_t)cur.size - (off_t)sizeof(cur), SEEK_CUR);
	    if (cur.size == 0)
		break;			/* size must be non-zero */
	    continue;
	}
	if (ts_match_record(key, &cur)) {
	    memcpy(entry, &cur, sizeof(struct timestamp_entry));
	    debug_return_bool(true);
	}
    }
    debug_return_bool(false);
}

/*
 * Find matching record to update or append a new one.
 * Returns true if the entry was written successfully, else false.
 */
static bool
ts_update_record(int fd, struct timestamp_entry *entry, off_t timestamp_hint)
{
    struct timestamp_entry cur;
    ssize_t nwritten;
    off_t old_eof = (off_t)-1;
    debug_decl(ts_update_record, SUDO_DEBUG_AUTH)

    /* First try the hint if one is given. */
    if (timestamp_hint != (off_t)-1) {
	if (lseek(fd, timestamp_hint, SEEK_SET) != -1) {
	    if (read(fd, &cur, sizeof(cur)) == sizeof(cur)) {
		if (ts_match_record(entry, &cur)) {
		    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
			"found existing time stamp record using hint");
		    goto found_it;
		}
	    }
	}
    }

    /* Search for matching record. */
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"searching for time stamp record");
    lseek(fd, (off_t)0, SEEK_SET);
    if (ts_find_record(fd, entry, &cur)) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "found existing time stamp record");
found_it:
	/* back up over old record */
	lseek(fd, (off_t)0 - (off_t)cur.size, SEEK_CUR);
    } else {
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "appending new time stamp record");
	old_eof = lseek(fd, (off_t)0, SEEK_CUR);
    }

    /* Overwrite existing record or append to end. */
    nwritten = write(fd, entry, sizeof(struct timestamp_entry));
    if ((size_t)nwritten == sizeof(struct timestamp_entry))
	debug_return_bool(true);

    log_warning(nwritten == -1 ? USE_ERRNO : 0,
	N_("unable to write to %s"), timestamp_file);

    /* Truncate on partial write to be safe. */
    if (nwritten > 0 && old_eof != (off_t)-1) {
	sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	    "short write, truncating partial time stamp record");
	if (ftruncate(fd, old_eof) != 0) {
	    warning(U_("unable to truncate time stamp file to %lld bytes"),
		(long long)old_eof);
	}
    }

    debug_return_bool(false);
}

/*
 * Create a directory and any missing parent directories with the
 * specified mode.
 * Returns true on success.
 * Returns false on failure and displays a warning to stderr.
 */
static bool
ts_mkdirs(char *path, uid_t owner, mode_t mode, mode_t parent_mode, bool quiet)
{
    struct stat sb;
    gid_t parent_gid = 0;
    char *slash = path;
    bool rval = false;
    debug_decl(ts_mkdirs, SUDO_DEBUG_AUTH)

    while ((slash = strchr(slash + 1, '/')) != NULL) {
	*slash = '\0';
	if (stat(path, &sb) != 0) {
	    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
		"mkdir %s, mode 0%o", path, parent_mode);
	    if (mkdir(path, parent_mode) != 0) {
		if (!quiet)
		    warning(U_("unable to mkdir %s"), path);
		goto done;
	    }
	    ignore_result(chown(path, (uid_t)-1, parent_gid));
	} else if (!S_ISDIR(sb.st_mode)) {
	    if (!quiet) {
		warningx(U_("%s exists but is not a directory (0%o)"),
		    path, (unsigned int) sb.st_mode);
	    }
	    goto done;
	} else {
	    /* Inherit gid of parent dir for ownership. */
	    parent_gid = sb.st_gid;
	}
	*slash = '/';
    }
    /* Create final path component. */
    sudo_debug_printf(SUDO_DEBUG_DEBUG|SUDO_DEBUG_LINENO,
	"mkdir %s, mode 0%o", path, mode);
    if (mkdir(path, mode) != 0 && errno != EEXIST) {
	if (!quiet)
	    warning(U_("unable to mkdir %s"), path);
	goto done;
    }
    ignore_result(chown(path, owner, parent_gid));
    rval = true;
done:
    debug_return_bool(rval);
}

/*
 * Check that path is owned by timestamp_uid and not writable by
 * group or other.  If path is missing and make_it is true, create
 * the directory and its parent dirs.
 * Returns true on success or false on failure, setting errno.
 */
static bool
ts_secure_dir(char *path, bool make_it, bool quiet)
{
    struct stat sb;
    bool rval = false;
    debug_decl(ts_secure_dir, SUDO_DEBUG_AUTH)

    sudo_debug_printf(SUDO_DEBUG_INFO|SUDO_DEBUG_LINENO, "checking %s", path);
    switch (sudo_secure_dir(path, timestamp_uid, -1, &sb)) {
    case SUDO_PATH_SECURE:
	rval = true;
	break;
    case SUDO_PATH_MISSING:
	if (make_it && ts_mkdirs(path, timestamp_uid, 0700, 0711, quiet)) {
	    rval = true;
	    break;
	}
	errno = ENOENT;
	break;
    case SUDO_PATH_BAD_TYPE:
	errno = ENOTDIR;
	if (!quiet)
	    warning("%s", path);
	break;
    case SUDO_PATH_WRONG_OWNER:
	if (!quiet) {
	    warningx(U_("%s is owned by uid %u, should be %u"),
		path, (unsigned int) sb.st_uid,
		(unsigned int) timestamp_uid);
	}
	errno = EACCES;
	break;
    case SUDO_PATH_GROUP_WRITABLE:
	if (!quiet)
	    warningx(U_("%s is group writable"), path);
	errno = EACCES;
	break;
    }
    debug_return_bool(rval);
}

/*
 * Fills in the timestamp_file[] global variable.
 * Returns the length of timestamp_file.
 */
int
build_timestamp(struct passwd *pw)
{
    int len;
    debug_decl(build_timestamp, SUDO_DEBUG_AUTH)

    len = snprintf(timestamp_file, sizeof(timestamp_file), "%s/%s",
	def_timestampdir, user_name);
    if (len <= 0 || (size_t)len >= sizeof(timestamp_file)) {
	log_fatal(0, N_("timestamp path too long: %s/%s"),
	    def_timestampdir, user_name);
    }

    debug_return_int(len);
}

/*
 * Update the time on the timestamp file/dir or create it if necessary.
 * Returns true on success or false on failure.
 */
bool
update_timestamp(struct passwd *pw)
{
    struct timestamp_entry entry;
    bool rval = false;
    int fd;
    debug_decl(update_timestamp, SUDO_DEBUG_AUTH)

    /* Zero timeout means don't update the time stamp file. */
    if (def_timestamp_timeout == 0)
	goto done;

    /* Check/create parent directories as needed. */
    if (!ts_secure_dir(def_timestampdir, true, false))
	goto done;

    /* Fill in time stamp. */
    memcpy(&entry, &timestamp_key, sizeof(struct timestamp_entry));
    clock_gettime(SUDO_CLOCK_MONOTONIC, &entry.ts);

    /* Open time stamp file and lock it for exclusive access. */
    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);
    fd = open(timestamp_file, O_RDWR|O_CREAT, 0600);
    if (timestamp_uid != 0)
	restore_perms();
    if (fd == -1) {
	log_warning(USE_ERRNO, N_("unable to open %s"), timestamp_file);
	goto done;
    }

    /* Update record or append a new one. */
    lock_file(fd, SUDO_LOCK);
    ts_update_record(fd, &entry, timestamp_hint);
    close(fd);

    rval = true;

done:
    debug_return_bool(rval);
}

/*
 * Check the timestamp file and directory and return their status.
 * Returns one of TS_CURRENT, TS_OLD, TS_MISSING, TS_NOFILE, TS_ERROR.
 */
int
timestamp_status(struct passwd *pw)
{
    struct timestamp_entry entry;
    struct timespec diff, timeout;
    int status = TS_ERROR;		/* assume the worst */
    struct stat sb;
    int fd = -1;
    debug_decl(timestamp_status, SUDO_DEBUG_AUTH)

    /* Reset time stamp offset hint. */
    timestamp_hint = (off_t)-1;

    /* Zero timeout means ignore time stamp files. */
    if (def_timestamp_timeout == 0) {
	status = TS_OLD;	/* XXX - could also be TS_MISSING */
	goto done;
    }

    /* Ignore time stamp files in an insecure directory. */
    if (!ts_secure_dir(def_timestampdir, false, false)) {
	if (errno != ENOENT) {
	    status = TS_ERROR;
	    goto done;
	}
	status = TS_MISSING;	/* not insecure, just missing */
    }

    /*
     * Create a key used for matching entries in the time stamp file.
     * The actual time stamp in the key is used below as the time "now".
     */
    memset(&timestamp_key, 0, sizeof(timestamp_key));
    timestamp_key.version = TS_VERSION;
    timestamp_key.size = sizeof(timestamp_key);
    timestamp_key.type = TS_GLOBAL;	/* may be overriden below */
    if (pw != NULL) {
	timestamp_key.auth_uid = pw->pw_uid;
    } else {
	timestamp_key.flags = TS_ANYUID;
    }
    timestamp_key.sid = user_sid;
    if (def_tty_tickets) {
	if (user_ttypath != NULL && stat(user_ttypath, &sb) == 0) {
	    /* tty-based time stamp */
	    timestamp_key.type = TS_TTY;
	    timestamp_key.u.ttydev = sb.st_rdev;
	} else {
	    /* ppid-based time stamp */
	    timestamp_key.type = TS_PPID;
	    timestamp_key.u.ppid = getppid();
	}
    }
    clock_gettime(SUDO_CLOCK_MONOTONIC, &timestamp_key.ts);

    /* If the time stamp dir is missing there is nothing to do. */
    if (status == TS_MISSING)
	goto done;

    /* Open time stamp file and lock it for exclusive access. */
    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);
    fd = open(timestamp_file, O_RDWR);
    if (timestamp_uid != 0)
	restore_perms();
    if (fd == -1) {
	status = TS_MISSING;
	goto done;
    }
    lock_file(fd, SUDO_LOCK);

    /* Ignore and clear time stamp file if mtime predates boot time. */
    if (fstat(fd, &sb) == 0) {
	struct timeval boottime, mtime;

	mtim_get(&sb, &mtime);
	if (get_boottime(&boottime) && sudo_timevalcmp(&mtime, &boottime, <)) {
	    ignore_result(ftruncate(fd, (off_t)0));
	    status = TS_MISSING;
	    goto done;
	}
    }

    /* Read existing record, if any. */
    if (!ts_find_record(fd, &timestamp_key, &entry)) {
	status = TS_MISSING;
	goto done;
    }

    /* Set record position hint for use by update_timestamp() */
    timestamp_hint = lseek(fd, (off_t)0, SEEK_CUR);
    if (timestamp_hint != (off_t)-1)
	timestamp_hint -= entry.size;

    if (ISSET(entry.flags, TS_DISABLED)) {
	status = TS_OLD;	/* disabled via sudo -k */
	goto done;
    }

    if (entry.type != TS_GLOBAL && entry.sid != timestamp_key.sid) {
	status = TS_OLD;	/* belongs to different session */
	goto done;
    }

    /* Negative timeouts only expire manually (sudo -k).  */
    if (def_timestamp_timeout < 0) {
	status = TS_CURRENT;
	goto done;
    }

    /* Compare stored time stamp with current time. */
    sudo_timespecsub(&timestamp_key.ts, &entry.ts, &diff);
    timeout.tv_sec = 60 * def_timestamp_timeout;
    timeout.tv_nsec = ((60.0 * def_timestamp_timeout) - (double)timeout.tv_sec)
	* 1000000000.0;
    if (sudo_timespeccmp(&diff, &timeout, <)) {
	status = TS_CURRENT;
#ifdef CLOCK_MONOTONIC
	/* A monotonic clock should never run backwards. */
	if (diff.tv_sec < 0) {
	    log_warning(0, N_("ignoring time stamp from the future"));
	    status = TS_OLD;
	    SET(entry.flags, TS_DISABLED);
	    ts_update_record(fd, &entry, timestamp_hint);
	}
#else
	/* Check for bogus (future) time in the stampfile. */
	sudo_timespecsub(&entry.ts, &timestamp_key.ts, &diff);
	timeout.tv_sec *= 2;
	if (sudo_timespeccmp(&diff, &timeout, >)) {
	    time_t tv_sec = (time_t)entry.ts.tv_sec;
	    log_warning(0,
		N_("time stamp too far in the future: %20.20s"),
		4 + ctime(&tv_sec));
	    status = TS_OLD;
	    SET(entry.flags, TS_DISABLED);
	    ts_update_record(fd, &entry, timestamp_hint);
	}
#endif /* CLOCK_MONOTONIC */
    } else {
	status = TS_OLD;
    }

done:
    if (fd != -1)
	close(fd);
    debug_return_int(status);
}

/*
 * Remove the timestamp entry or file if unlink_it is set.
 */
void
remove_timestamp(bool unlink_it)
{
    struct timestamp_entry entry;
    int fd = -1;
    debug_decl(remove_timestamp, SUDO_DEBUG_AUTH)

    if (build_timestamp(NULL) == -1)
	debug_return;

    /* For "sudo -K" simply unlink the time stamp file. */
    if (unlink_it) {
	(void) unlink(timestamp_file);
	debug_return;
    }

    /*
     * Create a key used for matching entries in the time stamp file.
     */
    memset(&timestamp_key, 0, sizeof(timestamp_key));
    timestamp_key.version = TS_VERSION;
    timestamp_key.size = sizeof(timestamp_key);
    timestamp_key.type = TS_GLOBAL;	/* may be overriden below */
    timestamp_key.flags = TS_ANYUID;
    if (def_tty_tickets) {
	struct stat sb;
	if (user_ttypath != NULL && stat(user_ttypath, &sb) == 0) {
	    /* tty-based time stamp */
	    timestamp_key.type = TS_TTY;
	    timestamp_key.u.ttydev = sb.st_rdev;
	} else {
	    /* ppid-based time stamp */
	    timestamp_key.type = TS_PPID;
	    timestamp_key.u.ppid = getppid();
	}
    }

    /* Open time stamp file and lock it for exclusive access. */
    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);
    fd = open(timestamp_file, O_RDWR);
    if (timestamp_uid != 0)
	restore_perms();
    if (fd == -1)
	goto done;
    lock_file(fd, SUDO_LOCK);

    /*
     * Find matching entries and invalidate them.
     */
    while (ts_find_record(fd, &timestamp_key, &entry)) {
	/* Set record position hint for use by update_timestamp() */
	timestamp_hint = lseek(fd, (off_t)0, SEEK_CUR);
	if (timestamp_hint != (off_t)-1)
	    timestamp_hint -= (off_t)entry.size;
	/* Disable the entry. */
	SET(entry.flags, TS_DISABLED);
	ts_update_record(fd, &entry, timestamp_hint);
    }
    close(fd);

done:
    debug_return;
}

/*
 * Returns true if the user has already been lectured.
 */
bool
already_lectured(int unused)
{
    char status_file[PATH_MAX];
    struct stat sb;
    int len;
    debug_decl(already_lectured, SUDO_DEBUG_AUTH)

    if (ts_secure_dir(def_lecture_status_dir, false, true)) {
	len = snprintf(status_file, sizeof(status_file), "%s/%s",
	    def_lecture_status_dir, user_name);
	if (len <= 0 || (size_t)len >= sizeof(status_file)) {
	    log_fatal(0, N_("lecture status path too long: %s/%s"),
		def_lecture_status_dir, user_name);
	}
	debug_return_bool(stat(status_file, &sb) == 0);
    }
    debug_return_bool(false);
}

/*
 * Create the lecture status file.
 * Returns true on success or false on failure.
 */
bool
set_lectured(void)
{
    char lecture_status[PATH_MAX];
    int len, fd = -1;
    debug_decl(set_lectured, SUDO_DEBUG_AUTH)

    len = snprintf(lecture_status, sizeof(lecture_status), "%s/%s",
	def_lecture_status_dir, user_name);
    if (len <= 0 || (size_t)len >= sizeof(lecture_status)) {
	log_fatal(0, N_("lecture status path too long: %s/%s"),
	    def_lecture_status_dir, user_name);
    }

    /* Sanity check lecture dir and create if missing. */
    if (!ts_secure_dir(def_lecture_status_dir, true, false))
	goto done;

    /* Create lecture file. */
    if (timestamp_uid != 0)
	set_perms(PERM_TIMESTAMP);
    fd = open(lecture_status, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (timestamp_uid != 0)
	restore_perms();
    if (fd != -1)
	close(fd);

done:
    debug_return_bool(fd != -1 ? true : false);
}
