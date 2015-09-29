/*
 * Copyright (c) 2004-2005, 2010-2015 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef HAVE_SPAWN_H
#include <spawn.h>
#endif

#include "sudo_compat.h"

#ifdef HAVE___INTERPOSE
/*
 * Mac OS X 10.4 and above has support for library symbol interposition.
 * There is a good explanation of this in the Mac OS X Internals book.
 */
typedef struct interpose_s {
    void *new_func;
    void *orig_func;
} interpose_t;

# define FN_NAME(fn)	dummy_ ## fn
# define INTERPOSE(fn) \
    __attribute__((__used__)) static const interpose_t interpose_ ## fn \
    __attribute__((__section__("__DATA,__interpose"))) = \
	{ (void *)dummy_ ## fn, (void *)fn };
#else
# define FN_NAME(fn)	fn
# define INTERPOSE(fn)
#endif

/*
 * Dummy versions of the exec(3) family of syscalls.  It is not enough to
 * just dummy out execve(2) since many C libraries do not call the public
 * execve(2) interface.  Note that it is still possible to access the real
 * syscalls via the syscall(2) interface, but that is rarely done.
 */

#define DUMMY_BODY				\
{						\
    errno = EACCES;				\
    return -1;					\
}

#define DUMMY1(fn, t1)				\
__dso_public int				\
FN_NAME(fn)(t1 a1)				\
DUMMY_BODY					\
INTERPOSE(fn)

#define DUMMY2(fn, t1, t2)			\
__dso_public int				\
FN_NAME(fn)(t1 a1, t2 a2)			\
DUMMY_BODY					\
INTERPOSE(fn)

#define DUMMY3(fn, t1, t2, t3)			\
__dso_public int				\
FN_NAME(fn)(t1 a1, t2 a2, t3 a3)		\
DUMMY_BODY					\
INTERPOSE(fn)

#define DUMMY6(fn, t1, t2, t3, t4, t5, t6)	\
__dso_public int				\
FN_NAME(fn)(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6)	\
DUMMY_BODY					\
INTERPOSE(fn)

#define DUMMY_VA(fn, t1, t2)			\
__dso_public int				\
FN_NAME(fn)(t1 a1, t2 a2, ...)			\
DUMMY_BODY					\
INTERPOSE(fn)

/*
 * Standard exec(3) family of functions.
 */
DUMMY_VA(execl, const char *, const char *)
DUMMY_VA(execle, const char *, const char *)
DUMMY_VA(execlp, const char *, const char *)
DUMMY2(execv, const char *, char * const *)
DUMMY2(execvp, const char *, char * const *)
DUMMY3(execve, const char *, char * const *, char * const *)

/*
 * Non-standard exec(3) functions and corresponding private versions.
 */
#ifdef HAVE_EXECVP
DUMMY3(execvP, const char *, const char *, char * const *)
#endif
#ifdef HAVE_EXECVPE
DUMMY3(execvpe, const char *, char * const *, char * const *)
#endif
#ifdef HAVE_EXECT
DUMMY3(exect, const char *, char * const *, char * const *)
#endif

/*
 * Not all systems support fexecve(2), posix_spawn(2) and posix_spawnp(2).
 */
#ifdef HAVE_FEXECVE
DUMMY3(fexecve, int , char * const *, char * const *)
#endif
#ifdef HAVE_POSIX_SPAWN
DUMMY6(posix_spawn, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif
#ifdef HAVE_POSIX_SPAWNP
DUMMY6(posix_spawnp, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif

/*
 * system(3) and popen(3).
 * We can't use a wrapper for popen since it returns FILE *, not int.
 */
DUMMY1(system, const char *)

__dso_public FILE *
FN_NAME(popen)(const char *c, const char *t)
{
    errno = EACCES;
    return NULL;
}
INTERPOSE(popen)
