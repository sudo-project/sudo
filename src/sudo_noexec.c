/*
 * Copyright (c) 2004-2005, 2010-2013 Todd C. Miller <Todd.Miller@courtesan.com>
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
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */
#ifdef HAVE_SPAWN_H
#include <spawn.h>
#endif

#include "missing.h"

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
 * Dummy versions of the exec(3) family of syscalls.  It is not enough
 * to just dummy out execve(2) since some C libraries use direct syscalls
 * for the other functions instead of calling execve(2).  Note that it is
 * still possible to access the real syscalls via the syscall(2) interface
 * but very few programs actually do that.
 */

#define DUMMY_BODY				\
{						\
    errno = EACCES;				\
    return -1;					\
}

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
 * Private versions of the above.
 */
#ifdef HAVE__EXECL
DUMMY_VA(_execl, const char *, const char *)
#endif
#ifdef HAVE___EXECL
DUMMY_VA(__execl, const char *, const char *)
#endif
#ifdef HAVE__EXECLE
DUMMY_VA(_execle, const char *, const char *)
#endif
#ifdef HAVE___EXECLE
DUMMY_VA(__execle, const char *, const char *)
#endif
#ifdef HAVE__EXECLP
DUMMY_VA(_execlp, const char *, const char *)
#endif
#ifdef HAVE___EXECLP
DUMMY_VA(__execlp, const char *, const char *)
#endif
#ifdef HAVE__EXECV
DUMMY2(_execv, const char *, char * const *)
#endif
#ifdef HAVE___EXECV
DUMMY2(__execv, const char *, char * const *)
#endif
#ifdef HAVE__EXECVP
DUMMY2(_execvp, const char *, char * const *)
#endif
#ifdef HAVE___EXECVP
DUMMY2(__execvp, const char *, char * const *)
#endif
#ifdef HAVE__EXECVE
DUMMY3(_execve, const char *, char * const *, char * const *)
#endif
#ifdef HAVE___EXECVE
DUMMY3(__execve, const char *, char * const *, char * const *)
#endif

/*
 * Non-standard exec functions and corresponding private versions.
 */
#ifdef HAVE_EXECVP
DUMMY3(execvP, const char *, const char *, char * const *)
#endif
#ifdef HAVE__EXECVP
DUMMY3(_execvP, const char *, const char *, char * const *)
#endif
#ifdef HAVE___EXECVP
DUMMY3(__execvP, const char *, const char *, char * const *)
#endif

#ifdef HAVE_EXECVPE
DUMMY3(execvpe, const char *, char * const *, char * const *)
#endif
#ifdef HAVE__EXECVPE
DUMMY3(_execvpe, const char *, char * const *, char * const *)
#endif
#ifdef HAVE___EXECVPE
DUMMY3(__execvpe, const char *, char * const *, char * const *)
#endif

#ifdef HAVE_EXECT
DUMMY3(exect, const char *, char * const *, char * const *)
#endif
#ifdef HAVE__EXECT
DUMMY3(_exect, const char *, char * const *, char * const *)
#endif
#ifdef HAVE___EXECT
DUMMY3(__exect, const char *, char * const *, char * const *)
#endif

#ifdef HAVE_FEXECVE
DUMMY3(fexecve, int , char * const *, char * const *)
#endif
#ifdef HAVE__FEXECVE
DUMMY3(_fexecve, int , char * const *, char * const *)
#endif
#ifdef HAVE___FEXECVE
DUMMY3(__fexecve, int , char * const *, char * const *)
#endif

/*
 * posix_spawn, posix_spawnp and any private versions.
 */
#ifdef HAVE_POSIX_SPAWN
DUMMY6(posix_spawn, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif
#ifdef HAVE__POSIX_SPAWN
DUMMY6(_posix_spawn, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif
#ifdef HAVE___POSIX_SPAWN
DUMMY6(__posix_spawn, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif

#ifdef HAVE_POSIX_SPAWNP
DUMMY6(posix_spawnp, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif
#ifdef HAVE_POSIX__SPAWNP
DUMMY6(_posix_spawnp, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif
#ifdef HAVE_POSIX___SPAWNP
DUMMY6(__posix_spawnp, pid_t *, const char *, const posix_spawn_file_actions_t *, const posix_spawnattr_t *, char * const *, char * const *)
#endif
