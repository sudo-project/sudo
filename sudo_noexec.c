/*
 * Copyright (c) 2004 Todd C. Miller <Todd.Miller@courtesan.com>
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

#include <errno.h>

#ifndef lint
static const char rcsid[] = "$Sudo$";
#endif /* lint */

/*
 * Dummy versions of the execve() family of syscalls.  We don't need
 * to stub out all of them, just the ones that correspond to actual
 * system calls (which varies by OS).  Note that it is still possible
 * to access the real syscalls via the syscall() interface but very
 * few programs actually do that.
 */

#ifndef errno
extern int errno;
#endif

#define DUMMY(fn, args, atypes)	\
int				\
fn args				\
    atypes			\
{				\
    errno = EACCES;		\
    return(-1);			\
}

DUMMY(execve, (path, argv, envp),
      const char *path; char *const argv[]; char *const envp[];)
DUMMY(_execve, (path, argv, envp),
      const char *path; char *const argv[]; char *const envp[];)
DUMMY(execv, (path, argv, envp),
      const char *path; char *const argv[];)
DUMMY(_execv, (path, argv, envp),
      const char *path; char *const argv[];)
DUMMY(fexecve, (fd, argv, envp),
      int fd; char *const argv[]; char *const envp[];)
DUMMY(_fexecve, (fd, argv, envp),
      int fd; char *const argv[]; char *const envp[];)
