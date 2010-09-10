/*
 * Copyright (c) 2010 Todd C. Miller <Todd.Miller@courtesan.com>
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

#ifndef _SUDO_EXEC_H
#define _SUDO_EXEC_H

/*
 * Symbols shared between exec.c and exec_pty.c
 */

/* exec.c */
int my_execve __P((const char *path, char *argv[], char *envp[]));
int pipe_nonblock __P((int fds[2]));

/* exec_pty.c */
int fork_pty __P((const char *path, char *argv[], char *envp[], int sv[],
    int rbac_enabled, int *maxfd));
int perform_io __P((fd_set *fdsr, fd_set *fdsw, struct command_status *cstat));
int suspend_parent __P((int signo));
void fd_set_iobs __P((fd_set *fdsr, fd_set *fdsw));
void handler __P((int s));
void pty_close __P((struct command_status *cstat));
void pty_setup __P((uid_t uid));
extern int signal_pipe[2];

#endif /* _SUDO_EXEC_H */
