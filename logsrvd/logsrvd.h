/*
 * Copyright (c) 2019 Todd C. Miller <Todd.Miller@courtesan.com>
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

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error protobuf-c version 1.30 or higher required
#endif

#define DEFAULT_PORT	30344
#define IOLOG_DIR	"/var/tmp/iologs"
#define RUNAS_DEFAULT	"root"

/* How often to send an ACK to the client (commit point) in seconds */
#define ACK_FREQUENCY	10

/* Shutdown timeout (in seconds) in case client connections time out. */
#define SHUTDOWN_TIMEO	10

/*
 * Indexes into io_fds[] and iolog_names[]
 * The first five must match the IO_EVENT_ defines in iolog.h.
 */
#define IOFD_STDIN	0
#define IOFD_STDOUT	1
#define IOFD_STDERR	2
#define IOFD_TTYIN	3
#define IOFD_TTYOUT	4
#define IOFD_TIMING	5
#define IOFD_MAX	6

/*
 * Connection status.
 * In the RUNNING state we expect I/O log buffers.
 */
enum connection_status {
    INITIAL,
    RUNNING,
    RESTARTING,
    EXITED,
    SHUTDOWN,
    FLUSHED
};

union sockaddr_union {
    struct sockaddr sa;
    struct sockaddr_in sin;
#ifdef HAVE_STRUCT_IN6_ADDR
    struct sockaddr_in6 sin6;
#endif
};

struct connection_buffer {
    uint8_t *data;		/* pre-allocated data buffer */
    unsigned int size;		/* currently always UINT16_MAX + 2 */
    unsigned int len;
    unsigned int off;
};

/*
 * Per-connection state.
 * TODO: iolog_compress
 */
struct connection_closure {
    TAILQ_ENTRY(connection_closure) entries;
    struct timespec start_time;
    struct timespec elapsed_time;
    struct connection_buffer read_buf;
    struct connection_buffer write_buf;
    struct sudo_event *commit_ev;
    struct sudo_event *read_ev;
    struct sudo_event *write_ev;
    char *iolog_dir;
    int iolog_dir_fd;
    int io_fds[IOFD_MAX];
    int sock;
    enum connection_status state;
};

/* iolog.c */
bool iolog_init(ExecMessage *msg, struct connection_closure *closure);
int store_iobuf(int iofd, IoBuffer *msg, struct connection_closure *closure);
int store_suspend(CommandSuspend *msg, struct connection_closure *closure);
int store_winsize(ChangeWindowSize *msg, struct connection_closure *closure);
void iolog_close(struct connection_closure *closure);
