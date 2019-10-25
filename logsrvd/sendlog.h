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

#define DEFAULT_PORT_STR	"30344"

/*
 * Indexes into io_fds[] and iolog_names[]
 * The first five must match the IO_EVENT_ defines in iolog.h.
 * XXX - needed?
 */
#define IOFD_STDIN	0
#define IOFD_STDOUT	1
#define IOFD_STDERR	2
#define IOFD_TTYIN	3
#define IOFD_TTYOUT	4
#define IOFD_TIMING	5
#define IOFD_MAX	6

struct timing_closure {
    struct timespec delay;
    int event;
    union {
	struct {
	    int lines;
	    int columns;
	} winsize;
	size_t nbytes;
    } u;
    char *buf;
    size_t bufsize;
};

enum client_state {
    ERROR,
    RECV_HELLO,
    SEND_EXEC,
    SEND_IO,
    SEND_EXIT,
    CLOSING,
    FINISHED
};

/* TODO: share with server */
struct connection_buffer {
    uint8_t *data;		/* pre-allocated data buffer */
    unsigned int size;		/* currently always UINT16_MAX + 2 */
    unsigned int len;
    unsigned int off;
};

struct client_closure {
    struct timespec elapsed;
    struct timespec committed;
    struct timing_closure timing;
    struct connection_buffer read_buf;
    struct connection_buffer write_buf;
    struct sudo_event *read_ev;
    struct sudo_event *write_ev;
    struct log_info *log_info;
    enum client_state state;
};

/* iolog_reader.c */
bool iolog_open(const char *iolog_path);
bool read_io_buf(struct timing_closure *timing);
int read_timing_record(struct timing_closure *timing);
struct log_info *parse_logfile(const char *logfile);
void free_log_info(struct log_info *li);
