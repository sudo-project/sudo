/*
 * Copyright (c) 1999-2001 Todd C. Miller <Todd.Miller@courtesan.com>
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
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 *
 * $Sudo$
 */

#ifndef _SUDO_DEFAULTS_H
#define _SUDO_DEFAULTS_H

#include <def_data.h>

struct list_member {
    char *value;
    struct list_member *next;
};

struct def_values {
    char *sval;		/* string value */
    int ival;		/* actually an enum */
};

enum list_ops {
    add,
    delete,
    freeall
};

/*
 * Structure describing compile-time and run-time options.
 */
struct sudo_defs_types {
    char *name;
    int type;
    char *desc;
    struct def_values *values;
    int (*callback) __P((char *));
    union {
	int flag;
	int ival;
	enum def_tupple tuple;
	char *str;
	mode_t mode;
	struct list_member *list;
    } sd_un;
};

/*
 * Four types of defaults: strings, integers, and flags.
 * Also, T_INT or T_STR may be ANDed with T_BOOL to indicate that
 * a value is not required.  Flags are boolean by nature...
 */
#undef T_INT
#define T_INT		0x001
#undef T_UINT
#define T_UINT		0x002
#undef T_STR
#define T_STR		0x003
#undef T_FLAG
#define T_FLAG		0x004
#undef T_MODE
#define T_MODE		0x005
#undef T_LIST
#define T_LIST		0x006
#undef T_LOGFAC
#define T_LOGFAC	0x007
#undef T_LOGPRI
#define T_LOGPRI	0x008
#undef T_TUPLE
#define T_TUPLE		0x009
#undef T_MASK
#define T_MASK		0x0FF
#undef T_BOOL
#define T_BOOL		0x100
#undef T_PATH
#define T_PATH		0x200

/*
 * Prototypes
 */
void dump_default	__P((void));
int set_default		__P((char *, char *, int));
void init_defaults	__P((void));
void list_options	__P((void));

extern struct sudo_defs_types sudo_defs_table[];

#endif /* _SUDO_DEFAULTS_H */
