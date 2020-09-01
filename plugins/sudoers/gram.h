#define END 0
#define COMMAND 257
#define ALIAS 258
#define DEFVAR 259
#define NTWKADDR 260
#define NETGROUP 261
#define USERGROUP 262
#define WORD 263
#define DIGEST 264
#define INCLUDE 265
#define INCLUDEDIR 266
#define DEFAULTS 267
#define DEFAULTS_HOST 268
#define DEFAULTS_USER 269
#define DEFAULTS_RUNAS 270
#define DEFAULTS_CMND 271
#define NOPASSWD 272
#define PASSWD 273
#define NOEXEC 274
#define EXEC 275
#define SETENV 276
#define NOSETENV 277
#define LOG_INPUT 278
#define NOLOG_INPUT 279
#define LOG_OUTPUT 280
#define NOLOG_OUTPUT 281
#define MAIL 282
#define NOMAIL 283
#define FOLLOWLNK 284
#define NOFOLLOWLNK 285
#define ALL 286
#define HOSTALIAS 287
#define CMNDALIAS 288
#define USERALIAS 289
#define RUNASALIAS 290
#define ERROR 291
#define NOMATCH 292
#define CHROOT 293
#define CWD 294
#define TYPE 295
#define ROLE 296
#define PRIVS 297
#define LIMITPRIVS 298
#define CMND_TIMEOUT 299
#define NOTBEFORE 300
#define NOTAFTER 301
#define MYSELF 302
#define SHA224_TOK 303
#define SHA256_TOK 304
#define SHA384_TOK 305
#define SHA512_TOK 306
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
    struct cmndspec *cmndspec;
    struct defaults *defaults;
    struct member *member;
    struct runascontainer *runas;
    struct privilege *privilege;
    struct command_digest *digest;
    struct sudo_command command;
    struct command_options options;
    struct cmndtag tag;
    char *string;
    int tok;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
extern YYSTYPE sudoerslval;
