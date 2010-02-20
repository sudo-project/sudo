#define COMMAND 257
#define ALIAS 258
#define DEFVAR 259
#define NTWKADDR 260
#define NETGROUP 261
#define USERGROUP 262
#define WORD 263
#define DEFAULTS 264
#define DEFAULTS_HOST 265
#define DEFAULTS_USER 266
#define DEFAULTS_RUNAS 267
#define DEFAULTS_CMND 268
#define NOPASSWD 269
#define PASSWD 270
#define NOEXEC 271
#define EXEC 272
#define SETENV 273
#define NOSETENV 274
#define TRANSCRIPT 275
#define NOTRANSCRIPT 276
#define ALL 277
#define COMMENT 278
#define HOSTALIAS 279
#define CMNDALIAS 280
#define USERALIAS 281
#define RUNASALIAS 282
#define ERROR 283
#define TYPE 284
#define ROLE 285
#ifndef YYSTYPE_DEFINED
#define YYSTYPE_DEFINED
typedef union {
    struct cmndspec *cmndspec;
    struct defaults *defaults;
    struct member *member;
    struct runascontainer *runas;
    struct privilege *privilege;
    struct sudo_command command;
    struct cmndtag tag;
    struct selinux_info seinfo;
    char *string;
    int tok;
} YYSTYPE;
#endif /* YYSTYPE_DEFINED */
extern YYSTYPE yylval;
