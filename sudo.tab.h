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
#define RUNAS 267
#define NOPASSWD 268
#define PASSWD 269
#define ALL 270
#define COMMENT 271
#define HOSTALIAS 272
#define CMNDALIAS 273
#define USERALIAS 274
#define RUNASALIAS 275
#define ERROR 276
typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
} YYSTYPE;
extern YYSTYPE yylval;
