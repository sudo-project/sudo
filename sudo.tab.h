#define COMMAND 257
#define ALIAS 258
#define NTWKADDR 259
#define NETGROUP 260
#define USERGROUP 261
#define WORD 262
#define DEFAULTS 263
#define DEFAULTS_HOST 264
#define DEFAULTS_USER 265
#define RUNAS 266
#define NOPASSWD 267
#define PASSWD 268
#define ALL 269
#define COMMENT 270
#define HOSTALIAS 271
#define CMNDALIAS 272
#define USERALIAS 273
#define RUNASALIAS 274
#define ERROR 275
typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
} YYSTYPE;
extern YYSTYPE yylval;
