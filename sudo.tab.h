#define ALIAS 257
#define NTWKADDR 258
#define FQHOST 259
#define NETGROUP 260
#define USERGROUP 261
#define NAME 262
#define RUNAS 263
#define NOPASSWD 264
#define PASSWD 265
#define COMMAND 266
#define COMMENT 267
#define ALL 268
#define HOSTALIAS 269
#define CMNDALIAS 270
#define USERALIAS 271
#define RUNASALIAS 272
#define ERROR 273
typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
} YYSTYPE;
extern YYSTYPE yylval;
