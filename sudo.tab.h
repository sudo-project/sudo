typedef union {
    char *string;
    int BOOLEAN;
    struct sudo_command command;
    int tok;
} YYSTYPE;
#define	COMMAND	257
#define	ALIAS	258
#define	NTWKADDR	259
#define	FQHOST	260
#define	NETGROUP	261
#define	USERGROUP	262
#define	NAME	263
#define	RUNAS	264
#define	NOPASSWD	265
#define	PASSWD	266
#define	ALL	267
#define	COMMENT	268
#define	HOSTALIAS	269
#define	CMNDALIAS	270
#define	USERALIAS	271
#define	RUNASALIAS	272
#define	ERROR	273


extern YYSTYPE yylval;
