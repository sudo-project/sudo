#ifndef	_UTIME_H
#define	_UTIME_H

struct	utimbuf {
	time_t	actime;		/* access time */
	time_t	modtime;	/* mod time */
};

int utime	__P((const char *, const struct utimbuf *));

#endif	/* _UTIME_H */
