#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <winsock2.h>
#include "errnet.h"

extern const char *__progname;

void vwarnnet(const char *fmt, va_list args)
{
	int errcode = WSAGetLastError();
	char buf[BUFSIZ];

	FormatMessage(
		/* dwFlags 	*/	FORMAT_MESSAGE_FROM_SYSTEM,
		/* lpSource 	*/	NULL,
		/* dwMessageId 	*/	errcode,
		/* dwLanguageId */	0,
		/* lpBuffer 	*/	buf,
		/* nSize 	*/	BUFSIZ,
		/* Arguments 	*/	NULL
	);

	fprintf(stderr, "%s: ", __progname);
	if (fmt) {
		vfprintf(stderr, fmt, args);
		fprintf(stderr, ": ");
	}
	fprintf(stderr, "%s\n", buf);
	WSASetLastError(0);
}

void noreturn verrnet(int eval, const char *fmt, va_list args)
{
	vwarnnet(fmt, args);
	exit(eval);
}

void warnnet(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarnnet(fmt, ap);
	va_end(ap);
}

void noreturn errnet(int eval, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	verrnet(eval, fmt, ap);
	va_end(ap);
}

