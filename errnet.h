#ifndef __ERRNET_H__
#define __ERRNET_H__

#ifdef __MINGW32__
#include <stdarg.h>
#include <stdnoreturn.h>
void vwarnnet(const char *fmt, va_list args);
void noreturn verrnet(int eval, const char *fmt, va_list args);
void warnnet(const char *fmt, ...);
void noreturn errnet(int eval, const char *fmt, ...);
#else
#define vwarnnet vwarn
#define verrnet verr
#define warnnet warn
#define errnet err
#endif

#endif
