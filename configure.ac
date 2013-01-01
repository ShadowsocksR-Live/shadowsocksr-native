#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([libev-hello], [0.1], [clowwindy42@gmail.com])
AC_CONFIG_SRCDIR([encrypt.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([MD5], [crypto], [ ], AC_MSG_ERROR([libcrypto not found.]))
AC_SEARCH_LIBS([ev_io_start], [ev], [ ], AC_MSG_ERROR([libev not found.]))

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h langinfo.h locale.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h unistd.h])

[echo -n "checking for little or big endian... " ]
AC_TRY_RUN([
#include <sys/types.h>
int main()
{
	uint16_t  s   = 1;
	uint16_t* ptr = &s;
	uint8_t   n   = *((uint8_t*)ptr);
	return n;     
}
]
, AC_DEFINE([BIGENDIAN], [1], [Define to 1 if system is big endian])
  [echo "big"]
, AC_DEFINE([LITTLEENDIAN], [1], [Define to 1 if system is little endian])
  [echo "little"] 
)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset socket])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
