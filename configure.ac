#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([shadowsocks], [0.9], [max.c.lv@gmail.com])
AC_CONFIG_SRCDIR([encrypt.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for libraries.
AC_SEARCH_LIBS([MD5], [crypto], [ ], AC_MSG_ERROR([libcrypto not found.]))
AC_SEARCH_LIBS([ev_io_start], [ev], [ ], AC_MSG_ERROR([libev not found.]))

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h langinfo.h locale.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h unistd.h])

AC_C_BIGENDIAN

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([malloc memset socket])

AC_CONFIG_MACRO_DIR([m4])


AC_CONFIG_FILES([Makefile])
AC_OUTPUT
