# inet_ntoa.m4 serial 19
dnl Copyright (C) 2005-2006, 2008-2013 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([ss_FUNC_INET_NTOA],
[
  AC_REQUIRE([AC_C_RESTRICT])

  dnl Most platforms that provide inet_ntoa define it in libc.
  dnl Solaris 8..10 provide inet_ntoa in libnsl instead.
  dnl Solaris 2.6..7 provide inet_ntoa in libresolv instead.
  HAVE_INET_NTOA=1
  INET_NTOA_LIB=
  ss_save_LIBS=$LIBS
  AC_SEARCH_LIBS([inet_ntoa], [nsl resolv], [],
    [AC_CHECK_FUNCS([inet_ntoa])
     if test $ac_cv_func_inet_ntoa = no; then
       HAVE_INET_NTOA=0
     fi
    ])
  LIBS=$ss_save_LIBS

  if test "$ac_cv_search_inet_ntoa" != "no" \
     && test "$ac_cv_search_inet_ntoa" != "none required"; then
    INET_NTOA_LIB="$ac_cv_search_inet_ntoa"
  fi

  AC_CHECK_HEADERS_ONCE([netdb.h])
  AC_CHECK_DECLS([inet_ntoa],,,
    [[#include <arpa/inet.h>
      #if HAVE_NETDB_H
      # include <netdb.h>
      #endif
    ]])
  if test $ac_cv_have_decl_inet_ntoa = no; then
    HAVE_DECL_INET_NTOA=0
  fi
  AC_SUBST([INET_NTOA_LIB])
])
