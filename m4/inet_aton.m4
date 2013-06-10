# inet_aton.m4 serial 19
dnl Copyright (C) 2005-2006, 2008-2013 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([ss_FUNC_INET_ATON],
[
  AC_REQUIRE([AC_C_RESTRICT])

  dnl Most platforms that provide inet_aton define it in libc.
  dnl Solaris 8..10 provide inet_aton in libnsl instead.
  dnl Solaris 2.6..7 provide inet_aton in libresolv instead.
  HAVE_INET_ATON=1
  INET_ATON_LIB=
  ss_save_LIBS=$LIBS
  AC_SEARCH_LIBS([inet_aton], [nsl resolv], [],
    [AC_CHECK_FUNCS([inet_aton])
     if test $ac_cv_func_inet_aton = no; then
       HAVE_INET_ATON=0
     fi
    ])
  LIBS=$ss_save_LIBS

  if test "$ac_cv_search_inet_aton" != "no" \
     && test "$ac_cv_search_inet_aton" != "none required"; then
    INET_ATON_LIB="$ac_cv_search_inet_aton"
  fi

  AC_CHECK_HEADERS_ONCE([netdb.h])
  AC_CHECK_DECLS([inet_aton],,,
    [[#include <arpa/inet.h>
      #if HAVE_NETDB_H
      # include <netdb.h>
      #endif
    ]])
  if test $ac_cv_have_decl_inet_aton = no; then
    HAVE_DECL_INET_ATON=0
  fi
  AC_SUBST([INET_ATON_LIB])
])
