dnl Check to find the mbed TLS headers/libraries

AC_DEFUN([ss_MBEDTLS],
[

  AC_ARG_WITH(mbedtls,
    AS_HELP_STRING([--with-mbedtls=DIR], [mbed TLS base directory, or:]),
    [mbedtls="$withval"
     CFLAGS="$CFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"]
  )

  AC_ARG_WITH(mbedtls-include,
    AS_HELP_STRING([--with-mbedtls-include=DIR], [mbed TLS headers directory (without trailing /mbedtls)]),
    [mbedtls_include="$withval"
     CFLAGS="$CFLAGS -I$withval"]
  )

  AC_ARG_WITH(mbedtls-lib,
    AS_HELP_STRING([--with-mbedtls-lib=DIR], [mbed TLS library directory]),
    [mbedtls_lib="$withval"
     LDFLAGS="$LDFLAGS -L$withval"]
  )

  AC_CHECK_LIB(mbedcrypto, mbedtls_cipher_setup,
    [LIBS="-lmbedcrypto $LIBS"],
    [AC_MSG_ERROR([mbed TLS libraries not found.])]
  )

  AC_MSG_CHECKING([whether mbedtls support Cipher Feedback mode or not])
  AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [[
#include <mbedtls/config.h>
      ]],
      [[
#ifndef MBEDTLS_CIPHER_MODE_CFB
#error Cipher Feedback mode a.k.a CFB not supported by your mbed TLS.
#endif
      ]]
    )],
    [AC_MSG_RESULT([ok])],
    [AC_MSG_ERROR([MBEDTLS_CIPHER_MODE_CFB required])]
  )
])
