AM_CFLAGS="-Wall -O0 -g"

AC_INIT([mtllib], [1.1], [jsharvey@verisign.com])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_MACRO_DIR([m4])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_ENABLE_SHARED(yes)
LT_INIT

AC_HEADER_STDC
AC_HEADER_DIRENT
AC_CHECK_HEADERS([stdlib.h stdio.h libintl.h locale.h])
AC_SEARCH_LIBS([EVP_MD_CTX_new], [crypto], ,[AC_MSG_ERROR(an acceptable version of libcrypto was not found)])
AC_SEARCH_LIBS([log10], [m] ,[], AC_MSG_ERROR([libdmtx requires libm]))

if test "${CFLAGS+set}" == set; then
    dnl Remove this or change this to non-debug default before release
    CFLAGS="-fPIC -Wall -Wextra -g -O0"
fi
AC_PROG_CC
dnl AC_PROG_RANLIB
AM_PROG_CC_C_O
AC_CONFIG_FILES([Makefile src/Makefile test/Makefile examples/Makefile])
AC_OUTPUT()
