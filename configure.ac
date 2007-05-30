# process this file with autoconf to get a configure script

AC_INIT(libraw1394, 1.3.0)
AC_CONFIG_SRCDIR(src/raw1394.h)
AM_CONFIG_HEADER(config.h)

dnl Checking if the NEWS file has been updated to reflect the current version.
AM_INIT_AUTOMAKE(check-news)

AC_PROG_CC
AC_PROG_LIBTOOL
AC_PROG_INSTALL

AC_CHECK_SIZEOF(void *, 8)
AC_C_CONST
AC_C_BIGENDIAN

# set the libtool so version numbers
lt_major=10
lt_revision=0
lt_age=2

AC_SUBST(lt_major)
AC_SUBST(lt_revision)
AC_SUBST(lt_age)

dnl Check to see if valgrind is available
AC_ARG_WITH(valgrind, AC_HELP_STRING([--with-valgrind],[compile with valgrind support]))
if test x$with_valgrind = xyes ; then
    AC_CHECK_HEADERS(valgrind/valgrind.h)
fi

#CFLAGS=${CFLAGS:-"-Wall"}
AC_OUTPUT([
Makefile
libraw1394.pc
libraw1394.spec
src/Makefile
tools/Makefile
doc/Makefile
doc/testlibraw.1
doc/sendiso.1
doc/dumpiso.1
doc/isodump.5
debian/Makefile
])
