# process this file with autoconf to get a configure script

AC_INIT(Makefile.am)
AM_INIT_AUTOMAKE(libraw1394, 1.0.0)
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AM_PROG_LIBTOOL
AC_PROG_INSTALL

AC_CHECK_SIZEOF(void *, 8)
AC_C_CONST
AC_C_BIGENDIAN

# set the libtool so version numbers
lt_major=7
lt_revision=0
lt_age=2

AC_SUBST(lt_major)
AC_SUBST(lt_revision)
AC_SUBST(lt_age)


CFLAGS=${CFLAGS:-"-Wall -O2"}
AC_OUTPUT([
Makefile
libraw1394.pc
src/Makefile
tools/Makefile
doc/Makefile
doc/testlibraw.1
doc/sendiso.1
doc/dumpiso.1
doc/isodump.5
debian/Makefile
])
