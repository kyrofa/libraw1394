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

AC_ARG_WITH(juju-dir,[  --with-juju-dir=<dir>  Path to juju include files])
if ! test -z "$with_juju_dir" ; then
   JUJU_DIR="$with_juju_dir"
   LIB_SUBDIR=juju
   AC_SUBST(JUJU_DIR)
else
   LIB_SUBDIR=src
fi
AC_SUBST(LIB_SUBDIR)

AC_ARG_WITH(fw-device-prefix,
	[  --with-fw-device-prefix=<prefix>  Prefix of firewire device file names (default "fw").],
	[FW_DEVICE_PREFIX="\"$withval\""], [FW_DEVICE_PREFIX="\"fw\""])
AC_ARG_WITH(fw-device-dir,
	[  --with-fw-device-dir=<dir>  Directory to watch for firewire device files (default "/dev").],
	[FW_DEVICE_DIR="\"$withval\""], [FW_DEVICE_DIR="\"/dev\""])

AC_DEFINE_UNQUOTED(FW_DEVICE_PREFIX, $FW_DEVICE_PREFIX,
	[Prefix of firewire device file names.])
AC_DEFINE_UNQUOTED(FW_DEVICE_DIR, $FW_DEVICE_DIR,
	[Directory to watch for firewire device files.])

#CFLAGS=${CFLAGS:-"-Wall"}
AC_OUTPUT([
Makefile
libraw1394.pc
libraw1394.spec
src/Makefile
juju/Makefile
tools/Makefile
doc/Makefile
doc/testlibraw.1
doc/sendiso.1
doc/dumpiso.1
doc/isodump.5
debian/Makefile
])
