dnl
dnl AC_LIB_RAW1394_FLAGS
dnl This just unconditionally sets the options.  It should offer an option for
dnl explicitly giving the path to libraw1394 on the configure command line.
dnl
AC_DEFUN(AC_LIB_RAW1394_FLAGS, [
LIBRAW1394_CPPFLAGS=""
LIBRAW1394_CFLAGS=""
LIBRAW1394_LIBS="-lraw1394"

AC_SUBST(LIBRAW1394_CPPFLAGS)
AC_SUBST(LIBRAW1394_CFLAGS)
AC_SUBST(LIBRAW1394_LIBS)
])

dnl
dnl AC_LIB_RAW1394_HEADERS([ACTION_IF_FOUND[,ACTION_IF_NOT_FOUND]])
dnl
AC_DEFUN(AC_LIB_RAW1394_HEADERS, [
AC_REQUIRE([AC_LIB_RAW1394_FLAGS])

ac_libraw1394_save_cppflags=$CPPFLAGS
CPPFLAGS="$LIBRAW1394_CPPFLAGS $CPPFLAGS"

ac_libraw1394_headers=no
AC_CHECK_HEADER(libraw1394/raw1394.h, ac_libraw1394_headers=yes)

CPPFLAGS=$ac_libraw1394_save_cppflags

if test $ac_libraw1394_headers = yes ; then
	ifelse([$1], , :, $1)
else
	ifelse([$2], , :, $2)
fi
])


dnl
dnl AC_LIB_RAW1394_LIBVERSION(MINIMUMVERSION[,ACTION_IF_FOUND[,ACTION_IF_NOT_FOUND]])
dnl
AC_DEFUN(AC_LIB_RAW1394_LIBVERSION, [
AC_REQUIRE([AC_PROG_CC])
AC_REQUIRE([AC_LIB_RAW1394_FLAGS])

ac_libraw1394_save_cppflags=$CPPFLAGS
ac_libraw1394_save_cflags=$CFLAGS
ac_libraw1394_save_libs=$LIBS
CPPFLAGS="$LIBRAW1394_CPPFLAGS $CPPFLAGS"
CFLAGS="$LIBRAW1394_CFLAGS $CFLAGS"
LIBS="$LIBRAW1394_LIBS $LIBS"

ac_libraw1394_versiontest_success=no
ac_libraw1394_ver_symbol=`echo __libraw1394_version_$1 | sed 's/\./_/g'`

AC_TRY_LINK([], [{
	extern char $ac_libraw1394_ver_symbol;
	$ac_libraw1394_ver_symbol++;
}], ac_libraw1394_versiontest_success=yes)

CPPFLAGS=$ac_libraw1394_save_cppflags
CFLAGS=$ac_libraw1394_save_cflags
LIBS=$ac_libraw1394_save_libs

if test $ac_libraw1394_versiontest_success = yes; then
	ifelse([$2], , :, $2)
else
	ifelse([$3], , :, $3)
fi
])


dnl
dnl AC_LIB_RAW1394_RUNTEST(MINIMUMVERSION[,ACTION_IF_FOUND
dnl                        [,ACTION_IF_NOT_FOUND[,ACTION_IF_CROSS_COMPILING]]])
AC_DEFUN(AC_LIB_RAW1394_RUNTEST, [
ac_libraw1394_save_cppflags=$CPPFLAGS
ac_libraw1394_save_cflags=$CFLAGS
ac_libraw1394_save_libs=$LIBS
CPPFLAGS="$LIBRAW1394_CPPFLAGS $CPPFLAGS"
CFLAGS="$LIBRAW1394_CFLAGS $CFLAGS"
LIBS="$LIBRAW1394_LIBS $LIBS"

dnl This program compares two version strings and returns with code 0 if
dnl req_ver <= lib_ver, returns 1 otherwise.
dnl 
dnl "1.23" < "1.23.1"   (missing fields assumed zero)
dnl "1.23pre" <> "1.23" (undefined, do not use text as version)
dnl "1.21" > "1.3"      (no implicit delimiters)
AC_TRY_RUN([
#include <stdlib.h>
#include <libraw1394/raw1394.h>

int main()
{
        char *req_ver, *lib_ver;
        unsigned int req_i, lib_i;

        req_ver = "$1";
        lib_ver = raw1394_get_libversion();

        while (1) {
                req_i = strtoul(req_ver, &req_ver, 10);
                lib_i = strtoul(lib_ver, &lib_ver, 10);

                if (req_i > lib_i) exit(1);
                if (req_i < lib_i) exit(0);

                if (*req_ver != '.' || *lib_ver != '.') exit(0);

                req_ver++;
                lib_ver++;
        }
}
], ac_libraw1394_run=yes, ac_libraw1394_run=no, ac_libraw1394_run=cross)


CPPFLAGS=$ac_libraw1394_save_cppflags
CFLAGS=$ac_libraw1394_save_cflags
LIBS=$ac_libraw1394_save_libs

if test $ac_libraw1394_run = yes; then
	ifelse([$2], , :, $2)
elif test $ac_libraw1394_run = no; then
	ifelse([$3], , :, $3)
else
	ifelse([$4], ,
               AC_MSG_ERROR([no default for cross compiling in libraw1394 runtest macro]),
               [$4])
fi
])

dnl
dnl AC_LIB_RAW1394(MINIMUMVERSION[,ACTION_IF_FOUND[,ACTION_IF_NOT_FOUND]])
dnl
dnl Versions before 0.9 can't be checked, so this will always fail if the
dnl installed libraw1394 is older than 0.9 as if the library weren't found.
dnl
AC_DEFUN(AC_LIB_RAW1394, [

AC_LIB_RAW1394_FLAGS
AC_LIB_RAW1394_HEADERS(ac_libraw1394_found=yes, ac_libraw1394_found=no)

if test $ac_libraw1394_found = yes ; then

AC_MSG_CHECKING(for libraw1394 version >= [$1])
AC_LIB_RAW1394_RUNTEST([$1], , ac_libraw1394_found=no,
                       AC_LIB_RAW1394_LIBVERSION([$1], , ac_libraw1394_found=no))

if test $ac_libraw1394_found = yes ; then
	AC_MSG_RESULT(yes)
	$2
else
	AC_MSG_RESULT(no)
	$3
fi

fi

])
