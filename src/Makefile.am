
# the libraw1394 itself

lib_LTLIBRARIES = libraw1394.la

libraw1394_la_LDFLAGS = -version-info 2:0:0

libraw1394_la_SOURCES =   \
	main.c            \
	eventloop.c       \
	readwrite.c       \
	iso.c             \
	kernel-raw1394.h  \
	raw1394_private.h

# headers to be installed
pkginclude_HEADERS = raw1394.h csr.h

# testlibraw
noinst_PROGRAMS = testlibraw
testlibraw_LDADD = libraw1394.la
