lib_LTLIBRARIES = libraw1394.la

INCLUDES = -I$(JUJU_DIR)
libraw1394_la_LDFLAGS = -version-info @lt_major@:@lt_revision@:@lt_age@

libraw1394_la_SOURCES = raw1394.c raw1394-iso.c juju.h

pkginclude_HEADERS = ../src/raw1394.h ../src/csr.h ../src/ieee1394.h
