# process this file with automake to create a Makefile.in

SUBDIRS = src doc debian

aclocaldir = @datadir@/aclocal
aclocal_DATA = libraw1394.m4

EXTRA_DIST = libraw1394.m4

doc: psdoc pdfdoc htmldoc

psdoc:
	$(MAKE) -C doc psdoc

pdfdoc:
	$(MAKE) -C doc pdfdoc

htmldoc:
	$(MAKE) -C doc htmldoc

.PHONY: doc psdoc pdfdoc htmldoc

# make required device file
dev:
	mknod -m 600 /dev/raw1394 c 171 0
	chown root.root /dev/raw1394
	@echo
	@echo "/dev/raw1394 created"
	@echo "It is owned by root with permissions 600.  You may want to fix"
	@echo "the group/permission to something appropriate for you."
	@echo "Note however that anyone who can open raw1394 can access all"
	@echo "devices on all connected 1394 buses unrestricted, including"
	@echo "harddisks and other probably sensitive devices."
	@echo

install-exec-hook:
	@if [ ! -c /dev/raw1394 ]; then                              \
		echo;                                                \
		echo "********************************************"; \
		echo "Required /dev/raw1394 device file not found."; \
		echo "Run 'make dev' to create it.";                 \
		echo "********************************************"; \
		echo;                                                \
	fi
