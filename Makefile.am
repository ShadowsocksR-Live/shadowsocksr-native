if USE_SYSTEM_SHARED_LIB
SUBDIRS = libcork libipset src doc
else
SUBDIRS = libsodium libcork libipset libudns libev src doc
endif

ACLOCAL_AMFLAGS = -I m4

pkgconfiglibdir = $(libdir)/pkgconfig
pkgconfiglib_DATA = shadowsocks-libev.pc
