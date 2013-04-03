bin_PROGRAMS = ss-local ss-server
ss_local_SOURCES = utils.c jconf.c json.c \
				   rc4.c md5.c encrypt.c \
				   local.c
ss_server_SOURCES = utils.c jconf.c json.c \
					rc4.c md5.c encrypt.c \
					server.c
ss_local_LDADD = $(top_builddir)/libev/libev.la
ss_local_LDADD += $(top_builddir)/libasyncns/libasyncns.la
ss_server_LDADD = $(top_builddir)/libev/libev.la
ss_server_LDADD += $(top_builddir)/libasyncns/libasyncns.la
AM_CFLAGS  = -O2 -Wall -fno-strict-aliasing 
AM_CFLAGS += -I$(top_builddir)/libev
AM_CFLAGS += -I$(top_builddir)/libasyncns
