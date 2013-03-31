bin_PROGRAMS = ss-local ss-server
ss_local_SOURCES = utils.c jconf.c json.c \
			 rc4.c rc4.h md5.c md5.h encrypt.c encrypt.h \
			 local.c local.h socks5.h
ss_server_SOURCES = utils.c jconf.c json.c \
			 rc4.c rc4.h md5.c md5.h encrypt.c encrypt.h \
			 server.c server.h socks5.h
AM_CFLAGS  = -O2 -Wall -fno-strict-aliasing 
ACLOCAL_AMFLAGS = -I m4
