# This file is part of libasyncns.
#
# Copyright 2005-2008 Lennart Poettering
#
# libasyncns is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 2.1 of the
# License, or (at your option) any later version.
#
# libasyncns is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with libasyncns. If not, see
# <http://www.gnu.org/licenses/>.

noinst_LTLIBRARIES = libcork.la

cli_src = cli/commands.c
core_src = core/allocator.c core/error.c core/gc.c \
		   core/hash.c core/ip-address.c core/mempool.c \
		   core/timestamp.c core/u128.c
ds_src = ds/array.c ds/bitset.c ds/buffer.c ds/dllist.c \
		 ds/file-stream.c ds/hash-table.c ds/managed-buffer.c \
		 ds/ring-buffer.c ds/slice.c
posix_src = posix/directory-walker.c posix/env.c posix/exec.c \
			posix/files.c posix/process.c posix/subprocess.c
pthreads_src = pthreads/thread.c

libcork_la_SOURCES = $(cli_src) $(core_src) $(ds_src) \
					 $(posix_src) $(pthreads_src)
libcork_la_CFLAGS = -I$(top_srcdir)/libcork/include -DCORK_API=CORK_LOCAL
					 
libcork_la_LDFLAGS = -static
