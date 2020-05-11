cmake_minimum_required(VERSION 2.4.4)
set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS ON)

project(zlib C)

set(VERSION "1.2.11")

include(CheckTypeSize)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckCSourceCompiles)

check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(stdint.h    HAVE_STDINT_H)
check_include_file(stddef.h    HAVE_STDDEF_H)

#
# Check to see if we have large file support
#
set(CMAKE_REQUIRED_DEFINITIONS -D_LARGEFILE64_SOURCE=1)
# We add these other definitions here because CheckTypeSize.cmake
# in CMake 2.4.x does not automatically do so and we want
# compatibility with CMake 2.4.x.
if(HAVE_SYS_TYPES_H)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -DHAVE_SYS_TYPES_H)
endif()
if(HAVE_STDINT_H)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -DHAVE_STDINT_H)
endif()
if(HAVE_STDDEF_H)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -DHAVE_STDDEF_H)
endif()
check_type_size(off64_t OFF64_T)
if(HAVE_OFF64_T)
   add_definitions(-D_LARGEFILE64_SOURCE=1)
endif()
set(CMAKE_REQUIRED_DEFINITIONS) # clear variable

#
# Check for fseeko
#
check_function_exists(fseeko HAVE_FSEEKO)
if(NOT HAVE_FSEEKO)
    add_definitions(-DNO_FSEEKO)
endif()

#
# Check for unistd.h
#
check_include_file(unistd.h Z_HAVE_UNISTD_H)

set(ZLIB_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

include_directories(${ZLIB_SOURCE_DIR})

if(NOT UNIX)
if(NOT ZLIB_SOURCE_DIR STREQUAL CMAKE_CURRENT_BINARY_DIR)
    # If we're doing an out of source build and the user has a zconf.h
    # in their source tree...
    if(EXISTS ${ZLIB_SOURCE_DIR}/zconf.h)
        message(STATUS "Renaming")
        message(STATUS "    ${ZLIB_SOURCE_DIR}/zconf.h")
        message(STATUS "to 'zconf.h.included' because this file is included with zlib")
        message(STATUS "but CMake generates it automatically in the build directory.")
        file(RENAME ${ZLIB_SOURCE_DIR}/zconf.h ${ZLIB_SOURCE_DIR}/zconf.h.included)
  endif()
endif()
endif(NOT UNIX)

set(ZLIB_PC ${CMAKE_CURRENT_BINARY_DIR}/zlib.pc)
configure_file( ${ZLIB_SOURCE_DIR}/zlib.pc.cmakein
		${ZLIB_PC} @ONLY)
configure_file(	${ZLIB_SOURCE_DIR}/zconf.h.cmakein
		${CMAKE_CURRENT_BINARY_DIR}/zconf.h @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})


#============================================================================
# zlib
#============================================================================

set(ZLIB_PUBLIC_HDRS
    ${CMAKE_CURRENT_BINARY_DIR}/zconf.h
    ${ZLIB_SOURCE_DIR}/zlib.h
)
set(ZLIB_PRIVATE_HDRS
    ${ZLIB_SOURCE_DIR}/crc32.h
    ${ZLIB_SOURCE_DIR}/deflate.h
    ${ZLIB_SOURCE_DIR}/gzguts.h
    ${ZLIB_SOURCE_DIR}/inffast.h
    ${ZLIB_SOURCE_DIR}/inffixed.h
    ${ZLIB_SOURCE_DIR}/inflate.h
    ${ZLIB_SOURCE_DIR}/inftrees.h
    ${ZLIB_SOURCE_DIR}/trees.h
    ${ZLIB_SOURCE_DIR}/zutil.h
)
set(ZLIB_SRCS
    ${ZLIB_SOURCE_DIR}/adler32.c
    ${ZLIB_SOURCE_DIR}/compress.c
    ${ZLIB_SOURCE_DIR}/crc32.c
    ${ZLIB_SOURCE_DIR}/deflate.c
    ${ZLIB_SOURCE_DIR}/gzclose.c
    ${ZLIB_SOURCE_DIR}/gzlib.c
    ${ZLIB_SOURCE_DIR}/gzread.c
    ${ZLIB_SOURCE_DIR}/gzwrite.c
    ${ZLIB_SOURCE_DIR}/inflate.c
    ${ZLIB_SOURCE_DIR}/infback.c
    ${ZLIB_SOURCE_DIR}/inftrees.c
    ${ZLIB_SOURCE_DIR}/inffast.c
    ${ZLIB_SOURCE_DIR}/trees.c
    ${ZLIB_SOURCE_DIR}/uncompr.c
    ${ZLIB_SOURCE_DIR}/zutil.c
)

add_library(zlib STATIC ${ZLIB_SRCS} ${ZLIB_PUBLIC_HDRS} ${ZLIB_PRIVATE_HDRS})
#add_library(zlib SHARED ${ZLIB_SRCS} ${ZLIB_PUBLIC_HDRS} ${ZLIB_PRIVATE_HDRS})

set(ZLIB_INCLUDE_DIR ${ZLIB_SOURCE_DIR} CACHE INTERNAL "zlib library" FORCE)

