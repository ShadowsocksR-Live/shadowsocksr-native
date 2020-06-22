# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------
# Copyright © 2011-2015, RedJack, LLC.
# All rights reserved.
#
# Please see the COPYING file in this distribution for license details.
# ----------------------------------------------------------------------

set(CMAKE_LEGACY_CYGWIN_WIN32 0)

cmake_minimum_required(VERSION 3.0)
set(PROJECT_NAME shadowsocksr-native)
set(RELEASE_DATE 2015-09-03)
project(${PROJECT_NAME} VERSION 0.6.0 LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(with_crypto_library "mbedtls" CACHE STRING "build with the given crypto library, TYPE=mbedtls")

IF(MSVC)
  include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/win32/include )
ENDIF(MSVC)

add_subdirectory(depends/mbedtls)

include ( cmake/dist.cmake )
include ( configure )

configure_file ( ${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h )
ADD_DEFINITIONS(-DHAVE_CONFIG_H)

add_subdirectory(depends/libsodium)
add_subdirectory(depends/libuv)
add_subdirectory(depends/json-c)
add_subdirectory(depends/uv-mbed/win32)

include_directories( ${CMAKE_CURRENT_BINARY_DIR} )

add_subdirectory(src)
