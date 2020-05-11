cmake_minimum_required(VERSION 2.4.4)
set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS ON)

project(pthreads C)

set(VERSION "3.0.2")

include(CheckTypeSize)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckCSourceCompiles)

check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(stdint.h    HAVE_STDINT_H)
check_include_file(stddef.h    HAVE_STDDEF_H)

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)
    add_definitions(-DHAVE_CONFIG_H)
    add_definitions(-DPTW32_RC_MSC)
    if(NOT "${CMAKE_GENERATOR}" MATCHES "(Win64|IA64)")
        add_definitions(-DPTW32_ARCHx64)
    else()
        add_definitions(-DPTW32_ARCHx86)
    endif()
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})

set(PTHREADS_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "pthreads4w library" FORCE)

set(PTHREADS_PRIVATE_HDRS
    pthread.h
)

set(PTHREADS_SRCS pthread.c)

add_library(pthread SHARED ${PTHREADS_SRCS} ${PTHREADS_PRIVATE_HDRS})
add_library(pthread_a STATIC ${PTHREADS_SRCS} ${PTHREADS_PRIVATE_HDRS})
set_target_properties(pthread_a PROPERTIES DEFINE_SYMBOL __PTW32_STATIC_LIB)

target_link_libraries(pthread kernel32.lib)
