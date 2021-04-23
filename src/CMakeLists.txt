set(SSR_MAIN_DIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "SSR main directory" FORCE)

option(ENABLE_DUMP_INFO "Out put the stage info." ON)
if (ENABLE_DUMP_INFO)
    add_definitions("-D__PRINT_INFO__")
endif()

if (MSVC)
    add_definitions("-DSODIUM_STATIC")
    add_definitions("-DMBEDTLS_API")
endif()

if(ANDROID)
include_directories(${LIB_ANCILLARY_DIR})
endif()

set(SOURCE_FILES_SNI
        shadowsocks.h
        socks5.h
        socks5.c
        http.c
        tls.c
        )

set(SOURCE_FILES_OBFS
        strtrim.c
        strtrim.h
        ssr_cipher_names.c
        ssr_cipher_names.h
        obfs/auth.c
        obfs/auth_chain.c
        obfs/base64.c
        obfs/crc32.c
        obfs/cstl_lib.c
        obfs/http_simple.c
        obfs/obfs.c
        obfs/obfsutil.c
        obfs/tls1.2_ticket.c
        obfs/tls1.2_ticket.h
        obfs/verify.c)

set(SOURCE_FILES_CLIENT
        ../depends/http-parser/http_parser.c
        ../depends/http-parser/http_parser.h
        ../depends/http-parser/http_parser_wrapper.c
        ../depends/http-parser/http_parser_wrapper.h
        cache.c
        cache.h
        encrypt.c
        encrypt.h
        ssrbuffer.c
        ssrbuffer.h
        ssrutils.c
        ssrutils.h
        udprelay.c
        udprelay.h
        client/defs.h
        client/listener.c
        client/main.c
        client/s5.c
        client/s5.h
        ssr_executive.c
        ssr_executive.h
        config_json.c
        config_json.h
        sockaddr_universal.h
        sockaddr_universal.c
        tunnel.c
        tunnel.h
        client/client.c
        client/tls_cli.c
        client/tls_cli.h
        websocket_basic.c
        websocket_basic.h
        text_in_color.c
        text_in_color.h
        dump_info.c
        dump_info.h
        cmd_line_parser.c
        cmd_line_parser.h
        exe_file_path.c
        exe_file_path.h
        daemon_wrapper.c
        daemon_wrapper.h
        ${SOURCE_FILES_OBFS}
        client/ssr_client_api.h)

set(SOURCE_FILES_SERVER
        ../depends/http-parser/http_parser.c
        ../depends/http-parser/http_parser.h
        ../depends/http-parser/http_parser_wrapper.c
        ../depends/http-parser/http_parser_wrapper.h
        websocket_basic.c
        websocket_basic.h
        text_in_color.c
        text_in_color.h
        dump_info.c
        dump_info.h
        client/s5.c
        client/s5.h
        ssrutils.h
        ssrutils.c
        ssrbuffer.c
        ssrbuffer.h
        encrypt.c
        udprelay.c
        cache.c
        ip_addr_cache.c
        ip_addr_cache.h
        ssr_executive.c
        ssr_executive.h
        cmd_line_parser.c
        cmd_line_parser.h
        exe_file_path.c
        exe_file_path.h
        daemon_wrapper.c
        daemon_wrapper.h
        config_json.c
        config_json.h
        sockaddr_universal.h
        sockaddr_universal.c
        tunnel.c
        tunnel.h
        server/server.c
        ${SOURCE_FILES_OBFS})

include_directories(obfs)
include_directories(client)
IF(MSVC)
  include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/../win32/include )
ENDIF(MSVC)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LIBUVDIR}/include)
include_directories(${libsodium_include_dirs})
include_directories(${LIB_JSON_C_BIN_DIR}/..)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../depends/http-parser)

if(USE_CRYPTO_MBEDTLS)
    include_directories(${MBEDTLS_ROOT_DIR}/include)
    include_directories(${UVMBED_DIR}/include)
endif()

if (MSVC)
    list ( APPEND SOURCE_FILES_CLIENT ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt.c ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt_long.c ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/strncasecmp.c )
    list ( APPEND SOURCE_FILES_SERVER ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt.c ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt_long.c ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/strncasecmp.c )
endif(MSVC)

if (!APPLE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_definitions(-Wall -Werror -ggdb3 -std=c99 -Wextra -pedantic)
    add_definitions("-D_DEFAULT_SOURCE -D_GNU_SOURCE")
endif()

if (UNIX)
if (APPLE)
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libstdc++ -static-libgcc")
endif()
endif()

add_definitions(-DUDP_RELAY_ENABLE)

if(ANDROID)
    LIST(APPEND SOURCE_FILES_CLIENT android.c)
endif()

add_executable(ssr-client ${SOURCE_FILES_CLIENT})
add_executable(ssr-server ${SOURCE_FILES_SERVER})

set_target_properties(ssr-client PROPERTIES COMPILE_DEFINITIONS MODULE_LOCAL)
set_target_properties(ssr-server PROPERTIES COMPILE_DEFINITIONS MODULE_REMOTE)

#target_compile_definitions(libssr-native PRIVATE MODULE_LOCAL LIB_ONLY)
#set_target_properties(libssr-native PROPERTIES SUFFIX ".la")

set (ss_lib_common
        json-c
        uv_a
        )

if (MSVC)
else()
    list ( APPEND ss_lib_common m )
endif()

set (ss_lib_net
        ${ss_lib_common}
        mbedtls # /usr/local/lib/libcrypto.a # libcrypto.a # ${LIBCRYPTO} #
        sodium
        )

if (WIN32)
    list ( APPEND ss_lib_net Ws2_32 )
endif()

if(ANDROID)
    LIST(APPEND ss_lib_net ancillary log)
    set_target_properties(ssr-client PROPERTIES PREFIX "lib" SUFFIX ".so")
endif()

target_link_libraries(ssr-client ${ss_lib_net} uv-mbed)
target_link_libraries(ssr-server ${ss_lib_net})

install(TARGETS ssr-server ssr-client
    RUNTIME DESTINATION /usr/bin)

install(FILES ../config.json 
    DESTINATION /etc/ssr-native/)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    # target_compile_definitions(ssr-server PUBLIC __AUTO_EXIT__=1 __AUTO_EXIT_TIMEOUT__=10000)
endif()

