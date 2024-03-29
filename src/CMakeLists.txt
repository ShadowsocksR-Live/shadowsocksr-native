set(SSR_MAIN_DIR ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "SSR main directory" FORCE)

option(ENABLE_DUMP_INFO "Out put the stage info." ON)
if (ENABLE_DUMP_INFO)
    add_definitions("-D__PRINT_INFO__")
endif()

if (MSVC)
    add_definitions("-DSODIUM_STATIC")
    add_definitions("-DMBEDTLS_API")

    add_definitions("-D__MINGW32__ -D__MINGW64_VERSION_MAJOR")
    add_definitions("-DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS")
    add_definitions("-DUSE_CRYPTO_MBEDTLS -D_WINSOCK_DEPRECATED_NO_WARNINGS -DUDP_RELAY_ENABLE")
    add_definitions("-DHAVE_PCRE_H")
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
        aead.c
        aead.h
        ppbloom.c
        ppbloom.h
        obfs/auth.c
        obfs/auth_chain.c
        obfs/base64.c
        obfs/crc32.c
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
        udp_ssr_client.c
        client/defs.h
        client/listener.c
        client/main.c
        client/s5.c
        client/s5.h
        ssr_executive.c
        ssr_executive.h
        ssr_qr_code.c
        ssr_qr_code.h
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
        udp_ssr_server.c
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
  include_directories( ${CMAKE_CURRENT_SOURCE_DIR}/../win32/include ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src )
ENDIF(MSVC)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LIBBLOOMDIR})
include_directories(${LIBUVDIR}/include)
include_directories(${libsodium_include_dirs})
include_directories(${LIB_JSON_C_BIN_DIR}/..)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../depends/http-parser)
include_directories(${URI_ENCODE_DIR})
include_directories(${CSTL_ROOT_DIR}/inc)

if(USE_CRYPTO_MBEDTLS)
    include_directories(${MBEDTLS_ROOT_DIR}/include)
    include_directories(${UVMBED_DIR}/include)
endif()

if (MSVC)
    list ( APPEND SOURCE_FILES_CLIENT ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt.c ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt_long.c ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/strncasecmp.c )
    list ( APPEND SOURCE_FILES_SERVER ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt.c ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt_long.c ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/strncasecmp.c )
endif(MSVC)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_definitions(-Wall -Werror -ggdb3 -std=c99 -Wextra -pedantic)
    add_definitions("-D_DEFAULT_SOURCE -D_GNU_SOURCE -D__FUNCTION__=__func__")
endif()

if (UNIX AND (NOT APPLE) AND (NOT ANDROID))
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -static-libstdc++ -static-libgcc")
endif()

add_definitions(-DUDP_RELAY_ENABLE)

if(ANDROID)
    #[[
    include_directories(${LIB_ANCILLARY_DIR})
    LIST(APPEND SOURCE_FILES_CLIENT android.c)
    add_executable(ssr-client ${SOURCE_FILES_CLIENT})
    set_target_properties(ssr-client PROPERTIES COMPILE_DEFINITIONS MODULE_LOCAL)
    set_target_properties(ssr-client PROPERTIES PREFIX "lib" SUFFIX ".so")
    target_link_libraries(ssr-client ancillary json-c uv_a cstl mbedtls sodium bloom m log uv-mbed uri-encode)
    ]]

    include(FetchContent)
    FetchContent_Declare(
            fake-dlfcn
            GIT_REPOSITORY https://github.com/ssrlive/fake-dlfcn.git
            GIT_TAG        2ee50c763c85f67a3062bf65163ea63a19a53709
    )
    FetchContent_MakeAvailable(fake-dlfcn)

    list ( APPEND SOURCE_FILES_CLIENT
            android.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../win32/src/getopt_long.c )

    add_library(ssr-client SHARED ${SOURCE_FILES_CLIENT})
    target_compile_definitions(ssr-client PRIVATE MODULE_LOCAL=1 HAVE_INT_OPTRESET=1)
    target_link_libraries(ssr-client fake-dlfcn json-c uv_a cstl mbedtls sodium bloom m log uv-mbed uri-encode)
    target_include_directories(ssr-client PRIVATE ${LIB_FAKE_DLFCN_DIR})
else()

add_executable(ssr-client ${SOURCE_FILES_CLIENT})
add_executable(ssr-server ${SOURCE_FILES_SERVER})

set_target_properties(ssr-client PROPERTIES COMPILE_DEFINITIONS MODULE_LOCAL)
set_target_properties(ssr-server PROPERTIES COMPILE_DEFINITIONS MODULE_REMOTE)

#target_compile_definitions(libssr-native PRIVATE MODULE_LOCAL LIB_ONLY)
#set_target_properties(libssr-native PROPERTIES SUFFIX ".la")

set (ss_lib_common
        json-c
        uv_a
        cstl
        )

if (MSVC)
else()
    list ( APPEND ss_lib_common m )
endif()

set (ss_lib_net
        ${ss_lib_common}
        mbedtls # /usr/local/lib/libcrypto.a # libcrypto.a # ${LIBCRYPTO} #
        sodium
        bloom
        )

if (WIN32)
    list ( APPEND ss_lib_net Ws2_32 )
endif()

target_link_libraries(ssr-client ${ss_lib_net} uv-mbed uri-encode)
target_link_libraries(ssr-server ${ss_lib_net})

install(TARGETS ssr-server ssr-client
    RUNTIME DESTINATION /usr/bin)

install(FILES ../config.json 
    DESTINATION /etc/ssr-native/)

if(CMAKE_BUILD_TYPE MATCHES Debug)
    # target_compile_definitions(ssr-server PUBLIC __AUTO_EXIT__=1 __AUTO_EXIT_TIMEOUT__=10000)
endif()

endif()
