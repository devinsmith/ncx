cmake_minimum_required(VERSION 3.8)

project(ncx)
set(TARGET_NAME ncx)

find_package(OpenSSL REQUIRED)

set(SOURCES
  ncx_certs.c ncx_certs.h
  ncx_color.c ncx_color.h
  ncx_io.c ncx_io.h
  ncx_main.c ncx_main.h
  ncx_net.c ncx_net.h
  ncx_opts.c ncx_opts.h)



add_executable(${TARGET_NAME} ${SOURCES})
target_link_libraries(${TARGET_NAME} PRIVATE ${OPENSSL_LIBRARIES})
#include_directories(${CMAKE_CURRENT_BINARY_DIR})

install(TARGETS ${TARGET_NAME} DESTINATION bin)

target_compile_options(${TARGET_NAME} PRIVATE -Wall -Werror)

