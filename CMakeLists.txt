cmake_minimum_required(VERSION 3.8)

project(ncx)
set(TARGET_NAME ncx)

find_package(OpenSSL REQUIRED)

set(SOURCES
  ncx_certs.cpp ncx_certs.h
  ncx_color.cpp ncx_color.h
  ncx_io.cpp ncx_io.h
  ncx_main.cpp ncx_main.h
  ncx_net.cpp ncx_net.h
  ncx_opts.cpp ncx_opts.h)



add_executable(${TARGET_NAME} ${SOURCES})
target_link_libraries(${TARGET_NAME} PRIVATE ${OPENSSL_LIBRARIES})
#include_directories(${CMAKE_CURRENT_BINARY_DIR})

install(TARGETS ${TARGET_NAME} DESTINATION bin)

target_compile_options(${TARGET_NAME} PRIVATE -Wall -Werror)

