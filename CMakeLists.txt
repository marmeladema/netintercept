cmake_minimum_required(VERSION 3.6)
project(netintercept)

find_package(OpenSSL REQUIRED)

set(CMAKE_CPP_FLAGS "-Wall -Wextra -Werror -fPIC -pthread")
set(CMAKE_C_FLAGS "-Wall -Wextra -Werror -fPIC -pthread")

add_definitions(-D_GNU_SOURCE)

set(NSPR_INCLUDE_DIR /usr/include/nspr)

include_directories(
	${OPENSSL_INCLUDE_DIR}
	${NSPR_INCLUDE_DIR}
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_library(netintercept SHARED
	include/netintercept.h
	src/netintercept.c

	include/stream.h
	src/stream.c
)
target_link_libraries(netintercept dl pcap)