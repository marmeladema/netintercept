cmake_minimum_required(VERSION 3.6)
project(netintercept
	VERSION 0.3.0
)

include(FeatureSummary)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

option(NETINTERCEPT_OPENSSL "Enable support for OpenSSL" ON)
add_feature_info(OpenSSL NETINTERCEPT_OPENSSL "netintercept has OpenSSL support enabled.")
option(NETINTERCEPT_NSPR "Enable support for NSPR" ON)
add_feature_info(NSPR NETINTERCEPT_NSPR "netintercept has NSPR support enabled.")

find_package(Threads REQUIRED)
find_package(PCAP REQUIRED)

set(CMAKE_CPP_FLAGS "-Wall -Wextra -Werror")
set(CMAKE_C_FLAGS "-Wall -Wextra -Werror")

add_definitions(-D_GNU_SOURCE)

if(${NETINTERCEPT_OPENSSL})
	find_package(OpenSSL REQUIRED)
	include_directories(${OPENSSL_INCLUDE_DIR})
endif()

if(${NETINTERCEPT_NSPR})
	find_package(NSPR REQUIRED)
	include_directories(${NSPR_INCLUDE_DIRS})
endif()

configure_file(
	config.h.in config.h
	@ONLY
)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include
	${CMAKE_CURRENT_BINARY_DIR}
)

add_library(netintercept SHARED
	include/netintercept.h
	src/netintercept.c

	include/stream.h
	src/stream.c
)
set_target_properties(netintercept
	PROPERTIES
		SOVERSION ${PROJECT_VERSION_MAJOR}
		VERSION ${PROJECT_VERSION}
)
target_link_libraries(netintercept
	${CMAKE_DL_LIBS}
	${CMAKE_THREAD_LIBS_INIT}
	${PCAP_LIBRARY}
)
install(
	TARGETS
		netintercept
	LIBRARY
          DESTINATION lib
)

feature_summary(WHAT ALL)
