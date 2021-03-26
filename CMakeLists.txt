cmake_minimum_required(VERSION 2.8)

project(pktburst)

#add_definitions(-std=c++17)

# generating build/compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_definitions(-march=native)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
    message(STATUS "No CMAKE_BUILD_TYPE selected, defaulting to ${CMAKE_BUILD_TYPE}")
endif()
set(CMAKE_C_FLAGS_DEBUG "$ENV{CFLAGS} -O0 -Wall -g -ggdb")
set(CMAKE_C_FLAGS_RELEASE "$ENV{CFLAGS} -O3 -Wall")

# Options exposed to the user
option(PERF "Compile for performance" OFF)

set(ENV{PKG_CONFIG_PATH} "/usr/local/lib/x86_64-linux-gnu/pkgconfig")

find_package(PkgConfig)

message(STATUS "--- PKG_CONFIG_FOUND: ${PKG_CONFIG_FOUND}")
message(STATUS "--- PKG_CONFIG_VERSION_STRING: ${PKG_CONFIG_VERSION_STRING}")

pkg_search_module(DPDK libdpdk)

if (DPDK_FOUND) # DPDK >= 20.11
    message(STATUS "dpdk libraries found by pkg-config")
    message(STATUS "DPDK_LIBRARIES: ${DPDK_LIBRARIES}")
    message(STATUS "DPDK_INCLUDE_DIRS: ${DPDK_INCLUDE_DIRS}")
    message(STATUS "DPDK_CFLAGS: ${DPDK_CFLAGS}")
    set(CFLAGS ${CFLAGS} ${DPDK_CFLAGS})
    set(LIBRARIES ${LIBRARIES} ${DPDK_LIBRARIES})
else()
    # DPDK include directory. Locating rte_config.h does not work on some systems.
    # Example: it may be kept in /usr/include/x86_64-linux-gnu/, and symlinked
    # from the real DPDK include directory (/usr/include/dpdk/).
    find_path(DPDK_INCLUDE_DIRS NAMES rte_ethdev.h PATH_SUFFIXES dpdk)
    if (DPDK_INCLUDE_DIRS)
        set(DPDK_LIBRARIES -Wl,--whole-archive dpdk -Wl,--no-whole-archive)
        message(STATUS "DPDK include directory = ${DPDK_INCLUDE_DIRS}")
    else()
        message(FATAL_ERROR "DPDK include directory not found. Please install DPDK.")
    endif()
endif()

include_directories(${PROJECT_SOURCE_DIR} ${DPDK_INCLUDE_DIRS})
set(LIBRARIES ${LIBRARIES} ${DPDK_LIBRARIES} pthread dl rt m numa)

include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(pktburst
    src/main.c
    src/pcap.c
    src/tx_core.c
    src/statistics.c
)
target_link_libraries(pktburst ${LIBRARIES})

include(GNUInstallDirs)
install(TARGETS pktburst RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
