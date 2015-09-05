#
# Cmake Module: DetectPlatform
#
message("Running CMAKE Module: DetectPlatform")
enable_language(CXX)
include(CheckCXXSourceRuns)
if(APPLE OR UNIX)
    set(SECP_PLATFORM_POSIX TRUE CACHE BOOL "Posix platform")
elseif(WIN32)
    set(SECP_PLATFORM_WIN32 TRUE CACHE BOOL "Windows platform")
endif()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    # using Clang
    set(SECP_SECURE_COMPILE_FLAGS "-Wall -Wextra -Wconversion -Wcast-align -Wformat=2 -Wformat-security -fno-common -Wstrict-overflow -Woverloaded-virtual")
    set(SECP_SECURE_LINK_FLAGS "")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    if(CMAKE_BUILD_TYPE STREQUAL "DebugSecure")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SECP_SECURE_COMPILE_FLAGS}")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    # using GCC
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
    # using Intel C++
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    # using Visual Studio C++
endif()

message("** CMAKE_CXX_COMPILER_ID......: ${CMAKE_CXX_COMPILER_ID}")
message("** CMAKE_CXX_FLAGS............: '${CMAKE_CXX_FLAGS}'")
message("** CMAKE_BUILD_TYPE...........: ${CMAKE_BUILD_TYPE}")
#message("** SECP_SECURE_COMPILE_FLAGS..: '${SECP_SECURE_COMPILE_FLAGS}'")

