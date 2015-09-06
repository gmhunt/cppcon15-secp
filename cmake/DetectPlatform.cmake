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
    set(SECP_BASIC_EXPLOIT_MITIGATION_COMPILE_FLAGS "-DFORTIFY_SOURCE=2 -fstack-protector-all -Wcast-align")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_CXX_FLAGS "-O0 ${CMAKE_CXX_FLAGS}")
    elseif(CMAKE_BUILD_TYPE STREQUAL "DebugSecure")
        set(CMAKE_CXX_FLAGS "-O0 ${CMAKE_CXX_FLAGS} ${SECP_SECURE_COMPILE_FLAGS}")
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CMAKE_CXX_FLAGS "-O2 ${CMAKE_CXX_FLAGS} ${SECP_SECURE_COMPILE_FLAGS} ${SECP_BASIC_EXPLOIT_MITIGATION_COMPILE_FLAGS}")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    # Using gcc
    set(SECP_GCC_CXX11_VERSION "4.7")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS ${SECP_GCC_CXX11_VERSION})
        message(FATAL_ERROR "C++11 Compiler version needs to be >= ${SECP_GCC_CXX11_VERSION}")
    endif()
    set(SECP_SECURE_COMPILE_FLAGS "-Wall -Wextra -Wconversion -Wcast-align -Wformat=2 -Wformat-security -fno-common -Wstrict-overflow -Woverloaded-virtual")
    set(SECP_BASIC_EXPLOIT_MITIGATION_COMPILE_FLAGS "-DFORTIFY_SOURCE=2 -fstack-protector-all -Wcast-align -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wno-unused-local-typedefs")
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_CXX_FLAGS "-O0 ${CMAKE_CXX_FLAGS}")
    elseif(CMAKE_BUILD_TYPE STREQUAL "DebugSecure")
        set(CMAKE_CXX_FLAGS "-O0 ${CMAKE_CXX_FLAGS} ${SECP_SECURE_COMPILE_FLAGS}")
    elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
        set(CMAKE_CXX_FLAGS "-O2 ${CMAKE_CXX_FLAGS} ${SECP_SECURE_COMPILE_FLAGS} ${SECP_BASIC_EXPLOIT_MITIGATION_COMPILE_FLAGS}")
    endif()
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Intel")
    # using Intel C++
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    # using Visual Studio C++
endif()

message("** CMAKE_CXX_COMPILER_ID......: '${CMAKE_CXX_COMPILER_ID}'")
message("** CMAKE_CXX_FLAGS............: '${CMAKE_CXX_FLAGS}'")
message("** CMAKE_CXX_FLAGS_RELEASE....: '${CMAKE_CXX_FLAGS}'")
message("** CMAKE_BUILD_TYPE...........: ${CMAKE_BUILD_TYPE}")

