cmake_minimum_required(VERSION 3.2)
project(scenario_2)


# Locate platform specific OpenSSL
#
set(OPENSSL_ROOT_DIR "/usr/local/ssl")
set(OPENSSL_INCLUDE_DIRS "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIB_DIRS "${OPENSSL_ROOT_DIR}/lib")
include_directories(${OPENSSL_INCLUDE_DIRS})
set(CMAKE_PREFIX_PATH "${OPENSSL_LIB_DIRS}")
find_library(OPENSSL_LIBRARY
        NAMES libcrypto libssl
        PATH "${OPENSSL_LIB_DIRS}"
)


#  Locate platform specific Boost
#
set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
set(Boost_USE_STATIC_RUNTIME    OFF)
set(BOOST_ROOT /usr/local/Boost_1_58_0)
find_package(Boost 1.58.0)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
endif()

include_directories(${CMAKE_CURRENT_SOURCE})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    aesgcm256_1.cpp
    aesgcm256_2.cpp
    aesgcm256_3.cpp
    )

ADD_LIBRARY("scenario2" STATIC
    ${SOURCE_FILES}
)

add_executable(scenario_2
    main.cpp
)

target_link_libraries(scenario_2
    scenario2
    ${OPENSSL_LIBRARY}
)

