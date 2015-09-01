cmake_minimum_required(VERSION 3.2)
project(scenario_2)

set(OPENSSL_ROOT_DIR "/usr/local/ssl")
set(OPENSSL_INCLUDE_DIRS "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_LIB_DIRS "${OPENSSL_ROOT_DIR}/lib")

include_directories(${OPENSSL_INCLUDE_DIRS})
set(CMAKE_PREFIX_PATH "${OPENSSL_LIB_DIRS}")
find_library(OPENSSL_LIBRARY
        NAMES libcrypto libssl
        PATH "${OPENSSL_LIB_DIRS}"
)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    main.cpp
    aesgcm256-1.cpp
    )

add_executable(scenario_2_1 ${SOURCE_FILES})
target_link_libraries(scenario_2_1
        ${OPENSSL_LIBRARY}
)

