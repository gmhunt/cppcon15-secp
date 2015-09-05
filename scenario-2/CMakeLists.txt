#cmake_minimum_required(VERSION 3.2)
include_directories(${CMAKE_CURRENT_SOURCE})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    aesgcm256_1.cpp
    aesgcm256_2.cpp
    aesgcm256_3.cpp
    )

add_library(aes1
    aesgcm256_1.cpp
)
add_library(aes2
    aesgcm256_2.cpp
)
add_library(aes3
    aesgcm256_3.cpp
)
add_library(aes4
    aesgcm256_4.cpp
)

add_executable(demo1
    main.cpp
)
target_link_libraries(demo1
    ${OPENSSL_LIBRARY}
    aes1
)

add_executable(demo2
    main.cpp
)
target_link_libraries(demo2
    ${OPENSSL_LIBRARY}
    aes2
)

add_executable(demo3
    main.cpp
)
target_link_libraries(demo3
    ${OPENSSL_LIBRARY}
    aes3
)

add_executable(demo4
    main.cpp
)
target_link_libraries(demo4
    ${OPENSSL_LIBRARY}
    aes4
)
