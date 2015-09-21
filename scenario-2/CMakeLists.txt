#cmake_minimum_required(VERSION 3.2)
include_directories(${CMAKE_CURRENT_SOURCE})

#
# demo 1
#
add_library(aes1
    aesgcm256_1.cpp
)
add_executable(demo1
    main.cpp
)
target_link_libraries(demo1
    ${OPENSSL_LIBRARY}
    aes1
)

#
# demo 2
#
add_library(aes2
    aesgcm256_2.cpp
)
add_executable(demo2
    main.cpp
)
target_link_libraries(demo2
    ${OPENSSL_LIBRARY}
    aes2
)

#
# demo 3
#
add_library(aes3
    aesgcm256_3.cpp
)
add_executable(demo3
    main.cpp
)
target_link_libraries(demo3
    ${OPENSSL_LIBRARY}
    aes3
)

#
# demo 4
#
add_library(aes4
    aesgcm256_4.cpp
    CryptoError.cpp
)
add_executable(demo4
    main.cpp
    )
target_link_libraries(demo4
    ${OPENSSL_LIBRARY}
    aes4
)

add_subdirectory(test)