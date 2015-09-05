#cmake_minimum_required(VERSION 3.2)
include_directories(${CMAKE_CURRENT_SOURCE})
include("DetectPlatform")
include("ConfigureThirdparty")

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

