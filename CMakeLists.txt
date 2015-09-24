#cmake_minimum_required(VERSION 3.2)
cmake_minimum_required(VERSION 2.8)

project(secp)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include("DetectPlatform")
include("ConfigureThirdparty")

add_subdirectory(examples)
add_subdirectory(scenario)

