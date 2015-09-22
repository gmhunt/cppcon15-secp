include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_BINARY_DIR} ${CMAKE_BINARY_DIR}/..)

add_executable(uint-wrap EXCLUDE_FROM_ALL
    UintWrap.cpp
)
add_executable(int-overflow EXCLUDE_FROM_ALL
    IntOverflow.cpp
)


if(SECP_PLATFORM_LINUX)
    target_link_libraries(uint-wrap
        dl
    )
    target_link_libraries(int-overflow
        dl
    )
endif()