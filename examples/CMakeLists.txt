include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_BINARY_DIR} ${CMAKE_BINARY_DIR}/..)

add_executable(ex1 EXCLUDE_FROM_ALL
    UintWrap.cpp
)
add_executable(ex2 EXCLUDE_FROM_ALL
    IntOverflow.cpp
)
add_executable(ex3 EXCLUDE_FROM_ALL
    Conversions.cpp
)
add_executable(ex4 EXCLUDE_FROM_ALL
    BadApp.cpp
)
target_link_libraries(ex4
    ${BOOST_ROOT}/lib/libboost_system.a
    ${BOOST_ROOT}/lib/libboost_thread.a
    ${BOOST_ROOT}/lib/libboost_program_options.a
)

add_executable(ex5 EXCLUDE_FROM_ALL
    BetterApp.cpp
    Properties.cpp
    Properties.hpp
    PropertyErrors.cpp
    PropertyErrors.hpp
    PropertyTypes.cpp
    PropertyTypes.hpp
)
target_link_libraries(ex5
    ${BOOST_ROOT}/lib/libboost_system.a
    ${BOOST_ROOT}/lib/libboost_thread.a
    ${BOOST_ROOT}/lib/libboost_program_options.a
)


if(SECP_PLATFORM_LINUX)
    target_link_libraries(ex1
        dl
    )
    target_link_libraries(ex2
        dl
    )
    target_link_libraries(ex3
        dl
    )
    target_link_libraries(ex4
        dl
        pthread
    )
    target_link_libraries(ex5
        dl
        pthread
    )
endif()