include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_BINARY_DIR} ${CMAKE_BINARY_DIR}/..)

##----------------------------------------------------------------
## platform independent source
##----------------------------------------------------------------
set(CRYPTO_BASE_SOURCES
    ../CryptoController.cpp
    ../CryptoError.cpp
    ../CryptoError.hpp
    ../Hmac.cpp
    ../Hmac.hpp
    ../Logger.cpp
    ../Logger.hpp
    ../RandomSequence.cpp
    ../RandomSequence.hpp
)
set(CRYPTO_TEST_BASE_SOURCES
    Harness.cpp
    TestCryptoController.cpp
    TestCryptoController.hpp
)

set(CRYPTO_EXAMPLE_SOURCES_1
    ../aesgcm256_1.cpp
    ${CRYPTO_BASE_SOURCES}
)
set(CRYPTO_EXAMPLE_SOURCES_234
    ../aesgcm256_2.cpp
    ../aesgcm256_3.cpp
    ../aesgcm256_4.cpp
    ${CRYPTO_BASE_SOURCES}
    )

set(CRYPTO_TEST_SOURCES_1
    AesGcmTest1.cpp
    ${CRYPTO_EXAMPLE_SOURCES_1}
    ${CRYPTO_TEST_BASE_SOURCES}
    )

set(CRYPTO_TEST_SOURCES_234
    AesGcmTest234.cpp
    ${CRYPTO_EXAMPLE_SOURCES_234}
    ${CRYPTO_TEST_BASE_SOURCES}
)


##----------------------------------------------------------------
## Build targets that use boost test framework
##----------------------------------------------------------------
add_executable(crypto-test1 EXCLUDE_FROM_ALL
    ${CRYPTO_TEST_SOURCES_1}
)

add_executable(crypto-test234 EXCLUDE_FROM_ALL
    ${CRYPTO_TEST_SOURCES_234}
)

##----------------------------------------------------------------
## Links
##----------------------------------------------------------------
target_link_libraries(crypto-test1
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
    ${BOOST_ROOT}/lib/libboost_date_time.a
    ${BOOST_ROOT}/lib/libboost_unit_test_framework.a
)
target_link_libraries(crypto-test234
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
    ${BOOST_ROOT}/lib/libboost_date_time.a
    ${BOOST_ROOT}/lib/libboost_unit_test_framework.a
)


if(SECP_PLATFORM_LINUX)
    target_link_libraries(crypto-test1
        dl
    )
    target_link_libraries(crypto-test234
        dl
    )
endif()
##----------------------------------------------------------------
## check targets run under boost test framework
##----------------------------------------------------------------
set(UNIT_TEST_LOG "test_suite" CACHE STRING "The log level for unit testing")
add_custom_target(check
    crypto-test234 --detect_memory_leak=0 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test234)
add_custom_target(check-hmac
    crypto-test234 --detect_memory_leak=0 --run_test=hmac --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test234)
add_custom_target(check-random
    crypto-test234 --detect_memory_leak=0 --run_test=random_sequence --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test234)
add_custom_target(check-demo1
    crypto-test1 --detect_memory_leak=0 --run_test=aes_encrypt_1 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test1)
add_custom_target(check-demo2
    crypto-test234 --detect_memory_leak=0 --run_test=aes_encrypt_2 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test234)
add_custom_target(check-demo3
    crypto-test234 --detect_memory_leak=0 --run_test=aes_encrypt_3 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test234)
add_custom_target(check-demo4
    crypto-test234 --detect_memory_leak=0 --run_test=aes_encrypt_4 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test234)

                  
