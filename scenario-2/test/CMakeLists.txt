include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_BINARY_DIR} ${CMAKE_BINARY_DIR}/..)

##----------------------------------------------------------------
## platform independent source
##----------------------------------------------------------------
SET(CRYPTO_TEST_SOURCES
    AesGcmTest.cpp
    Harness.cpp
    TestCryptoController.cpp
    TestCryptoController.hpp
    )
               
##----------------------------------------------------------------
## Build targets that use boost test framework
##----------------------------------------------------------------
add_executable(crypto-test EXCLUDE_FROM_ALL
    ${CRYPTO_TEST_SOURCES}
)
                      

##----------------------------------------------------------------
## Links
##----------------------------------------------------------------
target_link_libraries(crypto-test
    aesgcm
    ${OPENSSL_CRYPTO_LIBRARY}
    ${OPENSSL_SSL_LIBRARY}
    ${BOOST_ROOT}/lib/libboost_date_time.a
    ${BOOST_ROOT}/lib/libboost_unit_test_framework.a
)

##----------------------------------------------------------------
## check targets run under boost test framework
##----------------------------------------------------------------
set(UNIT_TEST_LOG "test_suite" CACHE STRING "The log level for unit testing")
add_custom_target(check
    crypto-test --detect_memory_leak=0 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test)
add_custom_target(check-random
    crypto-test --detect_memory_leak=0 --run_test=random_sequence --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test)
add_custom_target(check-demo1
    crypto-test --detect_memory_leak=0 --run_test=aes_encrypt_1 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test)
add_custom_target(check-demo2
    crypto-test --detect_memory_leak=0 --run_test=aes_encrypt_2 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test)
add_custom_target(check-demo3
    crypto-test --detect_memory_leak=0 --run_test=aes_encrypt_3 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test)
add_custom_target(check-demo4
    crypto-test --detect_memory_leak=0 --run_test=aes_encrypt_4 --log_level=${UNIT_TEST_LOG}
    DEPENDS crypto-test)

                  
