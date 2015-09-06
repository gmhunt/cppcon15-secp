INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_BINARY_DIR} ${CMAKE_BINARY_DIR}/..)

CAP_USE_FIPS()

##----------------------------------------------------------------
## platform independent source
##----------------------------------------------------------------
SET(CRYPTO_TEST_SOURCES
    AesGcmTest.cpp
    CertVerifyTest.cpp
    CryptoTest.cpp
    Harness.cpp
    KeyStoreTest.cpp
    PluginPackageTest.cpp
    PluginPackageTest.hpp
    TestCryptoController.cpp
    TestCryptoController.hpp
    TrustStoreTest.cpp
    ) 
               
SET(CRYPTO_TEST_COMPILE_FLAGS "${CAP_FIPS_COMPILE_FLAGS}")
SET_SOURCE_FILES_PROPERTIES(${CRYPTO_TEST_SOURCES}
                            PROPERTIES
                            COMPILE_FLAGS "${CRYPTO_TEST_COMPILE_FLAGS}"
                            )

MESSAGE("** CRYPTO_TEST_COMPILE_FLAGS.....: '${CRYPTO_TEST_COMPILE_FLAGS}'") 

##----------------------------------------------------------------
## Build targets that use boost test framework
##----------------------------------------------------------------
ADD_EXECUTABLE(crypto-test  EXCLUDE_FROM_ALL ${CRYPTO_TEST_SOURCES})
                      
##----------------------------------------------------------------
## Link Flags
##----------------------------------------------------------------
SET(CRYPTO_TEST_LINK_FLAGS "${CAP_FIPS_LINK_FLAGS}")
IF(CAP_COMPILER_MSC)
    IF(CAP_BITNESS EQUAL 32)
        SET(CRYPTO_TEST_LINK_FLAGS "${CRYPTO_TEST_LINK_FLAGS} /DYNAMICBASE:NO /FIXED /ignore:4099")
    ELSE()
        SET(CRYPTO_TEST_LINK_FLAGS "${CRYPTO_TEST_LINK_FLAGS} /ignore:4099")
    ENDIF()
ENDIF()
   
IF(CAP_COMPILER_INTEL)
    # Intel SSA Analysis requires the linker to use the same diagnostic flags that were used for compiling
    IF(CMAKE_BUILD_TYPE STREQUAL "SSA")
        IF(CAP_LINUX)
            SET(CRYPTO_TEST_LINK_FLAGS "${CRYPTO_TEST_LINK_FLAGS} -diag-enable sc3 -diag-sc-dir=${CMAKE_BINARY_DIR}/ssa")
        ENDIF(CAP_LINUX)
        IF(CAP_WINDOWS)
            SET(CRYPTO_TEST_LINK_FLAGS "${CRYPTO_TEST_LINK_FLAGS} -Qdiag-enable:sc3 -Qdiag-file-append:${CMAKE_BINARY_DIR}/ssa-intel.diag")
        ENDIF()
    ENDIF()               
ENDIF()

IF(NOT CRYPTO_TEST_LINK_FLAGS STREQUAL "")
    SET_TARGET_PROPERTIES(crypto-test
                          PROPERTIES
                          LINK_FLAGS "${CRYPTO_TEST_LINK_FLAGS}")
ENDIF()

MESSAGE("** CRYPTO_TEST_LINK_FLAGS........: '${CRYPTO_TEST_LINK_FLAGS}'") 
MESSAGE("**")
                      
##----------------------------------------------------------------
## Links
##----------------------------------------------------------------

SET(CAP_TEST_STD_LIBS 
    cap-common 
    boost_chrono
    boost_date_time 
    boost_filesystem 
    boost_iostreams 
    boost_program_options 
    boost_random 
    boost_system 
    boost_thread 
    protobuf
    log4cplus 
    )

TARGET_LINK_LIBRARIES(crypto-test  
    cap-crypto
    )

CAP_TARGET_LIBRARIES(crypto-test 
    ${CAP_TEST_STD_LIBS} 
    boost_unit_test_framework
    )

CAP_FIPS_TARGET(crypto-test)

TARGET_LINK_LIBRARIES(crypto-test 
    ${CAP_ICONV_LIB}
    )

IF(CAP_SOLARIS)
    SET(CAP_SOLARIS_LIBS socket nsl)
    TARGET_LINK_LIBRARIES(crypto-test  
        ${CAP_SOLARIS_LIBS}
        )
ENDIF()

IF(CAP_LINUX)
    SET(CAP_LINUX_LIBS rt dl m)
    TARGET_LINK_LIBRARIES(crypto-test 
        ${CAP_LINUX_LIBS}
        )
ENDIF()

IF(CAP_WINDOWS)
    TARGET_LINK_LIBRARIES(crypto-test 
        ws2_32
        )
ENDIF()

IF(CAP_MACINTOSH)
    TARGET_LINK_LIBRARIES(crypto-test c++)
ENDIF()

##----------------------------------------------------------------
## check targets run under boost test framework
##----------------------------------------------------------------
GET_TARGET_PROPERTY(CRYPTO_TEST_LOCATION crypto-test LOCATION)
SET(CAP_UNIT_TEST_LOG "test_suite" CACHE STRING "The log level for unit testing")
ADD_CUSTOM_TARGET(check
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-aes
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=aes_encrypt --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-cert
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=cert_verify --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-fips
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=fips --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-digest
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=file_digest --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-keystore
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=keystore --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-truststore
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=truststore --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-signed
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=signed_file_digest --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-basic-tool-package
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=full_tool_package/basic_tool_package --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-full-tool-package
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=full_tool_package --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-basic-plugin-package
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=basic_plugin_package --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
ADD_CUSTOM_TARGET(check-full-plugin-package
                  "${CRYPTO_TEST_LOCATION}" --detect_memory_leak=0 --run_test=full_plugin_package --log_level=${CAP_UNIT_TEST_LOG}
                  DEPENDS crypto-test)
                  
                  
