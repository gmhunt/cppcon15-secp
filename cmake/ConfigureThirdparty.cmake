message("Running CMAKE Module: ConfigureThirdparty")
#
# Cmake Module: ConfigureThirdparty
#
# This file sets up include and links paths
# - openssl
# - boost
# - chucho 

# Locate platform specific OpenSSL
#
if(SECP_PLATFORM_POSIX)
	set(OPENSSL_ROOT_DIR "/usr/local/ssl")
	set(OPENSSL_INCLUDE_DIRS "${OPENSSL_ROOT_DIR}/include")
	set(OPENSSL_LIB_DIRS "${OPENSSL_ROOT_DIR}/lib")

	#  Locate platform specific Boost
	#
	set(Boost_USE_STATIC_LIBS        ON) # only find static libs
	set(Boost_USE_MULTITHREADED      ON)
	set(Boost_USE_STATIC_RUNTIME    OFF)
	set(BOOST_ROOT /usr/local/Boost_1_58_0)
	find_package(Boost 1.58.0)
	if (Boost_FOUND)
	    include_directories(${Boost_INCLUDE_DIRS})
	endif()
elseif(SECP_PLATFORM_WINDOWS)
endif()

set(CMAKE_PREFIX_PATH "${OPENSSL_LIB_DIRS}")
find_library(OPENSSL_CRYPTO_LIBRARY
    NAMES libcrypto.a
    PATH "${OPENSSL_LIB_DIRS}"
)
if (OPENSSL_CRYPTO_LIBRARY_FOUND)
    message("** OpenSSL Crypto Library Found")
endif()
find_library(OPENSSL_SSL_LIBRARY
        NAMES libssl.a
        PATH "${OPENSSL_LIB_DIRS}"
)
if (OPENSSL_SSL_LIBRARY_FOUND)
    message("** OpenSSL SSL Library Found")
endif()
include_directories(${OPENSSL_INCLUDE_DIRS})

message("** OpenSSL root dir.......: ${OPENSSL_ROOT_DIR}")
message("** OpenSSL include dir....: ${OPENSSL_INCLUDE_DIRS}")
message("** OpenSSL lib dir........: ${OPENSSL_LIB_DIRS}")
message("** OPENSSL_CRYPTO_LIBRARY.: ${OPENSSL_CRYPTO_LIBRARY}")
message("** OPENSSL_SSL_LIBRARY....: ${OPENSSL_SSL_LIBRARY}")

message("** Boost root dir.........: ${BOOST_ROOT}")

