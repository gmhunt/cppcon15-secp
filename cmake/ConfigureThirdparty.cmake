message("Running CMAKE Module: ConfigureThirdparty")
#
# Cmake Module: ConfigureThirdparty
#
# This file sets up include and links paths.  Libs were built with the following configs:
# - openssl 1.0.2d
#		posix
#   	win32
#
# - boost 1.59.0
#       built with zlib and bzip2
#			$ mkdir ~/boost-build
#			$ cd ~/boost-build
#			$ tar xvfz ~/Downloads/boost_1_59_0.tar.gz
#			$ tar xvfz ~/Downloads/zlib-1.2.8.tar.gz
#			$ tar xvfz ~/Downloads/bzip2-1.0.6.tar.gz
#           $ cd boost_1_59_0
#
#		clang (osx)
#           ./bootstrap.sh
#			./bjam --disable-icu -q --prefix=/usr/local/boost_1_59_0 --without-python \
#                  --without-log --without-mpi --toolset=clang-cxx11 link=static \
#                  threading=multi variant=release address-model=64 architecture=x86 \
#                  -sBZIP2_SOURCE=~/build-boost/bzip2-1.0.6 \
#                  -sZLIB_SOURCE=~/build-boost/zlib-1.2.8 \
#                  cxxflags="-std=c++11 -I../zlib-1.2.8 -I../bzip2-1.0.6" \
#                  -linkflags=stdlib=libc++ install
#   	gcc (linux)
#           ./bootstrap.sh
#			./bjam --disable-icu -q --prefix=/usr/local/boost_1_59_0 --without-python \
#                  --without-log --without-mpi --toolset=gcc link=static \
#                  threading=multi variant=release address-model=64 architecture=x86 \
#                  -sBZIP2_SOURCE=~/build-boost/bzip2-1.0.6 \
#                  -sZLIB_SOURCE=~/build-boost/zlib-1.2.8 \
#                  cxxflags="-std=c++11 -I../zlib-1.2.8 -I../bzip2-1.0.6 -Wno-unused-local-typedefs" \
#                  install
#
#
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
	set(BOOST_ROOT /usr/local/boost_1_59_0)
	find_package(Boost 1.59.0)
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

message("** OpenSSL root dir...........: ${OPENSSL_ROOT_DIR}")
message("** OpenSSL include dir........: ${OPENSSL_INCLUDE_DIRS}")
message("** OpenSSL lib dir............: ${OPENSSL_LIB_DIRS}")
message("** OPENSSL_CRYPTO_LIBRARY.....: ${OPENSSL_CRYPTO_LIBRARY}")
message("** OPENSSL_SSL_LIBRARY........: ${OPENSSL_SSL_LIBRARY}")

message("** BOOST_ROOT.................: ${BOOST_ROOT}")

