
#define BOOST_TEST_MODULE crypto
#include "boost/test/unit_test.hpp"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>

#include "TestCryptoController.hpp"

struct CryptoFixture
{
    CryptoFixture()
    {
        cap::Log::initialize("crypto-test");
    }

};

BOOST_GLOBAL_FIXTURE(CryptoFixture);



