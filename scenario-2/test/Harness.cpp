
#define BOOST_TEST_MODULE crypto-test
#include "boost/test/unit_test.hpp"

struct CryptoFixture
{
    CryptoFixture()
    {
        // TODO Initialize log subsystem here
    }

};

BOOST_GLOBAL_FIXTURE(CryptoFixture);



