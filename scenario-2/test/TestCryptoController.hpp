#ifndef TEST_CRYPTO_CONTROLLER_HPP_
#define TEST_CRYPTO_CONTROLLER_HPP_

#include <CryptoController.hpp>
#include "boost/noncopyable.hpp"

/**
 * This singleton is used with the test harness
 * as a wrapper around the CryptoController.
 *
 */
class TestCryptoController : protected boost::noncopyable
{
public:
    static TestCryptoController* instance();

private:
    TestCryptoController();

    cap::CryptoController           cryptoController_;

    static TestCryptoController*    testCryptoController_;

};

void checkCrypto();


#endif /* TEST_CRYPTO_CONTROLLER_HPP_ */
