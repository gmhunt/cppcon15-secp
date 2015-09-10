#ifndef TEST_CRYPTO_CONTROLLER_HPP_
#define TEST_CRYPTO_CONTROLLER_HPP_

#include <CryptoController.hpp>
#include "boost/noncopyable.hpp"

#include <memory>
/**
 * This singleton is used with the test harness
 * as a wrapper around the CryptoController.
 *
 */
class TestCryptoController : protected boost::noncopyable
{
public:
    static std::shared_ptr<TestCryptoController> instance();

private:
    TestCryptoController() = default;

    secp::CryptoController        cryptoController_;

    static std::shared_ptr<TestCryptoController> testCryptoController_;

};

#endif /* TEST_CRYPTO_CONTROLLER_HPP_ */
