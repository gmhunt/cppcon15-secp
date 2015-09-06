#include "TestCryptoController.hpp"
#include "boost/test/unit_test.hpp"


TestCryptoController* TestCryptoController::instance()
{
    if (testCryptoController_ == nullptr) {
        testCryptoController_ = new TestCryptoController();
    }
    return testCryptoController_;
}

TestCryptoController::TestCryptoController()
    : cryptoController_()
{}


void checkCrypto()
{
    TestCryptoController* testCryptoController = TestCryptoController::instance();
    testCryptoController->enable();
    BOOST_CHECK_EQUAL(testCryptoController->isEnabled(), true);
}

TestCryptoController* TestCryptoController::testCryptoController_(nullptr);

