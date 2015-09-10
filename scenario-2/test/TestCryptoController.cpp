#include "TestCryptoController.hpp"
#include "boost/test/unit_test.hpp"


std::shared_ptr<TestCryptoController> TestCryptoController::instance()
{
    if (testCryptoController_ == nullptr) {
        TestCryptoController::testCryptoController_ = std::shared_ptr<TestCryptoController>(new TestCryptoController());
    }
    return testCryptoController_;
}

std::shared_ptr<TestCryptoController> TestCryptoController::testCryptoController_(nullptr);

