#include "boost/format.hpp"
#include "boost/test/unit_test.hpp"

//#include "TestCryptoController.hpp"

//#include "cap-common/BinHexUtils.hpp"
//#include "cap-common/Log.hpp"
//#include "cap-crypto/AESEncrypt.hpp"
//#include "cap-crypto/CryptoError.hpp"


#include <algorithm>
#include <vector>
#include <string>
#include <fstream>

namespace
{

const std::string genFailure("Generated Key, length in bits:[%1%], value in hex: '%2%'");

/**
 * Removes duplicate elements and returns number of unique elements.
 */
unsigned removeDuplicates(std::vector<std::string>& v)
{
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());

    return v.size();
}

struct Test
{
    enum Type {
        AES128,
        AES256
    };
};

void testGCMEncryption(const std::string& testName, const unsigned iterations, const Test::Type testType)
{
    std::string origPlainText;
    std::string cipherText;
    std::string decryptPlainText;

    /**
     * Generate plain text.
     */
    for (unsigned i(0); i < iterations; ++i) {
        std::string element = cap::generateAes256Key();
        origPlainText += element;
    }
    origPlainText += "CAFE8730921uiod1kjd9d2188092184092184lk"; // Make the length not be on even block boundaries
    std::string key;
    std::string iv  = cap::generateAesGcmIV();
    std::string tag(16, 0);

    key = cap::generateAes256Key();

    std::stringstream ssB;
    ssB << "\n### " << testName << " --------------------------------------------------------"
        << "\n### aesKey..............size:[" << key.length() << "], value: " << cap::bin2Hex(key)
        << "\n### aesGcmIV............size:[" << iv.length() << "], value: " << cap::bin2Hex(iv)
        << "\n### source plain text...size:[" << origPlainText.length() << "]";
//    ssB << ", value: " << cap::bin2Hex(origPlainText);
    logDebug(ssB.str());

    cap::authAes256GcmEncrypt(key, iv, origPlainText, cipherText, tag);
    cap::authAes256GcmDecrypt(key, iv, cipherText, tag, decryptPlainText);
    /**
     * Check for throw on following conditions:
     * - bad key
     * - bad iv
     * - bad cipherText
     * - bad tag
     */
    std::string badKey("#" + key);
    std::string badIv(iv + "#");
    std::string badCipherText("#392198309-01" + tag + iv);
    std::string badTag("#" + tag);
    std::string dummyPlainText;
    BOOST_CHECK_THROW(
            cap::authAes1256cmDecrypt(badKey, iv, cipherText, tag, dummyPlainText),
            cap::CryptoError);
    BOOST_CHECK_THROW(
            cap::authAes256GcmDecrypt(key, badIv, cipherText, tag, dummyPlainText),
            cap::CryptoError);
    BOOST_CHECK_THROW(
            cap::authAes256GcmDecrypt(key, iv, badCipherText, tag, dummyPlainText),
            cap::CryptoError);
    BOOST_CHECK_THROW(
            cap::authAes256GcmDecrypt(key, iv, cipherText, badTag, dummyPlainText),
            cap::CryptoError);
            }

    std::stringstream ssA;
    ssA << "\n### AEAD TAG............size:[" << tag.length() << "], value: " << cap::bin2Hex(tag)
       << "\n### cipher text.........size:[" << cipherText.length() << "]";
//    ssA << ", value: " << cap::bin2Hex(ciperText);
    ssA << "\n### decrypt plain text..size:[" << decryptPlainText.length() << "]";
//    ssA << ", value: " << cap::bin2Hex(decryptPlainText);
    logDebug(ssA.str());

    BOOST_CHECK(decryptPlainText.compare(origPlainText) == 0);
}


} // namespace null


BOOST_AUTO_TEST_SUITE(aes_encrypt)
BOOST_AUTO_TEST_CASE(create_aes_keys)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(create_aes_keys) - starting...");

        checkCrypto();

        unsigned iterations(1000);
	
        std::vector<std::string> v128;
    	for (unsigned i(0); i < iterations; ++i) {
            std::string aes128Key = cap::generateAes128Key();
            v128.push_back(aes128Key);
            unsigned bitLen128key = aes128Key.length() * 8;
            BOOST_CHECK(bitLen128key == 128);
	    }
    	unsigned unique128 = removeDuplicates(v128);
    	BOOST_CHECK(unique128 == iterations);
    	if (unique128 == iterations) {
    	    logDebug(boost::str(boost::format("Successfully generated %1% unique AES 128-bit keys") % iterations));
        } else {
            unsigned duplicates(iterations - unique128);
            logDebug(boost::str(boost::format("Generated %1% duplicate AES 128-bit keys out of %2% iterations") %
                    duplicates % iterations));
        }

    	std::vector<std::string> v256;
    	for (unsigned i(0); i < iterations; ++i) {
            std::string aes256Key = cap::generateAes256Key();
            v256.push_back(aes256Key);
            unsigned bitLen256key = aes256Key.length() * 8;
            BOOST_CHECK(bitLen256key == 256);
        }
    	unsigned unique256 = removeDuplicates(v256);
    	BOOST_CHECK(unique256 == iterations);
    	if (unique256 == iterations) {
    	    logDebug(boost::str(boost::format("Successfully generated %1% unique AES 256-bit keys") % iterations));
        } else {
            unsigned duplicates(iterations - unique256);
            logDebug(boost::str(boost::format("Generated %1% duplicate AES 128-bit keys out of %2% iterations") %
                    duplicates % iterations));
        }


        logInfo("BOOST_AUTO_TEST_CASE(create_aes_keys) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}

BOOST_AUTO_TEST_CASE(create_aes_iv)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(create_aes_iv) - starting...");

        checkCrypto();

        unsigned iterations(1000);

        std::vector<std::string> v128;
        for (unsigned i(0); i < iterations; ++i) {
            std::string aesCbcIV = cap::generateAesCbcIV();
            v128.push_back(aesCbcIV);
            unsigned bitLenCbcIV = aesCbcIV.length() * 8;
            BOOST_CHECK(bitLenCbcIV == 128);
        }
        unsigned unique128 = removeDuplicates(v128);
        BOOST_CHECK(unique128 == iterations);
        if (unique128 == iterations) {
            logDebug(boost::str(boost::format("Successfully generated %1% unique AES-CBC 128-bit iv") % iterations));
        } else {
            unsigned duplicates(iterations - unique128);
            logDebug(boost::str(boost::format("Generated %1% duplicate AES-CBC 128-bit IV out of %2% iterations") %
                    duplicates % iterations));
        }

        std::vector<std::string> v96;
        for (unsigned i(0); i < iterations; ++i) {
            std::string aesGcmIV = cap::generateAesGcmIV();
            v96.push_back(aesGcmIV);
            unsigned bitLenGcmIV = aesGcmIV.length() * 8;
            BOOST_CHECK(bitLenGcmIV == 96);
        }
        unsigned unique96 = removeDuplicates(v96);
        BOOST_CHECK(unique96 == iterations);
        if (unique96 == iterations) {
            logDebug(boost::str(boost::format("Successfully generated %1% unique AES-GCM 96-bit iv") % iterations));
        } else {
            unsigned duplicates(iterations - unique96);
            logDebug(boost::str(boost::format("Generated %1% duplicate AES-GCM 128-bit IV out of %2% iterations") %
                    duplicates % iterations));
        }

        logInfo("BOOST_AUTO_TEST_CASE(create_aes_iv) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}

BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt)
{
    try {

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt) - starting...");

        checkCrypto();

        testGCMEncryption("AES256-GCM", 1201, Test::AES256);

        logInfo("BOOST_AUTO_TEST_CASE(aes256_gcm_encrypt) - end.");

    } catch(std::exception& e) {
        std::cerr << "CAUGHT std::exception. " << e.what() << ". Shutting down..\n\n";
    }
}

BOOST_AUTO_TEST_SUITE_END()

