//
// Created by Gwendolyn Hunt on 9/9/15.
//

#ifndef SECP_HMAC_H
#define SECP_HMAC_H

#include <string>

namespace secp
{

std::string generateHmac(const std::string& key, const std::string& message);

}
#endif //SECP_HMAC_H
