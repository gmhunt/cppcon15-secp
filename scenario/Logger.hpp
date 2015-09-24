//
// Created by Gwendolyn Hunt on 9/9/15.
//

#ifndef SECP_LOGGER_H
#define SECP_LOGGER_H

#include <string>

namespace secp
{

extern const std::string DEBUG;
extern const std::string INFO;
extern const std::string FATAL;

void log(const std::string& type, const std::string& logEntry);

}
#endif //SECP_LOGGER_H
