#include <boost/algorithm/string.hpp>

#include "PropertyErrors.hpp"
#include "PropertyTypes.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <limits>
#include <algorithm>


namespace secp
{

const boost::uint32_t PROPERTIES_MIN_NAME_LENGTH         =     1;
const boost::uint32_t PROPERTIES_MAX_NAME_LENGTH         =   128;
const boost::uint32_t PROPERTIES_MIN_DESCRIPTION_LENGTH  =     0;
const boost::uint32_t PROPERTIES_MAX_DESCRIPTION_LENGTH  =  1024;
const boost::uint32_t PROPERTIES_MIN_STRING_LENGTH       =     0;
const boost::uint32_t PROPERTIES_MAX_STRING_LENGTH       =  4096;
const boost::uint32_t PROPERTIES_MIN_PATH_LENGTH         =     0;
const boost::uint32_t PROPERTIES_MAX_PATH_LENGTH         =  4096;

const std::string errorFormatNotFound("Property: \"%1%\" not found!");

const std::string errorFormatUnchangeable("Invalid attempt to set unchangeable property: \"%1%\". "
                                          "Remove setting from command line or config file");

const std::string errorFormatValueLength("%1%Property: \"%2%\" value_.length():[%3%], "
                                         "outside of range limits, min:[%4%], max:[%5%");

const std::string errorFormatRangeLimits("%1%Property: \"%2%\" outside of range limits, typeMin:[%3%], "
                                         "typeMax:[%4%], min:[%5%], max:[%6%");

std::string validatePropertyName(const std::string& propertyName,
                                 const boost::uint32_t minLength,
                                 const boost::uint32_t maxLength)
{
    boost::uint32_t nameLength = propertyName.length();
    if (nameLength < minLength || nameLength > maxLength) {
        std::string name = nameLength > 12 ? propertyName.substr(0,12) + "..." : propertyName;
        boost::format f("Invalid Property Name: %1% Outside of property name length limits, "
                        "min:[%2%] max:[%3%], length:[%4%]");
        f % name % minLength % maxLength % nameLength;
        THROW_SECP_ERROR(secp::PropertiesError, f.str());
    }
    return propertyName;
}

std::string validatePropertyDesc(const std::string& propertyName,
                                 const std::string& description,
                                 const boost::uint32_t minLength,
                                 const boost::uint32_t maxLength)
{
    boost::uint32_t descLength = description.length();
    if (descLength < minLength || descLength > maxLength) {
        boost::format f("Invalid Property Description for name = '%1%' Exceeds property description length limits, "
                        "min:[%2%] max:[%3%], length:[%4%]");
        f % propertyName % minLength % maxLength % descLength;
        THROW_SECP_ERROR(secp::PropertiesError, f.str());
    }
    return description;
}


} // namespace secp



