#ifndef PROPERTY_TYPES_HPP_
#define PROPERTY_TYPES_HPP_

#include <boost/cstdint.hpp>
//#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string/trim.hpp>

#include "PropertyErrors.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <limits>
#include <algorithm>

namespace secp
{

/**
 * See header Properties.hpp for explanation on property limits for the different
 * Property Types and for the general property limits.
 */
extern const boost::uint32_t PROPERTIES_MIN_NAME_LENGTH;
extern const boost::uint32_t PROPERTIES_MAX_NAME_LENGTH;
extern const boost::uint32_t PROPERTIES_MIN_DESCRIPTION_LENGTH;
extern const boost::uint32_t PROPERTIES_MAX_DESCRIPTION_LENGTH;

std::string validatePropertyName(const std::string& propertyName,
                                 const boost::uint32_t minLength = PROPERTIES_MIN_NAME_LENGTH,
                                 const boost::uint32_t maxLength = PROPERTIES_MAX_NAME_LENGTH);

std::string validatePropertyDesc(const std::string& propertyName,
                                 const std::string& description,
                                 const boost::uint32_t minLength = PROPERTIES_MIN_DESCRIPTION_LENGTH,
                                 const boost::uint32_t maxLength = PROPERTIES_MAX_DESCRIPTION_LENGTH);

template<typename T>
T sizeToBytes(const std::string& sizeString)
{
    std::string trimmed = boost::algorithm::trim_copy(sizeString);
    if (trimmed.empty()) {
        THROW_SECP_ERROR(InvalidByteSizeDescriptorError,
                  "The byte size descriptor cannot be empty");
    }
    std::locale cLocale("C");
    if (!std::isdigit(trimmed[0], cLocale)) {
        THROW_SECP_ERROR(InvalidByteSizeDescriptorError,
                  "Invalid byte size descriptor \"" + trimmed + "\": It must begin with a digit");
    }
    std::istringstream stream(trimmed);
    stream.imbue(cLocale);
    boost::uintmax_t result;
    std::string suffix;
    stream >> result;
    size_t streamPos = boost::lexical_cast<size_t>(stream.tellg());
    if (streamPos < trimmed.length() &&
        trimmed.find_first_not_of("bBkKmMgG", streamPos) != std::string::npos) {
        THROW_SECP_ERROR(InvalidByteSizeDescriptorError,
                  "Invalid byte size descriptor \"" + trimmed +
                  "\": The suffix must be one of (case-insensitive) b, k[b], m[b], or g[b]");
    }
    stream >> suffix;
    if (!suffix.empty()) {
        if (suffix.length() > 2 ||
            (suffix.length() == 2 &&
             (suffix[0] == 'B' || suffix[0] == 'b' || (suffix[1] != 'B' && suffix[1] != 'b')))) {
            THROW_SECP_ERROR(InvalidByteSizeDescriptorError,
                      "Invalid byte size descriptor \"" + trimmed +
                      "\": The suffix must be one of (case-insensitive) b, k[b], m[b], or g[b]");
        }
        if (suffix[0] == 'B' || suffix[0] == 'b') {
            result *= 1;
        } else if (suffix[0] == 'K' || suffix[0] == 'k') {
            result *= 1024;
        } else if (suffix[0] == 'M' || suffix[0] == 'm') {
            result *= 1024 * 1024;
        } else if (suffix[0] == 'G' || suffix[0] == 'g') {
            result *= 1024 * 1024 * 1024;
        } else {
            THROW_SECP_ERROR(InvalidByteSizeDescriptorError,
                      "Invalid byte size descriptor \"" + trimmed +
                      "\": The suffix must be one of (case-insensitive) b, k[b], m[b], or g[b]");
        }
    }
    if (result > std::numeric_limits<T>::max()) {
        std::ostringstream msg;
        msg << "Invalid byte size descriptor \"" << trimmed << "\": The resulting value of " <<
        result << " is greater than the maximum allowed value of " <<
        std::numeric_limits<T>::max();
        THROW_SECP_ERROR(PropertyRangeLimitError, msg.str());
    }
    return static_cast<T>(result);
}

/**
 * The classes are used for property types, storing them as real types and not strings. Provide defaults and
 * limits and self-validate.  They will throw a PropertyRangeLimitError if the value is outside the range
 * limits with the one exception: for std::strings the error is throw if the string  is too long.
 */
template<typename T>
class BasicProperty
{
public:
    BasicProperty()
    : name_(),
      description_(),
      defaultValue_(),
      value_(),
      stringValue_()
    {}

    BasicProperty(const std::string& propertyName,
                  const T& valueDefault,
                  const std::string& description)
        : name_(validatePropertyName(propertyName)),
          description_(validatePropertyDesc(name_, description)),
          defaultValue_(valueDefault),
          value_(defaultValue_),
          stringValue_(std::to_string(defaultValue_))
    {}

    virtual ~BasicProperty()
    {}

    const std::string& name() const
    {
        return name_;
    }

    const std::string& description() const
    {
        return description_;
    }

    const T& defaultValue() const
    {
        return defaultValue_;
    }

    const T& value() const
    {
        return value_;
    }

    const std::string& stringValue() const
    {
        return stringValue_;
    }

    virtual void setValue(const T& newValue)
    {
        value_ = newValue;
    }

    virtual void setDefault()
    {
        value_ = defaultValue_;
    }

    virtual void setStringValue(const std::string& newValue)
    {
        stringValue_ = newValue;
    }

    virtual bool isNonDefault()
    {
        return value_ == defaultValue_ ? false : true;
    }


protected:
    std::string name_;
    std::string description_;
    T defaultValue_;
    T value_;
    std::string stringValue_;

};

/**
 * Intermediate parent class for Numeric properties
 */
template<typename T>
class NumericProperty : public BasicProperty<T>
{
public:
    NumericProperty()
        : BasicProperty<T>()
    {}

    NumericProperty(const std::string& propertyName,
                    const T& valueDefault,
                    const std::string& description)
        : BasicProperty<T>(propertyName, valueDefault, description),
          rangeMin_(std::numeric_limits<T>::min()),
          rangeMax_(std::numeric_limits<T>::max()),
          typeMin_(std::numeric_limits<T>::min()),
          typeMax_(std::numeric_limits<T>::max())
    {}

    virtual ~NumericProperty()
    {}

    virtual void setValue(const T& newValue)
    {

        if (newValue >= rangeMin_ && newValue <= rangeMax_) {
            BasicProperty<T>::value_ = newValue;
        } else {
            std::stringstream ss;
            ss << "NumericProperty::setValue() - property: \"" << BasicProperty<T>::name_
               << "\" value:" << newValue
               << "] out side of range limits, min:[" << rangeMin_
               << "] max:[" << rangeMax_ << "]";
            THROW_SECP_ERROR(PropertyRangeLimitError, ss.str().c_str());
        }
        BasicProperty<T>::stringValue_ = boost::lexical_cast<std::string>(BasicProperty<T>::value_);
    }

    virtual void setStringValue(const std::string& stringValue)
    {
        std::string workString(stringValue);
        T intValue = sizeToBytes<T>(workString);

        // now test the actual value:
        if ((intValue < rangeMin_ ) || (intValue > rangeMax_) ) {
            std::stringstream ss;
            ss << "NumericProperty::setStringValue() - property: \"" << BasicProperty<T>::name_
               << "\" value:" << intValue
               << "] out side of range limits, min:[" << rangeMin_
               << "] max:[" << rangeMax_ << "]";
            THROW_SECP_ERROR(PropertyRangeLimitError, ss.str().c_str());

        } else {
            BasicProperty<T>::value_ = intValue;
        }

        BasicProperty<T>::stringValue_ = boost::lexical_cast<std::string>(BasicProperty<T>::value_);
    }

    NumericProperty<T>& setRange(const T& min, const T& max)
    {
        if (min >= typeMin_ && max <= typeMax_ && max >= BasicProperty<T>::defaultValue_ && min <= BasicProperty<T>::defaultValue_) {
            rangeMin_ = min;
            rangeMax_ = max;
        } else {
            std::stringstream ss;
            ss << "NumericProperty::setRange() - For property: \"" << BasicProperty<T>::name_
               << "\"  out side of range limits, min:[" << rangeMin_
               << "], max:[" << rangeMax_ << "]";
            THROW_SECP_ERROR(PropertyRangeLimitError, ss.str().c_str());
        }
        return *this;
    }

    T& rangeMin()
    {
        return rangeMin_;
    }

    T& rangeMax()
    {
        return rangeMax_;
    }

private:
    T rangeMin_;
    T rangeMax_;
    T typeMin_;
    T typeMax_;

};

typedef NumericProperty<std::uint32_t> Uint32Property;
typedef NumericProperty<std::uint64_t> Uint64Property;

} //namespace secp


#endif /* PROPERTY_TYPES_HPP_ */





