//
// Created by Gwendolyn Hunt on 9/9/15.
//
#include "Logger.hpp"
#include <boost/date_time.hpp>
#include <iostream>
#include <mutex>
#include <thread>

namespace
{

std::mutex logMutex;

}

namespace secp
{

const std::string DEBUG("DEBUG");
const std::string INFO("INFO");
const std::string FATAL("FATAL");

void log(const std::string& type, const std::string& logEntry)
{
    std::lock_guard<std::mutex> lock(logMutex);
    auto pt = boost::posix_time::microsec_clock::universal_time();
    std::cout << boost::posix_time::to_iso_extended_string(pt) << " " << type << " " << logEntry << std::endl;
}


}
