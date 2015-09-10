//
// Created by Gwendolyn Hunt on 9/9/15.
//
#include "Logger.hpp"
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

namespace
{

std::mutex logMutex;

}

namespace secp
{

const std::string DEBUG("DEBUG");
const std::string INFO("INFO");

void log(const std::string& type, const std::string& logEntry)
{
    std::lock_guard<std::mutex> lock(logMutex);
    auto ct  = std::chrono::system_clock::now();
    auto ttp = std::chrono::system_clock::to_time_t(ct);
    std::cout << std::ctime(&ttp) << " " << type << " " << logEntry << std::endl;
}


}
