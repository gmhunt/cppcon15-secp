//
// Created by Gwendolyn Hunt on 9/22/15.
//

#include <cstdint>
#include <limits>
#include <iostream>
#include <iomanip>

template<typename IntType>
void printResult(const std::string& label, const IntType t)
{
    std::cout << "\t" << label << ": " << std::setw(12) << t << std::endl;
}

void int32Overflow()
{
    std::cout << "Signed int overflow" << std::endl;

    std::int32_t i{std::numeric_limits<std::int32_t>::max()};

    printResult("max signed   ", i);

    i++;

    printResult("overflow (++)", i);

    i = std::numeric_limits<std::int32_t >::min();

    printResult("min signed   ", i);

    i--;

    printResult("overflow (--)", i);
}


int main()
{
    int32Overflow();
    return EXIT_SUCCESS;
}