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

/**
 * Wrap around based on Robert C Seacord's example 5.2
 */
void uint32WrapAround()
{
    std::cout << "Unsigned int wrap" << std::endl;

    std::uint32_t ui{std::numeric_limits<std::uint32_t >::max()};

    printResult("max unsigned", ui);

    ui++;

    printResult("wrapped (++)", ui);

    ui = std::numeric_limits<std::uint32_t >::min();

    printResult("min unsigned", ui);

    ui--;

    printResult("wrapped (--)", ui);
}

int main()
{
    uint32WrapAround();
    return EXIT_SUCCESS;
}