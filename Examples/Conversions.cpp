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
void conversions()
{
    std::cout << "Conversions" << std::endl;
    std::uint32_t ui32{std::numeric_limits<std::uint32_t>::max()};
    printResult("max unsigned 32-bit...............", ui32);
    std::int32_t i32{0};
    i32 = ui32;
    printResult("max unsigned to signed 32-bit.....", i32);

    std::uint16_t ui16{std::numeric_limits<std::uint16_t>::max()};
    printResult("max unsigned 16-bit...............", ui16);
    ui32 = ui16;
    printResult("16-bit unsigned to 32-bit unsigned", ui32);

    ui32 = std::numeric_limits<std::uint32_t>::max();
    printResult("max unsigned 32-bit...............", ui32);
    ui16 = ui32;
    printResult("32-bit unsigned to 16-bit unsigned", ui16);

}

int main()
{
    conversions();
    return EXIT_SUCCESS;
}