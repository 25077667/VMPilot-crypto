#include "../VMPilot_crypto.hpp"

#include <iostream>

int main()
{
    std::vector<uint8_t> data = {0x00, 0x01, 0x02, 0x03};
    std::vector<uint8_t> salt = {0x04, 0x05, 0x06, 0x07};
    const auto res = VMPilot::Crypto::BLAKE3(data, salt);

    for (const auto &i : res)
    {
        std::cout << std::hex << static_cast<int>(i) << " ";
    }
}
