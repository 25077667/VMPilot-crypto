#include <VMPilot_crypto.hpp>

#include <blake3.h>

std::vector<uint8_t> VMPilot::Crypto::BLAKE3(const std::vector<uint8_t> &data,
                                             const std::vector<uint8_t> &salt) noexcept
{

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    blake3_hasher_update(&hasher, data.data(), data.size());
    blake3_hasher_update(&hasher, salt.data(), salt.size());

    std::vector<uint8_t> result(BLAKE3_OUT_LEN);
    blake3_hasher_finalize(&hasher, result.data(), result.size());

    return result;
}