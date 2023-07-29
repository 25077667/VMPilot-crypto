#include <VMPilot_crypto.hpp>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <memory>

std::vector<uint8_t> VMPilot::Crypto::Encrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                                const std::string &key) noexcept
{
    std::vector<uint8_t> result;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (ctx == nullptr)
        return result;

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const uint8_t *>(key.c_str()), nullptr) != 1)
        return result;

    result.resize(data.size() + EVP_CIPHER_CTX_block_size(ctx.get()));

    int len = 0;
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx.get(), result.data(), &len, data.data(), data.size()) != 1)
        return result;

    out_len = len;

    if (EVP_EncryptFinal_ex(ctx.get(), result.data() + len, &len) != 1)
        return result;

    out_len += len;
    result.resize(out_len);
    return result;
}

std::vector<uint8_t> VMPilot::Crypto::Decrypt_AES_256_CBC_PKCS7(const std::vector<uint8_t> &data,
                                                                const std::string &key) noexcept
{
    std::vector<uint8_t> result;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (ctx == nullptr)
        return result;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const uint8_t *>(key.c_str()), nullptr) != 1)
        return result;

    result.resize(data.size());

    int len = 0;
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), result.data(), &len, data.data(), data.size()) != 1)
        return result;

    out_len = len;

    if (EVP_DecryptFinal_ex(ctx.get(), result.data() + len, &len) != 1)
        return result;

    out_len += len;
    result.resize(out_len);
    return result;
}

std::vector<uint8_t> VMPilot::Crypto::SHA256(const std::vector<uint8_t> &data,
                                             const std::vector<uint8_t> &salt) noexcept
{
    std::vector<uint8_t> result;

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
    if (ctx == nullptr)
        return result;

    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        return result;

    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
        return result;

    if (EVP_DigestUpdate(ctx.get(), salt.data(), salt.size()) != 1)
        return result;

    result.resize(EVP_MD_size(EVP_sha256()));

    unsigned int len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), result.data(), &len) != 1)
        return result;

    result.resize(len);
    return result;
}