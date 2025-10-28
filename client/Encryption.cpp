#include "Encryption.h"
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/queue.h>
#include <cryptopp/secblock.h>
#include <string>

std::vector<uint8_t> Encryption::AesCbcEncryptZeroIV(
    const std::array<uint8_t,16>& key, const std::vector<uint8_t>& plain)
{
    using namespace CryptoPP;
    std::vector<uint8_t> out;
    CBC_Mode<AES>::Encryption enc(key.data(), key.size(),
                                  std::vector<byte>(AES::BLOCKSIZE, 0).data());
    StringSource ss(plain.data(), plain.size(), true,
        new StreamTransformationFilter(enc, new VectorSink(out)));
    return out;
}

std::vector<uint8_t> Encryption::AesCbcDecryptZeroIV(
    const std::array<uint8_t,16>& key, const std::vector<uint8_t>& cipher, bool& ok)
{
    using namespace CryptoPP;
    std::vector<uint8_t> out;
    try {
        CBC_Mode<AES>::Decryption dec(key.data(), key.size(),
                                      std::vector<byte>(AES::BLOCKSIZE, 0).data());
        StringSource ss(cipher.data(), cipher.size(), true,
            new StreamTransformationFilter(dec, new VectorSink(out)));
        ok = true;
    } catch (...) { ok = false; }
    return out;
}

std::vector<uint8_t> Encryption::RsaEncryptOaepWithBase64X509Pub(
    const std::string& asciiBase64X509, const std::vector<uint8_t>& plain)
{
    using namespace CryptoPP;
    // Base64 decode SPKI DER bytes
    std::string der;
    StringSource ss(asciiBase64X509, true, new Base64Decoder(new StringSink(der)));

    ByteQueue q;
    q.Put(reinterpret_cast<const byte*>(der.data()), der.size());
    q.MessageEnd();

    RSA::PublicKey pub;
    pub.Load(q);

    AutoSeededRandomPool prng;
    RSAES_OAEP_SHA_Encryptor enc(pub);
    std::string cipher;
    StringSource ss2(plain.data(), plain.size(), true,
        new PK_EncryptorFilter(prng, enc, new StringSink(cipher)));
    return std::vector<uint8_t>(cipher.begin(), cipher.end());
}

std::array<uint8_t,16> Encryption::GenerateAesKey() {
    CryptoPP::AutoSeededRandomPool rng;
    std::array<uint8_t,16> key{};
    rng.GenerateBlock(key.data(), key.size());
    return key;
}
