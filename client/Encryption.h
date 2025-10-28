#pragma once
#include <array>
#include <vector>
#include <string>
#include <cstdint>

class Encryption {
public:
    // AES-CBC with 16-byte key, IV = all zeros (per spec)
    static std::vector<uint8_t> AesCbcEncryptZeroIV(const std::array<uint8_t,16>& key,
                                                    const std::vector<uint8_t>& plain);
    static std::vector<uint8_t> AesCbcDecryptZeroIV(const std::array<uint8_t,16>& key,
                                                    const std::vector<uint8_t>& cipher,
                                                    bool& ok);

    // RSA-OAEP(SHA) with peer's X509 public key provided as Base64 DER
    static std::vector<uint8_t> RsaEncryptOaepWithBase64X509Pub(const std::string& asciiBase64X509,
                                                                const std::vector<uint8_t>& plain);

    // Utility: produce a 16-byte random AES key
    static std::array<uint8_t,16> GenerateAesKey();
};
