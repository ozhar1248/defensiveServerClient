#pragma once
#include <array>
#include <vector>
#include <string>
#include <cstdint>

class Encryption {
public:
    // ---------- AES ----------
    // AES-CBC with 16-byte key, IV = all zeros (per spec)
    static std::vector<uint8_t> AesCbcEncryptZeroIV(const std::array<uint8_t,16>& key,
                                                    const std::vector<uint8_t>& plain);
    static std::vector<uint8_t> AesCbcDecryptZeroIV(const std::array<uint8_t,16>& key,
                                                    const std::vector<uint8_t>& cipher,
                                                    bool& ok);

    // Utility: produce a 16-byte random AES key
    static std::array<uint8_t,16> GenerateAesKey();

    // ---------- RSA ----------
    // RSA-OAEP(SHA) with peer's public key provided as Base64 DER (Crypto++ RSA::PublicKey::DEREncode output)
    static std::vector<uint8_t> RsaEncryptOaepWithBase64Pub(const std::string& asciiBase64DerPublic,
                                                            const std::vector<uint8_t>& plain);

    // RSA-OAEP(SHA) decrypt with my private key provided as Base64 DER (Crypto++ RSA::PrivateKey::DEREncode output)
    // Returns plaintext. 'ok' indicates success/failure.
    static std::vector<uint8_t> RsaDecryptOaepWithBase64Priv(const std::string& asciiBase64DerPrivate,
                                                             const std::vector<uint8_t>& cipher,
                                                             bool& ok);

    // Generate 1024-bit RSA keypair; both keys returned as Base64 DER strings
    struct RsaKeyPair {
        std::string publicKeyBase64;   // matches RSA::PublicKey::DEREncode + Base64
        std::string privateKeyBase64;  // matches RSA::PrivateKey::DEREncode + Base64
    };
    static RsaKeyPair GenerateRsaKeypair1024();
};
