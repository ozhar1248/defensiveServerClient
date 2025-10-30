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
#include <iostream>

using byte = CryptoPP::byte;

std::vector<uint8_t> Encryption::AesCbcEncryptZeroIV(
    const std::array<uint8_t, 16> &key, const std::vector<uint8_t> &plain)
{
    using namespace CryptoPP;
    std::vector<uint8_t> out;
    SecByteBlock iv(AES::BLOCKSIZE); // zeros by default
    memset(iv, 0, iv.size());

    CBC_Mode<AES>::Encryption enc(key.data(), key.size(), iv);
    StringSource ss(plain.data(), plain.size(), true,
                    new StreamTransformationFilter(enc, new VectorSink(out)));
    return out;
}

std::vector<uint8_t> Encryption::AesCbcDecryptZeroIV(
    const std::array<uint8_t, 16> &key, const std::vector<uint8_t> &cipher, bool &ok)
{
    using namespace CryptoPP;
    std::vector<uint8_t> out;
    ok = false;
    try
    {
        SecByteBlock iv(AES::BLOCKSIZE); // zeros
        memset(iv, 0, iv.size());

        CBC_Mode<AES>::Decryption dec(key.data(), key.size(), iv);
        StringSource ss(cipher.data(), cipher.size(), true,
                        new StreamTransformationFilter(dec, new VectorSink(out)));
        ok = true;
    }
    catch (...)
    {
        ok = false;
    }
    return out;
}

std::array<uint8_t, 16> Encryption::GenerateAesKey()
{
    CryptoPP::AutoSeededRandomPool rng;
    std::array<uint8_t, 16> key{};
    rng.GenerateBlock(key.data(), key.size());
    return key;
}

Encryption::RsaKeyPair Encryption::GenerateRsaKeypair1024()
{
    using namespace CryptoPP;
    AutoSeededRandomPool rng;

    RSA::PrivateKey priv;
    priv.GenerateRandomWithKeySize(rng, 1024);
    RSA::PublicKey pub(priv);

    // DER -> Base64 (no line breaks)
    std::string pubB64, privB64;

    ByteQueue pubQ;
    pub.DEREncode(pubQ);
    Base64Encoder pubEnc(new StringSink(pubB64), false /*insertLineBreaks*/);
    pubQ.CopyTo(pubEnc);
    pubEnc.MessageEnd();

    ByteQueue privQ;
    priv.DEREncodePrivateKey(privQ); // <-- PKCS#1 private key DER
    Base64Encoder privEnc(new StringSink(privB64), false);
    privQ.CopyTo(privEnc);
    privEnc.MessageEnd();

    return {pubB64, privB64};
}

std::vector<uint8_t> Encryption::RsaEncryptOaepWithBase64Pub(
    const std::string &asciiBase64DerPublic, const std::vector<uint8_t> &plain)
{
    using namespace CryptoPP;

    // Base64 decode DER bytes
    std::string der;
    StringSource b64(asciiBase64DerPublic, true, new Base64Decoder(new StringSink(der)));

    ByteQueue q;
    q.Put(reinterpret_cast<const byte *>(der.data()), der.size());
    q.MessageEnd();

    RSA::PublicKey pub;
    pub.Load(q);

    AutoSeededRandomPool prng;
    RSAES_OAEP_SHA_Encryptor enc(pub);

    std::string cipher;
    StringSource ss(plain.data(), plain.size(), true,
                    new PK_EncryptorFilter(prng, enc, new StringSink(cipher)));

    // debug
    std::cerr << "[DBG] pub DER len: " << der.size() << "\n";
    // end debug
    return std::vector<uint8_t>(cipher.begin(), cipher.end());
}

std::vector<uint8_t> Encryption::RsaDecryptOaepWithBase64Priv(
    const std::string &asciiBase64DerPrivate, const std::vector<uint8_t> &cipher, bool &ok)
{
    using namespace CryptoPP;

    ok = false;
    try
    {
        // Base64 decode DER bytes
        std::string der;
        StringSource b64(asciiBase64DerPrivate, true, new Base64Decoder(new StringSink(der)));
        // DEBUG
        std::cerr << "[DBG] priv DER len: " << der.size() << "\n";
        // END DEBUG

        ByteQueue q;
        q.Put(reinterpret_cast<const byte *>(der.data()), der.size());
        q.MessageEnd();

        RSA::PrivateKey priv;
        // Crypto++ encodes private key in DER/BER; use BERDecodePrivateKey for safety
        priv.BERDecodePrivateKey(q, false, q.MaxRetrievable());

        AutoSeededRandomPool prng;
        RSAES_OAEP_SHA_Decryptor dec(priv);

        std::string recovered;
        StringSource ss(cipher.data(), cipher.size(), true,
                        new PK_DecryptorFilter(prng, dec, new StringSink(recovered)));

        ok = true;
        return std::vector<uint8_t>(recovered.begin(), recovered.end());
    }
    catch (const CryptoPP::Exception &e)
    {
        ok = false;
        std::cerr << "[DBG] Crypto++ decrypt exception: " << e.what() << "\n";
        return {};
    }
    catch (...)
    {
        ok = false;
        std::cerr << "[DBG] Crypto++ decrypt exception: unknown\n";
        return {};
    }
}
