/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "alcp/rsa.hh"
#include "alcp/digest.hh"
#include "alcp/rng/drbg.hh"
#include "alcp/rsa/rsa_internal.hh"
#include "alcp/rsa/rsa_reference.hh"
#include "alcp/rsa/rsa_zen.hh"
#include "alcp/rsa/rsa_zen3.hh"
#include "alcp/rsa/rsa_zen4.hh"
#include "alcp/rsa/rsaerror.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#include "config.h"

using alcp::utils::CpuId;

namespace alcp::rsa {

#include "rsa.cc.inc"

// clang-format off
// As per rfc8017 appendix-A.2.4
static const Uint8 DigestInfo[SHA_UNKNOWN][19] = 
                    {{0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
                      0x05, 0x00, 0x04, 0x1c},
                     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                      0x05, 0x00, 0x04, 0x20},
                     {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
                      0x05, 0x00, 0x04, 0x30},
                     {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                      0x05, 0x00, 0x04, 0x40},
                     {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05,
                      0x05, 0x00, 0x04, 0x1c},
                     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06,
                      0x05, 0x00, 0x04, 0x20}
                    };

// clang-format on
static const Uint64 Sha512Size = 64;

static inline Uint8
IsZero(Uint8 num)
{
    return (0 - (static_cast<Uint8>(~num & (num - 1)) >> 7));
}

static inline Uint8
IsEqual(const Uint8* first, const Uint8* second, Uint16 len)
{
    Uint8 num = 0;
    for (Uint16 i = 0; i < len; i++)
        num |= (first[i] ^ second[i]);
    return IsZero(num);
}

static inline Uint8
IsLess(Uint8 first, Uint8 second)
{
    return 0 - (static_cast<Uint8>(first - second) >> 7);
}

static inline Uint8
Select(Uint8 mask, Uint8 first, Uint8 second)
{
    return (mask & first) | (~mask & second);
}

static inline void
Reset(void* buff, Uint64 size)
{
    if (buff) {
        alcp::utils::PadCompleteBlock<Uint64, 1ULL>(buff, 0LL, size);
    }
}

template<alc_rsa_key_size T>
Rsa<T>::Rsa()
    : m_key_size{ T / 8 }
    , m_digest_info_index{ SHA_UNKNOWN }
{}

template<alc_rsa_key_size T>
void
Rsa<T>::setDigest(digest::IDigest* digest)
{
    if (digest) {
        m_digest   = digest;
        m_hash_len = digest->getHashSize();
        switch (m_hash_len * 8) {
            case ALC_DIGEST_LEN_224:
                m_digest_info_index =
                    digest->getInputBlockSize() == 64
                        ? SHA_224
                        : SHA_512_224; // SHA_512_224 chunk size is 128 bytes
                break;
            case ALC_DIGEST_LEN_256:
                m_digest_info_index =
                    digest->getInputBlockSize() == 64
                        ? SHA_256
                        : SHA_512_256; // SHA_512_256 chunk size is 128 bytes
                break;
            case ALC_DIGEST_LEN_384:
                m_digest_info_index = SHA_384;
                break;
            case ALC_DIGEST_LEN_512:
                m_digest_info_index = SHA_512;
                break;
        }
    }
}

template<alc_rsa_key_size T>
void
Rsa<T>::setMgf(digest::IDigest* mgf)
{
    if (mgf) {
        m_mgf          = mgf;
        m_mgf_hash_len = mgf->getHashSize();
    }
}

template<alc_rsa_key_size T>
void
Rsa<T>::maskGenFunct(Uint8*       mask,
                     Uint64       maskSize,
                     const Uint8* input,
                     Uint64       inputLen)
{
    Uint64 out_len = 0;
    Uint32 count   = 0;
    Uint8  count_array[4];
    Uint8  hash[Sha512Size];

    while (out_len < maskSize) {

        m_mgf->reset();

        m_mgf->update(input, inputLen);
        count_array[0] = (count >> 24) & 0xff;
        count_array[1] = (count >> 16) & 0xff;
        count_array[2] = (count >> 8) & 0xff;
        count_array[3] = count & 0xff;

        m_mgf->finalize(count_array, 4);

        Uint64 copy_size = m_mgf_hash_len;
        if (out_len + m_mgf_hash_len <= maskSize) {
            m_mgf->copyHash(mask + out_len, m_mgf_hash_len);
        } else {
            m_mgf->copyHash(hash, m_mgf_hash_len);
            utils::CopyBytes(mask + out_len, hash, maskSize - out_len);
            break;
        }

        ++count;
        out_len += copy_size;
    }
}

template<alc_rsa_key_size T>
Rsa<T>::~Rsa()
{
    reset();
}

template<alc_rsa_key_size T>
Status
Rsa<T>::encryptPublic(const Uint8* pText, Uint64 textSize, Uint8* pEncText)
{
    // For non padded output
    if (textSize != m_pub_key.m_size * 8) {
        return status::NotPermitted("Text size should be equal to modulus");
    }

    if (pText == nullptr || pEncText == nullptr) {
        return status::NotPermitted("Buffer should be non null");
    }

    alignas(64) Uint64 bignum_text[T / 64];
    ConvertToBigNum(pText, bignum_text, m_key_size);

    auto mod_bignum = m_pub_key.m_mod;

    if (!IsLess(bignum_text, mod_bignum, m_pub_key.m_size)) {
        return status::NotPermitted(
            "text absolute value should be less than modulus");
    }

    // FIXME: We should probably use flag base dispatching than ZENVER dispatch
    //        as this kind of dispatch will pick reference in non AMD machines.
    static bool zen4_available = CpuId::cpuIsZen4();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();

    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        zen4::archEncryptPublic<T>(
            pEncText, bignum_text, m_pub_key, m_context_pub);
        return StatusOk();
    } else if (zen3_available) {
        zen3::archEncryptPublic<T>(
            pEncText, bignum_text, m_pub_key, m_context_pub);
        return StatusOk();
    } else if (zen_available || zen_available_flags) {
        zen::archEncryptPublic<T>(
            pEncText, bignum_text, m_pub_key, m_context_pub);
        return StatusOk();
    }

    archEncryptPublic<T>(pEncText, bignum_text, m_pub_key, m_context_pub);

    return StatusOk();
}

template<alc_rsa_key_size T>
Status
Rsa<T>::decryptPrivate(const Uint8* pEncText, Uint64 encSize, Uint8* pText)
{
    // For non padded output
    if (encSize != m_priv_key.m_size * 2 * 8) {
        return status::NotPermitted("Text size should be equal modulous");
    }

    if (pEncText == nullptr || pText == nullptr) {
        return status::NotPermitted("Buffer should be non null");
    }

    Uint64 bignum_text[T / 64];
    ConvertToBigNum(pEncText, bignum_text, m_priv_key.m_size * 2 * 8);

    auto mod_bignum = m_priv_key.m_mod;

    if (!IsLess(bignum_text, mod_bignum, m_priv_key.m_size * 2)) {
        return status::NotPermitted(
            "text absolute value should be less than modulus");
    }

    // FIXME: We should probably use flag base dispatching than ZENVER dispatch
    //        as this kind of dispatch will pick reference in non AMD machines.
    static bool zen4_available = CpuId::cpuIsZen4();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();

    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        zen4::archDecryptPrivate<T>(
            pText, bignum_text, m_priv_key, m_context_p, m_context_q);
        return StatusOk();
    } else if (zen3_available) {
        zen3::archDecryptPrivate<T>(
            pText, bignum_text, m_priv_key, m_context_p, m_context_q);
        return StatusOk();
    } else if (zen_available || zen_available_flags) {
        zen::archDecryptPrivate<T>(
            pText, bignum_text, m_priv_key, m_context_p, m_context_q);
        return StatusOk();
    }

    archDecryptPrivate<T>(
        pText, bignum_text, m_priv_key, m_context_p, m_context_q);

    return StatusOk();
}

template<alc_rsa_key_size T>
Status
Rsa<T>::encryptPublicOaep(const Uint8* pText,
                          Uint64       textSize,
                          const Uint8* pLabel,
                          Uint64       labelSize,
                          const Uint8* pSeed,
                          Uint8*       pEncText)
{
    // clang-format off
            //                     +----------+------+--+-------+
            //                DB = |  lHash   |  PS  |01|   M   |
            //                     +----------+------+--+-------+
            //                                    |
            //          +----------+              |
            //          |   seed   |              |
            //          +----------+              |
            //                |                   |
            //                |-------> MGF ---> xor
            //                |                   |
            //       +--+     V                   |
            //       |00|    xor <----- MGF <-----|
            //       +--+     |                   |
            //         |      |                   |
            //         V      V                   V
            //       +--+----------+----------------------------+
            // EM =  |00|maskedSeed|          maskedDB          |
            //       +--+----------+----------------------------+
    // clang-format on

    Uint8 *p_masked_db, *p_masked_seed;

    if (textSize > m_key_size - 2 * m_hash_len - 2) {
        return status::NotPermitted("input text size is larger than supported");
    }

    if (m_key_size < 2 * m_hash_len + 2) {
        return status::NotPermitted("key size is smaller than supported");
    }

    if (!m_mgf || !m_digest) {
        return status::NotPermitted(
            "digest and mask generation function should be non null");
    }

    auto   mod_text   = std::make_unique<Uint8[]>(m_key_size);
    Uint8* p_mod_text = mod_text.get();
    p_mod_text[0]     = 0;
    p_masked_seed     = p_mod_text + 1;
    p_masked_db       = p_masked_seed + m_hash_len; // seed size equals hashsize

    // generates masked db
    m_digest->reset();
    m_digest->finalize(pLabel, labelSize);
    m_digest->copyHash(p_masked_db, m_hash_len);

    Uint64 p_db_size                      = m_key_size - 1 - m_hash_len;
    p_masked_db[p_db_size - 1 - textSize] = 1;
    memcpy(&p_masked_db[p_db_size - textSize], pText, textSize);

    auto db_mask   = std::make_unique<Uint8[]>(p_db_size);
    auto p_db_mask = db_mask.get();

    maskGenFunct(p_db_mask, p_db_size, pSeed, m_hash_len);

    for (Uint16 i = 0; i < p_db_size; i++) {
        p_masked_db[i] ^= p_db_mask[i];
    }

    auto seed_mask   = std::make_unique<Uint8[]>(m_hash_len);
    auto p_seed_mask = seed_mask.get();

    maskGenFunct(p_seed_mask, m_hash_len, p_masked_db, p_db_size);

    for (Uint16 i = 0; i < m_hash_len; i++) {
        p_masked_seed[i] = pSeed[i] ^ p_seed_mask[i];
    }

    return encryptPublic(p_mod_text, m_key_size, pEncText);
}

template<alc_rsa_key_size T>
Status
Rsa<T>::decryptPrivateOaep(const Uint8* pEncText,
                           Uint64       encSize,
                           const Uint8* pLabel,
                           Uint64       labelSize,
                           Uint8*       pText,
                           Uint64&      textSize)
{

    // todo move to aligned buffer
    alignas(64) Uint8 mod_text[T / 8];
    // auto mod_text   = std::make_unique<Uint8[]>(encSize);
    auto p_mod_text = mod_text;

    Status status = decryptPrivate(pEncText, encSize, mod_text);

    if (!status.ok()) {
        return status;
    }

    if (m_key_size < 2 * m_hash_len + 2) {
        return status::NotPermitted(
            "decrypted size less than the expected size");
    }

    // decode oaep padding
    Uint8  seed[Sha512Size];       // max seed size is hashlen of sha512
    Uint8  hash_label[Sha512Size]; // max hashlen is of sha512
    Uint64 db_len = encSize - 1 - m_hash_len;

    auto db   = std::make_unique<Uint8[]>(db_len * 2);
    auto p_db = db.get();

    Uint8 success = IsZero(p_mod_text[0]);

    Uint8* p_masked_seed = p_mod_text + 1;
    Uint8* p_masked_db   = p_masked_seed + m_hash_len;

    maskGenFunct(seed, m_hash_len, p_masked_db, db_len);

    for (Uint16 i = 0; i < m_hash_len; i++) {
        seed[i] ^= p_masked_seed[i];
    }

    maskGenFunct(p_db, db_len, seed, m_hash_len);

    for (Uint32 i = 0; i < db_len; i++) {
        p_db[i] ^= p_masked_db[i];
    }

    // create db
    m_digest->reset();
    m_digest->finalize(pLabel, labelSize);
    m_digest->copyHash(hash_label, m_hash_len);

    success &= IsEqual(hash_label, p_db, m_hash_len);

    Uint32 one_index = 0;
    Uint8  found_one = 0;
    for (Uint32 i = m_hash_len; i < db_len; i++) {
        Uint8 is_one  = IsZero(p_db[i] ^ 1);
        Uint8 is_zero = IsZero(p_db[i]);
        one_index     = Select(~found_one & is_one, i, one_index);
        found_one |= is_one;
        success &= (found_one | is_zero);
    }
    success &= found_one;

    Uint32 text_index = one_index + 1;
    Uint32 text_len   = db_len - text_index;

    Uint64 max_msg_len = db_len - m_hash_len - 1;
    for (Uint32 i = 0; i < max_msg_len; i++) {
        Uint8 mask = success & IsLess(i, text_len);
        pText[i]   = Select(mask, p_db[text_index + i], pText[i]);
    }

    textSize = Select(success, text_len, -1);
    memset(p_mod_text, 0, encSize);
    memset(p_db, 0, db_len * 2);
    Uint8 error_code = Select(success, eOk, eInternal);
    return (error_code == eOk) ? StatusOk() : status::Generic("Generic error");
}

template<alc_rsa_key_size T>
Status
Rsa<T>::signPrivatePss(bool         check,
                       const Uint8* pText,
                       Uint64       textSize,
                       const Uint8* salt,
                       Uint64       saltSize,
                       Uint8*       pSignedBuff)
{

    // Add Pss encoding
    if (!pText || (saltSize > 0 && !salt) || !pSignedBuff
        || (T / 8 < m_hash_len + saltSize + 2)) {
        return status::NotPermitted(
            "Input parameters are incorrect for signing");
    }

    if (!m_digest) {
        return status::NotPermitted("hash function is not assigned");
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    alignas(64) Uint8 message[T / 8], message_check[T / 8], hash[64]{};

    m_digest->reset();
    m_digest->finalize(pText, textSize);
    m_digest->copyHash(hash, m_hash_len);

    auto message_tmp = std::make_unique<Uint8[]>(m_hash_len + saltSize + 8);
    auto p_message   = message_tmp.get();
    utils::CopyBytes(p_message + 8, hash, m_hash_len);
    utils::CopyBytes(p_message + 8 + m_hash_len, salt, saltSize);

    m_digest->reset();
    m_digest->finalize(p_message, m_hash_len + saltSize + 8);
    m_digest->copyHash(hash, m_hash_len);

    Uint64 p_db_size = T / 8 - m_hash_len - 1;
    auto   db        = std::make_unique<Uint8[]>(p_db_size);
    auto   p_db      = db.get();

    Uint64 pos = T / 8 - saltSize - m_hash_len - 2;
    p_db[pos]  = 0x01;
    utils::CopyBytes(p_db + pos + 1, salt, saltSize);

    auto db_mask   = std::make_unique<Uint8[]>(p_db_size);
    auto p_db_mask = db_mask.get();

    maskGenFunct(p_db_mask, p_db_size, hash, m_hash_len);

    for (Uint16 i = 0; i < p_db_size; i++) {
        p_db[i] ^= p_db_mask[i];
    }

    utils::CopyBytes(message, p_db, p_db_size);
    utils::CopyBytes(message + p_db_size, hash, m_hash_len);
    message[T / 8 - 1] = 0xbc;

    // emLen = 256  and emBits is 2047.Set the leftmost 8emLen - emBits bits of
    // the leftmost octet in maskedDB to zero as per rfc8017
    message[0] &= 0x7f;
    Status status = decryptPrivate(message, T / 8, pSignedBuff);

    // verify signature for mitigating the fault tolerance attack
    if (check) {
        status = encryptPublic(pSignedBuff, T / 8, message_check);

        Uint64* num1 = reinterpret_cast<Uint64*>(message);
        Uint64* num2 = reinterpret_cast<Uint64*>(message_check);
        Uint64  res  = 0;
        for (Uint64 i = 0; i < T / 64; i++) {
            res += (*num1 ^ *num2);
        }
        if (res != 0) {
            status = status::Generic("Generic error");
            utils::PadBytes(pSignedBuff, 0, T / 8);
        }
    }

    return status;
}

template<alc_rsa_key_size T>
Status
Rsa<T>::verifyPublicPss(const Uint8* pText,
                        Uint64       textSize,
                        const Uint8* pSignedBuff)
{
    if (!pText || !pSignedBuff) {
        return status::NotPermitted(
            "Input parameters are incorrect for signing");
    }

    if (!m_digest) {
        return status::NotPermitted("hash function is not assigned");
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    alignas(64) Uint8 mod_text[T / 8];

    Status status = encryptPublic(pSignedBuff, T / 8, mod_text);
    if (!status.ok()) {
        return status;
    }

    Uint8 success = IsZero(0xbc ^ mod_text[T / 8 - 1]);

    alignas(64) Uint8 hash[64]{};

    m_digest->reset();
    m_digest->finalize(pText, textSize);
    m_digest->copyHash(hash, m_hash_len);

    Uint64 db_len      = T / 8 - m_hash_len - 1;
    auto   masked_db   = std::make_unique<Uint8[]>(db_len);
    auto   p_masked_db = masked_db.get();
    auto   db_mask     = std::make_unique<Uint8[]>(db_len);
    auto   p_db_mask   = db_mask.get();

    alignas(64) Uint8 h[64]{};

    utils::CopyBytes(p_masked_db, mod_text, db_len);

    utils::CopyBytes(h, mod_text + db_len, m_hash_len);

    maskGenFunct(p_db_mask, db_len, h, m_hash_len);

    for (Uint16 i = 0; i < db_len; i++) {
        p_masked_db[i] ^= p_db_mask[i];
        p_db_mask[i] = 0;
    }
    // Set the leftmost 8emLen - emBits bits of the leftmost octet
    // in DB to zero as per rfc8017
    p_masked_db[0] &= 0x7f;
    Uint16 i = 0;
    for (; p_masked_db[i] == 0 && i < (db_len - 1); i++)
        ;

    success &= IsZero(p_masked_db[i++] ^ 0x1);

    Uint16 saltLen = db_len - i;

    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    utils::CopyBytes(p_db_mask + 8, hash, m_hash_len);
    utils::CopyBlock(p_db_mask + 8 + m_hash_len, p_masked_db + i, saltLen);

    m_digest->reset();
    m_digest->finalize(p_db_mask, 8 + m_hash_len + saltLen);
    m_digest->copyHash(hash, m_hash_len);

    success &= IsEqual(h, hash, m_hash_len);
    Uint8 error_code = Select(success, eOk, eInternal);
    return (error_code == eOk) ? StatusOk() : status::Generic("Generic error");
}

template<alc_rsa_key_size T>
Status
Rsa<T>::signPrivatePkcsv15(bool         check,
                           const Uint8* pText,
                           Uint64       textSize,
                           Uint8*       pSignedBuff)
{
    if (!pText || !pSignedBuff) {
        return status::NotPermitted(
            "Input parameters are incorrect for signing");
    }

    if (!m_digest || m_digest_info_index >= SHA_UNKNOWN) {
        return status::NotPermitted("hash function is not assigned");
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    alignas(64) Uint8 message[T / 8]{}, message_check[T / 8]{}, hash[64]{};

    m_digest->reset();
    m_digest->finalize(pText, textSize);
    m_digest->copyHash(hash, m_hash_len);

    // Encoded message :- 0x00 || 0x01 || PS || 0x00 || (DigestInfo || hash)
    message[1]     = 0x01;
    Uint64 pad_len = T / 8 - 3 - 19 - m_hash_len;
    utils::PadBytes(message + 2, 0xf, pad_len);
    utils::CopyBytes(
        message + 3 + pad_len, DigestInfo[m_digest_info_index], 19);
    utils::CopyBytes(message + 3 + pad_len + 19, hash, m_hash_len);

    Status status = decryptPrivate(message, T / 8, pSignedBuff);

    // verify signature for mitigating the fault tolerance attack
    if (check) {
        status = encryptPublic(pSignedBuff, T / 8, message_check);

        Uint64* num1 = reinterpret_cast<Uint64*>(message);
        Uint64* num2 = reinterpret_cast<Uint64*>(message_check);
        Uint64  res  = 0;
        for (Uint64 i = 0; i < T / 64; i++) {
            res += (*num1 ^ *num2);
        }
        if (res != 0) {
            status = status::Generic("Generic error");
            utils::PadBytes(pSignedBuff, 0, T / 8);
        }
    }
    return status;
}

template<alc_rsa_key_size T>
Status
Rsa<T>::verifyPublicPkcsv15(const Uint8* pText,
                            Uint64       textSize,
                            const Uint8* pSignedBuff)
{
    alignas(64) Uint8 mod_text[T / 8], hash[64], message[T / 8]{};

    if (!pText || !pSignedBuff) {
        return status::NotPermitted(
            "Input parameters are incorrect for signing");
    }

    if (!m_digest || m_digest_info_index >= SHA_UNKNOWN) {
        return status::NotPermitted("hash function is not assigned");
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    Status status = encryptPublic(pSignedBuff, T / 8, mod_text);
    if (!status.ok()) {
        return status;
    }

    m_digest->reset();
    m_digest->finalize(pText, textSize);
    m_digest->copyHash(hash, m_hash_len);

    // Encoded message :- 0x00 || 0x01 || PS || 0x00 || (DigestInfo || hash)
    message[1]     = 0x01;
    Uint64 pad_len = T / 8 - 3 - 19 - m_hash_len;
    utils::PadBytes(message + 2, 0xf, pad_len);
    utils::CopyBytes(
        message + 3 + pad_len, DigestInfo[m_digest_info_index], 19);
    utils::CopyBytes(message + 3 + pad_len + 19, hash, m_hash_len);

    Uint64* num1 = reinterpret_cast<Uint64*>(message);
    Uint64* num2 = reinterpret_cast<Uint64*>(mod_text);
    Uint64  res  = 0;
    for (Uint64 i = 0; i < T / 64; i++) {
        res += (*num1 ^ *num2);
    }

    return !res ? status : status::Generic("Generic error");
}

template<alc_rsa_key_size T>
Status
Rsa<T>::getPublickey(RsaPublicKey& pPublicKey)
{
    if (pPublicKey.size != m_key_size) {
        return status::NotPermitted("keyize should match");
    }
    Uint8* mod_text = reinterpret_cast<Uint8*>(m_pub_key.m_mod);

    if (pPublicKey.modulus == nullptr || mod_text == nullptr) {
        return status::NotPermitted("Modulus cannot be empty");
    }

    pPublicKey.public_exponent = m_pub_key.m_public_exponent;

    for (Int64 i = m_key_size - 1, j = 0; i >= 0; --i, ++j) {
        pPublicKey.modulus[j] = mod_text[i];
    }

    return StatusOk();
}

template<alc_rsa_key_size T>
Status
Rsa<T>::setPublicKey(const Uint64 exponent, const Uint8* mod, const Uint64 size)
{
    if (!mod || exponent == 0) {
        return status::NotPermitted("Invalid public key");
    }

    if (!(size == 128 || size == 256)) {
        return status::NotPermitted("Key sizes not supported currently");
    }

    m_pub_key.m_public_exponent = exponent;
    ConvertToBigNum(mod, m_pub_key.m_mod, size);
    m_pub_key.m_size           = size / 8;
    m_key_size                 = size;
    static bool zen4_available = CpuId::cpuIsZen4();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();
    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        zen4::archCreateContext<T>(
            m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);

    } else if (zen3_available) {
        zen3::archCreateContext<T>(
            m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);

    } else if (zen_available || zen_available_flags) {
        zen::archCreateContext<T>(
            m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);

    } else {

        archCreateContext<T>(m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
    }
    return StatusOk();
}

template<alc_rsa_key_size T>
Status
Rsa<T>::setPrivateKey(const Uint8* dp,
                      const Uint8* dq,
                      const Uint8* p,
                      const Uint8* q,
                      const Uint8* qinv,
                      const Uint8* mod,
                      const Uint64 size)
{
    if (!dp || !dq || !p || !q || !mod) {
        return status::NotPermitted("Invalid private key");
    }

    if (!(size == 128 || size == 64)) {
        return status::NotPermitted("Key sizes not supported currently");
    }

    m_key_size = size * 2; // keysize is twice the sizeof(p)

    ConvertToBigNum(dp, m_priv_key.m_dp, size);
    ConvertToBigNum(dq, m_priv_key.m_dq, size);
    ConvertToBigNum(p, m_priv_key.m_p, size);
    ConvertToBigNum(q, m_priv_key.m_q, size);
    ConvertToBigNum(qinv, m_priv_key.m_qinv, size);
    ConvertToBigNum(mod, m_priv_key.m_mod, size * 2);
    m_priv_key.m_size = size / 8;

    static bool zen4_available = CpuId::cpuIsZen4();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();
    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        zen4::archCreateContext<T>(
            m_context_p, m_priv_key.m_p, m_priv_key.m_size);
        zen4::archCreateContext<T>(
            m_context_q, m_priv_key.m_q, m_priv_key.m_size);
    } else if (zen3_available) {
        zen3::archCreateContext<T>(
            m_context_p, m_priv_key.m_p, m_priv_key.m_size);
        zen3::archCreateContext<T>(
            m_context_q, m_priv_key.m_q, m_priv_key.m_size);
    } else if (zen_available || zen_available_flags) {
        zen::archCreateContext<T>(
            m_context_p, m_priv_key.m_p, m_priv_key.m_size);
        zen::archCreateContext<T>(
            m_context_q, m_priv_key.m_q, m_priv_key.m_size);
    } else {

        archCreateContext<T>(m_context_p, m_priv_key.m_p, m_priv_key.m_size);
        archCreateContext<T>(m_context_q, m_priv_key.m_q, m_priv_key.m_size);
    }
    return StatusOk();
}

template<alc_rsa_key_size T>
void
Rsa<T>::reset()
{
    Reset(m_priv_key.m_dp, T / (2 * 64));
    Reset(m_priv_key.m_dq, T / (2 * 64));
    Reset(m_priv_key.m_mod, T / (64));
    Reset(m_priv_key.m_p, T / (2 * 64));
    Reset(m_priv_key.m_q, T / (2 * 64));
    Reset(m_priv_key.m_qinv, T / (2 * 64));
    Reset(m_pub_key.m_mod, T / (64));
    Reset(m_context_pub.m_mod_radix_52_bit, T / 52 + 1);
    Reset(m_context_p.m_mod_radix_52_bit, T / (2 * 52) + 1);
    Reset(m_context_q.m_mod_radix_52_bit, T / (2 * 52) + 1);
}

template<alc_rsa_key_size T>
Uint64
Rsa<T>::getKeySize()
{
    return m_key_size;
}
template class Rsa<KEY_SIZE_1024>;
template class Rsa<KEY_SIZE_2048>;
} // namespace alcp::rsa