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

Rsa::Rsa()
    : m_key_size{ 2048 / 8 }
    , m_digest_info_index{ SHA_UNKNOWN }
{}

Rsa::Rsa(const Rsa& rsa)
{
    m_priv_key          = rsa.m_priv_key;
    m_pub_key           = rsa.m_pub_key;
    m_context_pub       = rsa.m_context_pub;
    m_context_p         = rsa.m_context_p;
    m_context_q         = rsa.m_context_q;
    m_key_size          = rsa.m_key_size;
    m_hash_len          = rsa.m_hash_len;
    m_mgf_hash_len      = rsa.m_mgf_hash_len;
    m_digest_info_index = rsa.m_digest_info_index;
    m_digest_info_size  = rsa.m_digest_info_size;
}

void
Rsa::setDigest(digest::IDigest* digest)
{
    if (digest) {
        m_digest   = digest;
        m_hash_len = digest->getHashSize();
        switch (m_hash_len * 8) {
            case ALC_DIGEST_LEN_128:
                m_digest_info_index = MD_5;
                m_digest_info_size  = 18;
                break;
            case ALC_DIGEST_LEN_160:
                m_digest_info_index = SHA_1;
                m_digest_info_size  = 15;
                break;
            case ALC_DIGEST_LEN_224:
                m_digest_info_index =
                    digest->getInputBlockSize() == 64
                        ? SHA_224
                        : SHA_512_224; // SHA_512_224 chunk size is 128 bytes
                m_digest_info_size = 19;
                break;
            case ALC_DIGEST_LEN_256:
                m_digest_info_index =
                    digest->getInputBlockSize() == 64
                        ? SHA_256
                        : SHA_512_256; // SHA_512_256 chunk size is 128 bytes
                m_digest_info_size = 19;
                break;
            case ALC_DIGEST_LEN_384:
                m_digest_info_index = SHA_384;
                m_digest_info_size  = 19;
                break;
            case ALC_DIGEST_LEN_512:
                m_digest_info_index = SHA_512;
                m_digest_info_size  = 19;
                break;
        }
    }
}

void
Rsa::setMgf(digest::IDigest* mgf)
{
    if (mgf) {
        m_mgf          = mgf;
        m_mgf_hash_len = mgf->getHashSize();
    }
}

void
Rsa::maskGenFunct(Uint8*       mask,
                  Uint64       maskSize,
                  const Uint8* input,
                  Uint64       inputLen)
{
    Uint64 out_len = 0;
    Uint32 count   = 0;
    Uint8  count_array[4];
    Uint8  hash[Sha512Size];

    while (out_len < maskSize) {

        m_mgf->init();

        m_mgf->update(input, inputLen);
        count_array[0] = (count >> 24) & 0xff;
        count_array[1] = (count >> 16) & 0xff;
        count_array[2] = (count >> 8) & 0xff;
        count_array[3] = count & 0xff;

        m_mgf->update(count_array, 4);

        Uint64 copy_size = m_mgf_hash_len;
        if (out_len + m_mgf_hash_len <= maskSize) {
            m_mgf->finalize(mask + out_len, m_mgf_hash_len);
        } else {
            m_mgf->finalize(hash, m_mgf_hash_len);
            utils::CopyBytes(mask + out_len, hash, maskSize - out_len);
            break;
        }

        ++count;
        out_len += copy_size;
    }
}

Rsa::~Rsa()
{
    reset();
}

alc_error_t
Rsa::encryptPublic(const Uint8* pText, Uint64 textSize, Uint8* pEncText)
{
    // For non padded output
    if (textSize != m_pub_key.m_size * 8) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (pText == nullptr || pEncText == nullptr) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    alignas(64) Uint64 bignum_text[2048 / 64];
    ConvertToBigNum(pText, bignum_text, m_key_size);

    auto mod_bignum = m_pub_key.m_mod;

    if (!IsLess(bignum_text, mod_bignum, m_pub_key.m_size)) {
        return ALC_ERROR_INVALID_DATA;
    }

    // FIXME: We should probably use flag base dispatching than ZENVER dispatch
    //        as this kind of dispatch will pick reference in non AMD machines.
    static bool zen4_available = CpuId::cpuIsZen4() || CpuId::cpuIsZen5();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();

    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        if (m_key_size == 2048 / 8) {
            zen4::archEncryptPublic<KEY_SIZE_2048>(
                pEncText, bignum_text, m_pub_key, m_context_pub);
        } else {
            zen4::archEncryptPublic<KEY_SIZE_1024>(
                pEncText, bignum_text, m_pub_key, m_context_pub);
        }
        return ALC_ERROR_NONE;
    } else if (zen3_available) {
        if (m_key_size == 2048 / 8) {
            zen3::archEncryptPublic<KEY_SIZE_2048>(
                pEncText, bignum_text, m_pub_key, m_context_pub);
        } else {
            zen3::archEncryptPublic<KEY_SIZE_1024>(
                pEncText, bignum_text, m_pub_key, m_context_pub);
        }
        return ALC_ERROR_NONE;
    } else if (zen_available || zen_available_flags) {
        if (m_key_size == 2048 / 8) {
            zen::archEncryptPublic<KEY_SIZE_2048>(
                pEncText, bignum_text, m_pub_key, m_context_pub);
        } else {
            zen::archEncryptPublic<KEY_SIZE_1024>(
                pEncText, bignum_text, m_pub_key, m_context_pub);
        }
        return ALC_ERROR_NONE;
    }

    return ALC_ERROR_NOT_SUPPORTED;
}

alc_error_t
Rsa::decryptPrivate(const Uint8* pEncText, Uint64 encSize, Uint8* pText)
{
    // For non padded output
    if (encSize != m_priv_key.m_size * 2 * 8) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (pEncText == nullptr || pText == nullptr) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    Uint64 bignum_text[2048 / 64];
    ConvertToBigNum(pEncText, bignum_text, m_priv_key.m_size * 2 * 8);

    auto mod_bignum = m_priv_key.m_mod;

    if (!IsLess(bignum_text, mod_bignum, m_priv_key.m_size * 2)) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    // FIXME: We should probably use flag base dispatching than ZENVER dispatch
    //        as this kind of dispatch will pick reference in non AMD machines.
    static bool zen4_available = CpuId::cpuIsZen4() || CpuId::cpuIsZen5();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();

    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        if (m_key_size == 2048 / 8) {
            zen4::archDecryptPrivate<KEY_SIZE_2048>(
                pText, bignum_text, m_priv_key, m_context_p, m_context_q);
        } else {
            zen4::archDecryptPrivate<KEY_SIZE_1024>(
                pText, bignum_text, m_priv_key, m_context_p, m_context_q);
        }
        return ALC_ERROR_NONE;
    } else if (zen3_available) {
        if (m_key_size == 2048 / 8) {
            zen3::archDecryptPrivate<KEY_SIZE_2048>(
                pText, bignum_text, m_priv_key, m_context_p, m_context_q);
        } else {
            zen3::archDecryptPrivate<KEY_SIZE_1024>(
                pText, bignum_text, m_priv_key, m_context_p, m_context_q);
        }
        return ALC_ERROR_NONE;
    } else if (zen_available || zen_available_flags) {
        if (m_key_size == 2048 / 8) {
            zen::archDecryptPrivate<KEY_SIZE_2048>(
                pText, bignum_text, m_priv_key, m_context_p, m_context_q);
        } else {
            zen::archDecryptPrivate<KEY_SIZE_1024>(
                pText, bignum_text, m_priv_key, m_context_p, m_context_q);
        }
        return ALC_ERROR_NONE;
    }

    return ALC_ERROR_NOT_PERMITTED;
}

alc_error_t
Rsa::encryptPublicOaep(const Uint8* pText,
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
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (m_key_size < 2 * m_hash_len + 2) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_mgf || !m_digest) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    auto   mod_text   = std::make_unique<Uint8[]>(m_key_size);
    Uint8* p_mod_text = mod_text.get();
    p_mod_text[0]     = 0;
    p_masked_seed     = p_mod_text + 1;
    p_masked_db       = p_masked_seed + m_hash_len; // seed size equals hashsize

    // generates masked db
    m_digest->init();
    m_digest->update(pLabel, labelSize);
    m_digest->finalize(p_masked_db, m_hash_len);

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

alc_error_t
Rsa::decryptPrivateOaep(const Uint8* pEncText,
                        Uint64       encSize,
                        const Uint8* pLabel,
                        Uint64       labelSize,
                        Uint8*       pText,
                        Uint64&      textSize)
{

    // todo move to aligned buffer
    alignas(64) Uint8 mod_text[2048 / 8];
    // auto mod_text   = std::make_unique<Uint8[]>(encSize);
    auto p_mod_text = mod_text;

    if (m_key_size < 2 * m_hash_len + 2) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    decryptPrivate(pEncText, encSize, mod_text);

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
    m_digest->init();
    m_digest->update(pLabel, labelSize);
    m_digest->finalize(hash_label, m_hash_len);

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
    return Select(success, ALC_ERROR_NONE, ALC_ERROR_GENERIC);
}

alc_error_t
Rsa::signPrivatePss(bool         check,
                    const Uint8* pText,
                    Uint64       textSize,
                    const Uint8* salt,
                    Uint64       saltSize,
                    Uint8*       pSignedBuff)
{

    // Add Pss encoding
    if (!pText || (saltSize > 0 && !salt) || !pSignedBuff
        || (m_key_size < m_hash_len + saltSize + 2)) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_digest) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    alignas(64) Uint8 message[2048 / 8], message_check[2048 / 8], hash[64]{};

    m_digest->init();
    m_digest->update(pText, textSize);
    m_digest->finalize(hash, m_hash_len);

    auto message_tmp = std::make_unique<Uint8[]>(m_hash_len + saltSize + 8);
    auto p_message   = message_tmp.get();
    utils::CopyBytes(p_message + 8, hash, m_hash_len);
    if (salt != nullptr)
        utils::CopyBytes(p_message + 8 + m_hash_len, salt, saltSize);

    m_digest->init();
    m_digest->update(p_message, m_hash_len + saltSize + 8);
    m_digest->finalize(hash, m_hash_len);

    Uint64 p_db_size = m_key_size - m_hash_len - 1;
    auto   db        = std::make_unique<Uint8[]>(p_db_size);
    auto   p_db      = db.get();

    Uint64 pos = m_key_size - saltSize - m_hash_len - 2;
    p_db[pos]  = 0x01;

    if (salt != nullptr)
        utils::CopyBytes(p_db + pos + 1, salt, saltSize);

    auto db_mask   = std::make_unique<Uint8[]>(p_db_size);
    auto p_db_mask = db_mask.get();

    maskGenFunct(p_db_mask, p_db_size, hash, m_hash_len);

    for (Uint16 i = 0; i < p_db_size; i++) {
        p_db[i] ^= p_db_mask[i];
    }

    utils::CopyBytes(message, p_db, p_db_size);
    utils::CopyBytes(message + p_db_size, hash, m_hash_len);
    message[m_key_size - 1] = 0xbc;

    // emLen = 256  and emBits is 2047.Set the leftmost 8emLen - emBits bits of
    // the leftmost octet in maskedDB to zero as per rfc8017
    message[0] &= 0x7f;
    alc_error_t err = decryptPrivate(message, m_key_size, pSignedBuff);

    // verify signature for mitigating the fault tolerance attack
    if (check) {
        err = encryptPublic(pSignedBuff, m_key_size, message_check);

        Uint64* num1 = reinterpret_cast<Uint64*>(message);
        Uint64* num2 = reinterpret_cast<Uint64*>(message_check);
        Uint64  res  = 0;
        for (Uint64 i = 0; i < m_key_size / 8; i++) {
            res += (*(num1 + i) ^ *(num2 + i));
        }
        if (res != 0) {
            err = ALC_ERROR_GENERIC;
            utils::PadBytes(pSignedBuff, 0, m_key_size);
        }
    }

    return err;
}

alc_error_t
Rsa::signPrivatePssWithoutHash(const Uint8* pHash,
                               Uint64       hashSize,
                               const Uint8* salt,
                               Uint64       saltSize,
                               Uint8*       pSignedBuff)
{
    // Add Pss encoding
    if (!pHash || (saltSize > 0 && !salt) || !pSignedBuff
        || (m_key_size < hashSize + saltSize + 2)) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_digest) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    alignas(64) Uint8 message[2048 / 8], hash[64]{};

    auto message_tmp = std::make_unique<Uint8[]>(m_hash_len + saltSize + 8);
    auto p_message   = message_tmp.get();
    utils::CopyBytes(p_message + 8, pHash, m_hash_len);
    if (salt != nullptr)
        utils::CopyBytes(p_message + 8 + m_hash_len, salt, saltSize);

    m_digest->init();
    m_digest->update(p_message, m_hash_len + saltSize + 8);
    m_digest->finalize(hash, m_hash_len);

    Uint64 p_db_size = m_key_size - m_hash_len - 1;
    auto   db        = std::make_unique<Uint8[]>(p_db_size);
    auto   p_db      = db.get();

    Uint64 pos = m_key_size - saltSize - m_hash_len - 2;
    p_db[pos]  = 0x01;

    if (salt != nullptr)
        utils::CopyBytes(p_db + pos + 1, salt, saltSize);

    auto db_mask   = std::make_unique<Uint8[]>(p_db_size);
    auto p_db_mask = db_mask.get();

    maskGenFunct(p_db_mask, p_db_size, hash, m_hash_len);

    for (Uint16 i = 0; i < p_db_size; i++) {
        p_db[i] ^= p_db_mask[i];
    }

    utils::CopyBytes(message, p_db, p_db_size);
    utils::CopyBytes(message + p_db_size, hash, m_hash_len);
    message[m_key_size - 1] = 0xbc;

    // emLen = 256  and emBits is 2047.Set the leftmost 8emLen - emBits bits of
    // the leftmost octet in maskedDB to zero as per rfc8017
    message[0] &= 0x7f;
    alc_error_t err = decryptPrivate(message, m_key_size, pSignedBuff);

    return err;
}

alc_error_t
Rsa::verifyPublicPss(const Uint8* pText,
                     Uint64       textSize,
                     const Uint8* pSignedBuff)
{
    if (!pText || !pSignedBuff) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_digest) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    alignas(64) Uint8 mod_text[2048 / 8];

    alc_error_t err = encryptPublic(pSignedBuff, m_key_size, mod_text);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    Uint8 success = IsZero(0xbc ^ mod_text[m_key_size - 1]);

    alignas(64) Uint8 hash[64]{};

    m_digest->init();
    m_digest->update(pText, textSize);
    m_digest->finalize(hash, m_hash_len);

    Uint64 db_len      = m_key_size - m_hash_len - 1;
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

    // Fix the crash issue in fuzz
    Uint16 saltLen = success ? db_len - i : 0;

    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    utils::CopyBytes(p_db_mask + 8, hash, m_hash_len);
    utils::CopyBlock(p_db_mask + 8 + m_hash_len, p_masked_db + i, saltLen);

    m_digest->init();
    m_digest->update(p_db_mask, 8 + m_hash_len + saltLen);
    m_digest->finalize(hash, m_hash_len);

    success &= IsEqual(h, hash, m_hash_len);
    Uint8 error_code = Select(success, eOk, eInternal);
    return (error_code == eOk) ? ALC_ERROR_NONE : ALC_ERROR_GENERIC;
}

alc_error_t
Rsa::verifyPublicPssWithoutHash(const Uint8* pHash,
                                Uint64       hashSize,
                                const Uint8* pSignedBuff)
{
    if (!pHash || !pSignedBuff) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_digest) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    alignas(64) Uint8 mod_text[2048 / 8];

    alc_error_t err = encryptPublic(pSignedBuff, m_key_size, mod_text);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    Uint8 success = IsZero(0xbc ^ mod_text[m_key_size - 1]);

    alignas(64) Uint8 hash[64]{};

    Uint64 db_len      = m_key_size - m_hash_len - 1;
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

    // Fix the crash issue in fuzz
    Uint16 saltLen = success ? db_len - i : 0;

    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
    utils::CopyBytes(p_db_mask + 8, pHash, m_hash_len);
    utils::CopyBlock(p_db_mask + 8 + m_hash_len, p_masked_db + i, saltLen);

    m_digest->init();
    m_digest->update(p_db_mask, 8 + m_hash_len + saltLen);
    m_digest->finalize(hash, m_hash_len);

    success &= IsEqual(h, hash, m_hash_len);
    Uint8 error_code = Select(success, eOk, eInternal);
    return (error_code == eOk) ? ALC_ERROR_NONE : ALC_ERROR_GENERIC;
}

alc_error_t
Rsa::signPrivatePkcsv15(bool         check,
                        const Uint8* pText,
                        Uint64       textSize,
                        Uint8*       pSignedBuff)
{
    if (!pText || !pSignedBuff) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_digest || m_digest_info_index >= SHA_UNKNOWN) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    alignas(64) Uint8 message[2048 / 8]{}, message_check[2048 / 8]{},
        hash[64]{};

    m_digest->init();
    m_digest->update(pText, textSize);
    m_digest->finalize(hash, m_hash_len);

    // Encoded message :- 0x00 || 0x01 || PS || 0x00 || (DigestInfo || hash)
    message[1]     = 0x01;
    Uint64 pad_len = m_key_size - 3 - m_digest_info_size - m_hash_len;
    utils::PadBytes(message + 2, 0xff, pad_len);
    utils::CopyBytes(message + 3 + pad_len,
                     DigestInfo[m_digest_info_index],
                     m_digest_info_size);
    utils::CopyBytes(
        message + 3 + pad_len + m_digest_info_size, hash, m_hash_len);

    alc_error_t err = decryptPrivate(message, m_key_size, pSignedBuff);

    // verify signature for mitigating the fault tolerance attack
    if (check) {
        err = encryptPublic(pSignedBuff, m_key_size, message_check);

        Uint64* num1 = reinterpret_cast<Uint64*>(message);
        Uint64* num2 = reinterpret_cast<Uint64*>(message_check);
        Uint64  res  = 0;
        for (Uint64 i = 0; i < m_key_size / 8; i++) {
            res += (*(num1 + i) ^ *(num2 + i));
        }
        if (res != 0) {
            err = ALC_ERROR_GENERIC;
            utils::PadBytes(pSignedBuff, 0, m_key_size);
        }
    }
    return err;
}

alc_error_t
Rsa::signPrivatePkcsv15WithoutHash(const Uint8* pText,
                                   Uint64       textSize,
                                   Uint8*       decrypText)
{
    // textSize will already include hash size + DigestInfo size
    // pText will have the hash + DigestInfo

    if (!pText || !decrypText || textSize > m_key_size - 11) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    alignas(64) Uint8 message[2048 / 8]{};

    // Encoded message :- 0x00 || 0x01 || PS || 0x00 || (DigestInfo || hash)
    message[1]     = 0x01;
    Uint64 pad_len = m_key_size - 3 - textSize;
    utils::PadBytes(message + 2, 0xff, pad_len);
    utils::CopyBytes(message + 3 + pad_len, pText, textSize);

    alc_error_t err = decryptPrivate(message, m_key_size, decrypText);

    return err;
}

alc_error_t
Rsa::decryptPrivatePkcsv15(const Uint8* pEncryptedText,
                           Uint8*       pText,
                           Uint64*      textSize)
{
    if (!pText || !pEncryptedText) {
        return ALC_ERROR_NOT_PERMITTED;
    }
    alignas(64) Uint8 message[2048 / 8]{};

    decryptPrivate(pEncryptedText, m_key_size, message);
    // Encoded message :- 0x00 || 0x02 || PS || 0x00 || M

    Uint8 error_flag = 0;
    error_flag |= ((message[0] != 0) | (message[1] != 2));

    Uint64 i = 2;
    while (i < m_key_size && message[i]) {
        ++i;
    }

    Uint64 pad_len = i - 2;

    error_flag |= ((pad_len < 8) | (pad_len + 3 > m_key_size));
    error_flag |= (message[i] != 0);

    *textSize = ((m_key_size >= 3 + pad_len) ? m_key_size - 3 - pad_len : 0);

    utils::CopyBytes(pText, message + 3 + pad_len, *textSize);
    return Select(error_flag, ALC_ERROR_GENERIC, ALC_ERROR_NONE);
}

alc_error_t
Rsa::verifyPublicPkcsv15(const Uint8* pText,
                         Uint64       textSize,
                         const Uint8* pSignedBuff)
{
    alignas(64) Uint8 mod_text[2048 / 8], hash[64], message[2048 / 8]{};

    if (!pText || !pSignedBuff) {
        return ALC_ERROR_GENERIC;
    }

    if (!m_digest || m_digest_info_index >= SHA_UNKNOWN) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!m_mgf) {
        m_mgf          = m_digest;
        m_mgf_hash_len = m_hash_len;
    }

    alc_error_t err = encryptPublic(pSignedBuff, m_key_size, mod_text);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    m_digest->init();
    m_digest->update(pText, textSize);
    m_digest->finalize(hash, m_hash_len);

    // Encoded message :- 0x00 || 0x01 || PS || 0x00 || (DigestInfo || hash)
    message[1]     = 0x01;
    Uint64 pad_len = m_key_size - 3 - m_digest_info_size - m_hash_len;
    utils::PadBytes(message + 2, 0xff, pad_len);
    utils::CopyBytes(message + 3 + pad_len,
                     DigestInfo[m_digest_info_index],
                     m_digest_info_size);

    utils::CopyBytes(
        message + 3 + pad_len + m_digest_info_size, hash, m_hash_len);

    Uint64* num1 = reinterpret_cast<Uint64*>(message);
    Uint64* num2 = reinterpret_cast<Uint64*>(mod_text);
    Uint64  res  = 0;
    for (Uint64 i = 0; i < m_key_size / 8; i++) {
        res += (*(num1 + i) ^ *(num2 + i));
    }

    return !res ? err : ALC_ERROR_GENERIC;
}

alc_error_t
Rsa::verifyPublicPkcsv15WithoutHash(const Uint8* pText,
                                    Uint64       textSize,
                                    const Uint8* pEncryptText)
{
    alignas(64) Uint8 mod_text[2048 / 8], message[2048 / 8]{};

    if (!pText || !pEncryptText || textSize > m_key_size - 11) {
        return ALC_ERROR_GENERIC;
    }

    alc_error_t err = encryptPublic(pEncryptText, m_key_size, mod_text);
    if (err != ALC_ERROR_NONE) {
        return err;
    }

    // Encoded message :- 0x00 || 0x01 || PS || 0x00 || (DigestInfo || hash)
    message[1]    = 0x01;
    Int64 pad_len = m_key_size - 3 - textSize;
    utils::PadBytes(message + 2, 0xff, pad_len);
    utils::CopyBytes(message + 3 + pad_len, pText, textSize);

    Uint64* num1 = reinterpret_cast<Uint64*>(message);
    Uint64* num2 = reinterpret_cast<Uint64*>(mod_text);
    Uint64  res  = 0;
    for (Uint64 i = 0; i < m_key_size / 8; i++) {
        res += (*(num1 + i) ^ *(num2 + i));
    }

    return !res ? err : ALC_ERROR_GENERIC;
}

alc_error_t
Rsa::encryptPublicPkcsv15(const Uint8* pText,
                          Uint64       textSize,
                          Uint8*       pEncryptText,
                          const Uint8* randomPad)
{
    alignas(64) Uint8 message[2048 / 8]{};

    if (!pText || !pEncryptText || textSize > m_key_size - 11) {
        return ALC_ERROR_GENERIC;
    }

    // Encoded message :- 0x00 || 0x02 || PS || 0x00 || M
    message[1]    = 0x02;
    Int64 pad_len = m_key_size - 3 - textSize;
    utils::CopyBytes(message + 2, randomPad, pad_len);
    utils::CopyBytes(message + 3 + pad_len, pText, textSize);

    return encryptPublic(message, m_key_size, pEncryptText);
}

alc_error_t
Rsa::getPublickey(RsaPublicKey& pPublicKey)
{
    if (pPublicKey.size != m_key_size) {
        return ALC_ERROR_NOT_PERMITTED;
    }
    Uint8* mod_text = reinterpret_cast<Uint8*>(m_pub_key.m_mod);

    if (pPublicKey.modulus == nullptr || mod_text == nullptr) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    pPublicKey.public_exponent = *m_pub_key.m_public_exponent;

    for (Int64 i = m_key_size - 1, j = 0; i >= 0; --i, ++j) {
        pPublicKey.modulus[j] = mod_text[i];
    }

    return ALC_ERROR_NONE;
}

alc_error_t
Rsa::setPublicKey(const Uint64 exponent, const Uint8* mod, const Uint64 size)
{
    if (!mod || exponent == 0) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!(size == 128 || size == 256)) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    m_pub_key.m_public_exponent[0] = exponent;

    ConvertToBigNum(mod, m_pub_key.m_mod, size);
    m_pub_key.m_size           = size / 8;
    m_key_size                 = size;
    static bool zen4_available = CpuId::cpuIsZen4() || CpuId::cpuIsZen5();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();
    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        if (m_key_size == 2048 / 8) {
            zen4::archCreateContext<KEY_SIZE_2048>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        } else {
            zen4::archCreateContext<KEY_SIZE_1024>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        }
    } else if (zen3_available) {
        if (m_key_size == 2048 / 8) {
            zen3::archCreateContext<KEY_SIZE_2048>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        } else {
            zen3::archCreateContext<KEY_SIZE_1024>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        }
    } else if (zen_available || zen_available_flags) {
        if (m_key_size == 2048 / 8) {
            zen::archCreateContext<KEY_SIZE_2048>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        } else {
            zen::archCreateContext<KEY_SIZE_1024>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        }
    } else {
        return ALC_ERROR_NOT_PERMITTED;
    }
    return ALC_ERROR_NONE;
}

alc_error_t
Rsa::setPublicKeyAsBigNum(const BigNum* exponent, const BigNum* pModulus)
{
    if (!pModulus || !exponent || !exponent->num || !pModulus->num) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!(pModulus->size == 128 / 8 || pModulus->size == 256 / 8)) {
        return ALC_ERROR_NOT_PERMITTED;
    }
    // ToDo: check if the key can be stored as shared pointer
    // m_pub_key.m_public_exponent = exponent->num;
    utils::CopyQWord(
        m_pub_key.m_public_exponent, exponent->num, exponent->size * 8);

    // m_pub_key.m_mod             = pModulus->num;
    utils::CopyQWord(m_pub_key.m_mod, pModulus->num, pModulus->size * 8);

    m_pub_key.m_size           = pModulus->size;
    m_key_size                 = pModulus->size * 8;
    static bool zen4_available = CpuId::cpuIsZen4() || CpuId::cpuIsZen5();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();
    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        if (m_key_size == 2048 / 8) {
            zen4::archCreateContext<KEY_SIZE_2048>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        } else {
            zen4::archCreateContext<KEY_SIZE_1024>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        }

    } else if (zen3_available) {
        if (m_key_size == 2048 / 8) {
            zen3::archCreateContext<KEY_SIZE_2048>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        } else {
            zen3::archCreateContext<KEY_SIZE_1024>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        }

    } else if (zen_available || zen_available_flags) {
        if (m_key_size == 2048 / 8) {
            zen::archCreateContext<KEY_SIZE_2048>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        } else {
            zen::archCreateContext<KEY_SIZE_1024>(
                m_context_pub, m_pub_key.m_mod, m_pub_key.m_size);
        }
    } else {
        return ALC_ERROR_NOT_PERMITTED;
    }
    return ALC_ERROR_NONE;
}
alc_error_t
Rsa::setPrivateKey(const Uint8* dp,
                   const Uint8* dq,
                   const Uint8* p,
                   const Uint8* q,
                   const Uint8* qinv,
                   const Uint8* mod,
                   const Uint64 size)
{
    if (!dp || !dq || !p || !q || !mod) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    if (!(size == 128 || size == 64)) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    m_key_size = size * 2; // keysize is twice the sizeof(p)

    ConvertToBigNum(dp, m_priv_key.m_dp, size);
    ConvertToBigNum(dq, m_priv_key.m_dq, size);
    ConvertToBigNum(p, m_priv_key.m_p, size);
    ConvertToBigNum(q, m_priv_key.m_q, size);
    ConvertToBigNum(qinv, m_priv_key.m_qinv, size);
    ConvertToBigNum(mod, m_priv_key.m_mod, size * 2);
    m_priv_key.m_size = size / 8;

    static bool zen4_available = CpuId::cpuIsZen4() || CpuId::cpuIsZen5();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();
    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        if (m_key_size == 2048 / 8) {
            zen4::archCreateContext<KEY_SIZE_2048>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen4::archCreateContext<KEY_SIZE_2048>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        } else {
            zen4::archCreateContext<KEY_SIZE_1024>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen4::archCreateContext<KEY_SIZE_1024>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        }
    } else if (zen3_available) {
        if (m_key_size == 2048 / 8) {
            zen3::archCreateContext<KEY_SIZE_2048>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen3::archCreateContext<KEY_SIZE_2048>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        } else {
            zen3::archCreateContext<KEY_SIZE_1024>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen3::archCreateContext<KEY_SIZE_1024>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        }
    } else if (zen_available || zen_available_flags) {
        if (m_key_size == 2048 / 8) {
            zen::archCreateContext<KEY_SIZE_2048>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen::archCreateContext<KEY_SIZE_2048>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        } else {
            zen::archCreateContext<KEY_SIZE_1024>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen::archCreateContext<KEY_SIZE_1024>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        }
    } else {
        return ALC_ERROR_NOT_PERMITTED;
    }
    return ALC_ERROR_NONE;
}

alc_error_t
Rsa::setPrivateKeyAsBigNum(const BigNum* dp,
                           const BigNum* dq,
                           const BigNum* p,
                           const BigNum* q,
                           const BigNum* qinv,
                           const BigNum* mod)
{
    if (!dp || !dq || !p || !q || !mod) {
        return ALC_ERROR_NOT_PERMITTED;
    }

    m_key_size = dp->size * 2 * 8; // keysize is twice the sizeof(p)

    // Todo : check if the keys can be put in shared pointer

    // m_priv_key.m_dp   = dp->num;
    utils::CopyQWord(m_priv_key.m_dp, dp->num, dp->size * 8);
    // m_priv_key.m_dq   = dq->num;
    utils::CopyQWord(m_priv_key.m_dq, dq->num, dq->size * 8);
    // m_priv_key.m_p    = p->num;
    utils::CopyQWord(m_priv_key.m_p, p->num, p->size * 8);
    // m_priv_key.m_q    = q->num;
    utils::CopyQWord(m_priv_key.m_q, q->num, q->size * 8);
    // m_priv_key.m_qinv = qinv->num;
    utils::CopyQWord(m_priv_key.m_qinv, qinv->num, qinv->size * 8);
    // m_priv_key.m_mod = mod->num;
    utils::CopyQWord(m_priv_key.m_mod, mod->num, mod->size * 8);
    m_priv_key.m_size = dp->size;

    static bool zen4_available = CpuId::cpuIsZen4() || CpuId::cpuIsZen5();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1() || CpuId::cpuIsZen2();
    static bool zen_available_flags =
        CpuId::cpuHasAdx() && CpuId::cpuHasAvx2() && CpuId::cpuHasBmi2();

    if (zen4_available) {
        if (m_key_size == 2048 / 8) {
            zen4::archCreateContext<KEY_SIZE_2048>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen4::archCreateContext<KEY_SIZE_2048>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        } else {
            zen4::archCreateContext<KEY_SIZE_1024>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen4::archCreateContext<KEY_SIZE_1024>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        }
    } else if (zen3_available) {
        if (m_key_size == 2048 / 8) {
            zen3::archCreateContext<KEY_SIZE_2048>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen3::archCreateContext<KEY_SIZE_2048>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        } else {
            zen3::archCreateContext<KEY_SIZE_1024>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen3::archCreateContext<KEY_SIZE_1024>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        }
    } else if (zen_available || zen_available_flags) {
        if (m_key_size == 2048 / 8) {
            zen::archCreateContext<KEY_SIZE_2048>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen::archCreateContext<KEY_SIZE_2048>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        } else {
            zen::archCreateContext<KEY_SIZE_1024>(
                m_context_p, m_priv_key.m_p, m_priv_key.m_size);
            zen::archCreateContext<KEY_SIZE_1024>(
                m_context_q, m_priv_key.m_q, m_priv_key.m_size);
        }
    } else {
        return ALC_ERROR_NOT_PERMITTED;
    }
    return ALC_ERROR_NONE;
}

void
Rsa::reset()
{
    Reset(m_priv_key.m_dp, 2048 / (2 * 64));
    Reset(m_priv_key.m_dq, 2048 / (2 * 64));
    Reset(m_priv_key.m_mod, 2048 / (64));
    Reset(m_priv_key.m_p, 2048 / (2 * 64));
    Reset(m_priv_key.m_q, 2048 / (2 * 64));
    Reset(m_priv_key.m_qinv, 2048 / (2 * 64));
    Reset(m_pub_key.m_mod, 2048 / (64));
    // Todo : change this code in a proper way

    Reset(m_context_pub.m_mod_radix_52_bit, 2048 / 52 + 1);
    Reset(m_context_p.m_mod_radix_52_bit, 2048 / (2 * 52) + 1);
    Reset(m_context_q.m_mod_radix_52_bit, 2048 / (2 * 52) + 1);
}

Uint64
Rsa::getKeySize()
{
    return m_key_size;
}
} // namespace alcp::rsa