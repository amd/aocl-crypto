/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

static const Uint8 Modulus[] = {
    0xef, 0x4f, 0xa2, 0xcd, 0x00, 0xea, 0x99, 0xeb, 0x12, 0xa8, 0x3a, 0x1b,
    0xc5, 0x5d, 0x49, 0x04, 0x18, 0xcd, 0x96, 0x69, 0xc9, 0x28, 0x2c, 0x36,
    0x40, 0x9a, 0x15, 0x40, 0x05, 0x6b, 0x35, 0x6f, 0x89, 0x76, 0xf3, 0xb9,
    0xe3, 0xac, 0x4d, 0x2a, 0xe4, 0xba, 0xd9, 0x6e, 0xb8, 0xa4, 0x05, 0x0b,
    0xc5, 0x8e, 0xdf, 0x15, 0x33, 0xfc, 0x81, 0x2b, 0xb5, 0xf4, 0x3a, 0x0b,
    0x67, 0x2d, 0x7d, 0x7c, 0x41, 0x8c, 0xc0, 0x46, 0x93, 0x7d, 0xe9, 0x95,
    0x90, 0x1e, 0xdd, 0xc0, 0xf4, 0xfc, 0x23, 0x90, 0xbb, 0x14, 0x73, 0x5e,
    0xcc, 0x86, 0x45, 0x6a, 0x9c, 0x15, 0x46, 0x92, 0xf3, 0xac, 0x24, 0x8f,
    0x0c, 0x28, 0x25, 0x17, 0xb1, 0xb8, 0x3f, 0xa5, 0x9c, 0x61, 0xbd, 0x2c,
    0x10, 0x7a, 0x5c, 0x47, 0xe0, 0xa2, 0xf1, 0xf3, 0x24, 0xca, 0x37, 0xc2,
    0x06, 0x78, 0xa4, 0xad, 0x0e, 0xbd, 0x72, 0xeb
};

static const Uint8 PrivateKeyExponent[] = {
    0xc3, 0x33, 0x51, 0x17, 0x29, 0x05, 0x33, 0x91, 0x74, 0x81, 0x76, 0x0c,
    0x8a, 0xfb, 0x61, 0x80, 0x8e, 0xfe, 0xbb, 0x0f, 0x04, 0xbe, 0xd8, 0xf9,
    0x53, 0xce, 0x9b, 0x40, 0xc2, 0x6a, 0xc5, 0x86, 0x7a, 0x39, 0x65, 0xea,
    0x9d, 0xd4, 0x40, 0x89, 0x99, 0x52, 0xf3, 0xe2, 0x85, 0x87, 0x7c, 0x7a,
    0x32, 0xa6, 0x2c, 0x3f, 0x2e, 0x4d, 0x6b, 0xcb, 0x8c, 0xba, 0x6e, 0xd2,
    0x38, 0x51, 0xf9, 0xc4, 0xda, 0x1d, 0xdf, 0xa9, 0xa8, 0x41, 0x78, 0xb8,
    0x84, 0x52, 0x46, 0x67, 0x0e, 0x19, 0x4b, 0x2f, 0x71, 0x69, 0x23, 0x7d,
    0x92, 0x46, 0xe2, 0x4c, 0xf8, 0x50, 0xce, 0xe7, 0xd3, 0xb0, 0x8a, 0x35,
    0xe9, 0x82, 0x60, 0xc1, 0xee, 0x0d, 0xe6, 0x52, 0x11, 0x04, 0x10, 0xf1,
    0xf0, 0x0d, 0xe1, 0x5b, 0x76, 0xcf, 0x58, 0x18, 0xcb, 0x8a, 0x06, 0x7d,
    0xec, 0x36, 0x51, 0x13, 0x95, 0x39, 0xd2, 0x91
};

static const Uint8 P[] = { 0xfa, 0x5e, 0xa7, 0x98, 0x7d, 0x19, 0x66, 0xdf,
                           0x91, 0xd7, 0xe7, 0xf6, 0xbe, 0xb7, 0xdf, 0x51,
                           0x99, 0x61, 0xb8, 0x08, 0xff, 0xcd, 0xe1, 0xf4,
                           0x42, 0x0a, 0xc4, 0x01, 0xf8, 0xcb, 0x85, 0xd1,
                           0x64, 0xe0, 0x86, 0x66, 0xe3, 0x0b, 0xcc, 0x3b,
                           0x2f, 0xca, 0xc0, 0x47, 0x62, 0x8d, 0x4d, 0x0e,
                           0xf5, 0x81, 0x63, 0xa0, 0x70, 0x78, 0xb3, 0x69,
                           0xfa, 0xdd, 0x55, 0xd8, 0x53, 0xf2, 0xb1, 0xd3 };

static const Uint8 Q[] = { 0xf4, 0xb1, 0x51, 0x68, 0x20, 0x7b, 0x71, 0xd9,
                           0x69, 0x67, 0xe1, 0x5b, 0xdf, 0x98, 0x76, 0xae,
                           0x02, 0xc8, 0x76, 0xd9, 0xbd, 0x5a, 0xf5, 0x8d,
                           0x95, 0xa1, 0x5e, 0x66, 0xff, 0x67, 0xed, 0x0f,
                           0xa1, 0x8f, 0x78, 0xa0, 0x85, 0x6c, 0x6a, 0xae,
                           0x51, 0xcc, 0xd1, 0xed, 0x62, 0xb7, 0x9f, 0x7c,
                           0x75, 0xd3, 0xf7, 0x7a, 0x1a, 0xb7, 0x28, 0x06,
                           0x1a, 0x9d, 0x2a, 0x26, 0x05, 0x0b, 0xf3, 0x89 };

static const Uint8 DP[] = { 0x57, 0x7a, 0x0e, 0xf0, 0x96, 0x74, 0xf3, 0x9e,
                            0x95, 0xa4, 0x6c, 0x25, 0xa8, 0x09, 0x32, 0x7b,
                            0x9e, 0x2d, 0xa8, 0x51, 0x6c, 0x9f, 0x10, 0x9d,
                            0x79, 0x1d, 0xad, 0xd2, 0x4a, 0x8d, 0x41, 0x9a,
                            0x21, 0xb6, 0xd8, 0xfe, 0xc5, 0xc1, 0x6f, 0x80,
                            0x16, 0x78, 0xae, 0xa9, 0xc2, 0x63, 0x40, 0x53,
                            0x43, 0xb0, 0x0b, 0x91, 0x18, 0xfa, 0xf3, 0x24,
                            0xca, 0x43, 0xdf, 0x24, 0x90, 0x60, 0x31, 0x85 };

static const Uint8 DQ[] = { 0x1d, 0x7e, 0xf2, 0x6d, 0x36, 0xdd, 0x2a, 0x90,
                            0x26, 0xa0, 0x9b, 0x0d, 0xd4, 0x1a, 0x30, 0xd4,
                            0x31, 0x09, 0xb1, 0x29, 0xf6, 0x25, 0x6c, 0xcc,
                            0x30, 0x69, 0x4f, 0x53, 0xe3, 0x1d, 0xc7, 0xf9,
                            0xc6, 0x63, 0xe1, 0x0a, 0x98, 0x8a, 0xc5, 0x21,
                            0x56, 0x42, 0xf6, 0x5b, 0x43, 0x37, 0x17, 0x46,
                            0x8d, 0x7d, 0x8b, 0xab, 0x70, 0x64, 0xfb, 0xb2,
                            0x20, 0xab, 0x29, 0x55, 0x83, 0xee, 0x38, 0xe1 };

static const Uint8 QINV[] = { 0xad, 0xad, 0xc8, 0xfd, 0xd8, 0xc9, 0x60, 0x63,
                              0xfd, 0xe8, 0xcd, 0xff, 0xa1, 0x0a, 0x23, 0x2d,
                              0x0d, 0x1e, 0x3f, 0x53, 0xe4, 0x4d, 0xea, 0x8c,
                              0x8f, 0x1f, 0xd9, 0x41, 0xef, 0x87, 0x21, 0x9b,
                              0x89, 0xc7, 0x27, 0x1c, 0xb3, 0x7d, 0xa9, 0xe4,
                              0x66, 0x6d, 0x8e, 0x59, 0x1c, 0x01, 0xc4, 0x14,
                              0x7d, 0x69, 0x77, 0xb2, 0xbe, 0xb6, 0xd2, 0x8c,
                              0x43, 0xcc, 0xfd, 0x41, 0x43, 0x02, 0x45, 0xde };

static const Uint64 PublicKeyExponent = 0x10001;

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

Rsa::Rsa()
{
    // todo : this will be removed and will be called from outside
    // after testing is done
    Rsa::setPrivateKey(DP, DQ, P, Q, QINV, Modulus, sizeof(P));
    Rsa::setPublicKey(PublicKeyExponent, Modulus, sizeof(Modulus));
}

void
Rsa::setDigestOaep(digest::IDigest* digest)
{
    if (digest) {
        m_digest   = digest;
        m_hash_len = digest->getHashSize();
    }
}

void
Rsa::setMgfOaep(digest::IDigest* mgf)
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

Rsa::~Rsa()
{
    reset();
}

Status
Rsa::encryptPublic(const Uint8* pText, Uint64 textSize, Uint8* pEncText)
{
    // For non padded output
    if (textSize != m_key_size) {
        return status::NotPermitted("Text size should be equal to modulus");
    }

    if (pText == nullptr || pEncText == nullptr) {
        return status::NotPermitted("Buffer should be non null");
    }

    std::unique_ptr<Uint64[]> bignum_text;
    auto                      ptext_bignum = CreateBigNum(pText, m_key_size);
    auto                      mod_bignum   = m_pub_key.m_mod.get();

    if (!IsLess(ptext_bignum, mod_bignum, m_pub_key.m_size)) {
        return status::NotPermitted(
            "text absolute value should be less than modulus");
    }

    bignum_text.reset(ptext_bignum);

    static bool zen4_available = CpuId::cpuIsZen4();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1();

    if (zen4_available) {
        zen4::archEncryptPublic(
            pEncText, ptext_bignum, m_pub_key, m_context_pub);
        return StatusOk();
    } else if (zen3_available) {
        zen3::archEncryptPublic(
            pEncText, ptext_bignum, m_pub_key, m_context_pub);
        return StatusOk();
    } else if (zen_available) {
        zen::archEncryptPublic(
            pEncText, ptext_bignum, m_pub_key, m_context_pub);
        return StatusOk();
    }

    archEncryptPublic(pEncText, ptext_bignum, m_pub_key, m_context_pub);

    return StatusOk();
}

Status
Rsa::decryptPrivate(const Uint8* pEncText, Uint64 encSize, Uint8* pText)
{
    // For non padded output
    if (encSize != m_priv_key.m_size * 2 * 8) {
        return status::NotPermitted("Text size should be equal modulous");
    }

    if (pEncText == nullptr || pText == nullptr) {
        return status::NotPermitted("Buffer should be non null");
    }

    std::unique_ptr<Uint64[]> bignum_text;
    auto ptext_bignum = CreateBigNum(pEncText, m_priv_key.m_size * 2 * 8);
    auto mod_bignum   = m_priv_key.m_mod.get();

    if (!IsLess(ptext_bignum, mod_bignum, m_priv_key.m_size * 2)) {
        return status::NotPermitted(
            "text absolute value should be less than modulus");
    }

    static bool zen4_available = CpuId::cpuIsZen4();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1();

    if (zen4_available) {
        zen4::archDecryptPrivate(
            pText, ptext_bignum, m_priv_key, m_context_p, m_context_q);
        return StatusOk();
    } else if (zen3_available) {
        zen3::archDecryptPrivate(
            pText, ptext_bignum, m_priv_key, m_context_p, m_context_q);
        return StatusOk();
    } else if (zen_available) {
        zen::archDecryptPrivate(
            pText, ptext_bignum, m_priv_key, m_context_p, m_context_q);
        return StatusOk();
    }

    archDecryptPrivate(
        pText, ptext_bignum, m_priv_key, m_context_p, m_context_q);

    return StatusOk();
}

Status
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

    Uint8 *p_db, *p_seed;

    if (textSize > m_key_size - 2 * m_hash_len - 2) {
        return status::NotPermitted("input text size is larger than supported");
    }

    // to do check if this needs to be removed in case of sha512 where digest
    // size is 512 bits
    if (m_key_size < 2 * m_hash_len + 2) {
        return status::NotPermitted(
            "input text size is smaller than supported");
    }

    if (!m_mgf || !m_digest) {
        return status::NotPermitted(
            "digest and mask generation function should be non null");
    }

    auto   mod_text   = std::make_unique<Uint8[]>(m_key_size);
    Uint8* p_mod_text = mod_text.get();
    p_mod_text[0]     = 0;
    p_seed            = p_mod_text + 1;
    p_db              = p_seed + m_hash_len; // seed size equals hashsize

    // create db
    m_digest->finalize(pLabel, labelSize);

    m_digest->copyHash(p_db, m_hash_len);

    Uint64 p_db_size               = m_key_size - 1 - m_hash_len;
    p_db[p_db_size - 1 - textSize] = 1;
    memcpy(&p_db[p_db_size - textSize], pText, textSize);

    utils::CopyBytes(p_seed, pSeed, m_hash_len);

    auto p_db_mask = std::make_unique<Uint8[]>(p_db_size);

    maskGenFunct(p_db_mask.get(), p_db_size, p_seed, m_hash_len);

    for (Uint16 i = 0; i < p_db_size; i++) {
        p_db[i] ^= p_db_mask[i];
    }

    auto p_seed_mask = std::make_unique<Uint8[]>(m_hash_len);

    maskGenFunct(p_seed_mask.get(), m_hash_len, p_db, p_db_size);

    for (Uint16 i = 0; i < m_hash_len; i++) {
        p_seed[i] ^= p_seed_mask[i];
    }

    return encryptPublic(p_mod_text, m_key_size, pEncText);
}

Status
Rsa::decryptPrivateOaep(const Uint8* pEncText,
                        Uint64       encSize,
                        const Uint8* pLabel,
                        Uint64       labelSize,
                        Uint8*       pText,
                        Uint64&      textSize)
{

    auto p_mod_text = std::make_unique<Uint8[]>(encSize);

    Status status = decryptPrivate(pEncText, encSize, p_mod_text.get());

    if (!status.ok()) {
        return status;
    }

    // decode oaep padding
    Uint8  seed[Sha512Size];       // max seed size is hashlen of sha512
    Uint8  hash_label[Sha512Size]; // max hashlen is of sha512
    Uint64 db_len = encSize - 1 - m_hash_len;

    auto p_db = std::make_unique<Uint8[]>(db_len * 2);

    if (encSize < 2 * m_hash_len + 2) {
        return status::NotPermitted(
            "decrypted size less than the expected size");
    }

    Uint8 success = IsZero(p_mod_text[0]);

    Uint8* p_masked_seed = p_mod_text.get() + 1;
    Uint8* p_masked_db   = p_masked_seed + m_hash_len;

    maskGenFunct(seed, m_hash_len, p_masked_db, db_len);

    for (Uint16 i = 0; i < m_hash_len; i++) {
        seed[i] ^= p_masked_seed[i];
    }

    maskGenFunct(p_db.get(), db_len, seed, m_hash_len);

    for (Uint32 i = 0; i < db_len; i++) {
        p_db[i] ^= p_masked_db[i];
    }

    // create db
    m_digest->reset();
    m_digest->finalize(pLabel, labelSize);
    m_digest->copyHash(hash_label, m_hash_len);

    success &= IsEqual(hash_label, p_db.get(), m_hash_len);

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
    memset(p_mod_text.get(), 0, encSize);
    memset(p_db.get(), 0, db_len * 2);
    Uint8 error_code = Select(success, eOk, eInternal);
    return (error_code == eOk) ? StatusOk() : status::Generic("Generic error");
}

Status
Rsa::getPublickey(RsaPublicKey& pPublicKey)
{

    if (pPublicKey.size != m_key_size) {
        return status::NotPermitted("keyize should match");
    }

    if (pPublicKey.modulus == nullptr) {
        return status::NotPermitted("Modulus cannot be empty");
    }

    pPublicKey.public_exponent = PublicKeyExponent;

    Uint8* mod_text = reinterpret_cast<Uint8*>(m_pub_key.m_mod.get());
    for (Int64 i = m_key_size - 1, j = 0; i >= 0; --i, ++j) {
        pPublicKey.modulus[j] = mod_text[i];
    }

    return StatusOk();
}

Status
Rsa::setPublicKey(const Uint64 exponent, const Uint8* mod, const Uint64 size)
{
    if (!mod || exponent == 0) {
        return status::NotPermitted("Invalid public key");
    }

    if (!(size == 128 || size == 256)) {
        return status::NotPermitted("Key sizes not supported currently");
    }

    m_pub_key.m_public_exponent = exponent;
    m_pub_key.m_mod.reset(CreateBigNum(mod, size));
    m_pub_key.m_size           = size / 8;
    m_key_size                 = size;
    static bool zen4_available = CpuId::cpuIsZen4();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1();

    if (zen4_available) {
        zen4::archCreateContext(
            m_context_pub, m_pub_key.m_mod.get(), m_pub_key.m_size);

    } else if (zen3_available) {
        zen3::archCreateContext(
            m_context_pub, m_pub_key.m_mod.get(), m_pub_key.m_size);

    } else if (zen_available) {
        zen::archCreateContext(
            m_context_pub, m_pub_key.m_mod.get(), m_pub_key.m_size);

    } else {

        archCreateContext(
            m_context_pub, m_pub_key.m_mod.get(), m_pub_key.m_size);
    }
    return StatusOk();
}

Status
Rsa::setPrivateKey(const Uint8* dp,
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

    m_priv_key.m_dp.reset(CreateBigNum(dp, size));
    m_priv_key.m_dq.reset(CreateBigNum(dq, size));
    m_priv_key.m_p.reset(CreateBigNum(p, size));
    m_priv_key.m_q.reset(CreateBigNum(q, size));
    m_priv_key.m_qinv.reset(CreateBigNum(qinv, size));
    m_priv_key.m_mod.reset(CreateBigNum(mod, size * 2));
    m_priv_key.m_size = size / 8;

    static bool zen4_available = CpuId::cpuIsZen4();
    static bool zen3_available = CpuId::cpuIsZen3();
    static bool zen_available  = CpuId::cpuIsZen1();

    if (zen4_available) {
        zen4::archCreateContext(
            m_context_p, m_priv_key.m_p.get(), m_priv_key.m_size);
        zen4::archCreateContext(
            m_context_q, m_priv_key.m_q.get(), m_priv_key.m_size);
    } else if (zen3_available) {
        zen3::archCreateContext(
            m_context_p, m_priv_key.m_p.get(), m_priv_key.m_size);
        zen3::archCreateContext(
            m_context_q, m_priv_key.m_q.get(), m_priv_key.m_size);
    } else if (zen_available) {
        zen::archCreateContext(
            m_context_p, m_priv_key.m_p.get(), m_priv_key.m_size);
        zen::archCreateContext(
            m_context_q, m_priv_key.m_q.get(), m_priv_key.m_size);
    } else {

        archCreateContext(m_context_p, m_priv_key.m_p.get(), m_priv_key.m_size);
        archCreateContext(m_context_q, m_priv_key.m_q.get(), m_priv_key.m_size);
    }
    return StatusOk();
}

void
Rsa::reset()
{
    // Todo rest the big num here
}

Uint64
Rsa::getKeySize()
{
    return m_key_size;
}

} // namespace alcp::rsa
