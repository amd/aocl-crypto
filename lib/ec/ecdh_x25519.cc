/*
 * Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
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
#include "alcp/ec/ecdh.hh"
#include "alcp/ec/ecdh_avx2.hh"
#include "alcp/ec/ecdh_zen.hh"
#include "alcp/ec/ecdh_zen3.hh"
#include "alcp/utils/compare.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#include "alcp/utils/memory.hh"
#include "config.h"
#include <string.h>

namespace alcp::ec {

using alcp::utils::AlgorithmType;
using alcp::utils::CpuArchLevel;
using alcp::utils::CpuId;
static constexpr Uint32 KeySize = 32;
// The public key is the u-coordinate alone, the same width as the private key
static constexpr Uint32 PublicKeySize = KeySize;

namespace {

    void ClampPrivateKey(Uint8 (&privKey)[KeySize])
    {
        privKey[0] &= 248;
        privKey[KeySize - 1] &= 127;
        privKey[KeySize - 1] |= 64;
    }

} // namespace

X25519::X25519() = default;

X25519::~X25519()
{
    reset();
}

Status
X25519::setPrivateKey(const Uint8* pPrivKey, Uint64 privKeyLen)
{
    if (privKeyLen != sizeof(m_PrivKey)) {
        return status::InvalidArgument(
            "Private key length does not match the curve key size");
    }

    // store private key for secret key generation
    alcp::utils::CopyBytes(m_PrivKey, pPrivKey, sizeof(m_PrivKey));
    ClampPrivateKey(m_PrivKey);
    m_isPrivateKeySet = true;
    return StatusOk();
}

Status
X25519::generatePublicKey(Uint8*       pPublicKey,
                          Uint64       pubKeyLen,
                          const Uint8* pPrivKey,
                          Uint64       privKeyLen)
{
    if (privKeyLen != sizeof(m_PrivKey)) {
        return status::InvalidArgument(
            "Private key length does not match the curve key size");
    }

    if (pubKeyLen < KeySize) {
        return status::InvalidArgument(
            "Public key buffer is smaller than the curve key size");
    }

    // Check if required instruction sets are available (needs Zen baseline: ADX, AVX2, BMI2)
    static CpuArchLevel archLevel =
        CpuId::getCachedArchLevel(AlgorithmType::eX25519);
    if (archLevel < CpuArchLevel::eZen) {
        return status::NotAvailable(
            "Not supported due to missing instruction set (ADX or BMI2)");
    }

    // store private key for secret key generation
    alcp::utils::CopyBytes(m_PrivKey, pPrivKey, sizeof(m_PrivKey));
    ClampPrivateKey(m_PrivKey);
    m_isPrivateKeySet = true;

    Int8 priv_key_radix32[52];

    Uint16 j = 0;
    // clang-format off
    UNROLL_30
    for (Uint16 i = 0; i < 30; i += 5) {
        priv_key_radix32[j] = m_PrivKey[i] & 0x1f; // lower 5 bits
        priv_key_radix32[j + 1] = ((m_PrivKey[i + 1] & 0x3) << 3) | (m_PrivKey[i] >> 5);
        priv_key_radix32[j + 2] = (m_PrivKey[i + 1] >> 2) & 0x1f;
        priv_key_radix32[j + 3] = ((m_PrivKey[i + 2] & 0xf) << 1) | (m_PrivKey[i + 1] >> 7);
        priv_key_radix32[j + 4] = (m_PrivKey[i + 2] >> 4) | ((m_PrivKey[i + 3] & 0x1) << 4);
        priv_key_radix32[j + 5] = (m_PrivKey[i + 3] >> 1) & 0x1f;
        priv_key_radix32[j + 6] = (m_PrivKey[i + 3] >> 6) | ((m_PrivKey[i + 4] & 0x7) << 2);
        priv_key_radix32[j + 7] = m_PrivKey[i + 4] >> 3;
        j += 8;
    }
    priv_key_radix32[j] = m_PrivKey[30] & 0x1f;
    priv_key_radix32[j+1] = (m_PrivKey[30] >> 5) | ((m_PrivKey[31] & 0x3) << 3);
    priv_key_radix32[j+2] = m_PrivKey[31] >> 2;
    // clang-format on

    // all numbers between -16 to +16
    Int8 carry = 0;
    UNROLL_51
    for (Uint8 i = 0; i < 51; ++i) {
        priv_key_radix32[i] += carry;
        carry = priv_key_radix32[i] + 16;
        carry >>= 5;
        priv_key_radix32[i] -= carry << 5;
    }

    priv_key_radix32[51] = carry;

    switch (archLevel) {
        case CpuArchLevel::eZen3:
        case CpuArchLevel::eZen4:
            zen3::AlcpScalarPubX25519(priv_key_radix32, pPublicKey);
            break;
        case CpuArchLevel::eZen:
            avx2::AlcpScalarPubX25519(priv_key_radix32, pPublicKey);
            break;
        default:
            zen::AlcpScalarPubX25519(priv_key_radix32, pPublicKey);
            break;
    }

    return StatusOk();
}

Status
X25519::computeSecretKey(Uint8*       pSecretKey,
                         Uint64       secretKeyLen,
                         const Uint8* pPublicKey,
                         Uint64       pubKeyLen,
                         Uint64*      pKeyLength)
{
    if (pKeyLength == nullptr) {
        return status::InvalidArgument(
            "Shared secret length pointer must not be null");
    }

    *pKeyLength = 0;

    Status status = checkPrivateKeyIsSet();
    if (!status.ok()) {
        return status;
    }

    if (secretKeyLen < KeySize) {
        return status::InvalidArgument(
            "Secret key buffer is smaller than the shared secret size");
    }

    // Check if required instruction sets are available (needs Zen baseline: ADX, AVX2, BMI2)
    static CpuArchLevel archLevel =
        CpuId::getCachedArchLevel(AlgorithmType::eX25519);
    if (archLevel < CpuArchLevel::eZen) {
        return status::NotAvailable(
            "Not supported due to missing instruction set (ADX or BMI2)");
    }

    status = validatePublicKey(pPublicKey, pubKeyLen);
    if (!status.ok()) {
        return status;
    }

    Uint8 peer_u[PublicKeySize];
    alcp::utils::CopyBytes(peer_u, pPublicKey, PublicKeySize);
    peer_u[PublicKeySize - 1] &= 127;

    switch (archLevel) {
        case CpuArchLevel::eZen3:
        case CpuArchLevel::eZen4:
            zen3::alcpScalarMulX25519(pSecretKey, m_PrivKey, peer_u);
            break;
        case CpuArchLevel::eZen:
            avx2::alcpScalarMulX25519(pSecretKey, m_PrivKey, peer_u);
            break;
        default:
            zen::alcpScalarMulX25519(pSecretKey, m_PrivKey, peer_u);
            break;
    }

    static constexpr Uint8 cAllZero[KeySize] = {};
    if (alcp::utils::CompareConstTime(cAllZero, pSecretKey, KeySize)) {
        return status::InvalidArgument(
            "Peer public key produced an all-zero shared secret");
    }

    *pKeyLength = KeySize;
    return status;
}

Status
X25519::validatePublicKey(const Uint8* pPublicKey, Uint64 pKeyLength)
{
    if (pKeyLength != KeySize) {
        return Status(GenericError(ErrorCode::eInvalidArgument),
                      "Key validation failed");
    }

    static const Uint8 all_zero[KeySize] = { 0 };

    return !utils::CompareConstTime(all_zero, pPublicKey, KeySize)
               ? StatusOk()
               : Status(GenericError(ErrorCode::eInvalidArgument),
                        "Key validation failed");
}

void
X25519::reset()
{
    alcp::utils::SecureClear(m_PrivKey, sizeof(m_PrivKey));
    m_isPrivateKeySet = false;
}

Uint64
X25519::getKeySize()
{
    return KeySize;
}

Uint64
X25519::getPublicKeySize()
{
    return PublicKeySize;
}

} // namespace alcp::ec
