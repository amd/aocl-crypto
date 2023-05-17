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
#include "alcp/ec/ecdh.hh"
#include "alcp/ec/ecdh_avx2.hh"
#include "alcp/ec/ecdh_zen.hh"
#include "alcp/ec/ecdh_zen3.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#include "config.h"
#include <string.h>

namespace alcp::ec {

using alcp::utils::CpuId;
static constexpr Uint32 KeySize = 32;

X25519::X25519() = default;

X25519::~X25519()
{
    reset();
}

Status
X25519::setPrivateKey(const Uint8* pPrivKey)
{
    // store private key for secret key generation
    alcp::utils::CopyBytes(m_PrivKey, pPrivKey, KeySize);
    return StatusOk();
}

Status
X25519::generatePublicKey(Uint8* pPublicKey, const Uint8* pPrivKey)
{

    static bool has_adx  = CpuId::cpuHasAdx();
    static bool has_bmi2 = CpuId::cpuHasBmi2();

    if (!has_adx) {
        // Todo : cerr will be removed when error module is properly implemented
        std::cerr << "Not supported due to missing instruction set";
        return status::NotAvailable(
            "Not supported due to missing instruction set");
    }

    if (!has_bmi2) {
        // Todo : cerr will be removed when error module is properly implemented
        std::cerr << "Not supported due to missing instruction set";
        return status::NotAvailable(
            "Not supported due to missing instruction set");
    }

    // store private key for secret key generation
    alcp::utils::CopyBytes(m_PrivKey, pPrivKey, KeySize);

    m_PrivKey[0] &= 248;
    m_PrivKey[31] &= 127;
    m_PrivKey[31] |= 64;

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

    static bool zen2_available = CpuId::cpuIsZen2();
    static bool zen3_available = CpuId::cpuIsZen3() || CpuId::cpuIsZen4();

    if (zen3_available) {
        zen3::AlcpScalarPubX25519(priv_key_radix32, pPublicKey);
    } else if (zen2_available) {
        avx2::AlcpScalarPubX25519(priv_key_radix32, pPublicKey);
    } else {
        zen::AlcpScalarPubX25519(priv_key_radix32, pPublicKey);
    }

    return StatusOk();
}

Status
X25519::computeSecretKey(Uint8*       pSecretKey,
                         const Uint8* pPublicKey,
                         Uint64*      pKeyLength)
{

    static bool has_adx  = CpuId::cpuHasAdx();
    static bool has_bmi2 = CpuId::cpuHasBmi2();

    if (!has_adx) {
        // Todo : cerr will be removed when error module is properly implemented
        std::cerr << "Not supported due to missing instruction set";
        return status::NotAvailable("ADX instruction set not supported");
    }

    if (!has_bmi2) {
        // Todo : cerr will be removed when error module is properly implemented
        std::cerr << "Not supported due to missing instruction set";
        return status::NotAvailable("MULX instruction set not supported");
    }
    Status status = validatePublicKey(pPublicKey, KeySize);
    if (!status.ok()) {
        return status;
    }

    static bool zen2_available = CpuId::cpuIsZen2();
    static bool zen3_available = CpuId::cpuIsZen3() || CpuId::cpuIsZen4();

    if (zen3_available) {
        zen3::alcpScalarMulX25519(pSecretKey, m_PrivKey, pPublicKey);
    } else if (zen2_available) {
        avx2::alcpScalarMulX25519(pSecretKey, m_PrivKey, pPublicKey);
    } else {
        zen::alcpScalarMulX25519(pSecretKey, m_PrivKey, pPublicKey);
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

    return memcmp(all_zero, pPublicKey, KeySize)
               ? StatusOk()
               : Status(GenericError(ErrorCode::eInvalidArgument),
                        "Key validation failed");
}

void
X25519::reset()
{
    // clear private key with zeros
    alcp::utils::PadBytes(m_PrivKey, 0, KeySize);
}

Uint64
X25519::getKeySize()
{
    return KeySize;
}

} // namespace alcp::ec
