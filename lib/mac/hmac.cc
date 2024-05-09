/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/mac/hmac.hh"
#include "alcp/base.hh"
#include "alcp/mac/macerror.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"
#include <cstring> // for std::memset
#include <immintrin.h>

namespace alcp::mac {
using namespace alcp::mac::status;
using utils::CpuId;

Hmac::Hmac(Hmac& hmac)
{
    m_keylen             = hmac.m_keylen;
    m_k0_length          = hmac.m_k0_length;
    m_input_block_length = hmac.m_input_block_length;
    m_output_hash_size   = hmac.m_output_hash_size;
    m_finalized          = hmac.m_finalized;

    memcpy(m_pTempHash, hmac.m_pTempHash, cMaxHashSize);
    memcpy(m_pK0_xor_opad, hmac.m_pK0_xor_opad, cMaxInternalBlockLength);
    memcpy(m_pK0_xor_ipad, hmac.m_pK0_xor_ipad, cMaxInternalBlockLength);
    memcpy(m_pK0, hmac.m_pK0, cMaxInternalBlockLength);
}

Uint64
Hmac::getHashSize()
{
    return m_output_hash_size;
}

Status
Hmac::update(const Uint8* buff, Uint64 size)
{
    if (m_finalized) {
        return UpdateAfterFinalzeError("");
    }

    if (m_pKey == nullptr || m_pDigest == nullptr) {
        return InitError("");
    }

    Status status = StatusOk();
    if (buff != nullptr && size != 0) {
        alc_error_t err = m_pDigest->update(buff, size);
        if (alcp_is_error(err)) {
            return HMACDigestOperationError("");
        }
    }
    return status;
}

Status
Hmac::finalize(Uint8* buff, Uint64 size)
{
    if (m_finalized) {
        return AlreadyFinalizedError("");
    }

    Status      status = StatusOk();
    alc_error_t err    = ALC_ERROR_NONE;

    if (m_pDigest == nullptr || m_pKey == nullptr) {
        return InitError("");
    }

    /* TODO: For all the following calls to digest return the proper error
    and assign */

    err = m_pDigest->finalize(m_pTempHash, m_output_hash_size);
    if (alcp_is_error(err)) {
        return HMACDigestOperationError("");
    }
    m_pDigest->init();

    err = m_pDigest->update(m_pK0_xor_opad, m_k0_length);
    if (alcp_is_error(err)) {
        return HMACDigestOperationError("");
    }
    err = m_pDigest->update(m_pTempHash, m_output_hash_size);
    if (alcp_is_error(err)) {
        return HMACDigestOperationError("");
    }

    auto size_to_copy = size <= m_output_hash_size ? size : m_output_hash_size;

    err = m_pDigest->finalize(buff, size_to_copy);
    if (alcp_is_error(err)) {
        return HMACDigestOperationError("");
    }
    m_pDigest->init();
    m_finalized = true;
    return status;
}

Status
Hmac::reset()
{
    Status status = StatusOk();
    m_pDigest->init();
    alc_error_t err = m_pDigest->update(m_pK0_xor_ipad, m_input_block_length);
    if (alcp_is_error(err)) {
        return HMACDigestOperationError("");
    }
    m_finalized = false;
    return status;
}

Status
Hmac::init(const Uint8 key[], Uint32 keylen, digest::IDigest& digest)
{
    Status status = StatusOk();

    if (key == nullptr || keylen == 0) {
        return InitError("");
    }

    m_pDigest = &digest;
    m_pDigest->init();

    m_input_block_length = m_pDigest->getInputBlockSize();
    m_output_hash_size   = m_pDigest->getHashSize();

    m_finalized = false;

    m_pKey   = key;
    m_keylen = keylen;

    /* get_k0 function will process the key in such a way that processed key
    size will be the same as the internal block length of the digest used */
    m_k0_length = m_input_block_length;

    status = getK0();
    if (!status.ok()) {
        return status;
    }
    getK0XorPad();
    alc_error_t err = m_pDigest->update(m_pK0_xor_ipad, m_input_block_length);
    if (alcp_is_error(err)) {
        return HMACDigestOperationError("");
    }
    return status;
}

void
Hmac::getK0XorPad()
{
    if (CpuId::cpuHasAvx2()) {
        avx2::get_k0_xor_opad(
            m_input_block_length, m_pK0, m_pK0_xor_ipad, m_pK0_xor_opad);
        return;
    }

    /* Reference Algorithm for calculating K0_xor_opad and k0_xor_ipad */

    /*
    cIpad,cOpad: Fixed values from the specification
    cIpad,cOpad Little Endian and BigEndian representation is same. So no
    need for reinterpret_cast
    */
    constexpr Uint64 cIpad = 0x3636363636363636L;
    constexpr Uint64 cOpad = 0x5c5c5c5c5c5c5c5cL;

    Uint64* p_current_temp_k0_xor_ipad =
        reinterpret_cast<Uint64*>(m_pK0_xor_ipad);
    Uint64* p_current_temp_k0_xor_opad =
        reinterpret_cast<Uint64*>(m_pK0_xor_opad);
    Uint64* p_k0 = reinterpret_cast<Uint64*>(m_pK0);

    // 64 bit xor operations
    const int cNoOfXorOperations = m_input_block_length / 8;
    for (int i = 0; i < cNoOfXorOperations; i++) {
        *p_current_temp_k0_xor_ipad = *p_k0 ^ cIpad;
        *p_current_temp_k0_xor_opad = *p_k0 ^ cOpad;
        p_k0++;
        p_current_temp_k0_xor_ipad++;
        p_current_temp_k0_xor_opad++;
    }
}
void
Hmac::copyData(Uint8* destination, const Uint8* source, int len)
{
    if (CpuId::cpuHasAvx2()) {

        avx2::copyData(destination, source, len);
    } else {

        alcp::utils::CopyBytes(destination, source, len);
    }
}

Status
Hmac::getK0()
{
    Status status = StatusOk();
    if (m_input_block_length == m_keylen) {
        copyData(m_pK0, m_pKey, m_keylen);
    } else if (m_keylen < m_input_block_length) {
        copyData(m_pK0, m_pKey, m_keylen);
        std::memset(m_pK0 + m_keylen, 0x0, m_input_block_length - m_keylen);
    } else if (m_keylen > m_input_block_length) {
        // Optimization: Reusing p_digest for calculating
        /*TODO: For all the following digest calls check and update proper
        error status */
        alc_error_t err = ALC_ERROR_NONE;
        m_pDigest->init();
        err = m_pDigest->update(m_pKey, m_keylen);
        if (alcp_is_error(err)) {
            return HMACDigestOperationError("");
        }
        m_pDigest->finalize(m_pK0, m_output_hash_size);
        if (alcp_is_error(err)) {
            return HMACDigestOperationError("");
        }
        m_pDigest->init();
        std::memset(m_pK0 + m_output_hash_size,
                    0x0,
                    m_input_block_length - m_output_hash_size);
    }
    return status;
}

} // namespace alcp::mac
