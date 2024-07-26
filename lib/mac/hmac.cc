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
using utils::CpuId;

static inline alc_error_t
getK0(const Uint8*     pKey,
      Uint32           keylen,
      Uint8*           pK0,
      digest::IDigest* pDigest,
      Uint32           input_block_length,
      Uint32           output_hash_size)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (keylen <= input_block_length) {
        utils::CopyBlock<Uint64>(pK0, pKey, keylen);
    } else {
        // Optimization: Reusing pDigest for calculating
        pDigest->init();
        err = pDigest->update(pKey, keylen);
        if (alcp_is_error(err)) {
            return err;
        }
        pDigest->finalize(pK0, output_hash_size);
        if (alcp_is_error(err)) {
            return err;
        }
        pDigest->init();
    }
    return err;
}

static inline void
getK0XorPad(Uint32 input_block_length,
            Uint8* pK0,
            Uint8* pK0_xor_ipad,
            Uint8* pK0_xor_opad)
{
    if (CpuId::cpuHasAvx2()) {
        avx2::get_k0_xor_opad(
            input_block_length, pK0, pK0_xor_ipad, pK0_xor_opad);
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
        reinterpret_cast<Uint64*>(pK0_xor_ipad);
    Uint64* p_current_temp_k0_xor_opad =
        reinterpret_cast<Uint64*>(pK0_xor_opad);
    Uint64* p_k0 = reinterpret_cast<Uint64*>(pK0);

    // 64 bit xor operations
    const int cNoOfXorOperations = input_block_length / 8;
    for (int i = 0; i < cNoOfXorOperations; i++) {
        *p_current_temp_k0_xor_ipad = *p_k0 ^ cIpad;
        *p_current_temp_k0_xor_opad = *p_k0 ^ cOpad;
        p_k0++;
        p_current_temp_k0_xor_ipad++;
        p_current_temp_k0_xor_opad++;
    }
}

Hmac::Hmac(const Hmac& hmac)
{
    m_input_block_length = hmac.m_input_block_length;
    m_output_hash_size   = hmac.m_output_hash_size;
    m_finalized          = hmac.m_finalized;
    m_isInit             = hmac.m_isInit;

    memcpy(m_pK0_xor_opad, hmac.m_pK0_xor_opad, cMaxInternalBlockLength);
    memcpy(m_pK0_xor_ipad, hmac.m_pK0_xor_ipad, cMaxInternalBlockLength);
}

Uint64
Hmac::getHashSize()
{
    return m_output_hash_size;
}

alc_error_t
Hmac::update(const Uint8* buff, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;
    if (m_finalized) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }

    if (!m_isInit) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }

    if (buff != nullptr && size != 0) {
        err = m_pDigest->update(buff, size);
        if (alcp_is_error(err)) {
            return err;
        }
    }
    return err;
}

alc_error_t
Hmac::finalize(Uint8* buff, Uint64 size)
{
    alc_error_t err = ALC_ERROR_NONE;

    if (m_finalized) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }

    if (!m_isInit) {
        err = ALC_ERROR_BAD_STATE;
        return err;
    }

    /* TODO: For all the following calls to digest return the proper error
    and assign */

    /* Placeholder variable to hold intermediate hash and the the mac value
    after finalize has been called */
    alignas(16) Uint8 pTempHash[cMaxHashSize]{};

    err = m_pDigest->finalize(pTempHash, m_output_hash_size);
    if (alcp_is_error(err)) {
        return err;
    }
    m_pDigest->init();

    err = m_pDigest->update(m_pK0_xor_opad, m_input_block_length);
    if (alcp_is_error(err)) {
        return err;
    }
    err = m_pDigest->update(pTempHash, m_output_hash_size);
    if (alcp_is_error(err)) {
        return err;
    }

    auto size_to_copy = size <= m_output_hash_size ? size : m_output_hash_size;

    err = m_pDigest->finalize(buff, size_to_copy);
    if (alcp_is_error(err)) {
        return err;
    }
    m_finalized = true;
    return err;
}

alc_error_t
Hmac::reset()
{
    alc_error_t err = ALC_ERROR_NONE;
    m_pDigest->init();
    err = m_pDigest->update(m_pK0_xor_ipad, m_input_block_length);
    if (alcp_is_error(err)) {
        return err;
    }
    m_finalized = false;
    return err;
}

alc_error_t
Hmac::init(const Uint8 key[], Uint32 keylen, digest::IDigest* digest)
{
    alc_error_t err;

    if (key == nullptr || digest == nullptr) {
        err = ALC_ERROR_INVALID_ARG;
        return err;
    }

    m_pDigest = digest;
    m_pDigest->init();

    m_input_block_length = m_pDigest->getInputBlockSize();
    m_output_hash_size   = m_pDigest->getHashSize();

    m_finalized = false;

    /* get_k0 function will process the key in such a way that processed key
    size will be the same as the internal block length of the digest used */
    /**
     * Preprocessed Key to match the input block length input_block_length
     * get_k0 function performs the preprocessing
     * */
    alignas(16) Uint8 pK0[cMaxInternalBlockLength]{};

    err = getK0(
        key, keylen, pK0, m_pDigest, m_input_block_length, m_output_hash_size);

    if (err != ALC_ERROR_NONE) {
        return err;
    }
    getK0XorPad(m_input_block_length, pK0, m_pK0_xor_ipad, m_pK0_xor_opad);

    err = m_pDigest->update(m_pK0_xor_ipad, m_input_block_length);
    if (alcp_is_error(err)) {
        return err;
    }

    m_isInit = true;
    return err;
}

void
Hmac::setDigest(digest::IDigest* digest)
{
    m_pDigest = digest;
}

} // namespace alcp::mac
