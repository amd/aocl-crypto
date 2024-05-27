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

#pragma once

#include "alcp/base.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/aes_ctr.hh"
#include "alcp/cipher/cipher_error.hh"
#include "alcp/cipher/common.hh"
#include "alcp/utils/cpuid.hh"

#include "alcp/cipher/aes_cmac_siv_arch.hh"

#include "alcp/mac/cmac.hh"
#include "alcp/utils/copy.hh"
#include <new>
#include <vector>

using Cmac = alcp::mac::Cmac;
#define SIZE_CMAC 128 / 8
namespace alcp::cipher {

using utils::CpuId;

// RFC5297

class ALCP_API_EXPORT Siv
{
  protected:
    /*
 Set of preprocessed Additional Data. Its allocated in a chunk to avoid
 memory issues. Each chunk being 10 slots. Any number of addtional data
 can be given by user but most of the time it will be less than 10. So a
 default size of 10 is allocated.
*/
    std::vector<std::vector<Uint8>> m_additionalDataProcessed =
        std::vector<std::vector<Uint8>>(10);
    alignas(16) Uint8 m_iv[MAX_CIPHER_IV_SIZE] = {};
    alignas(16) Uint8 m_cmacTemp[SIZE_CMAC]    = {};
    Uint64       m_additionalDataProcessedSize = {};
    const Uint8* m_key1                        = {};
    const Uint8* m_key2                        = {};
    Uint64       m_keyLength                   = {};
    Uint64       m_padLen                      = {};
    Cmac         m_cmac;

    /**
     * @brief Do Cmac implementation
     * @param data Pointer to data to do cmac on
     * @param size Size of the data
     * @param mac OutputMac memory
     * @param macSize Size of Mac
     * @return Status
     */
    Status cmacWrapper(const Uint8 data[],
                       Uint64      size,
                       Uint8       mac[],
                       Uint64      macSize);
    /**
     * @brief Do Cmac implementation
     * @param data1 Pointer to data1 to do cmac on
     * @param size1 Size of the data1
     * @param data2 Pointer to data2 to do cmac on
     * @param size2 Size of the data2
     * @param mac OutputMac memory
     * @param macSize Size of Mac
     * @return Status
     */
    Status cmacWrapperMultiData(const Uint8 data1[],
                                Uint64      size1,
                                const Uint8 data2[],
                                Uint64      size2,
                                Uint8       mac[],
                                Uint64      macSize);

    /**
     * @brief Add An additonal Input into the SIV Algorithm
     * @param memory Pointer which points to the additional data.
     * @param length Length of the additional data
     * @return Status
     */
    Status addAdditionalInput(const Uint8 memory[], Uint64 length);

    /**
     * @brief Set Keys for SIV and CTR
     * @param key1  Key for SIV
     * @param key2  Key for CTR
     * @param length  Length of each key, same length keys
     * @return Status
     */
    Status setKeys(const Uint8 key1[], const Uint8 key2[], Uint64 length);

    /**
     * @brief Generate Synthetic IV from Additional Data + Plaintext
     * @param plainText Plaintext Data Input
     * @param size Size of Plaintext
     * @return Status, is failure or success status object
     */
    Status s2v(const Uint8 plainText[], Uint64 size);

    Siv() = default;
    Siv(alc_cipher_data_t* ctx);
};

AEAD_AUTH_CLASS_GEN(SivHash, Siv);

// Declare AEAD Classes
namespace aesni {
    AEAD_CLASS_GEN_DOUBLE(SivAead128, Ctr128, SivHash);
    AEAD_CLASS_GEN_DOUBLE(SivAead192, Ctr192, SivHash);
    AEAD_CLASS_GEN_DOUBLE(SivAead256, Ctr256, SivHash);
} // namespace aesni

namespace vaes {
    AEAD_CLASS_GEN_DOUBLE(SivAead128, Ctr128, SivHash);
    AEAD_CLASS_GEN_DOUBLE(SivAead192, Ctr192, SivHash);
    AEAD_CLASS_GEN_DOUBLE(SivAead256, Ctr256, SivHash);
} // namespace vaes

namespace vaes512 {
    AEAD_CLASS_GEN_DOUBLE(SivAead128, Ctr128, SivHash);
    AEAD_CLASS_GEN_DOUBLE(SivAead192, Ctr192, SivHash);
    AEAD_CLASS_GEN_DOUBLE(SivAead256, Ctr256, SivHash);
} // namespace vaes512

} // namespace alcp::cipher