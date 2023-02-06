/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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

#include "mac/hmac.hh"
#include "alcp/base.hh"
#include "alcp/utils/cpuid.hh"
#include "utils/copy.hh"
#include <cstring> // for std::memset
#include <immintrin.h>

using alcp::utils::CpuId;
namespace alcp::mac {
using Status = alcp::base::Status;
class Hmac::Impl
{
  private:
    // Input Key to HMAC
    const Uint8* m_pKey;
    // Length of the input key must be >0 to be valid
    Uint32 m_keylen;
    // Length of the preprocessed Key
    Uint32 m_k0_length;
    // Input Block Length or B of the digest used by HMAC
    Uint32 m_input_block_length{};
    // Size of the message digest
    Uint32 m_output_hash_size{};
    // Placeholder variable to hold intermediate hash and the the mac value
    // after finalize has been called
    // Optimization: Max Size of 1024 bits for any SHA
    Uint8 m_pTempHash[64];

    // TODO: Consider Shared pointer for this implementation
    /**
     * Pointer to the Base class Digest, holds the address of the derived class
     * object of Digest which supports HMAC
     *
     */
    alcp::digest::Digest* m_pDigest;

    // Single Memory Block to hold  m_pK0_xor_ipad,m_pK0_xor_opad,m_pK0.
    // 3*input_block_length (with SHA input block length max size 144 bytes for
    // SHA3-224)
    alignas(16) Uint8 m_pMemory_block[432];
    Uint8* m_pK0_xor_opad = m_pMemory_block;
    Uint8* m_pK0_xor_ipad = m_pMemory_block + 144;

    /**
     * Preprocessed Key to match the input block length input_block_length
     * get_k0 function performs the preprocessing
     * */
    Uint8* m_pK0 = m_pMemory_block + 288;

  public:
    Impl(const Uint8& key, Uint32 keylen, alcp::digest::Digest& p_digest)
        : m_pDigest{ &p_digest }
    {
        // Constructor argument validations
        m_input_block_length = m_pDigest->getInputBlockSize();
        m_output_hash_size   = m_pDigest->getHashSize();
        m_pKey               = &key;
        m_keylen             = keylen;

        // For HMAC, we require k0 to be same length as input block length of
        // the used hash
        m_k0_length = m_input_block_length;

        // Preprocess key to obtain K0
        get_k0();

        // obtain k0_xor_ipad and k0_xor_opad
        get_k0_xor_pad();

        // start the hash calculation
        calculate_hash(m_pDigest, m_pK0_xor_ipad, m_input_block_length);
    }

  public:
    /// @brief Get hash size in bytes of the digest used for HMAC
    /// @return hash size in bytes of the HMAC digest
    Uint64 getHashSize() { return m_output_hash_size; }

    /// @brief Update HMAC with the given buffer chunk
    /// @param buff The chunk of the message to be updated
    /// @param size size of buff in bytes
    /// @return ALC_ERROR_NONE if no errors otherwise appropriate error
    Status update(const Uint8* buff, Uint64 size)
    {
        Status status = StatusOk();
        if (buff != nullptr && size != 0) {
            status = calculate_hash(m_pDigest, buff, size);
        }
        return status;
    }

    /// @brief Last method to be called with any remaining chunks of the
    /// message to calculate HMAC
    /// @param buff final chunk of the message. Can be nullptr
    /// @param size size of buff in bytes
    /// @return ALC_ERROR_NONE if no errors otherwise appropriate error
    Status finalize(const Uint8* buff, Uint64 size)
    {
        Status      status = StatusOk();
        alc_error_t err    = ALC_ERROR_NONE;
        // TODO: For all the following calls to digest return the proper error
        // and assign
        if (sizeof(buff) != 0 && size != 0) {
            err    = m_pDigest->finalize(buff, size);
            status = validate_error_status(err);
        } else {
            err    = m_pDigest->finalize(nullptr, 0);
            status = validate_error_status(err);
        }
        if (!status.ok()) {
            return status;
        }
        err    = m_pDigest->copyHash(m_pTempHash, m_output_hash_size);
        status = validate_error_status(err);
        if (!status.ok()) {
            return status;
        }
        m_pDigest->reset();

        status = calculate_hash(m_pDigest, m_pK0_xor_opad, m_k0_length);
        if (!status.ok()) {
            return status;
        }
        err    = m_pDigest->finalize(m_pTempHash, m_output_hash_size);
        status = validate_error_status(err);
        if (!status.ok()) {
            return status;
        }

        err    = m_pDigest->copyHash(m_pTempHash, m_output_hash_size);
        status = validate_error_status(err);
        if (!status.ok()) {
            return status;
        }
        m_pDigest->reset();

        return status;
    }

    /// @brief copy the result of HMAC to buff. Should be Called only after
    /// Finalize
    /// @param buff Output Buffer where HMAC result should be copied to
    /// @param size Size of buff in bytes
    /// @return ALC_ERROR_NONE if no errors otherwise appropriate error
    Status copyHash(Uint8* buff, Uint64 size)
    {
        // TODO: Update status with proper error code.
        Status status = StatusOk();
        if (size >= m_output_hash_size) {
            alcp::utils::CopyBytes(buff, m_pTempHash, size);
        } else {
            status =
                InvalidArgumentError("HMAC: Copy Buffer Size should be greater "
                                     "than or equal to SHA output size");
        }
        return status;
    }

    void finish() {}

    Status reset()
    {
        Status status = StatusOk();
        m_pDigest->reset();
        status =
            calculate_hash(m_pDigest, m_pK0_xor_ipad, m_input_block_length);
        return status;
    }

  private:
    void get_k0_xor_pad()
    {
        if (CpuId::cpuHasAvx2()) {
            avx2::get_k0_xor_opad(
                m_input_block_length, m_pK0, m_pK0_xor_ipad, m_pK0_xor_opad);
            return;
        }

        /* Reference Algorithm for calculating K0_xor_opad and k0_xor_ipad */

        // cIpad,cOpad: Fixed values from the specification
        // cIpad,cOpad Little Endian and BigEndian representation is same. So no
        // need for reinterpret_cast
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
    void copyData(Uint8* destination, const Uint8* source, int len)
    {
        if (CpuId::cpuHasAvx2()) {

            avx2::copyData(destination, source, len);
        } else {

            alcp::utils::CopyBytes(destination, source, len);
        }
    }

    Status get_k0()
    {
        Status status = StatusOk();
        if (m_input_block_length == m_keylen) {
            copyData(m_pK0, m_pKey, m_keylen);
        } else if (m_keylen < m_input_block_length) {
            copyData(m_pK0, m_pKey, m_keylen);
            std::memset(m_pK0 + m_keylen, 0x0, m_input_block_length - m_keylen);
        } else if (m_keylen > m_input_block_length) {
            // Optimization: Reusing p_digest for calculating
            // TODO: For all the following digest calls check and update proper
            // error status
            alc_error_t err = ALC_ERROR_NONE;
            m_pDigest->reset();
            err    = m_pDigest->finalize(m_pKey, m_keylen);
            status = validate_error_status(err);
            if (!status.ok()) {
                return status;
            }
            m_pDigest->copyHash(m_pK0, m_output_hash_size);
            status = validate_error_status(err);
            if (!status.ok()) {
                return status;
            }
            m_pDigest->reset();
            std::memset(m_pK0 + m_output_hash_size,
                        0x0,
                        m_input_block_length - m_output_hash_size);
        }
        return status;
    }

    Status calculate_hash(alcp::digest::Digest* p_digest,
                          const Uint8*          input,
                          Uint64                len)
    {
        alc_error_t err = p_digest->update(input, len);
        // TODO: Based on the output from update call update status code
        Status status = validate_error_status(err);
        return status;
    }

    Status validate_error_status(alc_error_t err)
    {
        /* TODO: This function is temporary to support Digest classes
           which still uses alc_error_t. This will return any failures to CAPI,
           but not proper error codes. Replace it with Specific HMAC errors once
           Digest classes are supported. */
        if (alcp_is_error(err)) {
            return InternalError("HMAC: InternalError");
        } else {
            return StatusOk();
        }
    }
};

Hmac::Hmac(const Uint8& key, Uint32 keylen, alcp::digest::Digest& p_digest)
    : m_pImpl{ std::make_unique<Hmac::Impl>(key, keylen, p_digest) }
{}
Hmac::~Hmac() {}

Status
Hmac::update(const Uint8* buff, Uint64 size)
{
    return m_pImpl->update(buff, size);
}

Status
Hmac::finalize(const Uint8* buff, Uint64 size)
{

    return m_pImpl->finalize(buff, size);
}

Status
Hmac::copyHash(Uint8* buff, Uint64 size) const
{
    return m_pImpl->copyHash(buff, size);
}

Uint64
Hmac::getHashSize()
{
    return m_pImpl->getHashSize();
}

void
Hmac::finish()
{
    m_pImpl->finish();
}

Status
Hmac::reset()
{
    return m_pImpl->reset();
}
} // namespace alcp::mac
